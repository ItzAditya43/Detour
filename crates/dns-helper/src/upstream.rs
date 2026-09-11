//! Plain-DNS forwarding to the resolvers the system used before we took over.
//!
//! Needed for names a public resolver cannot answer: the router, `.local`
//! discovery, reverse lookups inside private ranges.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// EDNS0 advertises payloads well past the old 512-byte limit.
const MAX_UDP_RESPONSE: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("no system upstream resolvers are configured")]
    NoUpstreams,
    #[error("all {0} upstream resolver(s) failed or timed out")]
    AllFailed(usize),
    #[error("socket error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Forwarder {
    servers: Vec<SocketAddr>,
}

impl Forwarder {
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self { servers }
    }

    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Send a raw query to each upstream in turn, returning the first reply.
    pub async fn forward(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        if self.servers.is_empty() {
            return Err(UpstreamError::NoUpstreams);
        }

        for server in &self.servers {
            match self.try_one(*server, query).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    tracing::debug!(%server, error = %err, "upstream failed, trying next");
                }
            }
        }
        Err(UpstreamError::AllFailed(self.servers.len()))
    }

    async fn try_one(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        // Bind a fresh ephemeral socket per query so replies cannot be
        // cross-matched between concurrent lookups.
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid bind address")
        } else {
            "[::]:0".parse().expect("valid bind address")
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(server).await?;
        socket.send(query).await?;

        let mut buf = vec![0u8; MAX_UDP_RESPONSE];
        let len = tokio::time::timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| {
                UpstreamError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("no reply from {server} within {UPSTREAM_TIMEOUT:?}"),
                ))
            })??;

        buf.truncate(len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_forwarder_reports_no_upstreams() {
        let f = Forwarder::new(vec![]);
        assert!(matches!(
            f.forward(b"anything").await,
            Err(UpstreamError::NoUpstreams)
        ));
        assert!(f.is_empty());
    }

    #[tokio::test]
    async fn unreachable_upstream_times_out_and_reports_failure() {
        // 203.0.113.0/24 is TEST-NET-3, reserved and unroutable.
        let dead: SocketAddr = "203.0.113.1:53".parse().unwrap();
        let f = Forwarder::new(vec![dead]);
        let err = f.forward(b"\x00\x00\x01\x00").await.unwrap_err();
        assert!(matches!(err, UpstreamError::AllFailed(1)));
    }
}
