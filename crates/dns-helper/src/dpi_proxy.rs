//! Local HTTP CONNECT proxy that applies TLS-record fragmentation.
//!
//! Browsers point at `http://127.0.0.1:<port>` as their proxy. For each
//! `CONNECT host:443` the proxy dials the target, fragments the client's first
//! flight (the ClientHello) with [`crate::dpi::fragment_client_hello`], then
//! tunnels the rest untouched. It never decrypts anything and needs no root:
//! it binds a high loopback port and rewrites only TLS record boundaries.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dpi::fragment_client_hello;

#[derive(Default)]
pub struct Stats {
    pub connections: AtomicU64,
    pub fragmented: AtomicU64,
}

pub struct DpiProxy {
    pub stats: Arc<Stats>,
}

impl Default for DpiProxy {
    fn default() -> Self {
        Self { stats: Arc::new(Stats::default()) }
    }
}

/// Recover the address a redirected connection was *originally* headed to.
///
/// An nftables `redirect` rewrites the destination to our local port, so the
/// socket's peer address is useless. The kernel keeps the pre-NAT destination
/// and hands it back through `SO_ORIGINAL_DST`. Without this a transparently
/// redirected connection has no idea where to go.
pub fn original_destination(fd: std::os::fd::RawFd) -> std::io::Result<SocketAddr> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    // SOL_IP / SO_ORIGINAL_DST
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

impl DpiProxy {
    /// Serve transparently: every accepted connection was redirected here by a
    /// firewall rule, so the destination comes from `SO_ORIGINAL_DST` rather
    /// than an HTTP CONNECT request. This is what makes the bypass work for
    /// apps that have no proxy setting.
    pub async fn serve_transparent(self: Arc<Self>, addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "transparent DPI-bypass proxy listening");
        loop {
            let (client, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error=%e, "accept failed");
                    continue;
                }
            };
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = this.handle_transparent(client).await {
                    tracing::debug!(error=%e, "transparent connection ended");
                }
            });
        }
    }

    async fn handle_transparent(&self, client: TcpStream) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let target = original_destination(client.as_raw_fd())?;

        // Refuse to connect back to ourselves: without this a misplaced rule
        // would make the proxy loop forever on its own traffic.
        if target.ip().is_loopback() {
            return Ok(());
        }

        let upstream = TcpStream::connect(target).await?;
        self.stats.connections.fetch_add(1, Ordering::Relaxed);
        self.splice(client, upstream).await
    }

    /// Fragment the client's first flight, then splice both directions.
    async fn splice(&self, client: TcpStream, upstream: TcpStream) -> std::io::Result<()> {
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();

        let mut first = vec![0u8; 16 * 1024];
        let n = cr.read(&mut first).await?;
        if n == 0 {
            return Ok(());
        }
        let framed = fragment_client_hello(&first[..n]);
        if framed.len() != n {
            self.stats.fragmented.fetch_add(1, Ordering::Relaxed);
        }
        uw.write_all(&framed).await?;

        let c2u = async {
            tokio::io::copy(&mut cr, &mut uw).await.ok();
            uw.shutdown().await.ok();
        };
        let u2c = async {
            tokio::io::copy(&mut ur, &mut cw).await.ok();
            cw.shutdown().await.ok();
        };
        tokio::join!(c2u, u2c);
        Ok(())
    }

    /// Serve until the future is dropped. Binds loopback only, so nothing on
    /// the network can reach it.
    pub async fn serve(self: Arc<Self>, addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, "DPI-bypass proxy listening");
        loop {
            let (client, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error=%e, "accept failed");
                    continue;
                }
            };
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = this.handle(client).await {
                    tracing::debug!(error=%e, "connection ended");
                }
            });
        }
    }

    async fn handle(&self, mut client: TcpStream) -> std::io::Result<()> {
        // Read the request line + headers (up to the blank line).
        let mut buf = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            let n = client.read(&mut byte).await?;
            if n == 0 {
                return Ok(());
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }

        let head = String::from_utf8_lossy(&buf);
        let Some(target) = parse_connect_target(&head) else {
            let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await;
            return Ok(());
        };

        let upstream = match TcpStream::connect(&target).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e);
            }
        };
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        self.stats.connections.fetch_add(1, Ordering::Relaxed);
        self.splice(client, upstream).await
    }
}

/// Extract `host:port` from a `CONNECT host:port HTTP/1.1` request line.
fn parse_connect_target(head: &str) -> Option<String> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let authority = parts.next()?;
    // Must contain a port and a non-empty host.
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        return None;
    }
    Some(authority.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_line() {
        let h = "CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(parse_connect_target(h).as_deref(), Some("www.youtube.com:443"));
    }

    #[test]
    fn rejects_non_connect_and_malformed() {
        assert!(parse_connect_target("GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_connect_target("CONNECT nohost HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_connect_target("CONNECT host:notaport HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_connect_target("").is_none());
    }

    #[test]
    fn accepts_ipv6_authority() {
        let h = "CONNECT [2606:4700::1]:443 HTTP/1.1\r\n\r\n";
        assert_eq!(parse_connect_target(h).as_deref(), Some("[2606:4700::1]:443"));
    }
}
