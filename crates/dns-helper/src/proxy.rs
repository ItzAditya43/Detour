//! The local DNS proxy: listens on a loopback address and routes each query to
//! either DoH or the system's original resolver, per policy.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use dns_core::policy::Route;
use dns_core::{DohResolver, Policy};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::{TcpListener, UdpSocket};

use crate::upstream::Forwarder;

const MAX_UDP: usize = 4096;
/// Keep the last N queries for the UI's live log. Bounded so a long session
/// cannot grow without limit.
const LOG_CAPACITY: usize = 500;
const CACHE_PURGE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QueryLogEntry {
    pub name: String,
    pub record_type: String,
    pub route: String,
    pub outcome: String,
    pub elapsed_ms: u64,
    pub answers: Vec<String>,
}

#[derive(Default)]
pub struct QueryLog {
    entries: Mutex<VecDeque<QueryLogEntry>>,
    /// Lifetime count, which keeps rising after old entries are evicted.
    total: std::sync::atomic::AtomicU64,
}

impl QueryLog {
    pub fn push(&self, entry: QueryLogEntry) {
        self.total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut entries = self.entries.lock().expect("log mutex poisoned");
        if entries.len() >= LOG_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    pub fn total(&self) -> u64 {
        self.total.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn recent(&self, limit: usize) -> Vec<QueryLogEntry> {
        let entries = self.entries.lock().expect("log mutex poisoned");
        entries.iter().rev().take(limit).cloned().collect()
    }
}

pub struct Proxy {
    resolver: Arc<DohResolver>,
    forwarder: Arc<Forwarder>,
    policy: Arc<RwLock<Policy>>,
    pub log: Arc<QueryLog>,
}

impl Proxy {
    pub fn new(resolver: Arc<DohResolver>, forwarder: Arc<Forwarder>, policy: Policy) -> Self {
        Self {
            resolver,
            forwarder,
            policy: Arc::new(RwLock::new(policy)),
            log: Arc::new(QueryLog::default()),
        }
    }

    pub fn policy(&self) -> Arc<RwLock<Policy>> {
        Arc::clone(&self.policy)
    }

    /// Serve until cancelled. Binds UDP and TCP on the same address, as any
    /// resolver is expected to answer on both.
    pub async fn serve(self: Arc<Self>, addr: SocketAddr) -> anyhow::Result<()> {
        let udp = UdpSocket::bind(addr).await.map_err(|e| bind_error(addr, e))?;
        let tcp = TcpListener::bind(addr).await.map_err(|e| bind_error(addr, e))?;
        tracing::info!(%addr, "DNS proxy listening on UDP and TCP");

        let udp_task = tokio::spawn(Arc::clone(&self).serve_udp(udp));
        let tcp_task = tokio::spawn(Arc::clone(&self).serve_tcp(tcp));
        let purge_task = tokio::spawn(Arc::clone(&self).purge_loop());

        tokio::select! {
            r = udp_task => r??,
            r = tcp_task => r??,
            r = purge_task => r?,
        }
        Ok(())
    }

    async fn purge_loop(self: Arc<Self>) {
        let cache = self.resolver.cache();
        loop {
            tokio::time::sleep(CACHE_PURGE_INTERVAL).await;
            cache.lock().expect("cache mutex poisoned").purge_expired();
        }
    }

    async fn serve_udp(self: Arc<Self>, socket: UdpSocket) -> anyhow::Result<()> {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; MAX_UDP];

        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "UDP receive failed");
                    continue;
                }
            };

            let query = buf[..len].to_vec();
            let this = Arc::clone(&self);
            let socket = Arc::clone(&socket);
            // Handle off the accept path so one slow upstream cannot stall
            // every other client.
            tokio::spawn(async move {
                let response = this.handle(&query).await;
                // A UDP response over 512 bytes without EDNS negotiation must
                // be truncated so the client retries over TCP.
                let response = truncate_if_needed(response, &query);
                if let Err(e) = socket.send_to(&response, peer).await {
                    tracing::warn!(%peer, error = %e, "failed to send UDP response");
                }
            });
        }
    }

    async fn serve_tcp(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "TCP accept failed");
                    continue;
                }
            };

            let this = Arc::clone(&self);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // DNS over TCP frames each message with a 2-byte big-endian length.
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut query = vec![0u8; len];
                if stream.read_exact(&mut query).await.is_err() {
                    return;
                }

                let response = this.handle(&query).await;
                let framed = [&(response.len() as u16).to_be_bytes()[..], &response].concat();
                if let Err(e) = stream.write_all(&framed).await {
                    tracing::warn!(%peer, error = %e, "failed to send TCP response");
                }
            });
        }
    }

    /// Route one wire-format query and produce a wire-format response. Never
    /// fails: any error becomes a SERVFAIL, because a client waiting on a
    /// dropped packet is worse than a client told the lookup failed.
    pub async fn handle(&self, query_bytes: &[u8]) -> Vec<u8> {
        let started = Instant::now();

        let query = match Message::from_bytes(query_bytes) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(error = %e, "unparseable query dropped");
                return servfail_from_raw(query_bytes);
            }
        };

        let id = query.id();
        let Some(question) = query.queries().first().cloned() else {
            return servfail(id, ResponseCode::FormErr);
        };

        let name = question.name().clone();
        let record_type = question.query_type();
        let route = self.policy.read().expect("policy lock poisoned").route(&name);

        let (response_bytes, outcome, answers) = match route {
            Route::Doh => match self.resolver.resolve(&name, record_type).await {
                Ok(mut response) => {
                    // The cached/DoH message carries id 0; the client is
                    // matching on its own id.
                    response.set_id(id);
                    let answers = describe_answers(&response);
                    match response.to_vec() {
                        Ok(bytes) => (bytes, format!("{:?}", response.response_code()), answers),
                        Err(e) => {
                            tracing::warn!(%name, error = %e, "could not encode DoH response");
                            (servfail(id, ResponseCode::ServFail), "EncodeError".into(), vec![])
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(%name, error = %e, "DoH resolution failed");
                    (servfail(id, ResponseCode::ServFail), e.to_string(), vec![])
                }
            },
            Route::SystemUpstream => match self.forwarder.forward(query_bytes).await {
                Ok(bytes) => {
                    let answers = Message::from_bytes(&bytes)
                        .map(|m| describe_answers(&m))
                        .unwrap_or_default();
                    (bytes, "Forwarded".to_string(), answers)
                }
                Err(e) => {
                    tracing::warn!(%name, error = %e, "upstream forwarding failed");
                    (servfail(id, ResponseCode::ServFail), e.to_string(), vec![])
                }
            },
        };

        self.log.push(QueryLogEntry {
            name: name.to_string(),
            record_type: record_type.to_string(),
            route: match route {
                Route::Doh => "doh".to_string(),
                Route::SystemUpstream => "system".to_string(),
            },
            outcome,
            elapsed_ms: started.elapsed().as_millis() as u64,
            answers,
        });

        response_bytes
    }
}

fn describe_answers(msg: &Message) -> Vec<String> {
    msg.answers()
        .iter()
        .filter(|r| matches!(r.record_type(), RecordType::A | RecordType::AAAA | RecordType::CNAME))
        .filter_map(|r| r.data().map(|d| d.to_string()))
        .collect()
}

/// Build a minimal failure response that still echoes the client's id, so the
/// client fails fast instead of waiting for a timeout.
fn servfail(id: u16, code: ResponseCode) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_response_code(code)
        .set_recursion_desired(true)
        .set_recursion_available(true);
    msg.to_vec().unwrap_or_else(|_| Vec::new())
}

/// Last resort when the query could not be parsed at all: salvage the id from
/// the first two bytes if they exist.
fn servfail_from_raw(query: &[u8]) -> Vec<u8> {
    let id = if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        0
    };
    servfail(id, ResponseCode::FormErr)
}

/// Cap UDP responses at the size the client said it could accept, setting the
/// truncation bit so it retries over TCP.
fn truncate_if_needed(response: Vec<u8>, query: &[u8]) -> Vec<u8> {
    let advertised = Message::from_bytes(query)
        .ok()
        .and_then(|m| m.extensions().as_ref().map(|e| e.max_payload() as usize))
        .unwrap_or(512)
        .clamp(512, MAX_UDP);

    if response.len() <= advertised {
        return response;
    }

    match Message::from_bytes(&response) {
        Ok(msg) => {
            let mut truncated = Message::new();
            truncated
                .set_id(msg.id())
                .set_message_type(MessageType::Response)
                .set_op_code(msg.op_code())
                .set_response_code(msg.response_code())
                .set_recursion_desired(msg.recursion_desired())
                .set_recursion_available(true)
                .set_truncated(true);
            for q in msg.queries() {
                truncated.add_query(q.clone());
            }
            truncated.to_vec().unwrap_or(response)
        }
        Err(_) => response,
    }
}

fn bind_error(addr: SocketAddr, e: std::io::Error) -> anyhow::Error {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
            "permission denied binding {addr}: port 53 is privileged. \
             Run the helper as root, or grant it CAP_NET_BIND_SERVICE."
        ),
        std::io::ErrorKind::AddrInUse => anyhow::anyhow!(
            "{addr} is already in use: another resolver (dnsmasq, systemd-resolved) holds it."
        ),
        _ => anyhow::anyhow!("could not bind {addr}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_core::provider::Provider;
    use dns_core::resolver::build_query;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn test_proxy(policy: Policy) -> Proxy {
        let resolver = Arc::new(DohResolver::new(vec![Provider::cloudflare()]).unwrap());
        // Unroutable upstream: local-route tests should fail fast, not resolve.
        let forwarder = Arc::new(Forwarder::new(vec!["203.0.113.1:53".parse().unwrap()]));
        Proxy::new(resolver, forwarder, policy)
    }

    #[test]
    fn servfail_preserves_query_id() {
        let bytes = servfail(0xbeef, ResponseCode::ServFail);
        let msg = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.id(), 0xbeef);
        assert_eq!(msg.message_type(), MessageType::Response);
        assert_eq!(msg.response_code(), ResponseCode::ServFail);
    }

    #[test]
    fn raw_servfail_salvages_id_from_prefix() {
        let msg = Message::from_bytes(&servfail_from_raw(&[0xab, 0xcd, 0xff])).unwrap();
        assert_eq!(msg.id(), 0xabcd);
    }

    #[test]
    fn raw_servfail_handles_empty_input() {
        let msg = Message::from_bytes(&servfail_from_raw(&[])).unwrap();
        assert_eq!(msg.id(), 0);
    }

    #[tokio::test]
    async fn garbage_query_yields_formerr_not_panic() {
        let proxy = test_proxy(Policy::default());
        let msg = Message::from_bytes(&proxy.handle(&[0x12, 0x34, 0x99]).await).unwrap();
        assert_eq!(msg.id(), 0x1234);
        assert_eq!(msg.response_code(), ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn query_with_no_question_yields_formerr() {
        let mut empty = Message::new();
        empty.set_id(7).set_message_type(MessageType::Query);
        let proxy = test_proxy(Policy::default());
        let msg = Message::from_bytes(&proxy.handle(&empty.to_vec().unwrap()).await).unwrap();
        assert_eq!(msg.id(), 7);
        assert_eq!(msg.response_code(), ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn local_name_is_routed_to_upstream_and_logged() {
        let proxy = test_proxy(Policy::default());
        let mut q = build_query(&Name::from_str("nas.lan.").unwrap(), RecordType::A);
        q.set_id(99);

        // Upstream is unroutable, so this fails — but the routing decision is
        // what matters, and the log records it.
        let _ = proxy.handle(&q.to_vec().unwrap()).await;

        let recent = proxy.log.recent(1);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].name, "nas.lan.");
        assert_eq!(recent[0].route, "system");
    }

    #[test]
    fn log_is_bounded_and_newest_first() {
        let log = QueryLog::default();
        for i in 0..(LOG_CAPACITY + 50) {
            log.push(QueryLogEntry {
                name: format!("host{i}.test."),
                record_type: "A".into(),
                route: "doh".to_string(),
                outcome: "NoError".into(),
                elapsed_ms: 1,
                answers: vec![],
            });
        }
        let recent = log.recent(3);
        assert_eq!(recent[0].name, format!("host{}.test.", LOG_CAPACITY + 49));
        assert_eq!(log.entries.lock().unwrap().len(), LOG_CAPACITY);
    }

    #[test]
    fn oversized_response_is_truncated_with_tc_bit() {
        let query = build_query(&Name::from_str("example.com.").unwrap(), RecordType::A);
        let query_bytes = query.to_vec().unwrap();

        let mut response = Message::new();
        response.set_id(5).set_message_type(MessageType::Response);
        for i in 0..40 {
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                Name::from_str(&format!("very-long-host-name-number-{i}.example.com.")).unwrap(),
                300,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A::new(1, 2, 3, 4)),
            ));
        }
        let encoded = response.to_vec().unwrap();
        assert!(encoded.len() > 512, "fixture should exceed the UDP limit");

        let out = truncate_if_needed(encoded, &query_bytes);
        let parsed = Message::from_bytes(&out).unwrap();
        assert!(parsed.truncated());
        assert_eq!(parsed.id(), 5);
        assert!(out.len() <= 512);
    }

    #[test]
    fn unparseable_oversized_response_is_passed_through_untouched() {
        let query = build_query(&Name::from_str("example.com.").unwrap(), RecordType::A);
        let query_bytes = query.to_vec().unwrap();

        // A name whose compression pointer targets itself: a decompression
        // loop, which is what a corrupted or hostile response looks like. We
        // cannot rebuild a truncated form from something we cannot decode, so
        // it must pass through rather than be replaced with something invented.
        let mut malformed = vec![0u8; 1200];
        malformed[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        malformed[4..6].copy_from_slice(&1u16.to_be_bytes());
        malformed[12] = 0xC0;
        malformed[13] = 0x0C;
        assert!(Message::from_bytes(&malformed).is_err(), "fixture must not parse");

        let out = truncate_if_needed(malformed.clone(), &query_bytes);
        assert_eq!(out, malformed);
    }

    #[test]
    fn response_within_limit_is_left_alone() {
        let query = build_query(&Name::from_str("example.com.").unwrap(), RecordType::A);
        let query_bytes = query.to_vec().unwrap();
        let small = vec![7u8; 100];
        assert_eq!(truncate_if_needed(small.clone(), &query_bytes), small);
    }
}
