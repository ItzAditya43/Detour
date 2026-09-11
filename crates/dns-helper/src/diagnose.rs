//! Side-by-side comparison of ISP DNS versus DoH, plus reachability probes.
//!
//! DNS interference is only one way an ISP can break a game. This tells you
//! which failure you actually have before you write a single profile entry:
//!
//! * ISP and DoH agree, addresses connect  -> DNS is fine, look elsewhere.
//! * ISP fails or lies, DoH works and connects -> DNS interference; this tool helps.
//! * Both resolve, neither connects        -> IP or SNI level blocking; DNS cannot fix it.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use dns_core::resolver::build_query;
use dns_core::DohResolver;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use serde::Serialize;

use crate::upstream::Forwarder;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const PROBE_PORT: u16 = 443;

/// Addresses a resolver returns when a network forces Google/YouTube content
/// restriction. A network administrator enables this by making `www.youtube.com`
/// resolve here instead of to the normal frontends, so seeing one of these in an
/// answer is direct proof of enforced filtering rather than an inference.
const RESTRICTION_TARGETS: &[(&str, &str)] = &[
    ("216.239.38.120", "strict (restrict.youtube.com / forcesafesearch.google.com)"),
    ("216.239.38.119", "moderate (restrictmoderate.youtube.com)"),
    ("2001:4860:4802:32::78", "strict (IPv6)"),
    ("2001:4860:4802:32::77", "moderate (IPv6)"),
];

/// Describe the restriction level if `ip` is a known enforcement target.
fn restriction_level(ip: &IpAddr) -> Option<&'static str> {
    let text = ip.to_string();
    RESTRICTION_TARGETS
        .iter()
        .find(|(addr, _)| *addr == text)
        .map(|(_, level)| *level)
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub domain: String,
    pub isp_addresses: Vec<String>,
    pub isp_error: Option<String>,
    pub doh_addresses: Vec<String>,
    pub doh_error: Option<String>,
    /// Addresses that accepted a TCP connection on 443.
    pub reachable: Vec<String>,
    /// Addresses that did not.
    pub unreachable: Vec<String>,
    /// Set when an answer pointed at a known content-restriction target.
    pub restriction: Option<String>,
    pub conclusion: Conclusion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Conclusion {
    /// Both resolvers agree and the addresses connect.
    Healthy,
    /// ISP resolution failed or disagreed; DoH addresses connect.
    DnsInterference,
    /// Resolution works but nothing connects — beyond DNS.
    BlockedBeyondDns,
    /// Neither resolver produced an answer.
    ResolutionFailed,
    /// Resolvers disagree but both sets connect; usually just CDN geography.
    DivergentButHealthy,
    /// A resolver returned a Google/YouTube content-restriction address.
    ContentRestrictionForced,
}

impl Conclusion {
    pub fn explain(self) -> &'static str {
        match self {
            Self::Healthy => {
                "ISP and DoH agree and the addresses accept connections. DNS is not your problem here."
            }
            Self::DnsInterference => {
                "Your ISP's resolver failed or returned addresses that do not work, while DoH \
                 returned working ones. This is exactly what this tool routes around."
            }
            Self::BlockedBeyondDns => {
                "Both resolvers answered, but no address accepts a connection. The block is at \
                 the IP or SNI level, and changing DNS will not fix it."
            }
            Self::ResolutionFailed => {
                "Neither resolver returned an address. Check the domain name and your connection."
            }
            Self::DivergentButHealthy => {
                "The resolvers returned different addresses but both work. Normal for CDN-hosted \
                 domains; nothing to fix."
            }
            Self::ContentRestrictionForced => {
                "A resolver answered with a Google/YouTube content-restriction address, which is \
                 how a network forces SafeSearch or YouTube Restricted Mode. If only the system \
                 resolver does this, routing over DoH bypasses it."
            }
        }
    }
}

pub struct Diagnostics {
    resolver: DohResolver,
    forwarder: Forwarder,
}

impl Diagnostics {
    pub fn new(resolver: DohResolver, forwarder: Forwarder) -> Self {
        Self { resolver, forwarder }
    }

    pub async fn check(&self, domain: &str) -> Verdict {
        let name = match Name::from_utf8(domain) {
            Ok(n) => n,
            Err(e) => {
                return Verdict {
                    domain: domain.to_string(),
                    isp_addresses: vec![],
                    isp_error: Some(format!("invalid domain name: {e}")),
                    doh_addresses: vec![],
                    doh_error: None,
                    reachable: vec![],
                    unreachable: vec![],
                    restriction: None,
                    conclusion: Conclusion::ResolutionFailed,
                }
            }
        };

        let (isp, doh) = tokio::join!(self.via_isp(&name), self.via_doh(&name));

        let (isp_addresses, isp_error) = split(isp);
        let (doh_addresses, doh_error) = split(doh);

        // Probe the union, so we learn whether the ISP's answers are dead and
        // DoH's are live — the distinction the whole verdict turns on.
        let mut all: Vec<IpAddr> = isp_addresses.iter().chain(doh_addresses.iter()).copied().collect();
        all.sort();
        all.dedup();

        let mut reachable = Vec::new();
        let mut unreachable = Vec::new();
        for ip in all {
            if tcp_probe(ip).await {
                reachable.push(ip);
            } else {
                unreachable.push(ip);
            }
        }

        // A restriction address in either answer is decisive on its own, and
        // which side carries it says whether DoH can route around it.
        let isp_restricted = isp_addresses.iter().find_map(restriction_level);
        let doh_restricted = doh_addresses.iter().find_map(restriction_level);
        let restriction = match (isp_restricted, doh_restricted) {
            (Some(level), Some(_)) => Some(format!(
                "both resolvers return {level} restriction - enforced upstream, DoH cannot bypass it"
            )),
            (Some(level), None) => Some(format!(
                "system resolver returns {level} restriction; DoH does not - routing over DoH bypasses it"
            )),
            (None, Some(level)) => Some(format!(
                "the DoH provider returns {level} restriction - switch to a non-filtering provider"
            )),
            (None, None) => None,
        };

        let conclusion = if restriction.is_some() {
            Conclusion::ContentRestrictionForced
        } else {
            conclude(&isp_addresses, &doh_addresses, &reachable)
        };

        Verdict {
            domain: domain.to_string(),
            isp_addresses: to_strings(&isp_addresses),
            isp_error,
            doh_addresses: to_strings(&doh_addresses),
            doh_error,
            reachable: to_strings(&reachable),
            unreachable: to_strings(&unreachable),
            restriction,
            conclusion,
        }
    }

    /// Query both A and AAAA. Checking only IPv4 would miss a restriction
    /// applied solely to AAAA, which a browser preferring IPv6 would still hit.
    async fn via_isp(&self, name: &Name) -> Result<Vec<IpAddr>, String> {
        if self.forwarder.is_empty() {
            return Err("no system resolver configured".to_string());
        }

        let mut addrs = Vec::new();
        let mut last_err = None;
        for rtype in [RecordType::A, RecordType::AAAA] {
            let query = match build_query(name, rtype).to_vec() {
                Ok(q) => q,
                Err(e) => { last_err = Some(e.to_string()); continue }
            };
            match self.forwarder.forward(&query).await {
                Ok(bytes) => match Message::from_bytes(&bytes) {
                    Ok(msg) => addrs.extend(addresses_of(&msg)),
                    Err(e) => last_err = Some(e.to_string()),
                },
                Err(e) => last_err = Some(e.to_string()),
            }
        }

        if addrs.is_empty() {
            Err(last_err.unwrap_or_else(|| "no answer".to_string()))
        } else {
            Ok(addrs)
        }
    }

    async fn via_doh(&self, name: &Name) -> Result<Vec<IpAddr>, String> {
        let mut addrs = Vec::new();
        let mut last_err = None;
        for rtype in [RecordType::A, RecordType::AAAA] {
            match self.resolver.resolve(name, rtype).await {
                Ok(msg) => addrs.extend(addresses_of(&msg)),
                Err(e) => last_err = Some(e.to_string()),
            }
        }

        if addrs.is_empty() {
            Err(last_err.unwrap_or_else(|| "no answer".to_string()))
        } else {
            Ok(addrs)
        }
    }
}

fn conclude(isp: &[IpAddr], doh: &[IpAddr], reachable: &[IpAddr]) -> Conclusion {
    if isp.is_empty() && doh.is_empty() {
        return Conclusion::ResolutionFailed;
    }
    if reachable.is_empty() {
        return Conclusion::BlockedBeyondDns;
    }

    let isp_works = isp.iter().any(|ip| reachable.contains(ip));
    let doh_works = doh.iter().any(|ip| reachable.contains(ip));

    match (isp_works, doh_works) {
        // The ISP's answers are useless and DoH's are not: interference.
        (false, true) => Conclusion::DnsInterference,
        (true, true) if same_set(isp, doh) => Conclusion::Healthy,
        (true, true) => Conclusion::DivergentButHealthy,
        // DoH failed but the ISP works; nothing for this tool to fix.
        (true, false) => Conclusion::Healthy,
        (false, false) => Conclusion::BlockedBeyondDns,
    }
}

fn same_set(a: &[IpAddr], b: &[IpAddr]) -> bool {
    let mut a: Vec<_> = a.to_vec();
    let mut b: Vec<_> = b.to_vec();
    a.sort();
    a.dedup();
    b.sort();
    b.dedup();
    a == b
}

async fn tcp_probe(ip: IpAddr) -> bool {
    let addr = SocketAddr::new(ip, PROBE_PORT);
    let started = Instant::now();
    let result = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await;
    let ok = matches!(result, Ok(Ok(_)));
    tracing::debug!(%addr, ok, elapsed = ?started.elapsed(), "probe");
    ok
}

fn addresses_of(msg: &Message) -> Vec<IpAddr> {
    msg.answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::A(a)) => Some(IpAddr::V4(a.0)),
            Some(RData::AAAA(a)) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

fn split(result: Result<Vec<IpAddr>, String>) -> (Vec<IpAddr>, Option<String>) {
    match result {
        Ok(addrs) => (addrs, None),
        Err(e) => (Vec::new(), Some(e)),
    }
}

fn to_strings(addrs: &[IpAddr]) -> Vec<String> {
    addrs.iter().map(ToString::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn agreeing_and_reachable_is_healthy() {
        let both = ips(&["1.2.3.4"]);
        assert_eq!(conclude(&both, &both, &both), Conclusion::Healthy);
    }

    #[test]
    fn isp_dead_doh_alive_is_interference() {
        let isp = ips(&["10.10.10.10"]);
        let doh = ips(&["1.2.3.4"]);
        assert_eq!(conclude(&isp, &doh, &doh), Conclusion::DnsInterference);
    }

    #[test]
    fn isp_returning_nothing_while_doh_works_is_interference() {
        let doh = ips(&["1.2.3.4"]);
        assert_eq!(conclude(&[], &doh, &doh), Conclusion::DnsInterference);
    }

    #[test]
    fn nothing_reachable_is_blocked_beyond_dns() {
        let addrs = ips(&["1.2.3.4"]);
        assert_eq!(conclude(&addrs, &addrs, &[]), Conclusion::BlockedBeyondDns);
    }

    #[test]
    fn no_answers_at_all_is_resolution_failure() {
        assert_eq!(conclude(&[], &[], &[]), Conclusion::ResolutionFailed);
    }

    #[test]
    fn different_but_working_addresses_are_not_flagged() {
        let isp = ips(&["1.2.3.4"]);
        let doh = ips(&["5.6.7.8"]);
        let reachable = ips(&["1.2.3.4", "5.6.7.8"]);
        assert_eq!(conclude(&isp, &doh, &reachable), Conclusion::DivergentButHealthy);
    }

    #[test]
    fn identifies_known_restriction_targets() {
        assert!(restriction_level(&"216.239.38.120".parse().unwrap())
            .is_some_and(|l| l.contains("strict")));
        assert!(restriction_level(&"216.239.38.119".parse().unwrap())
            .is_some_and(|l| l.contains("moderate")));
        assert!(restriction_level(&"2001:4860:4802:32::78".parse().unwrap()).is_some());
        assert!(restriction_level(&"2001:4860:4802:32::77".parse().unwrap()).is_some());
    }

    #[test]
    fn normal_youtube_addresses_are_not_flagged() {
        // The real frontends must never trip the detector, or every healthy
        // lookup would report a restriction.
        for ip in ["142.251.154.4", "142.250.206.14", "2001:4860:4827:400::"] {
            assert!(
                restriction_level(&ip.parse().unwrap()).is_none(),
                "{ip} must not be treated as a restriction target"
            );
        }
    }

    #[test]
    fn every_conclusion_has_an_explanation() {
        for c in [
            Conclusion::Healthy,
            Conclusion::DnsInterference,
            Conclusion::BlockedBeyondDns,
            Conclusion::ResolutionFailed,
            Conclusion::DivergentButHealthy,
            Conclusion::ContentRestrictionForced,
        ] {
            assert!(!c.explain().is_empty());
        }
    }
}
