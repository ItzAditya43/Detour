//! DoH provider definitions.
//!
//! Every provider carries literal bootstrap IPs alongside its URL. Once this
//! machine's `resolv.conf` points at our own proxy, resolving a provider
//! hostname the normal way would recurse straight back into us, so the HTTP
//! client is told the address up front and never performs a lookup.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    /// Human-readable name, shown in the UI and logs.
    pub name: String,
    /// RFC 8484 endpoint, e.g. `https://cloudflare-dns.com/dns-query`.
    pub url: String,
    /// Literal addresses for the endpoint's host, used to bypass resolution.
    pub bootstrap: Vec<IpAddr>,
}

impl Provider {
    pub fn new(name: &str, url: &str, bootstrap: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            bootstrap: bootstrap.iter().filter_map(|s| s.parse().ok()).collect(),
        }
    }

    /// Host component of the endpoint URL, used as the pinning key.
    pub fn host(&self) -> Option<&str> {
        let rest = self.url.strip_prefix("https://")?;
        let end = rest.find(['/', ':']).unwrap_or(rest.len());
        Some(&rest[..end])
    }

    /// Bootstrap addresses paired with port 443, ready for `reqwest`'s resolver
    /// override.
    pub fn bootstrap_addrs(&self) -> Vec<SocketAddr> {
        self.bootstrap.iter().map(|ip| SocketAddr::new(*ip, 443)).collect()
    }

    pub fn cloudflare() -> Self {
        Self::new(
            "Cloudflare",
            "https://cloudflare-dns.com/dns-query",
            &["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"],
        )
    }

    pub fn google() -> Self {
        Self::new(
            "Google",
            "https://dns.google/dns-query",
            &["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"],
        )
    }

    pub fn quad9() -> Self {
        Self::new(
            "Quad9",
            "https://dns.quad9.net/dns-query",
            &["9.9.9.9", "149.112.112.112"],
        )
    }

    /// Blocks ads and trackers at the DNS level.
    pub fn adguard() -> Self {
        Self::new(
            "AdGuard",
            "https://dns.adguard-dns.com/dns-query",
            &["94.140.14.14", "94.140.15.15"],
        )
    }

    pub fn mullvad() -> Self {
        Self::new("Mullvad", "https://dns.mullvad.net/dns-query", &["194.242.2.2"])
    }
}

/// Providers offered as one-click choices in the settings page. Each was
/// checked to answer over DoH when pinned to its bootstrap address.
///
/// Deliberately excludes "family" variants: those enforce SafeSearch and
/// YouTube Restricted Mode, the opposite of what this tool is for.
pub fn presets() -> Vec<Provider> {
    vec![
        Provider::cloudflare(),
        Provider::quad9(),
        Provider::google(),
        Provider::adguard(),
        Provider::mullvad(),
    ]
}

/// Default chain: the first entry is tried first, the rest are fallbacks in
/// order. Deliberately spans three operators — if one is unreachable because of
/// the very interference this tool exists to route around, the next is not
/// under the same administrative control.
pub fn default_providers() -> Vec<Provider> {
    vec![Provider::cloudflare(), Provider::quad9(), Provider::google()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host_from_url() {
        assert_eq!(Provider::cloudflare().host(), Some("cloudflare-dns.com"));
        assert_eq!(Provider::google().host(), Some("dns.google"));
        assert_eq!(
            Provider::new("p", "https://example.com:8443/dns-query", &[]).host(),
            Some("example.com")
        );
        assert_eq!(
            Provider::new("p", "https://example.com", &[]).host(),
            Some("example.com")
        );
    }

    #[test]
    fn rejects_non_https_endpoint() {
        assert_eq!(Provider::new("p", "http://example.com/dns-query", &[]).host(), None);
    }

    #[test]
    fn bootstrap_addrs_use_https_port() {
        let addrs = Provider::cloudflare().bootstrap_addrs();
        assert!(addrs.iter().all(|a| a.port() == 443));
        assert!(addrs.iter().any(|a| a.ip().to_string() == "1.1.1.1"));
    }

    #[test]
    fn malformed_bootstrap_entries_are_dropped() {
        let p = Provider::new("p", "https://example.com/dns-query", &["1.1.1.1", "not-an-ip"]);
        assert_eq!(p.bootstrap.len(), 1);
    }
}
