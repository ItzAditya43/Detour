//! Per-query routing policy: which names go to DoH, and which must stay on the
//! network's own resolver.
//!
//! Because this proxy sits in front of *all* system DNS, it cannot simply send
//! everything upstream. Names that only the local network knows about — your
//! router, `.local` discovery, reverse lookups for private ranges — would come
//! back NXDOMAIN from a public resolver.

use serde::{Deserialize, Serialize};

use hickory_proto::rr::Name;

/// Where a given query should be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Resolve over DNS-over-HTTPS.
    Doh,
    /// Forward to the resolver the system was using before we took over.
    SystemUpstream,
}

/// Suffixes that are meaningless to a public resolver and must be answered
/// locally. `home.arpa` (RFC 8375) and `.internal` are included alongside the
/// long-standing conventions.
const LOCAL_SUFFIXES: &[&str] = &[
    "local", "lan", "home", "home.arpa", "internal", "intranet", "localdomain", "localhost",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Default route for names matching nothing more specific.
    #[serde(default = "default_route_doh")]
    pub default_doh: bool,
    /// Suffixes forced onto DoH regardless of anything else. Game profile
    /// domains land here.
    #[serde(default)]
    pub force_doh: Vec<String>,
    /// Suffixes forced to the system resolver, on top of the built-in local set.
    #[serde(default)]
    pub force_local: Vec<String>,
}

fn default_route_doh() -> bool {
    true
}

impl Default for Policy {
    fn default() -> Self {
        Self { default_doh: true, force_doh: Vec::new(), force_local: Vec::new() }
    }
}

impl Policy {
    /// Decide where a query goes. Precedence, most specific first:
    /// explicit local override, built-in local names, explicit DoH override,
    /// then the default.
    pub fn route(&self, name: &Name) -> Route {
        let labels = normalise(name);

        if self.force_local.iter().any(|s| suffix_matches(&labels, s)) {
            return Route::SystemUpstream;
        }
        if is_builtin_local(&labels) {
            return Route::SystemUpstream;
        }
        if self.force_doh.iter().any(|s| suffix_matches(&labels, s)) {
            return Route::Doh;
        }
        if self.default_doh {
            Route::Doh
        } else {
            Route::SystemUpstream
        }
    }

    /// Replace the forced-DoH list, e.g. when a game profile is activated.
    pub fn set_force_doh(&mut self, domains: impl IntoIterator<Item = String>) {
        self.force_doh = domains.into_iter().map(|d| normalise_str(&d)).collect();
    }
}

/// Lower-cased, trailing-dot-stripped form used for all comparisons.
fn normalise(name: &Name) -> String {
    normalise_str(&name.to_ascii())
}

fn normalise_str(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

/// True when `name` is `suffix` itself or a subdomain of it. Compares whole
/// labels, so `notexample.com` does not match a `example.com` rule.
fn suffix_matches(name: &str, suffix: &str) -> bool {
    let suffix = normalise_str(suffix);
    if suffix.is_empty() {
        return false;
    }
    if let Some(stripped) = suffix.strip_prefix("*.") {
        // A leading wildcard means subdomains only, not the bare name.
        return name.len() > stripped.len()
            && name.ends_with(stripped)
            && name.as_bytes()[name.len() - stripped.len() - 1] == b'.';
    }
    name == suffix
        || (name.len() > suffix.len()
            && name.ends_with(&suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

fn is_builtin_local(name: &str) -> bool {
    if LOCAL_SUFFIXES.iter().any(|s| suffix_matches(name, s)) {
        return true;
    }
    // Single-label names are host names from the local network, not public.
    if !name.contains('.') {
        return true;
    }
    is_private_reverse(name)
}

/// Reverse-lookup zones for address ranges that are private by definition.
fn is_private_reverse(name: &str) -> bool {
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let octets: Vec<&str> = rest.split('.').collect();
        // Reversed order: the last label here is the first octet of the address.
        return match octets.as_slice() {
            [.., b, a] => match (a.parse::<u8>(), b.parse::<u8>()) {
                (Ok(10), _) => true,
                (Ok(192), Ok(168)) => true,
                (Ok(172), Ok(n)) if (16..=31).contains(&n) => true,
                (Ok(127), _) => true,
                (Ok(169), Ok(254)) => true,
                _ => false,
            },
            [a] => matches!(a.parse::<u8>(), Ok(10) | Ok(127)),
            _ => false,
        };
    }
    if name.ends_with(".ip6.arpa") {
        // fc00::/7 (unique local) and fe80::/10 (link local).
        let nibbles: Vec<&str> = name.trim_end_matches(".ip6.arpa").split('.').collect();
        if let [.., c, d] = nibbles.as_slice() {
            let prefix = format!("{d}{c}");
            return prefix.starts_with("fc")
                || prefix.starts_with("fd")
                || prefix.starts_with("fe8")
                || prefix.starts_with("fe9")
                || prefix.starts_with("fea")
                || prefix.starts_with("feb");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn route(policy: &Policy, host: &str) -> Route {
        policy.route(&Name::from_str(host).unwrap())
    }

    #[test]
    fn public_names_default_to_doh() {
        let p = Policy::default();
        assert_eq!(route(&p, "example.com."), Route::Doh);
        assert_eq!(route(&p, "cdn.example.co.uk."), Route::Doh);
    }

    /// Ordinary browsing is covered by the default policy with no profile,
    /// no domain list, and no per-site configuration. This is load-bearing:
    /// it is the reason YouTube and general web traffic need no setup, and a
    /// regression here would silently push browsing back onto the ISP path.
    #[test]
    fn ordinary_browsing_needs_no_configuration() {
        let p = Policy::default();
        assert!(p.force_doh.is_empty(), "no per-domain config should be required");

        for host in [
            "youtube.com.",
            "www.youtube.com.",
            "googlevideo.com.",
            "rr1---sn-4g5e6nsz.googlevideo.com.",
            "i.ytimg.com.",
            "yt3.ggpht.com.",
            "github.com.",
            "en.wikipedia.org.",
        ] {
            assert_eq!(route(&p, host), Route::Doh, "{host} must resolve over DoH");
        }
    }

    #[test]
    fn local_suffixes_stay_on_system_resolver() {
        let p = Policy::default();
        for host in ["printer.local.", "nas.lan.", "router.home.arpa.", "host.internal."] {
            assert_eq!(route(&p, host), Route::SystemUpstream, "{host}");
        }
    }

    #[test]
    fn single_label_names_stay_local() {
        let p = Policy::default();
        assert_eq!(route(&p, "router."), Route::SystemUpstream);
    }

    #[test]
    fn private_reverse_lookups_stay_local() {
        let p = Policy::default();
        for host in [
            "1.0.42.10.in-addr.arpa.",
            "5.1.168.192.in-addr.arpa.",
            "8.0.16.172.in-addr.arpa.",
            "1.0.0.127.in-addr.arpa.",
        ] {
            assert_eq!(route(&p, host), Route::SystemUpstream, "{host}");
        }
    }

    #[test]
    fn public_reverse_lookups_use_doh() {
        let p = Policy::default();
        assert_eq!(route(&p, "34.216.184.93.in-addr.arpa."), Route::Doh);
        // 172.32 is outside the private 172.16/12 block.
        assert_eq!(route(&p, "8.0.32.172.in-addr.arpa."), Route::Doh);
    }

    #[test]
    fn suffix_match_respects_label_boundary() {
        assert!(suffix_matches("cdn.example.com", "example.com"));
        assert!(suffix_matches("example.com", "example.com"));
        assert!(!suffix_matches("notexample.com", "example.com"));
        assert!(!suffix_matches("example.com.evil.test", "example.com"));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        assert!(suffix_matches("cdn.example.com", "*.example.com"));
        assert!(!suffix_matches("example.com", "*.example.com"));
    }

    #[test]
    fn force_local_beats_force_doh() {
        let p = Policy {
            default_doh: true,
            force_doh: vec!["example.com".into()],
            force_local: vec!["dev.example.com".into()],
        };
        assert_eq!(route(&p, "dev.example.com."), Route::SystemUpstream);
        assert_eq!(route(&p, "www.example.com."), Route::Doh);
    }

    #[test]
    fn force_doh_applies_when_default_is_local() {
        let mut p = Policy { default_doh: false, ..Default::default() };
        p.set_force_doh(["Example.COM.".to_string()]);
        assert_eq!(route(&p, "cdn.example.com."), Route::Doh);
        assert_eq!(route(&p, "other.test."), Route::SystemUpstream);
    }
}
