//! Live tests against real DoH providers.
//!
//! These require working internet access, so they are `#[ignore]`d by default
//! and excluded from ordinary `cargo test` runs. Run them with:
//!
//! ```text
//! cargo test -p dns-core --test live_doh -- --ignored --nocapture
//! ```

use std::str::FromStr;

use dns_core::provider::Provider;
use dns_core::{default_providers, DohResolver};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};

fn name(s: &str) -> Name {
    Name::from_str(s).expect("valid name")
}

#[tokio::test]
#[ignore = "requires network"]
async fn resolves_a_record_via_cloudflare() {
    let resolver = DohResolver::new(vec![Provider::cloudflare()]).unwrap();
    let response = resolver
        .resolve(&name("example.com."), RecordType::A)
        .await
        .expect("cloudflare resolves example.com");

    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(!response.answers().is_empty(), "expected at least one A record");
    println!("cloudflare example.com -> {:?}", addresses(&response));
}

#[tokio::test]
#[ignore = "requires network"]
async fn resolves_a_record_via_google() {
    let resolver = DohResolver::new(vec![Provider::google()]).unwrap();
    let response = resolver
        .resolve(&name("cloudflare.com."), RecordType::A)
        .await
        .expect("google resolves cloudflare.com");

    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert!(!response.answers().is_empty());
    println!("google cloudflare.com -> {:?}", addresses(&response));
}

#[tokio::test]
#[ignore = "requires network"]
async fn resolves_aaaa_record() {
    let resolver = DohResolver::new(default_providers()).unwrap();
    let response = resolver
        .resolve(&name("example.com."), RecordType::AAAA)
        .await
        .expect("AAAA lookup succeeds");
    assert_eq!(response.response_code(), ResponseCode::NoError);
    println!("example.com AAAA -> {:?}", addresses(&response));
}

#[tokio::test]
#[ignore = "requires network"]
async fn nonexistent_name_returns_nxdomain() {
    let resolver = DohResolver::new(default_providers()).unwrap();
    let response = resolver
        .resolve(
            &name("this-name-should-not-exist-4f2a9c.invalid."),
            RecordType::A,
        )
        .await
        .expect("query completes");
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
}

#[tokio::test]
#[ignore = "requires network"]
async fn second_lookup_is_served_from_cache() {
    let resolver = DohResolver::new(default_providers()).unwrap();

    let first = std::time::Instant::now();
    resolver.resolve(&name("example.com."), RecordType::A).await.unwrap();
    let cold = first.elapsed();

    let second = std::time::Instant::now();
    resolver.resolve(&name("example.com."), RecordType::A).await.unwrap();
    let warm = second.elapsed();

    println!("cold {cold:?}, warm {warm:?}");
    assert!(
        warm < cold / 2,
        "cached lookup ({warm:?}) should be far faster than cold ({cold:?})"
    );
    assert_eq!(resolver.cache().lock().unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "requires network"]
async fn falls_back_when_first_provider_is_unreachable() {
    // A provider pinned to an address that cannot answer, so the first attempt
    // is guaranteed to fail and the chain must move on.
    let dead = Provider::new("Dead", "https://dead.invalid/dns-query", &["203.0.113.1"]);
    let resolver = DohResolver::new(vec![dead, Provider::cloudflare()]).unwrap();

    let response = resolver
        .resolve(&name("example.com."), RecordType::A)
        .await
        .expect("falls through to the working provider");
    assert!(!response.answers().is_empty());
}

#[tokio::test]
#[ignore = "requires network"]
async fn all_default_providers_answer() {
    for provider in default_providers() {
        let label = provider.name.clone();
        let resolver = DohResolver::new(vec![provider]).unwrap();
        let response = resolver
            .resolve(&name("example.com."), RecordType::A)
            .await
            .unwrap_or_else(|e| panic!("{label} failed: {e}"));
        println!("{label}: {:?}", addresses(&response));
        assert!(!response.answers().is_empty(), "{label} returned no answers");
    }
}

fn addresses(msg: &hickory_proto::op::Message) -> Vec<String> {
    msg.answers()
        .iter()
        .filter_map(|r| r.data().map(|d| d.to_string()))
        .collect()
}
