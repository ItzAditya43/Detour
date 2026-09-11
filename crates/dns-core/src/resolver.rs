//! RFC 8484 DNS-over-HTTPS resolver with provider fallback and caching.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::cache::{Cache, Key};
use crate::provider::Provider;

const DNS_MESSAGE: &str = "application/dns-message";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CACHE_CAPACITY: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no DoH providers configured")]
    NoProviders,
    #[error("all {tried} provider(s) failed; last error: {source}")]
    AllProvidersFailed {
        tried: usize,
        #[source]
        source: Box<ResolveError>,
    },
    #[error("provider {provider} returned HTTP {status}")]
    HttpStatus { provider: String, status: u16 },
    #[error("provider {provider} returned content-type {content_type:?}, expected {DNS_MESSAGE}")]
    BadContentType { provider: String, content_type: Option<String> },
    #[error("transport error talking to {provider}: {source}")]
    Transport {
        provider: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("could not parse DNS response from {provider}: {source}")]
    Decode {
        provider: String,
        #[source]
        source: hickory_proto::error::ProtoError,
    },
    #[error("could not encode DNS query: {0}")]
    Encode(#[source] hickory_proto::error::ProtoError),
    #[error("provider {provider} has no usable https endpoint ({url})")]
    BadEndpoint { provider: String, url: String },
    #[error("failed to build HTTP client for {provider}: {source}")]
    ClientBuild {
        provider: String,
        #[source]
        source: reqwest::Error,
    },
}

/// One provider plus the HTTP client pinned to its bootstrap addresses.
struct Upstream {
    provider: Provider,
    client: reqwest::Client,
}

pub struct DohResolver {
    upstreams: Vec<Upstream>,
    cache: Arc<Mutex<Cache>>,
}

impl DohResolver {
    pub fn new(providers: Vec<Provider>) -> Result<Self, ResolveError> {
        Self::with_capacity(providers, DEFAULT_CACHE_CAPACITY)
    }

    pub fn with_capacity(
        providers: Vec<Provider>,
        cache_capacity: usize,
    ) -> Result<Self, ResolveError> {
        if providers.is_empty() {
            return Err(ResolveError::NoProviders);
        }

        let upstreams = providers
            .into_iter()
            .map(|provider| {
                let host = provider.host().ok_or_else(|| ResolveError::BadEndpoint {
                    provider: provider.name.clone(),
                    url: provider.url.clone(),
                })?;

                let mut builder = reqwest::Client::builder()
                    .timeout(DEFAULT_TIMEOUT)
                    .https_only(true)
                    .user_agent(concat!("dns-core/", env!("CARGO_PKG_VERSION")));

                // Pin the endpoint's addresses so the HTTP client never asks
                // the system resolver where its DoH server lives — which, once
                // we are the system resolver, would be a loop.
                let addrs = provider.bootstrap_addrs();
                if !addrs.is_empty() {
                    builder = builder.resolve_to_addrs(host, &addrs);
                }

                let client = builder.build().map_err(|source| ResolveError::ClientBuild {
                    provider: provider.name.clone(),
                    source,
                })?;
                Ok(Upstream { provider, client })
            })
            .collect::<Result<Vec<_>, ResolveError>>()?;

        Ok(Self {
            upstreams,
            cache: Arc::new(Mutex::new(Cache::new(cache_capacity))),
        })
    }

    pub fn cache(&self) -> Arc<Mutex<Cache>> {
        Arc::clone(&self.cache)
    }

    pub fn provider_names(&self) -> Vec<&str> {
        self.upstreams.iter().map(|u| u.provider.name.as_str()).collect()
    }

    /// Resolve a name, serving from cache when possible and otherwise trying
    /// each provider in order until one answers.
    pub async fn resolve(
        &self,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Message, ResolveError> {
        let key = Key::new(name.clone(), record_type);

        if let Some(hit) = self.cache.lock().expect("cache mutex poisoned").get(&key) {
            tracing::trace!(%name, ?record_type, "cache hit");
            return Ok(hit);
        }

        let query = build_query(name, record_type);
        let response = self.resolve_uncached(&query).await?;

        self.cache
            .lock()
            .expect("cache mutex poisoned")
            .insert(key, response.clone());

        Ok(response)
    }

    /// Forward an already-built query, bypassing the cache. The proxy uses this
    /// to pass a client's wire message through untouched.
    pub async fn resolve_uncached(&self, query: &Message) -> Result<Message, ResolveError> {
        let mut last: Option<ResolveError> = None;

        for upstream in &self.upstreams {
            match self.query_one(upstream, query).await {
                Ok(response) => {
                    // A provider that answers SERVFAIL has not really answered;
                    // give the next one a chance rather than passing the
                    // failure straight back to the game.
                    if response.response_code() == ResponseCode::ServFail {
                        tracing::debug!(
                            provider = %upstream.provider.name,
                            "SERVFAIL, trying next provider"
                        );
                        last = Some(ResolveError::HttpStatus {
                            provider: upstream.provider.name.clone(),
                            status: 502,
                        });
                        continue;
                    }
                    tracing::debug!(provider = %upstream.provider.name, "resolved");
                    return Ok(response);
                }
                Err(err) => {
                    tracing::debug!(
                        provider = %upstream.provider.name,
                        error = %err,
                        "provider failed, trying next"
                    );
                    last = Some(err);
                }
            }
        }

        Err(ResolveError::AllProvidersFailed {
            tried: self.upstreams.len(),
            source: Box::new(last.unwrap_or(ResolveError::NoProviders)),
        })
    }

    async fn query_one(
        &self,
        upstream: &Upstream,
        query: &Message,
    ) -> Result<Message, ResolveError> {
        let name = &upstream.provider.name;
        let body = query.to_vec().map_err(ResolveError::Encode)?;

        let response = upstream
            .client
            .post(&upstream.provider.url)
            .header(reqwest::header::CONTENT_TYPE, DNS_MESSAGE)
            .header(reqwest::header::ACCEPT, DNS_MESSAGE)
            .body(body)
            .send()
            .await
            .map_err(|source| ResolveError::Transport { provider: name.clone(), source })?;

        let status = response.status();
        if !status.is_success() {
            return Err(ResolveError::HttpStatus {
                provider: name.clone(),
                status: status.as_u16(),
            });
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        // A captive portal or interception box will happily return 200 with an
        // HTML body; refuse to parse that as DNS.
        if !content_type.as_deref().is_some_and(|c| c.starts_with(DNS_MESSAGE)) {
            return Err(ResolveError::BadContentType { provider: name.clone(), content_type });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|source| ResolveError::Transport { provider: name.clone(), source })?;

        Message::from_bytes(&bytes)
            .map_err(|source| ResolveError::Decode { provider: name.clone(), source })
    }
}

/// Build a standard recursive query. The ID is left at 0 as RFC 8484 §4.1
/// recommends, so that identical queries are byte-identical and cacheable by
/// intermediaries.
pub fn build_query(name: &Name, record_type: RecordType) -> Message {
    let mut message = Message::new();
    message
        .set_id(0)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    message.add_query(Query::query(name.clone(), record_type));
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::default_providers;
    use std::str::FromStr;

    #[test]
    fn build_query_sets_rfc8484_defaults() {
        let q = build_query(&Name::from_str("example.com.").unwrap(), RecordType::A);
        assert_eq!(q.id(), 0);
        assert!(q.recursion_desired());
        assert_eq!(q.message_type(), MessageType::Query);
        assert_eq!(q.queries().len(), 1);
        assert_eq!(q.queries()[0].query_type(), RecordType::A);
    }

    #[test]
    fn query_round_trips_through_wire_format() {
        let q = build_query(&Name::from_str("example.com.").unwrap(), RecordType::AAAA);
        let bytes = q.to_vec().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.queries()[0].name().to_string(), "example.com.");
        assert_eq!(decoded.queries()[0].query_type(), RecordType::AAAA);
    }

    #[test]
    fn rejects_empty_provider_list() {
        assert!(matches!(
            DohResolver::new(vec![]),
            Err(ResolveError::NoProviders)
        ));
    }

    #[test]
    fn rejects_provider_without_https_endpoint() {
        let bad = Provider::new("Bad", "http://insecure.example/dns-query", &["1.2.3.4"]);
        assert!(matches!(
            DohResolver::new(vec![bad]),
            Err(ResolveError::BadEndpoint { .. })
        ));
    }

    #[test]
    fn builds_with_default_providers() {
        let r = DohResolver::new(default_providers()).expect("resolver builds");
        assert_eq!(r.provider_names(), vec!["Cloudflare", "Quad9", "Google"]);
    }
}
