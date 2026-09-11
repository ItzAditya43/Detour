//! TTL-respecting response cache.
//!
//! Entries expire on the minimum TTL across the answer section, and TTLs are
//! counted down on the way out so a client never sees a value that grows
//! stale-but-fresh-looking the longer it sits here.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

/// Ceiling applied to upstream TTLs, so a provider handing out a multi-day TTL
/// can't pin a CDN address here long after it stops working.
pub const MAX_TTL: Duration = Duration::from_secs(3600);
/// Floor, to keep a near-zero TTL from making the cache useless under load.
pub const MIN_TTL: Duration = Duration::from_secs(5);
/// Fixed lifetime for negative (NXDOMAIN / empty) answers.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub name: Name,
    pub record_type: RecordType,
}

impl Key {
    pub fn new(name: Name, record_type: RecordType) -> Self {
        // DNS names are case-insensitive; normalise so `Example.com` and
        // `example.com` share one entry.
        Self { name: name.to_lowercase(), record_type }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    message: Message,
    stored_at: Instant,
    ttl: Duration,
}

#[derive(Debug, Default)]
pub struct Cache {
    entries: HashMap<Key, Entry>,
    capacity: usize,
}

impl Cache {
    pub fn new(capacity: usize) -> Self {
        Self { entries: HashMap::new(), capacity }
    }

    /// Look up a cached response, with all TTLs decremented by the time spent
    /// here. Returns `None` once the entry has expired.
    pub fn get(&self, key: &Key) -> Option<Message> {
        self.get_at(key, Instant::now())
    }

    fn get_at(&self, key: &Key, now: Instant) -> Option<Message> {
        let entry = self.entries.get(key)?;
        let elapsed = now.saturating_duration_since(entry.stored_at);
        let remaining = entry.ttl.checked_sub(elapsed)?;
        if remaining.is_zero() {
            return None;
        }

        let mut message = entry.message.clone();
        let spent = elapsed.as_secs() as u32;
        for record in message.answers_mut() {
            record.set_ttl(record.ttl().saturating_sub(spent));
        }
        for record in message.name_servers_mut() {
            record.set_ttl(record.ttl().saturating_sub(spent));
        }
        Some(message)
    }

    /// Store a response. Returns the lifetime it was given, or `None` if the
    /// response was not cacheable.
    pub fn insert(&mut self, key: Key, message: Message) -> Option<Duration> {
        self.insert_at(key, message, Instant::now())
    }

    fn insert_at(&mut self, key: Key, message: Message, now: Instant) -> Option<Duration> {
        let ttl = cacheable_ttl(&message)?;

        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            self.evict_one(now);
        }
        self.entries.insert(key, Entry { message, stored_at: now, ttl });
        Some(ttl)
    }

    /// Drop the entry closest to expiry. Cheaper than maintaining LRU order,
    /// and for a DNS cache "expires soonest" is the more useful victim anyway.
    fn evict_one(&mut self, now: Instant) {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.ttl.saturating_sub(now.saturating_duration_since(e.stored_at)))
            .map(|(k, _)| k.clone());
        if let Some(k) = victim {
            self.entries.remove(&k);
        }
    }

    /// Remove expired entries. Called periodically by the proxy.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|_, e| e.ttl > now.saturating_duration_since(e.stored_at));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Decide how long a response may be held, clamped into `[MIN_TTL, MAX_TTL]`.
fn cacheable_ttl(message: &Message) -> Option<Duration> {
    match message.response_code() {
        ResponseCode::NoError => {}
        // A name that genuinely does not exist is worth remembering briefly.
        ResponseCode::NXDomain => return Some(NEGATIVE_TTL),
        // Anything else is a transient upstream failure; never cache it, or a
        // momentary blip becomes a sticky outage.
        _ => return None,
    }

    if message.answers().is_empty() {
        return Some(NEGATIVE_TTL);
    }

    let min = message.answers().iter().map(|r| r.ttl()).min()?;
    Some(Duration::from_secs(u64::from(min)).clamp(MIN_TTL, MAX_TTL))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{rdata::A, RData, Record};
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    fn response_with_ttl(host: &str, ttl: u32) -> Message {
        let mut m = Message::new();
        m.set_response_code(ResponseCode::NoError);
        m.add_answer(Record::from_rdata(
            name(host),
            ttl,
            RData::A(A::new(93, 184, 216, 34)),
        ));
        m
    }

    fn key(host: &str) -> Key {
        Key::new(name(host), RecordType::A)
    }

    #[test]
    fn stores_and_retrieves() {
        let mut cache = Cache::new(16);
        cache.insert(key("example.com."), response_with_ttl("example.com.", 300));
        let got = cache.get(&key("example.com.")).expect("entry present");
        assert_eq!(got.answers().len(), 1);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let mut cache = Cache::new(16);
        cache.insert(key("Example.COM."), response_with_ttl("example.com.", 300));
        assert!(cache.get(&key("example.com.")).is_some());
    }

    #[test]
    fn entry_expires_after_ttl() {
        let mut cache = Cache::new(16);
        let start = Instant::now();
        cache.insert_at(key("example.com."), response_with_ttl("example.com.", 30), start);

        let mid = start + Duration::from_secs(10);
        assert!(cache.get_at(&key("example.com."), mid).is_some());

        let after = start + Duration::from_secs(31);
        assert!(cache.get_at(&key("example.com."), after).is_none());
    }

    #[test]
    fn ttl_counts_down_while_cached() {
        let mut cache = Cache::new(16);
        let start = Instant::now();
        cache.insert_at(key("example.com."), response_with_ttl("example.com.", 300), start);

        let later = start + Duration::from_secs(100);
        let got = cache.get_at(&key("example.com."), later).unwrap();
        assert_eq!(got.answers()[0].ttl(), 200);
    }

    #[test]
    fn ttl_is_clamped_to_max() {
        let mut cache = Cache::new(16);
        let ttl = cache
            .insert(key("example.com."), response_with_ttl("example.com.", 86_400))
            .unwrap();
        assert_eq!(ttl, MAX_TTL);
    }

    #[test]
    fn ttl_is_clamped_to_min() {
        let mut cache = Cache::new(16);
        let ttl = cache
            .insert(key("example.com."), response_with_ttl("example.com.", 1))
            .unwrap();
        assert_eq!(ttl, MIN_TTL);
    }

    #[test]
    fn servfail_is_not_cached() {
        let mut cache = Cache::new(16);
        let mut m = Message::new();
        m.set_response_code(ResponseCode::ServFail);
        assert!(cache.insert(key("example.com."), m).is_none());
        assert!(cache.get(&key("example.com.")).is_none());
    }

    #[test]
    fn nxdomain_gets_negative_ttl() {
        let mut cache = Cache::new(16);
        let mut m = Message::new();
        m.set_response_code(ResponseCode::NXDomain);
        assert_eq!(cache.insert(key("nope.invalid."), m), Some(NEGATIVE_TTL));
    }

    #[test]
    fn evicts_when_over_capacity() {
        let mut cache = Cache::new(2);
        let start = Instant::now();
        // Shortest TTL should be the one dropped.
        cache.insert_at(key("a.test."), response_with_ttl("a.test.", 600), start);
        cache.insert_at(key("b.test."), response_with_ttl("b.test.", 10), start);
        cache.insert_at(key("c.test."), response_with_ttl("c.test.", 600), start);

        assert_eq!(cache.len(), 2);
        assert!(cache.get_at(&key("b.test."), start).is_none());
        assert!(cache.get_at(&key("a.test."), start).is_some());
        assert!(cache.get_at(&key("c.test."), start).is_some());
    }

    #[test]
    fn purge_drops_only_expired() {
        let mut cache = Cache::new(16);
        cache.insert(key("a.test."), response_with_ttl("a.test.", 600));
        cache.purge_expired();
        assert_eq!(cache.len(), 1);
    }
}
