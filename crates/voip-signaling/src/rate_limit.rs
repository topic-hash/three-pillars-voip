//! Simple token-bucket rate limiter.
//!
//! Limits from spec/11 §11.3:
//!   - 10 calls / minute
//!   - 6 registrations / minute
//!   - 30 WebSocket messages / second

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tracing::warn;

/// Configuration for a single token-bucket.
#[derive(Debug, Clone)]
pub struct BucketConfig {
    /// Maximum number of tokens the bucket can hold.
    pub max_tokens: u32,
    /// How many tokens are refilled per refill interval.
    pub refill_amount: u32,
    /// Refill interval in milliseconds.
    pub refill_interval_ms: u64,
}

impl BucketConfig {
    /// Calls: 10 per minute → refill 10 every 60 000 ms.
    pub const CALLS: BucketConfig = BucketConfig {
        max_tokens: 10,
        refill_amount: 10,
        refill_interval_ms: 60_000,
    };

    /// Registrations: 6 per minute → refill 6 every 60 000 ms.
    pub const REGISTRATIONS: BucketConfig = BucketConfig {
        max_tokens: 6,
        refill_amount: 6,
        refill_interval_ms: 60_000,
    };

    /// WebSocket messages: 30 per second → refill 30 every 1 000 ms.
    pub const WS_MESSAGES: BucketConfig = BucketConfig {
        max_tokens: 30,
        refill_amount: 30,
        refill_interval_ms: 1_000,
    };
}

/// A single token bucket for one key (peer_id / IP).
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    config: BucketConfig,
}

impl Bucket {
    fn new(config: BucketConfig) -> Self {
        Self {
            tokens: config.max_tokens as f64,
            last_refill: Instant::now(),
            config,
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one.
    /// Returns `true` if the request is allowed.
    fn try_consume(&mut self, count: u32) -> bool {
        self.refill();
        if self.tokens >= count as f64 {
            self.tokens -= count as f64;
            true
        } else {
            false
        }
    }

    /// Refill tokens proportionally to elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_millis() as u64;
        if elapsed >= self.config.refill_interval_ms {
            let intervals = elapsed / self.config.refill_interval_ms;
            let added = intervals as f64 * self.config.refill_amount as f64;
            self.tokens = (self.tokens + added).min(self.config.max_tokens as f64);
            self.last_refill = now;
        }
    }
}

/// A collection of named rate-limiters, each keyed by peer ID or IP.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<RateLimiterInner>>,
}

#[derive(Debug)]
struct RateLimiterInner {
    /// Per-peer call rate buckets.
    calls: HashMap<String, Bucket>,
    /// Per-peer registration rate buckets.
    registrations: HashMap<String, Bucket>,
    /// Per-peer WebSocket message rate buckets.
    ws_messages: HashMap<String, Bucket>,
    /// Configuration.
    config: RateLimitConfig,
    /// Maximum number of entries per bucket map before eviction.
    max_entries: usize,
}

/// Top-level rate-limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub calls: BucketConfig,
    pub registrations: BucketConfig,
    pub ws_messages: BucketConfig,
    /// Maximum number of entries per rate-limit map before eviction.
    pub max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            calls: BucketConfig::CALLS,
            registrations: BucketConfig::REGISTRATIONS,
            ws_messages: BucketConfig::WS_MESSAGES,
            max_entries: 50_000,
        }
    }
}

/// Actions that can be rate-limited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Action {
    Call,
    Registration,
    WsMessage,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let max_entries = config.max_entries;
        Self {
            inner: Arc::new(Mutex::new(RateLimiterInner {
                calls: HashMap::new(),
                registrations: HashMap::new(),
                ws_messages: HashMap::new(),
                config,
                max_entries,
            })),
        }
    }

    /// Check whether a call request is allowed for the given peer.
    /// Returns `true` if the request should proceed, `false` if rate-limited.
    pub async fn check_call(&self, peer_id: &str) -> bool {
        let mut inner = self.inner.lock().await;
        let config = inner.config.calls.clone();
        let bucket = inner
            .calls
            .entry(peer_id.to_owned())
            .or_insert_with(|| Bucket::new(config));
        let allowed = bucket.try_consume(1);
        if !allowed {
            warn!(peer_id, "call rate limit exceeded");
        }
        allowed
    }

    /// Check whether a registration request is allowed for the given peer.
    pub async fn check_registration(&self, peer_id: &str) -> bool {
        let mut inner = self.inner.lock().await;
        let config = inner.config.registrations.clone();
        let bucket = inner
            .registrations
            .entry(peer_id.to_owned())
            .or_insert_with(|| Bucket::new(config));
        let allowed = bucket.try_consume(1);
        if !allowed {
            warn!(peer_id, "registration rate limit exceeded");
        }
        allowed
    }

    /// Check whether a WebSocket message is allowed for the given peer.
    pub async fn check_ws_message(&self, peer_id: &str) -> bool {
        let mut inner = self.inner.lock().await;
        let config = inner.config.ws_messages.clone();
        let bucket = inner
            .ws_messages
            .entry(peer_id.to_owned())
            .or_insert_with(|| Bucket::new(config));
        let allowed = bucket.try_consume(1);
        if !allowed {
            warn!(peer_id, "WS message rate limit exceeded");
        }
        allowed
    }

    /// Generic check based on action type.
    #[allow(dead_code)]
    pub async fn check(&self, peer_id: &str, action: Action) -> bool {
        match action {
            Action::Call => self.check_call(peer_id).await,
            Action::Registration => self.check_registration(peer_id).await,
            Action::WsMessage => self.check_ws_message(peer_id).await,
        }
    }

    /// Remove rate-limit state for a disconnected peer.
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.calls.remove(peer_id);
        inner.registrations.remove(peer_id);
        inner.ws_messages.remove(peer_id);
    }

    /// Evict stale buckets and enforce the max-entries cap.
    ///
    /// Buckets whose last refill was more than two refill intervals ago
    /// are considered stale and removed. If a map still exceeds
    /// `max_entries` after stale eviction, the oldest entries (by
    /// insertion order) are dropped.
    pub async fn cleanup(&self) {
        let mut inner = self.inner.lock().await;
        let max = inner.config.max_entries;
        Self::cleanup_map(&mut inner.calls, max);
        Self::cleanup_map(&mut inner.registrations, max);
        Self::cleanup_map(&mut inner.ws_messages, max);
    }

    /// Evict stale and overflow entries from a single rate-limit map.
    fn cleanup_map(map: &mut HashMap<String, Bucket>, max: usize) {
        map.retain(|_, bucket| {
            let now = Instant::now();
            let elapsed = now.duration_since(bucket.last_refill).as_millis() as u64;
            elapsed < bucket.config.refill_interval_ms * 2
        });
        while map.len() > max {
            if let Some(key) = map.keys().next().cloned() {
                map.remove(&key);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_within_limit() {
        let config = BucketConfig {
            max_tokens: 3,
            refill_amount: 3,
            refill_interval_ms: 1000,
        };
        let mut bucket = Bucket::new(config);
        assert!(bucket.try_consume(1));
        assert!(bucket.try_consume(1));
        assert!(bucket.try_consume(1));
    }

    #[test]
    fn bucket_rejects_over_limit() {
        let config = BucketConfig {
            max_tokens: 2,
            refill_amount: 2,
            refill_interval_ms: 1000,
        };
        let mut bucket = Bucket::new(config);
        assert!(bucket.try_consume(1));
        assert!(bucket.try_consume(1));
        assert!(!bucket.try_consume(1));
    }
}
