use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use prism_core::ids::CgroupId;
use tokio::sync::RwLock;

use crate::metadata::{ContainerMeta, MetadataError, RuntimeProvider};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataCacheConfig {
    capacity: usize,
    ttl: Duration,
}

impl MetadataCacheConfig {
    #[must_use]
    pub const fn new(capacity: usize, ttl: Duration) -> Self {
        Self { capacity, ttl }
    }

    #[must_use]
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    #[must_use]
    pub const fn ttl(self) -> Duration {
        self.ttl
    }
}

impl Default for MetadataCacheConfig {
    fn default() -> Self {
        Self {
            capacity: 4_096,
            ttl: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MetadataCacheCounters {
    hits: u64,
    misses: u64,
    stale: u64,
    evictions: u64,
}

impl MetadataCacheCounters {
    #[must_use]
    pub const fn hits(self) -> u64 {
        self.hits
    }

    #[must_use]
    pub const fn misses(self) -> u64 {
        self.misses
    }

    #[must_use]
    pub const fn stale(self) -> u64 {
        self.stale
    }

    #[must_use]
    pub const fn evictions(self) -> u64 {
        self.evictions
    }
}

#[derive(Debug)]
pub struct MetadataCache<P> {
    provider: P,
    config: MetadataCacheConfig,
    state: RwLock<CacheState>,
}

impl<P> MetadataCache<P>
where
    P: RuntimeProvider,
{
    #[must_use]
    pub fn new(provider: P, config: MetadataCacheConfig) -> Self {
        Self {
            provider,
            config,
            state: RwLock::new(CacheState::with_capacity(config.capacity())),
        }
    }

    /// Resolves metadata through a bounded cache backed by the wrapped provider.
    ///
    /// # Errors
    ///
    /// Returns provider errors when the cache misses or an entry has expired.
    pub async fn resolve(
        &self,
        cgroup_id: CgroupId,
    ) -> Result<Option<ContainerMeta>, MetadataError> {
        let lookup = {
            let mut state = self.state.write().await;
            state.lookup(cgroup_id, self.config.ttl())
        };

        if let CacheLookup::Hit(meta) = lookup {
            return Ok(meta);
        }

        let meta = self.provider.resolve(cgroup_id).await?;
        let mut state = self.state.write().await;
        state.insert(cgroup_id, meta.clone(), self.config.capacity());
        Ok(meta)
    }

    pub async fn update(&self, meta: ContainerMeta) {
        let mut state = self.state.write().await;
        state.insert(meta.cgroup_id, Some(meta), self.config.capacity());
    }

    pub async fn invalidate(&self, cgroup_id: CgroupId) {
        let mut state = self.state.write().await;
        state.entries.remove(&cgroup_id);
    }

    pub async fn counters(&self) -> MetadataCacheCounters {
        self.state.read().await.counters
    }

    pub async fn len(&self) -> usize {
        self.state.read().await.entries.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.state.read().await.entries.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CacheLookup {
    Hit(Option<ContainerMeta>),
    Miss,
    Stale,
}

#[derive(Debug)]
struct CacheState {
    clock: u64,
    entries: HashMap<CgroupId, CacheEntry>,
    counters: MetadataCacheCounters,
}

impl CacheState {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            clock: 0,
            entries: HashMap::with_capacity(capacity),
            counters: MetadataCacheCounters::default(),
        }
    }

    fn lookup(&mut self, cgroup_id: CgroupId, ttl: Duration) -> CacheLookup {
        let clock = self.next_clock();
        let Some(entry) = self.entries.get_mut(&cgroup_id) else {
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss;
        };

        if entry.is_expired(Instant::now(), ttl) {
            self.counters.stale = self.counters.stale.saturating_add(1);
            self.counters.misses = self.counters.misses.saturating_add(1);
            self.entries.remove(&cgroup_id);
            return CacheLookup::Stale;
        }

        entry.last_used = clock;
        self.counters.hits = self.counters.hits.saturating_add(1);
        CacheLookup::Hit(entry.meta.clone())
    }

    fn insert(&mut self, cgroup_id: CgroupId, meta: Option<ContainerMeta>, capacity: usize) {
        if capacity == 0 {
            return;
        }

        let clock = self.next_clock();
        self.entries.insert(
            cgroup_id,
            CacheEntry {
                meta,
                inserted_at: Instant::now(),
                last_used: clock,
            },
        );
        self.evict_if_needed(capacity);
    }

    fn evict_if_needed(&mut self, capacity: usize) {
        while self.entries.len() > capacity {
            if let Some(cgroup_id) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(cgroup_id, _)| *cgroup_id)
            {
                self.entries.remove(&cgroup_id);
                self.counters.evictions = self.counters.evictions.saturating_add(1);
            }
        }
    }

    fn next_clock(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheEntry {
    meta: Option<ContainerMeta>,
    inserted_at: Instant,
    last_used: u64,
}

impl CacheEntry {
    fn is_expired(&self, now: Instant, ttl: Duration) -> bool {
        now.duration_since(self.inserted_at) >= ttl
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use tokio::{
        sync::{Notify, RwLock, mpsc},
        time::{sleep, timeout},
    };

    use super::*;
    use crate::metadata::RuntimeEvent;

    #[tokio::test]
    async fn cache_records_miss_then_hit() {
        let provider = MockProvider::new();
        let cgroup_id = CgroupId::new(7);
        provider.insert(meta(cgroup_id, "container-a")).await;
        let cache = MetadataCache::new(provider.clone(), MetadataCacheConfig::default());

        let first = cache.resolve(cgroup_id).await.expect("miss should resolve");
        let second = cache.resolve(cgroup_id).await.expect("hit should resolve");
        let counters = cache.counters().await;

        assert_eq!(first, second);
        assert_eq!(provider.resolve_calls(), 1);
        assert_eq!(counters.misses(), 1);
        assert_eq!(counters.hits(), 1);
    }

    #[tokio::test]
    async fn cache_updates_entry() {
        let provider = MockProvider::new();
        let cgroup_id = CgroupId::new(7);
        let cache = MetadataCache::new(provider, MetadataCacheConfig::default());

        cache.update(meta(cgroup_id, "container-a")).await;
        let resolved = cache.resolve(cgroup_id).await.expect("hit should resolve");

        assert_eq!(resolved, Some(meta(cgroup_id, "container-a")));
        assert_eq!(cache.counters().await.hits(), 1);
    }

    #[tokio::test]
    async fn cache_evicts_lru_entry() {
        let provider = MockProvider::new();
        provider.insert(meta(CgroupId::new(1), "one")).await;
        provider.insert(meta(CgroupId::new(2), "two")).await;
        provider.insert(meta(CgroupId::new(3), "three")).await;
        let cache = MetadataCache::new(
            provider.clone(),
            MetadataCacheConfig::new(2, Duration::from_secs(30)),
        );

        cache
            .resolve(CgroupId::new(1))
            .await
            .expect("first should resolve");
        cache
            .resolve(CgroupId::new(2))
            .await
            .expect("second should resolve");
        cache
            .resolve(CgroupId::new(3))
            .await
            .expect("third should resolve");

        assert_eq!(cache.len().await, 2);
        assert_eq!(cache.counters().await.evictions(), 1);
    }

    #[tokio::test]
    async fn cache_expires_stale_entries() {
        let provider = MockProvider::new();
        let cgroup_id = CgroupId::new(7);
        provider.insert(meta(cgroup_id, "container-a")).await;
        let cache = MetadataCache::new(
            provider.clone(),
            MetadataCacheConfig::new(16, Duration::from_millis(1)),
        );

        cache.resolve(cgroup_id).await.expect("miss should resolve");
        sleep(Duration::from_millis(5)).await;
        cache
            .resolve(cgroup_id)
            .await
            .expect("stale should resolve");
        let counters = cache.counters().await;

        assert_eq!(provider.resolve_calls(), 2);
        assert_eq!(counters.stale(), 1);
        assert_eq!(counters.misses(), 2);
    }

    #[tokio::test]
    async fn cache_invalidate_removes_entry() {
        let provider = MockProvider::new();
        let cgroup_id = CgroupId::new(7);
        provider.insert(meta(cgroup_id, "container-a")).await;
        let cache = MetadataCache::new(provider.clone(), MetadataCacheConfig::default());

        cache.resolve(cgroup_id).await.expect("miss should resolve");
        cache.invalidate(cgroup_id).await;
        cache
            .resolve(cgroup_id)
            .await
            .expect("second miss should resolve");

        assert_eq!(provider.resolve_calls(), 2);
    }

    #[tokio::test]
    async fn cache_does_not_hold_lock_across_provider_io() {
        let provider = GateProvider::new(Some(meta(CgroupId::new(7), "container-a")));
        let cache = Arc::new(MetadataCache::new(
            provider.clone(),
            MetadataCacheConfig::default(),
        ));
        let task_cache = Arc::clone(&cache);
        let task = tokio::spawn(async move { task_cache.resolve(CgroupId::new(7)).await });

        provider.wait_until_entered().await;
        let counters = timeout(Duration::from_millis(100), cache.counters())
            .await
            .expect("cache counters should not block on provider I/O");
        provider.release();
        task.await
            .expect("resolve task should join")
            .expect("provider should resolve");

        assert_eq!(counters.misses(), 1);
    }

    fn meta(cgroup_id: CgroupId, name: &str) -> ContainerMeta {
        ContainerMeta {
            cgroup_id,
            container_id: format!("id-{name}"),
            container_name: name.to_owned(),
            namespace: None,
            pod_name: None,
        }
    }

    #[derive(Debug, Clone)]
    struct MockProvider {
        metadata: Arc<RwLock<HashMap<CgroupId, ContainerMeta>>>,
        calls: Arc<AtomicUsize>,
    }

    impl MockProvider {
        fn new() -> Self {
            Self {
                metadata: Arc::new(RwLock::new(HashMap::new())),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        async fn insert(&self, meta: ContainerMeta) {
            self.metadata.write().await.insert(meta.cgroup_id, meta);
        }

        fn resolve_calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl RuntimeProvider for MockProvider {
        async fn resolve(
            &self,
            cgroup_id: CgroupId,
        ) -> Result<Option<ContainerMeta>, MetadataError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.metadata.read().await.get(&cgroup_id).cloned())
        }

        async fn watch_events(&self) -> Result<mpsc::Receiver<RuntimeEvent>, MetadataError> {
            let (_sender, receiver) = mpsc::channel(1);
            Ok(receiver)
        }
    }

    #[derive(Debug, Clone)]
    struct GateProvider {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        meta: Option<ContainerMeta>,
    }

    impl GateProvider {
        fn new(meta: Option<ContainerMeta>) -> Self {
            Self {
                entered: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
                meta,
            }
        }

        async fn wait_until_entered(&self) {
            self.entered.notified().await;
        }

        fn release(&self) {
            self.release.notify_waiters();
        }
    }

    #[async_trait]
    impl RuntimeProvider for GateProvider {
        async fn resolve(
            &self,
            _cgroup_id: CgroupId,
        ) -> Result<Option<ContainerMeta>, MetadataError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(self.meta.clone())
        }

        async fn watch_events(&self) -> Result<mpsc::Receiver<RuntimeEvent>, MetadataError> {
            let (_sender, receiver) = mpsc::channel(1);
            Ok(receiver)
        }
    }
}
