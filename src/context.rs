// Shardnet - Serverless peer-to-peer encrypted file storage and messaging
// Copyright (C) 2026 Anthony Clicheroux
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::net::{SocketAddr, IpAddr};
use std::collections::{HashMap, HashSet};
use tokio::sync::{RwLock, Semaphore, Mutex, broadcast};
use std::time::Instant;
use quinn::{Endpoint, ServerConfig, ClientConfig, Connection, TransportConfig};
use tracing::{info, warn};

use ed25519_dalek::SigningKey;

use crate::identity;
use crate::dht::{RoutingTable, NodeId};
use crate::storage::LocalStorage;
use crate::error::Result;
use crate::config::{ShardConfig, StorageConfig};
use crate::events::ShardEvent;

#[cfg(unix)]
use rlimit::{getrlimit, Resource};

pub const MAX_PACKET_SIZE: usize = 10 * 1024 * 1024;

pub struct MessageCache {
    pub current: HashSet<Vec<u8>>,
    pub previous: HashSet<Vec<u8>>,
}

impl MessageCache {
    pub fn new() -> Self {
        Self { current: HashSet::new(), previous: HashSet::new() }
    }
    pub fn try_insert(&mut self, hash: Vec<u8>) -> bool {
        if self.current.contains(&hash) || self.previous.contains(&hash) { return false; }
        self.current.insert(hash);
        true
    }
    pub fn rotate(&mut self) {
        self.previous = std::mem::take(&mut self.current);
    }
}

struct ClientBucket {
    tokens: f32,
    last_update: Instant,
}

pub struct RateLimiter {
    buckets: HashMap<IpAddr, ClientBucket>,
    capacity: f32,
    refill_rate: f32,
    cleanup_interval: u64,
}

impl RateLimiter {
    pub fn new(capacity: f32, refill_rate: f32, cleanup_interval: u64) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            refill_rate,
            cleanup_interval
        }
    }

    pub fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let bucket = self.buckets.entry(ip).or_insert(ClientBucket {
            tokens: self.capacity,
            last_update: now,
        });

        let elapsed = now.duration_since(bucket.last_update).as_secs_f32();
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.capacity);
            bucket.last_update = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let limit = self.cleanup_interval;
        self.buckets.retain(|_, v| now.duration_since(v.last_update).as_secs() < limit);
    }
}

pub struct InnerNode {
    pub config: ShardConfig,
    pub storage_config: RwLock<StorageConfig>,
    pub id: NodeId,
    pub signing_key: SigningKey,
    pub routing_table: RwLock<RoutingTable>,
    pub storage: LocalStorage,
    pub connections: RwLock<HashMap<SocketAddr, Connection>>,
    pub conn_semaphore: Arc<Semaphore>,
    pub active_room: RwLock<Option<String>>,
    pub seen_messages: RwLock<MessageCache>,
    pub public_address: RwLock<Option<SocketAddr>>,
    pub pending_stun_nonce: RwLock<Option<u64>>,
    /// Nodes received via DHT responses, not yet verified by a direct TLS handshake.
    pub unverified_hints: RwLock<HashMap<SocketAddr, crate::dht::Node>>,
    pub rate_limiter: Mutex<RateLimiter>,
    /// Per-destination relay rate limiter — prevents one upstream connection from amplifying
    /// traffic toward many targets.
    pub relay_limiter: Mutex<RateLimiter>,
    pub event_bus: broadcast::Sender<ShardEvent>,
    /// Set by POST /api/sleep when the app goes to background; cleared by POST /api/wake.
    /// Background tasks check this flag to reduce their activity.
    pub sleeping: AtomicBool,
}

#[derive(Clone)]
pub struct Node {
    pub endpoint: Endpoint,
    pub inner: Arc<InnerNode>,
}

impl Node {
    pub async fn new(config: ShardConfig, bind_address: &str, storage_path: &str, _password: &str) -> Result<Self> {
        let storage = LocalStorage::new(storage_path, config.storage.max_storage_bytes)?;

        let (tls_server_config, client_config, node_id, signing_key) = identity::configure_quic_tls(
            storage_path,
            &config.security,
            config.mining.difficulty,
        )?;

        let mut transport_config = TransportConfig::default();
        // 120s to tolerate Android Doze CPU suspensions without dropping peers.
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(120).try_into().unwrap()));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

        let os_limit = detect_os_limit();
        let config_limit = config.limits.max_concurrent_connections;
        let final_limit = if config_limit > os_limit {
            warn!("Configured connection limit ({}) exceeds OS limit ({}). Capping.", config_limit, os_limit);
            os_limit
        } else {
            config_limit
        };

        transport_config.max_concurrent_uni_streams((final_limit as u32).into());

        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_server_config))?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(transport_config));

        let addr: SocketAddr = bind_address.parse()?;
        let mut endpoint = Endpoint::server(server_config, addr)?;

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_config))?;
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic_client_config)));

        let rate_limiter = RateLimiter::new(
            config.limits.rate_limit_capacity,
            config.limits.rate_limit_refill_per_sec,
            config.limits.rate_limit_cleanup_sec
        );

        // Init event bus
        let (tx, _rx) = broadcast::channel(100);

        let storage_config = config.storage.clone();
        let inner = Arc::new(InnerNode {
            storage_config: RwLock::new(storage_config),
            config,
            id: node_id,
            signing_key,
            routing_table: RwLock::new(RoutingTable::new(node_id)),
            storage,
            connections: RwLock::new(HashMap::new()),
            conn_semaphore: Arc::new(Semaphore::new(final_limit)),
            active_room: RwLock::new(None),
            seen_messages: RwLock::new(MessageCache::new()),
            public_address: RwLock::new(None),
            pending_stun_nonce: RwLock::new(None),
            unverified_hints: RwLock::new(HashMap::new()),
            rate_limiter: Mutex::new(rate_limiter),
            relay_limiter: Mutex::new(RateLimiter::new(5.0, 2.0, 300)),
            event_bus: tx,
            sleeping: AtomicBool::new(false),
        });

        info!(node_id = %hex::encode(node_id.0), "Node initialized");

        Ok(Self { endpoint, inner })
    }

    pub fn id(&self) -> NodeId { self.inner.id }

    pub fn emit(&self, event: ShardEvent) {
        let _ = self.inner.event_bus.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ShardEvent> {
        self.inner.event_bus.subscribe()
    }
}

fn detect_os_limit() -> usize {
    #[cfg(unix)]
    {
        match getrlimit(Resource::NOFILE) {
            Ok((soft, _)) => {
                let safe_limit = (soft as f64 * 0.8) as usize;
                std::cmp::max(50, safe_limit)
            },
            Err(e) => {
                warn!("Failed to query OS limits: {}. Defaulting to 100.", e);
                100
            }
        }
    }
    #[cfg(not(unix))]
    100
}
