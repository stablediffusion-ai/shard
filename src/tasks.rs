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
use std::time::{Duration, SystemTime};
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tracing::{info, debug};
use tokio::time::sleep;

use rand::RngCore;
use crate::context::Node;
use crate::packet::{DspPacket, PacketType};

pub fn start_background_tasks(node: Node) {
    let n1 = node.clone();
    tokio::spawn(async move { run_storage_cleanup(n1).await; });

    let n2 = node.clone();
    tokio::spawn(async move { run_routing_table_maintenance(n2).await; });

    let n3 = node.clone();
    tokio::spawn(async move { run_stun_refresh(n3).await; });
}

// ── Storage cleanup ────────────────────────────────────────────────────────
async fn run_storage_cleanup(node: Node) {
    let root_path = node.inner.storage.root_path.clone();

    loop {
        let (interval, retention) = {
            let cfg = node.inner.storage_config.read().await;
            (Duration::from_secs(cfg.cleanup_interval_sec),
             Duration::from_secs(cfg.retention_period_sec))
        };
        sleep(interval).await;

        node.inner.storage.cleanup_expired(retention);

        let download_dir = Path::new(&root_path).join("downloads");
        if let Ok(entries) = fs::read_dir(download_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(age) = SystemTime::now().duration_since(modified) {
                            if age > retention {
                                let _ = fs::remove_file(entry.path());
                                debug!("Cleaned up old file: {:?}", entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Peer health proactif ───────────────────────────────────────────────────
// Grace 15s → first cycles run without eviction (DHT not yet stable).
// Cycle every 30s, ping timeout 1s.
// A peer is evicted after EVICT_THRESHOLD CONSECUTIVE failures to avoid
// evicting a temporarily slow node.
const EVICT_THRESHOLD: u8 = 3;

async fn run_routing_table_maintenance(node: Node) {
    info!("Peer Maintenance: grace period 15s…");
    sleep(Duration::from_secs(15)).await;

    // Consecutive failure counter per address
    let mut fail_counts: HashMap<SocketAddr, u8> = HashMap::new();

    loop {
        let peers = node.inner.routing_table.read().await.get_all_nodes();
        if !peers.is_empty() {
            debug!("Peer Maintenance: checking {} peers", peers.len());
        }

        let mut removed_count = 0;

        for peer in peers {
            sleep(Duration::from_millis(50)).await;

            let target_addr = crate::transport::resolve_peer_addr(&node, &peer).await;
            let pkt = DspPacket::new(PacketType::KeepAlive, 0, 0, vec![]);

            let alive = tokio::time::timeout(
                Duration::from_secs(1),
                node.send_packet(pkt, target_addr, Some(peer.id)),
            ).await.map(|r| r.is_ok()).unwrap_or(false);

            if alive {
                fail_counts.remove(&peer.address);
            } else {
                let count = fail_counts.entry(peer.address).or_insert(0);
                *count += 1;
                if *count >= EVICT_THRESHOLD {
                    debug!("Evicting unresponsive peer {} ({} failures)", peer.address, count);
                    node.remove_peer(peer.address).await;
                    fail_counts.remove(&peer.address);
                    removed_count += 1;
                }
            }
        }

        // Clean up orphaned entries (peers already evicted via other paths)
        let current_addrs: std::collections::HashSet<SocketAddr> = node
            .inner.routing_table.read().await
            .get_all_nodes().iter()
            .map(|n| n.address)
            .collect();
        fail_counts.retain(|addr, _| current_addrs.contains(addr));

        if removed_count > 0 {
            info!("Peer Maintenance: pruned {} zombie peers", removed_count);
            let _ = node.save_routing_table().await;
        }

        // ── Reconnection guard ─────────────────────────────────────────────
        // After evictions (or a cascade disconnect), check whether the routing
        // table is empty.  If hints survive, a single iterative_lookup is enough
        // to promote them back via TLS handshake.  If everything is gone, fall
        // back to the public seed then the local seed.
        let rt_empty    = node.inner.routing_table.read().await.get_all_nodes().is_empty();
        let hints_count = node.inner.unverified_hints.read().await.len();

        if rt_empty {
            if hints_count > 0 {
                debug!("Peer Maintenance: routing table empty — reconnecting from {} hint(s)", hints_count);
                node.iterative_lookup(node.inner.id, 2).await;
            } else {
                debug!("Peer Maintenance: fully isolated — re-bootstrapping to default seed");
                if let Ok(mut addrs) = tokio::net::lookup_host("shardnet.app:9100").await {
                    if let Some(addr) = addrs.next() {
                        let _ = node.bootstrap(addr).await;
                    }
                }
                // If the public seed is also unreachable, try a local instance.
                if node.inner.routing_table.read().await.get_all_nodes().is_empty() {
                    if let Ok(mut addrs) = tokio::net::lookup_host("127.0.0.1:9100").await {
                        if let Some(addr) = addrs.next() {
                            let _ = node.bootstrap(addr).await;
                        }
                    }
                }
            }
        }

        // In sleep mode (app backgrounded) slow down to 5 min to reduce QUIC traffic.
        let interval = if node.inner.sleeping.load(Ordering::Relaxed) {
            Duration::from_secs(300)
        } else {
            Duration::from_secs(30)
        };
        sleep(interval).await;
    }
}

// ── Periodic STUN refresh ──────────────────────────────────────────────────
// Re-checks the public IP every 60s by querying a known peer.
// Essential for nodes behind a NAT with a changing IP (4G, VPN, etc.).
async fn run_stun_refresh(node: Node) {
    sleep(Duration::from_secs(30)).await; // initial delay to let the node stabilise

    loop {
        let maybe_peer = {
            let table = node.inner.routing_table.read().await;
            table.get_all_nodes().into_iter().next()
        };

        // Skip STUN refresh when sleeping — no point updating public IP in background.
        if node.inner.sleeping.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(60)).await;
            continue;
        }

        if let Some(peer) = maybe_peer {
            let target = crate::transport::resolve_peer_addr(&node, &peer).await;
            let nonce = rand::rngs::OsRng.next_u64();
            *node.inner.pending_stun_nonce.write().await = Some(nonce);
            let pkt = DspPacket::new(PacketType::StunRequest, 0, 0, nonce.to_le_bytes().to_vec());
            let _ = node.send_packet(pkt, target, Some(peer.id)).await;
            debug!("STUN refresh sent to {}", target);
        }

        sleep(Duration::from_secs(60)).await;
    }
}
