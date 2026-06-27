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
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn, debug};
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
use ed25519_dalek::Signer;

use crate::context::Node;
use crate::dht::NodeId;
use crate::packet::{DspPacket, PacketType, ChatMessage, DhtQueryPayload};
use crate::router;
use crate::tasks;
use crate::transfer;
use crate::handlers;
use crate::transport;
use crate::error::{Result, ShardError};
use crate::events::ShardEvent;

impl Node {
    pub async fn run(&self) -> Result<()> {
        while let Some(incoming) = self.endpoint.accept().await {
            let src_ip = incoming.remote_address().ip();

            // Loopback cannot be a DoS source — skip rate limiting for local test environments.
            if !src_ip.is_loopback() {
                let mut limiter: tokio::sync::MutexGuard<crate::context::RateLimiter> = self.inner.rate_limiter.lock().await;
                if !limiter.check(src_ip) {
                    warn!("Rate limit exceeded for {}. Dropping connection.", src_ip);
                    continue;
                }
            }

            let node = self.clone();
            let conn_permit = match node.inner.conn_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => continue,
            };

            tokio::spawn(async move {
                let _permit = conn_permit;
                match incoming.await {
                    Ok(connection) => {
                        transport::listen_on_connection(&node, connection);
                    },
                    Err(e) => {
                        debug!("Connection accept error: {}", e);
                    }
                }
            });
        }
        Ok(())
    }

    pub fn start_background_tasks(&self) {
        tasks::start_background_tasks(self.clone());
    }

    pub async fn bootstrap(&self, peer_addr: SocketAddr) -> Result<()> {
        let my_port = self.endpoint.local_addr().map(|s| s.port()).unwrap_or(0);
        let net_info = transport::detect_network_interfaces();
        let local_hint = net_info.local_lan.map(|ip| SocketAddr::new(ip, my_port));

        let q = DhtQueryPayload {
            node_id: self.inner.id.0.to_vec(),
            lan_address: local_hint,
        };
        let payload = bincode::serialize(&q)?;

        let pkt = DspPacket::new(PacketType::DhtQuery, 0, 0, payload);
        router::send_packet(self, pkt, peer_addr, None).await?;

        // Generate and store a nonce so handle_stun_response can validate the reply.
        let stun_nonce = rand::rngs::OsRng.next_u64();
        *self.inner.pending_stun_nonce.write().await = Some(stun_nonce);
        let pkt_ask = DspPacket::new(PacketType::StunRequest, 0, 0, stun_nonce.to_le_bytes().to_vec());
        let _ = router::send_packet(self, pkt_ask, peer_addr, None).await;

        // Wait for STUN + first DHT response before iterative lookup.
        // STUN must resolve public_address BEFORE resolve_peer_addr runs,
        // otherwise same-NAT peers don't get the LAN-preference optimization.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(800);
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if self.inner.public_address.read().await.is_some() { break; }
            if tokio::time::Instant::now() >= deadline { break; }
        }
        self.lookup_dht(self.inner.id).await;
        Ok(())
    }

    /// Iterative Kademlia lookup: contacts the closest nodes to `target_id`,
    /// awaits their responses, then repeats with newly discovered nodes.
    /// Repeats `rounds` times — the routing table stabilises after 2-3 rounds on a
    /// typical network.
    pub async fn iterative_lookup(&self, target_id: NodeId, rounds: u32) {
        let my_port = self.endpoint.local_addr().map(|s| s.port()).unwrap_or(0);
        let net_info = transport::detect_network_interfaces();
        let local_hint = net_info.local_lan.map(|ip| SocketAddr::new(ip, my_port));

        let q = DhtQueryPayload {
            node_id: self.inner.id.0.to_vec(),
            lan_address: local_hint,
        };
        let payload = bincode::serialize(&q).unwrap_or_default();

        let mut queried: HashSet<NodeId> = HashSet::new();

        for round in 0..rounds {
            // Read routing table first; if it is empty (e.g. first round after bootstrap
            // before any TLS handshake has completed), seed from unverified hints.
            // Sending a DhtQuery to a hint node triggers get_or_connect → TLS → promotion,
            // so subsequent rounds will find real routing-table entries.
            let candidates: Vec<crate::dht::Node> = {
                let table_nodes = {
                    let table = self.inner.routing_table.read().await;
                    table.find_closest_nodes(&target_id, crate::dht::K_PARAM)
                };
                if !table_nodes.is_empty() {
                    table_nodes
                } else {
                    let hint_nodes: Vec<_> = self.inner.unverified_hints.read().await.values().cloned().collect();
                    if !hint_nodes.is_empty() {
                        hint_nodes
                    } else {
                        // Last resort: active QUIC connections whose peer was never added to
                        // routing_table or hints (e.g. bootstrap target when seed has no peers).
                        // Use address-hash as a temporary NodeId — only used for the queried set.
                        self.inner.connections.read().await
                            .iter()
                            .filter(|(_, c)| c.close_reason().is_none())
                            .map(|(addr, _)| {
                                let mut h = Sha256::new();
                                h.update(addr.to_string().as_bytes());
                                let id: [u8; 32] = h.finalize().into();
                                crate::dht::Node { id: crate::dht::NodeId::new(id), address: *addr, lan_address: None, rtt_ms: 0 }
                            })
                            .collect()
                    }
                }
            };

            let to_query: Vec<_> = candidates.into_iter()
                .filter(|n| !queried.contains(&n.id))
                .collect();

            if to_query.is_empty() {
                debug!("iterative_lookup: table stable after {} round(s)", round);
                break;
            }

            let mut handles = Vec::new();
            for node in to_query {
                queried.insert(node.id);
                let resolved = transport::resolve_peer_addr(self, &node).await;
                let n = self.clone();
                let pkt = DspPacket::new(PacketType::DhtQuery, 0, 0, payload.clone());
                let nid = node.id;
                handles.push(tokio::spawn(async move {
                    let _ = router::send_packet(&n, pkt, resolved, Some(nid)).await;
                }));
            }

            for h in handles { let _ = h.await; }

            // Let async responses arrive and be processed by handle_dht_response
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let size = self.inner.routing_table.read().await.get_all_nodes().len();
        debug!("iterative_lookup done: {} nodes in routing table", size);
    }

    // Async-safe save with spawn_blocking
    pub async fn save_routing_table(&self) -> Result<()> {
        let nodes: Vec<crate::dht::Node> = self.inner.routing_table.read().await.get_all_nodes();
        let inner = self.inner.clone();

        tokio::task::spawn_blocking(move || {
            let path = Path::new(&inner.storage.root_path).join("sys").join("routing_table.bin");
            let data = bincode::serialize(&nodes)?;
            std::fs::write(path, data)?;
            Ok::<(), ShardError>(())
        })
        .await
        .map_err(|e| ShardError::Other(format!("Task join error: {}", e)))??;

        Ok(())
    }

    pub async fn load_routing_table(&self) -> Vec<SocketAddr> {
        let path = Path::new(&self.inner.storage.root_path).join("sys").join("routing_table.bin");
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(nodes) = bincode::deserialize::<Vec<crate::dht::Node>>(&bytes) {
                let mut table: tokio::sync::RwLockWriteGuard<crate::dht::RoutingTable> = self.inner.routing_table.write().await;
                let mut addrs = Vec::new();
                for node in nodes {
                    if handlers::is_global_address(node.address) {
                        addrs.push(node.address);
                        table.update(node);
                    }
                }
                return addrs;
            }
        }
        Vec::new()
    }

    pub async fn lookup_dht(&self, target_id: NodeId) -> Vec<crate::dht::Node> {
        self.iterative_lookup(target_id, 3).await;
        let table = self.inner.routing_table.read().await;
        table.find_closest_nodes(&target_id, crate::dht::K_PARAM)
    }

    pub async fn remove_peer(&self, addr: SocketAddr) {
        // 1. Remove from Active Connections (Quinn)
        {
            let mut conns = self.inner.connections.write().await;
            if conns.remove(&addr).is_some() {
                debug!("Connection dropped for {}", addr);
            }
        }

        // 2. Demote from routing table to unverified_hints instead of deleting.
        //    This preserves the peer's address so the next iterative_lookup can
        //    promote it back once the QUIC connection is re-established.
        {
            let demoted = self.inner.routing_table.write().await.remove_returning(&addr);
            if let Some(peer_node) = demoted {
                self.inner.unverified_hints.write().await.insert(addr, peer_node);
                debug!("Peer {} demoted to hints (connection dropped)", addr);
            }
        }
    }

    pub async fn resolve_peer_addr(&self, peer: &crate::dht::Node) -> SocketAddr {
        transport::resolve_peer_addr(self, peer).await
    }

    pub async fn send_packet(&self, packet: DspPacket, target: SocketAddr, target_id: Option<NodeId>) -> Result<()> {
        router::send_packet(self, packet, target, target_id).await
    }

    pub async fn send_packet_reliable(&self, packet: DspPacket, target: SocketAddr, target_id: Option<NodeId>) -> Result<()> {
        router::send_packet_reliable(self, packet, target, target_id).await
    }

    pub async fn send_file_stream(&self, path: &str) -> Result<([u8; 32], [u8; 32])> {
        transfer::send_file_stream(self, path).await
    }

    pub async fn fetch_file_stream(&self, file_id: [u8; 32], key: [u8; 32], output_path: &str) -> Result<()> {
        transfer::fetch_file_stream(self, file_id, key, output_path).await
    }

    pub async fn join_room(&self, name: String) {
        let mut lock = self.inner.active_room.write().await;
        *lock = Some(name.clone());
        info!("Joined room: '{}'", name);
    }

    pub async fn leave_room(&self) {
        let mut lock = self.inner.active_room.write().await;
        *lock = None;
        info!("Left current chat room");
    }

    pub async fn broadcast_chat(&self, content: String) -> Result<()> {
        let (room, nonce) = {
            let r_guard: tokio::sync::RwLockReadGuard<Option<String>> = self.inner.active_room.read().await;
            if let Some(r) = r_guard.as_ref() {
                (r.clone(), rand::rngs::OsRng.next_u64())
            } else {
                return Err(ShardError::Other("You must join a room first".to_string()));
            }
        };

        let sender_id = hex::encode(self.inner.id.0);
        let sender_pubkey = self.inner.signing_key.verifying_key().to_bytes().to_vec();

        // Canonical bytes: room || sender_id || nonce (LE) || content
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(room.as_bytes());
        to_sign.extend_from_slice(sender_id.as_bytes());
        to_sign.extend_from_slice(&nonce.to_le_bytes());
        to_sign.extend_from_slice(content.as_bytes());
        let signature = self.inner.signing_key.sign(&to_sign).to_bytes().to_vec();

        let chat_msg = ChatMessage {
            room_name: room,
            sender_id,
            content,
            nonce,
            sender_pubkey,
            signature,
        };

        let payload = bincode::serialize(&chat_msg)?;
        
        {
            let mut cache: tokio::sync::RwLockWriteGuard<crate::context::MessageCache> = self.inner.seen_messages.write().await;
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            cache.try_insert(hasher.finalize().to_vec());
        }

        // Emit locally so the sender's own subscribers (e.g. GUI WebSocket) see
        // the message immediately without waiting for a round-trip via peers.
        self.emit(ShardEvent::ChatMessage {
            room: chat_msg.room_name.clone(),
            sender: chat_msg.sender_id.clone(),
            content: chat_msg.content.clone(),
        });

        let packet = DspPacket::new(PacketType::ChatMessage, 0, 0, payload);

        // If all QUIC connections dropped (NAT keepalive expiry), attempt a
        // fast reconnect before broadcasting so the message is not silently lost.
        {
            let empty = self.inner.connections.read().await.is_empty();
            if empty {
                let has_hints = !self.inner.unverified_hints.read().await.is_empty();
                let has_rt    = !self.inner.routing_table.read().await
                                    .get_all_nodes().is_empty();
                if has_hints || has_rt {
                    self.iterative_lookup(self.inner.id, 1).await;
                } else {
                    if let Ok(mut addrs) =
                        tokio::net::lookup_host("sh4rd.net:9100").await
                    {
                        if let Some(addr) = addrs.next() {
                            let _ = self.bootstrap(addr).await;
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            }
        }

        let peers: HashMap<SocketAddr, quinn::Connection> = self.inner.connections.read().await.clone();

        for (addr, conn) in peers {
            if conn.close_reason().is_some() { continue; }
            
            let node = self.clone();
            let p = packet.clone();
            tokio::spawn(async move {
                if let Err(e) = router::send_packet(&node, p, addr, None).await {
                    debug!("Failed to broadcast chat to {}: {}", addr, e);
                }
            });
        }
        Ok(())
    }
}
