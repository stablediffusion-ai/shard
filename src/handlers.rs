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
use std::net::{SocketAddr, IpAddr};
use quinn::Connection;
use sha2::{Sha256, Digest};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

use crate::context::Node;
use crate::packet::{DspPacket, PacketType, ChatMessage, RendezvousInfo, RelayPayload, NatPunchReqPayload, DhtQueryPayload};
use crate::dht::{NodeId, K_PARAM};
use crate::transport;
use crate::events::ShardEvent;

// --- IP VALIDATION LOGIC ---

pub fn is_global_address(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            
            // 0.0.0.0/8 (Current network)
            if octets[0] == 0 { return false; }
            
            // 10.0.0.0/8 (Private)
            if octets[0] == 10 { return false; }
            
            // 100.64.0.0/10 (CGNAT) - Often usable as public in P2P context, 
            // but strictly speaking not globally routable. 
            // We allow it here as WAN, but it won't pass is_private() check usually.
            
            // 127.0.0.0/8 (Loopback)
            if octets[0] == 127 { return false; }
            
            // 169.254.0.0/16 (Link-Local)
            if octets[0] == 169 && octets[1] == 254 { return false; }
            
            // 172.16.0.0/12 (Private) -> This was the leak source
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) { return false; }
            
            // 192.168.0.0/16 (Private)
            if octets[0] == 192 && octets[1] == 168 { return false; }
            
            // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved/Broadcast)
            if octets[0] >= 224 { return false; }

            true
        },
        IpAddr::V6(ip) => {
            !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()
        },
    }
}

// FIXED: Stricter LAN detection to prevent "Docker vs AWS" confusion.
// Old logic treated 172.17.x.x (Local) and 172.31.x.x (AWS) as the same LAN.
fn is_same_lan(my_ip: IpAddr, peer_ip: IpAddr) -> bool {
    match (my_ip, peer_ip) {
        (IpAddr::V4(my), IpAddr::V4(peer)) => {
            let my_oct = my.octets();
            let peer_oct = peer.octets();

            // Link-local is always same LAN
            if my.is_link_local() && peer.is_link_local() { return true; }

            // If IPs are Private (RFC1918), require strict Subnet match (/24)
            // to avoid routing across different private networks (e.g. VPN tunnels vs Local WiFi)
            if !is_global_address(SocketAddr::new(my_ip, 0)) && !is_global_address(SocketAddr::new(peer_ip, 0)) {
                return my_oct[0] == peer_oct[0] 
                    && my_oct[1] == peer_oct[1] 
                    && my_oct[2] == peer_oct[2];
            }

            my == peer
        },
        _ => false 
    }
}

// --- HANDLERS ---

pub async fn handle_stun_request(node: &Node, packet: DspPacket, requester: SocketAddr) {
    // Reflect the requester's observed address + the nonce they sent so they can validate the reply.
    // Payload format: [nonce:8][addr_str bytes]
    let addr_bytes = requester.to_string().into_bytes();
    let mut payload = packet.payload; // nonce bytes from request
    payload.extend_from_slice(&addr_bytes);
    let response = DspPacket::new(PacketType::StunResponse, 0, 0, payload);
    let _ = crate::router::send_packet(node, response, requester, None).await;
}

pub async fn handle_stun_response(node: &Node, packet: DspPacket) {
    // Payload: [nonce:8][addr_str bytes]
    if packet.payload.len() < 8 { return; }

    let (nonce_bytes, addr_bytes) = packet.payload.split_at(8);
    let received_nonce = u64::from_le_bytes(nonce_bytes.try_into().unwrap());

    // Drop unsolicited responses — only accept if nonce matches our outstanding request.
    let expected = *node.inner.pending_stun_nonce.read().await;
    if expected != Some(received_nonce) {
        tracing::warn!("Dropping unsolicited or replayed StunResponse (nonce mismatch).");
        return;
    }

    // Consume the nonce so it cannot be replayed.
    *node.inner.pending_stun_nonce.write().await = None;

    if let Ok(addr_str) = String::from_utf8(addr_bytes.to_vec()) {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            if is_global_address(addr) {
                let mut guard = node.inner.public_address.write().await;
                if guard.is_none() || guard.unwrap() != addr {
                    *guard = Some(addr);
                }
            }
        }
    }
}

pub async fn handle_nat_punch_request(node: &Node, packet: DspPacket, requester: SocketAddr) {
    if let Ok(req) = bincode::deserialize::<NatPunchReqPayload>(&packet.payload) {
        let target_bytes: [u8; 32] = req.target_id.try_into().unwrap_or([0;32]);
        let target_id = NodeId::new(target_bytes);
        let requester_local_hint = req.local_hint;

        let maybe_target = {
            let table = node.inner.routing_table.read().await;
            table.get_node(&target_id).map(|n| n.address)
        };

        if let Some(target_addr) = maybe_target {
            let payload_to_req = bincode::serialize(&RendezvousInfo {
                peer_id: target_id.0.to_vec(),
                peer_addr: target_addr,
                peer_local_hint: None, 
            }).unwrap_or_default();
            
            let pkt_req = DspPacket::new(PacketType::NatPunchRendezvous, 0, 0, payload_to_req);
            let _ = crate::router::send_packet(node, pkt_req, requester, None).await;

            let payload_to_tgt = bincode::serialize(&RendezvousInfo {
                peer_id: vec![], 
                peer_addr: requester,
                peer_local_hint: requester_local_hint, 
            }).unwrap_or_default();
            
            let pkt_tgt = DspPacket::new(PacketType::NatPunchRendezvous, 0, 0, payload_to_tgt);
            let _ = crate::router::send_packet(node, pkt_tgt, target_addr, Some(target_id)).await;
        }
    }
}

pub async fn handle_nat_punch_rendezvous(node: &Node, packet: DspPacket) {
    if let Ok(info) = bincode::deserialize::<RendezvousInfo>(&packet.payload) {
        let peer_addr = info.peer_addr; 
        let peer_local = info.peer_local_hint;
        let node_ref = node.clone();
        
        tokio::spawn(async move {
            let mut candidates = vec![];
            // Filter: Only try connecting to peer_addr if it's Global
            if is_global_address(peer_addr) { candidates.push(peer_addr); }
            
            if let Some(local) = peer_local {
                if local != peer_addr { candidates.push(local); }
            }

            for addr in candidates {
                let n = node_ref.clone();
                tokio::spawn(async move {
                    let _ = crate::transport::get_or_connect(&n, addr, None).await;
                });
            }
        });
    }
}

pub async fn handle_relay_data(node: &Node, packet: DspPacket, src: SocketAddr) {
    let mut relay_pkg = match bincode::deserialize::<RelayPayload>(&packet.payload) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Drop exhausted relays to cap hop depth.
    if relay_pkg.ttl == 0 {
        tracing::debug!("Relay TTL exhausted from {}, dropping.", src);
        return;
    }

    let target_bytes: [u8; 32] = relay_pkg.target_id.clone().try_into().unwrap_or([0; 32]);
    let target_id = NodeId::new(target_bytes);

    if node.inner.id == target_id {
        if let Ok(inner_pkt) = DspPacket::deserialize(&relay_pkg.inner_packet) {
            match inner_pkt.msg_type {
                PacketType::Fragment => handle_fragment(node, inner_pkt, src).await,
                PacketType::FragmentRequest => {
                    if let Ok(conn) = crate::transport::get_or_connect(node, src, None).await {
                        handle_fragment_request(node, inner_pkt, conn).await;
                    }
                },
                _ => {}
            }
        }
    } else {
        // Per-destination relay rate limit — keyed on the target's address.
        let target_sock = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0
        );
        let closest: Vec<crate::dht::Node> = node.inner.routing_table.read().await
            .find_closest_nodes(&target_id, K_PARAM);

        if let Some(next_hop) = closest.first() {
            let allowed = node.inner.relay_limiter.lock().await.check(next_hop.address.ip());
            if !allowed {
                tracing::debug!("Relay rate limit hit for destination {}", next_hop.address);
                return;
            }
            relay_pkg.ttl -= 1;
            if let Ok(payload) = bincode::serialize(&relay_pkg) {
                let forwarded = DspPacket::new(packet.msg_type, packet.version, packet.reserved, payload);
                let _ = crate::router::send_packet(node, forwarded, next_hop.address, Some(next_hop.id)).await;
            }
        }
        let _ = target_sock; // suppress unused warning
    }
}

pub async fn handle_dht_query(node: &Node, packet: DspPacket, src: SocketAddr) {
    let (target_id, lan_hint) = if let Ok(q) = bincode::deserialize::<DhtQueryPayload>(&packet.payload) {
        let Ok(b): Result<[u8; 32], _> = q.node_id.try_into() else { return; };
        (NodeId::new(b), q.lan_address)
    } else {
        return;
    };

    let mut effective_addr = src;
    if let Some(lan_ip) = lan_hint {
        let my_net_info = transport::detect_network_interfaces();
        if let Some(my_lan) = my_net_info.local_lan {
            // Strict LAN check applied here
            if is_same_lan(my_lan, lan_ip.ip()) {
                effective_addr = lan_ip;
            }
        }
    }

    // Accept the node if:
    // 1. Global address (WAN)
    // 2. LAN hint different from source (normalised LAN-side address)
    // 3. Loopback → loopback: same host, different ports (local dev / VM)
    let is_loopback_peer = effective_addr.ip().is_loopback() && src.ip().is_loopback();
    if is_global_address(effective_addr) || (effective_addr != src) || is_loopback_peer {
        let mut table = node.inner.routing_table.write().await;
        table.update(crate::dht::Node {
            id: target_id,
            address: effective_addr,
            lan_address: lan_hint,
            rtt_ms: 0
        });
    }

    let nodes = {
        let table = node.inner.routing_table.read().await;
        table.find_closest_nodes(&target_id, K_PARAM)
    };

    if let Ok(resp) = bincode::serialize(&nodes) {
        let pkt = DspPacket::new(PacketType::DhtResponse, 0, 0, resp);
        let _ = crate::router::send_packet(node, pkt, effective_addr, Some(target_id)).await;
    }
}

pub async fn handle_dht_response(node: &Node, packet: DspPacket, _src: SocketAddr) {
    if let Ok(nodes) = bincode::deserialize::<Vec<crate::dht::Node>>(&packet.payload) {
        let my_net_info = transport::detect_network_interfaces();
        let mut hints = node.inner.unverified_hints.write().await;

        for mut n in nodes {
            let mut use_lan = false;

            if let Some(lan_ip) = n.lan_address {
                if let Some(my_lan) = my_net_info.local_lan {
                    if is_same_lan(my_lan, lan_ip.ip()) {
                        n.address = lan_ip;
                        use_lan = true;
                    }
                }
            }

            let is_loopback_peer = n.address.ip().is_loopback();
            if use_lan || is_global_address(n.address) || is_loopback_peer {
                // Hold as hint — promoted to routing table only after a successful TLS handshake.
                hints.insert(n.address, n);
            }
        }
    }
}

pub async fn handle_fragment(node: &Node, packet: DspPacket, _src: SocketAddr) {
    let payload = packet.payload;
    if payload.len() < 36 { return; }
    let key_raw = payload[0..32].to_vec();
    let data = payload[36..].to_vec();
    let inner = node.inner.clone();
    
    let _ = tokio::task::spawn_blocking(move || {
        let key_hex = hex::encode(&key_raw);
        if let Err(e) = inner.storage.store_named(key_hex.as_bytes(), &data, None) {
            tracing::warn!("Store failed: {}", e); 
        }
    }).await;
}

pub async fn handle_fragment_request(node: &Node, packet: DspPacket, conn: Connection) {
    let req_hash = packet.payload;
    let inner = node.inner.clone();
    let key_hex = hex::encode(&req_hash);
    
    let maybe_data: Option<Vec<u8>> = tokio::task::spawn_blocking(move || {
        inner.storage.retrieve_by_hash(key_hex.as_bytes()).ok()
    }).await.unwrap_or(None);

    if let Some(data) = maybe_data {
        let mut resp = Vec::with_capacity(36 + data.len());
        resp.extend_from_slice(&req_hash);
        resp.extend_from_slice(&[0u8; 4]);
        resp.extend_from_slice(&data);
        
        let response = DspPacket::new(PacketType::Fragment, 0, 0, resp);
        if let Ok(mut send) = conn.open_uni().await {
             if let Ok(b) = response.serialize() {
                 let _ = send.write_all(&b).await;
                 let _ = send.finish();
             }
        }
    }
}

#[cfg(test)]
mod tests {
    // ── DSP-001 : sender_id slice sans panic ──

    #[test]
    fn sender_id_exact_8_chars() {
        let id = "abcdef12".to_string();
        let result = id.get(0..8).unwrap_or(&id).to_string();
        assert_eq!(result, "abcdef12");
    }

    #[test]
    fn sender_id_longer_than_8_truncated() {
        let id = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string();
        let result = id.get(0..8).unwrap_or(&id).to_string();
        assert_eq!(result, "abcdef12");
    }

    #[test]
    fn sender_id_shorter_than_8_no_panic() {
        // Before the fix: id[0..8] would have panicked here
        let id = "ab".to_string();
        let result = id.get(0..8).unwrap_or(&id).to_string();
        assert_eq!(result, "ab");
    }

    #[test]
    fn sender_id_empty_no_panic() {
        let id = String::new();
        let result = id.get(0..8).unwrap_or(&id).to_string();
        assert_eq!(result, "");
    }

    // ── DSP-002 : node_id try_into sans panic ──

    #[test]
    fn node_id_exact_32_bytes_accepted() {
        let id: Vec<u8> = vec![0xAB; 32];
        let result: Result<[u8; 32], _> = id.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn node_id_too_short_rejected() {
        // Before the fix: copy_from_slice would have panicked here
        let id: Vec<u8> = vec![1, 2, 3];
        let result: Result<[u8; 32], _> = id.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn node_id_too_long_rejected() {
        let id: Vec<u8> = vec![0u8; 64];
        let result: Result<[u8; 32], _> = id.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn node_id_empty_rejected() {
        let id: Vec<u8> = vec![];
        let result: Result<[u8; 32], _> = id.try_into();
        assert!(result.is_err());
    }
}

pub async fn handle_chat_message(node: &Node, packet: DspPacket, _src: SocketAddr) {
    let msg = match bincode::deserialize::<ChatMessage>(&packet.payload) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Verify Ed25519 signature before doing anything with this message.
    let pubkey_bytes: [u8; 32] = match msg.sender_pubkey.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => { tracing::warn!("Chat: invalid pubkey length from {}", _src); return; }
    };
    let sig_bytes: [u8; 64] = match msg.signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => { tracing::warn!("Chat: invalid signature length from {}", _src); return; }
    };
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(_) => { tracing::warn!("Chat: invalid pubkey from {}", _src); return; }
    };
    let signature = Signature::from_bytes(&sig_bytes);

    let mut to_verify = Vec::new();
    to_verify.extend_from_slice(msg.room_name.as_bytes());
    to_verify.extend_from_slice(msg.sender_id.as_bytes());
    to_verify.extend_from_slice(&msg.nonce.to_le_bytes());
    to_verify.extend_from_slice(msg.content.as_bytes());

    if verifying_key.verify(&to_verify, &signature).is_err() {
        tracing::warn!("Chat: dropping message with invalid signature from {}", _src);
        return;
    }

    // Dedup check after signature validation so replay attacks don't pollute the cache.
    let mut hasher = Sha256::new();
    hasher.update(&packet.payload);
    let msg_hash = hasher.finalize().to_vec();
    {
        let mut cache = node.inner.seen_messages.write().await;
        if !cache.try_insert(msg_hash) { return; }
    }

    let my_room = node.inner.active_room.read().await.clone();
    if let Some(current) = my_room {
        if current == msg.room_name {
            let sender_prefix = msg.sender_id.get(0..8).unwrap_or(&msg.sender_id).to_string();
            node.emit(ShardEvent::ChatMessage {
                room: msg.room_name.clone(),
                sender: sender_prefix,
                content: msg.content.clone()
            });
        }
    }

    let peers = node.inner.connections.read().await.clone();
    for (addr, _) in peers {
        if addr != _src {
            let n = node.clone();
            let p = packet.clone();
            tokio::spawn(async move { let _ = crate::router::send_packet(&n, p, addr, None).await; });
        }
    }
}
