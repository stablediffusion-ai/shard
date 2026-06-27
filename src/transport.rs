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
use std::time::Duration;
use quinn::{Connection, RecvStream};
use tracing::debug;
use if_addrs::get_if_addrs; 

use crate::context::{Node, MAX_PACKET_SIZE};
use crate::dht::NodeId;
use crate::packet::{DspPacket, PacketType, NatPunchReqPayload};
use crate::handlers;
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub public_wan: Option<IpAddr>,
    pub local_lan: Option<IpAddr>,
}

// Detects local interfaces to help with LAN discovery and NAT detection
pub fn detect_network_interfaces() -> NetworkInfo {
    let mut info = NetworkInfo { public_wan: None, local_lan: None };
    let mut best_lan_score = 0;

    if let Ok(interfaces) = get_if_addrs() {
        for iface in interfaces {
            let ip = iface.addr.ip();
            match ip {
                IpAddr::V4(ipv4) => {
                    if ipv4.is_loopback() || ipv4.is_link_local() { continue; }

                    if ipv4.is_private() {
                        let octets = ipv4.octets();
                        
                        // Check for CGNAT (100.64.0.0/10)
                        // It is private but often acts as the WAN interface behind ISP NAT
                        if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
                            if info.public_wan.is_none() { info.public_wan = Some(ip); }
                            continue;
                        }

                        // Score RFC1918 ranges for LAN preference
                        let score = match octets[0] {
                            192 => 3, // 192.168.x.x (Most common home LAN)
                            172 => 2, // 172.16.x.x (Docker/Corp)
                            10 => 1,  // 10.x.x.x
                            _ => 0,
                        };

                        if score > best_lan_score {
                            info.local_lan = Some(ip);
                            best_lan_score = score;
                        } else if info.local_lan.is_none() {
                            info.local_lan = Some(ip);
                        }
                    } else {
                        // Real Public IP attached to interface
                        if info.public_wan.is_none() { info.public_wan = Some(ip); }
                    }
                },
                IpAddr::V6(ipv6) => {
                    if ipv6.is_loopback() { continue; }
                    // Assume Global Unicast IPv6 is public
                    if info.public_wan.is_none() { info.public_wan = Some(ip); }
                }
            }
        }
    }
    info
}

pub fn id_to_sni(id: &NodeId) -> String {
    let hex_id = hex::encode(id.0);
    format!("{}.{}", &hex_id[0..32], &hex_id[32..64])
}

pub fn is_same_node(addr1: SocketAddr, addr2: SocketAddr) -> bool {
    if addr1.port() != addr2.port() { return false; }
    match (addr1.ip(), addr2.ip()) {
        (IpAddr::V4(ip1), IpAddr::V4(ip2)) => {
            if ip1.is_loopback() && ip2.is_unspecified() { return true; }
            if ip1.is_unspecified() && ip2.is_loopback() { return true; }
            ip1 == ip2
        },
        _ => addr1.ip() == addr2.ip()
    }
}

pub async fn resolve_peer_addr(node: &Node, peer: &crate::dht::Node) -> SocketAddr {
    let my_public: Option<SocketAddr> = *node.inner.public_address.read().await;
    
    // Optimization: If we share the same Public IP, we are likely behind the same NAT.
    // Use LAN address to route internally.
    if let Some(my_pub) = my_public {
        if my_pub.ip() == peer.address.ip() {
            if let Some(lan) = peer.lan_address {
                debug!("Peer detected on same LAN. Using local IP: {}", lan);
                return lan;
            }
        }
    }
    peer.address
}

pub async fn get_or_connect(node: &Node, addr: SocketAddr, target_id: Option<NodeId>) -> Result<Connection> {
    {
        // Try to reuse existing connection
        let guard = node.inner.connections.read().await;
        if let Some(conn) = guard.get(&addr) {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
    }

    let sni_domain = if let Some(id) = &target_id { id_to_sni(id) } else { "bootstrap".to_string() };

    // First attempt: short timeout — avoids blocking callers for 10s on unreachable peers.
    let direct = match node.endpoint.connect(addr, &sni_domain) {
        Ok(c) => tokio::time::timeout(Duration::from_millis(3000), c).await.ok().and_then(|r| r.ok()),
        Err(_) => None,
    };

    if let Some(connection) = direct {
        return store_connection(node, addr, connection).await;
    }

    // Direct connect failed. If the target is a global (WAN) address and we know its NodeId,
    // request UDP hole punching via any already-connected relay peer.
    if let Some(tid) = &target_id {
        if handlers::is_global_address(addr) {
            let relay = {
                let conns = node.inner.connections.read().await;
                conns.iter()
                    .find(|(_, c)| c.close_reason().is_none())
                    .map(|(a, _)| *a)
            };

            if let Some(relay_addr) = relay {
                let my_port = node.endpoint.local_addr().map(|s| s.port()).unwrap_or(0);
                let local_hint = detect_network_interfaces()
                    .local_lan
                    .map(|ip| SocketAddr::new(ip, my_port));

                let req = NatPunchReqPayload { target_id: tid.0.to_vec(), local_hint };
                if let Ok(payload) = bincode::serialize(&req) {
                    let pkt = DspPacket::new(PacketType::NatPunchRequest, 0, 0, payload);
                    // Send directly on an existing connection — avoids recursive get_or_connect.
                    let relay_conn = node.inner.connections.read().await.get(&relay_addr).cloned();
                    if let Some(conn) = relay_conn {
                        if let Ok(data) = pkt.serialize() {
                            if let Ok(mut send) = conn.open_uni().await {
                                let _ = send.write_all(&data).await;
                                let _ = send.finish();
                            }
                        }
                    }
                }

                // Give the relay time to send rendezvous to both sides and for UDP mappings to open.
                tokio::time::sleep(Duration::from_millis(1500)).await;

                // Retry with generous timeout — hole is now (hopefully) open on both NATs.
                if let Ok(c) = node.endpoint.connect(addr, &sni_domain) {
                    if let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_millis(6000), c).await {
                        return store_connection(node, addr, connection).await;
                    }
                }
            }
        }
    }

    Err(crate::error::ShardError::Network(format!("Connection to {} failed (direct + hole punch)", addr)))
}

async fn store_connection(node: &Node, addr: SocketAddr, connection: quinn::Connection) -> Result<Connection> {
    listen_on_connection(node, connection.clone());

    let mut guard = node.inner.connections.write().await;
    if let Some(existing) = guard.get(&addr) {
        if existing.close_reason().is_none() {
            return Ok(existing.clone());
        }
    }
    guard.insert(addr, connection.clone());

    if let Some(hint_node) = node.inner.unverified_hints.write().await.remove(&addr) {
        node.inner.routing_table.write().await.update(hint_node);
    }

    Ok(connection)
}

pub fn listen_on_connection(node: &Node, connection: Connection) {
    let node_cloned = node.clone();
    tokio::spawn(async move {
        while let Ok(recv) = connection.accept_uni().await {
            let n = node_cloned.clone();
            let c = connection.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_stream(&n, recv, c).await {
                    debug!("Stream handling error: {}", e);
                }
            });
        }
        node_cloned.remove_peer(connection.remote_address()).await;
    });
}

async fn handle_stream(node: &Node, mut recv: RecvStream, conn: Connection) -> Result<()> {
    let data = recv.read_to_end(MAX_PACKET_SIZE).await?;
    let packet = DspPacket::deserialize(&data)?;
    let src = conn.remote_address();

    match packet.msg_type {
        PacketType::StunRequest => handlers::handle_stun_request(node, packet, src).await,
        PacketType::StunResponse => handlers::handle_stun_response(node, packet).await,
        PacketType::NatPunchRequest => handlers::handle_nat_punch_request(node, packet, src).await,
        PacketType::NatPunchRendezvous => handlers::handle_nat_punch_rendezvous(node, packet).await,
        PacketType::RelayData => handlers::handle_relay_data(node, packet, src).await,
        PacketType::KeepAlive => { },
        PacketType::Fragment => handlers::handle_fragment(node, packet, src).await,
        PacketType::FragmentRequest => handlers::handle_fragment_request(node, packet, conn).await,
        PacketType::DhtQuery => handlers::handle_dht_query(node, packet, src).await,
        PacketType::DhtResponse => handlers::handle_dht_response(node, packet, src).await,
        PacketType::ChatMessage => handlers::handle_chat_message(node, packet, src).await,
    }
    Ok(())
}
