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
use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use std::collections::HashMap;

pub const K_PARAM: usize = 20;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn new(id: [u8; 32]) -> Self { Self(id) }

    pub fn distance(&self, other: &NodeId) -> [u8; 32] {
        let mut res = [0u8; 32];
        for i in 0..32 {
            res[i] = self.0[i] ^ other.0[i];
        }
        res
    }

    pub fn bucket_index(&self, other: &NodeId) -> usize {
        let dist = self.distance(other);
        for (i, byte) in dist.iter().enumerate() {
            if *byte != 0 {
                return (31 - i) * 8 + (7 - byte.leading_zeros() as usize);
            }
        }
        0
    }
}

// Added PartialEq, Eq, Hash to allow usage in HashSet
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: NodeId,
    pub address: SocketAddr, 
    pub lan_address: Option<SocketAddr>, 
    pub rtt_ms: u16,
}

impl Node {
    pub fn update_rtt(&mut self, new_rtt: u16) {
        if new_rtt == 0 { return; }
        if self.rtt_ms == 0 {
            self.rtt_ms = new_rtt;
        } else {
            self.rtt_ms = (self.rtt_ms + new_rtt) / 2;
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct KBucket {
    active_nodes: Vec<Node>,
    replacement_cache: Vec<Node>,
}

impl KBucket {
    fn new() -> Self {
        Self {
            active_nodes: Vec::with_capacity(K_PARAM),
            replacement_cache: Vec::with_capacity(K_PARAM),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RoutingTable {
    local_id: NodeId,
    buckets: Vec<KBucket>,
    addr_map: HashMap<SocketAddr, NodeId>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(KBucket::new());
        }
        Self {
            local_id,
            buckets,
            addr_map: HashMap::new()
        }
    }

    pub fn update(&mut self, node: Node) {
        if node.id == self.local_id { return; }
        
        let idx = self.local_id.bucket_index(&node.id);
        if idx >= self.buckets.len() { return; }
        
        let bucket = &mut self.buckets[idx];

        // Capture keys before move (Node is not Copy)
        let node_addr = node.address;
        let node_id = node.id;

        if let Some(pos) = bucket.active_nodes.iter().position(|n| n.id == node.id) {
            bucket.active_nodes[pos].update_rtt(node.rtt_ms);
            // Update IP info if changed
            bucket.active_nodes[pos].address = node.address; 
            bucket.active_nodes[pos].lan_address = node.lan_address;
            
            let n = bucket.active_nodes.remove(pos);
            bucket.active_nodes.push(n);
        } else {
            if bucket.active_nodes.len() < K_PARAM {
                bucket.active_nodes.push(node);
                self.addr_map.insert(node_addr, node_id);
            } else {
                if let Some(pos) = bucket.replacement_cache.iter().position(|n| n.id == node.id) {
                    bucket.replacement_cache[pos].update_rtt(node.rtt_ms);
                } else {
                    bucket.replacement_cache.push(node);
                    self.addr_map.insert(node_addr, node_id);
                }
                
                bucket.replacement_cache.sort_by(|a, b| {
                    let rtt_a = if a.rtt_ms == 0 { u16::MAX } else { a.rtt_ms };
                    let rtt_b = if b.rtt_ms == 0 { u16::MAX } else { b.rtt_ms };
                    rtt_a.cmp(&rtt_b)
                });
                
                while bucket.replacement_cache.len() > K_PARAM {
                    if let Some(removed) = bucket.replacement_cache.pop() {
                        if !bucket.active_nodes.iter().any(|n| n.address == removed.address) {
                            self.addr_map.remove(&removed.address);
                        }
                    }
                }
            }
        }
    }

    pub fn remove_returning(&mut self, addr: &SocketAddr) -> Option<Node> {
        let id = *self.addr_map.get(addr)?;
        let idx = self.local_id.bucket_index(&id);
        let bucket = self.buckets.get(idx)?;
        // get_node only searches active_nodes — also check replacement_cache.
        let node = bucket.active_nodes.iter()
            .chain(bucket.replacement_cache.iter())
            .find(|n| n.id == id)
            .cloned()?;
        self.remove(addr);
        Some(node)
    }

    pub fn remove(&mut self, addr: &SocketAddr) {
        if let Some(id) = self.addr_map.remove(addr) {
            let idx = self.local_id.bucket_index(&id);
            if let Some(bucket) = self.buckets.get_mut(idx) {
                if let Some(pos) = bucket.active_nodes.iter().position(|n| n.id == id) {
                    bucket.active_nodes.remove(pos);
                    if !bucket.replacement_cache.is_empty() {
                        let replacement = bucket.replacement_cache.remove(0);
                        bucket.active_nodes.push(replacement);
                    }
                }
                else if let Some(pos) = bucket.replacement_cache.iter().position(|n| n.id == id) {
                    bucket.replacement_cache.remove(pos);
                }
            }
        }
    }

    pub fn get_all_nodes(&self) -> Vec<Node> {
        self.buckets.iter()
            .flat_map(|b| b.active_nodes.clone())
            .collect()
    }

    // Exclude self from search results to avoid routing loops
    pub fn find_closest_nodes(&self, target: &NodeId, limit: usize) -> Vec<Node> {
        let mut nodes = self.get_all_nodes();
        // Filter out our own node ID to prevent self-relay attempts
        nodes.retain(|n| n.id != self.local_id);
        
        nodes.sort_by(|a, b| {
            let dist_a = target.distance(&a.id);
            let dist_b = target.distance(&b.id);
            dist_a.cmp(&dist_b)
        });
        nodes.truncate(limit);
        nodes
    }

    pub fn get_node(&self, id: &NodeId) -> Option<Node> {
        let idx = self.local_id.bucket_index(id);
        self.buckets.get(idx).and_then(|b| {
            b.active_nodes.iter().find(|n| n.id == *id).cloned()
        })
    }
}
