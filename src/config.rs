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
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use crate::error::{Result, ShardError};

// --- RUNTIME CONFIGURATION (Full Application State) ---

#[derive(Debug, Clone)]
pub struct ShardConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub mining: MiningConfig,     // Dynamic Difficulty
    pub security: SecurityConfig, // Remaining hardcoded params
    pub limits: LimitsConfig,     // Hardcoded limits
}

// --- FILE CONFIGURATION (Serializable parts only) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub mining: MiningConfig, 
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub default_port: u16,
    pub enable_upnp: bool,
    pub public_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub max_storage_bytes: u64,
    pub cleanup_interval_sec: u64,
    pub retention_period_sec: u64,
}

// Configurable Mining (Bit precision)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningConfig {
    pub difficulty: usize, // Number of leading zero BITS required
}

// --- HARDCODED CONFIGURATION (Non-serializable) ---

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub argon_memory: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
}

#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub max_concurrent_connections: usize,
    pub rate_limit_capacity: f32,
    pub rate_limit_refill_per_sec: f32,
    pub rate_limit_cleanup_sec: u64,
}

// --- DEFAULTS ---

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            default_port: 9000,
            enable_upnp: false,
            public_address: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_storage_bytes: 500_000_000,
            cleanup_interval_sec: 1800,
            retention_period_sec: 604_800, // 7 days
        }
    }
}

// implementation for MiningConfig
impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            // 16 bits = 2 bytes = ~65k hashes.
            // Reasonable for a generic PC (takes ~1-5 seconds to mine).
            difficulty: 6, 
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            argon_memory: 65536,
            argon_iterations: 1,
            argon_parallelism: 1,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_connections: 100,
            rate_limit_capacity: 20.0,
            rate_limit_refill_per_sec: 10.0,
            rate_limit_cleanup_sec: 300,
        }
    }
}

// --- IMPLEMENTATION ---

impl ShardConfig {
    pub fn load_or_create(path: &str) -> Result<Self> {
        let config_path = Path::new(path).join("config.toml");

        // 1. Try to load from file (Network, Storage, Mining)
        let (network, storage, mining) = if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let file_config: ConfigFile = toml::from_str(&content)
                .map_err(|e| ShardError::Other(format!("Config parse error: {}", e)))?;
            (file_config.network, file_config.storage, file_config.mining)
        } else {
            // 2. Create default file if missing
            let defaults = ConfigFile {
                network: NetworkConfig::default(),
                storage: StorageConfig::default(),
                mining: MiningConfig::default(),
            };
            let toml_string = toml::to_string_pretty(&defaults)
                .map_err(|e| ShardError::Other(format!("Config serialize error: {}", e)))?;

            let _ = fs::write(&config_path, toml_string);

            (defaults.network, defaults.storage, defaults.mining)
        };

        // 3. Merge with Hardcoded Security & Limits
        Ok(Self {
            network,
            storage,
            mining,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
        })
    }
}
