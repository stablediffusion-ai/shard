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
pub mod config;
pub mod context;
pub mod crypto;
pub mod dht;
pub mod error;
pub mod handlers;
pub mod identity;
pub mod node;
pub mod packet;
pub mod router;
pub mod sharding;
pub mod storage;
pub mod tasks;
pub mod transfer;
pub mod transport;
pub mod events;
pub mod gui_server;

pub use context::Node;
pub use config::ShardConfig;
pub use error::{Result, ShardError};
pub use events::ShardEvent;
