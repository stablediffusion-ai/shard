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
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShardError {
    #[error("IO operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization failed: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),

    #[error("QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("Stream write failed: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("Stream read failed: {0}")]
    Read(#[from] quinn::ReadError),

    #[error("Stream read to end failed: {0}")]
    ReadToEnd(#[from] quinn::ReadToEndError),

    #[error("Stream closed: {0}")]
    StreamClosed(#[from] quinn::ClosedStream),

    #[error("Address parsing failed: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("TLS Configuration failed: {0}")]
    TlsConfig(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Crypto/TLS error: {0}")]
    Crypto(String),

    #[error("Protocol violation: {0}")]
    Protocol(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network Logic error: {0}")]
    Network(String),

    #[error("Generic error: {0}")]
    Other(String),
}

impl From<String> for ShardError {
    fn from(s: String) -> Self {
        ShardError::Other(s)
    }
}

impl From<&str> for ShardError {
    fn from(s: &str) -> Self {
        ShardError::Other(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ShardError>;
