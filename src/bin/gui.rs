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
use clap::Parser;
use rand::RngCore;
use std::path::Path;
use tracing::info;

use shard::config::ShardConfig;
use shard::error::Result;
use shard::gui_server::build_app;

#[derive(Parser, Debug)]
#[command(author, version, about = "Shard DSP — GUI node")]
struct Args {
    #[arg(short, long, default_value_t = 9200)]
    port: u16,

    #[arg(long, default_value_t = 9201)]
    gui_port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    gui_host: String,

    #[arg(short, long)]
    bootstrap: Option<String>,

    #[arg(short, long, default_value_t = false)]
    seed: bool,

    #[arg(long)]
    data_dir: Option<String>,

    /// Storage quota in bytes (overrides config.toml; e.g. 500000000 = 500 MB)
    #[arg(long)]
    disk_quota: Option<u64>,

    /// Shard retention period in seconds (overrides config.toml; e.g. 604800 = 7 days)
    #[arg(long)]
    retention: Option<u64>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .init();

    let bind_addr = format!("0.0.0.0:{}", args.port);
    let storage_path = args.data_dir
        .unwrap_or_else(|| format!("./data_swarm/node_{}", args.port));
    std::fs::create_dir_all(Path::new(&storage_path).join("sys"))?;

    let mut config = ShardConfig::load_or_create(&storage_path)?;
    if let Some(quota) = args.disk_quota {
        config.storage.max_storage_bytes = quota;
    }
    if let Some(ret) = args.retention {
        config.storage.retention_period_sec = ret;
    }
    let password = load_or_generate_password(&storage_path)?;
    let node = shard::context::Node::new(config.clone(), &bind_addr, &storage_path, &password).await?;

    info!(node_id = %hex::encode(node.id().0), port = args.port, gui_port = args.gui_port, "Node ready");

    {
        let n = node.clone();
        tokio::spawn(async move { let _ = n.run().await; });
    }

    let cached = node.load_routing_table().await;
    if !cached.is_empty() {
        info!("Verifying {} cached peer(s)", cached.len());
        for addr in cached {
            let n = node.clone();
            tokio::spawn(async move { let _ = n.bootstrap(addr).await; });
        }
    }

    const DEFAULT_SEED: &str = "shardnet.app:9100";
    const LOCAL_SEED:   &str = "127.0.0.1:9100";

    if let Some(boot_str) = &args.bootstrap {
        // Explicit seed specified — use it directly
        if let Ok(mut addrs) = tokio::net::lookup_host(boot_str.as_str()).await {
            if let Some(addr) = addrs.next() {
                let _ = node.bootstrap(addr).await;
            }
        }
    } else if !args.seed {
        // Default public seed
        let mut joined = false;
        if let Ok(mut addrs) = tokio::net::lookup_host(DEFAULT_SEED).await {
            if let Some(addr) = addrs.next() {
                joined = node.bootstrap(addr).await.is_ok();
            }
        }
        // Local fallback if public seed unreachable
        if !joined {
            if let Ok(mut addrs) = tokio::net::lookup_host(LOCAL_SEED).await {
                if let Some(addr) = addrs.next() {
                    let _ = node.bootstrap(addr).await;
                }
            }
        }
    }

    node.start_background_tasks();

    let app = build_app(node, storage_path.clone(), args.seed);
    let gui_addr = format!("{}:{}", args.gui_host, args.gui_port);
    let listener = tokio::net::TcpListener::bind(&gui_addr).await?;

    println!("> GUI available at http://{}", gui_addr);
    info!("GUI server listening on http://{}", gui_addr);

    axum::serve(listener, app).await?;
    Ok(())
}

fn load_or_generate_password(storage: &str) -> Result<String> {
    let path = Path::new(storage).join("sys").join("node_secret");
    if path.exists() {
        return Ok(std::fs::read_to_string(&path)?.trim().to_string());
    }

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let secret = hex::encode(bytes);
    std::fs::write(&path, &secret)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(secret)
}
