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
mod term_md;

use clap::Parser;
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use tokio::time::sleep;
use tokio::io::{AsyncBufReadExt, BufReader};
use rand::rngs::OsRng;
use rand::RngCore;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use shard::events::ShardEvent;

#[cfg(all(unix, not(target_os = "android")))]
use daemonize::Daemonize;

// IMPORT DEPUIS NOTRE NOUVELLE LIB
use shard::context::Node;
use shard::error::Result;
use shard::config::ShardConfig;

const PEER_NAMES: &[&str] = &[
    "Ada","Ade","Aiko","Alec","Alma","Amos","Anja","Ara","Ari","Axel",
    "Bea","Bela","Ben","Bo","Boris","Bram","Cal","Cleo","Cole","Cora",
    "Dana","Dani","Dev","Dov","Eli","Emil","Era","Eva","Finn","Flora",
    "Flo","Gil","Gus","Hana","Hans","Ian","Ida","Ines","Iris","Ivan",
    "Jade","Jan","Jax","Jin","Jo","Jon","Joy","Jun","Kai","Kaz",
    "Kim","Kira","Koa","Lars","Lea","Leo","Lena","Lin","Liz","Lou",
    "Luc","Mae","Marc","Max","Mel","Mia","Mir","Nate","Ned","Neo",
    "Nia","Nils","Noa","Noel","Nora","Olga","Ole","Omar","Oscar","Otto",
    "Pan","Pat","Paz","Per","Pim","Pia","Raf","Rex","Rio","Rob",
    "Rosa","Roy","Rui","Sai","Sam","Sara","Seb","Sid","Sol","Sue",
    "Suki","Tao","Ted","Tim","Tom","Tove","Uma","Ulf","Val","Vera",
    "Vic","Wren","Yael","Yuki","Zara","Zed","Zen","Zia","Zoe","Zola",
    "Abe","Ace","Ai","Akira","Alva","Ami","Asha","Avi","Ayo","Bao",
    "Bay","Bix","Blu","Brin","Cai","Cara","Cato","Ceri","Ciel","Cyan",
    "Dag","Dara","Dex","Dima","Dion","Dora","Drew","Echo","Eda","Eden",
    "Elif","Elsa","Emre","Eno","Eri","Faye","Fern","Fox","Gene","Gio",
    "Glen","Grey","Hiro","Ike","Ilya","Ina","Jora","Jude","Jules","Juno",
    "Kael","Kali","Kana","Kei","Kit","Lake","Lalo","Lane","Lani","Lark",
    "Lev","Linh","Lior","Loa","Lore","Mads","Mael","Mali","Malu","Manu",
    "Mara","Maro","Meta","Miko","Mila","Milo","Mio","Miri","Nabi","Nao",
    "Nara","Neve","Nico","Nima","Oak","Obi","Ori","Pax","Penn","Peri",
    "Rael","Rafi","Rain","Ravi","Reed","Remi","Ren","Riv","Roan","Romy",
    "Rue","Rumi","Rune","Sage","Sana","Saya","Shea","Shu","Sky","Tae",
    "Tai","Tara","Taro","Tia","Tobi","Tui","Veda","Vela","Yara","Zion",
];

fn peer_name_hash(key: &str) -> usize {
    let mut h: u32 = 0;
    for c in key.chars() {
        h = h.wrapping_mul(31).wrapping_add(c as u32);
    }
    h as usize
}

fn resolve_name(id: &str, cache: &mut HashMap<String, String>) -> String {
    let key = id[..id.len().min(8)].to_string();
    if let Some(name) = cache.get(&key) {
        return name.clone();
    }
    let name = PEER_NAMES[peer_name_hash(&key) % PEER_NAMES.len()].to_string();
    cache.insert(key, name.clone());
    name
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, default_value_t = 9000)]
    port: u16,
    #[arg(short, long)]
    bootstrap: Option<String>,
    #[arg(short, long, default_value_t = false)]
    seed: bool,
    #[arg(long, default_value_t = false)]
    daemon: bool,
    #[arg(long, default_value_t = false)]
    passive: bool,

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

    if args.daemon {
        #[cfg(all(unix, not(target_os = "android")))]
        {
            println!("> Starting Shard Node in background (Daemon mode)...");
            let log_dir = PathBuf::from("./logs");
            std::fs::create_dir_all(&log_dir)?;
            let mut dir_perms = std::fs::metadata(&log_dir)?.permissions();
            dir_perms.set_mode(0o700);
            std::fs::set_permissions(&log_dir, dir_perms)?;

            println!("> Logs location: {:?}", log_dir);
            let stdout_path = log_dir.join("shard.out");
            let stderr_path = log_dir.join("shard.err");
            let pid_path = log_dir.join("shard.pid");

            let stdout = OpenOptions::new().create(true).append(true).mode(0o600).open(&stdout_path)?;
            let stderr = OpenOptions::new().create(true).append(true).mode(0o600).open(&stderr_path)?;

            let daemon = Daemonize::new()
                .pid_file(pid_path)
                .working_directory(".")
                .stdout(stdout)
                .stderr(stderr);

            match daemon.start() {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("Error starting daemon: {}", e);
                    std::process::exit(1);
                },
            }
        }
        #[cfg(any(not(unix), target_os = "android"))]
        {
            eprintln!("Error: --daemon mode is not supported on this platform.");
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async_main(args))
}

async fn async_main(args: Args) -> Result<()> {
    {
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error"));
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .init();
    }

    let bind_addr = format!("0.0.0.0:{}", args.port);
    let storage_path = args.data_dir
        .unwrap_or_else(|| format!("./data_swarm/node_{}", args.port));
    std::fs::create_dir_all(Path::new(&storage_path).join("sys"))?;

    if !args.daemon {
        println!("--- Shard Node ---");
        println!("Type /help for commands.");
    }

    let mut config = ShardConfig::load_or_create(&storage_path)?;
    if let Some(quota) = args.disk_quota {
        config.storage.max_storage_bytes = quota;
    }
    if let Some(ret) = args.retention {
        config.storage.retention_period_sec = ret;
    }
    let password = load_or_generate_password(&storage_path)?;

    let node = Node::new(config.clone(), &bind_addr, &storage_path, &password).await?;

    let node_clone = node.clone();

    let name_cache: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let name_cache_ev = name_cache.clone();

    // subscribe to events
    let mut rx = node.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            match event {
                ShardEvent::Log { level, message } => {
                    println!("[{}] {}", level, message);
                },
                ShardEvent::ChatMessage { room, sender, content } => {
                    if content.starts_with('\x1f') {
                        if let Some(name) = content.strip_prefix('\x1f').and_then(|r| r.strip_prefix("NAME:")) {
                            let name = name.trim();
                            if !name.is_empty() && !sender.is_empty() {
                                let key = sender[..sender.len().min(8)].to_string();
                                name_cache_ev.lock().unwrap().insert(key, name.to_string());
                            }
                        }
                        continue;
                    }
                    let display = resolve_name(&sender, &mut name_cache_ev.lock().unwrap());
                    println!("\n[#{}] {}: {}", room, display, content);
                    print!("shard> ");
                    let _ = std::io::stdout().flush();
                },
                ShardEvent::TransferProgress { current_chunk, total_chunks, is_upload, .. } => {
                    if current_chunk % 5 == 0 || current_chunk == total_chunks {
                        let kind = if is_upload { "UP" } else { "DOWN" };
                        println!("[{}] {}/{} chunks", kind, current_chunk, total_chunks);
                    }
                },
                ShardEvent::TransferComplete { magnet, path, .. } => {
                    if let Some(m) = magnet {
                         println!("\n[SUCCESS] Upload finished. Magnet: {}", m);
                    }
                    if let Some(p) = path {
                         println!("\n[SUCCESS] Download finished. Saved to: {}", p);
                    }
                    print!("shard> ");
                    let _ = std::io::stdout().flush();
                }
                _ => {}
            }
        }
    });

    tokio::spawn(async move {
        if let Err(e) = node_clone.run().await {
            tracing::error!("Node runtime error: {}", e);
        }
    });

    if !args.daemon {
        sleep(Duration::from_millis(100)).await;
        if args.passive {
            println!("> Node active. ID: {} [PASSIVE]", hex::encode(node.id().0));
        } else {
            println!("> Node active. ID: {}", hex::encode(node.id().0));
        }
    }

    let cached_addrs: Vec<SocketAddr> = node.load_routing_table().await;
    let mut connected = false;

    // 1. Cached Peers Verification & Refresh
    if !cached_addrs.is_empty() {
        if !args.daemon { println!("> Verifying {} cached peers...", cached_addrs.len()); }
        let mut tasks = Vec::new();
        for addr in cached_addrs {
            let node_ref = node.clone();
            tasks.push(tokio::spawn(async move {
                let _ = node_ref.bootstrap(addr).await;
            }));
        }
        for t in tasks { let _ = t.await; }

        if !args.daemon { println!("> Refreshing DHT topology..."); }
        node.lookup_dht(node.id()).await;

        let table_size = node.inner.routing_table.read().await.get_all_nodes().len();
        if table_size > 0 {
            connected = true;
            if !args.daemon { println!("> DHT Refreshed. Active peers: {}", table_size); }
        } else {
            if !args.daemon { println!("> Warning: Cached peers unresponsive."); }
        }
    }

    const DEFAULT_SEED: &str = "shardnet.app:9100";
    const LOCAL_SEED:   &str = "127.0.0.1:9100";

    // 2. Explicit bootstrap argument
    if !connected && !args.seed {
        if let Some(boot_str) = args.bootstrap.as_ref() {
            if !args.daemon { println!("> Bootstrapping via {}...", boot_str); }
            if let Ok(mut addrs) = tokio::net::lookup_host(boot_str.as_str()).await {
                if let Some(addr) = addrs.next() {
                    if node.bootstrap(addr).await.is_ok() { connected = true; }
                }
            }
        }
    }

    // 3. Default public seed: shardnet.app:9100
    if !connected && !args.seed && args.bootstrap.is_none() {
        if !args.daemon { println!("> Trying default seed {}...", DEFAULT_SEED); }
        if let Ok(mut addrs) = tokio::net::lookup_host(DEFAULT_SEED).await {
            if let Some(addr) = addrs.next() {
                if node.bootstrap(addr).await.is_ok() { connected = true; }
            }
        }
    }

    // 4. Local fallback: 127.0.0.1:9100
    if !connected && !args.seed && args.bootstrap.is_none() {
        if !args.daemon { println!("> Default seed unreachable, trying local seed {}...", LOCAL_SEED); }
        if let Ok(mut addrs) = tokio::net::lookup_host(LOCAL_SEED).await {
            if let Some(addr) = addrs.next() {
                if node.bootstrap(addr).await.is_ok() { connected = true; }
            }
        }
    }

    // 5. Interactive fallback (non-daemon, non-seed only)
    if !connected && !args.seed && !args.daemon {
        println!("\n[!] All seeds unreachable. Node is running isolated.");
        println!("[?] Enter a bootstrap address or press Enter to continue:");
        loop {
            print!("bootstrap> ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let choice = input.trim().to_string();
            if choice.is_empty() { break; }
            match tokio::net::lookup_host(choice).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        if node.bootstrap(addr).await.is_ok() { break; }
                        else { println!("[!] Connect failed."); }
                    }
                }
                Err(_) => println!("[!] Invalid address."),
            }
        }
    }

    node.start_background_tasks();

    if args.daemon {
        tracing::info!("Daemon started successfully. Running indefinitely.");
        // Wait strictly for signal in daemon mode
        wait_for_signal().await;
        tracing::info!("Shutdown signal received. Saving state...");
        if let Err(e) = node.save_routing_table().await {
            tracing::error!("Failed to save routing table: {}", e);
        }
        std::process::exit(0);
    } else {
        println!("> Node operational.");
        // Unify Shutdown Path & Force Exit
        tokio::select! {
            _ = run_cli(node.clone(), args.passive, args.seed, name_cache) => {}, // Exits on /exit
            _ = wait_for_signal() => { println!("\n> Shutdown signal received."); } // Exits on Ctrl+C
        }

        println!("> Saving state...");
        let _ = node.save_routing_table().await;
        println!("> Goodbye.");

        // Force kill the process to terminate the stuck tokio::io::stdin thread
        std::process::exit(0);
    }
}

// Renamed from setup_shutdown_signal to reflect it just waits
async fn wait_for_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn load_or_generate_password(path: &str) -> Result<String> {
    let p = Path::new(path).join("sys").join("node_secret");
    if p.exists() {
        Ok(std::fs::read_to_string(p)?.trim().to_string())
    } else {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        let s = hex::encode(b);
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(p)?;
        file.write_all(s.as_bytes())?;
        Ok(s)
    }
}

fn sanitize_path(input: &str) -> String {
    let raw = input.trim().trim_matches(|c| c == '"' || c == '\'');
    Path::new(raw)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

async fn run_cli(node: Node, passive: bool, is_seed: bool, name_cache: Arc<Mutex<HashMap<String, String>>>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut input = String::new();

    loop {
        print!("\nshard> ");
        io::stdout().flush()?;

        input.clear();

        if reader.read_line(&mut input).await.is_err() {
            break;
        }

        let raw_trimmed = input.trim();
        if raw_trimmed.is_empty() { continue; }

        if raw_trimmed.starts_with('/') {
            let parts: Vec<&str> = raw_trimmed.split_whitespace().collect();
            let command = parts[0];

            match command {
                "/put" => {
                    if passive {
                        println!("[passive mode] /put is not available.");
                        continue;
                    }
                    if parts.len() < 2 {
                        println!("Usage: /put <filename>");
                    } else {
                        let path_part = raw_trimmed.strip_prefix("/put").unwrap_or("").trim();
                        let clean_path = sanitize_path(path_part);
                        if clean_path.is_empty() { println!("[!] Invalid filename."); }
                        else { handle_put(&node, &clean_path).await; }
                    }
                }
                "/get" => {
                    if parts.len() < 2 { println!("Usage: /get <link>"); continue; }
                    handle_get(&node, parts[1]).await;
                }
                "/peers" => {
                    let table: Vec<SocketAddr> = node.load_routing_table().await;
                    println!("> Routing table size: {} active peers", table.len());
                }
                "/status" => {
                    let node_id   = hex::encode(node.id().0);
                    let bound     = node.endpoint.local_addr()
                        .map(|a| a.to_string()).unwrap_or_else(|_| "unknown".into());
                    let peers     = node.inner.routing_table.read().await.get_all_nodes().len();
                    let room      = node.inner.active_room.read().await.clone()
                        .map(|r| format!("#{}", r)).unwrap_or_else(|| "none".into());
                    let used      = node.inner.storage.disk_used_bytes();
                    let max       = node.inner.storage.max_storage_bytes();
                    let pct       = if max > 0 { used * 100 / max } else { 0 };
                    let retention = node.inner.config.storage.retention_period_sec;
                    let cleanup   = node.inner.config.storage.cleanup_interval_sec;
                    let path      = node.inner.storage.root_path.display().to_string();
                    let mode      = if is_seed { "seed" } else if passive { "passive" } else { "node" };
                    let fmt = |b: u64| -> String {
                        if b >= 1_000_000_000 { format!("{:.1} GB", b as f64 / 1e9) }
                        else if b >= 1_000_000 { format!("{} MB", b / 1_000_000) }
                        else { format!("{} KB", b / 1_000) }
                    };
                    let dur = |s: u64| -> String {
                        if s >= 86400 { format!("{}d", s / 86400) }
                        else if s >= 3600 { format!("{}h", s / 3600) }
                        else { format!("{}min", s / 60) }
                    };
                    println!("\n--- Node Status ---");
                    println!("  ID        : {}", node_id);
                    println!("  Address   : {}", bound);
                    println!("  Peers     : {}", peers);
                    println!("  Room      : {}", room);
                    println!("  Mode      : {}", mode);
                    println!("  --- Storage ---");
                    println!("  Path      : {}", path);
                    println!("  Used      : {} / {} ({}%)", fmt(used), fmt(max), pct);
                    println!("  Retention : {}", dur(retention));
                    println!("  Cleanup   : every {}", dur(cleanup));
                    println!("-------------------");
                }
                "/join" => {
                    if passive {
                        println!("[passive mode] /join is not available.");
                        continue;
                    }
                    if parts.len() < 2 { println!("Usage: /join <room>"); continue; }
                    node.join_room(parts[1].to_string()).await;
                    println!("> Joined room '{}'.", parts[1]);
                }
                "/leave" => {
                    if passive {
                        println!("[passive mode] /leave is not available.");
                        continue;
                    }
                    node.leave_room().await;
                    println!("> Left room.");
                }
                "/read" | "/browse" => {
                    if parts.len() < 2 {
                        println!("Usage: /read <magnet>");
                    } else {
                        handle_read(&node, parts[1]).await;
                    }
                }
                "/name" => {
                    if passive {
                        println!("[passive mode] /name is not available.");
                        continue;
                    }
                    let alias = raw_trimmed.strip_prefix("/name").unwrap_or("").trim();
                    if alias.is_empty() {
                        println!("Usage: /name <alias>");
                    } else {
                        let own_id = hex::encode(node.id().0);
                        let key = own_id[..8].to_string();
                        name_cache.lock().unwrap().insert(key, alias.to_string());
                        if node.broadcast_chat(format!("\x1fNAME:{}", alias)).await.is_err() {
                            println!("> [!] Join a room first to broadcast your name.");
                        }
                        println!("> Name set to '{}'.", alias);
                    }
                }
                "/exit" => { break; }
                "/help" | "/?" => { display_help(passive); }
                _ => println!("Unknown command: {}. Type /help.", command),
            }
        } else {
            if passive {
                println!("[passive mode] Chat and upload are not available.");
                continue;
            }
            let possible_path_str = sanitize_path(raw_trimmed);
            if !possible_path_str.is_empty() {
                let path = Path::new(&possible_path_str);
                if path.exists() && path.is_file() {
                    println!("> Auto-detected file: '{}'", possible_path_str);
                    handle_put(&node, &possible_path_str).await;
                } else {
                    match node.broadcast_chat(raw_trimmed.to_string()).await {
                        Ok(_) => {},
                        Err(_) => println!("> [!] System: You must join a room first using /join <room> to chat."),
                    }
                }
            } else {
                 match node.broadcast_chat(raw_trimmed.to_string()).await {
                        Ok(_) => {},
                        Err(_) => println!("> [!] Join a room to chat."),
                 }
            }
        }
    }
    Ok(())
}

fn display_help(passive: bool) {
    if passive {
        println!("\n--- Available Commands [PASSIVE MODE] ---");
        println!("/get <magnet>    : Download a file via magnet link");
        println!("/read <magnet>   : Read a markdown shard inline");
        println!("/peers           : Show active peers count");
        println!("/status          : Node info, storage usage and config");
        println!("/exit            : Save state and quit");
        println!("/help            : Show this menu");
        println!("-----------------------------------------");
    } else {
        println!("\n--- Available Commands ---");
        println!("/put <file>      : Upload a file (Current Directory only)");
        println!("/get <magnet>    : Download a file via magnet link");
        println!("/read <magnet>   : Read a markdown shard inline");
        println!("/join <room>     : Join a chat room");
        println!("/leave           : Leave current room");
        println!("/name <alias>    : Set your display name");
        println!("/peers           : Show active peers count");
        println!("/status          : Node info, storage usage and config");
        println!("/exit            : Save state and quit");
        println!("/help            : Show this menu");
        println!("--------------------------");
    }
}

/// Display `text` through `less -R -F` when available, otherwise print directly.
/// -R passes ANSI colour codes; -F quits immediately if content fits one screen.
fn page(text: &str) {
    use std::io::Write as _;
    match std::process::Command::new("less")
        .args(["-R", "-F"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
        Err(_) => print!("{text}"),
    }
}

async fn handle_put(node: &Node, path: &str) {
    if !Path::new(path).exists() { println!("File not found in CWD: {}", path); return; }
    match node.send_file_stream(path).await {
        Ok((fid, key)) => {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&fid);
            combined.extend_from_slice(&key);
            let secret = BASE64_URL_SAFE_NO_PAD.encode(&combined);
            println!("\n[SUCCESS] Uploaded.\nMagnet: {}", secret);
        }
        Err(e) => println!("\nUpload failed: {}", e),
    }
}

async fn handle_get(node: &Node, secret_block: &str) {
    let combined = match BASE64_URL_SAFE_NO_PAD.decode(secret_block) {
        Ok(v) => v,
        Err(_) => { println!("Invalid format."); return; }
    };
    if combined.len() != 64 { println!("Invalid link version."); return; }
    let mut fid = [0u8; 32];
    let mut key = [0u8; 32];
    fid.copy_from_slice(&combined[0..32]);
    key.copy_from_slice(&combined[32..64]);
    println!("> Fetching file to ./downloads...");
    match node.fetch_file_stream(fid, key, ".").await {
        Ok(_) => println!("\n[SUCCESS] Download complete."),
        Err(e) => println!("\nDownload failed: {}", e),
    }
}

async fn handle_read(node: &Node, secret_block: &str) {
    const PREVIEW_LIMIT: u64 = 512 * 1024;

    let combined = match BASE64_URL_SAFE_NO_PAD.decode(secret_block) {
        Ok(v) => v,
        Err(_) => { println!("[!] Invalid magnet format."); return; }
    };
    if combined.len() != 64 {
        println!("[!] Invalid magnet (expected 64 bytes).");
        return;
    }
    let mut fid = [0u8; 32];
    let mut key = [0u8; 32];
    fid.copy_from_slice(&combined[0..32]);
    key.copy_from_slice(&combined[32..64]);

    let mut rng_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rng_bytes);
    let tmp_dir = std::env::temp_dir()
        .join(format!("shard_read_{}", hex::encode(rng_bytes)));

    if std::fs::create_dir_all(&tmp_dir).is_err() {
        println!("[!] Failed to create temp directory.");
        return;
    }

    let out = tmp_dir.to_str().unwrap_or(".").to_string();
    println!("> Fetching...");
    let fetch = node.fetch_file_stream(fid, key, &out).await;

    let result: std::result::Result<(), String> = (|| {
        fetch.map_err(|e| e.to_string())?;

        let entry = std::fs::read_dir(tmp_dir.join("downloads"))
            .ok()
            .and_then(|mut d| d.next())
            .and_then(|e| e.ok())
            .ok_or_else(|| "Download produced no file.".to_string())?;

        let path = entry.path();
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if ext != "md" && ext != "markdown" {
            return Err(format!(
                "Not a markdown file (.{ext}) — use /get to download it."
            ));
        }

        let size = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();
        if size > PREVIEW_LIMIT {
            return Err(format!(
                "File too large for preview ({} KB) — use /get to download it.",
                size / 1024
            ));
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|_| "Content is not valid UTF-8.".to_string())?;

        let fname = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("document.md");

        let mut rendered = String::new();
        rendered.push('\n');
        rendered.push_str(&term_md::render_header_to_string(fname));
        rendered.push_str(&term_md::render_to_string(&content));
        rendered.push('\n');

        page(&rendered);

        Ok(())
    })();

    let _ = std::fs::remove_dir_all(&tmp_dir);

    if let Err(e) = result {
        println!("[!] Read error: {e}");
    }
}
