
use anyhow::*;
use tauri::{Manager, SystemTray, SystemTrayEvent};
use std::{path::PathBuf};
use tokio::{sync::mpsc, fs};
use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind};
use directories::ProjectDirs;
use rusqlite::{params, Connection};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use rand::RngCore;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use futures::StreamExt;

#[derive(Clone)]
struct AppCfg {
  root: PathBuf,        // ~/Bloom
  servers: Vec<String>, // server endpoints
  key: Option<[u8;32]>, // AES-256-GCM key for Private
  db_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct ServersCfg { servers: Vec<String> }

fn ensure_db(db_path: &PathBuf) -> Result<()> {
  let conn = Connection::open(db_path)?;
  conn.execute_batch(r#"
  PRAGMA journal_mode=WAL;
  CREATE TABLE IF NOT EXISTS uploads(
    id INTEGER PRIMARY KEY,
    content_sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    rel_path TEXT NOT NULL,
    is_private INTEGER NOT NULL,
    server_url TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(content_sha256, server_url) ON CONFLICT IGNORE
  );
  "#)?;
  Ok(())
}

fn mark_status(db: &PathBuf, sha: &str, size: u64, rel: &str, privv: bool, server: &str, status: &str) -> Result<()> {
  let conn = Connection::open(db)?;
  let now = chrono::Utc::now().timestamp();
  conn.execute(
    "INSERT OR REPLACE INTO uploads(content_sha256,size_bytes,rel_path,is_private,server_url,status,created_at)
     VALUES(?1,?2,?3,?4,?5,?6,COALESCE((SELECT created_at FROM uploads WHERE content_sha256=?1 AND server_url=?5),?7))",
     params![sha, size as i64, rel, if privv {1} else {0}, server, status, now]
  )?;
  Ok(())
}

fn already_done_for_all(db: &PathBuf, sha: &str, servers: &[String]) -> Result<bool> {
  let conn = Connection::open(db)?;
  for s in servers {
    let mut st = conn.prepare("SELECT 1 FROM uploads WHERE content_sha256=?1 AND server_url=?2 AND status='done' LIMIT 1")?;
    let has = st.exists(params![sha, s])?;
    if !has { return Ok(false); }
  }
  Ok(true)
}

fn already_done_for(db: &PathBuf, sha: &str, server: &str) -> Result<bool> {
  let conn = Connection::open(db)?;
  let mut st = conn.prepare("SELECT 1 FROM uploads WHERE content_sha256=?1 AND server_url=?2 AND status='done' LIMIT 1")?;
  Ok(st.exists(params![sha, server])?)
}

#[tauri::command]
async fn start_watcher() -> Result<(), String> {
  inner_start_watcher().await.map_err(|e| format!("{:#}", e))
}

#[tokio::main]
async fn main() -> Result<()> {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![start_watcher])
    .setup(|app| {
      use tauri_plugin_notification::NotificationExt;

      tauri::Builder::default()
      .plugin(tauri_plugin_notification::init())
      .invoke_handler(tauri::generate_handler![start_watcher])
      /* ... */
      .run(tauri::generate_context!())
      .expect("error while running tauri application");
      let tray = SystemTray::new();
      app.set_system_tray(tray).unwrap();
      Ok(())
    })
    .on_system_tray_event(|_app, event| {
      if let SystemTrayEvent::LeftClick { .. } = event {
        // Could open preferences window
      }
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
  Ok(())
}

async fn inner_start_watcher() -> Result<()> {
  let cfg = init_cfg().await?;
  ensure_dirs(&cfg).await?;
  ensure_db(&cfg.db_path)?;

  let (tx, mut rx) = mpsc::channel::<PathBuf>(1024);

  let mut watcher = notify::recommended_watcher({
    let tx = tx.clone();
    move |res: notify::Result<notify::Event>| {
      if let Ok(ev) = res {
        if matches!(ev.kind, EventKind::Modify(_) | EventKind::Create(_)) {
          for p in ev.paths {
            let _ = tx.try_send(p);
          }
        }
      }
    }
  })?;
  watcher.watch(&cfg.root.join("Public"), RecursiveMode::NonRecursive)?;
  watcher.watch(&cfg.root.join("Private"), RecursiveMode::NonRecursive)?;

  prime_existing(&cfg, tx.clone()).await?;

  while let Some(path) = rx.recv().await {
    let cfg2 = cfg.clone();
    tokio::spawn(async move {
      if let Err(e) = handle_path(&cfg2, path).await {
        eprintln!("upload error: {e:#}");
      }
    });
  }
  Ok(())
}

async fn init_cfg() -> Result<AppCfg> {
  let home = dirs::home_dir().context("no home dir")?;
  let root = home.join("Bloom");

  let proj = ProjectDirs::from("org","bloom","VineWatcher").context("no project dirs")?;
  let cfg_dir = proj.config_dir().to_path_buf();
  fs::create_dir_all(&cfg_dir).await?;
  let db_path = cfg_dir.join("state.sqlite");

  let servers_path = cfg_dir.join("servers.json");
  let servers: Vec<String> = if fs::try_exists(&servers_path).await? {
    let s = fs::read(&servers_path).await?;
    serde_json::from_slice::<ServersCfg>(&s)?.servers
  } else {
    let default = ServersCfg { servers: vec!["https://blossom.example".into()] };
    fs::write(&servers_path, serde_json::to_vec_pretty(&default)?).await?;
    default.servers
  };

  let key_path = cfg_dir.join("private.key");
  let key = if fs::try_exists(&key_path).await? {
    let k = fs::read(&key_path).await?;
    if k.len() == 32 {
      let mut arr = [0u8;32]; arr.copy_from_slice(&k); Some(arr)
    } else { None }
  } else {
    let mut k = [0u8;32];
    rand::thread_rng().fill_bytes(&mut k);
    fs::write(&key_path, &k).await?;
    Some(k)
  };

  Ok(AppCfg { root, servers, key, db_path })
}

async fn ensure_dirs(cfg: &AppCfg) -> Result<()> {
  fs::create_dir_all(cfg.root.join("Public")).await?;
  fs::create_dir_all(cfg.root.join("Private")).await?;
  Ok(())
}

async fn prime_existing(cfg: &AppCfg, tx: mpsc::Sender<PathBuf>) -> Result<()> {
  for sub in ["Public", "Private"] {
    let dir = cfg.root.join(sub);
    let mut rd = match fs::read_dir(&dir).await {
      Ok(x) => x,
      Err(_) => continue
    };
    while let Ok(Some(ent)) = rd.next_entry().await {
      if ent.file_type().await.map(|t| t.is_file()).unwrap_or(false) {
        let _ = tx.send(ent.path()).await;
      }
    }
  }
  Ok(())
}

async fn handle_path(cfg: &AppCfg, p: PathBuf) -> Result<()> {
  if !p.is_file() { return Ok(()); }
  tokio::time::sleep(std::time::Duration::from_secs(2)).await;

  let is_private = p.starts_with(cfg.root.join("Private"));
  let rel_path = p.strip_prefix(&cfg.root).unwrap_or(&p).to_string_lossy().to_string();
  let meta = fs::metadata(&p).await?;
  let size = meta.len();

  let mut hasher = Sha256::new();
  let mut f = tokio::fs::File::open(&p).await?;
  use tokio::io::AsyncReadExt;
  let mut buf = vec![0u8; 1024*1024];
  loop {
    let n = f.read(&mut buf).await?;
    if n == 0 { break; }
    hasher.update(&buf[..n]);
  }
  let sha = hex::encode(hasher.finalize());

  if already_done_for_all(&cfg.db_path, &sha, &cfg.servers)? { return Ok(()); }

  let mime = infer::get_from_path(&p).ok().flatten().map(|t| t.mime_type().to_string()).unwrap_or("application/octet-stream".into());

  for server in &cfg.servers {
    if already_done_for(&cfg.db_path, &sha, server)? { continue; }

    let res = if is_private {
      upload_private(&p, &mime, server, cfg.key.as_ref().context("no private key")?).await
    } else {
      upload_public(&p, &mime, server).await
    };

    match res {
      Ok(_) => { let _ = mark_status(&cfg.db_path, &sha, size, &rel_path, is_private, server, "done"); }
      Err(e) => {
        eprintln!("upload failed to {server}: {e:#}");
        let _ = mark_status(&cfg.db_path, &sha, size, &rel_path, is_private, server, "failed");
      }
    }
  }

  Ok(())
}

async fn upload_public(p: &PathBuf, mime: &str, server: &str) -> Result<()> {
  let url = format!("{server}/upload");
  let file = tokio::fs::File::open(p).await?;
  let stream = tokio_util::io::ReaderStream::new(file);
  let body = reqwest::Body::wrap_stream(stream);
  let res = reqwest::Client::new()
    .post(url)
    .header("Content-Type", mime)
    .body(body)
    .send().await?;
  if !res.status().is_success() { bail!("status {}", res.status()); }
  Ok(())
}

async fn upload_private(p: &PathBuf, _mime: &str, server: &str, key: & [u8;32]) -> Result<()> {
  let plaintext = tokio::fs::read(p).await?;
  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
  let nonce_bytes: [u8;12] = rand::random();
  let nonce = Nonce::from_slice(&nonce_bytes);
  let mut blob = cipher.encrypt(nonce, plaintext.as_ref())
    .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
  let mut payload = nonce_bytes.to_vec();
  payload.append(&mut blob);

  let url = format!("{server}/upload");
  let res = reqwest::Client::new()
    .post(url)
    .header("Content-Type", "application/octet-stream")
    .body(payload)
    .send().await?;
  if !res.status().is_success() { bail!("status {}", res.status()); }
  Ok(())
}
