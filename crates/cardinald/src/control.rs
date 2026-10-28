//! The local control socket: one JSON request per line, one JSON reply per
//! line. Only the user who runs the daemon can connect (mode 0600).
//!
//! Requests are `{"cmd": "<name>", ...}`; replies are `{"ok": true, ...}`
//! or `{"ok": false, "error": "<what to do>"}`.

use std::collections::HashMap;
use std::sync::Arc;

use cardinal_identity::Power;
use cardinal_space::account;
use cardinal_space::files::{self, Content, Files, FILE_CONTENT};
use cardinal_space::state::State;
use cardinal_space::{NodeId, SpaceOpBody, ROOT};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::daemon::{Daemon, PairState};

/// Sends a request to a running daemon and returns its reply.
pub async fn request(socket: &std::path::Path, req: &Value) -> anyhow::Result<Value> {
    let s = UnixStream::connect(socket).await?;
    let (r, mut w) = s.into_split();
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    w.write_all(line.as_bytes()).await?;
    let mut lines = BufReader::new(r).lines();
    let reply = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("the daemon closed the connection"))?;
    Ok(serde_json::from_str(&reply)?)
}

/// Starts serving the control socket.
pub fn serve(d: Arc<Daemon>) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let path = d.paths.socket.clone();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            anyhow::bail!(
                "a cardinal daemon is already running for {} (socket {})",
                d.paths.home.display(),
                path.display()
            );
        }
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(tokio::spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else {
                continue;
            };
            let d = d.clone();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let reply = match serde_json::from_str::<Value>(&line) {
                        Ok(req) => match handle(&d, &req).await {
                            Ok(mut v) => {
                                v["ok"] = json!(true);
                                v
                            }
                            Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
                        },
                        Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
                    };
                    let mut out = reply.to_string();
                    out.push('\n');
                    if w.write_all(out.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    }))
}

fn arg<'a>(req: &'a Value, name: &str) -> anyhow::Result<&'a str> {
    req.get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing argument {name}"))
}

fn power_name(p: Power) -> &'static str {
    match p {
        Power::Device => "device",
        Power::Admin => "admin",
        Power::Root => "root",
    }
}

/// The path of a node in a files space's state.
pub fn node_path(st: &State, node: &NodeId) -> String {
    let mut parts = Vec::new();
    let mut cur = *node;
    for _ in 0..10_000 {
        if cur == ROOT {
            break;
        }
        let Some(n) = st.node(&cur) else { break };
        parts.push(n.name.clone());
        cur = n.parent;
    }
    parts.reverse();
    parts.join("/")
}

fn require_files(d: &Daemon) -> anyhow::Result<[u8; 32]> {
    let core = d.core();
    if core.identity.is_none() {
        anyhow::bail!(
            "this device does not belong to anyone yet: run `cardinal init` or `cardinal pair`"
        );
    }
    core.files_id().ok_or_else(|| {
        anyhow::anyhow!("your files have not arrived on this device yet; wait for it to sync")
    })
}

async fn handle(d: &Arc<Daemon>, req: &Value) -> anyhow::Result<Value> {
    let cmd = arg(req, "cmd")?;
    match cmd {
        "status" => Ok(status(d)),
        "devices" => Ok(json!({"devices": devices(d)})),
        "stop" => {
            let _ = d.stopping.send(true);
            Ok(json!({}))
        }
        "reload" => {
            reload(d)?;
            Ok(json!({}))
        }
        "flush" => {
            let d2 = d.clone();
            let n = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
                let m = d2.mount.lock().unwrap_or_else(|e| e.into_inner());
                match m.as_ref() {
                    Some(m) => m.flush(),
                    None => Ok(0),
                }
            })
            .await??;
            Ok(json!({"entries": n}))
        }
        "pair-show" => {
            let admin = req.get("admin").and_then(|v| v.as_bool()).unwrap_or(false);
            let s = crate::pair::show(d, admin).await?;
            Ok(
                json!({"code": s.code, "addrs": s.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>() }),
            )
        }
        "pair-status" => {
            let ps = d.pairing.lock().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(match ps {
                PairState::Idle => json!({"state": "idle"}),
                PairState::Showing { code } => json!({"state": "showing", "code": code}),
                PairState::Joining { admin_name, .. } => {
                    json!({"state": "joining", "admin": admin_name})
                }
                PairState::Joined { admin_name } => {
                    let files = d.core().files_id().is_some();
                    json!({"state": "joined", "admin": admin_name, "files": files})
                }
                PairState::Failed(e) => json!({"state": "failed", "error": e}),
            })
        }
        "pair-type" => {
            let code = arg(req, "code")?;
            let at = match req.get("at").and_then(|v| v.as_str()) {
                Some(a) => Some(
                    tokio::net::lookup_host(a)
                        .await
                        .ok()
                        .and_then(|mut i| i.next())
                        .ok_or_else(|| anyhow::anyhow!("{a} is not an address (ip:port)"))?,
                ),
                None => None,
            };
            let admin = req.get("admin").and_then(|v| v.as_bool()).unwrap_or(false);
            let name = crate::pair::type_code(d, code, at, admin).await?;
            Ok(json!({"name": name}))
        }
        "remove-device" => remove_device(d, arg(req, "who")?),
        "peer-add" => {
            let addr = arg(req, "addr")?.trim().to_owned();
            if !addr.contains(':') {
                anyhow::bail!("give the address as host:port, e.g. myserver.example.com:7171");
            }
            {
                let mut c = d.config();
                if !c.peers.contains(&addr) {
                    c.peers.push(addr.clone());
                }
            }
            d.save_config()?;
            let d2 = d.clone();
            tokio::spawn(async move { d2.connect_all().await });
            Ok(json!({"addr": addr}))
        }
        "peer-remove" => {
            let addr = arg(req, "addr")?;
            let found = {
                let mut c = d.config();
                let before = c.peers.len();
                c.peers.retain(|p| p != addr);
                before != c.peers.len()
            };
            if !found {
                anyhow::bail!("{addr} is not in the list; see `cardinal peer list`");
            }
            d.book
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .manual
                .remove(addr);
            d.save_config()?;
            Ok(json!({}))
        }
        "peer-list" => {
            let peers = d.config().peers.clone();
            let book = d.book.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let names = d.core().device_names();
            let list: Vec<Value> = peers
                .iter()
                .map(|p| {
                    let dev = book.manual.get(p).and_then(|h| {
                        let b = hex::decode(h).ok()?;
                        <[u8; 32]>::try_from(&b[..]).ok()
                    });
                    json!({
                        "addr": p,
                        "device": dev.map(|k| names.get(&k).cloned().unwrap_or_else(|| account::short_key(&k))),
                    })
                })
                .collect();
            Ok(json!({"peers": list}))
        }
        "mount" => {
            let path = req
                .get("path")
                .and_then(|v| v.as_str())
                .map(std::path::PathBuf::from)
                .or_else(|| d.config().mount.clone())
                .unwrap_or_else(|| crate::paths::home_dir().join("Cardinal"));
            let d2 = d.clone();
            let p2 = path.clone();
            tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                d2.unmount();
                d2.config().mount = Some(p2.clone());
                d2.save_config()?;
                if d2.core().files_id().is_none() {
                    return Ok(());
                }
                if let Err(e) = crate::daemon::fuse_usable() {
                    anyhow::bail!("cannot mount: FUSE is not available here ({e})");
                }
                d2.ensure_mounted();
                if d2.mount.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
                    anyhow::bail!("could not mount at {}; see `cardinal log`", p2.display());
                }
                Ok(())
            })
            .await??;
            Ok(json!({"path": path}))
        }
        "unmount" => {
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || {
                d2.unmount();
                d2.config().mount = None;
                d2.save_config()
            })
            .await??;
            Ok(json!({}))
        }
        "conflicts" => conflicts(d),
        "history" => history(d, arg(req, "path")?),
        "restore" => {
            let path = arg(req, "path")?.to_owned();
            let version = req
                .get("version")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("missing --version"))?;
            restore(d, &path, version).await
        }
        "pin" | "unpin" => {
            let path = arg(req, "path")?.trim_matches('/').to_owned();
            {
                let mut c = d.config();
                c.pins.retain(|p| *p != path);
                if cmd == "pin" {
                    c.pins.push(path.clone());
                }
            }
            d.save_config()?;
            d.bump();
            let on_demand = d.config().on_demand();
            Ok(json!({"path": path, "on_demand": on_demand}))
        }
        "retention" => {
            let mode = arg(req, "mode")?;
            if mode != "full" && mode != "on-demand" {
                anyhow::bail!("retention is `full` or `on-demand`");
            }
            d.config().retention = mode.to_owned();
            d.save_config()?;
            d.bump();
            Ok(json!({"retention": mode}))
        }
        other => anyhow::bail!("unknown command {other:?}"),
    }
}

fn reload(d: &Arc<Daemon>) -> anyhow::Result<()> {
    {
        let mut core = d.core();
        if core.identity.is_some() {
            return Ok(());
        }
        *core = crate::core::Core::load(&d.paths, d.keys.clone())?;
    }
    let (id, st) = {
        let core = d.core();
        let Some(i) = core.identity.as_ref() else {
            anyhow::bail!("no identity was found in {}", d.paths.home.display());
        };
        (i.id(), i.state())
    };
    d.endpoint.set_identity(Some(cardinal_link::LocalIdentity {
        identity: id,
        signing_key: d.keys.signing.clone(),
    }));
    d.directory.update(Some(&st));
    *d.config() = crate::config::Config::load(&d.paths.config())?;
    d.bump();
    d.housekeeping();
    Ok(())
}

fn devices(d: &Daemon) -> Vec<Value> {
    let (st, names) = {
        let core = d.core();
        let Some(i) = core.identity.as_ref() else {
            return Vec::new();
        };
        (i.state(), core.device_names())
    };
    let me = d.keys.key();
    let book = d.book.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let stats = d
        .blob_stats
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut v: Vec<Value> = st
        .keys
        .values()
        .map(|k| {
            let x = k.link_key.as_ref().map(|l| *l.x25519());
            let online = k.key == me || x.is_some_and(|x| d.is_online(&x));
            // Where it listens, if known; else where its session comes from.
            let addr = book
                .addrs
                .get(&hex::encode(k.key))
                .and_then(|v| v.first().cloned())
                .or_else(|| x.and_then(|x| d.session_addr(&x)).map(|a| a.to_string()));
            json!({
                "name": names.get(&k.key).cloned().unwrap_or_else(|| account::short_key(&k.key)),
                "key": hex::encode(&k.key[..8]),
                "power": power_name(k.power),
                "this": k.key == me,
                "online": online,
                "addr": if k.key == me { None } else { addr },
                // what this device's fetcher thinks of it as a source
                "fetch": x.and_then(|x| stats.get(&x)).map(|s| json!({
                    "rate": s.rate as u64,
                    "latency_ms": (s.latency * 1000.0) as u64,
                    "replies": s.samples,
                    "received": s.bytes_total,
                })),
            })
        })
        .collect();
    v.sort_by_key(|x| {
        (
            !x["this"].as_bool().unwrap_or(false),
            x["name"].as_str().unwrap_or("").to_owned(),
        )
    });
    v
}

fn status(d: &Arc<Daemon>) -> Value {
    let cfg = d.config().clone();
    let (identity, spaces, conflicts, files) = {
        let core = d.core();
        let identity = core.identity.as_ref().map(|i| hex::encode(&i.id()[..8]));
        let files = core.files_id();
        let spaces: Vec<Value> = core
            .spaces
            .values()
            .map(|h| {
                json!({
                    "id": hex::encode(&h.id[..8]),
                    "kind": match h.profile() {
                        Some(cardinal_space::Profile::ACCOUNT) => "account",
                        Some(cardinal_space::Profile::FILES) => "files",
                        Some(_) => "other",
                        None => "arriving",
                    },
                    "entries": h.set_len(),
                })
            })
            .collect();
        let conflicts = files
            .and_then(|f| core.spaces.get(&f))
            .and_then(|h| h.space.as_ref())
            .map(|s| s.state().conflicts().len())
            .unwrap_or(0);
        (identity, spaces, conflicts, files)
    };
    let (mounted, pending) = {
        let m = d.mount.lock().unwrap_or_else(|e| e.into_inner());
        match m.as_ref() {
            Some(m) => (
                Some(m.path.display().to_string()),
                m.tree()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .has_pending(),
            ),
            None => (None, false),
        }
    };
    let progress = d.progress.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let pairing = match d.pairing.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        PairState::Idle => Value::Null,
        PairState::Showing { code } => json!({"state": "showing", "code": code}),
        PairState::Joining { admin_name, .. } => json!({"state": "joining", "admin": admin_name}),
        PairState::Joined { .. } => Value::Null,
        PairState::Failed(e) => json!({"state": "failed", "error": e}),
    };
    json!({
        "name": cfg.name,
        "home": d.paths.home.display().to_string(),
        "identity": identity,
        "listen": d.endpoint.tcp_addr().map(|a| a.to_string()),
        "devices": devices(d),
        "spaces": spaces,
        "files_ready": files.is_some(),
        "mount": cfg.mount.as_ref().map(|p| p.display().to_string()),
        "mounted": mounted,
        "mount_unavailable": d.mount_unavailable.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        "pending_changes": pending,
        "retention": cfg.retention,
        "conflicts": conflicts,
        "progress": progress,
        "pairing": pairing,
        "peers": cfg.peers,
        "uptime_s": d.uptime().as_secs(),
    })
}

fn conflicts(d: &Daemon) -> anyhow::Result<Value> {
    let files_id = require_files(d)?;
    let core = d.core();
    let names = core.device_names();
    let sp = core.spaces[&files_id]
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
    let f = Files::with_device_names(sp, |k| {
        names
            .get(k)
            .cloned()
            .unwrap_or_else(|| account::short_key(k))
    });
    let st = sp.state();
    let mut out = Vec::new();
    for n in st.conflicts() {
        if !st.is_visible(&n.id) && !n.delete_conflict {
            continue;
        }
        let path = node_path(st, &n.id);
        let versions: Vec<Value> = f
            .content(&n.id)
            .iter()
            .map(|v| {
                json!({
                    "device": names.get(&v.device).cloned().unwrap_or_else(|| account::short_key(&v.device)),
                    "time": v.time,
                    "size": v.content.as_ref().map(|c| c.size()),
                })
            })
            .collect();
        let copies: Vec<String> = {
            let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            f.list_path(parent)
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.node == n.id && e.conflict_version.is_some())
                .map(|e| {
                    if parent.is_empty() {
                        e.name
                    } else {
                        format!("{parent}/{}", e.name)
                    }
                })
                .collect()
        };
        out.push(json!({
            "path": path,
            "versions": versions,
            "copies": copies,
            "delete_conflict": n.delete_conflict,
        }));
    }
    Ok(json!({"conflicts": out}))
}

/// One content version: entry, time, device, content.
type VersionRow = ([u8; 32], Option<u64>, [u8; 32], Option<Content>);

/// The content versions of a node, oldest first.
fn versions(sp: &cardinal_space::Space, node: &NodeId) -> Vec<VersionRow> {
    let f = Files::new(sp);
    let mut out = Vec::new();
    for h in f.history(node) {
        let c = match &h.op {
            SpaceOpBody::Create { fields, .. } => {
                fields.get(FILE_CONTENT).and_then(Content::from_value)
            }
            SpaceOpBody::Set { key, value, .. } if *key == FILE_CONTENT => {
                value.as_ref().and_then(Content::from_value)
            }
            _ => continue,
        };
        out.push((h.entry, h.time, h.device, c));
    }
    out
}

fn history(d: &Daemon, path: &str) -> anyhow::Result<Value> {
    let files_id = require_files(d)?;
    let core = d.core();
    let names = core.device_names();
    let sp = core.spaces[&files_id]
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
    let r = Files::new(sp)
        .resolve(path)
        .ok_or_else(|| anyhow::anyhow!("{path} does not exist in your files"))?;
    let vs = versions(sp, &r.node);
    let current: HashMap<[u8; 32], ()> = Files::new(sp)
        .content(&r.node)
        .iter()
        .map(|v| (v.entry, ()))
        .collect();
    let list: Vec<Value> = vs
        .iter()
        .enumerate()
        .map(|(i, (e, t, dev, c))| {
            json!({
                "version": i + 1,
                "time": t,
                "device": names.get(dev).cloned().unwrap_or_else(|| account::short_key(dev)),
                "size": c.as_ref().map(|c| c.size()),
                "current": current.contains_key(e),
            })
        })
        .collect();
    Ok(json!({"path": path, "versions": list}))
}

async fn restore(d: &Arc<Daemon>, path: &str, version: u64) -> anyhow::Result<Value> {
    let files_id = require_files(d)?;
    // save anything pending first, so the restore descends from it
    let d2 = d.clone();
    tokio::task::spawn_blocking(move || {
        let m = d2.mount.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = m.as_ref() {
            let _ = m.flush();
        }
    })
    .await?;
    let (node, content) = {
        let core = d.core();
        let sp = core.spaces[&files_id]
            .space
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
        let r = Files::new(sp)
            .resolve(path)
            .ok_or_else(|| anyhow::anyhow!("{path} does not exist in your files"))?;
        let vs = versions(sp, &r.node);
        let (_, _, _, c) = vs
            .get((version as usize).wrapping_sub(1))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{path} has versions 1 to {}; see `cardinal history {path}`",
                    vs.len()
                )
            })?;
        (
            r.node,
            c.ok_or_else(|| anyhow::anyhow!("that version has no content"))?,
        )
    };
    d.write_and_push(&files_id, vec![files::set_content(node, &content)])?;
    Ok(json!({"path": path, "version": version}))
}

fn remove_device(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Value> {
    let me = d.keys.key();
    let (key, name) = {
        let core = d.core();
        let ident = core
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
        let names = core.device_names();
        let st = ident.state();
        let w = who.to_lowercase();
        let matches: Vec<[u8; 32]> = st
            .keys
            .keys()
            .filter(|k| {
                names.get(*k).is_some_and(|n| n.to_lowercase() == w)
                    || hex::encode(k).starts_with(&w)
            })
            .copied()
            .collect();
        match matches.as_slice() {
            [] => anyhow::bail!("no device called {who:?}; see `cardinal devices`"),
            [k] => (
                *k,
                names
                    .get(k)
                    .cloned()
                    .unwrap_or_else(|| account::short_key(k)),
            ),
            _ => anyhow::bail!(
                "several devices match {who:?}; use the key shown by `cardinal devices`"
            ),
        }
    };
    if key == me {
        anyhow::bail!("this is the device you are using; remove it from another of your devices");
    }
    let entries = {
        let mut core = d.core();
        let ident = core.identity.as_mut().expect("identity");
        let current = ident
            .enc
            .first()
            .map(|k| cardinal_crypto::HybridKeyPair::from_secret_bytes(&k.secret_bytes()));
        let e1 = ident
            .log
            .remove_key(&d.keys.device.signing, &key)
            .map_err(|e| {
                anyhow::anyhow!(
                    "cannot remove {name}: {e} (only a device with more power can remove it)"
                )
            })?;
        ident.record_own(&e1)?;
        let new = cardinal_crypto::HybridKeyPair::generate();
        let e2 = ident
            .log
            .set_encryption_key(&d.keys.device.signing, &new, current.as_ref())?;
        ident.record_own(&e2)?;
        drop(core);
        let mut core = d.core();
        let keys = d.keys.clone();
        if let Some(i) = core.identity.as_mut() {
            if let Ok(k) = i.log.open_encryption_key(&keys.device) {
                i.enc = i.log.key_chain(k);
            }
        }
        for h in core.spaces.values_mut() {
            h.needs_rotate = true;
        }
        vec![e1.encode(), e2.encode()]
    };
    d.identity_changed();
    d.push_identity(entries);
    // forget its device node
    let acc = {
        let core = d.core();
        core.account_id().and_then(|a| {
            let st = core.spaces[&a].space.as_ref()?.state();
            account::devices(st)
                .into_iter()
                .find(|x| x.key == key)
                .map(|x| (a, x.node))
        })
    };
    if let Some((a, node)) = acc {
        d.write_and_push(&a, vec![cardinal_space::SpaceOp::delete(node)])?;
    }
    Ok(json!({"name": name}))
}
