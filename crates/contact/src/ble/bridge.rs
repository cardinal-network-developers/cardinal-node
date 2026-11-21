//! A radio another program drives, over a Unix socket: on Android the app,
//! whose Kotlin has the Bluetooth APIs, while this service is a program of
//! its own that cannot reach them.
//!
//! The service listens on the socket, which only its own user may open
//! (mode 0600, and each connection's peer is checked to be of the same
//! user). The app opens one **control** connection, whose first line is
//! `{"control": true}`, then a JSON object per line each way, and one
//! connection more for each **channel**, whose first line says which, after
//! which the bytes are the channel's. Any other first line, or none within
//! five seconds, ends the connection.
//!
//! The service asks, on the control connection:
//!
//! - `{"op": "listen"}`, answered `{"op": "listening", "psm": n}` or
//!   `{"op": "listen-failed", "error": "..."}`; `{"op": "unlisten"}`;
//! - `{"op": "advertise", "data": hex, "legacy": hex}`: the service data of
//!   an extended advertisement, and of a legacy one with the UUID in the
//!   advertisement and the data in the scan response, for where extended
//!   advertising is not supported; `{"op": "unadvertise"}`;
//! - `{"op": "scan"}`, `{"op": "unscan"}`;
//! - `{"op": "connect", "id": n, "addr": "AA:BB:...", "random": bool,
//!   "psm": n}`.
//!
//! The app says:
//!
//! - `{"op": "state", "available": bool, "why": "..."}`, first and at each
//!   change;
//! - `{"op": "seen", "addr": "...", "random": bool, "data": hex}` for each
//!   advertisement under the service UUID;
//! - `{"op": "connect-failed", "id": n, "error": "..."}`;
//! - `{"op": "advertise-failed", "error": "..."}`;
//! - `{"op": "scan-failed", "error": "..."}`: scanning stopped, and the
//!   service says why and starts again.
//!
//! A channel connection begins `{"channel": n}` for the channel `connect`
//! asked for, or `{"incoming": true, "addr": "...", "random": bool}` for one
//! another device opened.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use super::{BleAddr, BoxChannel, Keys, Listening, Radio, RadioFuture, Sighting};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Default)]
struct Shared {
    /// Lines to the app, while it is connected.
    to_app: Option<mpsc::UnboundedSender<String>>,
    /// What the app last said of the radio.
    state: Option<Result<(), String>>,
    listening: Option<mpsc::Sender<(BleAddr, BoxChannel)>>,
    psm: Option<oneshot::Sender<io::Result<u16>>>,
    scanning: Option<mpsc::Sender<Sighting>>,
    connecting: HashMap<u64, oneshot::Sender<io::Result<BoxChannel>>>,
    /// Which control connection is the app's now: a later one replaces it.
    control: u64,
    /// What the app last said went wrong.
    failure: Option<String>,
}

/// A radio the app drives (see the module's documentation).
#[derive(Clone)]
pub struct BridgeRadio {
    shared: Arc<Mutex<Shared>>,
    /// Channels asked for, by number.
    next: Arc<AtomicU64>,
    /// Refreshes of the advertisement: whose turn a legacy one is.
    turn: Arc<AtomicU64>,
    path: PathBuf,
}

/// How long a connection may take to say what it is.
const FIRST_LINE_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether the other end of `s` runs as `uid`.
fn same_user(s: &UnixStream, uid: u32) -> bool {
    s.peer_cred().is_ok_and(|c| c.uid() == uid)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

fn addr_of(v: &Value) -> Option<BleAddr> {
    BleAddr::parse(v["addr"].as_str()?, v["random"].as_bool().unwrap_or(true))
}

/// One line, read a byte at a time, so nothing after it is taken from the
/// channel.
async fn first_line(s: &mut UnixStream) -> io::Result<String> {
    let mut line = Vec::new();
    loop {
        let b = s.read_u8().await?;
        if b == b'\n' {
            break;
        }
        line.push(b);
        if line.len() > 4096 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
    }
    String::from_utf8(line).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

impl BridgeRadio {
    /// Listens at `path` for the app. Must be called within a runtime.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<BridgeRadio> {
        let path = path.as_ref().to_path_buf();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        // The socket is this process's user's: only they may use it.
        let uid = std::fs::metadata(&path)?.uid();
        let r = BridgeRadio {
            shared: Arc::default(),
            next: Arc::new(AtomicU64::new(1)),
            turn: Arc::new(AtomicU64::new(0)),
            path,
        };
        let shared = r.shared.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                if !same_user(&s, uid) {
                    continue;
                }
                let shared = shared.clone();
                tokio::spawn(async move {
                    let _ = serve(shared, s).await;
                });
            }
        });
        Ok(r)
    }

    fn tell(&self, v: Value) -> io::Result<()> {
        let held = lock(&self.shared);
        let tx = held
            .to_app
            .as_ref()
            .ok_or_else(|| io::Error::other("the app's Bluetooth is not connected"))?;
        tx.send(v.to_string())
            .map_err(|_| io::Error::other("the app's Bluetooth went away"))
    }

    fn told_on_drop(&self, v: Value) -> Box<dyn Send> {
        struct Tell(BridgeRadio, Value);
        impl Drop for Tell {
            fn drop(&mut self) {
                let _ = self.0.tell(self.1.clone());
            }
        }
        Box::new(Tell(self.clone(), v))
    }
}

async fn serve(shared: Arc<Mutex<Shared>>, mut s: UnixStream) -> io::Result<()> {
    let first = tokio::time::timeout(FIRST_LINE_WITHIN, first_line(&mut s))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let v: Value =
        serde_json::from_str(&first).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if let Some(id) = v["channel"].as_u64() {
        let tx = lock(&shared).connecting.remove(&id);
        if let Some(tx) = tx {
            let _ = tx.send(Ok(Box::new(s)));
        }
        return Ok(());
    }
    if v["incoming"] == json!(true) {
        let Some(from) = addr_of(&v) else {
            return Ok(());
        };
        let tx = lock(&shared).listening.clone();
        if let Some(tx) = tx {
            let _ = tx.send((from, Box::new(s))).await;
        }
        return Ok(());
    }
    if v["control"] != json!(true) {
        return Ok(());
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let me = {
        let mut held = lock(&shared);
        held.control += 1;
        held.to_app = Some(tx);
        held.control
    };
    let (r, mut w) = s.into_split();
    let writer = tokio::spawn(async move {
        while let Some(mut line) = rx.recv().await {
            line.push('\n');
            if w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            on_event(&shared, &v);
        }
    }
    writer.abort();
    let mut held = lock(&shared);
    if held.control != me {
        // Another took its place.
        return Ok(());
    }
    held.to_app = None;
    held.state = Some(Err("the app's Bluetooth went away".into()));
    // What was under way ends with it.
    held.listening = None;
    held.scanning = None;
    held.connecting.clear();
    Ok(())
}

fn on_event(shared: &Mutex<Shared>, v: &Value) {
    let mut held = lock(shared);
    match v["op"].as_str() {
        Some("state") => {
            held.state = Some(match v["available"].as_bool() {
                Some(true) => Ok(()),
                _ => Err(v["why"].as_str().unwrap_or("Bluetooth is off").to_owned()),
            });
        }
        Some("listening") => {
            if let (Some(tx), Some(psm)) = (held.psm.take(), v["psm"].as_u64()) {
                let _ = tx.send(Ok(psm as u16));
            }
        }
        Some("listen-failed") => {
            if let Some(tx) = held.psm.take() {
                let e = v["error"].as_str().unwrap_or("cannot listen").to_owned();
                let _ = tx.send(Err(io::Error::other(e)));
            }
        }
        Some("seen") => {
            let data = v["data"].as_str().and_then(unhex);
            if let (Some(addr), Some(data), Some(tx)) = (addr_of(v), data, &held.scanning) {
                let _ = tx.try_send(Sighting { addr, data });
            }
        }
        Some("scan-failed") | Some("advertise-failed") => {
            let e = v["error"].as_str().unwrap_or("it failed");
            let what = if v["op"] == "scan-failed" {
                "scanning"
            } else {
                "advertising"
            };
            held.failure = Some(format!("{what} failed: {e}"));
            if what == "scanning" {
                // The scan ends; the service starts again and says why.
                held.scanning = None;
            }
        }
        Some("connect-failed") => {
            if let Some(tx) = v["id"].as_u64().and_then(|id| held.connecting.remove(&id)) {
                let e = v["error"].as_str().unwrap_or("no channel").to_owned();
                let _ = tx.send(Err(io::Error::other(e)));
            }
        }
        _ => {}
    }
}

impl Radio for BridgeRadio {
    fn describe(&self) -> String {
        format!("the app's Bluetooth, through {}", self.path.display())
    }

    fn failure(&self) -> Option<String> {
        lock(&self.shared).failure.clone()
    }

    fn available(&self) -> RadioFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let held = lock(&self.shared);
            Ok(match (&held.to_app, &held.state) {
                (None, _) => Err("the app's Bluetooth is not connected".into()),
                (_, Some(s)) => s.clone(),
                (_, None) => Err("the app has not said whether Bluetooth is on".into()),
            })
        })
    }

    fn listen(&self) -> RadioFuture<'_, Listening> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let (in_tx, in_rx) = mpsc::channel(16);
            {
                let mut held = lock(&self.shared);
                held.psm = Some(tx);
                held.listening = Some(in_tx);
            }
            self.tell(json!({"op": "listen"}))?;
            let psm = tokio::time::timeout(std::time::Duration::from_secs(10), rx)
                .await
                .map_err(|_| io::Error::other("the app did not say which PSM"))?
                .map_err(|_| io::Error::other("the app's Bluetooth went away"))??;
            Ok(Listening {
                psm,
                incoming: in_rx,
                guard: self.told_on_drop(json!({"op": "unlisten"})),
            })
        })
    }

    fn advertise(&self, keys: &Keys, psm: u16) -> RadioFuture<'_, Box<dyn Send>> {
        let data = keys.advert(psm).encode();
        let n = self.turn.fetch_add(1, Ordering::Relaxed) as usize;
        let legacy = keys
            .legacy(psm, n)
            .and_then(|a| a.encode_legacy())
            .unwrap_or_default();
        Box::pin(async move {
            self.tell(json!({"op": "advertise", "data": hex(&data), "legacy": hex(&legacy)}))?;
            Ok(self.told_on_drop(json!({"op": "unadvertise"})))
        })
    }

    fn scan(&self) -> RadioFuture<'_, mpsc::Receiver<Sighting>> {
        Box::pin(async move {
            let (tx, rx) = mpsc::channel(64);
            // Only the shared state holds the sender, so that the scan ends
            // when the app says it failed.
            let weak = tx.downgrade();
            lock(&self.shared).scanning = Some(tx);
            self.tell(json!({"op": "scan"}))?;
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    match weak.upgrade() {
                        None => break,
                        Some(t) if t.is_closed() => {
                            let _ = me.tell(json!({"op": "unscan"}));
                            break;
                        }
                        Some(_) => {}
                    }
                }
            });
            Ok(rx)
        })
    }

    fn connect(&self, to: BleAddr, psm: u16) -> RadioFuture<'_, BoxChannel> {
        Box::pin(async move {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            lock(&self.shared).connecting.insert(id, tx);
            // However this ends, given up on included, nothing waits for it.
            struct Forget(Arc<Mutex<Shared>>, u64);
            impl Drop for Forget {
                fn drop(&mut self) {
                    lock(&self.0).connecting.remove(&self.1);
                }
            }
            let _forget = Forget(self.shared.clone(), id);
            self.tell(json!({
                "op": "connect", "id": id, "addr": to.to_string(), "random": to.random, "psm": psm,
            }))?;
            rx.await
                .map_err(|_| io::Error::other("the app's Bluetooth went away"))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble::{Advert, TagType};

    /// The app, as a test plays it: a radio in memory behind the bridge.
    async fn app(path: PathBuf, radio: crate::ble::MemoryRadio) {
        let s = UnixStream::connect(&path).await.unwrap();
        let (r, mut w) = s.into_split();
        w.write_all(b"{\"control\":true}\n{\"op\":\"state\",\"available\":true}\n")
            .await
            .unwrap();
        let (out, mut out_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(l) = out_rx.recv().await {
                w.write_all(format!("{l}\n").as_bytes()).await.unwrap();
            }
        });
        let mut lines = BufReader::new(r).lines();
        let mut held: Vec<Box<dyn Send>> = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let v: Value = serde_json::from_str(&line).unwrap();
            match v["op"].as_str().unwrap() {
                "listen" => {
                    let mut l = radio.listen().await.unwrap();
                    out.send(json!({"op": "listening", "psm": l.psm}).to_string())
                        .unwrap();
                    // The task takes only the channels: the guard stays here.
                    held.push(std::mem::replace(&mut l.guard, Box::new(())));
                    let path = path.clone();
                    tokio::spawn(async move {
                        while let Some((from, mut ch)) = l.incoming.recv().await {
                            let mut s = UnixStream::connect(&path).await.unwrap();
                            let head = json!({"incoming": true, "addr": from.to_string(), "random": from.random});
                            s.write_all(format!("{head}\n").as_bytes()).await.unwrap();
                            tokio::spawn(async move {
                                let _ = tokio::io::copy_bidirectional(&mut s, &mut ch).await;
                            });
                        }
                    });
                }
                "advertise" => {
                    let data = unhex(v["data"].as_str().unwrap()).unwrap();
                    assert!(Advert::decode(&data).is_some());
                    assert!(unhex(v["legacy"].as_str().unwrap()).is_some());
                    held.push(radio.advertise_data(data));
                }
                "connect" => {
                    let to = addr_of(&v).unwrap();
                    let psm = v["psm"].as_u64().unwrap() as u16;
                    let id = v["id"].as_u64().unwrap();
                    match radio.connect(to, psm).await {
                        Ok(mut ch) => {
                            let mut s = UnixStream::connect(&path).await.unwrap();
                            s.write_all(format!("{}\n", json!({"channel": id})).as_bytes())
                                .await
                                .unwrap();
                            tokio::spawn(async move {
                                let _ = tokio::io::copy_bidirectional(&mut s, &mut ch).await;
                            });
                        }
                        Err(e) => out
                            .send(
                                json!({"op": "connect-failed", "id": id, "error": e.to_string()})
                                    .to_string(),
                            )
                            .unwrap(),
                    }
                }
                "scan" => {
                    let mut seen = radio.scan().await.unwrap();
                    let out = out.clone();
                    tokio::spawn(async move {
                        while let Some(s) = seen.recv().await {
                            let v = json!({"op": "seen", "addr": s.addr.to_string(), "random": s.addr.random, "data": hex(&s.data)});
                            if out.send(v.to_string()).is_err() {
                                break;
                            }
                        }
                    });
                }
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn only_an_explicit_control_connection_drives_the_radio() {
        let dir = std::env::temp_dir().join(format!(
            "cardinal-bridge-{}",
            hex(&cardinal_crypto::random_bytes::<6>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("b");
        let bridge = BridgeRadio::bind(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "only this user may connect");
        // A state line with no control line first is not the app.
        let mut s = UnixStream::connect(&path).await.unwrap();
        s.write_all(b"{\"op\":\"state\",\"available\":true}\n")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(bridge.available().await.unwrap().is_err());
        // A connection that says nothing is let go.
        let mut quiet = UnixStream::connect(&path).await.unwrap();
        let mut b = [0u8; 1];
        let ended = tokio::time::timeout(
            FIRST_LINE_WITHIN + std::time::Duration::from_secs(2),
            quiet.read(&mut b),
        )
        .await;
        assert!(matches!(ended, Ok(Ok(0)) | Ok(Err(_))), "{ended:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_connect_given_up_on_is_forgotten() {
        let dir = std::env::temp_dir().join(format!(
            "cardinal-bridge-{}",
            hex(&cardinal_crypto::random_bytes::<6>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("b");
        let bridge = BridgeRadio::bind(&path).unwrap();
        // An app that takes the control connection and never answers.
        let mut app = UnixStream::connect(&path).await.unwrap();
        app.write_all(b"{\"control\":true}\n{\"op\":\"state\",\"available\":true}\n")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let to = BleAddr::parse("C0:00:00:00:00:01", true).unwrap();
        let tried = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            bridge.connect(to, 0x80),
        )
        .await;
        assert!(tried.is_err(), "nobody answered");
        assert!(lock(&bridge.shared).connecting.is_empty());
        // A scan the app says failed ends, and says why.
        let mut seen = bridge.scan().await.unwrap();
        app.write_all(b"{\"op\":\"scan-failed\",\"error\":\"status 2\"}\n")
            .await
            .unwrap();
        assert!(seen.recv().await.is_none());
        assert_eq!(
            bridge.failure().as_deref(),
            Some("scanning failed: status 2")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_bridged_radio_finds_listens_and_connects() {
        let dir = std::env::temp_dir().join(format!(
            "cardinal-bridge-{}",
            hex(&cardinal_crypto::random_bytes::<6>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ether = crate::ble::MemoryEther::new();
        let (near, far) = (ether.radio(), ether.radio());
        let path = dir.join("bluetooth.sock");
        let bridge = BridgeRadio::bind(&path).unwrap();
        assert!(bridge.available().await.unwrap().is_err(), "no app yet");
        tokio::spawn(app(path.clone(), near.clone()));
        for _ in 0..50 {
            if bridge.available().await.unwrap().is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(bridge.available().await.unwrap(), Ok(()));

        // Listening through the app: the far radio connects to it.
        let mut l = bridge.listen().await.unwrap();
        let keys = Keys {
            keys: vec![(TagType::Own, cardinal_crypto::Zeroizing::new([1; 32]))],
        };
        let _ad = bridge.advertise(&keys, l.psm).await.unwrap();
        let mut ch = far.connect(near.addr(), l.psm).await.unwrap();
        let (from, mut got) = l.incoming.recv().await.unwrap();
        assert_eq!(from, far.addr());
        ch.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        got.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");

        // Scanning through the app sees the far radio, and connects to it.
        let mut fl = far.listen().await.unwrap();
        let fkeys = Keys {
            keys: vec![(TagType::Contacts, cardinal_crypto::Zeroizing::new([2; 32]))],
        };
        let _fad = far.advertise(&fkeys, fl.psm).await.unwrap();
        let mut seen = bridge.scan().await.unwrap();
        let s = loop {
            let s = seen.recv().await.unwrap();
            if s.addr == far.addr() {
                break s;
            }
        };
        let ad = Advert::decode(&s.data).unwrap();
        assert!(ad.has(TagType::Contacts, &[2; 32]));
        let mut out = bridge.connect(s.addr, ad.psm).await.unwrap();
        let (_, mut back) = fl.incoming.recv().await.unwrap();
        back.write_all(b"pong").await.unwrap();
        out.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"pong");
        // A PSM nobody listens on fails, as the app says.
        assert!(bridge.connect(far.addr(), 1).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
