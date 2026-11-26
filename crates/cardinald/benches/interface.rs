//! What answering the local interface costs, for answers that grow with
//! what the person holds: a folder of 5,000 entries (`files`), a full page
//! of a group's conversation (`messages`), and one small request asked
//! often (`call`, with no call under way).
//!
//! For each: the time in the service from the handler's answer to the
//! reply's bytes, and from a request's bytes to its arguments; what that
//! allocates (count and bytes, counted on this thread only, so the
//! service's own tasks do not count); and the time of one request over the
//! real socket, with and without the client reading the reply.
//!
//! Not part of any test tier. Run it with
//! `cargo bench -p cardinald --bench interface`; `BENCH_ROUNDS` sets how
//! many times each step runs (the median is shown).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cardinald::api;
use cardinald::transport::{self, Received};
use cardinald::{Config, Daemon, Paths};
use serde_json::json;

// ---- Counting allocations, on this thread ----

struct Counting;

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<u64> = const { Cell::new(0) };
    static BYTES: Cell<u64> = const { Cell::new(0) };
}

fn note(bytes: usize) {
    let _ = ON.try_with(|on| {
        if on.get() {
            COUNT.with(|c| c.set(c.get() + 1));
            BYTES.with(|b| b.set(b.get() + bytes as u64));
        }
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        note(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        // A reallocation counts as one more, of the bytes it adds.
        note(new.saturating_sub(l.size()));
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// What one step costs: its median time over the rounds, and what one run
/// of it allocates.
#[derive(Clone, Copy, Default)]
struct Cost {
    time: Duration,
    allocs: u64,
    bytes: u64,
}

fn counted<T>(f: impl FnOnce() -> T) -> (T, u64, u64) {
    COUNT.with(|c| c.set(0));
    BYTES.with(|b| b.set(0));
    ON.with(|on| on.set(true));
    let out = f();
    ON.with(|on| on.set(false));
    (out, COUNT.with(Cell::get), BYTES.with(Cell::get))
}

fn rounds() -> usize {
    std::env::var("BENCH_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// Runs `f` once counted, then `rounds` times timed: the median.
fn measure<T>(mut f: impl FnMut() -> T) -> Cost {
    let (out, allocs, bytes) = counted(&mut f);
    drop(out);
    let mut times: Vec<Duration> = (0..rounds())
        .map(|_| {
            let t = Instant::now();
            let out = f();
            let e = t.elapsed();
            drop(out);
            e
        })
        .collect();
    times.sort();
    Cost {
        time: times[times.len() / 2],
        allocs,
        bytes,
    }
}

fn show(what: &str, c: Cost) {
    println!(
        "  {what:<44} {:>10.1} µs {:>9} allocs {:>12} bytes",
        c.time.as_secs_f64() * 1e6,
        c.allocs,
        c.bytes
    );
}

// ---- A device with something to list ----

const FILES: usize = 5_000;
const MESSAGE_TEXT: usize = 160;

async fn device(dir: &std::path::Path) -> Arc<Daemon> {
    let paths = Paths::at(dir);
    let mut config = Config {
        listen: "127.0.0.1:0".into(),
        ..Default::default()
    };
    config.this_run.no_mount = true;
    config.this_run.no_discovery = true;
    config.this_run.no_udp = true;
    let p = cardinald::setup::prepare(&paths).unwrap();
    cardinald::setup::install(&paths, p, &config, "Me").unwrap();
    Daemon::start(paths, config).await.unwrap()
}

/// A folder `Big` of 5,000 small files, and a group `Bench` whose
/// conversation is longer than one message of the interface holds.
async fn fill(d: &Arc<Daemon>, dir: &std::path::Path) -> String {
    let t = Instant::now();
    cardinald::onefolder::mkdir(d, "Big").unwrap();
    let local = dir.join("one-file");
    std::fs::write(&local, b"a small file").unwrap();
    let local = local.to_str().unwrap().to_owned();
    for i in 0..FILES {
        cardinald::onefolder::write(d, &local, &format!("Big/file-{i:05}.txt"))
            .await
            .unwrap();
    }
    eprintln!("{FILES} files written in {:.1} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let g = cardinald::groups::create(d, "Bench", &[], false, true).unwrap();
    let group = g["group"].as_str().unwrap().to_owned();
    let text: String = "word ".repeat(MESSAGE_TEXT / 5);
    // more than a page: a page holds about 256 KiB
    let n = transport::MAX_MESSAGE / (MESSAGE_TEXT + 40) + 200;
    for i in 0..n {
        cardinald::groups::say(d, &group, &format!("{i} {text}"), None, &[])
            .await
            .unwrap();
    }
    eprintln!("{n} messages written in {:.1} s", t.elapsed().as_secs_f64());
    group
}

// ---- Over the socket ----

async fn round_trip(socket: &std::path::Path, msg: &[u8]) -> Vec<u8> {
    let (mut r, mut w) = transport::connect(socket).await.unwrap();
    w.send(msg).await.unwrap();
    match r.recv().await.unwrap() {
        Some(Received::Message(m)) => m,
        _ => panic!("no reply"),
    }
}

/// The median of `rounds` round trips of `msg`, each on a connection of its
/// own as the command line makes one, and with the client reading the reply
/// with `read`.
fn over_socket(
    rt: &tokio::runtime::Runtime,
    socket: &std::path::Path,
    msg: &[u8],
    read: impl Fn(&[u8]),
) -> (Duration, Duration, usize) {
    let mut raw = Vec::new();
    let mut read_too = Vec::new();
    let mut len = 0;
    for _ in 0..rounds() {
        let t = Instant::now();
        let reply = rt.block_on(round_trip(socket, msg));
        raw.push(t.elapsed());
        len = reply.len();
        let t = Instant::now();
        let reply = rt.block_on(round_trip(socket, msg));
        read(&reply);
        read_too.push(t.elapsed());
    }
    raw.sort();
    read_too.sort();
    (raw[raw.len() / 2], read_too[read_too.len() / 2], len)
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let d = rt.block_on(device(dir.path()));
    let group = rt.block_on(fill(&d, dir.path()));
    let _serving = rt.block_on(async { cardinald::control::serve(d.clone()).unwrap() });
    let socket = d.paths.socket.clone();
    println!("rounds: {} (median shown)", rounds());

    let asks = [
        ("files", json!({"cmd": "files", "path": "Big"})),
        (
            "messages",
            json!({"cmd": "messages", "group": format!("{}{group}", api::EXACT)}),
        ),
        ("call", json!({"cmd": "call"})),
    ];
    for (name, req) in asks {
        let (spec, msg) = api::encode_request(&req).unwrap();
        println!("{name}: request {} bytes", msg.len());
        // the request's bytes to what the handler takes
        let decode = measure(|| api::decode_request(&msg).unwrap());
        let (_, args) = api::decode_request(&msg).unwrap();
        // the handler: what the person holds, to its answer
        let answer = || match name {
            "files" => cardinald::onefolder::list(&d, "Big").unwrap(),
            "messages" => cardinald::groups::messages(&d, &group, None).unwrap(),
            _ => cardinald::calls::current(&d),
        };
        let handler = rt.block_on(async { measure(answer) });
        let value = rt.block_on(async { answer() });
        // the answer to the reply's bytes: a page of it, encoded
        let encode = measure(|| {
            let v = api::page(spec, &args, value.clone()).unwrap();
            api::encode_reply(spec, Ok(&v))
        });
        let clone = measure(|| value.clone());
        let encode = Cost {
            time: encode.time.saturating_sub(clone.time),
            allocs: encode.allocs - clone.allocs,
            bytes: encode.bytes - clone.bytes,
        };
        let reply = api::encode_reply(spec, Ok(&api::page(spec, &args, value.clone()).unwrap()));
        // the client: the reply's bytes to what it reads
        let read = measure(|| api::decode_reply(spec, &reply).unwrap());
        show("request bytes -> arguments", decode);
        show("handler -> answer", handler);
        show("answer -> reply bytes (page, encode)", encode);
        show(
            "in the service, all",
            Cost {
                time: decode.time + handler.time + encode.time,
                allocs: decode.allocs + handler.allocs + encode.allocs,
                bytes: decode.bytes + handler.bytes + encode.bytes,
            },
        );
        show("client: reply bytes -> what it reads", read);
        let (raw, with_read, len) = over_socket(&rt, &socket, &msg, |r| {
            api::decode_reply(spec, r).unwrap();
        });
        println!(
            "  over the socket: {:.1} µs, {:.1} µs with the client reading; reply {len} bytes",
            raw.as_secs_f64() * 1e6,
            with_read.as_secs_f64() * 1e6
        );
    }
}
