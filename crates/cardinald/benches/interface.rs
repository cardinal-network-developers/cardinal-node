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
//! Both ways are measured side by side, on the same data and in the same
//! run: by name (the handler's JSON tree, turned into a record at the edge
//! by the tables) and typed (`api::typed`); the two replies are checked to
//! be the same bytes. The socket is served typed, as the service is now.
//!
//! Not part of any test tier. Run it with
//! `cargo bench -p cardinald --bench interface --features by-name`;
//! `BENCH_ROUNDS` sets how many times each step runs (the median is shown).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cardinald::api::typed::Ask;
use cardinald::api::{self, CallArgs, FilesArgs, MessagesArgs};
use cardinald::control::typed as t;
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
    eprintln!(
        "{FILES} files written in {:.1} s",
        t.elapsed().as_secs_f64()
    );
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

/// One request's steps on one way: from its bytes to its arguments, the
/// handler, the reply's bytes, and the client's reading.
struct Steps {
    decode: Cost,
    handler: Cost,
    encode: Cost,
    read: Cost,
    reply: Vec<u8>,
}

fn less(a: Cost, b: Cost) -> Cost {
    Cost {
        time: a.time.saturating_sub(b.time),
        allocs: a.allocs.saturating_sub(b.allocs),
        bytes: a.bytes.saturating_sub(b.bytes),
    }
}

/// The way by name: a JSON tree from the handler, cut and turned into a
/// record at the edge by the tables.
fn by_name(
    rt: &tokio::runtime::Runtime,
    msg: &[u8],
    answer: impl Fn(&serde_json::Value) -> serde_json::Value,
) -> Steps {
    let decode = measure(|| api::decode_request(msg).unwrap());
    let (spec, args) = api::decode_request(msg).unwrap();
    let handler = rt.block_on(async { measure(|| answer(&args)) });
    let value = rt.block_on(async { answer(&args) });
    let encode = measure(|| {
        let v = api::page(spec, &args, value.clone()).unwrap();
        api::encode_reply(spec, Ok(&v))
    });
    let encode = less(encode, measure(|| value.clone()));
    let reply = api::encode_reply(spec, Ok(&api::page(spec, &args, value.clone()).unwrap()));
    let read = measure(|| api::decode_reply(spec, &reply).unwrap());
    Steps {
        decode,
        handler,
        encode,
        read,
        reply,
    }
}

/// The typed way: typed values from the handler, written straight to the
/// encoding.
fn typed<A: Ask + Clone>(
    rt: &tokio::runtime::Runtime,
    d: &Arc<Daemon>,
    msg: &[u8],
    answer: fn(&Arc<Daemon>, &A) -> anyhow::Result<A::Reply>,
) -> Steps
where
    A::Reply: Clone,
{
    let args = || {
        let (_, r) = api::decode_record(msg).unwrap();
        A::from_request(r).unwrap()
    };
    let decode = measure(args);
    let a = args();
    let handler = rt.block_on(async { measure(|| answer(d, &a).unwrap()) });
    let value = rt.block_on(async { answer(d, &a).unwrap() });
    let encode = less(
        measure(|| a.reply_bytes(value.clone())),
        measure(|| value.clone()),
    );
    let reply = a.reply_bytes(value.clone());
    let read = measure(|| api::typed::read_reply::<A>(&reply).unwrap().unwrap());
    Steps {
        decode,
        handler,
        encode,
        read,
        reply,
    }
}

fn show_steps(way: &str, s: &Steps) {
    println!(" {way}:");
    show("request bytes -> arguments", s.decode);
    show("handler -> answer", s.handler);
    show("answer -> reply bytes (page, encode)", s.encode);
    show(
        "in the service, all",
        Cost {
            time: s.decode.time + s.handler.time + s.encode.time,
            allocs: s.decode.allocs + s.handler.allocs + s.encode.allocs,
            bytes: s.decode.bytes + s.handler.bytes + s.encode.bytes,
        },
    );
    show("client: reply bytes -> what it reads", s.read);
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let d = rt.block_on(device(dir.path()));
    let group = rt.block_on(fill(&d, dir.path()));
    let _serving = {
        let _in = rt.enter();
        cardinald::control::serve(d.clone()).unwrap()
    };
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
        let old = by_name(&rt, &msg, |args| match name {
            "files" => {
                cardinald::onefolder::list_by_name(&d, args["path"].as_str().unwrap()).unwrap()
            }
            "messages" => {
                cardinald::groups::messages_by_name(&d, args["group"].as_str().unwrap(), None)
                    .unwrap()
            }
            _ => cardinald::calls::current_by_name(&d),
        });
        let new = match name {
            "files" => typed::<FilesArgs>(&rt, &d, &msg, t::files),
            "messages" => typed::<MessagesArgs>(&rt, &d, &msg, t::messages),
            _ => typed::<CallArgs>(&rt, &d, &msg, t::call),
        };
        assert_eq!(old.reply, new.reply, "{name}: the two ways differ");
        show_steps("by name", &old);
        show_steps("typed", &new);
        let (raw, with_read, len) = over_socket(&rt, &socket, &msg, |r| match name {
            "files" => drop(api::typed::read_reply::<FilesArgs>(r).unwrap().unwrap()),
            "messages" => drop(api::typed::read_reply::<MessagesArgs>(r).unwrap().unwrap()),
            _ => drop(api::typed::read_reply::<CallArgs>(r).unwrap().unwrap()),
        });
        println!(
            "  over the socket (typed): {:.1} µs, {:.1} µs with the client reading typed; \
             reply {len} bytes",
            raw.as_secs_f64() * 1e6,
            with_read.as_secs_f64() * 1e6
        );
        let (_, with_read, _) = over_socket(&rt, &socket, &msg, |r| {
            api::decode_reply(spec, r).unwrap();
        });
        println!(
            "  over the socket, the client reading by name: {:.1} µs",
            with_read.as_secs_f64() * 1e6
        );
    }
}
