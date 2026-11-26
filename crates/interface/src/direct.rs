//! The direct reading held to the way through the tree: for random and
//! mutated messages of every declared request, reply, event, frame and
//! program reply, reading straight from the bytes and decoding into the
//! encoding's tree then taking the fields accept the same messages, give
//! equal values, and refuse the rest with the same status and the same
//! words.
//!
//! The messages are made from the rows themselves: each field of the type
//! its row gives, mostly, or of another; optional fields present or not,
//! fields always sent now and then missing, numbers no longer used and
//! keys no build knows mixed in, nesting past the limit; then the bytes
//! changed here and there, cut short or added to.

use std::fmt::Debug;

use cardinal_encoding::{Int, Record, Value};

use crate::table::{Field, Ty};
use crate::typed::{read_message, read_reply, read_reply_tree, Ask, At, Fields};
use crate::{decode_record, request_of, Event, Frame, Refused, EVENTS, FRAMES, REQUESTS};

/// A small generator of its own, the same every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    /// True `p` times in a hundred.
    fn chance(&mut self, p: u64) -> bool {
        self.below(100) < p
    }
}

fn text(rng: &mut Rng) -> String {
    match rng.below(8) {
        0 => String::new(),
        1 => "\u{0}0011".into(),
        2 => "ü€x".into(),
        3 => " \u{0}ab".into(),
        _ => (0..rng.below(12))
            .map(|_| (b'a' + rng.below(26) as u8) as char)
            .collect(),
    }
}

fn bytes(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n).map(|_| rng.next() as u8).collect()
}

fn uint(rng: &mut Rng) -> u64 {
    match rng.below(6) {
        0 => 0,
        1 => 1,
        2 => rng.below(300),
        3 => (1 << 60) - 1,
        _ => rng.below(1 << 40),
    }
}

/// Any value, of any type, nested at most `depth`.
fn any(rng: &mut Rng, depth: usize) -> Value {
    let top = if depth == 0 { 4 } else { 6 };
    match rng.below(top) {
        0 => Value::from(uint(rng)),
        1 => Value::Int(Int::new(-(rng.below(1 << 50) as i64) - 1).unwrap()),
        2 => {
            let n = rng.below(40) as usize;
            Value::Bytes(bytes(rng, n))
        }
        3 => Value::Text(text(rng)),
        4 => Value::List((0..rng.below(4)).map(|_| any(rng, depth - 1)).collect()),
        _ => {
            let mut r = Record::new();
            for _ in 0..rng.below(4) {
                r.insert(rng.below(12), any(rng, depth - 1));
            }
            Value::Record(r)
        }
    }
}

/// Lists nested `n` deep: past 32, which no decoder takes.
fn deep(n: usize) -> Value {
    let mut v = Value::from(0u64);
    for _ in 0..n {
        v = Value::List(vec![v]);
    }
    v
}

/// A value for a field of type `ty`: mostly of that type, now and then
/// of another.
fn value(rng: &mut Rng, ty: &Ty, depth: usize) -> Value {
    if rng.chance(4) || depth == 0 {
        return any(rng, depth.min(2));
    }
    match ty {
        Ty::Text => Value::Text(text(rng)),
        Ty::Bytes => {
            let n = [0, 8, 16, 32, 5][rng.below(5) as usize];
            Value::Bytes(bytes(rng, n))
        }
        Ty::BytesOf(n) => {
            let n = if rng.chance(90) {
                *n
            } else {
                n + 1 - rng.below(3) as usize
            };
            Value::Bytes(bytes(rng, n))
        }
        Ty::Uint => Value::from(uint(rng)),
        Ty::Int => match rng.below(3) {
            0 => Value::from(uint(rng)),
            _ => Value::Int(Int::new(-(rng.below(1000) as i64)).unwrap()),
        },
        Ty::Bool => Value::from(if rng.chance(95) { rng.below(2) } else { 2 }),
        Ty::Ref | Ty::Kind | Ty::Scalar => match rng.below(3) {
            0 => Value::Text(text(rng)),
            1 => {
                let n = [8, 16, 32][rng.below(3) as usize];
                Value::Bytes(bytes(rng, n))
            }
            _ => Value::from(uint(rng)),
        },
        Ty::List(t) => Value::List(
            (0..rng.below(4))
                .map(|_| value(rng, t, depth - 1))
                .collect(),
        ),
        Ty::Rec(r) => Value::Record(record(rng, r.fields, depth - 1)),
        Ty::Recs(r) => Value::List(
            (0..rng.below(4))
                .map(|_| value(rng, &Ty::Rec(r), depth - 1))
                .collect(),
        ),
        Ty::Gone(t) => value(rng, t, depth),
    }
}

/// A record of `fields`: optional ones present or not, those always sent
/// mostly present, numbers no longer used and keys no build knows now and
/// then.
fn record(rng: &mut Rng, fields: &[Field], depth: usize) -> Record {
    let mut r = Record::new();
    for f in fields {
        let present = match (&f.ty, f.optional) {
            (Ty::Gone(_), _) => rng.chance(10),
            (_, true) => rng.chance(60),
            (_, false) => rng.chance(96),
        };
        if present {
            r.insert(f.n, value(rng, &f.ty, depth));
        }
    }
    if rng.chance(15) {
        let k = [0, 1, 40, 99, 1 << 40][rng.below(5) as usize];
        if !fields.iter().any(|f| f.n == k) {
            r.insert(k, any(rng, 2));
        }
    }
    if rng.chance(2) {
        r.insert(1000, deep(31 + rng.below(4) as usize));
    }
    r
}

/// Its bytes, changed here and there, now and then.
fn mutated(rng: &mut Rng, mut b: Vec<u8>) -> Vec<u8> {
    if rng.chance(70) {
        return b;
    }
    for _ in 0..1 + rng.below(3) {
        match rng.below(5) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len() as u64) as usize;
                b[i] = rng.next() as u8;
            }
            1 => {
                let i = rng.below(b.len() as u64 + 1) as usize;
                b.insert(i, rng.next() as u8);
            }
            2 if !b.is_empty() => {
                let i = rng.below(b.len() as u64) as usize;
                b.remove(i);
            }
            3 => b.truncate(rng.below(b.len() as u64 + 1) as usize),
            _ => b.push(rng.next() as u8),
        }
    }
    b
}

/// What a request's refusal is, to compare.
fn said(r: Refused) -> (u64, String) {
    (r.status, r.why)
}

/// How many messages of each kind: `CARDINAL_DIRECT_ROUNDS` times 400.
fn each() -> usize {
    400 * std::env::var("CARDINAL_DIRECT_ROUNDS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1)
}

/// A request's arguments and its reply, both ways.
fn request_and_reply<A: Ask + PartialEq + Debug>(rng: &mut Rng, seen: &mut [usize; 2])
where
    A::Reply: PartialEq + Debug,
{
    let spec = A::REQUEST;
    for _ in 0..each() {
        // a request: mostly this one, now and then another number, a
        // number no longer answered, or none
        let mut r = record(rng, spec.args, 4);
        match rng.below(20) {
            0 => drop(r.insert(0, rng.below(300))),
            1 => drop(r.insert(0, 165u64)),
            2 => drop(r.insert(0, any(rng, 1))),
            3 => {}
            _ => drop(r.insert(0, spec.n)),
        }
        let msg = mutated(rng, r.encode());
        // `request_of` reads key 0 alone, and the arguments' reading the
        // rest: the two together are `decode_record` and `from_request`
        let tree = decode_record(&msg)
            .map_err(said)
            .and_then(|(s, r)| match s.n == spec.n {
                true => A::from_request(r).map(Some).map_err(said),
                false => Ok(None),
            });
        let direct = request_of(&msg)
            .map_err(said)
            .and_then(|s| match s.n == spec.n {
                true => A::read_request(&msg).map(Some).map_err(said),
                // another request's, which its own reading reads
                false => Ok(None),
            });
        match (&direct, &tree) {
            (Ok(None), _) => {}
            _ => assert_eq!(direct, tree, "{}: the request {msg:02x?}", spec.name),
        }
        if let Ok(Some(_)) | Err(_) = direct {
            seen[direct.is_ok() as usize] += 1;
        }

        // a reply: mostly done, now and then an error of any number, with
        // or without why and what more it says
        let mut r = record(rng, spec.reply, 4);
        if rng.chance(85) {
            r.insert(0, 0u64);
        } else {
            r = Record::new();
            if rng.chance(95) {
                r.insert(0, [1, 2, 3, 4, 5, 6, 99][rng.below(7) as usize]);
            }
            if rng.chance(90) {
                r.insert(1, value(rng, &Ty::Text, 1));
            }
            for f in crate::ERROR_FIELDS {
                if rng.chance(50) {
                    r.insert(f.n, value(rng, &f.ty, 1));
                }
            }
        }
        let msg = mutated(rng, r.encode());
        let direct = read_reply::<A>(&msg);
        assert_eq!(
            direct,
            read_reply_tree::<A>(&msg),
            "{}: the reply {msg:02x?}",
            spec.name
        );
        seen[matches!(direct, Ok(Ok(_))) as usize] += 1;
    }
}

/// A record as a whole message, both ways.
fn whole<R: Fields + PartialEq + Debug>(rng: &mut Rng, name: &'static str, first: u64) {
    for _ in 0..each() {
        let mut r = record(rng, R::FIELDS, 4);
        if first == 2 && rng.chance(90) {
            r.insert(0, 0u64);
        }
        let msg = mutated(rng, r.encode());
        let at = At::Top(name);
        let direct = read_message(&msg, |w| R::read_fields(w, &at));
        let tree = Record::decode(&msg)
            .map_err(|e| format!("not one record: {e}"))
            .and_then(|r| R::take_fields(r, &at));
        assert_eq!(direct, tree, "{name}: {msg:02x?}");
    }
}

/// Every stream's messages, both ways.
fn streams(rng: &mut Rng) -> [usize; 2] {
    let mut seen = [0; 2];
    for _ in 0..each() * 20 {
        let (table, n) = if rng.chance(50) {
            (EVENTS, 1 + rng.below(2))
        } else {
            (FRAMES, 1 + rng.below(8))
        };
        let fields = table.iter().find(|k| k.n == n).map_or(&[][..], |k| k.args);
        let mut r = record(rng, fields, 4);
        match rng.below(20) {
            0 => {}
            1 => drop(r.insert(0, any(rng, 1))),
            _ => drop(r.insert(0, n)),
        }
        let msg = mutated(rng, r.encode());
        if std::ptr::eq(table, EVENTS) {
            let direct = Event::read(&msg);
            assert_eq!(direct, Event::read_tree(&msg), "event {msg:02x?}");
            seen[matches!(direct, Ok(Some(_))) as usize] += 1;
        } else {
            let direct = Frame::read(&msg);
            assert_eq!(direct, Frame::read_tree(&msg), "frame {msg:02x?}");
            seen[matches!(direct, Ok(Some(_))) as usize] += 1;
        }
    }
    seen
}

macro_rules! every_request {
    ($($how:ident $x:ident,)*) => {
        fn every_request(rng: &mut Rng) -> (usize, [usize; 2]) {
            let mut seen = [0; 2];
            let mut n = 0;
            $(every_request!(@one rng seen n $how $x);)*
            (n, seen)
        }
    };
    (@one $rng:ident $seen:ident $n:ident gone $row:ident) => {};
    (@one $rng:ident $seen:ident $n:ident $how:ident $args:ident) => {
        request_and_reply::<crate::$args>($rng, &mut $seen);
        $n += 1;
    };
}
crate::each_request!(every_request);

/// Read straight from the bytes or through the tree, every message is
/// taken or refused alike, the same values or the same words.
#[test]
fn reading_straight_from_the_bytes_is_reading_through_the_tree() {
    let mut rng = Rng(0x5eed_cafe_f00d_0001);
    let (asked, seen) = every_request(&mut rng);
    assert_eq!(asked, REQUESTS.iter().filter(|r| !r.gone).count());
    // both outcomes are met often enough to mean something
    assert!(seen[0] > 10_000 && seen[1] > 10_000, "{seen:?}");
    let streamed = streams(&mut rng);
    assert!(streamed[0] > 1_000 && streamed[1] > 1_000, "{streamed:?}");
    eprintln!(
        "{asked} requests: {} messages refused alike, {} read alike; {} of streams refused or \
         passed over alike, {} read alike",
        seen[0], seen[1], streamed[0], streamed[1]
    );
    whole::<crate::StoreReply>(&mut rng, "--store", 2);
    whole::<crate::Done>(&mut rng, "--clear", 2);
    whole::<crate::ErrorMore>(&mut rng, "error", 2);
}

/// Replies of real v0.1.27 services, as an independent review captured
/// them (`replies-0127.txt`: the request, its message and its reply, in
/// hex), read straight from the bytes and through the tree: every one read,
/// and alike; and their requests too.
#[test]
fn replies_of_a_release_read_alike_both_ways() {
    fn both<A: Ask + PartialEq + Debug>(request: &[u8], reply: &[u8]) -> bool
    where
        A::Reply: PartialEq + Debug,
    {
        let direct = read_reply::<A>(reply);
        assert_eq!(direct, read_reply_tree::<A>(reply), "{}", A::REQUEST.name);
        assert!(
            matches!(direct, Ok(Ok(_))),
            "{}: {direct:?}",
            A::REQUEST.name
        );
        let asked = request_of(request).map(|s| s.n).map_err(said);
        assert_eq!(asked, Ok(A::REQUEST.n));
        let tree = A::from_request(decode_record(request).unwrap().1).map_err(said);
        assert_eq!(A::read_request(request).map_err(said), tree);
        true
    }
    let unhex = |h: &str| crate::unhex(h).expect("hex");
    let mut read = 0;
    for line in include_str!("replies-0127.txt").lines() {
        let mut parts = line.split('\t');
        let (name, request, reply) = (
            parts.next().unwrap(),
            unhex(parts.next().unwrap()),
            unhex(parts.next().unwrap()),
        );
        read += match name {
            "hello" => both::<crate::HelloArgs>(&request, &reply),
            "call" => both::<crate::CallArgs>(&request, &reply),
            "conversations" => both::<crate::ConversationsArgs>(&request, &reply),
            "groups" => both::<crate::GroupsArgs>(&request, &reply),
            "contacts" => both::<crate::ContactsArgs>(&request, &reply),
            "files" => both::<crate::FilesArgs>(&request, &reply),
            "messages" => both::<crate::MessagesArgs>(&request, &reply),
            other => panic!("a reply to {other}"),
        } as usize;
    }
    assert_eq!(read, 57);
}
