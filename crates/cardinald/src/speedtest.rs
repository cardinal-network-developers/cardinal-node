//! `cardinal speedtest`: measures the encrypted link to one of the
//! person's own devices, with no disk involved: round trips, then about
//! 10 s of receiving and 10 s of sending.
//!
//! This is a link service of this implementation, not of the
//! specification (see DEVIATIONS.md): the application service named by
//! `BLAKE3("cardinal-node speedtest 1")`. One stream carries one test,
//! as records `{0: op, ...}` and, for the data, byte strings of 64 KiB:
//!
//! - the client sends `{0: 1}`; the server answers `{0: 2, 1: 0}` with
//!   the phase length in ms (2) and the number of pings (3), or refuses:
//!   `{0: 2, 1: 1}` while another test runs, `{0: 2, 1: 2, 4: seconds}`
//!   when over its budget;
//! - pings `{0: 3, 1: n}`, each echoed as `{0: 4, 1: n}`;
//! - `{0: 5}`: the server sends data for one phase, then `{0: 6, 1:
//!   bytes}`;
//! - `{0: 7}`, data for one phase, `{0: 8}`: the client sends; the
//!   server answers `{0: 9, 1: bytes, 2: microseconds}`.
//!
//! A device serves only its person's own devices, one test at a time, of
//! a length it sets itself (it resets a test that runs over), and at most
//! two minutes of tests in any ten minutes; it refuses the rest. A device
//! without the service (0.1.3 and older) resets the stream.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use cardinal_encoding::{Record, Value};
use cardinal_link::{Priority, Service, Session, Stream};
use serde_json::{json, Value as Json};
use tokio::io::AsyncWriteExt;

use crate::daemon::{Daemon, PeerKind};

/// The service's name; the link service is its BLAKE3 hash.
pub const SERVICE_NAME: &str = "cardinal-node speedtest 1";

/// The link service.
pub fn service() -> Service {
    Service::App(*blake3::hash(SERVICE_NAME.as_bytes()).as_bytes())
}

const HELLO: u64 = 1;
const ACCEPT: u64 = 2;
const PING: u64 = 3;
const PONG: u64 = 4;
const RECEIVE: u64 = 5;
const END: u64 = 6;
const SEND: u64 = 7;
const SENT: u64 = 8;
const RESULT: u64 = 9;

const OK: u64 = 0;
const BUSY: u64 = 1;
const LIMIT: u64 = 2;

/// Round trips measured.
const PINGS: u64 = 20;
/// Bytes per data message.
const CHUNK: usize = 64 * 1024;
/// Test time a device gives within [`WINDOW`].
const BUDGET: Duration = Duration::from_secs(120);
/// See [`BUDGET`].
const WINDOW: Duration = Duration::from_secs(600);
/// Extra time a test may take beyond its two phases before it is cut.
const GRACE: Duration = Duration::from_secs(15);

/// How long each data phase lasts: 10 s, or
/// `CARDINAL_TEST_SPEEDTEST_MS` (tests).
pub fn phase() -> Duration {
    static PHASE: OnceLock<Duration> = OnceLock::new();
    *PHASE.get_or_init(|| {
        std::env::var("CARDINAL_TEST_SPEEDTEST_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|ms| *ms > 0)
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(10))
    })
}

/// Whether this device offers the service. `CARDINAL_TEST_NO_SPEEDTEST`
/// makes it answer like a device without it (tests).
pub fn offered() -> bool {
    std::env::var_os("CARDINAL_TEST_NO_SPEEDTEST").is_none()
}

fn data_message() -> &'static [u8] {
    static DATA: OnceLock<Vec<u8>> = OnceLock::new();
    DATA.get_or_init(|| Value::Bytes(vec![0u8; CHUNK]).encode())
}

fn msg(op: u64) -> Record {
    Record::new().with(0, op)
}

/// Why a test was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another test is running.
    Busy,
    /// Over the budget; try again after this long.
    Limit(Duration),
}

/// One test at a time, and at most [`BUDGET`] of tests per [`WINDOW`].
#[derive(Default)]
pub struct Limiter {
    inner: Mutex<LimitState>,
}

#[derive(Default)]
struct LimitState {
    busy: bool,
    /// Tests run: start, length.
    past: VecDeque<(Instant, Duration)>,
}

impl Limiter {
    /// Starts a test at `now`, unless refused.
    pub fn admit(&self, now: Instant) -> Result<(), Refusal> {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if s.busy {
            return Err(Refusal::Busy);
        }
        while s
            .past
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) > WINDOW)
        {
            s.past.pop_front();
        }
        let used: Duration = s.past.iter().map(|(_, d)| *d).sum();
        if used >= BUDGET {
            let oldest = s.past.front().map(|(t, _)| *t).unwrap_or(now);
            let retry = WINDOW.saturating_sub(now.saturating_duration_since(oldest));
            return Err(Refusal::Limit(retry.max(Duration::from_secs(1))));
        }
        s.busy = true;
        Ok(())
    }

    /// Ends the test that started at `started`.
    pub fn done(&self, started: Instant, now: Instant) {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.busy = false;
        s.past
            .push_back((started, now.saturating_duration_since(started)));
    }
}

/// Ends the test when dropped, however it ended.
struct Running<'a> {
    limiter: &'a Limiter,
    started: Instant,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.limiter.done(self.started, Instant::now());
    }
}

/// Reads one message: a record, or the length of a data message.
enum Msg {
    Control(Record),
    Data(usize),
}

async fn recv(st: &mut Stream) -> std::io::Result<Option<Msg>> {
    let Some(body) = st.recv_message_bytes_max(CHUNK + 64).await? else {
        return Ok(None);
    };
    let bad = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
    match cardinal_encoding::decode(&body).map_err(|e| bad(e.to_string()))? {
        Value::Record(r) => Ok(Some(Msg::Control(r))),
        Value::Bytes(b) => Ok(Some(Msg::Data(b.len()))),
        _ => Err(bad("unexpected speed test message".into())),
    }
}

async fn recv_control(st: &mut Stream) -> anyhow::Result<Record> {
    match recv(st).await? {
        Some(Msg::Control(r)) => Ok(r),
        Some(Msg::Data(_)) => anyhow::bail!("unexpected data"),
        None => anyhow::bail!("the stream ended"),
    }
}

fn op(r: &Record) -> u64 {
    r.uint(0).unwrap_or(0)
}

/// Serves a speed test a peer opened.
pub async fn serve(d: &Arc<Daemon>, s: &Session, mut st: Stream) -> anyhow::Result<()> {
    if !matches!(d.classify(s), PeerKind::Own(_)) {
        st.reset(0);
        return Ok(());
    }
    let hello = tokio::time::timeout(Duration::from_secs(10), recv_control(&mut st)).await??;
    if op(&hello) != HELLO {
        st.reset(0);
        return Ok(());
    }
    let phase = phase();
    let started = Instant::now();
    match d.speedtest.admit(started) {
        Err(Refusal::Busy) => {
            st.send_message(&msg(ACCEPT).with(1, BUSY).into()).await?;
            st.shutdown().await?;
            return Ok(());
        }
        Err(Refusal::Limit(retry)) => {
            st.send_message(&msg(ACCEPT).with(1, LIMIT).with(4, retry.as_secs()).into())
                .await?;
            st.shutdown().await?;
            return Ok(());
        }
        Ok(()) => {}
    }
    let _running = Running {
        limiter: &d.speedtest,
        started,
    };
    tracing::info!(
        "running a speed test for {}",
        crate::core::short(&s.peer_static())
    );
    st.send_message(
        &msg(ACCEPT)
            .with(1, OK)
            .with(2, phase.as_millis() as u64)
            .with(3, PINGS)
            .into(),
    )
    .await?;
    let deadline = started + 2 * phase + GRACE;
    match tokio::time::timeout_at(deadline.into(), run_server(&mut st, phase)).await {
        Ok(r) => r,
        Err(_) => {
            st.reset(0);
            anyhow::bail!("the speed test ran over its time")
        }
    }
}

async fn run_server(st: &mut Stream, phase: Duration) -> anyhow::Result<()> {
    // Round trips.
    let mut pings = 0;
    loop {
        let m = recv_control(st).await?;
        match op(&m) {
            PING => {
                pings += 1;
                if pings > 2 * PINGS {
                    anyhow::bail!("too many pings");
                }
                let n = m.uint(1).unwrap_or(0);
                st.send_message(&msg(PONG).with(1, n).into()).await?;
            }
            RECEIVE => break,
            other => anyhow::bail!("unexpected message {other}"),
        }
    }
    // Send for one phase.
    let t0 = Instant::now();
    let mut sent = 0u64;
    while t0.elapsed() < phase {
        st.send_message_bytes(data_message()).await?;
        sent += CHUNK as u64;
    }
    st.send_message(&msg(END).with(1, sent).into()).await?;
    // Receive for one phase, and not much longer.
    let m = recv_control(st).await?;
    if op(&m) != SEND {
        anyhow::bail!("expected the client to send");
    }
    let t1 = Instant::now();
    let until = t1 + phase + Duration::from_secs(5);
    let mut got = 0u64;
    loop {
        match tokio::time::timeout_at(until.into(), recv(st)).await {
            Err(_) => anyhow::bail!("the client sent for too long"),
            Ok(r) => match r? {
                Some(Msg::Data(n)) => got += n as u64,
                Some(Msg::Control(m)) if op(&m) == SENT => break,
                _ => anyhow::bail!("unexpected message while receiving"),
            },
        }
    }
    let micros = t1.elapsed().as_micros() as u64;
    st.send_message(&msg(RESULT).with(1, got).with(2, micros).into())
        .await?;
    st.shutdown().await?;
    Ok(())
}

/// One measured link.
#[derive(Clone, Debug)]
pub struct Measured {
    /// Bytes per second received by this device.
    pub receive: f64,
    /// Bytes per second sent by this device (as the other received them).
    pub send: f64,
    /// Fastest round trip.
    pub rtt_min: Duration,
    /// Median round trip.
    pub rtt_median: Duration,
    /// Bytes received.
    pub received: u64,
    /// Bytes sent.
    pub sent: u64,
    /// Length of each data phase.
    pub phase: Duration,
}

impl Measured {
    /// As JSON.
    pub fn to_json(&self) -> Json {
        json!({
            "receive": self.receive.round() as u64,
            "send": self.send.round() as u64,
            "rtt_min_ms": self.rtt_min.as_secs_f64() * 1000.0,
            "rtt_median_ms": self.rtt_median.as_secs_f64() * 1000.0,
            "received_bytes": self.received,
            "sent_bytes": self.sent,
            "seconds": self.phase.as_secs_f64(),
        })
    }
}

/// Runs a speed test with the device whose session is `s` (named `name`
/// in messages).
pub async fn run(s: &Session, name: &str) -> anyhow::Result<Measured> {
    let older = || anyhow::anyhow!("{name} runs an older version without speedtest");
    let mut st = s.open_stream(service(), Priority::Interactive)?;
    st.send_message(&msg(HELLO).with(1, 1u64).into()).await?;
    let reply = match tokio::time::timeout(Duration::from_secs(10), recv(&mut st)).await {
        Err(_) => anyhow::bail!("{name} did not answer"),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => return Err(older()),
        Ok(Err(e)) => anyhow::bail!("{name}: {e}"),
        Ok(Ok(None)) => return Err(older()),
        Ok(Ok(Some(Msg::Data(_)))) => anyhow::bail!("{name} answered strangely"),
        Ok(Ok(Some(Msg::Control(r)))) => r,
    };
    if op(&reply) != ACCEPT {
        anyhow::bail!("{name} answered strangely");
    }
    match reply.uint(1).unwrap_or(BUSY) {
        OK => {}
        BUSY => anyhow::bail!("{name} is running another speed test; try again in a minute"),
        LIMIT => {
            let m = reply.uint(4).unwrap_or(60).div_ceil(60).max(1);
            anyhow::bail!(
                "{name} has run speed tests for two minutes in the last ten; try again in {m} \
                 minute{}",
                if m == 1 { "" } else { "s" }
            )
        }
        other => anyhow::bail!("{name} refused the speed test ({other})"),
    }
    let phase = Duration::from_millis(reply.uint(2).unwrap_or(10_000).clamp(100, 60_000));
    let pings = reply.uint(3).unwrap_or(PINGS).min(PINGS);
    // Round trips.
    let mut rtts = Vec::new();
    for n in 0..pings {
        let t = Instant::now();
        st.send_message(&msg(PING).with(1, n).into()).await?;
        let m = recv_control(&mut st).await?;
        if op(&m) != PONG || m.uint(1).ok() != Some(n) {
            anyhow::bail!("{name} answered a ping strangely");
        }
        rtts.push(t.elapsed());
    }
    rtts.sort();
    // Receive.
    let t0 = Instant::now();
    st.send_message(&msg(RECEIVE).into()).await?;
    let mut received = 0u64;
    loop {
        match recv(&mut st).await? {
            Some(Msg::Data(n)) => received += n as u64,
            Some(Msg::Control(m)) if op(&m) == END => break,
            _ => anyhow::bail!("{name} stopped sending"),
        }
    }
    let receive = received as f64 / t0.elapsed().as_secs_f64().max(1e-6);
    // Send.
    st.send_message(&msg(SEND).into()).await?;
    let t1 = Instant::now();
    let mut sent = 0u64;
    while t1.elapsed() < phase {
        st.send_message_bytes(data_message()).await?;
        sent += CHUNK as u64;
    }
    st.send_message(&msg(SENT).into()).await?;
    let m = recv_control(&mut st).await?;
    if op(&m) != RESULT {
        anyhow::bail!("{name} did not report what it received");
    }
    let got = m.uint(1).unwrap_or(0);
    let micros = m.uint(2).unwrap_or(1).max(1);
    let _ = st.shutdown().await;
    Ok(Measured {
        receive,
        send: got as f64 * 1e6 / micros as f64,
        rtt_min: rtts.first().copied().unwrap_or_default(),
        rtt_median: rtts.get(rtts.len() / 2).copied().unwrap_or_default(),
        received,
        sent,
        phase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_test_at_a_time_and_a_budget() {
        let l = Limiter::default();
        let t = Instant::now();
        assert_eq!(l.admit(t), Ok(()));
        assert_eq!(l.admit(t), Err(Refusal::Busy));
        l.done(t, t + Duration::from_secs(25));
        // four more tests of 25 s fill the two minutes
        let mut now = t + Duration::from_secs(30);
        for _ in 0..4 {
            assert_eq!(l.admit(now), Ok(()));
            l.done(now, now + Duration::from_secs(25));
            now += Duration::from_secs(30);
        }
        match l.admit(now) {
            Err(Refusal::Limit(d)) => assert!(d <= WINDOW && d >= Duration::from_secs(1)),
            other => panic!("{other:?}"),
        }
        // ten minutes after the first, there is room again
        assert_eq!(l.admit(t + WINDOW + Duration::from_secs(1)), Ok(()));
    }

    #[test]
    fn service_is_an_application_service() {
        assert!(matches!(service(), Service::App(_)));
        assert_ne!(service(), Service::SYNC);
        assert_ne!(service(), Service::BLOB);
    }
}
