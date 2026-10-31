//! Congestion control for carriers without their own (`link.md#priority`).
//! TCP has its own; this runs for UDP, and for a relay over UDP.
//!
//! The session has one window, which answers to loss and to queueing delay.
//! Background traffic has a smaller limit of its own, in the manner of
//! LEDBAT: it grows only while the queue is under 25 ms and shrinks as soon
//! as it is over, so it takes what is spare and gives it back within a round
//! trip. Sending is paced from the window, so a window is not sent as a
//! burst into a queue.
//!
//! Queueing delay is the recent round-trip time less the lowest seen lately.
//! A flow that starts while the queue is full would take that for the empty
//! path and crowd out the others, so background traffic stands back briefly
//! now and then, which lets the queue empty and every flow see the real one.
//!
//! Nothing here reads a clock or touches a socket, which is what lets the
//! tests run it against simulated links.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The largest packet, as the window counts it.
const MSS: u64 = 1232;
/// The window of a new session.
const INITIAL_WINDOW: u64 = 32 * MSS;
/// The window never goes under this.
const MIN_WINDOW: u64 = 4 * MSS;
/// The queueing delay background traffic accepts (`link.md#priority`).
const BACKGROUND_TARGET: Duration = Duration::from_millis(25);
/// The queueing delay the session as a whole accepts.
const SESSION_TARGET: Duration = Duration::from_millis(60);
/// The queueing delay that ends slow start.
const SLOW_START_EXIT: Duration = Duration::from_millis(12);
/// Under this much queue, a loss is not taken as a sign of a full queue.
const QUIET: Duration = Duration::from_millis(4);
/// A window grows by at most one part in this per round trip, on top of one
/// packet, so a fast path is filled in seconds and not minutes.
const RAMP: f64 = 16.0;
/// How long a low round-trip time counts. Two periods are kept.
const BASE_PERIOD: Duration = Duration::from_secs(300);
/// Round-trip times taken together to see past noise.
const RECENT: usize = 4;
/// How soon after the first round trips background traffic first stands
/// back, and how often after that.
const FIRST_DRAIN: Duration = Duration::from_secs(5);
const DRAIN_EVERY: Duration = Duration::from_secs(30);
/// Standing back lasts at least this long, to let a queue at the target
/// empty, and at least two round trips.
const DRAIN_TIME: Duration = Duration::from_millis(50);
/// A round-trip time to pace by before there is any.
const FIRST_RTT: Duration = Duration::from_millis(100);
/// Pacing is this much faster than the window would need, so the pacer is
/// not what limits the window.
const PACE_GAIN: f64 = 1.25;
const PACE_GAIN_SLOW_START: f64 = 2.0;
/// The shortest burst worth a timer: timers here are about a millisecond.
const BURST_TIME: Duration = Duration::from_millis(2);
const MIN_BURST: u64 = 10 * MSS;

/// The classes of `link.md#priority`, as they matter here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// Sent first, and never waits for the window.
    RealTime,
    /// Sent within the window.
    Interactive,
    /// Sent within the window and the background limit.
    Background,
}

impl Class {
    pub(crate) fn from_index(class: usize) -> Class {
        match class {
            0 => Class::RealTime,
            1 => Class::Interactive,
            _ => Class::Background,
        }
    }
}

/// What an acknowledgement covered.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Acked {
    /// Bytes of packets newly acknowledged.
    pub bytes: u64,
    /// How many of them were background traffic.
    pub background: u64,
}

pub(crate) struct Controller {
    window: u64,
    background: u64,
    slow_start_until: u64,
    in_flight: u64,
    background_in_flight: u64,
    srtt: Option<Duration>,
    recent: VecDeque<Duration>,
    lowest: Duration,
    lowest_before: Duration,
    period_began: Instant,
    /// Losses of packets sent before this are the same congestion event.
    recovering_from: Option<Instant>,
    next_session_cut: Instant,
    next_background_cut: Instant,
    next_drain: Instant,
    draining_until: Option<Instant>,
    tokens: f64,
    refilled: Instant,
    rate: f64,
}

impl Controller {
    pub(crate) fn new(now: Instant) -> Controller {
        Controller {
            window: INITIAL_WINDOW,
            background: INITIAL_WINDOW,
            slow_start_until: u64::MAX,
            in_flight: 0,
            background_in_flight: 0,
            srtt: None,
            recent: VecDeque::with_capacity(RECENT),
            lowest: Duration::MAX,
            lowest_before: Duration::MAX,
            period_began: now,
            recovering_from: None,
            next_session_cut: now,
            next_background_cut: now,
            next_drain: now + FIRST_DRAIN,
            draining_until: None,
            tokens: INITIAL_WINDOW as f64,
            refilled: now,
            rate: 0.0,
        }
    }

    /// The session's window, in bytes.
    pub(crate) fn window(&self) -> u64 {
        self.window
    }

    fn in_slow_start(&self) -> bool {
        self.window < self.slow_start_until
    }

    /// The queueing delay, as far as it can be told.
    fn queue_delay(&self) -> Duration {
        let Some(recent) = self.recent.iter().min() else {
            return Duration::ZERO;
        };
        recent.saturating_sub(self.lowest.min(self.lowest_before))
    }

    fn limit(&self, class: Class) -> u64 {
        match class {
            Class::Background if self.draining_until.is_some() => MIN_WINDOW,
            Class::Background => self.background.min(self.window),
            _ => self.window,
        }
    }

    /// Whether the window has room for a packet of `class`. A real-time
    /// packet is never kept waiting for it.
    pub(crate) fn has_room(&self, class: Class) -> bool {
        match class {
            Class::RealTime => true,
            Class::Interactive => self.in_flight < self.window,
            Class::Background => {
                self.in_flight < self.window
                    && self.background_in_flight < self.limit(Class::Background)
            }
        }
    }

    /// Whether the pacer lets a packet of `class` go now.
    pub(crate) fn is_paced_now(&mut self, class: Class, now: Instant) -> bool {
        if class == Class::RealTime {
            return true;
        }
        self.rate = self.pace_rate(class);
        let burst = (self.rate * BURST_TIME.as_secs_f64()).max(MIN_BURST as f64);
        let idle = now.saturating_duration_since(self.refilled);
        self.tokens = (self.tokens + self.rate * idle.as_secs_f64()).min(burst);
        self.refilled = now;
        self.tokens >= 0.0
    }

    fn pace_rate(&self, class: Class) -> f64 {
        let gain = if self.in_slow_start() {
            PACE_GAIN_SLOW_START
        } else {
            PACE_GAIN
        };
        let rtt = self.srtt.unwrap_or(FIRST_RTT).as_secs_f64().max(1e-6);
        self.limit(class) as f64 * gain / rtt
    }

    /// When the pacer will next let a packet go, if it is holding one back.
    pub(crate) fn next_paced(&self) -> Option<Instant> {
        if self.tokens >= 0.0 || self.rate <= 0.0 {
            return None;
        }
        Some(self.refilled + Duration::from_secs_f64(-self.tokens / self.rate))
    }

    /// A packet of `bytes` left.
    pub(crate) fn on_sent(&mut self, bytes: u64, background: bool) {
        self.in_flight += bytes;
        if background {
            self.background_in_flight += bytes;
        }
        self.tokens -= bytes as f64;
    }

    fn note_rtt(&mut self, rtt: Duration, now: Instant) {
        self.srtt = Some(match self.srtt {
            Some(s) => (s * 7 + rtt) / 8,
            None => rtt,
        });
        if self.recent.len() == RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(rtt);
        if now.saturating_duration_since(self.period_began) >= BASE_PERIOD {
            self.lowest_before = self.lowest;
            self.lowest = Duration::MAX;
            self.period_began = now;
        }
        self.lowest = self.lowest.min(rtt);
    }

    /// One round trip from now, for a cut that should happen once in each.
    fn after_round_trip(&self, now: Instant) -> Instant {
        now + self.srtt.unwrap_or(FIRST_RTT)
    }

    /// Packets were acknowledged. `rtt` is the round trip of the newest, if
    /// it could be measured, and `sent` when that one was sent.
    pub(crate) fn on_ack(
        &mut self,
        acked: Acked,
        rtt: Option<Duration>,
        sent: Instant,
        now: Instant,
    ) {
        let flight_before = self.in_flight;
        self.in_flight = self.in_flight.saturating_sub(acked.bytes);
        self.background_in_flight = self.background_in_flight.saturating_sub(acked.background);
        if let Some(rtt) = rtt {
            self.note_rtt(rtt, now);
        }
        self.drain(acked, now);
        // Nothing grows on what was sent before the last loss.
        if self.recovering_from.is_some_and(|r| sent <= r) {
            return;
        }
        self.recovering_from = None;
        let queue = self.queue_delay();
        // A window that is not being used says nothing about the path.
        let limited = flight_before >= self.window / 2;
        if self.in_slow_start() {
            if queue >= SLOW_START_EXIT {
                self.slow_start_until = self.window;
            } else if limited {
                self.window += acked.bytes;
                self.background += acked.bytes;
                return;
            } else {
                return;
            }
        }
        if queue > SESSION_TARGET {
            if now >= self.next_session_cut {
                self.next_session_cut = self.after_round_trip(now);
                let keep = SESSION_TARGET.as_secs_f64() / queue.as_secs_f64();
                self.window = scale(self.window, keep.clamp(0.7, 0.95));
            }
        } else if limited {
            let room = 1.0 - queue.as_secs_f64() / SESSION_TARGET.as_secs_f64();
            self.window += growth(acked.bytes, self.window, room);
        }
        if queue > BACKGROUND_TARGET {
            if now >= self.next_background_cut {
                self.next_background_cut = self.after_round_trip(now);
                let keep = BACKGROUND_TARGET.as_secs_f64() / queue.as_secs_f64();
                self.background = scale(self.background, keep.clamp(0.5, 0.95));
            }
        } else if acked.background > 0 && self.draining_until.is_none() {
            let room = 1.0 - queue.as_secs_f64() / BACKGROUND_TARGET.as_secs_f64();
            self.background += growth(acked.background, self.background, room);
        }
        self.background = self.background.min(self.window);
    }

    /// Stands background traffic back, or lets it go on again.
    fn drain(&mut self, acked: Acked, now: Instant) {
        if self.draining_until.is_some_and(|until| now >= until) {
            self.draining_until = None;
            self.next_drain = now + DRAIN_EVERY;
        } else if self.draining_until.is_none() && acked.background > 0 && now >= self.next_drain {
            let rtt = self.srtt.unwrap_or(FIRST_RTT);
            self.draining_until = Some(now + (rtt * 2).max(DRAIN_TIME));
        }
    }

    /// A packet of `bytes`, sent at `sent`, was lost.
    pub(crate) fn on_lost(&mut self, bytes: u64, background: bool, sent: Instant, now: Instant) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
        if background {
            self.background_in_flight = self.background_in_flight.saturating_sub(bytes);
        }
        if self.recovering_from.is_some_and(|r| sent <= r) {
            return;
        }
        self.recovering_from = Some(now);
        // With no queue to speak of the loss did not come from a full one,
        // as on a radio link. It still counts, but for less.
        let quiet = self.queue_delay() < QUIET;
        let (session, background) = if quiet { (0.9, 0.8) } else { (0.75, 0.5) };
        self.window = scale(self.window, session);
        self.background = scale(self.background, background);
        self.slow_start_until = self.window;
    }

    /// Nothing has been acknowledged for several timeouts: start again.
    pub(crate) fn on_timeout(&mut self, now: Instant) {
        self.slow_start_until = (self.window / 2).max(MIN_WINDOW);
        self.window = MIN_WINDOW;
        self.background = MIN_WINDOW;
        self.draining_until = None;
        self.recovering_from = Some(now);
    }
}

fn scale(window: u64, by: f64) -> u64 {
    ((window as f64 * by) as u64).max(MIN_WINDOW)
}

/// How much a window grows when `acked` bytes of it arrive, with `room`
/// between 0 and 1 for how far the queue is below its target.
fn growth(acked: u64, window: u64, room: f64) -> u64 {
    let per_round = MSS as f64 + window as f64 / RAMP;
    (per_round * room * acked as f64 / window as f64).ceil() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Reverse;
    use std::collections::{BTreeMap, BinaryHeap};

    /// A path with one bottleneck, in simulated time.
    #[derive(Clone, Copy)]
    struct Path {
        /// Bytes per second through the bottleneck.
        rate: f64,
        /// Round-trip time with an empty queue.
        rtt: Duration,
        /// Bytes the bottleneck can queue.
        queue: u64,
        /// One packet in this many is lost at random, if not 0.
        lose_one_in: u64,
    }

    const MBIT: f64 = 1e6 / 8.0;

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Event {
        /// Flow `.0` may send.
        Send(usize),
        /// A packet reached the bottleneck.
        Arrive { flow: usize, packet: u64 },
        /// An acknowledgement reached the sender.
        Ack { flow: usize, packet: u64 },
    }

    struct Flow {
        cc: Controller,
        class: Class,
        end: Duration,
        next: u64,
        sent: BTreeMap<u64, Duration>,
        largest: u64,
        delivered: u64,
        lost: u64,
        wake: Option<Duration>,
    }

    impl Flow {
        fn new(class: Class, end: Duration, t0: Instant) -> Flow {
            Flow {
                cc: Controller::new(t0),
                class,
                end,
                next: 1,
                sent: BTreeMap::new(),
                largest: 0,
                delivered: 0,
                lost: 0,
                wake: None,
            }
        }
    }

    struct Sim {
        t0: Instant,
        now: Duration,
        path: Path,
        events: BinaryHeap<Reverse<(Duration, u64, Event)>>,
        seq: u64,
        /// When the bottleneck has finished with what it already has.
        busy_until: Duration,
        flows: Vec<Flow>,
        random: u64,
        queue_seen: Vec<(Duration, Duration)>,
    }

    impl Sim {
        fn new(path: Path) -> Sim {
            Sim {
                t0: Instant::now(),
                now: Duration::ZERO,
                path,
                events: BinaryHeap::new(),
                seq: 0,
                busy_until: Duration::ZERO,
                flows: Vec::new(),
                random: 0x9E37_79B9_7F4A_7C15,
                queue_seen: Vec::new(),
            }
        }

        fn add(&mut self, class: Class, begin: Duration, end: Duration) -> usize {
            let f = Flow::new(class, end, self.t0);
            self.flows.push(f);
            let i = self.flows.len() - 1;
            self.at(begin, Event::Send(i));
            i
        }

        fn at(&mut self, t: Duration, e: Event) {
            self.seq += 1;
            self.events.push(Reverse((t, self.seq, e)));
        }

        fn chance(&mut self, one_in: u64) -> bool {
            self.random ^= self.random << 13;
            self.random ^= self.random >> 7;
            self.random ^= self.random << 17;
            one_in != 0 && self.random % one_in == 0
        }

        fn clock(&self) -> Instant {
            self.t0 + self.now
        }

        fn send(&mut self, i: usize) {
            let now = self.clock();
            let (t, class) = (self.now, self.flows[i].class);
            if t >= self.flows[i].end {
                return;
            }
            while self.flows[i].cc.has_room(class) && self.flows[i].cc.is_paced_now(class, now) {
                let f = &mut self.flows[i];
                let packet = f.next;
                f.next += 1;
                f.sent.insert(packet, t);
                f.cc.on_sent(MSS, class == Class::Background);
                let arrive = t + self.path.rtt / 2;
                self.at(arrive, Event::Arrive { flow: i, packet });
            }
            let f = &mut self.flows[i];
            f.cc.is_paced_now(class, now);
            if let Some(next) = f.cc.next_paced() {
                let wake = next
                    .duration_since(self.t0)
                    .max(t + Duration::from_micros(1));
                if f.wake.is_none_or(|w| w <= t || wake < w) {
                    f.wake = Some(wake);
                    self.at(wake, Event::Send(i));
                }
            }
        }

        fn arrive(&mut self, flow: usize, packet: u64) {
            let backlog = self.busy_until.saturating_sub(self.now);
            let queued = (backlog.as_secs_f64() * self.path.rate) as u64;
            if queued + MSS > self.path.queue || self.chance(self.path.lose_one_in) {
                return;
            }
            let service = Duration::from_secs_f64(MSS as f64 / self.path.rate);
            self.busy_until = self.busy_until.max(self.now) + service;
            self.queue_seen.push((self.now, backlog));
            self.at(
                self.busy_until + self.path.rtt / 2,
                Event::Ack { flow, packet },
            );
        }

        fn ack(&mut self, i: usize, packet: u64) {
            let now = self.clock();
            let t = self.now;
            let f = &mut self.flows[i];
            let Some(sent) = f.sent.remove(&packet) else {
                return;
            };
            f.delivered += MSS;
            let newest = packet > f.largest;
            f.largest = f.largest.max(packet);
            let background = f.class == Class::Background;
            let acked = Acked {
                bytes: MSS,
                background: if background { MSS } else { 0 },
            };
            let rtt = newest.then(|| t.saturating_sub(sent));
            f.cc.on_ack(acked, rtt, self.t0 + sent, now);
            // Three packets later, a packet still missing is lost.
            let lost: Vec<(u64, Duration)> = f
                .sent
                .range(..f.largest.saturating_sub(2))
                .map(|(k, v)| (*k, *v))
                .collect();
            for (k, at) in lost {
                f.sent.remove(&k);
                f.lost += 1;
                f.cc.on_lost(MSS, background, self.t0 + at, now);
            }
            self.send(i);
        }

        fn run(&mut self, until: Duration) {
            while let Some(Reverse((t, _, e))) = self.events.pop() {
                if t > until {
                    self.events.push(Reverse((t, 0, e)));
                    break;
                }
                self.now = t;
                match e {
                    Event::Send(i) => {
                        self.flows[i].wake = None;
                        self.send(i);
                    }
                    Event::Arrive { flow, packet } => self.arrive(flow, packet),
                    Event::Ack { flow, packet } => self.ack(flow, packet),
                }
            }
            self.now = until;
        }

        /// The bottleneck's mean queue between two times, as delay.
        fn mean_queue(&self, from: Duration, to: Duration) -> Duration {
            let seen: Vec<f64> = self
                .queue_seen
                .iter()
                .filter(|(t, _)| *t >= from && *t < to)
                .map(|(_, q)| q.as_secs_f64())
                .collect();
            Duration::from_secs_f64(seen.iter().sum::<f64>() / seen.len().max(1) as f64)
        }

        fn delivered(&self, i: usize) -> u64 {
            self.flows[i].delivered
        }
    }

    fn secs(s: f64) -> Duration {
        Duration::from_secs_f64(s)
    }

    /// The share of the link one flow used over its last seconds.
    fn share_over(sim: &mut Sim, flow: usize, from: f64, to: f64) -> f64 {
        sim.run(secs(from));
        let before = sim.delivered(flow);
        sim.run(secs(to));
        (sim.delivered(flow) - before) as f64 / (sim.path.rate * (to - from))
    }

    const FOREVER: Duration = Duration::from_secs(10_000);

    #[test]
    fn background_fills_a_link_and_keeps_the_queue_near_its_target() {
        for (name, rate, rtt) in [
            ("home uplink", 20.0, 20),
            ("fast home", 100.0, 20),
            ("across a continent", 100.0, 80),
            ("gigabit lan", 1000.0, 1),
        ] {
            let path = Path {
                rate: rate * MBIT,
                rtt: Duration::from_millis(rtt),
                queue: 8 << 20,
                lose_one_in: 0,
            };
            let mut sim = Sim::new(path);
            let f = sim.add(Class::Background, Duration::ZERO, FOREVER);
            let used = share_over(&mut sim, f, 10.0, 20.0);
            let queue = sim.mean_queue(secs(10.0), secs(20.0));
            eprintln!("{name}: used {used:.2} queue {queue:?}");
            assert!(used > 0.9, "{name}: used {used:.2}");
            assert!(queue < Duration::from_millis(40), "{name}: queue {queue:?}");
        }
    }

    #[test]
    fn interactive_traffic_fills_a_link_without_a_long_queue() {
        let path = Path {
            rate: 100.0 * MBIT,
            rtt: Duration::from_millis(20),
            queue: 8 << 20,
            lose_one_in: 0,
        };
        let mut sim = Sim::new(path);
        let f = sim.add(Class::Interactive, Duration::ZERO, FOREVER);
        let used = share_over(&mut sim, f, 10.0, 20.0);
        let queue = sim.mean_queue(secs(10.0), secs(20.0));
        eprintln!("used {used:.2} queue {queue:?}");
        assert!(used > 0.9, "used {used:.2}");
        assert!(queue < Duration::from_millis(90), "queue {queue:?}");
    }

    #[test]
    fn a_short_queue_means_loss_and_the_link_stays_in_use() {
        let path = Path {
            rate: 100.0 * MBIT,
            rtt: Duration::from_millis(20),
            queue: 32 << 10,
            lose_one_in: 0,
        };
        let mut sim = Sim::new(path);
        let f = sim.add(Class::Background, Duration::ZERO, FOREVER);
        let used = share_over(&mut sim, f, 10.0, 20.0);
        let lost = sim.flows[f].lost as f64 / sim.flows[f].next as f64;
        eprintln!("used {used:.2}, lost {:.3}%", lost * 100.0);
        assert!(used > 0.6, "used {used:.2}");
        assert!(lost < 0.02, "lost {lost:.3}");
    }

    #[test]
    fn background_gives_way_to_interactive_traffic_within_moments() {
        let path = Path {
            rate: 20.0 * MBIT,
            rtt: Duration::from_millis(20),
            queue: 8 << 20,
            lose_one_in: 0,
        };
        let mut sim = Sim::new(path);
        let bg = sim.add(Class::Background, Duration::ZERO, FOREVER);
        let alone = share_over(&mut sim, bg, 5.0, 10.0);
        let call = sim.add(Class::Interactive, secs(10.0), FOREVER);
        let shared = share_over(&mut sim, bg, 12.0, 20.0);
        let call_share = (sim.delivered(call) as f64) / (sim.path.rate * 10.0);
        eprintln!("alone {alone:.2}, then {shared:.2} against {call_share:.2}");
        assert!(alone > 0.9, "alone {alone:.2}");
        assert!(shared < 0.2, "background kept {shared:.2}");
        assert!(call_share > 0.7, "interactive got {call_share:.2}");

        // It comes back when the other is done.
        sim.flows[call].end = secs(20.0);
        let after = share_over(&mut sim, bg, 25.0, 30.0);
        assert!(after > 0.8, "came back to {after:.2}");
    }

    #[test]
    fn random_loss_slows_a_flow_but_does_not_stop_it() {
        let path = Path {
            rate: 100.0 * MBIT,
            rtt: Duration::from_millis(20),
            queue: 8 << 20,
            lose_one_in: 100,
        };
        let mut sim = Sim::new(path);
        let f = sim.add(Class::Interactive, Duration::ZERO, FOREVER);
        let used = share_over(&mut sim, f, 10.0, 20.0);
        eprintln!("used {used:.3} of 100 Mbit/s at 1% loss");
        assert!(used > 0.05, "used {used:.3}");
    }

    #[test]
    fn two_flows_share_a_link() {
        let path = Path {
            rate: 100.0 * MBIT,
            rtt: Duration::from_millis(20),
            queue: 8 << 20,
            lose_one_in: 0,
        };
        let mut sim = Sim::new(path);
        let a = sim.add(Class::Background, Duration::ZERO, FOREVER);
        let b = sim.add(Class::Background, secs(5.0), FOREVER);
        sim.run(secs(20.0));
        let (a0, b0) = (sim.delivered(a), sim.delivered(b));
        sim.run(secs(40.0));
        let (ra, rb) = (
            (sim.delivered(a) - a0) as f64 / (sim.path.rate * 20.0),
            (sim.delivered(b) - b0) as f64 / (sim.path.rate * 20.0),
        );
        eprintln!("shares {ra:.2} and {rb:.2}");
        assert!(ra + rb > 0.85, "together {:.2}", ra + rb);
        assert!(ra.min(rb) > 0.1, "shares {ra:.2} and {rb:.2}");
    }

    #[test]
    fn a_link_that_slows_down_is_followed() {
        let path = Path {
            rate: 100.0 * MBIT,
            rtt: Duration::from_millis(20),
            queue: 8 << 20,
            lose_one_in: 0,
        };
        let mut sim = Sim::new(path);
        let f = sim.add(Class::Background, Duration::ZERO, FOREVER);
        sim.run(secs(10.0));
        sim.path.rate = 10.0 * MBIT;
        let used = share_over(&mut sim, f, 14.0, 20.0);
        let queue = sim.mean_queue(secs(14.0), secs(20.0));
        eprintln!("used {used:.2}, queue {queue:?}");
        assert!(used > 0.8, "used {used:.2}");
        assert!(queue < Duration::from_millis(50), "queue {queue:?}");
    }

    #[test]
    fn a_window_nobody_uses_does_not_grow() {
        let t0 = Instant::now();
        let mut c = Controller::new(t0);
        let rtt = Duration::from_millis(20);
        let mut t = t0;
        for _ in 0..1000 {
            c.on_sent(MSS, false);
            t += rtt;
            let acked = Acked {
                bytes: MSS,
                background: 0,
            };
            c.on_ack(acked, Some(rtt), t - rtt, t);
        }
        assert_eq!(c.window(), INITIAL_WINDOW);
    }

    #[test]
    fn real_time_never_waits() {
        let t0 = Instant::now();
        let mut c = Controller::new(t0);
        for _ in 0..1000 {
            c.on_sent(MSS, true);
        }
        assert!(!c.has_room(Class::Background));
        assert!(!c.has_room(Class::Interactive));
        assert!(c.has_room(Class::RealTime));
        assert!(c.is_paced_now(Class::RealTime, t0));
        assert!(!c.is_paced_now(Class::Interactive, t0));
        assert!(c.next_paced().is_some_and(|t| t > t0));
    }

    #[test]
    fn standing_back_ends_even_in_slow_start() {
        let t0 = Instant::now();
        let mut c = Controller::new(t0);
        let rtt = Duration::from_millis(20);
        let acked = Acked {
            bytes: MSS,
            background: MSS,
        };
        c.on_sent(MSS, true);
        c.draining_until = Some(t0 + rtt);
        c.next_drain = t0 + DRAIN_EVERY;
        assert_eq!(c.limit(Class::Background), MIN_WINDOW);
        c.on_ack(acked, Some(rtt), t0 + rtt / 2, t0 + rtt * 2);
        assert!(c.draining_until.is_none());
        assert!(c.limit(Class::Background) > MIN_WINDOW);

        // A timeout in the middle of one does not leave it standing.
        c.draining_until = Some(t0 + rtt * 100);
        c.on_timeout(t0 + rtt * 3);
        assert!(c.draining_until.is_none());
    }

    #[test]
    fn a_timeout_starts_over_and_climbs_back() {
        let t0 = Instant::now();
        let mut c = Controller::new(t0);
        c.window = 1000 * MSS;
        c.background = 1000 * MSS;
        c.on_timeout(t0);
        assert_eq!(c.window(), MIN_WINDOW);
        assert!(c.in_slow_start());
    }
}
