//! A calendar on the command line: a program of the Cardinal application
//! interface (`apps.md#the-application-interface`), and nothing else. It
//! implements the calendar application (`basics/calendar.md`, draft 1),
//! whose document it carries and gives the service in `hello`.
//!
//! It finds the service's application socket at `$CARDINAL_APP_SOCKET`,
//! else `$XDG_RUNTIME_DIR/cardinal-apps.sock`.

use anyhow::{bail, Context};
use cardinal_encoding::{Record, Value};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cardinal-calendar", version, about = "Calendars, shared with the people you choose")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Ask to see your calendars, and with --change to change them too.
    Approve {
        #[arg(long)]
        change: bool,
    },
    /// Start a calendar of yours.
    New { name: String },
    /// The calendars you have, and those shared with you.
    List,
    /// Add an event to a calendar (by its name or handle). Dates are
    /// 20261121, local times 20261121T180000.
    Add {
        calendar: String,
        title: String,
        start: String,
        #[arg(long)]
        end: Option<String>,
        #[arg(long)]
        zone: Option<String>,
        #[arg(long)]
        all_day: bool,
        #[arg(long)]
        location: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// How it repeats, as an RRULE value: FREQ=WEEKLY;BYDAY=TH
        #[arg(long)]
        repeat: Option<String>,
    },
    /// The events of a calendar, by start.
    Events { calendar: String },
    /// Share a calendar: Cardinal asks you whom with.
    Share { calendar: String },
    /// Print the calendar application's document, as bytes.
    Document,
}

/// The words of `basics/calendar.md`, draft 1.
const WORDS: &str = "\
A calendar space holds one calendar node, the events of the calendar, and the changes made to single occurrences of repeating events.
Times are Earth's civil times unless the calendar names a frame.
Every value is in the one canonical form RFC 5545 gives it.
A date is a DATE, such as 20261121. A time is a local DATE-TIME with no zone and no Z, such as 20261121T180000.
A zone is an IANA time zone name, such as America/Chicago. There is no VTIMEZONE.
Calendar, field 1: the calendar's name. Field 2: a colour to show it in, as # and six lowercase hex digits; a hint only. Field 3: the zone of times that name none.
Calendar, field 4: the frame whose clock the times are on, by the name of a frame document. Absent, it is Earth. A program that does not know the frame never shows the times as Earth's.
Event, field 1: the title. Field 2: when it starts, a date or a local time. Field 3: when it ends, of the same form; a date ends the day it names.
Event, field 4: the zone of its times. Absent, the calendar's; with neither, the times are floating, the same clock time wherever one is.
Event, field 5: it lasts all day; its start and end are dates.
Event, fields 6 and 7: where, and notes, as plain text.
Event, field 8: how it repeats, as the value of an RRULE, such as FREQ=WEEKLY;BYDAY=TH.
Event, field 9: the members it is for. Field 10: tags, as plain text.
Event, field 11: the UID of RFC 5545, by which a copy or an import finds the event again. A program that makes an event gives it one.
Change: made under a repeating event, for one occurrence. Field 1: which, by its start as the event's repeat gives it. Field 2: that occurrence is cancelled.
Change, fields 3 to 8: the title, start, end, zone, location and notes of that occurrence alone, where they differ from the event's.
";

const TEXT: u64 = 1;
const BOOLEAN: u64 = 3;
const BYTES: u64 = 4;
const MEMBER: u64 = 7;

const CALENDAR: u64 = 1;
const EVENT: u64 = 2;

fn field(key: u64, name: &str, ty: u64, list: bool) -> Value {
    let r = Record::new().with(1, key).with(2, name).with(3, ty);
    Value::Record(if list { r.with(4, true) } else { r })
}

fn kind(n: u64, name: &str, under: Value, fields: Vec<Value>) -> Value {
    Value::Record(
        Record::new()
            .with(1, n)
            .with(2, name)
            .with(3, Value::list([under]))
            .with(5, Value::List(fields)),
    )
}

/// The calendar application's document (`basics/calendar.md`).
pub fn document() -> Vec<u8> {
    let calendar = kind(
        CALENDAR,
        "calendar",
        Value::from(0u64),
        vec![
            field(1, "name", TEXT, false),
            field(2, "colour", TEXT, false),
            field(3, "zone", TEXT, false),
            field(4, "frame", BYTES, false),
        ],
    );
    let event = kind(
        EVENT,
        "event",
        Value::from(0u64),
        vec![
            field(1, "title", TEXT, false),
            field(2, "start", TEXT, false),
            field(3, "end", TEXT, false),
            field(4, "zone", TEXT, false),
            field(5, "all day", BOOLEAN, false),
            field(6, "location", TEXT, false),
            field(7, "notes", TEXT, false),
            field(8, "repeat", TEXT, false),
            field(9, "for", MEMBER, true),
            field(10, "tags", TEXT, true),
            field(11, "uid", TEXT, false),
        ],
    );
    let change = kind(
        3,
        "change",
        Value::from(EVENT),
        vec![
            field(1, "occurrence", TEXT, false),
            field(2, "cancelled", BOOLEAN, false),
            field(3, "title", TEXT, false),
            field(4, "start", TEXT, false),
            field(5, "end", TEXT, false),
            field(6, "zone", TEXT, false),
            field(7, "location", TEXT, false),
            field(8, "notes", TEXT, false),
        ],
    );
    Record::new()
        .with(0, 14u64)
        .with(1, "Calendar")
        .with(2, "Events, shared with the people you choose")
        .with(4, Record::new().with(1, true).with(2, 0u64))
        .with(5, Value::List(vec![calendar, event, change]))
        .with(6, WORDS)
        .with(8, "en")
        .encode()
}

#[cfg(unix)]
mod client {
    use cardinal_encoding::Record;
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::path::PathBuf;

    pub struct Client(Socket);

    fn path() -> PathBuf {
        if let Some(p) = std::env::var_os("CARDINAL_APP_SOCKET") {
            return PathBuf::from(p);
        }
        let run = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        run.unwrap_or_else(|| PathBuf::from("/tmp")).join("cardinal-apps.sock")
    }

    impl Client {
        pub fn connect() -> anyhow::Result<Client> {
            let p = path();
            let s = Socket::new(Domain::UNIX, Type::SEQPACKET, None)?;
            s.connect(&SockAddr::unix(&p)?)
                .map_err(|e| anyhow::anyhow!("Cardinal is not running here ({}): {e}", p.display()))?;
            let _ = s.set_send_buffer_size(512 * 1024);
            Ok(Client(s))
        }

        pub fn send(&mut self, r: &Record) -> anyhow::Result<()> {
            self.0.send(&r.encode())?;
            Ok(())
        }

        pub fn recv(&mut self) -> anyhow::Result<Record> {
            let mut buf = vec![std::mem::MaybeUninit::<u8>::uninit(); 256 * 1024 + 1];
            let n = self.0.recv(&mut buf)?;
            anyhow::ensure!(n > 0, "Cardinal closed the connection");
            // SAFETY: `recv` initialised the first `n` bytes.
            let bytes: Vec<u8> = buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect();
            Ok(Record::decode(&bytes)?)
        }
    }
}

#[cfg(unix)]
struct App {
    c: client::Client,
    root: [u8; 32],
}

#[cfg(unix)]
impl App {
    /// Connects, and says hello with the calendar's document.
    fn start() -> anyhow::Result<App> {
        let mut c = client::Client::connect()?;
        let hello = Record::new()
            .with(0, 1u64)
            .with(1, "Calendar")
            .with(2, Value::list([Value::from(document())]));
        c.send(&hello)?;
        let r = ok(c.recv()?)?;
        let root = r
            .list(4)?
            .first()
            .and_then(|v| v.as_bytes())
            .and_then(|b| b.try_into().ok())
            .context("the service named no application")?;
        Ok(App { c, root })
    }

    fn ask(&mut self, r: Record) -> anyhow::Result<Record> {
        self.c.send(&r)?;
        ok(self.c.recv()?)
    }

    /// Every item of a paged list, field `list` of the reply.
    fn all(&mut self, r: Record, list: u64, after: u64, more: u64, next: u64) -> anyhow::Result<Vec<Record>> {
        let mut out = Vec::new();
        let mut at = 0u64;
        loop {
            let got = self.ask(r.clone().with(after, at))?;
            for v in got.opt_list(list)?.unwrap_or(&[]) {
                out.push(v.as_record().context("a record")?.clone());
            }
            if got.opt_bool(more)? != Some(true) {
                return Ok(out);
            }
            at = got.uint(next)?;
        }
    }

    /// The calendars this program may see: handle, name, whether it may
    /// change each.
    fn calendars(&mut self) -> anyhow::Result<Vec<([u8; 16], String, bool)>> {
        let all = self.all(Record::new().with(0, 5u64), 2, 1, 3, 4)?;
        Ok(all
            .iter()
            .filter(|s| s.opt_bytes(3).ok().flatten() == Some(&self.root[..]))
            .filter_map(|s| {
                let h = s.bytes_n::<16>(1).ok()?;
                let name = s.opt_text(2).ok().flatten().unwrap_or("").to_owned();
                Some((h, name, s.opt_bool(5).ok().flatten() == Some(true)))
            })
            .collect())
    }

    /// A calendar by its name or the start of its handle.
    fn find(&mut self, which: &str) -> anyhow::Result<([u8; 16], String, bool)> {
        let all = self.calendars()?;
        let w = which.to_ascii_lowercase();
        let found: Vec<_> = all
            .into_iter()
            .filter(|(h, n, _)| n == which || (w.len() >= 4 && hex::encode(h).starts_with(&w)))
            .collect();
        match found.len() {
            1 => Ok(found.into_iter().next().expect("one")),
            0 => bail!("you have no calendar {which}: `cardinal-calendar list` shows them"),
            _ => bail!("more than one calendar is {which}: give its handle"),
        }
    }
}

fn ok(r: Record) -> anyhow::Result<Record> {
    match r.uint(0)? {
        0 => Ok(r),
        n => bail!("{} (error {n})", r.opt_text(1)?.unwrap_or("refused")),
    }
}

fn uid() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("random");
    format!("{}@cardinal", hex::encode(b))
}

#[cfg(unix)]
fn run(cmd: Cmd) -> anyhow::Result<()> {
    if let Cmd::Document = cmd {
        use std::io::Write;
        std::io::stdout().write_all(&document())?;
        return Ok(());
    }
    let mut app = App::start()?;
    match cmd {
        Cmd::Document => unreachable!(),
        Cmd::Approve { change } => {
            eprintln!("Waiting for you to say yes in Cardinal (`cardinal approve`)...");
            let r = app.ask(Record::new().with(0, 3u64).with(1, app.root).with(2, change))?;
            match r.opt_record(2)? {
                Some(a) if a.opt_bool(2)? == Some(true) => println!("Approved to see and change your calendars."),
                Some(_) => println!("Approved to see your calendars."),
                None => bail!("you said no"),
            }
        }
        Cmd::New { name } => {
            let r = app.ask(Record::new().with(0, 4u64).with(1, app.root).with(2, name.as_str()))?;
            let space = r.bytes_n::<16>(2)?;
            let node = Record::new()
                .with(0, 32u64)
                .with(1, CALENDAR)
                .with(2, [0u8; 16])
                .with(3, "calendar")
                .with(4, Record::new().with(1, name.as_str()));
            app.ask(Record::new().with(0, 8u64).with(1, space).with(2, Value::list([Value::Record(node)])))?;
            println!("{}", hex::encode(space));
        }
        Cmd::List => {
            for (h, name, change) in app.calendars()? {
                let how = if change { "yours to change" } else { "to see" };
                println!("{}  {name}  ({how})", hex::encode(h));
            }
        }
        Cmd::Add {
            calendar,
            title,
            start,
            end,
            zone,
            all_day,
            location,
            notes,
            repeat,
        } => {
            let (h, name, change) = app.find(&calendar)?;
            anyhow::ensure!(change, "{name} is shared with you to see, not to change");
            let fields = Record::new()
                .with(1, title.as_str())
                .with(2, start.as_str())
                .with_opt(3, end)
                .with_opt(4, zone)
                .with_opt(5, all_day.then_some(true))
                .with_opt(6, location)
                .with_opt(7, notes)
                .with_opt(8, repeat)
                .with(11, uid());
            let op = Record::new()
                .with(0, 32u64)
                .with(1, EVENT)
                .with(2, [0u8; 16])
                .with(3, title.as_str())
                .with(4, fields);
            let r = app.ask(Record::new().with(0, 8u64).with(1, h).with(2, Value::list([Value::Record(op)])))?;
            let id = r.list(2)?.first().and_then(|v| v.as_bytes()).map(hex::encode);
            println!("{}", id.unwrap_or_default());
        }
        Cmd::Events { calendar } => {
            let (h, _, _) = app.find(&calendar)?;
            let mut events = Vec::new();
            for n in app.all(Record::new().with(0, 7u64).with(1, h).with(3, EVENT), 2, 5, 4, 5)? {
                let mut start = String::new();
                let mut title = String::new();
                for f in n.opt_list(5)?.unwrap_or(&[]) {
                    let Some(f) = f.as_record() else { continue };
                    let text = f.opt_text(2).ok().flatten().unwrap_or("").to_owned();
                    match f.uint(1)? {
                        1 => title = text,
                        2 => start = text,
                        _ => {}
                    }
                }
                let fits = n.opt_bool(6)? == Some(true);
                events.push((start, title, fits));
            }
            events.sort();
            for (start, title, fits) in events {
                let odd = if fits { "" } else { "  (not as this calendar expects)" };
                println!("{start}  {title}{odd}");
            }
        }
        Cmd::Share { calendar } => {
            let (h, name, _) = app.find(&calendar)?;
            eprintln!("Choose whom to share {name} with in Cardinal (`cardinal approve`)...");
            let r = app.ask(Record::new().with(0, 11u64).with(1, h))?;
            for m in r.opt_list(2)?.unwrap_or(&[]) {
                let Some(m) = m.as_record() else { continue };
                let who = m.opt_text(2)?.unwrap_or("");
                let role = m.opt_text(3)?.unwrap_or("");
                let you = if m.opt_bool(4)? == Some(true) { " (you)" } else { "" };
                println!("{who}{you}: {role}");
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn run(_: Cmd) -> anyhow::Result<()> {
    bail!("the application interface is reached through a Unix socket, which this platform lacks")
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli.cmd) {
        eprintln!("cardinal-calendar: {e:#}");
        std::process::exit(1);
    }
}
