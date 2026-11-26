//! `cardinal messages` with nobody named: every conversation, people and
//! groups together, newest first, with what is new in each, laid out for a
//! person reading a terminal.

use cardinal_interface as api;

/// How the overview is drawn.
pub struct Style {
    /// Columns available.
    pub width: usize,
    /// Bold and dim, for a terminal that shows them.
    pub color: bool,
    /// Now, in ms since the epoch, and the local time zone's view of it.
    pub now_ms: u64,
}

impl Style {
    /// For this terminal: its width, and color unless output goes elsewhere
    /// or `NO_COLOR` is set.
    pub fn here() -> Style {
        use std::io::IsTerminal;
        let terminal = std::io::stdout().is_terminal();
        Style {
            width: terminal_width().unwrap_or(80).clamp(40, 160),
            color: terminal && std::env::var_os("NO_COLOR").is_none(),
            now_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
        }
    }
}

fn terminal_width() -> Option<usize> {
    #[cfg(unix)]
    {
        let mut w: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: TIOCGWINSZ fills a winsize, which `w` is.
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut w) } == 0
            && w.ws_col > 0
        {
            return Some(w.ws_col as usize);
        }
    }
    std::env::var("COLUMNS").ok()?.parse().ok()
}

/// One conversation, as shown.
struct Row {
    name: String,
    /// `group of 4`, or nothing for a person.
    kind: String,
    unread: u64,
    when: Option<u64>,
    /// `you: …` or `Bo: …`, or why there is nothing.
    last: String,
}

fn rows(conversations: &[api::Conversation], groups: &[api::Group]) -> Vec<Row> {
    let mut rows = Vec::new();
    for c in conversations {
        let mut name = crate::printable(&c.name);
        if name.is_empty() {
            name = crate::printable(c.suggested.as_deref().unwrap_or("?"));
        }
        let last = c.last.as_ref();
        rows.push(Row {
            name,
            kind: String::new(),
            unread: c.unread,
            when: last.and_then(|l| l.time),
            last: said(last, None),
        });
    }
    // Groups this person is in; offers are listed by `cardinal groups`.
    for g in groups {
        let last = g.last.as_ref();
        rows.push(Row {
            name: crate::printable(&g.name),
            kind: format!("group of {}", g.members),
            unread: g.unread,
            when: last.and_then(|l| l.time),
            last: said(last, last.and_then(|l| l.from.as_deref())),
        });
    }
    // Newest first; a conversation with nothing said goes last.
    rows.sort_by_key(|r| std::cmp::Reverse(r.when));
    rows
}

/// The last thing said, with who said it where that is not plain.
fn said(last: Option<&api::Last>, from: Option<&str>) -> String {
    let Some(last) = last else {
        return "nothing said yet".into();
    };
    let text = crate::printable(&last.text);
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let text = if text.is_empty() {
        "(a file)".to_owned()
    } else {
        text
    };
    if last.mine {
        format!("you: {text}")
    } else if let Some(from) = from {
        format!("{}: {text}", crate::printable(from))
    } else {
        text
    }
}

/// The overview, as text.
pub fn render(conversations: &[api::Conversation], groups: &[api::Group], s: &Style) -> String {
    let rows = rows(conversations, groups);
    if rows.is_empty() {
        return "No conversations yet. To start one, invite someone: cardinal invite\n".into();
    }
    let paint = |code: &str, t: &str| {
        if s.color {
            format!("\x1b[{code}m{t}\x1b[0m")
        } else {
            t.to_owned()
        }
    };
    let chars = |t: &str| t.chars().count();
    let name_w = rows
        .iter()
        .map(|r| chars(&r.name))
        .max()
        .unwrap_or(0)
        .min(24);
    let kind_w = rows.iter().map(|r| chars(&r.kind)).max().unwrap_or(0);
    let new_w = rows
        .iter()
        .map(|r| {
            if r.unread > 0 {
                chars(&format!("{} new", r.unread))
            } else {
                0
            }
        })
        .max()
        .unwrap_or(0);
    let when_w = 6;

    let mut out = String::new();
    for r in &rows {
        let fresh = r.unread > 0;
        let mark = if fresh { "●" } else { " " };
        let name = fit(&r.name, name_w);
        let kind = fit(&r.kind, kind_w);
        let new = if fresh {
            format!("{} new", r.unread)
        } else {
            String::new()
        };
        let when = r
            .when
            .map(|t| when(t.min(s.now_ms), s.now_ms))
            .unwrap_or_default();
        let kind = if kind_w > 0 {
            format!("{kind}  ")
        } else {
            String::new()
        };
        let line = format!("{mark} {name}  {kind}{new:>new_w$}  {when:<when_w$}  ");
        let used = chars(&line);
        let room = s.width.saturating_sub(used);
        let last = clip(&r.last, room);
        if fresh {
            out.push_str(&paint("1", &line));
            out.push_str(&last);
        } else {
            out.push_str(&paint("2", &format!("{line}{last}")));
        }
        out.push('\n');
    }

    let fresh: Vec<&Row> = rows.iter().filter(|r| r.unread > 0).collect();
    let total: u64 = fresh.iter().map(|r| r.unread).sum();
    out.push('\n');
    match fresh.len() {
        0 => out.push_str("Nothing new.\n"),
        1 => out.push_str(&format!(
            "{total} new {} from {}.\n",
            if total == 1 { "message" } else { "messages" },
            fresh[0].name
        )),
        n => out.push_str(&format!("{total} new messages in {n} conversations.\n")),
    }
    out.push_str(&paint(
        "2",
        "Read one: cardinal messages <name>    a group: cardinal group messages <group>",
    ));
    out.push('\n');
    out
}

/// `t` padded or cut to `w` characters.
fn fit(t: &str, w: usize) -> String {
    let n = t.chars().count();
    if n <= w {
        format!("{t}{}", " ".repeat(w - n))
    } else {
        let mut s: String = t.chars().take(w.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}

/// `t` cut to `w` characters, with an ellipsis if cut.
fn clip(t: &str, w: usize) -> String {
    if t.chars().count() <= w {
        t.to_owned()
    } else if w == 0 {
        String::new()
    } else {
        let mut s: String = t.chars().take(w - 1).collect();
        s.push('…');
        s
    }
}

/// When, as people say it: `14:05` today, `Tue` this week, `Nov 12` this
/// year, `2025-03-01` before.
fn when(t_ms: u64, now_ms: u64) -> String {
    let (t, now) = (local(t_ms), local(now_ms));
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let same_year = t.year == now.year;
    if same_year && t.yday == now.yday {
        format!("{:02}:{:02}", t.hour, t.min)
    } else if now_ms.saturating_sub(t_ms) < 6 * 86_400_000 {
        DAYS[t.wday % 7].to_owned()
    } else if same_year {
        format!("{} {}", MONTHS[t.mon % 12], t.mday)
    } else {
        format!("{}-{:02}-{:02}", t.year, t.mon + 1, t.mday)
    }
}

struct Local {
    year: i32,
    yday: i32,
    mon: usize,
    mday: i32,
    wday: usize,
    hour: i32,
    min: i32,
}

fn local(ms: u64) -> Local {
    #[cfg(unix)]
    {
        let t = (ms / 1000) as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: both pointers are to live values of the right types.
        if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
            return Local {
                year: tm.tm_year + 1900,
                yday: tm.tm_yday,
                mon: tm.tm_mon as usize,
                mday: tm.tm_mday,
                wday: tm.tm_wday as usize,
                hour: tm.tm_hour,
                min: tm.tm_min,
            };
        }
    }
    utc(ms)
}

/// The civil date in UTC, where the local zone cannot be read.
fn utc(ms: u64) -> Local {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let mday = (doy - (153 * mp + 2) / 5 + 1) as i32;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 } as usize; // 1..=12
    let year = (yoe + era * 400 + i64::from(mon <= 2)) as i32;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let before = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][mon - 1];
    Local {
        year,
        yday: before + mday - 1 + i32::from(leap && mon > 2),
        mon: mon - 1,
        mday,
        wday: ((days + 4).rem_euclid(7)) as usize,
        hour: (rem / 3600) as i32,
        min: ((rem % 3600) / 60) as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_794_995_000_000; // 2026-11-18, mid-morning UTC

    fn style() -> Style {
        Style {
            width: 80,
            color: false,
            now_ms: NOW,
        }
    }

    fn last(mine: bool, from: Option<&str>, text: &str, time: u64) -> Option<api::Last> {
        Some(api::Last {
            from: from.map(str::to_owned),
            mine,
            text: text.to_owned(),
            time: Some(time),
        })
    }

    fn conversation(name: &str, unread: u64, last: Option<api::Last>) -> api::Conversation {
        let reach = cardinal_interface::new!(api::ContactReach {
            named: Vec::new(),
            said_no: false,
            shared: false,
            waiting: false
        });
        api::Conversation {
            last,
            ..cardinal_interface::new!(api::Conversation {
                connected: false,
                id: [0; 8],
                introductions: true,
                name: name.to_owned(),
                nearby: false,
                own: true,
                reach,
                relayed: false,
                trusted: true,
                unread
            })
        }
    }

    fn group(name: &str, members: u64, unread: u64, last: Option<api::Last>) -> api::Group {
        let reach = cardinal_interface::new!(api::GroupReach {
            added: Vec::new(),
            ask: false,
            public: false,
            said_no: false,
            set: false,
            shared: false,
            waiting: false,
            what: Vec::new(),
            who: Vec::new()
        });
        api::Group {
            last,
            ..cardinal_interface::new!(api::Group {
                admin: false,
                did_not_stand: Vec::new(),
                did_not_stand_changes: Vec::new(),
                group: [0; 32],
                held_back: 0,
                introductions: true,
                members,
                name: name.to_owned(),
                not_posted: 0,
                public: false,
                reach,
                unread
            })
        }
    }

    #[test]
    fn people_and_groups_newest_first_with_what_is_new() {
        let conversations = [
            conversation(
                "Ana",
                0,
                last(true, None, "see you sunday", NOW - 3 * 86_400_000),
            ),
            conversation(
                "Daniel Wigton",
                2,
                last(
                    false,
                    None,
                    "At some point we'll need a harness so arriving chats submit a turn. But I'll leave speccing software",
                    NOW - 60_000,
                ),
            ),
            api::Conversation {
                suggested: Some("Cousin Al".into()),
                own: false,
                ..conversation("", 0, None)
            },
        ];
        // offers are another list, which the overview is not given
        let groups = [group(
            "Choir",
            4,
            1,
            last(false, Some("Bo"), "thanks\nall", NOW - 3_600_000),
        )];
        let out = render(&conversations, &groups, &style());
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("● Daniel Wigton"), "{out}");
        assert!(lines[0].contains("2 new"), "{out}");
        assert!(lines[0].ends_with('…'), "{out}");
        assert!(lines[1].starts_with("● Choir"), "{out}");
        assert!(lines[1].contains("group of 4"), "{out}");
        assert!(lines[1].contains("Bo: thanks all"), "{out}");
        assert!(lines[2].starts_with("  Ana"), "{out}");
        assert!(lines[2].contains("you: see you sunday"), "{out}");
        assert!(lines[3].starts_with("  Cousin Al"), "{out}");
        assert!(lines[3].contains("nothing said yet"), "{out}");
        assert!(!out.contains("Offered"), "{out}");
        assert!(out.contains("3 new messages in 2 conversations."), "{out}");
        for l in &lines {
            assert!(l.chars().count() <= 80, "too wide: {l}");
        }
        // The last column starts at the same place on every line.
        let at = |l: &str, w: &str| l.chars().count() - l[l.find(w).unwrap()..].chars().count();
        assert_eq!(at(lines[2], "you:"), at(lines[3], "nothing"));
        assert_eq!(at(lines[1], "Bo:"), at(lines[2], "you:"));
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn nothing_yet_says_how_to_begin() {
        let out = render(&[], &[], &style());
        assert!(out.contains("cardinal invite"));
    }

    #[test]
    fn times_read_as_people_say_them() {
        // Days and dates, in UTC so the test does not depend on the zone.
        let d = utc(1_794_995_000_000);
        assert_eq!((d.year, d.mon + 1, d.mday, d.wday), (2026, 11, 18, 3));
        assert_eq!(utc(0).year, 1970);
        assert_eq!(utc(951_782_400_000).mday, 29); // 2000-02-29
        assert_eq!(when(NOW - 60_000, NOW).len(), 5); // hh:mm
        assert_eq!(when(NOW - 400 * 86_400_000, NOW).len(), 10); // yyyy-mm-dd
    }
}
