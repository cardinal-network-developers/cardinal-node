//! `cardinal`: one folder, the same on every device you own.
//!
//! `cardinal daemon` runs the daemon (crate `cardinald`); every other
//! command talks to it over its local socket, except `init`, which can
//! also set up a device while the daemon is stopped, and the deployment
//! commands (`install`, `update`, `uninstall`, `version`), which come from
//! `cardinal-update`.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cardinald::{control, setup, Config, Paths};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(
    name = "cardinal",
    version = cardinal_update::VERSION,
    about = "One folder, the same on every device you own.",
    after_help = "Start here: `cardinal init` on your first device, then `cardinal pair` on each \
                  other device."
)]
struct Cli {
    /// Use this data directory instead of ~/.local/share/cardinal (also
    /// CARDINAL_HOME). Lets two devices run on one machine.
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up this device as your first device: creates who you are, shows
    /// your 24 recovery words, and creates your synced folder.
    Init {
        /// This device's name, shown on your other devices.
        #[arg(long)]
        name: Option<String>,
        /// Do not ask to confirm the recovery words were written down.
        #[arg(long)]
        yes: bool,
        /// Fetch file content only when opened, instead of keeping
        /// everything on this device.
        #[arg(long)]
        on_demand: bool,
        /// Where your files appear (default ~/Cardinal).
        #[arg(long, value_name = "DIR")]
        mount: Option<PathBuf>,
    },
    /// Run the daemon in the foreground (normally started by the service).
    Daemon {
        /// Listen for your other devices on this address (default
        /// 0.0.0.0:7171; saved for next time).
        #[arg(long, value_name = "IP:PORT")]
        listen: Option<String>,
        /// Mount your files here (saved for next time).
        #[arg(long, value_name = "DIR")]
        mount: Option<PathBuf>,
        /// Do not mount your files this time.
        #[arg(long)]
        no_mount: bool,
        /// Do not look for your devices on the local network.
        #[arg(long)]
        no_discovery: bool,
        /// Multicast DNS port (for testing).
        #[arg(long, hide = true)]
        mdns_port: Option<u16>,
        /// This device's name (saved for next time).
        #[arg(long)]
        name: Option<String>,
    },
    /// Show this device, your devices, sync progress, and conflicts.
    Status {
        /// Print the raw status as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Add a device. On the NEW device run `cardinal pair` and it shows a
    /// code; on a device you already use, run `cardinal pair <code>`.
    Pair {
        /// The code the new device shows (type it on an existing device).
        code: Option<String>,
        /// The new device's address, if it cannot be found on the local
        /// network (shown next to the code).
        #[arg(long, value_name = "IP:PORT")]
        at: Option<String>,
        /// Make the new device an admin device (it can add and remove
        /// devices). Give it on both devices.
        #[arg(long)]
        admin: bool,
    },
    /// List your devices.
    Devices,
    /// Measure the encrypted link to your other devices: about 10 seconds
    /// receiving and 10 sending, without touching the disk, and the round
    /// trip time.
    Speedtest {
        /// The device (name or key); default: each online device in turn.
        device: Option<String>,
        /// Print the results as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove a device you no longer use (it is cut off from your files).
    RemoveDevice {
        /// The device's name or key, as `cardinal devices` shows.
        who: String,
    },
    /// Devices reached over the internet, by address.
    Peer {
        #[command(subcommand)]
        cmd: PeerCmd,
    },
    /// Show your files in a folder (default ~/Cardinal).
    Mount {
        /// The folder.
        path: Option<PathBuf>,
    },
    /// Stop showing your files in a folder, for good (also on later
    /// starts, until `cardinal mount`): for hosts without FUSE, such as
    /// containers.
    Unmount,
    /// List the versions of a file.
    History {
        /// The file (in your Cardinal folder).
        path: PathBuf,
    },
    /// Bring back an earlier version of a file.
    Restore {
        /// The file.
        path: PathBuf,
        /// The version number, as `cardinal history` shows.
        #[arg(long)]
        version: u64,
    },
    /// List files that have two versions.
    Conflicts,
    /// Keep a file or folder on this device even with on-demand fetching.
    Pin {
        /// The file or folder.
        path: PathBuf,
    },
    /// Stop keeping a pinned file or folder.
    Unpin {
        /// The file or folder.
        path: PathBuf,
    },
    /// Keep all files on this device (`full`) or fetch them when opened
    /// (`on-demand`).
    Retention {
        /// `full` or `on-demand`.
        mode: String,
    },
    /// Show the daemon's log.
    Log {
        /// Keep following it.
        #[arg(short, long)]
        follow: bool,
    },
    /// Save pending changes in the folder now.
    #[command(hide = true)]
    Flush,
    /// Stop the daemon.
    Stop,
    #[command(flatten)]
    Deploy(cardinal_update::DeployCommand),
}

#[derive(Subcommand)]
enum PeerCmd {
    /// Reach your devices at this address (host:port), e.g. a server over
    /// the internet.
    Add {
        /// host:port
        addr: String,
    },
    /// List addresses.
    List,
    /// Forget an address.
    Remove {
        /// host:port
        addr: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Some(h) = &cli.home {
        std::env::set_var("CARDINAL_HOME", h);
    }
    let r = match cli.cmd {
        Cmd::Deploy(c) => cardinal_update::run(c),
        Cmd::Daemon {
            listen,
            mount,
            no_mount,
            no_discovery,
            mdns_port,
            name,
        } => {
            cardinald::init_logging();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(cardinald::run(
                Paths::from_env(),
                cardinald::Overrides {
                    listen,
                    mount,
                    no_mount,
                    no_discovery,
                    mdns_port,
                    name,
                },
            ))
        }
        cmd => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(client(cmd))
        }
    };
    if let Err(e) = r {
        eprintln!("cardinal: {e:#}");
        std::process::exit(1);
    }
}

async fn call(paths: &Paths, req: Value) -> anyhow::Result<Value> {
    let v = control::request(&paths.socket, &req).await.map_err(|_| {
        anyhow::anyhow!(
            "the cardinal daemon is not running. Start it with `cardinal daemon` (or \
             `systemctl --user start cardinal` if you installed it with `cardinal install`)."
        )
    })?;
    if v["ok"].as_bool() == Some(true) {
        Ok(v)
    } else {
        anyhow::bail!("{}", v["error"].as_str().unwrap_or("the daemon failed"))
    }
}

async fn running(paths: &Paths) -> bool {
    control::request(&paths.socket, &json!({"cmd": "status"}))
        .await
        .is_ok()
}

/// A path inside the mount, relative to its top.
fn space_path(p: &Path, mount: Option<&str>) -> String {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    if let Some(m) = mount {
        if let Ok(rest) = abs.strip_prefix(m) {
            return rest.to_string_lossy().trim_matches('/').to_owned();
        }
    }
    p.to_string_lossy().trim_matches('/').to_owned()
}

async fn mount_path(paths: &Paths) -> Option<String> {
    call(paths, json!({"cmd": "status"}))
        .await
        .ok()
        .and_then(|v| v["mount"].as_str().map(str::to_owned))
}

fn human_size(n: u64) -> String {
    let units = ["B", "kB", "MB", "GB", "TB"];
    let mut x = n as f64;
    let mut u = 0;
    while x >= 1000.0 && u + 1 < units.len() {
        x /= 1000.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{x:.1} {}", units[u])
    }
}

/// `fetching 412 files, 1.8 GB left, 31.0 MB/s` from `progress`.
fn fetch_line(p: &Value) -> String {
    let files = p["files_pending"].as_u64().unwrap_or(0);
    let mut line = format!(
        "fetching {} file{}, {} left",
        files,
        if files == 1 { "" } else { "s" },
        human_size(p["bytes_pending"].as_u64().unwrap_or(0))
    );
    let wanted = p["bytes_wanted"].as_u64().unwrap_or(0);
    if wanted > 0 {
        line += &format!(" of {}", human_size(wanted));
    }
    let rate = p["rate"].as_u64().unwrap_or(0);
    if rate > 0 {
        line += &format!(", {}/s", human_size(rate));
    }
    line
}

fn human_time(ms: Option<u64>) -> String {
    let Some(ms) = ms else {
        return "unknown time".into();
    };
    let t: libc::time_t = (ms / 1000) as libc::time_t;
    // SAFETY: localtime_r only writes into the struct we pass.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return format!("{t}");
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

fn prompt(q: &str) -> anyhow::Result<String> {
    print!("{q}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim().to_owned())
}

async fn init(
    paths: &Paths,
    name: Option<String>,
    yes: bool,
    on_demand: bool,
    mount: Option<PathBuf>,
) -> anyhow::Result<()> {
    let daemon = running(paths).await;
    if daemon {
        let st = call(paths, json!({"cmd": "status"})).await?;
        if !st["identity"].is_null() {
            anyhow::bail!("this device is already set up. See `cardinal status`.");
        }
    }
    let prepared = setup::prepare(paths)?;
    let words = prepared.phrase().to_words();
    let list: Vec<&str> = words.split(' ').collect();
    println!();
    println!("Your recovery words. Write them down, in order, and keep them somewhere safe.");
    println!("They are the only way back in if you lose all your devices, and anyone who");
    println!("has them can become you. They will not be shown again.");
    println!();
    for row in 0..8 {
        let mut line = String::from("   ");
        for col in 0..3 {
            let i = row + col * 8;
            line.push_str(&format!("{:>2}. {:<12}", i + 1, list[i]));
        }
        println!("{line}");
    }
    println!();
    println!("This version has no guardians yet: if someone gets your words, your identity");
    println!("is frozen, not recovered, and you would start over with a new one.");
    println!();
    if !yes {
        let r: [u8; 2] = cardinal_crypto::random_bytes();
        let a = (r[0] as usize) % 24;
        let mut b = (r[1] as usize) % 24;
        if b == a {
            b = (a + 7) % 24;
        }
        let picks = [a.min(b), a.max(b)];
        prompt("Press Enter once you have written them down. ")?;
        // Clear the words from the screen before asking for two of them.
        print!("\x1b[2J\x1b[H");
        std::io::stdout().flush()?;
        let mut ok = false;
        for _ in 0..3 {
            let w1 = prompt(&format!("Word number {}: ", picks[0] + 1))?;
            let w2 = prompt(&format!("Word number {}: ", picks[1] + 1))?;
            if w1.eq_ignore_ascii_case(list[picks[0]]) && w2.eq_ignore_ascii_case(list[picks[1]]) {
                ok = true;
                break;
            }
            println!("That does not match. Check what you wrote down and try again.");
        }
        if !ok {
            anyhow::bail!(
                "the words did not match, so nothing was set up. Run `cardinal init` again \
                 for new words."
            );
        }
    }
    let mut config = Config::load(&paths.config())?;
    if let Some(n) = name {
        config.name = n;
    }
    if on_demand {
        config.retention = "on-demand".into();
    }
    if let Some(m) = mount {
        config.mount = Some(if m.is_absolute() {
            m
        } else {
            std::env::current_dir()?.join(m)
        });
    }
    std::fs::create_dir_all(&paths.home)?;
    config.save(&paths.config())?;
    setup::install(paths, prepared, &config)?;
    println!("Set up. This device is \"{}\".", config.name);
    if daemon {
        call(paths, json!({"cmd": "reload"})).await?;
        if let Some(m) = &config.mount {
            println!("Your files are in {}.", m.display());
        }
    } else {
        println!(
            "Start the daemon to see your files{}: `cardinal daemon`, or `cardinal install` to \
             run it in the background.",
            config
                .mount
                .as_ref()
                .map(|m| format!(" in {}", m.display()))
                .unwrap_or_default()
        );
    }
    println!();
    println!("To add another device: run `cardinal pair` on it, then type the code it shows");
    println!("here with `cardinal pair <code>`.");
    Ok(())
}

async fn pair(
    paths: &Paths,
    code: Option<String>,
    at: Option<String>,
    admin: bool,
) -> anyhow::Result<()> {
    if let Some(code) = code {
        println!("Looking for the new device...");
        let v = call(
            paths,
            json!({"cmd": "pair-type", "code": code, "at": at, "admin": admin}),
        )
        .await?;
        println!(
            "Added \"{}\". It is getting your files now; see `cardinal status`.",
            v["name"].as_str().unwrap_or("the device")
        );
        return Ok(());
    }
    let v = call(paths, json!({"cmd": "pair-show", "admin": admin})).await?;
    let code = v["code"].as_str().unwrap_or("?");
    println!();
    println!("    {code}");
    println!();
    println!("On a device you already use, run:");
    println!();
    println!("    cardinal pair {code}");
    println!();
    if let Some(a) = v["addrs"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|a| a.as_str())
    {
        println!("(If it cannot find this device, add `--at {a}`.)");
    }
    println!("Waiting...");
    let start = Instant::now();
    let mut said_joining = false;
    loop {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let s = call(paths, json!({"cmd": "pair-status"})).await?;
        match s["state"].as_str().unwrap_or("") {
            "joining" if !said_joining => {
                said_joining = true;
                println!(
                    "Paired with \"{}\". Receiving your identity...",
                    s["admin"].as_str().unwrap_or("your device")
                );
            }
            "joined" => {
                if s["files"].as_bool() == Some(true) {
                    let st = call(paths, json!({"cmd": "status"})).await?;
                    println!(
                        "Done. This device now belongs to you{}.",
                        st["mount"]
                            .as_str()
                            .map(|m| format!("; your files are in {m}"))
                            .unwrap_or_default()
                    );
                    return Ok(());
                }
                if start.elapsed() > Duration::from_secs(600) {
                    println!("Joined. Your files are still on their way; see `cardinal status`.");
                    return Ok(());
                }
            }
            "failed" => anyhow::bail!("{}", s["error"].as_str().unwrap_or("pairing failed")),
            "idle" => anyhow::bail!("pairing stopped; run `cardinal pair` again"),
            _ => {}
        }
        if start.elapsed() > Duration::from_secs(900) {
            anyhow::bail!("gave up waiting; run `cardinal pair` again");
        }
    }
}

fn print_devices(devs: &Value) {
    for d in devs.as_array().cloned().unwrap_or_default() {
        let online = d["online"].as_bool().unwrap_or(false);
        let mut line = format!(
            "  {} {}",
            if online { "●" } else { "○" },
            d["name"].as_str().unwrap_or("?")
        );
        if d["this"].as_bool() == Some(true) {
            line.push_str(" (this device)");
        } else {
            line.push_str(if online { "  online" } else { "  offline" });
        }
        line.push_str(&format!("  {}", d["power"].as_str().unwrap_or("")));
        if let Some(a) = d["addr"].as_str() {
            line.push_str(&format!("  {a}"));
        }
        line.push_str(&format!("  [{}]", d["key"].as_str().unwrap_or("")));
        println!("{line}");
        if let Some(f) = source_line(&d["fetch"]) {
            println!("      {f}");
        }
    }
}

/// `sent 1.1 GB to this device; now 38.0 MB/s, 3 ms` from a device's
/// `fetch` statistics, if it has sent anything.
fn source_line(f: &Value) -> Option<String> {
    if f["replies"].as_u64().unwrap_or(0) == 0 {
        return None;
    }
    Some(format!(
        "sent {} to this device; now {}/s, {} ms",
        human_size(f["received"].as_u64().unwrap_or(0)),
        human_size(f["rate"].as_u64().unwrap_or(0)),
        f["latency_ms"].as_u64().unwrap_or(0)
    ))
}

fn print_status(v: &Value) {
    if v["identity"].is_null() {
        println!(
            "This device (\"{}\") does not belong to anyone yet.",
            v["name"].as_str().unwrap_or("")
        );
        if let Some(s) = v["pairing"]["state"].as_str() {
            println!("Pairing: {s}");
        }
        println!(
            "Run `cardinal init` if it is your first device, or `cardinal pair` to add it to \
             your others."
        );
        return;
    }
    println!("This device: {}", v["name"].as_str().unwrap_or(""));
    match (v["mounted"].as_str(), v["mount"].as_str()) {
        (Some(m), _) => println!("Your files: {m}"),
        (None, Some(_)) if v["mount_unavailable"].is_string() => println!(
            "Your files: FUSE is not available here ({}); syncing without a mount \
             (`cardinal unmount` stops trying)",
            v["mount_unavailable"].as_str().unwrap_or("")
        ),
        (None, Some(m)) if v["files_ready"].as_bool() == Some(true) => {
            println!("Your files: not mounted at {m}; see `cardinal log`")
        }
        (None, Some(_)) => println!("Your files: still arriving from your other devices"),
        (None, None) => println!("Your files: not shown in a folder (`cardinal mount` shows them)"),
    }
    println!(
        "Keeping: {}",
        if v["retention"] == "on-demand" {
            "files you open (on demand)"
        } else {
            "everything (full)"
        }
    );
    println!("Devices:");
    print_devices(&v["devices"]);
    let p = &v["progress"];
    let files = p["files_pending"].as_u64().unwrap_or(0);
    if files > 0 {
        println!("Sync: {}", fetch_line(p));
        if let Some(e) = p["last_error"].as_str() {
            println!("      {e}");
        }
    } else if v["pending_changes"].as_bool() == Some(true) {
        println!("Sync: saving changes...");
    } else {
        println!("Sync: up to date");
    }
    for line in copies_lines(&v["copies"], v["devices"].as_array().map_or(0, |d| d.len())) {
        println!("{line}");
    }
    let c = v["conflicts"].as_u64().unwrap_or(0);
    if c > 0 {
        println!(
            "Two versions: {c} file{} — see `cardinal conflicts`",
            if c == 1 { " has" } else { "s have" }
        );
    }
}

/// `4 minutes ago` for a span of `ms`.
fn ago(ms: u64) -> String {
    let s = ms / 1000;
    let unit = |n: u64, what: &str| format!("{n} {what}{} ago", if n == 1 { "" } else { "s" });
    match s {
        0..=1 => "just now".into(),
        2..=59 => unit(s, "second"),
        60..=3599 => unit(s / 60, "minute"),
        3600..=172_799 => unit(s / 3600, "hour"),
        _ => unit(s / 86_400, "day"),
    }
}

/// `an hour`, `2 hours`, `3 seconds` for a span of `ms`.
fn span(ms: u64) -> String {
    let s = ms / 1000;
    let n = |n: u64, what: &str, one: &str| {
        if n == 1 {
            one.to_owned()
        } else {
            format!("{n} {what}s")
        }
    };
    if s >= 3600 && s % 3600 == 0 {
        n(s / 3600, "hour", "an hour")
    } else if s >= 60 && s % 60 == 0 {
        n(s / 60, "minute", "a minute")
    } else {
        n(s, "second", "a second")
    }
}

/// The `Copies:` lines of `cardinal status`, from its `copies` object
/// (`blobs.md#counting-copies`). `devices`: how many devices the person
/// has. Says what was seen, never that files are safe.
fn copies_lines(c: &Value, devices: usize) -> Vec<String> {
    if c.is_null() || c["blobs"].as_u64().unwrap_or(0) == 0 {
        return Vec::new();
    }
    let now = c["now"].as_u64().unwrap_or(0);
    let age = |t: &Value| t.as_u64().map(|t| ago(now.saturating_sub(t)));
    let holders = c["holders"].as_array().cloned().unwrap_or_default();
    let name = |h: &Value| {
        if h["this"] == true {
            "this device".to_owned()
        } else {
            h["name"].as_str().unwrap_or("?").to_owned()
        }
    };
    let is = |h: &Value, k: &str| h[k].as_bool() == Some(true);
    let counted: Vec<&Value> = holders.iter().filter(|h| is(h, "counted")).collect();
    let pending: Vec<&Value> = holders
        .iter()
        .filter(|h| h["state"] == "unchecked" && is(h, "online") && !is(h, "this"))
        .collect();
    let older = span(c["older_than_ms"].as_u64().unwrap_or(3_600_000));
    let mut out = Vec::new();
    if holders.is_empty() {
        out.push(
            "Copies: no device keeps all your files (each fetches them when opened)".to_owned(),
        );
        return out;
    }
    let pending_names = pending
        .iter()
        .map(|h| name(h))
        .collect::<Vec<_>>()
        .join(", ");
    if counted.is_empty() && !pending.is_empty() {
        let mut l = format!("Copies: checking {pending_names}…");
        if c["eligible"].as_u64() == Some(0) {
            l += &format!(" (nothing older than {older} yet)");
        }
        out.push(l);
    } else if counted.is_empty() {
        out.push("Copies: none seen recently".to_owned());
    } else {
        // When the others were checked at about the same time, say it
        // once; else per device.
        let ages: Vec<u64> = counted
            .iter()
            .filter(|h| !is(h, "this"))
            .filter_map(|h| h["last_pass"].as_u64())
            .map(|t| now.saturating_sub(t))
            .collect();
        let interval = c["interval_ms"].as_u64().unwrap_or(600_000);
        let spread = ages.iter().max().unwrap_or(&0) - ages.iter().min().unwrap_or(&0) > interval;
        let list: Vec<String> = counted
            .iter()
            .map(|h| match age(&h["last_pass"]) {
                Some(a) if spread && !is(h, "this") => format!("{} (checked {a})", name(h)),
                _ => name(h),
            })
            .collect();
        let mut l = format!("Copies: {} — {}", counted.len(), list.join(", "));
        match ages.iter().max() {
            Some(a) if !spread => l += &format!(" (checked {}; files older than {older})", ago(*a)),
            Some(_) => l += &format!("; files older than {older}"),
            None => l += &format!(" (files older than {older})"),
        }
        if !pending.is_empty() {
            l += &format!("; checking {pending_names}…");
        }
        out.push(l);
    }
    for h in holders
        .iter()
        .filter(|h| !is(h, "counted") && !pending.iter().any(|p| std::ptr::eq(*p, *h)))
    {
        let when = |k: &str| age(&h[k]).map(|a| format!(" ({a})")).unwrap_or_default();
        let why = match h["state"].as_str().unwrap_or("") {
            "fetching" => format!(
                "fetching files from this device{}; it counts again once it passes a check",
                when("fetched_at")
            ),
            "failed" => format!(
                "{}{}",
                h["reason"].as_str().unwrap_or("failed a check"),
                when("last_fail")
            ),
            "stale" => {
                let mut w = format!("last checked {}", age(&h["last_pass"]).unwrap_or_default());
                if !is(h, "online") {
                    w += ", offline";
                }
                w
            }
            "unchecked" => "offline, not checked yet".to_owned(),
            _ => h["reason"].as_str().unwrap_or("").to_owned(),
        };
        out.push(format!("  {}: not counted — {why}", name(h)));
    }
    if counted.len() == 1 && pending.is_empty() {
        let only = counted[0];
        let others_expected = holders.len() > 1;
        out.push(if !is(only, "this") {
            format!(
                "Your files are only on {}. Keep a second copy: `cardinal retention full` here, \
                 or run `cardinal pair` on another device.",
                name(only)
            )
        } else if others_expected {
            "Your files are only on this device until another device passes its checks.".to_owned()
        } else if devices > 1 {
            "Your files are only on this device. Keep a copy on another device: run \
             `cardinal retention full` on one of your others, or `cardinal pair` on a new one."
                .to_owned()
        } else {
            "Your files are only on this device. Keep a copy on another device: run \
             `cardinal pair` on it."
                .to_owned()
        });
    }
    out
}

/// `0.4 ms` for a round trip.
fn rtt(ms: f64) -> String {
    if ms < 0.1 {
        format!("{ms:.2} ms")
    } else if ms < 10.0 {
        format!("{ms:.1} ms")
    } else {
        format!("{ms:.0} ms")
    }
}

/// `saint-joseph: receive 38.2 MB/s, send 36.9 MB/s, round trip 0.4 ms
/// (median 0.6 ms)` from a speed test result.
fn speed_line(v: &Value) -> String {
    let name = v["device"].as_str().unwrap_or("?");
    if let Some(e) = v["error"].as_str() {
        return e.to_owned();
    }
    format!(
        "{name}: receive {}/s, send {}/s, round trip {} (median {})",
        human_size(v["receive"].as_u64().unwrap_or(0)),
        human_size(v["send"].as_u64().unwrap_or(0)),
        rtt(v["rtt_min_ms"].as_f64().unwrap_or(0.0)),
        rtt(v["rtt_median_ms"].as_f64().unwrap_or(0.0)),
    )
}

async fn speedtest(paths: &Paths, device: Option<String>, raw: bool) -> anyhow::Result<()> {
    let named = device.is_some();
    let targets: Vec<(String, String)> = match device {
        Some(d) => vec![(d.clone(), d)],
        None => {
            let v = call(paths, json!({"cmd": "devices"})).await?;
            let all = v["devices"].as_array().cloned().unwrap_or_default();
            let t: Vec<(String, String)> = all
                .iter()
                .filter(|d| d["this"] != true && d["online"] == true)
                .map(|d| {
                    (
                        d["key"].as_str().unwrap_or("").to_owned(),
                        d["name"].as_str().unwrap_or("?").to_owned(),
                    )
                })
                .collect();
            if t.is_empty() {
                anyhow::bail!(
                    "none of your other devices is online; `cardinal devices` lists them"
                );
            }
            t
        }
    };
    let mut results = Vec::new();
    for (who, name) in targets {
        if !raw {
            eprintln!("Measuring the link to {name}...");
        }
        let r = call(paths, json!({"cmd": "speedtest", "device": who})).await;
        let v = match r {
            Ok(mut v) => {
                if let Some(o) = v.as_object_mut() {
                    o.remove("ok");
                }
                v
            }
            Err(e) if named => return Err(e),
            Err(e) => json!({"device": name, "error": format!("{e:#}")}),
        };
        if !raw {
            println!("{}", speed_line(&v));
        }
        results.push(v);
    }
    if raw {
        println!("{}", serde_json::to_string_pretty(&results)?);
    }
    Ok(())
}

async fn client(cmd: Cmd) -> anyhow::Result<()> {
    let paths = Paths::from_env();
    match cmd {
        Cmd::Init {
            name,
            yes,
            on_demand,
            mount,
        } => init(&paths, name, yes, on_demand, mount).await,
        Cmd::Status { json: raw } => {
            let v = call(&paths, json!({"cmd": "status"})).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                print_status(&v);
            }
            Ok(())
        }
        Cmd::Pair { code, at, admin } => pair(&paths, code, at, admin).await,
        Cmd::Devices => {
            let v = call(&paths, json!({"cmd": "devices"})).await?;
            print_devices(&v["devices"]);
            Ok(())
        }
        Cmd::Speedtest { device, json: raw } => speedtest(&paths, device, raw).await,
        Cmd::RemoveDevice { who } => {
            let v = call(&paths, json!({"cmd": "remove-device", "who": who})).await?;
            println!(
                "Removed \"{}\". It can no longer read or change your files; what it already \
                 wrote is kept.",
                v["name"].as_str().unwrap_or(&who)
            );
            Ok(())
        }
        Cmd::Peer { cmd } => match cmd {
            PeerCmd::Add { addr } => {
                call(&paths, json!({"cmd": "peer-add", "addr": addr})).await?;
                println!(
                    "Will look for your devices at {addr} too. `cardinal devices` shows when one \
                     is online."
                );
                Ok(())
            }
            PeerCmd::Remove { addr } => {
                call(&paths, json!({"cmd": "peer-remove", "addr": addr})).await?;
                println!("Forgot {addr}.");
                Ok(())
            }
            PeerCmd::List => {
                let v = call(&paths, json!({"cmd": "peer-list"})).await?;
                let list = v["peers"].as_array().cloned().unwrap_or_default();
                if list.is_empty() {
                    println!("No addresses. Add one with `cardinal peer add host:port`.");
                }
                for p in list {
                    println!(
                        "  {}  {}",
                        p["addr"].as_str().unwrap_or(""),
                        p["device"]
                            .as_str()
                            .map(|d| format!("({d})"))
                            .unwrap_or_else(|| "(not reached yet)".into())
                    );
                }
                Ok(())
            }
        },
        Cmd::Mount { path } => {
            let path = path.map(|p| {
                if p.is_absolute() {
                    p
                } else {
                    std::env::current_dir().unwrap_or_default().join(p)
                }
            });
            let v = call(&paths, json!({"cmd": "mount", "path": path})).await?;
            println!("Your files are in {}.", v["path"].as_str().unwrap_or(""));
            Ok(())
        }
        Cmd::Unmount => {
            call(&paths, json!({"cmd": "unmount"})).await?;
            println!(
                "Unmounted, and the daemon will not mount again (saved as `mount = \"\"` in \
                 config.toml). Your files still sync; `cardinal mount` shows them again."
            );
            Ok(())
        }
        Cmd::History { path } => {
            let m = mount_path(&paths).await;
            let p = space_path(&path, m.as_deref());
            let v = call(&paths, json!({"cmd": "history", "path": p})).await?;
            println!("Versions of {p} (oldest first):");
            for x in v["versions"].as_array().cloned().unwrap_or_default() {
                println!(
                    "  {:>3}  {}  {:<16} {:>10}{}",
                    x["version"],
                    human_time(x["time"].as_u64()),
                    x["device"].as_str().unwrap_or(""),
                    x["size"].as_u64().map(human_size).unwrap_or_default(),
                    if x["current"].as_bool() == Some(true) {
                        "  (current)"
                    } else {
                        ""
                    }
                );
            }
            println!("Bring one back with: cardinal restore {p} --version N");
            Ok(())
        }
        Cmd::Restore { path, version } => {
            let m = mount_path(&paths).await;
            let p = space_path(&path, m.as_deref());
            call(
                &paths,
                json!({"cmd": "restore", "path": p, "version": version}),
            )
            .await?;
            println!("Restored version {version} of {p}.");
            Ok(())
        }
        Cmd::Conflicts => {
            let v = call(&paths, json!({"cmd": "conflicts"})).await?;
            let list = v["conflicts"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("No file has two versions.");
                return Ok(());
            }
            for c in list {
                println!("{}", c["path"].as_str().unwrap_or(""));
                if c["delete_conflict"].as_bool() == Some(true) {
                    println!("  deleted on one device while changed on another; kept");
                }
                for x in c["versions"].as_array().cloned().unwrap_or_default() {
                    println!(
                        "  version from {} at {}",
                        x["device"].as_str().unwrap_or("?"),
                        human_time(x["time"].as_u64())
                    );
                }
                for copy in c["copies"].as_array().cloned().unwrap_or_default() {
                    println!("  other version shown as: {}", copy.as_str().unwrap_or(""));
                }
            }
            println!("Keep the version under the file's own name by deleting the other copies,");
            println!("or keep another by renaming its copy to the file's name.");
            Ok(())
        }
        Cmd::Pin { path } => {
            let m = mount_path(&paths).await;
            let p = space_path(&path, m.as_deref());
            let v = call(&paths, json!({"cmd": "pin", "path": p})).await?;
            if v["on_demand"].as_bool() == Some(true) {
                println!("{p} will be kept on this device.");
            } else {
                println!(
                    "Pinned {p}. This device keeps everything already; pins matter with \
                     `cardinal retention on-demand`."
                );
            }
            Ok(())
        }
        Cmd::Unpin { path } => {
            let m = mount_path(&paths).await;
            let p = space_path(&path, m.as_deref());
            call(&paths, json!({"cmd": "unpin", "path": p})).await?;
            println!("Unpinned {p}.");
            Ok(())
        }
        Cmd::Retention { mode } => {
            call(&paths, json!({"cmd": "retention", "mode": mode})).await?;
            println!("Retention is now {mode}.");
            Ok(())
        }
        Cmd::Log { follow } => {
            let mut c = std::process::Command::new("journalctl");
            c.args(["--user", "-u", "cardinal", "-n", "200", "--no-pager"]);
            if follow {
                c.arg("-f");
            }
            if !matches!(c.status(), Ok(s) if s.success()) {
                println!("The daemon logs to its standard error. As a service, see:");
                println!("  journalctl --user -u cardinal -f");
                println!("If you started it with `cardinal daemon`, the log is in that terminal.");
                println!("Set CARDINAL_LOG=debug for more detail.");
            }
            Ok(())
        }
        Cmd::Flush => {
            let v = call(&paths, json!({"cmd": "flush"})).await?;
            println!("Saved ({} entries).", v["entries"]);
            Ok(())
        }
        Cmd::Stop => {
            call(&paths, json!({"cmd": "stop"})).await?;
            println!("Stopping the daemon.");
            Ok(())
        }
        Cmd::Daemon { .. } | Cmd::Deploy(_) => unreachable!("handled in main"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_status_line() {
        let p = json!({"files_pending": 412, "bytes_pending": 1_800_000_000u64,
            "bytes_wanted": 2_000_000_000u64, "rate": 31_000_000});
        assert_eq!(
            fetch_line(&p),
            "fetching 412 files, 1.8 GB left of 2.0 GB, 31.0 MB/s"
        );
        let p = json!({"files_pending": 1, "bytes_pending": 500});
        assert_eq!(fetch_line(&p), "fetching 1 file, 500 B left");
    }

    fn holder(name: &str, this: bool, state: &str, last_pass: Option<u64>) -> Value {
        json!({"name": name, "this": this, "online": true, "counted": state == "passed",
            "state": state, "last_pass": last_pass, "reason": null})
    }

    #[test]
    fn copies_status_lines() {
        let now = 10_000_000u64;
        let c = |holders: Vec<Value>| {
            json!({"now": now, "blobs": 12, "eligible": 10, "older_than_ms": 3_600_000,
                "interval_ms": 600_000, "holders": holders})
        };
        // Alone.
        let alone = c(vec![holder("carbonite", true, "passed", Some(now - 1000))]);
        assert_eq!(
            copies_lines(&alone, 1),
            vec![
                "Copies: 1 — this device (files older than an hour)",
                "Your files are only on this device. Keep a copy on another device: run \
                 `cardinal pair` on it."
            ]
        );
        // Three, checked about the same time.
        let three = c(vec![
            holder("carbonite", true, "passed", Some(now - 1000)),
            holder("saint-joseph", false, "passed", Some(now - 240_000)),
            holder("nuc", false, "passed", Some(now - 200_000)),
        ]);
        assert_eq!(
            copies_lines(&three, 3),
            vec![
                "Copies: 3 — this device, saint-joseph, nuc (checked 4 minutes ago; files older \
                 than an hour)"
            ]
        );
        // One fetching, one offline for a day: per-device ages, and why.
        let mut fetching = holder("nuc", false, "fetching", Some(now - 3_000_000));
        fetching["fetched_at"] = json!(now - 120_000);
        let mixed = c(vec![
            holder("carbonite", true, "passed", Some(now - 1000)),
            holder("saint-joseph", false, "passed", Some(now - 60_000)),
            {
                let mut h = holder("laptop", false, "passed", Some(now - 7_200_000));
                h["online"] = json!(false);
                h
            },
            fetching,
        ]);
        assert_eq!(
            copies_lines(&mixed, 4),
            vec![
                "Copies: 3 — this device, saint-joseph (checked 1 minute ago), laptop (checked \
                 2 hours ago); files older than an hour",
                "  nuc: not counted — fetching files from this device (2 minutes ago); it \
                 counts again once it passes a check"
            ]
        );
        // Only this device, another catching up.
        let one = c(vec![
            holder("carbonite", true, "passed", Some(now - 1000)),
            fetching_holder(now),
        ]);
        let lines = copies_lines(&one, 2);
        assert_eq!(
            lines.last().unwrap(),
            "Your files are only on this device until another device passes its checks."
        );
        // Before the first check of another device.
        let mut start = c(vec![
            holder("carbonite", true, "passed", None),
            holder("nuc", false, "unchecked", None),
        ]);
        assert_eq!(
            copies_lines(&start, 2),
            vec!["Copies: 1 — this device (files older than an hour); checking nuc…"]
        );
        // On demand here, nothing old enough to check yet.
        start["holders"] = json!([holder("nuc", false, "unchecked", None)]);
        start["eligible"] = json!(0);
        assert_eq!(
            copies_lines(&start, 2),
            vec!["Copies: checking nuc… (nothing older than an hour yet)"]
        );
        // No content yet: nothing to say.
        assert!(copies_lines(&json!({"blobs": 0}), 1).is_empty());
        assert!(copies_lines(&Value::Null, 1).is_empty());
    }

    fn fetching_holder(now: u64) -> Value {
        let mut h = holder("nuc", false, "fetching", Some(now - 3_000_000));
        h["fetched_at"] = json!(now - 5_000);
        h
    }

    #[test]
    fn speedtest_line() {
        let v = json!({"device": "saint-joseph", "receive": 38_200_000u64,
            "send": 36_900_000u64, "rtt_min_ms": 0.42, "rtt_median_ms": 0.61});
        assert_eq!(
            speed_line(&v),
            "saint-joseph: receive 38.2 MB/s, send 36.9 MB/s, round trip 0.4 ms (median 0.6 ms)"
        );
        let e = json!({"device": "nuc", "error": "nuc runs an older version without speedtest"});
        assert_eq!(
            speed_line(&e),
            "nuc runs an older version without speedtest"
        );
        assert_eq!(
            (ago(500), ago(4 * 60_000), ago(3 * 86_400_000)),
            (
                "just now".into(),
                "4 minutes ago".into(),
                "3 days ago".into()
            )
        );
        assert_eq!(
            (span(3_600_000), span(2_000), span(7_200_000)),
            ("an hour".into(), "2 seconds".into(), "2 hours".into())
        );
    }

    #[test]
    fn source_status_line() {
        let f = serde_json::json!({"rate": 38_000_000u64, "latency_ms": 3,
            "replies": 412, "received": 1_100_000_000u64});
        assert_eq!(
            source_line(&f).unwrap(),
            "sent 1.1 GB to this device; now 38.0 MB/s, 3 ms"
        );
        assert_eq!(source_line(&serde_json::json!({"replies": 0})), None);
        assert_eq!(source_line(&Value::Null), None);
    }
}
