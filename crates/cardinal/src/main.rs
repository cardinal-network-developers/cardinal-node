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

mod overview;

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
    /// CARDINAL_HOME). Lets two devices run on one machine, each on its own
    /// port.
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    /// Show each request this command sends the daemon, and its reply, on
    /// standard error, in the text rendering with field names.
    #[arg(long, global = true)]
    trace: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up this device as your first device: creates who you are, shows
    /// your 24 recovery words, and creates your synced folder.
    Init {
        /// Your name: the one you suggest to the people you invite. Asked
        /// for if not given (with --yes, your login's name).
        #[arg(long)]
        name: Option<String>,
        /// This device's name, shown on your other devices (default: the
        /// machine's name).
        #[arg(long, value_name = "NAME")]
        device_name: Option<String>,
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
        /// Do not listen on UDP this time (for testing).
        #[arg(long, hide = true)]
        no_udp: bool,
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
    #[command(visible_alias = "add-device")]
    Pair {
        /// The code the new device shows (type it on an existing device).
        code: Option<String>,
        /// The new device's address, if it cannot be found on the local
        /// network (shown next to the code).
        #[arg(long, value_name = "IP:PORT")]
        at: Option<String>,
        /// Add the new device as an admin device (it can add and remove
        /// devices). Give it where you type the code: the new device is
        /// told, and agrees to exactly that.
        #[arg(long)]
        admin: bool,
        /// What to call the new device (default: its machine's name). Your
        /// own name stays as it is.
        #[arg(long, value_name = "NAME")]
        device_name: Option<String>,
    },
    /// The name you suggest for yourself to the people you invite, and to
    /// groups; with NAME, change it, on all your devices. Your devices'
    /// names are separate (`cardinal rename-device`).
    Me {
        /// Your new name.
        name: Option<String>,
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
    /// Rename one of your devices. Your other devices show the new name;
    /// the name you suggest for yourself (`cardinal me`) does not change.
    RenameDevice {
        /// The device's name or key, as `cardinal devices` shows.
        device: String,
        /// Its new name.
        name: String,
    },
    /// Remove a device you no longer use (it is cut off from your files).
    /// Removing an admin device, or removing from a device that is not an
    /// admin, asks for your recovery words.
    RemoveDevice {
        /// The device's name or key, as `cardinal devices` shows.
        who: String,
        /// It was lost or stolen: keep nothing of its that your other
        /// devices have not built on. Without this, its work is kept.
        #[arg(long)]
        lost: bool,
    },
    /// Make an invitation for someone else. Send it the way you would send
    /// a house key: whoever uses it becomes your contact.
    Invite {
        /// Where they can reach this device (ip:port); by default its
        /// address on the local network.
        #[arg(long)]
        address: Option<String>,
        /// The name to suggest they know you by, this once (default: yours,
        /// as `cardinal me` shows).
        #[arg(long)]
        name: Option<String>,
        /// Do not trust them with your devices' addresses: reach them only
        /// through a host.
        #[arg(long)]
        hosts_only: bool,
        /// Let nothing reach you through them, though you still see what
        /// they write.
        #[arg(long)]
        no_introductions: bool,
    },
    /// Use an invitation someone gave you.
    Accept {
        /// The invitation, starting `cardinal:`.
        code: String,
        /// What to call them; by default the name they suggested.
        #[arg(long)]
        name: Option<String>,
        /// Do not trust them with your devices' addresses: reach them only
        /// through a host.
        #[arg(long)]
        hosts_only: bool,
        /// Let nothing reach you through them, though you still see what
        /// they write.
        #[arg(long)]
        no_introductions: bool,
        /// For a recovery invitation made for whomever you name: whom it
        /// is for, of those you guard.
        #[arg(long = "for")]
        for_whom: Option<String>,
    },
    /// The people you are connected to. With a name: how your devices reach
    /// theirs, what each address did, and what you tell them
    Contacts {
        /// One contact to show in detail, as the list names them.
        who: Option<String>,
        /// Show those you have refused too.
        #[arg(long)]
        all: bool,
        /// With a name: look for them now (up to 12 s), then show.
        #[arg(long)]
        look: bool,
        /// With a name: try each of their devices at this address
        /// (ip:port) first, for when neither of you names anything the
        /// other can use.
        #[arg(long, value_name = "ADDRESS")]
        at: Option<String>,
        /// With a name: print it as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Change how you regard a contact. It stays on your own devices, and
    /// they are told nothing.
    Contact {
        /// Who, as `cardinal contacts` shows.
        who: String,
        /// `trust` connects your devices directly if they trust you too.
        /// `hosts-only` stops that. `no-introductions` lets nothing reach
        /// you through them. `refuse` ends everything with them and hides
        /// them. `name` changes what you call them ("" goes back to the name
        /// they suggest), `picture` the picture you see for them (a file in
        /// your Cardinal folder or on this computer; "" clears it), and
        /// `category` the folder they are listed in (People unless you say).
        /// `name-hosts` lets them have where your hosts are, so their
        /// devices can find yours; `no-hosts` takes that back, and your
        /// hosts stay out until you say `name-hosts` again; `no-host
        /// DEVICE` takes out one host of yours, which stays out likewise.
        #[arg(value_parser = ["trust", "hosts-only", "introductions", "no-introductions", "refuse", "unrefuse", "name", "picture", "category", "name-hosts", "no-hosts", "no-host"])]
        setting: String,
        /// The new name, after `name`; the picture, after `picture`; the
        /// category, after `category`; or the host, after `no-host`.
        new_name: Option<String>,
    },
    /// What is in a folder of your Cardinal folder: your files, and beside
    /// them a folder for each person you know, shared with them.
    Files {
        /// The folder, such as `People/Ana` (the top if left out).
        path: Option<String>,
    },
    /// Put files of your Cardinal folder in the folder you share with
    /// someone. With --message they go in a message too; without, the
    /// conversation shows nothing.
    Share {
        /// Who, as `cardinal contacts` shows.
        who: String,
        /// What, as `cardinal files` shows it, such as `Photos/beach.jpg`.
        #[arg(required = true)]
        paths: Vec<String>,
        /// A message to send them with it.
        #[arg(long)]
        message: Option<String>,
    },
    /// Copy a file or folder from this computer into your Cardinal folder.
    Put {
        /// The file or folder on this computer.
        from: PathBuf,
        /// The folder it goes in, such as `People/Ana` (the top if left out).
        to: Option<String>,
    },
    /// Copy a file of your Cardinal folder onto this computer.
    Get {
        /// The file, as `cardinal files` shows it.
        path: String,
        /// Where it goes on this computer.
        to: PathBuf,
    },
    /// The invitations you made, and whether each can still be used. `cancel ID`
    /// ends one on all your devices. An invitation lasts 30 days.
    Invitations {
        /// `cancel` ends the invitation given next.
        #[arg(value_parser = ["cancel"])]
        action: Option<String>,
        /// The invitation, as `cardinal invitations` shows it.
        id: Option<String>,
    },
    /// Send a message to a contact.
    Say {
        /// Who, as `cardinal contacts` shows.
        who: String,
        /// What to say.
        text: String,
        /// A file to send with it; give it again for more.
        #[arg(long)]
        attach: Vec<PathBuf>,
    },
    /// Save a file someone sent you, as `cardinal messages` shows it.
    Save {
        /// Who, as `cardinal contacts` shows.
        who: String,
        /// The message, as `cardinal messages` shows it.
        message: String,
        /// Which of its files, from 1.
        n: usize,
        /// Where to save it.
        to: PathBuf,
    },
    /// Your conversation with a contact; with nobody named, all of them:
    /// what is new, newest first.
    Messages {
        /// Who, as `cardinal contacts` shows. Without it: every conversation,
        /// newest first, with what is new.
        who: Option<String>,
    },
    /// The groups you are in, and those offered to you.
    Groups,
    /// Introduce one contact to another.
    Introduce {
        /// Who to introduce, as `cardinal contacts` shows.
        who: String,
        /// To whom.
        to: String,
        /// Something to say to them.
        #[arg(long)]
        note: Option<String>,
    },
    /// Introductions waiting for you, or say yes or no to one.
    Introductions {
        /// `yes` or `no`.
        answer: Option<String>,
        /// The introduction, as listed.
        id: Option<String>,
    },
    /// Make, join, talk in, or change a group.
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Answer what a program asks of you: to see or change an
    /// application's spaces, to start one, or whom to share one with. With
    /// nothing, lists what is waiting; with its number, says yes, or no
    /// with --no.
    Approve {
        id: Option<u64>,
        /// Say no.
        #[arg(long)]
        no: bool,
        /// Whom to share with, by what you call them.
        #[arg(long = "with", num_args = 1..)]
        with: Vec<String>,
        /// What those you share with may do: reader or writer.
        #[arg(long)]
        role: Option<String>,
    },
    /// Programs and the applications they may use: approvals on all your
    /// devices, and spaces of applications offered to you.
    Apps {
        #[command(subcommand)]
        cmd: AppsCmd,
    },
    /// A clipboard shared by your own devices: copy on one, paste on
    /// another, for ten minutes. Nobody else is sent it, and it is not kept.
    Clip {
        #[command(subcommand)]
        cmd: ClipCmd,
    },
    /// Whether your devices ask the router for a port (PCP, NAT-PMP or
    /// UPnP), and name themselves where your trusted contacts can find
    /// them at the address it gives. They do so only on networks you said
    /// are yours (`cardinal network`). `off` turns it off on every device
    /// of yours; with `--this-device`, on this one alone. With nothing,
    /// says what this device does now.
    Router {
        #[arg(value_parser = ["on", "off"])]
        setting: Option<String>,
        /// Only this device.
        #[arg(long)]
        this_device: bool,
    },
    /// Bluetooth on this device, so that people in range find each other
    /// with no network at all: your own devices, your trusted contacts, and
    /// whoever holds an invitation you made. `off` (the default), `open`
    /// (while a Cardinal window is open) or `always` (while it is closed
    /// too). With nothing, says where it stands.
    Bluetooth {
        #[arg(value_parser = ["off", "open", "always"])]
        setting: Option<String>,
    },
    /// Which network this device is on, known by its router, and whether
    /// it is yours. Only on your own networks do your devices ask the
    /// router for a port and name themselves at the address it gives: a
    /// router at someone else's house is left alone. Your answer holds on
    /// all your devices.
    Network {
        /// `mine` or `not-mine`.
        #[arg(value_parser = ["mine", "not-mine"])]
        setting: Option<String>,
        /// What to call it, such as its Wi-Fi name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Make this device a host for your own devices: it keeps a full copy
    /// of your files, and can bring them back if every other device is lost.
    Host {
        /// Where your devices can reach this one (host:port, the port this
        /// device listens on). Needed to become a host. Give it more than
        /// once for more than one address.
        #[arg(long = "address")]
        addresses: Vec<String>,
        /// Stop being a host.
        #[arg(long)]
        off: bool,
    },
    /// Your 24 recovery words.
    Recovery {
        #[command(subcommand)]
        cmd: RecoveryCmd,
    },
    /// Your guardians: people you trust who, together, can give your
    /// identity back to you if you lose every device and your words.
    Guardians {
        #[command(subcommand)]
        cmd: Option<GuardiansCmd>,
    },
    /// What a removed device of yours wrote that your other devices had
    /// not built on before it was removed, as after a recovery that kept
    /// none of your old devices: listed, and with --up-to, kept. Keep only
    /// what you recognize: a thief's changes with a stolen device are
    /// among them.
    KeepWork {
        /// The device, by the name it had.
        name: String,
        /// Keep what it wrote up to this time, as listed (milliseconds), or
        /// "all".
        #[arg(long)]
        up_to: Option<String>,
    },
    /// The people you guard, and any recovery of theirs under way.
    Guarding {
        #[command(subcommand)]
        cmd: Option<GuardingCmd>,
    },
    /// Lost every device and your words: get your identity back on this
    /// new device through your guardians.
    Recover {
        #[command(subcommand)]
        cmd: Option<RecoverCmd>,
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
    /// Free the space this device uses for deleted files and old versions
    /// now, instead of when they are older than `keep-old` allows. They
    /// can then be restored only from your other devices.
    FreeSpace {
        /// Do not ask to confirm.
        #[arg(long)]
        yes: bool,
        /// Instead, count what this device stores that nothing it holds
        /// names: what a space it no longer holds left behind, or a save
        /// that never finished.
        #[arg(long)]
        unnamed: bool,
        /// With `--unnamed`: delete what it counted.
        #[arg(long, requires = "unnamed")]
        delete: bool,
    },
    /// Remove everything Cardinal keeps on this device, to start again in
    /// the same place: this device's keys, who you are on it, your spaces
    /// and their content. Your settings stay, and so do the files kept on
    /// this device only. The daemon must be stopped first.
    Clear {
        /// Say what is there and what would go, and remove nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask to type `clear`.
        #[arg(long)]
        yes: bool,
        /// Also remove the files kept on this device only
        /// (`.cardinalignore`). They are your own files and exist nowhere
        /// else.
        #[arg(long)]
        including_local: bool,
    },
    /// How long this device keeps deleted files and old versions so you
    /// can restore them: a number of days (30 unless set), or `forever`.
    KeepOld {
        /// Days, or `forever`.
        keep: String,
        /// For this space alone (its id, as `space-usage` gives it), in
        /// place of the device's period.
        #[arg(long)]
        space: Option<String>,
    },
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
    /// Show what a client and the daemon say to each other: listens at
    /// PATH, passes every message on to the daemon and back, and prints each
    /// in the text rendering with field names. Point a client's
    /// CARDINAL_SOCKET at PATH.
    ApiTrace {
        /// Where to listen (a socket path; on Windows a pipe name).
        #[arg(long, value_name = "PATH")]
        listen: PathBuf,
    },
    /// Let a program you choose look at everything this device holds, keys
    /// aside, for designing Cardinal's data structures: `on` prints a token
    /// to give it, `off` ends it at once.
    Inspect {
        #[command(subcommand)]
        cmd: InspectCmd,
    },
    /// Stop the daemon.
    Stop,
    /// Say which Cardinal data is on this device, and change nothing: the
    /// record `cardinald --store` writes, for a window to read when the
    /// daemon does not answer, or to a terminal its text rendering.
    #[command(hide = true)]
    Store,
    #[command(flatten)]
    Deploy(cardinal_update::DeployCommand),
}

#[derive(Subcommand)]
enum InspectCmd {
    /// Turn inspection on, and print the token a program needs for it.
    On {
        /// For how long, in minutes (at most a day).
        #[arg(long, default_value_t = 60)]
        minutes: u64,
        /// Do not ask first.
        #[arg(long)]
        yes: bool,
        /// Print the token alone, for a script.
        #[arg(long)]
        quiet: bool,
    },
    /// Turn inspection off: the token stops working.
    Off,
    /// Say whether inspection is on.
    Status,
}

#[derive(Subcommand)]
enum ClipCmd {
    /// Copy text to your other devices: the text given, or what comes on
    /// standard input (`some-command | cardinal clip copy`).
    Copy { text: Option<String> },
    /// Print what was last copied on any of your devices.
    Paste,
}

#[derive(Subcommand)]
enum AppsCmd {
    /// Every approval of yours, on every device.
    Approvals,
    /// Take an approval back, by the start of its id.
    Revoke { id: String },
    /// Spaces of applications offered to you, such as a calendar.
    Offers,
    /// Take a space offered to you, by its id or name.
    Join { space: String },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Make a group with contacts, each of whom is offered it.
    Create {
        /// What to call it.
        name: String,
        /// Who to offer it to, as `cardinal contacts` shows them.
        people: Vec<String>,
    },
    /// Join a group offered to you.
    Join {
        /// The group, by name or id.
        group: String,
        /// Let its members have where your host is. Asked for only when
        /// someone in the group is not a contact of yours.
        #[arg(long, conflicts_with = "keep_host")]
        share_host: bool,
        /// Do not: they reach you only through someone in touch with both.
        #[arg(long)]
        keep_host: bool,
    },
    /// Whether a group's members have where your host is: `share` or `keep`.
    /// `keep` stays until you say `share` again.
    Reach {
        /// The group, by name or id.
        group: String,
        /// `share` or `keep`.
        setting: String,
        /// With `keep`: only this host of yours, by device name.
        #[arg(long, value_name = "DEVICE")]
        host: Option<String>,
    },
    /// Say no to a group offered to you.
    Decline {
        /// The group, by name or id.
        group: String,
    },
    /// Leave a group.
    Leave {
        /// The group, by name or id.
        group: String,
    },
    /// Add contacts to a group you are an admin of.
    Add {
        /// The group, by name or id.
        group: String,
        /// Who, as `cardinal contacts` shows them.
        people: Vec<String>,
        /// The name the others see, for one person: yours for them if not given.
        #[arg(long = "as")]
        shown: Option<String>,
    },
    /// Take someone out of a group you own: the group is replaced by one
    /// that leaves them out, and everyone else's devices move to it.
    Remove {
        /// The group, by name or id.
        group: String,
        /// Who, as the group's members show them.
        who: String,
    },
    /// Give someone in a group a role: reader, member or admin. A higher
    /// one is given by an admin; a lower one replaces the group with one
    /// that names them with it, and only its owner does that.
    Role {
        /// The group, by name or id.
        group: String,
        /// Who, as the group's members show them.
        who: String,
        /// reader, member or admin.
        role: String,
    },
    /// Post in a group what you wrote before it moved on and was held
    /// back, because someone is there now it was written without.
    PostAgain {
        /// The group, by name or id.
        group: String,
    },
    /// Who is in a group.
    Members {
        /// The group, by name or id.
        group: String,
    },
    /// Send a message to a group.
    Say {
        /// The group, by name or id.
        group: String,
        /// What to say.
        text: String,
    },
    /// A group's conversation.
    Messages {
        /// The group, by name or id.
        group: String,
    },
    /// Rename a group you are an admin of.
    Rename {
        /// The group, by name or id.
        group: String,
        /// Its new name.
        name: String,
    },
    /// Whether a group you are an admin of introduces its members: on or off.
    Introductions {
        /// The group, by name or id.
        group: String,
        /// `on` or `off`.
        setting: String,
    },
    /// How the others see a member of a group you are an admin of.
    Member {
        /// The group, by name or id.
        group: String,
        /// Who, as the group's members show them.
        who: String,
        /// The name the others see.
        #[arg(long = "as")]
        shown: Option<String>,
        /// Not introduced through the group.
        #[arg(long)]
        no_introductions: bool,
        /// Introduced through the group again.
        #[arg(long, conflicts_with = "no_introductions")]
        introductions: bool,
    },
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Check the words you wrote down: type them, and this says whether
    /// they are yours. Nothing is changed or kept.
    Check,
    /// Show what to add to your recovery sheet: where your always-on device
    /// is, and its key.
    Sheet,
    /// Lost every device: bring everything back on this one, with your 24
    /// words and the address and key on your recovery sheet.
    Restore {
        /// The always-on device's address (host:port).
        #[arg(long)]
        host: String,
        /// Its key.
        #[arg(long)]
        key: String,
    },
}

#[derive(Subcommand)]
enum GuardiansCmd {
    /// Ask a contact you trust to be your guardian. Their device shows it,
    /// and they answer with `cardinal guarding accept YOUR-NAME`.
    Ask {
        /// Whom.
        who: String,
    },
    /// Name your guardians, from the people you trust. Your first
    /// guardians are named with your recovery words.
    Set {
        /// Who, as `cardinal contacts` shows them.
        #[arg(required = true)]
        names: Vec<String>,
        /// How many of them must agree: more than half (the default is the
        /// smallest majority).
        #[arg(long)]
        threshold: Option<u64>,
        /// How long they wait before a recovery takes effect, so that you
        /// can object: 7d (the default), 12h, 30m, or seconds.
        #[arg(long)]
        delay: Option<String>,
    },
    /// Object to a recovery of your identity under way that is not yours:
    /// your guardians then wait twice as long.
    Object {
        /// Its fingerprint, five words, if more than one is under way.
        fingerprint: Vec<String>,
    },
}

#[derive(Subcommand)]
enum GuardingCmd {
    /// After the wait, and checking with them: confirm the change of
    /// guardians that someone you guard asked for.
    ConfirmChange {
        /// Whom.
        who: String,
        /// The change's fingerprint they read you: five words. Needed when
        /// more than one is under way.
        fingerprint: Vec<String>,
        /// Do not ask again: you have read the warning.
        #[arg(long)]
        yes: bool,
    },
    /// Accept being someone's guardian, when they ask: your device makes a
    /// persona for guarding them alone, which they then name.
    Accept {
        /// Whom.
        who: String,
    },
    /// An invitation for the new device of someone you guard, who lost
    /// every device: they use it there (`cardinal recover start CODE`),
    /// and their device meets yours for the recovery alone.
    Invite {
        /// Whom it is for.
        who: String,
        /// Where their device can reach yours (host:port), if not your
        /// host or this network.
        #[arg(long = "address")]
        address: Option<String>,
    },
    /// Say that someone you guard really is asking for their identity
    /// back, after checking with them the fingerprint their new device
    /// shows.
    Endorse {
        /// Whom.
        who: String,
        /// The fingerprint they read you from their new device: five words.
        #[arg(num_args = 1.., required = true)]
        fingerprint: Vec<String>,
        /// Do not ask again: you have read the warning.
        #[arg(long)]
        yes: bool,
    },
    /// After the wait, and checking the fingerprint with them again: give
    /// their identity back to their new device.
    Confirm {
        /// Whom.
        who: String,
        /// The fingerprint they read you from their new device: five words.
        #[arg(num_args = 1.., required = true)]
        fingerprint: Vec<String>,
        /// Do not ask again: you have read the warning.
        #[arg(long)]
        yes: bool,
    },
    /// Never endorse or confirm this recovery, on any of your devices: the
    /// person started over, because the new device was lost, or it is not
    /// theirs.
    Never {
        /// Whom.
        who: String,
        /// The fingerprint of the recovery: five words.
        #[arg(num_args = 1.., required = true)]
        fingerprint: Vec<String>,
    },
}

#[derive(Subcommand)]
enum RecoverCmd {
    /// Start getting your identity back on this device, and with a
    /// guardian's invitation meet that guardian. Bring each guardian's
    /// invitation the same way, and read each of them the fingerprint
    /// shown.
    Start {
        /// The invitation from `cardinal guarding invite` on the guardian's
        /// device.
        code: Option<String>,
        /// Whom you recover (the id a guardian's device shows), to make an
        /// invitation for a guardian before using any of theirs.
        #[arg(long)]
        identity: Option<String>,
    },
    /// An invitation for a guardian who is with you to take up on their
    /// device (`cardinal accept CODE`).
    Invite {
        /// Where their device can reach this one (host:port), if not this
        /// network.
        #[arg(long)]
        address: Option<String>,
    },
    /// Give up the recovery under way on this device. Tell each guardian
    /// not to confirm it (`cardinal guarding never`).
    Cancel,
    /// Once your guardians have confirmed: become your identity's device,
    /// from what your guardians hold. The recovery keeps none of your old
    /// devices; pair them again afterwards.
    Finish {
        /// Go on without your account, if no guardian holds it: you start
        /// with an empty one, for good.
        #[arg(long)]
        without_account: bool,
        /// When you lost your devices (milliseconds since the epoch, by
        /// their own clocks): what they wrote up to then is kept.
        #[arg(long)]
        lost_at: Option<u64>,
    },
}

/// A delay as typed: 7d, 12h, 30m, 45s, or seconds.
fn parse_delay(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (n, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c.to_ascii_lowercase()),
        _ => (s, 's'),
    };
    let n: u64 = n
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("{s} is not a delay; it looks like 7d, 12h or 30m"))?;
    let per = match unit {
        'd' => 86_400,
        'h' => 3600,
        'm' => 60,
        's' => 1,
        _ => anyhow::bail!("{s} is not a delay; it looks like 7d, 12h or 30m"),
    };
    Ok(n * per)
}

/// Prints new recovery words, as `cardinal init` does.
fn show_words(words: &str) {
    let list: Vec<&str> = words.split(' ').collect();
    for row in 0..8 {
        let mut line = String::from("   ");
        for col in 0..3 {
            let i = row + col * 8;
            line.push_str(&format!("{:>2}. {:<12}", i + 1, list.get(i).unwrap_or(&"")));
        }
        println!("{line}");
    }
}

fn print_guardians(v: &Value) {
    let n = v["guardians"].as_u64().unwrap_or(0);
    if n == 0 {
        println!("You have no guardians. If you lose every device and your words, nobody can");
        println!("give your identity back. Name some: cardinal guardians set NAME... ");
    } else {
        let names: Vec<&str> = v["names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        println!(
            "{} of your {n} guardians can give your identity back, after {}.",
            v["threshold"],
            v["delay_text"].as_str().unwrap_or("")
        );
        if !names.is_empty() {
            println!("Guardians: {}", names.join(", "));
        }
    }
    let list = |k: &str| -> Vec<String> {
        v[k].as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect()
    };
    if !list("asked").is_empty() {
        println!("Asked to be your guardian: {}.", list("asked").join(", "));
    }
    if !list("ready").is_empty() {
        println!(
            "Ready to be named (`cardinal guardians set`): {}.",
            list("ready").join(", ")
        );
    }
    for n in v["copy_full"].as_array().into_iter().flatten() {
        println!(
            "{} holds as much of your account as a guardian takes: their copy no longer updates.",
            n.as_str().unwrap_or("")
        );
    }
    for c in v["changes"].as_array().into_iter().flatten() {
        let fp = c["fingerprint"].as_str().unwrap_or("");
        println!(
            "A change of your guardians is under way (fingerprint \"{fp}\"): {} of them, \
             recovering after {}; {} confirmed{}. If it is not yours, or you gave it up, run \
             `cardinal guardians object {fp}`.",
            c["guardians"],
            c["delay_text"].as_str().unwrap_or(""),
            c["confirmed"],
            if c["objected"] == true {
                "; you objected"
            } else {
                ""
            }
        );
    }
    for r in v["recoveries"].as_array().into_iter().flatten() {
        let fp = r["fingerprint"].as_str().unwrap_or("");
        if r["in_effect"] == true {
            println!("Recovered to the device with fingerprint \"{fp}\".");
        } else {
            println!(
                "WARNING: someone asked your guardians to recover your identity (fingerprint \"{fp}\"): \
                 {} endorsed, {} confirmed{}. If it is not you, tell your guardians, and run \
                 `cardinal guardians object`.",
                r["endorsed"],
                r["confirmed"],
                if r["objected"] == true {
                    "; you objected"
                } else {
                    ""
                }
            );
        }
    }
}

/// The devices a recovery removed, to pair again.
fn print_pair_again(v: &Value) {
    let again = v["pair_again"].as_array().cloned().unwrap_or_default();
    if again.is_empty() {
        return;
    }
    println!("Pair your other devices again (`cardinal pair`): the recovery kept none of");
    println!("them, hosts included. Forget any that was lost:");
    for k in again {
        let key = k["key"].as_str().unwrap_or("");
        match k["name"].as_str() {
            Some(name) => println!("  {name}  [{key}]"),
            None => println!("  [{key}]"),
        }
    }
}

fn print_recover(v: &Value) {
    if v["finished"] == true {
        println!("Recovered. This device became yours before the recovery could finish tidying");
        println!("up. Your new recovery words, shown this once: write them down, in order, and");
        println!("keep them safe. The old ones no longer work.");
        println!();
        show_words(v["words"].as_str().unwrap_or(""));
        println!();
        print_pair_again(v);
        return;
    }
    if v["under_way"] != true {
        println!("No recovery is under way. Ask a guardian for an invitation (`cardinal guarding invite`).");
        print_pair_again(v);
        return;
    }
    println!(
        "Recovering. Read each guardian this fingerprint: {}",
        v["fingerprint"].as_str().unwrap_or("")
    );
    let lost = v["lost_devices"].as_array().map_or(0, Vec::len);
    if lost > 0 {
        println!("The recovery removes your {lost} other device(s); you pair them again after.");
    }
    let met = v["guardians"].as_u64().unwrap_or(0);
    if met == 0 {
        println!("No guardian is in touch yet: use a guardian's invitation (`cardinal recover start CODE`).");
    } else if v["asked"] != true {
        println!("{met} guardian(s) in touch; waiting for one to propose the recovery.");
    } else if v["in_effect"] == true {
        println!("Your guardians have confirmed. Run `cardinal recover finish`.");
        if v["held"].as_u64().unwrap_or(0) > 0 {
            println!("They gave back what they hold of yours, your account among it.");
        }
    } else {
        println!(
            "{met} guardian(s) in touch: {} endorsed, {} confirmed, of {} needed.",
            v["endorsed"], v["confirmed"], v["threshold"]
        );
    }
    print_pair_again(v);
}

fn print_guarding(v: &Value) {
    let people = v["guarding"].as_array().cloned().unwrap_or_default();
    for a in v["asked"].as_array().into_iter().flatten() {
        let n = a.as_str().unwrap_or("");
        println!("{n} asked you to be their guardian: `cardinal guarding accept {n}`.");
    }
    for a in v["named_in_change"].as_array().into_iter().flatten() {
        println!(
            "{} named you in a change of guardians, waiting for their guardians to confirm it.",
            a.as_str().unwrap_or("")
        );
    }
    for a in v["accepted"].as_array().into_iter().flatten() {
        println!(
            "You accepted guarding {}; they have not named you yet.",
            a.as_str().unwrap_or("")
        );
    }
    for a in v["no_longer_needed"].as_array().into_iter().flatten() {
        println!("{}.", a["text"].as_str().unwrap_or(""));
    }
    if people.is_empty() {
        println!("You guard nobody.");
        return;
    }
    let now = v["now_ms"].as_u64().unwrap_or(0);
    for p in people {
        println!(
            "{}: one of {} guardians, {} of whom must agree, after {}.",
            p["name"].as_str().unwrap_or(""),
            p["guardians"],
            p["threshold"],
            p["delay_text"].as_str().unwrap_or("")
        );
        for r in p["recoveries"].as_array().into_iter().flatten() {
            let fp = r["fingerprint"].as_str().unwrap_or("");
            let state = if r["in_effect"] == true {
                "done".to_owned()
            } else if r["confirmed_by_me"] == true {
                format!("you confirmed; {} have", r["confirmed"])
            } else if r["pending"] == true {
                match r["confirm_from_ms"].as_u64() {
                    Some(t) if t > now => {
                        format!("pending: you can confirm in {} s", (t - now).div_ceil(1000))
                    }
                    _ => "pending: you can confirm now, after checking with them again".to_owned(),
                }
            } else if r["endorsed_by_me"] == true {
                format!("you endorsed; {} have", r["endorsed"])
            } else {
                format!(
                    "asked for; {} endorsed. Check with them before you endorse",
                    r["endorsed"]
                )
            };
            println!("  recovery \"{fp}\": {state}");
        }
        for ch in p["changes"].as_array().into_iter().flatten() {
            let state = if ch["in_effect"] == true {
                "in effect".to_owned()
            } else if ch["confirmed_by_me"] == true {
                format!("you confirmed; {} have", ch["confirmed"])
            } else {
                match ch["confirm_from_ms"].as_u64() {
                    Some(t) if t > now => {
                        format!("you can confirm in {} s", (t - now).div_ceil(1000))
                    }
                    _ => "you can confirm now, after checking with them".to_owned(),
                }
            };
            println!(
                "  change of guardians \"{}\" ({} of {}, after {}): {state}",
                ch["fingerprint"].as_str().unwrap_or(""),
                ch["threshold"],
                ch["guardians"],
                ch["delay_text"].as_str().unwrap_or("")
            );
        }
        if p["account_copy"] == true {
            println!("  You hold a sealed copy of their account, which you cannot read.");
        }
        if let Some(w) = p["warning"].as_str() {
            println!("  WARNING: {w}");
        }
        for fp in p["never"].as_array().into_iter().flatten() {
            println!(
                "  recovery \"{}\": you said never to confirm it",
                fp.as_str().unwrap_or("")
            );
        }
    }
}

/// The fingerprint as typed, its words joined.
fn typed_fingerprint(words: &[String]) -> String {
    words.join(" ")
}

/// Shows a guardian the warning before they endorse or confirm, and asks
/// them to go on, unless they said so already.
async fn cautioned(paths: &Paths, who: &str, yes: bool) -> anyhow::Result<()> {
    let v = call(paths, json!({"cmd": "guarding-caution", "who": who})).await?;
    println!("{}", v["caution"].as_str().unwrap_or(""));
    if yes {
        return Ok(());
    }
    let said = prompt("Go on? Type yes: ")?;
    anyhow::ensure!(said.eq_ignore_ascii_case("yes"), "nothing was done");
    Ok(())
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
    control::trace(cli.trace);
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
            no_udp,
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
                    no_udp,
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
    let v = request(paths, &req).await?;
    if v["ok"].as_bool() == Some(true) {
        Ok(v)
    } else {
        anyhow::bail!("{}", v["error"].as_str().unwrap_or("the daemon failed"))
    }
}

/// The daemon's reply, whether it succeeded or not.
async fn request(paths: &Paths, req: &Value) -> anyhow::Result<Value> {
    let reply = control::request(&paths.socket, req).await;
    if reply.is_err() {
        // A daemon refuses to start on a store this version cannot read:
        // say that, and not only that none is running.
        cardinald::format::check(paths)?;
        // One that holds the data and does not answer is not "not
        // running": it has not bound its socket yet, or listens elsewhere.
        if held(paths)? {
            return Err(starting(paths));
        }
    }
    reply.map_err(|_| {
        anyhow::anyhow!(
            "the cardinal daemon is not running. Start it with `cardinal daemon` (or \
             `systemctl --user start cardinal` if you installed it with `cardinal install`)."
        )
    })
}

/// Calls the daemon; when this device lacks the power for the action,
/// says why, asks for the recovery words, and calls again with them.
async fn call_with_words(paths: &Paths, mut req: Value) -> anyhow::Result<Value> {
    let v = request(paths, &req).await?;
    if v["ok"].as_bool() == Some(true) {
        return Ok(v);
    }
    let why = v["error"].as_str().unwrap_or("the daemon failed");
    if v["needs_words"].as_bool() != Some(true) {
        anyhow::bail!("{why}");
    }
    println!("{}.", capitalized(why));
    let words = ask_words(paths, "Your recovery words can approve it instead.").await?;
    req["words"] = json!(words.as_str());
    call(paths, req).await
}

fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// Asks for the 24 recovery words (typed whole, or their first four
/// letters), until they are valid and this identity's, three times at
/// most. They are used once and not kept.
async fn ask_words(
    paths: &Paths,
    intro: &str,
) -> anyhow::Result<cardinal_crypto::Zeroizing<String>> {
    read_words(Some(paths), intro).await
}

/// Reads the 24 words: checked against this device's identity if `paths`
/// are given, or else only for being recovery words at all.
async fn read_words(
    paths: Option<&Paths>,
    intro: &str,
) -> anyhow::Result<cardinal_crypto::Zeroizing<String>> {
    println!("{intro}");
    println!("Type them in order, separated by spaces; the first four letters of each");
    println!("are enough. Press Enter after each line.");
    for attempt in 0..3 {
        let mut typed: Vec<String> = Vec::new();
        while typed.len() < 24 {
            print!("words {}-24: ", typed.len() + 1);
            std::io::stdout().flush()?;
            let mut line = cardinal_crypto::Zeroizing::new(String::new());
            if std::io::stdin().lock().read_line(&mut line)? == 0 {
                anyhow::bail!("stopped before all 24 words were typed");
            }
            typed.extend(line.split_whitespace().map(str::to_owned));
        }
        let mut words = cardinal_crypto::Zeroizing::new(String::new());
        let mut bad = None;
        for (i, w) in typed.iter().enumerate() {
            match cardinal_crypto::bip39::complete_word(w) {
                Some(full) => {
                    if i > 0 {
                        words.push(' ');
                    }
                    words.push_str(full);
                }
                None => bad = bad.or(Some(i)),
            }
        }
        typed.iter_mut().for_each(cardinal_crypto::Zeroize::zeroize);
        let problem = match bad {
            Some(i) => format!("word {} is not a recovery word; check its spelling", i + 1),
            None => match paths {
                Some(paths) => match request(
                    paths,
                    &json!({"cmd": "recovery-check", "words": words.as_str()}),
                )
                .await?
                {
                    v if v["ok"].as_bool() == Some(true) => return Ok(words),
                    v => v["error"]
                        .as_str()
                        .unwrap_or("the words were not accepted")
                        .to_owned(),
                },
                None => match cardinal_crypto::RecoveryPhrase::parse(&words) {
                    Ok(_) => return Ok(words),
                    Err(_) => "the words do not fit together: one is wrong or out of place".into(),
                },
            },
        };
        println!("{}.", capitalized(&problem));
        if attempt < 2 {
            println!("Try again from the first word.");
        }
    }
    anyhow::bail!("the recovery words were not accepted; nothing was changed")
}

/// What belongs on the recovery sheet.
/// Where Bluetooth stands on this device.
fn print_bluetooth(b: &Value) {
    let mode = b["mode"].as_str().unwrap_or("off");
    let when = match mode {
        "open" => "on while a window is open",
        "always" => "on, open or closed",
        _ => "off",
    };
    let now = if b["on"] == json!(true) {
        let psm = b["psm"]
            .as_u64()
            .map(|p| format!(", PSM {p}"))
            .unwrap_or_default();
        format!("on now{psm}")
    } else {
        "not on now".to_owned()
    };
    println!("Bluetooth: {when} (`cardinal bluetooth off|open|always`); {now}.");
    if b["too_old"] == json!(true) {
        println!(
            "  This device's Bluetooth is too old for Cardinal to find people nearby. Wi-Fi and \
             the internet still work."
        );
        return;
    }
    match (&b["available"], b["why_not"].as_str()) {
        (Value::Bool(true), _) => {
            let radio = b["radio"].as_str().unwrap_or("a radio");
            println!("  Available: {radio}.");
        }
        (_, Some(why)) => println!("  Not available: {why}."),
        _ => {}
    }
    if let Some(e) = b["error"].as_str() {
        println!("  Last problem: {e}.");
    }
    let seen = b["seen"].as_u64().unwrap_or(0);
    if seen > 0 {
        println!(
            "  Seen {seen} advertisements of Cardinal devices, {} of them yours or your trusted \
             contacts'.",
            b["recognized"].as_u64().unwrap_or(0)
        );
    }
}

/// What the router gave, or why it gave nothing, whether it is asked at
/// all, and where this device names itself.
fn print_router(router: &Value) {
    if router["on"] == json!(false) {
        println!("Router: not asked for a port (`cardinal router on` asks it).");
    } else if router["network"]["mine"] != json!(true) {
        println!(
            "Router: not asked for a port: this is not a network you said is yours \
             (`cardinal network mine` if it is)."
        );
    } else if let Some(at) = router["external"].as_str() {
        println!(
            "Router: reaches this device from outside at {at} ({}).",
            router["protocol"].as_str().unwrap_or("")
        );
    } else if let Some(why) = router["error"].as_str() {
        println!(
            "Router: gives no port: {why}. A forward set up by hand, or a host, does instead."
        );
    }
    let named: Vec<&str> = router["named"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !named.is_empty() {
        println!(
            "        named as a host at {}, for your trusted contacts (`cardinal router off` \
             stops it).",
            named.join(", ")
        );
    }
}

/// The network this device is on, and whether it is the person's.
fn print_network(v: &Value) {
    if v["known"] != json!(true) {
        println!("This device cannot tell which network it is on: it sees no router.");
        return;
    }
    let router = v["router"].as_str().unwrap_or("");
    let called = v["name"]
        .as_str()
        .map(|n| format!(" ({n})"))
        .unwrap_or_default();
    match (v["answered"] == json!(true), v["mine"] == json!(true)) {
        (_, true) => println!(
            "This network{called}, router {router}, is yours: your devices ask its router for \
             a port here."
        ),
        (true, false) => println!(
            "This network{called}, router {router}, is not yours: your devices leave its \
             router alone."
        ),
        (false, _) => println!(
            "Is this your network? Router {router}. Until you say so, your devices leave its \
             router alone: `cardinal network mine` or `cardinal network not-mine`."
        ),
    }
}

fn print_sheet(v: &Value) {
    let hosts = v["hosts"].as_array().cloned().unwrap_or_default();
    if hosts.is_empty() {
        println!();
        println!("You have no always-on device yet, so your recovery sheet has only your");
        println!("24 words. If every device were lost they could not bring your files back.");
        println!("On a device that stays on, run: cardinal host --address <host:port>");
        return;
    }
    println!();
    println!("Write this on your recovery sheet, with your 24 words:");
    for h in &hosts {
        println!();
        println!("  Always-on device: {}", h["name"].as_str().unwrap_or(""));
        // the key's bytes, written for a person to copy
        let key = h["key"]
            .as_str()
            .and_then(|k| <[u8; 32]>::try_from(hex::decode(k).ok()?).ok())
            .map(|k| cardinald::host::sheet_key(&k))
            .unwrap_or_default();
        for a in h["addresses"].as_array().into_iter().flatten() {
            println!("  Address:          {}", a.as_str().unwrap_or(""));
        }
        println!("  Key:              {key}");
    }
    println!();
    println!("On a new device, after installing Cardinal: cardinal recovery restore \\");
    println!("  --host <address> --key <key>");
}

/// Whether a service runs on the data directory: one answers on its
/// socket, or holds the directory, which it does from before it reads
/// anything there and whatever name it was given for it.
async fn running(paths: &Paths) -> anyhow::Result<bool> {
    Ok(answers(paths).await || held(paths)?)
}

/// Whether a service answers on the socket.
async fn answers(paths: &Paths) -> bool {
    let status = control::request(&paths.socket, &json!({"cmd": "status"})).await;
    status.is_ok()
}

/// Whether a process holds the data directory. A directory that cannot be
/// looked at is an error: "no service" would be a guess.
fn held(paths: &Paths) -> anyhow::Result<bool> {
    cardinald::lock::held(paths)
        .map_err(|e| anyhow::anyhow!("{}", cardinald::lock::cannot(paths, &e)))
}

/// What to say of a service that holds the data and does not answer.
fn starting(paths: &Paths) -> anyhow::Error {
    anyhow::anyhow!(
        "a Cardinal service is starting on {}, or listens somewhere other than {}: it holds \
         the data and does not answer here yet. Try again in a moment. Nothing was changed.",
        paths.home.display(),
        paths.socket.display()
    )
}

/// Whether a service answers, waiting a while for one that holds the data
/// and has not bound its socket yet (it holds the directory from before
/// it reads anything, which for a large store takes time). An error if it
/// still does not answer: nothing is to be set up or changed beside it.
async fn service(paths: &Paths) -> anyhow::Result<bool> {
    let wait = std::env::var("CARDINAL_TEST_STARTING_WAIT_MS").ok();
    let wait = wait.and_then(|ms| ms.parse().ok()).unwrap_or(15_000);
    let until = std::time::Instant::now() + std::time::Duration::from_millis(wait);
    loop {
        if answers(paths).await {
            return Ok(true);
        }
        if !held(paths)? {
            return Ok(false);
        }
        if std::time::Instant::now() >= until {
            return Err(starting(paths));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
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

/// The `Old versions:` line of `cardinal status`, if any are kept.
fn old_line(old: &Value) -> Option<String> {
    let bytes = old["bytes"].as_u64().filter(|b| *b > 0)?;
    let keep = old["keep"].as_str().unwrap_or("30 days");
    Some(format!(
        "Old versions: {}, kept {keep} (`cardinal free-space` frees them now)",
        human_size(bytes)
    ))
}

/// Someone else's words, with nothing in them the terminal would act on.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
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

/// A day, as `2026-11-21`, in local time.
fn human_day(ms: u64) -> String {
    let t = human_time(Some(ms));
    t.split(' ').next().unwrap_or(&t).to_owned()
}

fn human_time(ms: Option<u64>) -> String {
    let Some(ms) = ms else {
        return "unknown time".into();
    };
    // `time_t` as localtime_r takes it (its alias is deprecated on musl).
    let t = (ms / 1000) as _;
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

/// A list of names from the daemon, for a line of output.
fn names(v: &Value) -> String {
    let all = v.as_array().into_iter().flatten();
    let all: Vec<String> = all.map(|x| printable(x.as_str().unwrap_or(""))).collect();
    all.join(", ")
}

/// Tells the person who reads where their hosts are in a group without
/// their having been told: someone who is not their contact and was
/// added there while it named them. They are told, and offered to stop
/// (`hosts.md#telling-others-where-to-reach-you`). Nothing waits for
/// them: a yes was to the group, whoever is added to it.
fn tell_who_reads_reach(g: &Value) {
    let added = names(&g["reach"]["added"]);
    if added.is_empty() {
        return;
    }
    let name = printable(g["name"].as_str().unwrap_or(""));
    println!(
        "    {added} was added to {name} and is not a contact of yours. They can see where \
         your host is ({}).",
        names(&g["reach"]["what"])
    );
    println!(
        "    To stop sharing it there: cardinal group reach {name} keep. To keep sharing it: \
         cardinal group reach {name} share."
    );
}

/// Asks, as part of refusing someone, about each group they are in where
/// this person's hosts are named: they can still see the address there.
/// Nothing asks again afterwards.
fn tell_where_refused_reads_reach(who: &str, refused: &Value) {
    for g in refused["reach"].as_array().into_iter().flatten() {
        let name = printable(g["name"].as_str().unwrap_or(""));
        println!(
            "{who} is in {name} and can still see your host's address there ({}).",
            names(&g["what"])
        );
        println!(
            "    To stop sharing it there: cardinal group reach {name} keep. To keep sharing \
             it, do nothing."
        );
    }
}

fn files(n: u64) -> String {
    format!("{n} file{}", if n == 1 { "" } else { "s" })
}

/// `cardinal clear`: says what Cardinal keeps in the data directory, and
/// on the person's word removes it, so that `cardinal init` can start
/// again there. It reads none of it, so it works whatever version wrote it.
async fn clear(
    paths: &Paths,
    dry_run: bool,
    yes: bool,
    including_local: bool,
) -> anyhow::Result<()> {
    let home = paths.home.display();
    let stop_first = || {
        anyhow::anyhow!(
            "the cardinal daemon is running on {home}. Stop it first (`cardinal stop`, or \
             `systemctl --user stop cardinal`), then run `cardinal clear` again. Nothing was \
             changed."
        )
    };
    if running(paths).await? {
        return Err(stop_first());
    }
    let found = cardinald::clear::found(paths);
    let (local, local_bytes) = found.local;
    // What `.cardinalignore` keeps on this device only, and where.
    let holds = |d: &str| {
        let dir = std::fs::read_dir(paths.home.join(d));
        dir.is_ok_and(|mut r| r.next().is_some())
    };
    let places: Vec<String> = ["local", "local-shared"]
        .into_iter()
        .filter(|d| holds(d))
        .map(|d| paths.home.join(d).display().to_string())
        .collect();
    let own = format!(
        "what is kept on this device only, {} ({}) in {}: your own files, which exist nowhere \
         else",
        files(local),
        human_size(local_bytes),
        places.join(" and ")
    );
    if !found.anything(including_local) {
        println!("There is nothing of Cardinal's to remove in {home}.");
        if local > 0 {
            println!("It leaves {own}. `--including-local` removes them.");
        }
        return Ok(());
    }
    println!("In {home}, Cardinal keeps:");
    if found.identity {
        println!("  this device's keys, and who you are on it");
    }
    if found.spaces > 0 {
        let s = if found.spaces == 1 { "" } else { "s" };
        println!(
            "  {} space{s}: your files, your settings, and each conversation",
            found.spaces
        );
    }
    let (objects, object_bytes) = found.objects;
    if objects > 0 {
        let s = if objects == 1 { "" } else { "s" };
        println!(
            "  {objects} object{s} ({}): the content of files and attachments",
            human_size(object_bytes)
        );
    }
    let (staged, staged_bytes) = found.staged;
    if staged > 0 {
        println!(
            "  {} ({}) that were being written and never saved",
            files(staged),
            human_size(staged_bytes)
        );
    }
    if found.other {
        println!("  what it remembers of your other devices and of other people");
    }
    println!("`cardinal clear` removes all of that. It leaves your settings (config.toml).");
    if local > 0 && including_local {
        println!("It also removes {own}.");
    } else if local > 0 {
        println!("It leaves {own}. `--including-local` removes them too.");
    }
    let mount = Config::load(&paths.config()).ok().and_then(|c| c.mount);
    if let Some(m) = mount {
        println!(
            "Files shown in {} whose content is only on this device will be gone from this \
             device.",
            m.display()
        );
    }
    if dry_run {
        println!("Nothing was removed.");
        return Ok(());
    }
    if !yes && prompt("Type clear to remove it: ")? != "clear" {
        println!("Nothing was removed.");
        return Ok(());
    }
    if running(paths).await? {
        return Err(stop_first());
    }
    // It takes the directory as a daemon does: one that started since is
    // found here, where nothing can come between.
    match cardinald::clear::clear(paths, including_local) {
        Err(e) if e.kind() == std::io::ErrorKind::ResourceBusy => return Err(stop_first()),
        done => done?,
    }
    println!("Removed. `cardinal init` sets this device up again.");
    Ok(())
}

/// `cardinal free-space --unnamed`: what the store holds that nothing this
/// device holds names, and with `--delete` its removal.
async fn free_unnamed(paths: &Paths, delete: bool) -> anyhow::Result<()> {
    let req = json!({"cmd": "free-space", "unnamed": true, "delete": delete});
    let v = call(paths, req).await?;
    let objects = v["objects"].as_u64().unwrap_or(0);
    let s = if objects == 1 { "" } else { "s" };
    let size = human_size(v["bytes"].as_u64().unwrap_or(0));
    let unsure: Vec<&str> = v["unsure"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if !unsure.is_empty() {
        println!(
            "{objects} object{s} ({size}) on this device look as if nothing names them. That \
             count may be too high:"
        );
        for why in &unsure {
            println!("  {}", printable(why));
        }
        if delete {
            anyhow::bail!("nothing was deleted: some of them may be named after all");
        }
        println!("So `--delete` would delete nothing.");
    } else if v["deleted"].as_bool() == Some(true) {
        println!("Deleted {objects} object{s} ({size}) that nothing named.");
    } else if objects == 0 {
        println!("Everything this device stores is named by something it holds.");
    } else {
        println!(
            "{objects} object{s} ({size}) on this device are named by nothing it holds. \
             `cardinal free-space --unnamed --delete` deletes them."
        );
    }
    println!("What was stored or read in the last hour is not counted.");
    Ok(())
}

async fn init(
    paths: &Paths,
    name: Option<String>,
    device_name: Option<String>,
    yes: bool,
    on_demand: bool,
    mount: Option<PathBuf>,
) -> anyhow::Result<()> {
    let daemon = service(paths).await?;
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
    println!("Name guardians too, people you trust, with `cardinal guardians set`: if you");
    println!("lose your words and every device, they can give your identity back.");
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
    let named = device_name.is_some();
    if let Some(n) = device_name
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
    {
        config.name = n;
    }
    // the person's name, which is not this device's
    let person = match name.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty()) {
        Some(n) => n,
        None if yes => cardinald::config::default_person(),
        None => {
            let guess = cardinald::config::default_person();
            let said = prompt(&format!(
                "What should people call you? It is the name you suggest to those you \
                 invite. [{guess}] "
            ))?;
            if said.is_empty() {
                guess
            } else {
                said
            }
        }
    };
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
    // With no service, this takes the directory as one would, for as long
    // as it writes: a `cardinal clear` or a service starting at the same
    // moment finds it held, and leaves no half of an identity behind. A
    // running service holds it already, and is told to load what is new.
    let lock = match daemon {
        true => None,
        false => {
            let taken = cardinald::lock::take(paths);
            let taken =
                taken.map_err(|e| anyhow::anyhow!("{}", cardinald::lock::cannot(paths, &e)))?;
            Some(taken.ok_or_else(|| starting(paths))?)
        }
    };
    config.save(&paths.config())?;
    setup::install(paths, prepared, &config, &person)?;
    drop(lock);
    println!(
        "Set up. You are \"{person}\" to the people you invite, and this device is \"{}\".",
        config.name
    );
    if !named {
        println!(
            "To call it something else: cardinal rename-device \"{}\" <name>",
            config.name
        );
    }
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
    device: Option<String>,
) -> anyhow::Result<()> {
    if let Some(code) = code {
        let mut req = json!({"cmd": "pair-type", "code": code, "at": at, "admin": admin});
        if let Some(d) = &device {
            req["device"] = json!(d);
        }
        // Only an admin device adds devices; elsewhere the recovery words
        // approve it. Ask before the code times out on the new device.
        let st = call(paths, json!({"cmd": "status"})).await?;
        let mine = st["devices"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["this"] == true))
            .and_then(|x| x["power"].as_str())
            .unwrap_or("");
        if !st["identity"].is_null() && mine != "admin" && mine != "root" {
            println!("This device cannot add devices (it is not an admin device).");
            let words = ask_words(paths, "Your recovery words can approve it instead.").await?;
            req["words"] = json!(words.as_str());
        }
        println!("Looking for the new device...");
        let v = call(paths, req).await?;
        println!(
            "Added \"{}\". It is getting your files now; see `cardinal status`.",
            v["name"].as_str().unwrap_or("the device")
        );
        return Ok(());
    }
    if admin {
        anyhow::bail!(
            "give --admin where you type the code: `cardinal pair <code> --admin` on the \
             device you already use. This device is told, and shows it."
        );
    }
    let mut req = json!({"cmd": "pair-show"});
    if let Some(d) = &device {
        req["device"] = json!(d);
    }
    let v = call(paths, req).await?;
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
        let state = s["state"].as_str().unwrap_or("");
        // Said once, even where joining was over before it was asked.
        if (state == "joining" || state == "joined") && !said_joining {
            said_joining = true;
            let power = match s["power"].as_str() {
                Some("admin") => "an admin device (it can add and remove devices)",
                _ => "a device",
            };
            println!(
                "Paired with \"{}\". This device will join as {power}. Receiving your \
                 identity...",
                s["admin"].as_str().unwrap_or("your device")
            );
        }
        match state {
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
        if let Some(c) = d["carrier"].as_str() {
            line.push_str(&format!("  {c}"));
        }
        if let Some(t) = d["through"].as_str() {
            line.push_str(&format!(" through {t}"));
        }
        line.push_str(&format!("  [{}]", d["key"].as_str().unwrap_or("")));
        println!("{line}");
        if let Some(f) = source_line(&d["fetch"]) {
            println!("      {f}");
        }
        print!("{}", unreadable_line(&d["unreadable"]));
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
    if v["removed"] == true {
        println!("It was removed from your devices: it no longer syncs, and what is here stays.");
    }
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
    if v["hosts"].as_u64() == Some(0) {
        println!("Always-on device: none yet, so your words alone could not bring your");
        println!("  files back if every device were lost (`cardinal host` on one that stays on)");
    }
    if let Some(line) = old_line(&v["old"]) {
        println!("{line}");
    }
    if let Some(old) = v["moved_from"].as_u64() {
        let now = v["listen"].as_str().unwrap_or("");
        let port = now.rsplit(':').next().unwrap_or(now);
        println!(
            "Port: {old} was in use by another program, so this device listens on {port} now."
        );
        for a in v["left_behind"].as_array().into_iter().flatten() {
            println!(
                "  {} still names port {old}: point your router's forward at {port}, then give the \
                 addresses again with `cardinal host --address`.",
                a.as_str().unwrap_or("")
            );
        }
    }
    print_router(&v["router"]);
    if v["bluetooth"]["mode"].as_str().is_some_and(|m| m != "off") {
        print_bluetooth(&v["bluetooth"]);
    }
    if v["network"]["ask"] == json!(true) {
        println!(
            "Network: is this your network? `cardinal network mine` lets your devices ask its \
             router for a port; until then they leave it alone."
        );
    }
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
    // What an entry that was not accepted carried is kept, and not saved.
    // What was deleted, or chosen between two versions, in such an entry
    // is undone: there is nothing of it to keep.
    let not_saved = v["not_saved"].as_u64().unwrap_or(0);
    let undone = v["not_saved_undone"].as_u64().unwrap_or(0).min(not_saved);
    let kept = not_saved - undone;
    if kept > 0 {
        println!(
            "      {kept} changes to your files could not be saved. What you wrote is kept on \
             this device; change a file again to try it again (for what is in a new folder, \
             rename the folder)."
        );
    }
    if undone > 0 {
        println!(
            "      {undone} deletions or choices between two versions could not be saved, and \
             are undone: those files are as they were."
        );
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
                Some(a) if spread && !is(h, "this") => format!("{} (spot-checked {a})", name(h)),
                _ => name(h),
            })
            .collect();
        let mut l = format!("Copies: {} — {}", counted.len(), list.join(", "));
        match ages.iter().max() {
            Some(a) if !spread => {
                l += &format!(" (files older than {older}, spot-checked {})", ago(*a))
            }
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
            // silent: nothing confirmed, nothing lost
            "unconfirmed" => format!(
                "not confirmed: {}{}",
                h["reason"].as_str().unwrap_or("did not answer"),
                when("last_check")
            ),
            // passed once, and its last check found pieces gone
            "missing" => format!(
                "missing pieces: {}{}",
                h["reason"].as_str().unwrap_or("failed a check"),
                when("last_fail")
            ),
            // never passed yet
            "copying" => match h["reason"].as_str() {
                Some(why) => format!("still copying: {why}"),
                None => "still copying".to_owned(),
            },
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
        rtt(v["rtt_min_us"].as_u64().unwrap_or(0) as f64 / 1000.0),
        rtt(v["rtt_median_us"].as_u64().unwrap_or(0) as f64 / 1000.0),
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
            device_name,
            yes,
            on_demand,
            mount,
        } => init(&paths, name, device_name, yes, on_demand, mount).await,
        Cmd::Me { name } => {
            let v = call(&paths, json!({"cmd": "me", "name": name})).await?;
            let shown = printable(v["name"].as_str().unwrap_or(""));
            if name.is_some() {
                println!("You are \"{shown}\" to the people you invite from now on.");
            } else {
                println!("{shown}");
            }
            Ok(())
        }
        Cmd::Status { json: raw } => {
            let v = call(&paths, json!({"cmd": "status"})).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                print_status(&v);
            }
            Ok(())
        }
        Cmd::Pair {
            code,
            at,
            admin,
            device_name,
        } => pair(&paths, code, at, admin, device_name).await,
        Cmd::Devices => {
            let v = call(&paths, json!({"cmd": "devices"})).await?;
            print_devices(&v["devices"]);
            Ok(())
        }
        Cmd::Speedtest { device, json: raw } => speedtest(&paths, device, raw).await,
        Cmd::RenameDevice { device, name } => {
            let v = call(
                &paths,
                json!({"cmd": "device-rename", "device": device, "name": name}),
            )
            .await?;
            println!(
                "Renamed {device} to {}.",
                v["name"].as_str().unwrap_or(&name)
            );
            Ok(())
        }
        Cmd::RemoveDevice { who, lost } => {
            let req = json!({"cmd": "remove-device", "who": who, "lost": lost});
            let v = call_with_words(&paths, req).await?;
            let name = v["name"].as_str().unwrap_or(&who);
            if lost {
                println!(
                    "Removed \"{name}\". It can no longer read or change your files. Changes of \
                     its that your other devices had not built on are not kept: {}.",
                    v["dropped"].as_u64().unwrap_or(0)
                );
            } else {
                println!(
                    "Removed \"{name}\". It can no longer read or change your files; everything \
                     of its that reached your other devices is kept."
                );
            }
            let devs = call(&paths, json!({"cmd": "devices"})).await?;
            let admins = devs["devices"]
                .as_array()
                .map_or(0, |a| a.iter().filter(|d| d["power"] == "admin").count());
            if admins == 0 {
                println!(
                    "None of your devices is an admin device now, so adding a device will ask for\n\
                     your recovery words. To have one again, run `cardinal pair` on a new device\n\
                     and type its code here with `cardinal pair <code> --admin`."
                );
            }
            Ok(())
        }
        Cmd::Recovery {
            cmd: RecoveryCmd::Check,
        } => {
            ask_words(
                &paths,
                "Checking your 24 recovery words; nothing is changed or kept.",
            )
            .await?;
            println!("These are your recovery words. Keep them where only you can find them.");
            Ok(())
        }
        Cmd::Recovery {
            cmd: RecoveryCmd::Sheet,
        } => {
            print_sheet(&call(&paths, json!({"cmd": "recovery-sheet"})).await?);
            Ok(())
        }
        Cmd::Recovery {
            cmd: RecoveryCmd::Restore { host, key },
        } => {
            // the key as the sheet writes it, checked before anything is sent
            let key = cardinald::host::read_sheet_key(&key).ok_or_else(|| {
                anyhow::anyhow!("that key does not check out; a character was probably mistyped")
            })?;
            let words = read_words(None, "Type your 24 recovery words.").await?;
            println!("Reaching {host}...");
            let key = hex::encode(key);
            call(
                &paths,
                json!({"cmd": "restore-from-host", "words": words.as_str(), "at": host, "key": key}),
            )
            .await?;
            println!("Restored. Your files are coming back.");
            println!(
                "Your old devices are still listed under `cardinal devices`; remove any you \
                 lost with `cardinal remove-device`."
            );
            Ok(())
        }
        Cmd::Guardians { cmd: None } => {
            print_guardians(&call(&paths, json!({"cmd": "guardians"})).await?);
            Ok(())
        }
        Cmd::Guardians {
            cmd:
                Some(GuardiansCmd::Set {
                    names,
                    threshold,
                    delay,
                }),
        } => {
            let delay = delay.as_deref().map(parse_delay).transpose()?;
            let req = json!({"cmd": "guardians-set", "who": names, "threshold": threshold, "delay": delay});
            let v = call_with_words(&paths, req).await?;
            let names: Vec<&str> = v["names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if v["pending"] == true {
                println!(
                    "Asked your guardians to confirm the change to {}: once enough of them \
                     have, after the wait, they are your guardians.",
                    names.join(", ")
                );
                return Ok(());
            }
            println!(
                "Your guardians are {}. {} of them together can give your identity back, after {}.",
                names.join(", "),
                v["threshold"],
                v["delay_text"].as_str().unwrap_or("")
            );
            println!("Nobody but you and them knows who they are. Tell them you named them.");
            Ok(())
        }
        Cmd::Guardians {
            cmd: Some(GuardiansCmd::Object { fingerprint }),
        } => {
            call(
                &paths,
                json!({"cmd": "guardians-object", "fingerprint": (!fingerprint.is_empty()).then(|| typed_fingerprint(&fingerprint))}),
            )
            .await?;
            println!("Objected. Your guardians now wait twice as long; tell them it is not you.");
            Ok(())
        }
        Cmd::KeepWork { name, up_to } => {
            let v = call(
                &paths,
                json!({"cmd": "keep-work", "name": name, "up_to": up_to}),
            )
            .await?;
            if up_to.is_some() {
                println!("Kept {} changes.", v["kept"]);
            } else {
                let listed = v["set_aside"].as_array().cloned().unwrap_or_default();
                println!("{} changes of {name} are set aside:", listed.len());
                for e in listed {
                    println!(
                        "  {}  in space {}  written at {}",
                        e["entry"].as_str().unwrap_or(""),
                        e["space"].as_str().unwrap_or(""),
                        e["time_ms"]
                    );
                }
                println!("Keep those you recognize, up to a time: cardinal keep-work {name} --up-to TIME (or all)");
            }
            Ok(())
        }
        Cmd::Guarding { cmd: None } => {
            print_guarding(&call(&paths, json!({"cmd": "guarding"})).await?);
            Ok(())
        }
        Cmd::Guardians {
            cmd: Some(GuardiansCmd::Ask { who }),
        } => {
            let v = call(&paths, json!({"cmd": "guardians-ask", "who": who})).await?;
            println!(
                "Asked {} to be your guardian. Once they accept, name them with \
                 `cardinal guardians set`.",
                v["name"].as_str().unwrap_or(&who)
            );
            Ok(())
        }
        Cmd::Guarding {
            cmd:
                Some(GuardingCmd::ConfirmChange {
                    who,
                    fingerprint,
                    yes,
                }),
        } => {
            if !yes {
                println!(
                    "Before you go on: this changes who can give {who}'s identity back. Check \
                     with {who}, in person if you can, that they asked for it."
                );
                let said = prompt("Go on? Type yes: ")?;
                anyhow::ensure!(said.eq_ignore_ascii_case("yes"), "nothing was done");
            }
            let v = call(
                &paths,
                json!({"cmd": "guarding-confirm-change", "who": who, "understood": true,
                    "fingerprint": (!fingerprint.is_empty()).then(|| typed_fingerprint(&fingerprint))}),
            )
            .await?;
            println!("Confirmed the change.");
            print_guarding(&v);
            Ok(())
        }
        Cmd::Guarding {
            cmd: Some(GuardingCmd::Accept { who }),
        } => {
            let v = call(&paths, json!({"cmd": "guarding-accept", "who": who})).await?;
            let name = v["name"].as_str().unwrap_or(&who);
            if v["already"] == true {
                println!("You had accepted already: {name} can name you a guardian.");
            } else {
                println!(
                    "You accepted guarding {name}. Your device made a persona for it, which {name} \
                     can now name (`cardinal guardians set`)."
                );
            }
            Ok(())
        }
        Cmd::Guarding {
            cmd: Some(GuardingCmd::Invite { who, address }),
        } => {
            let v = call(
                &paths,
                json!({"cmd": "guarding-invite", "who": who, "at": address}),
            )
            .await?;
            println!(
                "Give {} this invitation, for their new device (`cardinal recover start CODE`). \
                 It meets your device for their recovery alone:",
                v["name"].as_str().unwrap_or(&who)
            );
            println!("{}", v["code"].as_str().unwrap_or(""));
            Ok(())
        }
        Cmd::Guarding {
            cmd:
                Some(GuardingCmd::Endorse {
                    who,
                    fingerprint,
                    yes,
                }),
        } => {
            cautioned(&paths, &who, yes).await?;
            let v = call(
                &paths,
                json!({"cmd": "guarding-endorse", "who": who, "fingerprint": typed_fingerprint(&fingerprint), "understood": true}),
            )
            .await?;
            println!("Endorsed. Once enough guardians have, everyone waits, and then confirms.");
            print_guarding(&v);
            Ok(())
        }
        Cmd::Guarding {
            cmd:
                Some(GuardingCmd::Confirm {
                    who,
                    fingerprint,
                    yes,
                }),
        } => {
            cautioned(&paths, &who, yes).await?;
            let v = call(
                &paths,
                json!({"cmd": "guarding-confirm", "who": who, "fingerprint": typed_fingerprint(&fingerprint), "understood": true}),
            )
            .await?;
            println!("Confirmed.");
            print_guarding(&v);
            Ok(())
        }
        Cmd::Guarding {
            cmd: Some(GuardingCmd::Never { who, fingerprint }),
        } => {
            let v = call(
                &paths,
                json!({"cmd": "guarding-never", "who": who, "fingerprint": typed_fingerprint(&fingerprint)}),
            )
            .await?;
            println!("You will never endorse or confirm that recovery, on any of your devices.");
            print_guarding(&v);
            Ok(())
        }
        Cmd::Recover { cmd: None } => {
            let v = call(&paths, json!({"cmd": "recover"})).await?;
            print_recover(&v);
            Ok(())
        }
        Cmd::Recover {
            cmd: Some(RecoverCmd::Start { code, identity }),
        } => {
            let v = call(
                &paths,
                json!({"cmd": "recover-start", "code": code, "identity": identity}),
            )
            .await?;
            if code.is_some() {
                println!(
                    "You are in touch with that guardian. Read each guardian this fingerprint:"
                );
            } else {
                println!("Recovering. Read each guardian this fingerprint:");
            }
            println!("    {}", v["fingerprint"].as_str().unwrap_or(""));
            println!("Bring each guardian's invitation the same way. Once enough have confirmed,");
            println!("run `cardinal recover finish`.");
            Ok(())
        }
        Cmd::Recover {
            cmd: Some(RecoverCmd::Invite { address }),
        } => {
            let v = call(&paths, json!({"cmd": "recover-invite", "at": address})).await?;
            println!("Have your guardian use this on their device (`cardinal accept CODE`):");
            println!("{}", v["code"].as_str().unwrap_or(""));
            println!(
                "Then read them this fingerprint: {}",
                v["fingerprint"].as_str().unwrap_or("")
            );
            Ok(())
        }
        Cmd::Recover {
            cmd: Some(RecoverCmd::Cancel),
        } => {
            let v = call(&paths, json!({"cmd": "recover-cancel"})).await?;
            match v["fingerprint"].as_str() {
                Some(fp) => println!(
                    "Given up. Tell each guardian never to confirm the recovery \"{fp}\" \
                     (`cardinal guarding never`)."
                ),
                None => println!("No recovery was under way."),
            }
            Ok(())
        }
        Cmd::Recover {
            cmd:
                Some(RecoverCmd::Finish {
                    without_account,
                    lost_at,
                }),
        } => {
            let v = call(
                &paths,
                json!({"cmd": "recover-finish", "without_account": without_account, "lost_at": lost_at}),
            )
            .await?;
            if v["account"] == true {
                println!("Recovered, from what your guardians hold: your account, contacts and");
                println!(
                    "settings are back. Your other spaces come back as their holders are reached."
                );
            } else {
                println!("Recovered, from what your guardians hold. They held no copy of your");
                println!("account, so this device starts with an empty one.");
            }
            print_pair_again(&v);
            let lost: Vec<&Value> = v["lost_devices"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|l| l["set_aside"].as_u64().unwrap_or(0) > 0)
                .collect();
            if !lost.is_empty() {
                println!();
                println!("When did you lose your devices? What they wrote is set aside, since a");
                println!("thief may have written with them. Keep what they wrote up to then:");
                for l in lost {
                    let name = l["name"]
                        .as_str()
                        .unwrap_or_else(|| l["key"].as_str().unwrap_or(""));
                    println!(
                        "  cardinal keep-work {name} --up-to TIME   ({} set aside)",
                        l["set_aside"]
                    );
                }
                println!("The time is each device's own clock, which a thief can set.");
            }
            println!();
            println!("Name your guardians again: ask each (`cardinal guardians ask NAME`), then");
            println!(
                "`cardinal guardians set`. Those who just acted keep the role until then, and"
            );
            println!("confirm the change.");
            println!();
            println!("Your new recovery words. Write them down, in order, and keep them safe:");
            println!("the old ones no longer work.");
            println!();
            show_words(v["words"].as_str().unwrap_or(""));
            println!();
            Ok(())
        }
        Cmd::Invite {
            address,
            name,
            hosts_only,
            no_introductions,
        } => {
            let req = json!({
                "cmd": "invite",
                "address": address,
                "name": name,
                "hosts_only": hosts_only,
                "no_introductions": no_introductions,
            });
            let v = call(&paths, req).await?;
            println!("{}", v["code"].as_str().unwrap_or(""));
            Ok(())
        }
        Cmd::Accept {
            code,
            name,
            hosts_only,
            no_introductions,
            for_whom,
        } => {
            let req = json!({
                "cmd": "accept",
                "code": code,
                "for": for_whom,
                "name": name,
                "hosts_only": hosts_only,
                "no_introductions": no_introductions,
            });
            let v = call(&paths, req).await?;
            if v["recovery_of"].is_string() {
                println!(
                    "In touch, as {}. It is no contact: see it with `cardinal guarding`, \
                     and check the fingerprint with them before you endorse.",
                    v["name"].as_str().unwrap_or("")
                );
            } else {
                println!("Connected to {}.", v["name"].as_str().unwrap_or(""));
            }
            Ok(())
        }
        Cmd::Contacts {
            who: Some(who),
            look,
            at,
            json,
            ..
        } => {
            let v = call(
                &paths,
                json!({"cmd": "contact-status", "who": who, "look": look, "at": at}),
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                print!("{}", contact_status(&v));
            }
            Ok(())
        }
        Cmd::Contacts { all, .. } => {
            let v = call(&paths, json!({"cmd": "contacts", "all": all})).await?;
            for c in v["contacts"].as_array().into_iter().flatten() {
                let mut line = c["name"].as_str().unwrap_or("").to_owned();
                if c["own"] == false {
                    line.push_str(" (their name)");
                }
                if c["picture"].is_string() {
                    line.push_str("  picture");
                }
                line.push_str(if c["trusted"] == true {
                    "  trusted"
                } else {
                    "  through hosts only"
                });
                if c["connected"] == true {
                    line.push_str("  connected");
                }
                if c["introductions"] == false {
                    line.push_str("  no introductions");
                }
                if c["refused"] == true {
                    line.push_str("  refused");
                }
                println!("{line}  [{}]", c["identity"].as_str().unwrap_or(""));
                if let Some(u) = c["unreadable"].as_str() {
                    println!("  {}", printable(u));
                }
                if let Some(r) = c["recovered"].as_str() {
                    let name = c["name"].as_str().unwrap_or("");
                    // the day in this person's own time, from the fields
                    let local = c["recovered_seen"]
                        .as_u64()
                        .zip(c["recovered_delay"].as_u64());
                    match local {
                        Some((seen, delay)) => println!(
                            "  {name} was recovered by guardians they had chosen by {}, after \
                             {}. If in doubt, check with them in person.",
                            human_day(seen),
                            cardinald::guardians::delay_text(delay)
                        ),
                        None => println!("  {name} {r}"),
                    }
                }
            }
            Ok(())
        }
        Cmd::Contact {
            who,
            setting,
            new_name,
        } => {
            let req = match (setting.as_str(), new_name) {
                ("name", Some(name)) => json!({"cmd": "contact", "who": who, "name": name}),
                ("picture", Some(p)) => {
                    // a file on this computer, as the service sees it
                    let here = std::path::Path::new(&p);
                    let p = match std::env::current_dir() {
                        Ok(cwd) if !p.is_empty() && !here.is_absolute() && here.is_file() => {
                            cwd.join(here).display().to_string()
                        }
                        _ => p,
                    };
                    json!({"cmd": "contact", "who": who, "picture": p})
                }
                ("picture", None) => anyhow::bail!(
                    "say which file: `cardinal contact {who} picture People/{who}/photo.jpg`, \
                     or \"\" to clear it"
                ),
                ("name", None) => {
                    anyhow::bail!("say what to call them: `cardinal contact {who} name NEW`")
                }
                ("category", Some(c)) => json!({"cmd": "contact", "who": who, "category": c}),
                ("category", None) => {
                    anyhow::bail!(
                        "say where to list them: `cardinal contact {who} category Family`"
                    )
                }
                ("no-host", Some(h)) => {
                    json!({"cmd": "contact", "who": who, "setting": "no-host", "host": h})
                }
                ("no-host", None) => {
                    anyhow::bail!("say which host: `cardinal contact {who} no-host DEVICE`")
                }
                (_, Some(_)) => {
                    anyhow::bail!("only `name`, `picture`, `category` and `no-host` take a value")
                }
                (_, None) => json!({"cmd": "contact", "who": who, "setting": setting}),
            };
            let done = call(&paths, req).await?;
            // Someone refused may be in a group where this person's hosts
            // are named: they are asked about it now, and only now.
            if setting == "refuse" {
                tell_where_refused_reads_reach(&printable(&who), &done);
            }
            let who = printable(&who);
            match done["named"].as_str() {
                Some("named") => println!("{who} can now find your devices through your hosts."),
                Some("waiting") => println!(
                    "Your host cannot be reached from here now. It is named for {who} as soon as it can be."
                ),
                Some("no host") => println!("You have no host to name."),
                Some("none") => println!(
                    "{who} is no longer told where your hosts are. Your hosts stay out until \
                     you say `cardinal contact {who} name-hosts`."
                ),
                Some("taken out") => println!(
                    "That host is no longer named for {who}, and stays out until you say \
                     `cardinal contact {who} name-hosts`."
                ),
                Some("not named") => println!(
                    "That host was not named for {who}. It stays out until you say \
                     `cardinal contact {who} name-hosts`."
                ),
                _ => {}
            }
            Ok(())
        }
        Cmd::Invitations { action, id } => match (action.as_deref(), id) {
            (Some("cancel"), Some(id)) => {
                call(&paths, json!({"cmd": "cancel-invitation", "id": id})).await?;
                println!("Cancelled: nobody can use it now, on any of your devices.");
                Ok(())
            }
            (Some(_), None) => anyhow::bail!("say which: `cardinal invitations cancel ID`"),
            _ => {
                let v = call(&paths, json!({"cmd": "invitations"})).await?;
                let all = v["invitations"].as_array().cloned().unwrap_or_default();
                if all.is_empty() {
                    println!("You have made no invitations.");
                }
                for i in all {
                    let standing = if i["outstanding"] == true {
                        "can be used"
                    } else if i["cancelled"] == true {
                        "cancelled"
                    } else if i["expired"] == true {
                        "expired"
                    } else {
                        "used"
                    };
                    let name = i["name"].as_str().unwrap_or("(no name)");
                    let only = if i["hosts_only"] == true {
                        "  through hosts only"
                    } else {
                        ""
                    };
                    println!(
                        "{}  {name}  {standing}{only}",
                        i["id"].as_str().unwrap_or("")
                    );
                }
                Ok(())
            }
        },
        Cmd::Files { path } => {
            let path = path.unwrap_or_default();
            let v = call(&paths, json!({"cmd": "files", "path": path})).await?;
            if let Some(name) = v["place"]["name"]
                .as_str()
                .filter(|_| v["place"]["kind"] == "shared")
            {
                println!("Shared with {name}: you both see what is here.");
            }
            for f in v["files"].as_array().into_iter().flatten() {
                let name = printable(f["name"].as_str().unwrap_or("?"));
                if f["folder"] == true {
                    println!("{name}/");
                } else {
                    let size = f["size"].as_u64().map(human_size).unwrap_or_default();
                    println!("{name}  {size}");
                }
            }
            Ok(())
        }
        Cmd::Share {
            who,
            paths: what,
            message,
        } => {
            let req = json!({"cmd": "share", "who": who, "paths": what, "text": message});
            let v = call(&paths, req).await?;
            println!(
                "In {}{}.",
                v["path"].as_str().unwrap_or(""),
                if v["message"] == true {
                    ", with your message"
                } else {
                    ""
                }
            );
            Ok(())
        }
        Cmd::Put { from, to } => {
            let from = std::path::absolute(from)?;
            let req = json!({"cmd": "put", "from": from, "to": to.unwrap_or_default()});
            call(&paths, req).await?;
            Ok(())
        }
        Cmd::Get { path, to } => {
            let to = std::path::absolute(to)?;
            call(&paths, json!({"cmd": "save", "path": path, "to": to})).await?;
            Ok(())
        }
        Cmd::Say { who, text, attach } => {
            // The daemon has its own working directory.
            let attach: Vec<PathBuf> = attach
                .iter()
                .map(std::path::absolute)
                .collect::<Result<_, _>>()?;
            let req = json!({"cmd": "say", "who": who, "text": text, "attach": attach});
            let v = call(&paths, req).await?;
            if v["reachable"] == false {
                println!(
                    "Kept here: this cannot reach {who} through a host, so it waits \
                     until you connect."
                );
            }
            Ok(())
        }
        Cmd::Introduce { who, to, note } => {
            call(
                &paths,
                json!({"cmd": "introduce", "who": who, "to": to, "note": note}),
            )
            .await?;
            println!("Asked {to} whether to meet {who}.");
            Ok(())
        }
        Cmd::Introductions { answer, id } => {
            match (answer.as_deref(), id) {
                (Some("yes"), Some(id)) => {
                    call(&paths, json!({"cmd": "introduction-accept", "id": id})).await?;
                }
                (Some("no"), Some(id)) => {
                    call(&paths, json!({"cmd": "introduction-decline", "id": id})).await?;
                }
                (None, _) => {
                    let v = call(&paths, json!({"cmd": "introductions"})).await?;
                    for i in v["introductions"].as_array().into_iter().flatten() {
                        let (from, name) = (
                            printable(i["from"].as_str().unwrap_or("")),
                            printable(i["name"].as_str().unwrap_or("")),
                        );
                        let id = i["id"].as_str().unwrap_or("");
                        if i["kind"] == "meet" {
                            println!("{from} would like you to meet {name}: cardinal introductions yes {id}");
                        } else {
                            println!(
                                "{from} introduced you to {name}: cardinal introductions yes {id}"
                            );
                        }
                    }
                }
                _ => anyhow::bail!("say yes or no, and which: cardinal introductions yes ID"),
            }
            Ok(())
        }
        Cmd::Groups => {
            let v = call(&paths, json!({"cmd": "groups"})).await?;
            for g in v["groups"].as_array().into_iter().flatten() {
                let unread = g["unread"].as_u64().unwrap_or(0);
                let unread = if unread > 0 {
                    format!(", {unread} unread")
                } else {
                    String::new()
                };
                let public = match g["public"] == true {
                    true => ", public",
                    false => "",
                };
                println!(
                    "{}  ({} members{unread}{public})  {}",
                    printable(g["name"].as_str().unwrap_or("")),
                    g["members"],
                    &g["group"].as_str().unwrap_or("")[..16]
                );
                tell_who_reads_reach(g);
            }
            for o in v["offers"].as_array().into_iter().flatten() {
                println!(
                    "{} added you to {}: cardinal group join {}",
                    printable(o["from"].as_str().unwrap_or("")),
                    printable(o["name"].as_str().unwrap_or("")),
                    &o["group"].as_str().unwrap_or("")[..16]
                );
                if o["public"] == true {
                    println!(
                        "    It is public: anyone who gets what is written in it can read it."
                    );
                }
                if o["reach"]["ask"] == true {
                    println!(
                        "    Not contacts of yours in it: {}. Joining with --share-host tells \
                         them, and anyone added later, where your host is ({}); with \
                         --keep-host it does not.",
                        names(&o["reach"]["who"]),
                        names(&o["reach"]["what"]),
                    );
                }
            }
            Ok(())
        }
        Cmd::Approve { id, no, with, role } => {
            let Some(id) = id else {
                let v = call(&paths, json!({"cmd": "app-questions"})).await?;
                let qs = v["questions"].as_array().cloned().unwrap_or_default();
                if qs.is_empty() {
                    println!("Nothing is waiting for you.");
                }
                for q in qs {
                    println!("{}. {}", q["id"], q["what"].as_str().unwrap_or(""));
                    println!("   ({}: {})", q["name"].as_str().unwrap_or(""), q["program"].as_str().unwrap_or(""));
                    if q["asks"] == "share" {
                        println!("   Answer with --with and the people, and --role reader or writer.");
                    }
                }
                return Ok(());
            };
            let req = json!({"cmd": "app-answer", "id": id, "yes": !no, "people": with, "role": role});
            call(&paths, req).await?;
            println!("{}", if no { "Said no." } else { "Said yes." });
            Ok(())
        }
        Cmd::Apps { cmd } => match cmd {
            AppsCmd::Approvals => {
                let v = call(&paths, json!({"cmd": "approvals"})).await?;
                let all = v["approvals"].as_array().cloned().unwrap_or_default();
                if all.is_empty() {
                    println!("No program is approved for anything.");
                }
                for a in all {
                    let how = if a["change"] == true { "see and change" } else { "see" };
                    let off = if a["revoked"] == true { "  (revoked)" } else { "" };
                    let here = if a["this_device"] == true { "this device".to_owned() } else {
                        a["device"].as_str().unwrap_or("another device").to_owned()
                    };
                    println!(
                        "{}  {} may {how} every {}, on {here}: {}{off}",
                        &a["id"].as_str().unwrap_or("")[..8.min(a["id"].as_str().unwrap_or("").len())],
                        a["name"].as_str().unwrap_or(""),
                        a["covers"].as_str().unwrap_or(""),
                        a["program"].as_str().unwrap_or(""),
                    );
                }
                Ok(())
            }
            AppsCmd::Revoke { id } => {
                call(&paths, json!({"cmd": "approval-revoke", "id": id})).await?;
                println!("Revoked.");
                Ok(())
            }
            AppsCmd::Offers => {
                let v = call(&paths, json!({"cmd": "app-offers"})).await?;
                let all = v["offers"].as_array().cloned().unwrap_or_default();
                if all.is_empty() {
                    println!("Nothing is offered to you.");
                }
                for o in all {
                    let app = o["application"].as_str().unwrap_or("something");
                    println!(
                        "{}  {} shares a {} with you: {}",
                        &o["space"].as_str().unwrap_or("")[..16],
                        o["from"].as_str().unwrap_or(""),
                        app.to_lowercase(),
                        o["name"].as_str().unwrap_or(""),
                    );
                }
                Ok(())
            }
            AppsCmd::Join { space } => {
                let v = call(&paths, json!({"cmd": "app-join", "space": space})).await?;
                println!("Joined {}.", v["name"].as_str().unwrap_or(""));
                Ok(())
            }
        },
        Cmd::Clip { cmd } => match cmd {
            ClipCmd::Copy { text } => {
                let text = match text {
                    Some(t) => t,
                    None => {
                        let mut t = String::new();
                        std::io::Read::read_to_string(&mut std::io::stdin(), &mut t)
                            .map_err(|e| anyhow::anyhow!("reading what to copy: {e}"))?;
                        t
                    }
                };
                let v = call(&paths, json!({"cmd": "clip-copy", "text": text})).await?;
                match v["devices"].as_u64().unwrap_or(0) {
                    0 => eprintln!(
                        "Copied here. None of your other devices is online; \
                         one that comes online within ten minutes does not get it."
                    ),
                    1 => eprintln!("Copied to 1 other device."),
                    n => eprintln!("Copied to {n} other devices."),
                }
                Ok(())
            }
            ClipCmd::Paste => {
                let v = call(&paths, json!({"cmd": "clip"})).await?;
                match v["text"].as_str() {
                    Some(text) => {
                        print!("{text}");
                        if std::io::IsTerminal::is_terminal(&std::io::stdout())
                            && !text.ends_with('\n')
                        {
                            println!();
                        }
                        Ok(())
                    }
                    None => anyhow::bail!("nothing copied on your devices in the last ten minutes"),
                }
            }
        },
        Cmd::Group { cmd } => {
            let req = match &cmd {
                GroupCmd::Create { name, people } => {
                    json!({"cmd": "group-create", "name": name, "people": people})
                }
                GroupCmd::Join {
                    group,
                    share_host,
                    keep_host,
                } => {
                    let reach = match (*share_host, *keep_host) {
                        (true, _) => Some(true),
                        (_, true) => Some(false),
                        _ => None,
                    };
                    json!({"cmd": "group-join", "group": group, "reach": reach})
                }
                GroupCmd::Reach {
                    group,
                    setting,
                    host,
                } => {
                    let share = match setting.as_str() {
                        "share" => true,
                        "keep" => false,
                        _ => anyhow::bail!("say share or keep"),
                    };
                    anyhow::ensure!(
                        !(share && host.is_some()),
                        "`--host` goes with keep: share names every host of yours"
                    );
                    let mut req = json!({"cmd": "group-reach", "group": group, "share": share});
                    if let Some(h) = host {
                        req["host"] = json!(h);
                    }
                    req
                }
                GroupCmd::Decline { group } => json!({"cmd": "group-decline", "group": group}),
                GroupCmd::Leave { group } => json!({"cmd": "group-leave", "group": group}),
                GroupCmd::Add {
                    group,
                    people,
                    shown,
                } => {
                    json!({"cmd": "group-add", "group": group, "people": people, "shown": shown})
                }
                GroupCmd::Remove { group, who } => {
                    json!({"cmd": "group-remove", "group": group, "who": who})
                }
                GroupCmd::Role { group, who, role } => {
                    json!({"cmd": "group-role", "group": group, "who": who, "role": role})
                }
                GroupCmd::PostAgain { group } => {
                    json!({"cmd": "group-post-again", "group": group})
                }
                GroupCmd::Members { group } => json!({"cmd": "group-members", "group": group}),
                GroupCmd::Say { group, text } => {
                    json!({"cmd": "say", "group": group, "text": text})
                }
                GroupCmd::Messages { group } => json!({"cmd": "messages", "group": group}),
                GroupCmd::Rename { group, name } => {
                    json!({"cmd": "group-set", "group": group, "name": name})
                }
                GroupCmd::Introductions { group, setting } => {
                    let on = match setting.as_str() {
                        "on" => true,
                        "off" => false,
                        _ => anyhow::bail!("say on or off"),
                    };
                    json!({"cmd": "group-set", "group": group, "introductions": on})
                }
                GroupCmd::Member {
                    group,
                    who,
                    shown,
                    no_introductions,
                    introductions,
                } => {
                    let introduce = match (*no_introductions, *introductions) {
                        (true, _) => Some(false),
                        (_, true) => Some(true),
                        _ => None,
                    };
                    json!({"cmd": "group-member", "group": group, "who": who, "shown": shown, "introduce": introduce})
                }
            };
            let v = call(&paths, req).await?;
            match cmd {
                GroupCmd::Create { .. } => println!(
                    "Made {}: {}",
                    printable(v["name"].as_str().unwrap_or("")),
                    v["group"].as_str().unwrap_or("")
                ),
                GroupCmd::Members { .. } => {
                    for m in v["members"].as_array().into_iter().flatten() {
                        println!(
                            "{}  {}",
                            printable(m["name"].as_str().unwrap_or("")),
                            m["role"].as_str().unwrap_or("")
                        );
                    }
                }
                GroupCmd::Messages { .. } => {
                    for m in v["messages"].as_array().into_iter().flatten() {
                        let by = if m["mine"] == true {
                            "you"
                        } else {
                            m["from"].as_str().unwrap_or("")
                        };
                        println!(
                            "{}: {}",
                            printable(by),
                            printable(m["text"].as_str().unwrap_or(""))
                        );
                    }
                }
                GroupCmd::Join { group, .. } | GroupCmd::Reach { group, .. }
                    if v["waiting"] == true =>
                {
                    println!(
                        "Your host cannot be reached right now. It will be shared with {} when \
                         it can.",
                        printable(&group)
                    );
                }
                _ => {}
            }
            Ok(())
        }
        Cmd::Messages { who: None } => {
            let conversations = call(&paths, json!({"cmd": "conversations"})).await?;
            let groups = call(&paths, json!({"cmd": "groups"})).await?;
            print!(
                "{}",
                overview::render(&conversations, &groups, &overview::Style::here())
            );
            Ok(())
        }
        Cmd::Messages { who: Some(who) } => {
            let v = call(&paths, json!({"cmd": "messages", "who": who})).await?;
            for m in v["messages"].as_array().into_iter().flatten() {
                let by = if m["mine"] == true {
                    "you"
                } else {
                    who.as_str()
                };
                println!("{by}: {}", printable(m["text"].as_str().unwrap_or("")));
                let files = m["attachments"].as_array().cloned().unwrap_or_default();
                for (n, a) in files.iter().enumerate() {
                    let size = a["size"].as_u64().map(human_size).unwrap_or_default();
                    println!(
                        "    {} ({size}): cardinal save {who} {} {} PATH",
                        printable(a["name"].as_str().unwrap_or("")),
                        m["id"].as_str().unwrap_or(""),
                        n + 1
                    );
                }
            }
            // Shown is read, as in a window; their devices see it too.
            call(&paths, json!({"cmd": "mark-read", "who": who})).await?;
            Ok(())
        }
        Cmd::Save {
            who,
            message,
            n,
            to,
        } => {
            anyhow::ensure!(n >= 1, "files are counted from 1");
            let to = std::path::absolute(&to)?;
            let req = json!({"cmd": "save-attachment", "who": who, "id": message, "index": n - 1, "to": to});
            let v = call(&paths, req).await?;
            println!(
                "Saved {} at {}.",
                human_size(v["size"].as_u64().unwrap_or(0)),
                to.display()
            );
            Ok(())
        }
        Cmd::Bluetooth { setting } => {
            let mut req = json!({"cmd": "bluetooth"});
            if let Some(s) = &setting {
                req["mode"] = json!(s);
            }
            let v = call(&paths, req).await?;
            match setting.as_deref() {
                Some("off") => println!("Bluetooth is off on this device."),
                Some("open") => {
                    println!("Bluetooth is on on this device while a Cardinal window is open.")
                }
                Some(_) => println!(
                    "Bluetooth is on on this device, while Cardinal is open and while it is \
                     closed."
                ),
                None => {}
            }
            print_bluetooth(&v);
            Ok(())
        }
        Cmd::Router {
            setting,
            this_device,
        } => {
            let mut req = json!({"cmd": "router"});
            if let Some(s) = &setting {
                req["on"] = json!(s == "on");
                req["this_device"] = json!(this_device);
            }
            let v = call(&paths, req).await?;
            let which = if this_device {
                "This device"
            } else {
                "Your devices"
            };
            match setting.as_deref() {
                Some("off") => println!(
                    "{which} no longer ask a router for a port, and no longer name \
                     themselves as a host where they were named at one."
                ),
                Some(_) => println!(
                    "{which} ask the router for a port on networks you said are yours, and \
                     name themselves as a host at the address it gives, where every other \
                     member is a trusted contact."
                ),
                None => {}
            }
            print_router(&v);
            Ok(())
        }
        Cmd::Network { setting, name } => {
            let mut req = json!({"cmd": "network"});
            if let Some(s) = &setting {
                req["mine"] = json!(s == "mine");
            }
            if let Some(n) = &name {
                req["name"] = json!(n);
            }
            let v = call(&paths, req).await?;
            print_network(&v);
            Ok(())
        }
        Cmd::Host { addresses, off } => {
            let req = if off {
                json!({"cmd": "host-off"})
            } else {
                json!({"cmd": "host", "addresses": addresses})
            };
            let v = call(&paths, req).await?;
            println!(
                "{}",
                if off {
                    "This device no longer hosts your other devices."
                } else {
                    "This device now keeps a full copy of your files and can restore them."
                }
            );
            print_sheet(&v);
            for w in v["warnings"].as_array().into_iter().flatten() {
                println!();
                println!("Warning: {}", w.as_str().unwrap_or(""));
            }
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
                    } else if x["here"].as_bool() == Some(false) {
                        "  (not on this device)"
                    } else {
                        ""
                    }
                );
            }
            println!("Bring one back with: cardinal restore {p} --version N");
            Ok(())
        }
        Cmd::Clear {
            dry_run,
            yes,
            including_local,
        } => clear(&paths, dry_run, yes, including_local).await,
        Cmd::FreeSpace {
            unnamed: true,
            delete,
            ..
        } => free_unnamed(&paths, delete).await,
        Cmd::FreeSpace { yes, .. } => {
            let mut v = call(&paths, json!({"cmd": "free-space", "dry_run": true})).await?;
            let bytes = v["bytes"].as_u64().unwrap_or(0);
            if bytes == 0 {
                println!("Nothing to free now.");
            } else {
                println!(
                    "This frees {} on this device. Deleted files and old versions can then be \
                     restored\nonly from your other devices, for as long as they keep theirs.",
                    human_size(bytes)
                );
                if !yes && !prompt("Free it? [y/N] ")?.eq_ignore_ascii_case("y") {
                    println!("Nothing was freed.");
                    return Ok(());
                }
                v = call(&paths, json!({"cmd": "free-space"})).await?;
                println!("Freed {}.", human_size(v["bytes"].as_u64().unwrap_or(0)));
            }
            // Over the budget, but on no device that keeps everything yet.
            if let Some(n) = v["only_here"]["files"].as_u64().filter(|n| *n > 0) {
                println!(
                    "{n} files here are not on your other devices yet, so removing them to make \
                     room would lose them. They stay."
                );
            } else if v["unchecked"].as_bool() == Some(true) {
                println!(
                    "Your devices that keep everything cannot be reached now, so nothing more \
                     was removed to make room."
                );
            }
            // What changed in the last hour is not freed yet.
            if let Some(b) = v["left"].as_u64().filter(|b| *b > 0) {
                println!(
                    "{} changed in the last hour stays until it is an hour old.",
                    human_size(b)
                );
            }
            Ok(())
        }
        Cmd::KeepOld { keep, space } => {
            let mut req = json!({"cmd": "keep-old", "keep": keep});
            if let Some(s) = &space {
                req["space"] = json!(s);
            }
            let v = call(&paths, req).await?;
            println!(
                "This device now keeps deleted files and old versions{} {}.",
                if space.is_some() {
                    " in that space"
                } else {
                    ""
                },
                match v["keep"].as_str().unwrap_or("") {
                    "forever" => "forever".to_owned(),
                    k => format!("for {k}"),
                }
            );
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
        Cmd::ApiTrace { listen } => api_trace(&paths, &listen).await,
        Cmd::Flush => {
            let v = call(&paths, json!({"cmd": "flush"})).await?;
            println!("Saved ({} entries).", v["entries"]);
            Ok(())
        }
        Cmd::Store => {
            use std::io::{IsTerminal, Write};
            let report = cardinald::format::report(&paths);
            let mut out = std::io::stdout().lock();
            if out.is_terminal() {
                let spec = cardinald::api::program("--store").expect("the table has it");
                writeln!(out, "{}", cardinald::api::render_reply(spec, &report))?;
            } else {
                out.write_all(&report)?;
            }
            out.flush()?;
            Ok(())
        }
        Cmd::Inspect { cmd } => match cmd {
            InspectCmd::On {
                minutes,
                yes,
                quiet,
            } => {
                if !yes {
                    eprintln!(
                        "Whoever has the token can read everything this device holds for the \n\
                         next {minutes} minutes: your identity log, your account, every space, \n\
                         the addresses and tokens in them. Never your keys. Nothing can be \n\
                         changed through it. Give it only to a program you chose, such as \n\
                         the space explorer. Type yes to turn inspection on:"
                    );
                    let mut answer = String::new();
                    std::io::stdin().read_line(&mut answer)?;
                    if answer.trim() != "yes" {
                        anyhow::bail!("inspection stays off");
                    }
                }
                let v = call(&paths, json!({"cmd": "inspect-on", "minutes": minutes})).await?;
                let token = v["token"].as_str().unwrap_or_default();
                if quiet {
                    println!("{token}");
                } else {
                    println!(
                        "Inspection is on until {}.",
                        clock(v["until"].as_u64().unwrap_or(0))
                    );
                    println!("Token: {token}");
                    println!("`cardinal inspect off` ends it.");
                }
                Ok(())
            }
            InspectCmd::Off => {
                let v = call(&paths, json!({"cmd": "inspect-off"})).await?;
                if v["was_on"] == true {
                    println!("Inspection is off.");
                } else {
                    println!("Inspection was not on.");
                }
                Ok(())
            }
            InspectCmd::Status => {
                let v = call(&paths, json!({"cmd": "status"})).await?;
                match v["inspection"]["until"].as_u64() {
                    Some(until) => println!("Inspection is on until {}.", clock(until)),
                    None => println!("Inspection is off."),
                }
                Ok(())
            }
        },
        Cmd::Stop => {
            call(&paths, json!({"cmd": "stop"})).await?;
            println!("Stopping the daemon.");
            Ok(())
        }
        Cmd::Daemon { .. } | Cmd::Deploy(_) => unreachable!("handled in main"),
    }
}

/// The time of day of a moment, in milliseconds since 1970.
fn clock(ms: u64) -> String {
    let t = human_time(Some(ms));
    t.get(11..).map_or(t.clone(), str::to_owned)
}

fn secs_ago(s: u64) -> String {
    match s {
        0..=59 => format!("{s} s ago"),
        60..=3599 => format!("{} min ago", s / 60),
        _ => format!("{} h {} min ago", s / 3600, s % 3600 / 60),
    }
}

fn steps(out: &mut String, list: &serde_json::Value) {
    for s in list.as_array().into_iter().flatten() {
        let mark = match s["ok"].as_bool() {
            Some(true) => "ok  ",
            Some(false) => "no  ",
            None => "    ",
        };
        out.push_str(&format!(
            "  {}  {mark}{}\n",
            clock(s["at"].as_u64().unwrap_or(0)),
            printable(s["text"].as_str().unwrap_or(""))
        ));
    }
}

fn reach_lines(out: &mut String, list: &serde_json::Value, whose: &str) {
    let list = list.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        out.push_str("  nothing: no host named, which says nothing either way\n");
        return;
    }
    for r in &list {
        let who = if r["this_device"] == true {
            "this device".to_owned()
        } else if let Some(k) = r["device"].as_str() {
            format!("{whose} device {k}")
        } else {
            "a host that is not one of their devices".to_owned()
        };
        let session = if r["session"] == true {
            ", in touch now"
        } else {
            ""
        };
        let key = if r["device"].is_string() {
            String::new()
        } else {
            format!("  [{}]", r["host"].as_str().unwrap_or(""))
        };
        out.push_str(&format!("  {who}{key}{session}\n"));
        for e in r["endpoints"].as_array().into_iter().flatten() {
            let ep = printable(e["endpoint"].as_str().unwrap_or(""));
            let note = match e["why_not"].as_str() {
                Some(w) => format!("not tried: {w}"),
                None if e["local"] == true => {
                    "used when looking; local, so it works only on that network".into()
                }
                None => "used when looking".into(),
            };
            out.push_str(&format!("      {ep:<28} {note}\n"));
        }
    }
}

/// `cardinal contacts NAME`, in words.
/// What a device that could not be read says, on lines of its own, or
/// nothing.
fn unreadable_line(u: &serde_json::Value) -> String {
    let Some(says) = u["says"].as_str() else {
        return String::new();
    };
    let mut out = format!("      {}\n", printable(says));
    out.push_str(&format!(
        "      ({}; trying again in {})\n",
        printable(u["reason"].as_str().unwrap_or("")),
        secs_ago(u["retry_in_s"].as_u64().unwrap_or(0)).trim_end_matches(" ago")
    ));
    out
}

fn contact_status(v: &serde_json::Value) -> String {
    let mut out = String::new();
    let mut head = printable(v["name"].as_str().unwrap_or(""));
    head.push_str(if v["trusted"] == true {
        "  trusted"
    } else {
        "  through hosts only"
    });
    if v["introductions"] == false {
        head.push_str("  no introductions");
    }
    if v["refused"] == true {
        head.push_str("  refused");
    }
    out.push_str(&format!(
        "{head}  [{}]\n",
        v["identity"].as_str().unwrap_or("")
    ));
    out.push_str("Their devices:\n");
    let devices = v["devices"].as_array().cloned().unwrap_or_default();
    if devices.is_empty() {
        out.push_str("  none known yet\n");
    }
    for dv in &devices {
        let key = dv["key"].as_str().unwrap_or("");
        let kept = if dv["kept_in_touch"] == true {
            "  (kept in touch: you have no host)"
        } else {
            ""
        };
        let unread = unreadable_line(&dv["unreadable"]);
        if dv["online"] != true {
            out.push_str(&format!("  ○ {key}  no session{kept}\n"));
            out.push_str(&unread);
            continue;
        }
        let route = match (
            dv["route"].as_str(),
            dv["addr"].as_str(),
            dv["through"].as_str(),
        ) {
            (Some("relay"), _, Some(t)) => format!("relayed through {t}"),
            (Some("relay"), _, None) => "relayed".to_owned(),
            (_, Some(a), _) => format!("direct  {a}  {}", dv["carrier"].as_str().unwrap_or("")),
            _ => "direct".to_owned(),
        };
        let rtt = dv["rtt_ms"]
            .as_u64()
            .map(|r| format!(", {r} ms"))
            .unwrap_or_default();
        out.push_str(&format!("  ● {key}  {route}{rtt}{kept}\n"));
        out.push_str(&format!(
            "      opened by {} {} ago, heard {} ms ago; sent {}, received {}",
            dv["opened_by"].as_str().unwrap_or("?"),
            secs_ago(dv["open_for_s"].as_u64().unwrap_or(0)).trim_end_matches(" ago"),
            dv["heard_ms_ago"].as_u64().unwrap_or(0),
            human_size(dv["bytes_sent"].as_u64().unwrap_or(0)),
            human_size(dv["bytes_received"].as_u64().unwrap_or(0)),
        ));
        let lost = dv["packets_lost"].as_u64().unwrap_or(0);
        if lost > 0 {
            out.push_str(&format!(", {lost} packets lost"));
        }
        out.push('\n');
        if let Some(a) = dv["they_see_you_at"].as_str() {
            out.push_str(&format!("      they see you at {a}\n"));
        }
        out.push_str(&unread);
    }
    out.push_str("Where they say to find them, in the space you share:\n");
    reach_lines(&mut out, &v["their_reach"], "their");
    out.push_str(&format!(
        "Looked for: {}\n",
        v["looked_for"].as_str().unwrap_or("")
    ));
    if let Some(s) = v["in_use_for_s"].as_u64() {
        out.push_str(&format!(
            "  in use for {} more\n",
            secs_ago(s).trim_end_matches(" ago")
        ));
    }
    match (v["looked_s_ago"].as_u64(), v["looking"] == true) {
        (_, true) => out.push_str("  looking now\n"),
        (Some(s), _) => out.push_str(&format!("  last looked {}\n", secs_ago(s))),
        (None, _) => out.push_str("  not looked for since this service started\n"),
    }
    let looks = v["looks_without_session"].as_u64().unwrap_or(0);
    if looks > 1 {
        if let Some(since) = v["looking_since"].as_u64() {
            out.push_str(&format!(
                "  {looks} looks since {} without a new session\n",
                clock(since)
            ));
        }
    }
    if v["last_look"].as_array().is_some_and(|a| !a.is_empty()) {
        out.push_str("The last look:\n");
        steps(&mut out, &v["last_look"]);
    }
    if v["nearby_tries"].as_array().is_some_and(|a| !a.is_empty()) {
        out.push_str("Where their tag was seen on the local network:\n");
        steps(&mut out, &v["nearby_tries"]);
    }
    if v["sessions"].as_array().is_some_and(|a| !a.is_empty()) {
        out.push_str("Sessions with them since this service started:\n");
        steps(&mut out, &v["sessions"]);
    }
    out.push_str("Where you tell them to find you:\n");
    reach_lines(&mut out, &v["your_reach"], "your");
    if let Some(e) = v["router"]["external"].as_str() {
        out.push_str(&format!("  (your router gives this device {e})\n"));
    }
    out
}

/// `cardinal api-trace`: passes a client's messages on to the daemon and
/// back, and prints each, numbered by connection.
async fn api_trace(paths: &Paths, listen: &std::path::Path) -> anyhow::Result<()> {
    use cardinald::transport::{self, Listener};
    let mut listener = Listener::bind(listen)?;
    eprintln!(
        "Passing {} on to {}. Point a client's CARDINAL_SOCKET at {0}.",
        listen.display(),
        paths.socket.display()
    );
    let mut n = 0u64;
    loop {
        let (cr, cw) = listener.accept().await?;
        n += 1;
        let (sr, sw) = match transport::connect(&paths.socket).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!(
                    "[{n}] the daemon does not answer at {}: {e}",
                    paths.socket.display()
                );
                continue;
            }
        };
        tokio::spawn(trace_connection(n, cr, cw, sr, sw));
    }
}

/// One traced connection: requests one way and replies the other, then a
/// `watch`'s events or a call's frames.
async fn trace_connection(
    n: u64,
    mut cr: cardinald::transport::Reader,
    mut cw: cardinald::transport::Writer,
    mut sr: cardinald::transport::Reader,
    mut sw: cardinald::transport::Writer,
) {
    use cardinald::api::{self, Zero};
    use cardinald::transport::Received;
    // the request a reply answers, and what the connection carries after it
    let mut asked: std::collections::VecDeque<&'static api::Request> = Default::default();
    let mut stream: Option<&'static [api::Request]> = None;
    let bytes = |m: &Received| match m {
        Received::Message(b) => b.clone(),
        Received::TooLarge => Vec::new(),
    };
    loop {
        tokio::select! {
            m = cr.recv() => {
                let Ok(Some(m)) = m else {
                    println!("[{n}] the client closed");
                    return;
                };
                let msg = bytes(&m);
                match stream {
                    Some(t) => println!("[{n}] > {}", api::render_stream(t, &msg)),
                    None => {
                        println!("[{n}] > {}", api::render_request(&msg));
                        let spec = cardinal_encoding::Record::decode(&msg)
                            .ok()
                            .and_then(|r| r.get(0).and_then(cardinal_encoding::Value::as_uint))
                            .and_then(api::by_number);
                        if let Some(spec) = spec {
                            asked.push_back(spec);
                        }
                    }
                }
                if sw.send(&msg).await.is_err() {
                    return;
                }
            }
            m = sr.recv() => {
                let Ok(Some(m)) = m else {
                    println!("[{n}] the daemon closed");
                    return;
                };
                let msg = bytes(&m);
                match (stream, asked.pop_front()) {
                    (Some(t), _) => println!("[{n}] < {}", api::render_stream(t, &msg)),
                    (None, Some(spec)) => {
                        println!("[{n}] < {}", api::render_reply(spec, &msg));
                        let ok = cardinal_encoding::Record::decode(&msg)
                            .ok()
                            .and_then(|r| r.get(0).and_then(cardinal_encoding::Value::as_uint))
                            == Some(api::status::OK);
                        stream = match spec.name {
                            "watch" if ok => Some(api::EVENTS),
                            "call-media" if ok => Some(api::FRAMES),
                            _ => None,
                        };
                    }
                    (None, None) => println!("[{n}] < {}", api::render(&msg, Zero::Status, &[], 2)),
                }
                if cw.send(&msg).await.is_err() {
                    return;
                }
            }
        }
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
                "Copies: 3 — this device, saint-joseph, nuc (files older than an hour, \
                 spot-checked 4 minutes ago)"
            ]
        );
        // One missing pieces, one offline for a day: per-device ages, and
        // why.
        let mixed = c(vec![
            holder("carbonite", true, "passed", Some(now - 1000)),
            holder("saint-joseph", false, "passed", Some(now - 60_000)),
            {
                let mut h = holder("laptop", false, "passed", Some(now - 7_200_000));
                h["online"] = json!(false);
                h
            },
            failed_holder(now),
        ]);
        assert_eq!(
            copies_lines(&mixed, 4),
            vec![
                "Copies: 3 — this device, saint-joseph (spot-checked 1 minute ago), laptop \
                 (spot-checked 2 hours ago); files older than an hour",
                "  nuc: not counted — not confirmed: did not answer its last check (not within \
                 4 s) (2 minutes ago)"
            ]
        );
        // Only this device, another catching up.
        let one = c(vec![
            holder("carbonite", true, "passed", Some(now - 1000)),
            failed_holder(now),
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

    fn failed_holder(now: u64) -> Value {
        let mut h = holder("nuc", false, "unconfirmed", Some(now - 3_000_000));
        h["reason"] = json!("did not answer its last check (not within 4 s)");
        h["last_check"] = json!(now - 120_000);
        h
    }

    #[test]
    fn speedtest_line() {
        let v = json!({"device": "saint-joseph", "receive": 38_200_000u64,
            "send": 36_900_000u64, "rtt_min_us": 420, "rtt_median_us": 610});
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
