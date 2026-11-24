//! The local interface (`apps.md#the-local-interface`): one request per
//! message and one reply per message, each a record in the base encoding,
//! over a channel only the user who runs the daemon can open
//! (`transport.rs`). `api` turns messages into the named form the
//! handlers here take and give.
//!
//! After `watch`, a connection only carries news, an event `changed` with
//! the count of changes, until the client closes it. A window says
//! `window` with it: while one watches, Cardinal is open, and Bluetooth set
//! to `open` is on (`bluetooth.rs`). After `call-media` it carries a call's
//! frames (`calls.rs`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cardinal_identity::Power;
use cardinal_space::account;
use cardinal_space::files::{self, Content, Files, FILE_CONTENT};
use cardinal_space::state::State;
use cardinal_space::{NodeId, SpaceId, SpaceOpBody, ROOT};
use serde_json::{json, Value};

use crate::api::{self, status};
use crate::core::short;
use crate::daemon::{Daemon, PairState};
use crate::net;
use crate::transport::{self, Listener, Reader, Received, Writer, MAX_MESSAGE};

/// The version of this interface. A client compares it with `hello`'s.
/// 2: the base encoding, with numbered fields, in place of lines of JSON.
const API: u64 = 2;
/// How long news waits, so that a burst of changes is one event.
const NEWS_GATHERS: Duration = Duration::from_millis(100);

/// Whether [`request`] shows each request and reply on standard error, in
/// the text rendering with the tables' names (`cardinal --trace`).
static TRACE: AtomicBool = AtomicBool::new(false);

/// Shows every request [`request`] sends, and its reply, on standard error.
pub fn trace(on: bool) {
    TRACE.store(on, Ordering::Relaxed);
}

/// Sends a request to a running daemon and returns its reply. Both are by
/// name: `req` names the request in `cmd`, and the reply has `ok`, and
/// `error` when it is not. A request whose answer comes in pages is asked
/// for page after page, and the reply holds every page's items, unless
/// `req` asks for one page itself, with `limit`, `after` or `before`.
pub async fn request(socket: &std::path::Path, req: &Value) -> anyhow::Result<Value> {
    let name = req.get("cmd").and_then(Value::as_str).unwrap_or("");
    let one = ["limit", "after", "before"]
        .iter()
        .any(|k| req.get(*k).is_some_and(|v| !v.is_null()));
    let page = match api::by_name(name) {
        Some(spec) if !one => spec.page,
        _ => api::Page::Whole,
    };
    let mut all = request_one(socket, req).await?;
    if page == api::Page::Whole {
        return Ok(all);
    }
    let spec = api::by_name(name).expect("paged above");
    let lists: Vec<&'static str> = match page {
        api::Page::Before { list } => vec![list],
        _ => spec
            .reply
            .iter()
            .filter(|f| matches!(f.ty, api::Ty::List(_) | api::Ty::Recs(_)))
            .map(|f| f.name)
            .collect(),
    };
    let mut next_req = req.clone();
    while all["ok"] == true && all["more"] == true {
        let Some(next) = all.get("next").cloned() else {
            break;
        };
        let cursor = match page {
            api::Page::Before { .. } => "before",
            _ => "after",
        };
        next_req[cursor] = next;
        let more = request_one(socket, &next_req).await?;
        if more["ok"] != true {
            return Ok(more);
        }
        let mut grew = false;
        for l in &lists {
            let got = more[*l].as_array().cloned().unwrap_or_default();
            grew |= !got.is_empty();
            let had = all[*l].as_array().cloned().unwrap_or_default();
            all[*l] = match page {
                api::Page::Before { .. } => json!(got.into_iter().chain(had).collect::<Vec<_>>()),
                _ => json!(had.into_iter().chain(got).collect::<Vec<_>>()),
            };
        }
        all["more"] = more["more"].clone();
        all["next"] = more["next"].clone();
        if !grew {
            break;
        }
    }
    if let Some(o) = all.as_object_mut() {
        o.remove("more");
        o.remove("next");
    }
    Ok(all)
}

/// [`request`], one page of it.
async fn request_one(socket: &std::path::Path, req: &Value) -> anyhow::Result<Value> {
    let (spec, msg) = api::encode_request(req)?;
    let tracing = TRACE.load(Ordering::Relaxed);
    if tracing {
        eprintln!("> {}", api::render_request(&msg));
    }
    let (mut r, mut w) = transport::connect(socket).await?;
    w.send(&msg).await?;
    let reply = match r.recv().await? {
        Some(Received::Message(m)) => m,
        Some(Received::TooLarge) => anyhow::bail!("the daemon's reply was larger than a message"),
        None => anyhow::bail!("the daemon closed the connection"),
    };
    if tracing {
        eprintln!("< {}", api::render_reply(spec, &reply));
    }
    api::decode_reply(spec, &reply)
}

/// Starts serving the local interface.
pub fn serve(d: Arc<Daemon>) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let mut listener = Listener::bind(&d.paths.socket)
        .map_err(|e| anyhow::anyhow!("{e:#} for {}", d.paths.home.display()))?;
    Ok(tokio::spawn(async move {
        loop {
            let Ok((r, w)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(connection(d.clone(), r, w));
        }
    }))
}

/// Answers one connection's requests in turn, until it closes or becomes a
/// stream.
async fn connection(d: Arc<Daemon>, mut r: Reader, mut w: Writer) {
    while let Ok(Some(got)) = r.recv().await {
        let msg = match got {
            Received::Message(m) => m,
            Received::TooLarge => {
                let why = format!("a message is at most {MAX_MESSAGE} bytes");
                if w.send(&api::error_reply(status::MALFORMED, &why))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
        };
        let (spec, req) = match api::decode_request(&msg) {
            Ok(x) => x,
            Err(refused) => {
                if w.send(&api::error_reply(refused.status, &refused.why))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
        };
        match spec.name {
            "watch" => {
                // A window watching: "on while open" is on while it does.
                let window = req["window"].as_bool() == Some(true);
                let _window = window.then(|| crate::bluetooth::window(&d));
                if w.send(&api::encode_reply(spec, Ok(&json!({}))))
                    .await
                    .is_ok()
                {
                    watch(&d, r, w).await;
                }
                return;
            }
            "call-media" => {
                crate::calls::media(&d, spec, r, w).await;
                return;
            }
            _ => {}
        }
        let reply = match handle(&d, &req).await.map_err(|e| capitalized(&req, e)) {
            Ok(v) => match api::page(spec, &req, v) {
                Ok(v) => api::encode_reply(spec, Ok(&v)),
                Err((st, why, item)) => api::error_reply_with(st, &why, &item),
            },
            Err(e) => {
                let st = if e.is::<crate::recovery::NeedsWords>() {
                    status::NEEDS_WORDS
                } else if e.is::<crate::contacts::NeedsFor>() {
                    status::NEEDS_FOR
                } else {
                    status::FAILED
                };
                api::encode_reply(spec, Err((st, &format!("{e:#}"))))
            }
        };
        let reply = if reply.len() > MAX_MESSAGE {
            let why = format!(
                "the answer to {} would be {} bytes, and a message is at most {MAX_MESSAGE}",
                spec.name,
                reply.len()
            );
            api::error_reply(status::TOO_LARGE, &why)
        } else {
            reply
        };
        if w.send(&reply).await.is_err() {
            return;
        }
    }
}

/// An error of the guardians' and recovery requests, starting with a
/// capital letter, as a window shows it word for word. Others are as
/// they were.
fn capitalized(req: &Value, e: anyhow::Error) -> anyhow::Error {
    let cmd = req["cmd"].as_str().unwrap_or("");
    let ours = cmd.starts_with("guardians")
        || cmd.starts_with("guarding")
        || cmd.starts_with("recover-")
        || cmd == "recover"
        || cmd == "accept";
    if !ours || e.is::<crate::recovery::NeedsWords>() || e.is::<crate::contacts::NeedsFor>() {
        return e;
    }
    let text = format!("{e:#}");
    let mut c = text.chars();
    match c.next() {
        Some(f) if f.is_lowercase() => anyhow::anyhow!("{}{}", f.to_uppercase(), c.as_str()),
        _ => e,
    }
}

/// Tells a client each time something changed, until it goes. An event says
/// only that there is news, and the client asks for what it shows, so one that
/// is missed, or two that come as one, lose nothing.
async fn watch(d: &Daemon, mut r: Reader, mut w: Writer) {
    let mut changed = d.changed.subscribe();
    let mut stopping = d.stopping.subscribe();
    loop {
        let seq = *changed.borrow_and_update();
        if w.send(&api::event_message(seq)).await.is_err() {
            return;
        }
        loop {
            tokio::select! {
                c = changed.changed() => match c {
                    Ok(()) => break,
                    Err(_) => return,
                },
                _ = stopping.changed() => return,
                m = r.recv() => match m {
                    Ok(Some(_)) => continue,
                    _ => return,
                },
            }
        }
        tokio::time::sleep(NEWS_GATHERS).await;
    }
}

/// A field that is a list of text, or nothing.
fn strings(req: &Value, name: &str) -> Vec<String> {
    let list = req.get(name).and_then(|v| v.as_array());
    let items = list.into_iter().flatten();
    items
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect()
}

/// What a client knows of this device's power and network
/// (`apps.md#the-local-interface`), and what the service makes of it.
fn conditions(d: &Arc<Daemon>, req: &Value) -> anyhow::Result<Value> {
    let flag = |name| req.get(name).and_then(|v| v.as_bool());
    if let Some(plugged_in) = flag("plugged_in") {
        let metered = flag("metered").unwrap_or(false);
        d.conditions.tell(crate::conditions::Told {
            plugged_in,
            metered,
        });
        d.bump();
    }
    Ok(d.conditions.json())
}

/// The formats a window offers or takes, as hex names (`formats`), or by
/// their draft short names (`format_names`, such as "video vp8 1").
fn formats(req: &Value) -> anyhow::Result<Option<Vec<crate::calls::Format>>> {
    if let Some(names) = req.get("format_names").and_then(|v| v.as_array()) {
        let names = names.iter().filter_map(|n| n.as_str());
        return Ok(Some(names.map(crate::calls::draft_format).collect()));
    }
    let Some(list) = req.get("formats").and_then(|v| v.as_array()) else {
        return Ok(None);
    };
    list.iter()
        .map(|f| {
            let bytes = f.as_str().and_then(|h| hex::decode(h).ok());
            bytes
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("a format is 32 bytes of hex"))
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map(Some)
}

/// A space held here, by its id in hex or the start of it.
fn space_held(d: &Daemon, s: &str) -> anyhow::Result<cardinal_space::SpaceId> {
    let s = crate::api::id_hex(s).trim().to_ascii_lowercase();
    let core = d.core();
    let found: Vec<cardinal_space::SpaceId> = core
        .spaces
        .keys()
        .filter(|id| hex::encode(id).starts_with(&s))
        .copied()
        .collect();
    match found[..] {
        [one] if !s.is_empty() => Ok(one),
        [] => anyhow::bail!("no space held here has the id {s}"),
        _ => anyhow::bail!("more than one space held here starts with {s}: give more of its id"),
    }
}

fn arg<'a>(req: &'a Value, name: &str) -> anyhow::Result<&'a str> {
    req.get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing argument {name}"))
}

/// How someone added by this request starts out.
fn regard(req: &Value) -> account::Regard {
    let says = |name| req.get(name).and_then(|v| v.as_bool()) == Some(true);
    account::Regard {
        trusted: !says("hosts_only"),
        introductions: !says("no_introductions"),
    }
}

/// The power a pairing joins this device at, as `pair-status` says it:
/// `device` or `admin`, as the admin device named it.
fn joins_as(p: Option<cardinal_identity::Power>) -> Value {
    match p {
        Some(cardinal_identity::Power::Admin) => json!("admin"),
        Some(cardinal_identity::Power::Device) => json!("device"),
        _ => Value::Null,
    }
}

fn power_name(p: Power) -> &'static str {
    match p {
        Power::Device => "device",
        Power::Admin => "admin",
        Power::Root => "root",
    }
}

/// The path of a node in a files space's state.
pub fn node_path(st: &State, node: &NodeId) -> String {
    let mut parts = Vec::new();
    let mut cur = *node;
    for _ in 0..10_000 {
        if cur == ROOT {
            break;
        }
        let Some(n) = st.node(&cur) else { break };
        parts.push(n.name.clone());
        cur = n.parent;
    }
    parts.reverse();
    parts.join("/")
}

fn require_files(d: &Daemon) -> anyhow::Result<[u8; 32]> {
    let core = d.core();
    if core.identity.is_none() {
        anyhow::bail!(
            "this device does not belong to anyone yet: run `cardinal init` or `cardinal pair`"
        );
    }
    core.files_id().ok_or_else(|| {
        anyhow::anyhow!("your files have not arrived on this device yet; wait for it to sync")
    })
}

async fn handle(d: &Arc<Daemon>, req: &Value) -> anyhow::Result<Value> {
    let cmd = arg(req, "cmd")?;
    match cmd {
        "hello" => Ok(json!({"api": API, "version": env!("CARGO_PKG_VERSION")})),
        "setup-begin" => setup_begin(d),
        "setup-finish" => setup_finish(d, req),
        "me" => crate::names::me(d, req.get("name").and_then(|v| v.as_str())),
        "status" => Ok(status(d)),
        // Inspection (`inspect.rs`): the person turns it on, on this
        // device, and only whoever holds the token it gives may look.
        "inspect-on" => {
            let minutes = req.get("minutes").and_then(Value::as_u64);
            let (token, until) = d
                .inspection
                .grant(minutes.unwrap_or(crate::inspect::DEFAULT_MINUTES))?;
            d.bump();
            Ok(json!({"token": token, "until": until}))
        }
        "inspect-off" => {
            let was = d.inspection.revoke();
            d.bump();
            Ok(json!({"was_on": was}))
        }
        // One request for each view, which `inspect.rs` tells by `what`.
        "inspect" | "inspect-identity" | "inspect-space" | "inspect-entries" | "inspect-entry"
        | "inspect-nodes" | "inspect-node" => {
            d.inspection
                .check(req.get("token").and_then(Value::as_str))?;
            let mut req = req.clone();
            req["what"] = json!(cmd.strip_prefix("inspect-").unwrap_or("overview"));
            crate::inspect::handle(d, &req)
        }
        "devices" => Ok(json!({"devices": devices(d)})),
        "stop" => {
            let _ = d.stopping.send(true);
            Ok(json!({}))
        }
        "reload" => {
            reload(d)?;
            Ok(json!({}))
        }
        "network-changed" => {
            Ok(d.network_changed(req.get("why").and_then(|v| v.as_str()).unwrap_or("told")))
        }
        // The device woke (D86): what a network change does, said by
        // whatever sees it wake, as Android does for the app.
        "wake" => Ok(d.network_changed("woke")),
        "flush" => {
            let d2 = d.clone();
            let n = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
                let m = d2.mount.lock().unwrap_or_else(|e| e.into_inner());
                match m.as_ref() {
                    Some(m) => m.flush(),
                    None => Ok(0),
                }
            })
            .await??;
            Ok(json!({"entries": n}))
        }
        "pair-show" => {
            // what to call this device, where the window knows better
            if let Some(name) = device_name(req)? {
                rename_this_device(d, &name)?;
            }
            let s = crate::pair::show(d).await?;
            Ok(
                json!({"code": s.code, "addrs": s.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>() }),
            )
        }
        "pair-status" => {
            let ps = d.pairing.lock().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(match ps {
                PairState::Idle => json!({"state": "idle"}),
                PairState::Showing { code } => json!({"state": "showing", "code": code}),
                PairState::Joining {
                    admin_name, power, ..
                } => {
                    json!({"state": "joining", "admin": admin_name, "power": joins_as(power)})
                }
                PairState::Joined { admin_name, power } => {
                    let files = d.core().files_id().is_some();
                    json!({"state": "joined", "admin": admin_name, "files": files,
                        "power": joins_as(power)})
                }
                PairState::Failed(e) => json!({"state": "failed", "error": e}),
            })
        }
        "pair-type" => {
            let code = arg(req, "code")?;
            let at = match req.get("at").and_then(|v| v.as_str()) {
                Some(a) => Some(
                    tokio::net::lookup_host(a)
                        .await
                        .ok()
                        .and_then(|mut i| i.next())
                        .ok_or_else(|| anyhow::anyhow!("{a} is not an address (ip:port)"))?,
                ),
                None => None,
            };
            let admin = req.get("admin").and_then(|v| v.as_bool()).unwrap_or(false);
            let device = device_name(req)?;
            let name =
                crate::pair::type_code(d, code, at, admin, words(req), device.as_deref()).await?;
            Ok(json!({"name": name}))
        }
        "device-rename" => rename_device(d, arg(req, "device")?, arg(req, "name")?),
        "remove-device" => {
            let lost = req.get("lost").and_then(|v| v.as_bool()).unwrap_or(false);
            remove_device(d, arg(req, "who")?, words(req), lost).await
        }
        "invite" => {
            let address = req.get("address").and_then(|v| v.as_str());
            let name = req.get("name").and_then(|v| v.as_str());
            crate::contacts::invite(d, address, name, regard(req))
        }
        "accept" => {
            let name = req.get("name").and_then(|v| v.as_str());
            let met = cardinal_space::account::Met {
                how: cardinal_space::account::MET_THEIR_INVITATION,
                via: req.get("via").and_then(|v| v.as_str()).map(str::to_owned),
                ..Default::default()
            };
            // the person's own accept: the only one that takes a recovery's;
            // `for`, whom a recovery invitation made for whomever this
            // guardian names is for, as their contacts call them
            let whom = match req.get("for").and_then(Value::as_str) {
                Some(w) => Some(crate::contacts::find(d, w)?.identity),
                None => None,
            };
            crate::contacts::accept_for(d, arg(req, "code")?, name, regard(req), met, true, whom)
                .await
        }
        "invitations" => Ok(crate::contacts::invitations(d)),
        "cancel-invitation" => crate::contacts::cancel_invitation(d, arg(req, "id")?),
        "contact-status" => {
            // looking is done with the first page, never again for the next
            let first = req.get("after").and_then(Value::as_u64).unwrap_or(0) == 0;
            let look = first && req.get("look").and_then(|v| v.as_bool()) == Some(true);
            let at = match req.get("at").and_then(|v| v.as_str()).filter(|_| first) {
                Some(a) => Some(a.parse().map_err(|_| {
                    anyhow::anyhow!("{a} is not an address; it looks like 192.168.1.20:7171")
                })?),
                None => None,
            };
            crate::contacts::status(d, arg(req, "who")?, look, at).await
        }
        "contacts" => {
            let all = req.get("all").and_then(|v| v.as_bool()) == Some(true);
            Ok(crate::contacts::list(d, all))
        }
        "contact" => match (
            req.get("name").and_then(|v| v.as_str()),
            req.get("category").and_then(|v| v.as_str()),
        ) {
            (Some(name), _) => crate::contacts::rename(d, arg(req, "who")?, name),
            (None, _) if req.get("picture").is_some() => {
                let from = req.get("picture").and_then(|v| v.as_str()).unwrap_or("");
                crate::names::set_picture(d, arg(req, "who")?, from).await
            }
            (None, Some(category)) => crate::contacts::set_category(d, arg(req, "who")?, category),
            (None, None) => match arg(req, "setting")? {
                "name-hosts" => crate::contacts::name_hosts(d, arg(req, "who")?, true).await,
                "no-hosts" => crate::contacts::name_hosts(d, arg(req, "who")?, false).await,
                "no-host" => crate::contacts::no_host(d, arg(req, "who")?, arg(req, "host")?).await,
                setting => crate::contacts::set(d, arg(req, "who")?, setting),
            },
        },
        "say" if req.get("group").is_some() => {
            let reply_to = req.get("reply_to").and_then(|v| v.as_str());
            let attach = strings(req, "attach");
            crate::groups::say(d, arg(req, "group")?, arg(req, "text")?, reply_to, &attach).await
        }
        "messages" if req.get("group").is_some() => crate::groups::messages(
            d,
            arg(req, "group")?,
            req.get("before").and_then(Value::as_str),
        ),
        "mark-read" if req.get("group").is_some() => {
            crate::groups::mark_read(d, arg(req, "group")?)
        }
        "react" if req.get("group").is_some() => {
            crate::groups::react(d, arg(req, "group")?, arg(req, "id")?, arg(req, "text")?)
        }
        "edit-message" if req.get("group").is_some() => {
            crate::groups::edit_message(d, arg(req, "group")?, arg(req, "id")?, arg(req, "text")?)
        }
        "delete-message" if req.get("group").is_some() => {
            crate::groups::delete_message(d, arg(req, "group")?, arg(req, "id")?)
        }
        "groups" => Ok(crate::groups::list(d)),
        "introductions" => Ok(crate::introductions::list(d)),
        "introduce" => {
            let note = req.get("note").and_then(|v| v.as_str());
            crate::introductions::introduce(d, arg(req, "who")?, arg(req, "to")?, note)
        }
        "introduction-accept" => crate::introductions::accept(d, arg(req, "id")?).await,
        "introduction-decline" => crate::introductions::decline(d, arg(req, "id")?),
        "group-connect" => {
            let note = req.get("note").and_then(|v| v.as_str());
            crate::introductions::ask_in_group(d, arg(req, "group")?, arg(req, "who")?, note)
        }
        "group-create" => crate::groups::create(d, arg(req, "name")?, &strings(req, "people")),
        "group-add" => {
            let shown = req.get("shown").and_then(|v| v.as_str());
            crate::groups::add(d, arg(req, "group")?, &strings(req, "people"), shown)
        }
        "group-remove" => crate::groups::remove(d, arg(req, "group")?, arg(req, "who")?).await,
        "group-role" => {
            let (group, who) = (arg(req, "group")?, arg(req, "who")?);
            crate::groups::set_role(d, group, who, arg(req, "role")?).await
        }
        "group-post-again" => crate::groups::post_again(d, arg(req, "group")?),
        "group-moved-seen" => crate::groups::moved_seen(d, arg(req, "group")?),
        "group-confirm-move" => crate::groups::confirm_move(
            d,
            arg(req, "group")?,
            &strings(req, "moves"),
            &strings(req, "to"),
        ),
        "group-leave" => crate::groups::leave(d, arg(req, "group")?),
        "group-join" => {
            let reach = answer_in(req, "reach")?;
            crate::groups::join(d, arg(req, "group")?, reach).await
        }
        "group-reach" => {
            let share = req.get("share").and_then(|v| v.as_bool());
            let share = share.ok_or_else(|| anyhow::anyhow!("say whether to share: share"))?;
            match req.get("host").and_then(|v| v.as_str()) {
                Some(host) if !share => crate::groups::no_host(d, arg(req, "group")?, host).await,
                Some(_) => anyhow::bail!("a host is taken out with share false"),
                None => crate::groups::set_reach(d, arg(req, "group")?, share).await,
            }
        }
        "group-decline" => crate::groups::decline(d, arg(req, "group")?),
        "group-members" => crate::groups::members(d, arg(req, "group")?),
        "group-set" => {
            let name = req.get("name").and_then(|v| v.as_str());
            let introductions = req.get("introductions").and_then(|v| v.as_bool());
            crate::groups::set(d, arg(req, "group")?, name, introductions)
        }
        "group-member" => {
            let shown = req.get("shown").and_then(|v| v.as_str());
            let introduce = req.get("introduce").and_then(|v| v.as_bool());
            crate::groups::set_member(d, arg(req, "group")?, arg(req, "who")?, shown, introduce)
        }
        "say" => {
            let reply_to = req.get("reply_to").and_then(|v| v.as_str());
            let attach: Vec<String> = req
                .get("attach")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|p| p.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            crate::contacts::say(d, arg(req, "who")?, arg(req, "text")?, reply_to, &attach).await
        }
        "save-attachment" if req.get("group").is_some() => {
            let index = req.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let (group, id, to) = (arg(req, "group")?, arg(req, "id")?, arg(req, "to")?);
            crate::groups::save_attachment(d, group, id, index, to).await
        }
        "save-attachment" => {
            let index = req.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let (who, id, to) = (arg(req, "who")?, arg(req, "id")?, arg(req, "to")?);
            crate::contacts::save_attachment(d, who, id, index, to).await
        }
        "edit-message" => {
            crate::contacts::edit_message(d, arg(req, "who")?, arg(req, "id")?, arg(req, "text")?)
        }
        "delete-message" => crate::contacts::delete_message(d, arg(req, "who")?, arg(req, "id")?),
        "react" => crate::contacts::react(d, arg(req, "who")?, arg(req, "id")?, arg(req, "text")?),
        "call" => Ok(crate::calls::current(d)),
        "conditions" => conditions(d, req),
        "call-start" if req.get("group").is_some() => {
            crate::calls::start_group(d, arg(req, "group")?).await
        }
        "call-start" => crate::calls::start(d, arg(req, "who")?, formats(req)?).await,
        "clip-copy" => crate::clipboard::copy(d, arg(req, "text")?).await,
        "clip" => Ok(crate::clipboard::paste(d)),
        // What programs ask through the application interface, and the
        // person's approvals (`apps.rs`).
        "app-questions" => Ok(crate::apps::questions(d)),
        "app-answer" => crate::apps::answer(d, req),
        "approvals" => Ok(crate::apps::list_approvals(d)),
        "approval-revoke" => crate::apps::revoke(d, arg(req, "id")?),
        "app-offers" => Ok(crate::apps::list_offers(d)),
        "app-join" => crate::apps::join(d, arg(req, "space")?),
        "call-answer" => crate::calls::answer(d, formats(req)?).await,
        "call-end" => crate::calls::end(d).await,
        "conversations" => Ok(crate::contacts::conversations(d)),
        "mark-read" => crate::contacts::mark_read(d, arg(req, "who")?),
        "read-markers" => {
            let on = req.get("on").and_then(|v| v.as_bool());
            crate::settings::read_markers(d, on)
        }
        "files" => crate::onefolder::list(d, req.get("path").and_then(Value::as_str).unwrap_or("")),
        "mkdir" => crate::onefolder::mkdir(d, arg(req, "path")?),
        "move" => crate::onefolder::move_to(d, arg(req, "from")?, arg(req, "to")?).await,
        "remove" => crate::onefolder::remove(d, arg(req, "path")?),
        "copy" => crate::onefolder::copy(d, arg(req, "from")?, arg(req, "to")?).await,
        "put" => crate::onefolder::put(d, arg(req, "from")?, arg(req, "to")?).await,
        "save" => crate::onefolder::save(d, arg(req, "path")?, arg(req, "to")?).await,
        "write" => crate::onefolder::write(d, arg(req, "from")?, arg(req, "path")?).await,
        "share" => {
            let paths: Vec<String> = req
                .get("paths")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|p| p.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let text = req.get("text").and_then(|v| v.as_str());
            let who = req.get("who").and_then(|v| v.as_str());
            let group = req.get("group").and_then(|v| v.as_str());
            crate::onefolder::share(d, who, group, &paths, text).await
        }
        "messages" => crate::contacts::messages(
            d,
            arg(req, "who")?,
            req.get("before").and_then(Value::as_str),
        ),
        "recovery-check" => {
            crate::recovery::root_from_words(d, arg(req, "words")?)?;
            Ok(json!({}))
        }
        "host" => {
            let addresses: Vec<String> = req
                .get("addresses")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            crate::host::enable(d, &addresses)
        }
        "host-off" => crate::host::disable(d),
        "host-offer" => {
            let devices = strings(req, "devices");
            let n = |k: &str| req.get(k).and_then(|v| v.as_u64());
            crate::hosting::offer(d, arg(req, "who")?, &devices, n("envelopes"), n("relay_mb"))
        }
        "host-accept" => crate::hosting::accept(d, arg(req, "who")?),
        "host-end" => crate::hosting::end(d, arg(req, "who")?),
        "hosting" => Ok(crate::hosting::list(d)),
        "router" => {
            if let Some(on) = req.get("on").and_then(|v| v.as_bool()) {
                let here = req.get("this_device").and_then(|v| v.as_bool()) == Some(true);
                crate::portmap::set_on(d, on, here)?;
            }
            Ok(crate::portmap::status(d))
        }
        "bluetooth" => match req.get("mode").and_then(|v| v.as_str()) {
            Some(m) => {
                let m = crate::bluetooth::Mode::parse(m)
                    .ok_or_else(|| anyhow::anyhow!("Bluetooth is `off`, `open` or `always`"))?;
                crate::bluetooth::set(d, m)
            }
            None => Ok(crate::bluetooth::check(d).await),
        },
        "network" => match req.get("mine").and_then(|v| v.as_bool()) {
            Some(mine) => {
                let name = req.get("name").and_then(|v| v.as_str());
                crate::networks::mark(d, mine, name)
            }
            None => Ok(crate::networks::status(d)),
        },
        "recovery-sheet" => crate::host::sheet(d),
        "guardians" => crate::guardians::show(d),
        "guardians-set" => crate::guardians::set(
            d,
            &strings(req, "who"),
            req.get("threshold").and_then(Value::as_u64),
            req.get("delay").and_then(Value::as_u64),
            words(req),
        ),
        "guardians-object" => {
            crate::guardians::object(d, req.get("fingerprint").and_then(Value::as_str))
        }
        "guarding" => Ok(crate::guardians::list(d)),
        "guarding-invite" => {
            crate::guardians::invite(d, arg(req, "who")?, req.get("at").and_then(Value::as_str))
                .await
        }
        "guarding-accept" => crate::guardians::accept_role(d, arg(req, "who")?).await,
        "guardians-ask" => crate::guardians::ask(d, arg(req, "who")?),
        "guarding-confirm-change" => {
            let understood = req.get("understood").and_then(Value::as_bool) == Some(true);
            let fp = req.get("fingerprint").and_then(Value::as_str);
            crate::guardians::confirm_change(d, arg(req, "who")?, fp, understood).await
        }
        "guarding-never" => crate::guardians::never(d, arg(req, "who")?, arg(req, "fingerprint")?),
        "guarding-caution" => crate::guardians::caution_for(d, arg(req, "who")?),
        "guarding-endorse" => {
            let understood = req.get("understood").and_then(Value::as_bool) == Some(true);
            crate::guardians::endorse(d, arg(req, "who")?, arg(req, "fingerprint")?, understood)
                .await
        }
        "guarding-confirm" => {
            let understood = req.get("understood").and_then(Value::as_bool) == Some(true);
            crate::guardians::confirm(d, arg(req, "who")?, arg(req, "fingerprint")?, understood)
                .await
        }
        "recover" => crate::recovering::status(d),
        "keep-work" => crate::recovering::keep_work(
            d,
            arg(req, "name")?,
            req.get("up_to").and_then(Value::as_str),
        ),
        "recover-start" => {
            let opt = |k: &str| req.get(k).and_then(Value::as_str);
            crate::recovering::start(d, opt("code"), opt("identity")).await
        }
        "recover-invite" => {
            crate::recovering::invite(d, req.get("at").and_then(Value::as_str)).await
        }
        "recover-lost-at" => {
            crate::recovering::set_lost_at(d, req.get("lost_at").and_then(Value::as_u64))
        }
        "recover-cancel" => crate::recovering::cancel(d).await,
        "recover-undo" => crate::recovering::undo_kept(d, arg(req, "to")?).await,
        "recover-kept-seen" => crate::recovering::kept_seen(d, &strings(req, "to")),
        "recover-finish" => {
            let without = req.get("without_account").and_then(Value::as_bool) == Some(true);
            let lost_at = req.get("lost_at").and_then(Value::as_u64);
            crate::recovering::finish(d, without, lost_at).await
        }
        "restore-from-host" => {
            crate::host::restore(d, arg(req, "words")?, arg(req, "at")?, arg(req, "key")?).await
        }
        "peer-add" => {
            let addr = arg(req, "addr")?.trim().to_owned();
            if !addr.contains(':') {
                anyhow::bail!("give the address as host:port, e.g. myserver.example.com:7171");
            }
            {
                let mut c = d.config();
                if !c.peers.contains(&addr) {
                    c.peers.push(addr.clone());
                }
            }
            d.save_config()?;
            let d2 = d.clone();
            tokio::spawn(async move { d2.connect_all().await });
            Ok(json!({"addr": addr}))
        }
        "peer-remove" => {
            let addr = arg(req, "addr")?;
            let found = {
                let mut c = d.config();
                let before = c.peers.len();
                c.peers.retain(|p| p != addr);
                before != c.peers.len()
            };
            if !found {
                anyhow::bail!("{addr} is not in the list; see `cardinal peer list`");
            }
            d.book
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .manual
                .remove(addr);
            d.save_config()?;
            Ok(json!({}))
        }
        "peer-list" => {
            let peers = d.config().peers.clone();
            let book = d.book.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let names = d.core().device_names();
            let list: Vec<Value> = peers
                .iter()
                .map(|p| {
                    let dev = book.manual.get(p).and_then(|h| {
                        let b = hex::decode(h).ok()?;
                        <[u8; 32]>::try_from(&b[..]).ok()
                    });
                    json!({
                        "addr": p,
                        "device": dev.map(|k| names.get(&k).cloned().unwrap_or_else(|| account::short_key(&k))),
                    })
                })
                .collect();
            Ok(json!({"peers": list}))
        }
        "mount" => {
            let path = req
                .get("path")
                .and_then(|v| v.as_str())
                .map(std::path::PathBuf::from)
                .or_else(|| d.config().mount.clone())
                .unwrap_or_else(|| crate::paths::home_dir().join("Cardinal"));
            let d2 = d.clone();
            let p2 = path.clone();
            tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                d2.unmount();
                {
                    let mut c = d2.config();
                    c.mount = Some(p2.clone());
                    c.this_run.no_mount = false;
                }
                d2.save_config()?;
                if d2.core().files_id().is_none() {
                    return Ok(());
                }
                if let Err(e) = crate::daemon::fuse_usable() {
                    anyhow::bail!("cannot mount: FUSE is not available here ({e})");
                }
                d2.ensure_mounted();
                if d2.mount.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
                    anyhow::bail!("could not mount at {}; see `cardinal log`", p2.display());
                }
                Ok(())
            })
            .await??;
            Ok(json!({"path": path}))
        }
        "unmount" => {
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || {
                d2.unmount();
                d2.config().mount = None;
                d2.save_config()
            })
            .await??;
            Ok(json!({}))
        }
        "conflicts" => conflicts(d),
        "debug-tree" => debug_tree(d),
        "free-space" if req.get("unnamed").and_then(|v| v.as_bool()) == Some(true) => {
            let delete = req.get("delete").and_then(|v| v.as_bool()) == Some(true);
            let d2 = d.clone();
            let found = tokio::task::spawn_blocking(move || crate::cleanup::unnamed(&d2, delete));
            let found = found.await??;
            Ok(json!({
                "objects": found.objects,
                "bytes": found.bytes,
                "deleted": found.deleted,
                "unsure": found.unsure,
            }))
        }
        "free-space" => {
            let dry_run = req
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let d2 = d.clone();
            let f = tokio::task::spawn_blocking(move || crate::cleanup::pass(&d2, true, dry_run))
                .await??;
            Ok(json!({
                "objects": f.objects,
                "bytes": f.bytes,
                "left": f.left,
                "only_here": crate::cleanup::status(d)["only_here"],
                "unchecked": crate::cleanup::status(d)["unchecked"],
            }))
        }
        "space-usage" => {
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || crate::cleanup::usage_of(&d2)).await?
        }
        "history-empty" => {
            let empty = match req.get("space").and_then(Value::as_str) {
                None | Some("") => crate::cleanup::Empty::All,
                Some(s) => crate::cleanup::Empty::Space(space_held(d, s)?),
            };
            let d2 = d.clone();
            let f = tokio::task::spawn_blocking(move || {
                crate::cleanup::pass_emptying(&d2, empty, false)
            })
            .await??;
            Ok(json!({"objects": f.objects, "bytes": f.bytes, "left": f.left}))
        }
        "keep-old" => {
            let keep = crate::cleanup::Keep::parse(arg(req, "keep")?)?;
            // for one space, in place of the device's period; without
            // one, the device's, for every space not set otherwise
            match req.get("space").and_then(Value::as_str) {
                None | Some("") => d.config().keep_old = keep.to_string(),
                Some(s) => {
                    let space = hex::encode(space_held(d, s)?);
                    d.config().keep_old_spaces.insert(space, keep.to_string());
                }
            }
            d.save_config()?;
            // Forever is history retention: record it for the other devices.
            d.housekeeping();
            // A shorter period applies now, not at the next hourly pass.
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = crate::cleanup::pass(&d2, false, false) {
                    tracing::warn!("freeing old versions: {e:#}");
                }
            });
            Ok(json!({"keep": keep.to_string()}))
        }
        "history" => history(d, arg(req, "path")?),
        "restore" => {
            let path = arg(req, "path")?.to_owned();
            let version = req
                .get("version")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("missing --version"))?;
            restore(d, &path, version).await
        }
        "pin" | "unpin" => {
            let path = arg(req, "path")?.trim_matches('/').to_owned();
            {
                let mut c = d.config();
                c.pins.retain(|p| *p != path);
                if cmd == "pin" {
                    c.pins.push(path.clone());
                }
            }
            d.save_config()?;
            d.bump();
            let on_demand = d.config().on_demand();
            Ok(json!({"path": path, "on_demand": on_demand}))
        }
        "retention" => {
            let mode = arg(req, "mode")?;
            if mode != "full" && mode != "on-demand" {
                anyhow::bail!("retention is `full` or `on-demand`");
            }
            d.config().retention = mode.to_owned();
            d.save_config()?;
            d.bump();
            // Record it in the account space for the other devices.
            d.housekeeping();
            Ok(json!({"retention": mode}))
        }
        "speedtest" => speedtest(d, arg(req, "device")?).await,
        other => anyhow::bail!("unknown command {other:?}"),
    }
}

/// Measures the link to one of the person's devices (`speedtest.rs`).
async fn speedtest(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Value> {
    let me = d.keys.key();
    let (key, name, x) = {
        let core = d.core();
        let ident = core
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone yet"))?;
        let names = core.device_names();
        let st = ident.state();
        let w = who.to_lowercase();
        let asked = api::reference(who);
        let who = api::shown(who);
        let matches: Vec<_> = st
            .keys
            .values()
            .filter(|k| match asked {
                api::Ref::Id(_) => asked.is_id(&k.key),
                api::Ref::Typed(_) => {
                    names.get(&k.key).is_some_and(|n| n.to_lowercase() == w)
                        || hex::encode(k.key).starts_with(&w)
                }
            })
            .collect();
        let k = match matches.as_slice() {
            [] => anyhow::bail!("no device called {who:?}; see `cardinal devices`"),
            [k] => *k,
            _ => anyhow::bail!(
                "several devices match {who:?}; use the key shown by `cardinal devices`"
            ),
        };
        let name = names
            .get(&k.key)
            .cloned()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| account::short_key(&k.key));
        (k.key, name, k.link_key.as_ref().map(|l| *l.x25519()))
    };
    if key == me {
        anyhow::bail!("{name} is this device; name one of your others");
    }
    let session = x
        .and_then(|x| d.own_sessions().into_iter().find(|s| s.peer_static() == x))
        .ok_or_else(|| anyhow::anyhow!("{name} is offline"))?;
    let m = crate::speedtest::run(&session, &name).await?;
    let mut v = m.to_json();
    v["device"] = json!(name);
    Ok(v)
}

pub(crate) fn reload(d: &Arc<Daemon>) -> anyhow::Result<()> {
    {
        let mut core = d.core();
        if core.identity.is_some() {
            return Ok(());
        }
        *core = crate::core::Core::load(&d.paths, d.keys.clone())?;
    }
    let (id, st) = {
        let core = d.core();
        let Some(i) = core.identity.as_ref() else {
            anyhow::bail!("no identity was found in {}", d.paths.home.display());
        };
        (i.id(), i.state())
    };
    d.endpoint.set_identity(Some(cardinal_link::LocalIdentity {
        identity: id,
        signing_key: d.keys.signing.clone(),
    }));
    d.directory.update(Some(&st), &[]);
    let mut config = crate::config::Config::load(&d.paths.config())?;
    config.this_run = d.config().this_run.clone();
    *d.config() = config;
    d.bump();
    d.housekeeping();
    Ok(())
}

/// Makes an identity for a client to set up, and says which two of its words
/// to ask for back. Nothing is saved until [`setup_finish`].
fn setup_begin(d: &Daemon) -> anyhow::Result<Value> {
    let prepared = crate::setup::prepare(&d.paths)?;
    let phrase = prepared.phrase().to_words();
    let words: Vec<&str> = phrase.split(' ').collect();
    let r: [u8; 2] = cardinal_crypto::random_bytes();
    let (a, mut b) = (r[0] as usize % words.len(), r[1] as usize % words.len());
    if b == a {
        b = (a + 7) % words.len();
    }
    let ask = [a.min(b), a.max(b)];
    let reply = json!({"words": words, "ask": ask});
    *d.setting_up.lock().unwrap_or_else(|e| e.into_inner()) = Some((prepared, ask));
    Ok(reply)
}

/// Saves the identity once its person has shown they have the words.
fn setup_finish(d: &Arc<Daemon>, req: &Value) -> anyhow::Result<Value> {
    let mut held = d.setting_up.lock().unwrap_or_else(|e| e.into_inner());
    let (prepared, ask) = held
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("nothing is being set up"))?;
    let words_are = prepared.phrase().to_words();
    let words: Vec<&str> = words_are.split(' ').collect();
    let answers = req["answers"].as_array().cloned().unwrap_or_default();
    let matches = ask.iter().enumerate().all(|(i, at)| {
        let answer = answers.get(i).and_then(Value::as_str).unwrap_or_default();
        answer.trim().eq_ignore_ascii_case(words[*at])
    });
    anyhow::ensure!(matches, "that does not match; check what you wrote down");
    let mut config = crate::config::Config::load(&d.paths.config())?;
    // `name` is the person's, the name they suggest for themselves; the
    // device keeps its machine's name unless the window knows a better one.
    if let Some(device) = device_name(req)? {
        config.name = device;
    }
    let person = req["name"]
        .as_str()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(crate::config::default_person);
    anyhow::ensure!(!person.contains('\n'), "a name is one line");
    let (prepared, _) = held.take().expect("checked above");
    drop(held);
    crate::setup::install(&d.paths, prepared, &config, &person)?;
    config.save(&d.paths.config())?;
    reload(d)?;
    Ok(json!({"name": person, "device": config.name}))
}

/// The `device` a window gives, the name it knows this device by: one
/// line, and not empty if given.
fn device_name(req: &Value) -> anyhow::Result<Option<String>> {
    let Some(name) = req.get("device").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let name = name.trim();
    if name.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(!name.contains('\n'), "a device's name is one line");
    Ok(Some(name.to_owned()))
}

/// Names this device, before it belongs to anyone: in its settings, which
/// is what it says it is when it is paired.
fn rename_this_device(d: &Daemon, name: &str) -> anyhow::Result<()> {
    let mut config = crate::config::Config::load(&d.paths.config())?;
    config.name = name.to_owned();
    config.this_run = d.config().this_run.clone();
    config.save(&d.paths.config())?;
    d.config().name = name.to_owned();
    Ok(())
}

fn devices(d: &Daemon) -> Vec<Value> {
    let (st, names) = {
        let core = d.core();
        let Some(i) = core.identity.as_ref() else {
            return Vec::new();
        };
        (i.state(), core.device_names())
    };
    let me = d.keys.key();
    let book = d.book.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let stats = d
        .blob_stats
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let name_of = |k: &[u8; 32]| {
        names
            .get(k)
            .cloned()
            .unwrap_or_else(|| account::short_key(k))
    };
    let by_link: HashMap<[u8; 32], String> = st
        .keys
        .values()
        .filter_map(|k| Some((*k.link_key.as_ref()?.x25519(), name_of(&k.key))))
        .collect();
    let mut v: Vec<Value> = st
        .keys
        .values()
        .map(|k| {
            let x = k.link_key.as_ref().map(|l| *l.x25519());
            let online = k.key == me || x.is_some_and(|x| d.is_online(&x));
            let carrier = x.and_then(|x| d.session_carrier(&x));
            let (dials, redial) = d.dialled(&k.key);
            let through = x
                .and_then(|x| d.relayed_through(&x))
                .and_then(|h| by_link.get(&h));
            // Where its session runs, or else where it was last known. A
            // relayed session's address is the relay's.
            let addr = x
                .filter(|x| d.is_direct(x))
                .and_then(|x| d.session_addr(&x))
                .map(|a| a.to_string())
                .or_else(|| {
                    book.addrs
                        .get(&hex::encode(k.key))
                        .and_then(|v| v.first().cloned())
                });
            json!({
                "name": name_of(&k.key),
                // what it sent that this device cannot read, or the other
                // way round (`unreadable.rs`)
                "unreadable": d.unreadable.json(&k.key, &name_of(&k.key)),
                "key": hex::encode(&k.key[..8]),
                "power": power_name(k.power),
                "this": k.key == me,
                "online": online,
                "addr": if k.key == me || carrier == Some("relay") { None } else { addr },
                "carrier": carrier,
                "through": through,
                // how often this device dialled it, and the wait before
                // the next try (`redial.rs`)
                "dials": dials,
                "redial_s": redial.map(|w| w.as_secs()),
                // what this device's fetcher thinks of it as a source
                "fetch": x.and_then(|x| stats.get(&x)).map(|s| json!({
                    "rate": s.rate as u64,
                    "latency_ms": (s.latency * 1000.0) as u64,
                    "replies": s.samples,
                    "received": s.bytes_total,
                })),
            })
        })
        .collect();
    v.sort_by_key(|x| {
        (
            !x["this"].as_bool().unwrap_or(false),
            x["name"].as_str().unwrap_or("").to_owned(),
        )
    });
    v
}

fn status(d: &Arc<Daemon>) -> Value {
    let cfg = d.config().clone();
    let (identity, spaces, conflicts, files) = {
        let core = d.core();
        let identity = core.identity.as_ref().map(|i| hex::encode(&i.id()[..8]));
        let files = core.files_id();
        let spaces: Vec<Value> = core
            .spaces
            .values()
            .map(|h| {
                json!({
                    "id": hex::encode(&h.id[..8]),
                    "kind": match h.profile() {
                        Some(cardinal_space::Profile::ACCOUNT) => "account",
                        Some(cardinal_space::Profile::FILES) => "files",
                        Some(_) => "other",
                        None => "arriving",
                    },
                    "entries": h.set_len(),
                    // set aside for want of a witness (`spaces.md#authors`)
                    "set_aside": h.space.as_ref().map_or(0, |s| s.validity().unwitnessed.len()),
                    "valid": h.space.as_ref().map_or(0, |s| s.validity().valid.len()),
                })
            })
            .collect();
        let conflicts = files
            .and_then(|f| core.spaces.get(&f))
            .and_then(|h| h.space.as_ref())
            .map(|s| shown_conflicts(s).len())
            .unwrap_or(0);
        (identity, spaces, conflicts, files)
    };
    // the whole id, beside the short one shown
    let identity_id = d.core().identity.as_ref().map(|i| hex::encode(i.id()));
    let (mounted, pending, not_saved, undone) = {
        let m = d.mount.lock().unwrap_or_else(|e| e.into_inner());
        match m.as_ref() {
            Some(m) => (
                Some(m.path.display().to_string()),
                m.has_pending(),
                m.refused_count(),
                m.undone_count(),
            ),
            None => (None, false, 0, 0),
        }
    };
    let progress = d.progress.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let pairing = match d.pairing.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        PairState::Idle => Value::Null,
        PairState::Showing { code } => json!({"state": "showing", "code": code}),
        PairState::Joining {
            admin_name, power, ..
        } => json!({"state": "joining", "admin": admin_name, "power": joins_as(power)}),
        PairState::Joined { .. } => Value::Null,
        PairState::Failed(e) => json!({"state": "failed", "error": e}),
    };
    json!({
        "name": cfg.name,
        "router": crate::portmap::status(d),
        "bluetooth": crate::bluetooth::status(d),
        "network": crate::networks::status(d),
        "read_markers": crate::settings::read_markers_on(&d.core()),
        "home": d.paths.home.display().to_string(),
        "identity": identity,
        "identity_id": identity_id,
        "listen": d.endpoint.tcp_addr().map(|a| a.to_string()),
        "devices": devices(d),
        "hosts": crate::host::sheet(d).ok().and_then(|v| v["hosts"].as_array().map(Vec::len)),
        // the person's devices with a mailbox, reachable from outside: an
        // explicit host, or one that names itself (D72)
        "always_on": always_on(d),
        "spaces": spaces,
        "files_ready": files.is_some(),
        // whether this device may be inspected now, and until when
        "inspection": d.inspection.status(),
        "mount": cfg.mount_here().map(|p| p.display().to_string()),
        "mounted": mounted,
        "removed": d.core().removed(),
        "mount_unavailable": d.mount_unavailable.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        "pending_changes": pending,
        "not_saved": not_saved,
        "not_saved_undone": undone,
        "retention": cfg.retention,
        "conflicts": conflicts,
        "listen": cfg.listen,
        "moved_from": cfg.this_run.moved_from,
        "left_behind": cfg.this_run.left_behind,
        "progress": progress,
        "copies": crate::copies::status(d),
        "conditions": d.conditions.json(),
        "redial": d.redial_json(),
        "carrying_calls": crate::calls::carried(d),
        "old": crate::cleanup::status(d),
        "pairing": pairing,
        "peers": cfg.peers,
        "uptime_s": d.uptime().as_secs(),
    })
}

/// The conflicts of a files space that its folder shows: of nodes that
/// belong to it, and are there or were deleted while someone else was
/// changing them. A conflict in a node of a kind this build does not know,
/// or in a place where its kind means nothing, is in the state and is
/// nobody's to settle here.
fn shown_conflicts(sp: &cardinal_space::Space) -> Vec<&cardinal_space::Node> {
    let st = sp.state();
    let f = Files::new(sp);
    let all = st.conflicts().into_iter();
    all.filter(|n| f.belongs(&n.id) && (st.is_visible(&n.id) || n.delete_conflict))
        .collect()
}

fn conflicts(d: &Daemon) -> anyhow::Result<Value> {
    let files_id = require_files(d)?;
    let core = d.core();
    let names = core.device_names();
    let sp = core.spaces[&files_id]
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
    let f = Files::with_device_names(sp, |k| {
        names
            .get(k)
            .cloned()
            .unwrap_or_else(|| account::short_key(k))
    });
    let st = sp.state();
    let mut out = Vec::new();
    for n in shown_conflicts(sp) {
        let path = node_path(st, &n.id);
        let versions: Vec<Value> = f
            .content(&n.id)
            .iter()
            .map(|v| {
                json!({
                    "device": names.get(&v.device).cloned().unwrap_or_else(|| account::short_key(&v.device)),
                    "time": v.time,
                    "size": v.content.as_ref().map(|c| c.size()),
                })
            })
            .collect();
        let copies: Vec<String> = {
            let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            f.list_path(parent)
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.node == n.id && e.conflict_version.is_some())
                .map(|e| {
                    if parent.is_empty() {
                        e.name
                    } else {
                        format!("{parent}/{}", e.name)
                    }
                })
                .collect()
        };
        out.push(json!({
            "path": path,
            "versions": versions,
            "copies": copies,
            "delete_conflict": n.delete_conflict,
        }));
    }
    Ok(json!({"conflicts": out}))
}

/// One content version: entry, time, device, content.
type VersionRow = ([u8; 32], Option<u64>, [u8; 32], Option<Content>);

/// The content versions of a node, oldest first.
fn versions(sp: &cardinal_space::Space, node: &NodeId) -> Vec<VersionRow> {
    let f = Files::new(sp);
    let mut out = Vec::new();
    for h in f.history(node) {
        let c = match &h.op {
            SpaceOpBody::Create { fields, .. } => {
                fields.get(FILE_CONTENT).and_then(Content::from_value)
            }
            SpaceOpBody::Set { key, value, .. } if *key == FILE_CONTENT => {
                value.as_ref().and_then(Content::from_value)
            }
            _ => continue,
        };
        out.push((h.entry, h.time, h.device, c));
    }
    out
}

/// What is in a folder of this person's files, folders first.
fn history(d: &Daemon, path: &str) -> anyhow::Result<Value> {
    let files_id = require_files(d)?;
    let core = d.core();
    let names = core.device_names();
    let sp = core.spaces[&files_id]
        .space
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
    let r = Files::new(sp)
        .resolve(path)
        .ok_or_else(|| anyhow::anyhow!("{path} does not exist in your files"))?;
    let vs = versions(sp, &r.node);
    let current: HashMap<[u8; 32], ()> = Files::new(sp)
        .content(&r.node)
        .iter()
        .map(|v| (v.entry, ()))
        .collect();
    let list: Vec<Value> = vs
        .iter()
        .enumerate()
        .map(|(i, (e, t, dev, c))| {
            json!({
                "version": i + 1,
                "time": t,
                "device": names.get(dev).cloned().unwrap_or_else(|| account::short_key(dev)),
                "size": c.as_ref().map(|c| c.size()),
                "current": current.contains_key(e),
                // whether its content is on this device (`cleanup.rs`)
                "here": match c {
                    Some(Content::Blob(b)) => {
                        cardinal_blob::ObjectStore::has(&*d.store, &b.id).unwrap_or(false)
                    }
                    _ => true,
                },
            })
        })
        .collect();
    Ok(json!({"path": path, "versions": list}))
}

async fn restore(d: &Arc<Daemon>, path: &str, version: u64) -> anyhow::Result<Value> {
    let files_id = require_files(d)?;
    // save anything pending first, so the restore descends from it
    let d2 = d.clone();
    tokio::task::spawn_blocking(move || {
        let m = d2.mount.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = m.as_ref() {
            let _ = m.flush();
        }
    })
    .await?;
    let (node, content) = {
        let core = d.core();
        let sp = core.spaces[&files_id]
            .space
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("files space not open"))?;
        let r = Files::new(sp)
            .resolve(path)
            .ok_or_else(|| anyhow::anyhow!("{path} does not exist in your files"))?;
        let vs = versions(sp, &r.node);
        let (_, _, _, c) = vs
            .get((version as usize).wrapping_sub(1))
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{path} has versions 1 to {}; see `cardinal history {path}`",
                    vs.len()
                )
            })?;
        (
            r.node,
            c.ok_or_else(|| anyhow::anyhow!("that version has no content"))?,
        )
    };
    // Its content may have been freed here (`cleanup.rs`): get all of it
    // first, or the restored file could not be read.
    if let Content::Blob(b) = &content {
        let (d2, b) = (d.clone(), crate::fetch::blob_ref(b));
        let missing = tokio::task::spawn_blocking(move || held_or_fetched(&d2, b)).await??;
        if missing > 0 {
            anyhow::bail!(
                "version {version} of {path} is no longer kept: this device freed it, and none \
                 of your online devices has all of it"
            );
        }
    }
    d.write_and_push(&files_id, vec![files::set_content(node, &content)])?;
    Ok(json!({"path": path, "version": version}))
}

/// Makes sure every object of `b` is on this device, fetching what is
/// missing from the person's online devices (blocking). Returns how many
/// objects are still missing.
fn held_or_fetched(d: &Arc<Daemon>, b: cardinal_blob::BlobRef) -> anyhow::Result<usize> {
    use cardinal_blob::{BlobReader, Fetch, ObjectStore};
    let fetcher = crate::fetch::Fetcher::new(d, cardinal_link::Priority::Interactive);
    // Listing fetches and keeps the indexes.
    let mut chunks = Vec::new();
    let listed = BlobReader::new(d.store.clone(), &fetcher, b).for_each_entry(|e, chunk| {
        if chunk {
            chunks.push(e.id)
        }
    });
    if listed.is_err() {
        return Ok(1);
    }
    let mut missing: Vec<[u8; 32]> = Vec::new();
    for id in chunks {
        if !d.store.has(&id)? {
            missing.push(id);
        }
    }
    for batch in missing.chunks(256) {
        for (id, ct) in fetcher.fetch(batch)? {
            if blake3::hash(&ct).as_bytes() == &id {
                d.store.put(&id, &ct)?;
            }
        }
    }
    let mut left = 0;
    for id in &missing {
        if !d.store.has(id)? {
            left += 1;
        }
    }
    Ok(left)
}

/// For tests: a digest of the files space's heads, whether the mount has
/// changes to commit, and every item the mount shows, with whether it is
/// local (`fs/local.rs`).
fn debug_tree(d: &Daemon) -> anyhow::Result<Value> {
    let files = require_files(d)?;
    let heads = {
        let core = d.core();
        let mut hs = core.spaces[&files]
            .space
            .as_ref()
            .map(|s| s.heads())
            .unwrap_or_default();
        hs.sort();
        let mut h = blake3::Hasher::new();
        for x in &hs {
            h.update(x);
        }
        hex::encode(&h.finalize().as_bytes()[..16])
    };
    let epoch = {
        let core = d.core();
        core.spaces[&files]
            .space
            .as_ref()
            .and_then(|s| s.current_epoch())
            .map(hex::encode)
    };
    let (state, snap) = {
        let core = d.core();
        let h = &core.spaces[&files];
        let sp = h.space.as_ref();
        (
            sp.map(|s| hex::encode(&blake3::hash(&s.state().canonical().encode()).as_bytes()[..8])),
            sp.map(|s| crate::fs::tree::Snapshot::take(s, h.version, &core.device_names())),
        )
    };
    let m = d.mount.lock().unwrap_or_else(|e| e.into_inner());
    let Some(m) = m.as_ref() else {
        return Ok(json!({"heads": heads, "epoch": epoch, "mounted": false}));
    };
    let tree = m.tree();
    let t = tree.lock().unwrap_or_else(|e| e.into_inner());
    let mut items = Vec::new();
    let mut stack = vec![t.root];
    while let Some(ino) = stack.pop() {
        let Some(i) = t.inodes.get(&ino) else {
            continue;
        };
        for c in i.children.values() {
            let Some(x) = t.inodes.get(c) else { continue };
            let kind = match x.kind {
                crate::fs::tree::Kind::Dir => "dir",
                crate::fs::tree::Kind::File => "file",
                crate::fs::tree::Kind::Symlink => "link",
                crate::fs::tree::Kind::Conflict(_) => "conflict",
            };
            items.push(json!({
                "path": t.path(*c), "kind": kind, "local": x.local, "size": x.size,
                "node": x.node.map(|n| hex::encode(&n[..6])), "ino": x.ino,
                "dirty": x.dirty.any_change(),
            }));
            stack.push(*c);
        }
    }
    // What keeps a device from settling, and what its state holds that its
    // tree does not show.
    let stuck: Vec<Value> = t
        .inodes
        .values()
        .filter(|x| x.parent != 0 && !x.local && (x.node.is_none() || x.dirty.any_change()))
        .map(|x| {
            json!({
                "path": t.path(x.ino), "kind": format!("{:?}", x.kind),
                "dirty": format!("{:?}", x.dirty), "staged": x.staged.is_some(), "opens": x.opens,
            })
        })
        .collect();
    let unshown: Vec<Value> = snap
        .iter()
        .flat_map(|s| s.entries.iter())
        .filter(|e| e.version.is_none() && !t.by_node.contains_key(&e.node))
        .map(|e| json!({"node": hex::encode(&e.node[..6]), "name": e.name}))
        .collect();
    Ok(json!({
        "heads": heads, "epoch": epoch, "state": state, "mounted": true, "pending": t.has_pending(),
        "items": items, "stuck": stuck, "unshown": unshown,
        "deleted": t.deleted.len(), "settle": t.settle.len(),
    }))
}

/// The recovery words of a request, if given ([`crate::recovery`]).
fn words(req: &Value) -> Option<&str> {
    req.get("words").and_then(|v| v.as_str())
}

/// How long a device gets to give up what it has, before its removal.
const SYNC_WITHIN: Duration = Duration::from_secs(10);

/// How long a device gets to take the news of its own removal.
const TELL_WITHIN: Duration = Duration::from_secs(3);

/// For a device that is retired rather than lost (`spaces.md#authors`): gets
/// what can be had of its work, from it first, and builds on that, so that
/// nothing goes with its key.
async fn keep_work_of(d: &Arc<Daemon>, key: &[u8; 32]) -> anyhow::Result<()> {
    let mut sessions = d.own_sessions();
    sessions.sort_by_key(|s| s.peer_identity().map(|p| p.signing_key) != Some(*key));
    for s in sessions {
        if tokio::time::timeout(SYNC_WITHIN, net::sync_all(d, &s))
            .await
            .is_err()
        {
            tracing::warn!("syncing with {} took too long", short(&s.peer_static()));
        }
    }
    let spaces: Vec<SpaceId> = d.core().spaces.keys().copied().collect();
    for space in &spaces {
        let entry = d.core().witness(space, key)?;
        if let Some(entry) = entry {
            d.push(space, vec![entry]);
        }
    }
    // and its successions, which building on them does not keep
    let kept = d.core().keep_successions_of(key);
    for (space, bytes) in kept {
        d.push(&space, vec![bytes]);
    }
    Ok(())
}

/// Removes a device. A device that is `lost` or stolen gets nothing kept
/// that no other key built on; any other keeps its work. Either way it is
/// told first, while it still can be: nobody answers it afterwards, and until
/// then it can pass the news to devices this one cannot reach.
/// One of this person's devices, typed by its name or the start of its
/// key, or as bytes by its key (as `devices` gives it, or whole), and what
/// it is called.
fn find_device(d: &Daemon, who: &str) -> anyhow::Result<([u8; 32], String)> {
    let core = d.core();
    let ident = core
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
    let names = core.device_names();
    let st = ident.state();
    let w = who.trim().to_lowercase();
    let asked = api::reference(who);
    let who = api::shown(who);
    let matches: Vec<[u8; 32]> = st
        .keys
        .keys()
        .filter(|k| match asked {
            api::Ref::Id(_) => asked.is_id(k.as_slice()),
            api::Ref::Typed(_) => {
                names.get(*k).is_some_and(|n| n.to_lowercase() == w)
                    || (!w.is_empty() && hex::encode(k).starts_with(&w))
            }
        })
        .copied()
        .collect();
    match matches.as_slice() {
        [] => anyhow::bail!("no device called {who:?}; see `cardinal devices`"),
        [k] => Ok((
            *k,
            names
                .get(k)
                .cloned()
                .unwrap_or_else(|| account::short_key(k)),
        )),
        _ => {
            anyhow::bail!("several devices match {who:?}; use the key shown by `cardinal devices`")
        }
    }
}

/// Renames one of this person's devices: the name in its device node in the
/// account space (`profiles.md#account`, kind 4, field 2), which only the
/// person's own devices read and any of them may set. Every node naming the
/// device is set, should two have been made at once. No two of a person's
/// devices share a name, since a device is also found by its name.
fn rename_device(d: &Arc<Daemon>, which: &str, name: &str) -> anyhow::Result<Value> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "a name cannot be empty");
    anyhow::ensure!(
        !name.chars().any(char::is_control),
        "a device's name is one line"
    );
    let (key, _) = find_device(d, which)?;
    let (acc, nodes, taken) = {
        let core = d.core();
        let acc = core
            .account_id()
            .ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let held = core.account().and_then(|h| h.space.as_ref());
        let held = held.ok_or_else(|| anyhow::anyhow!("the account space is not here yet"))?;
        let all = account::devices(held.state());
        let nodes: Vec<_> = all
            .iter()
            .filter(|r| r.key == key)
            .map(|r| r.node)
            .collect();
        let taken = all
            .iter()
            .any(|r| r.key != key && r.name.to_lowercase() == name.to_lowercase());
        (acc, nodes, taken)
    };
    anyhow::ensure!(!taken, "another of your devices is called {name:?}");
    anyhow::ensure!(
        !nodes.is_empty(),
        "that device is not named in your account yet; try again once it has synced"
    );
    let ops = nodes
        .into_iter()
        .map(|n| account::set_field(n, account::DEVICE_NAME, name))
        .collect();
    d.write_and_push(&acc, ops)?;
    Ok(json!({"name": name, "key": hex::encode(&key[..8])}))
}

async fn remove_device(
    d: &Arc<Daemon>,
    who: &str,
    words: Option<&str>,
    lost: bool,
) -> anyhow::Result<Value> {
    let me = d.keys.key();
    let (key, name) = find_device(d, who)?;
    if key == me {
        anyhow::bail!("this is the device you are using; remove it from another of your devices");
    }
    // Its link key, which is what a list of hosts names it by, while the
    // log still has it.
    let link = d.core().identity.as_ref().and_then(|i| {
        let st = i.state();
        let k = st.keys.values().find(|k| k.key == key)?;
        k.link_key.as_ref().map(|l| *l.x25519())
    });
    // Removals go strictly down in power: an admin removes devices, and
    // only the root (the recovery words) removes an admin.
    let target = d
        .core()
        .identity
        .as_ref()
        .and_then(|i| i.state().power(&key));
    let root = crate::recovery::signer(
        d,
        words,
        |mine| mine >= Some(Power::Admin) && mine > target,
        || {
            if target >= Some(Power::Admin) {
                format!("{name} is an admin device: no device can remove it")
            } else {
                format!("this device cannot remove {name} (it is not an admin device)")
            }
        },
    )?;
    if !lost {
        keep_work_of(d, &key).await?;
    }
    let signer = root.as_ref().unwrap_or(&d.keys.device.signing);
    let (entries, label) = {
        let mut core = d.core();
        let ident = core.identity.as_mut().expect("identity");
        let current = ident
            .enc
            .first()
            .map(|k| cardinal_crypto::HybridKeyPair::from_secret_bytes(&k.secret_bytes()));
        let removal = if lost {
            ident.log.remove_lost_key(signer, &key)
        } else {
            ident.log.remove_key(signer, &key)
        };
        let e1 = removal.map_err(|e| {
            anyhow::anyhow!(
                "cannot remove {name}: {e} (only a device with more power can remove it)"
            )
        })?;
        ident.record_own(&e1)?;
        let new = cardinal_crypto::HybridKeyPair::generate();
        let e2 = ident
            .log
            .set_encryption_key(signer, &new, current.as_ref())?;
        ident.record_own(&e2)?;
        drop(core);
        let mut core = d.core();
        let keys = d.keys.clone();
        if let Some(i) = core.identity.as_mut() {
            if let Ok(k) = i.log.open_encryption_key(&keys.device) {
                i.enc = i.log.key_chain(k);
            }
        }
        let entries = vec![(e1.encode(), e1.id()), (e2.encode(), e2.id())];
        (entries, core.identity_label())
    };
    let session = d
        .own_sessions()
        .into_iter()
        .find(|s| s.peer_identity().map(|p| p.signing_key) == Some(key));
    if let (Some(s), Some(label)) = (session, label) {
        let tell = async {
            for (entry, id) in &entries {
                net::deliver(&s, label, entry.clone(), *id).await?;
            }
            anyhow::Ok(())
        };
        match tokio::time::timeout(TELL_WITHIN, tell).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!("telling {name} of its removal: {e:#}"),
            Err(_) => tracing::debug!("telling {name} of its removal took too long"),
        }
    }
    d.identity_changed();
    d.push_identity(entries.into_iter().map(|(entry, _)| entry).collect());
    // Every space moves to keys it never held, now rather than at the next
    // write here. Any device's next write would do it, so one that fails
    // is not lost.
    let spaces: Vec<SpaceId> = d.core().spaces.keys().copied().collect();
    for space in &spaces {
        let rotated = d.core().rotate_if_due(space);
        match rotated {
            Ok(Some(entry)) => d.push(space, vec![entry]),
            Ok(None) => {}
            Err(e) => tracing::warn!("no new keys yet for {}: {e:#}", short(space)),
        }
    }
    // forget its device node and its placements
    let acc = {
        let core = d.core();
        core.account_id().and_then(|a| {
            let st = core.spaces[&a].space.as_ref()?.state();
            let mut nodes: Vec<NodeId> = account::devices(st)
                .into_iter()
                .filter(|x| x.key == key)
                .map(|x| x.node)
                .collect();
            for rec in account::spaces(st) {
                nodes.extend(
                    rec.placements
                        .iter()
                        .filter(|p| p.device == key)
                        .map(|p| p.node),
                );
            }
            Some((a, nodes))
        })
    };
    if let Some((a, nodes)) = acc {
        if !nodes.is_empty() {
            let ops = nodes
                .into_iter()
                .map(cardinal_space::SpaceOp::delete)
                .collect();
            d.write_and_push(&a, ops)?;
        }
    }
    // The person removed it: it leaves the lists that name it.
    if let Some(link) = link {
        crate::mailbox::take_out_removed(d, &link);
    }
    let dropped = d.core().unwitnessed_by(&key);
    Ok(json!({"name": name, "dropped": dropped}))
}

/// A person's yes or no in a request, if it holds one.
fn answer_in(req: &Value, key: &str) -> anyhow::Result<Option<bool>> {
    match req.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(yes)) => Ok(Some(*yes)),
        Some(other) => anyhow::bail!("`{key}` is true or false, not {other}"),
    }
}

/// For `status`: the names of the person's devices that keep mail, reached
/// from outside, as [`mailboxes`](crate::core::Core::mailboxes) has them.
fn always_on(d: &Daemon) -> Vec<String> {
    let keys: Vec<[u8; 32]> = d
        .core()
        .mailboxes()
        .into_iter()
        .filter(|(g, _)| {
            g.endpoints
                .iter()
                .any(cardinal_space::grant::Endpoint::usable)
        })
        .map(|(_, k)| k)
        .collect();
    let mut names: Vec<String> = keys.iter().map(|k| d.device_name(k)).collect();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P14. An answer is true or false. Anything else where one belongs is
    /// not "nothing was said": joining a group with `"reach": "no"` named
    /// the person's hosts there.
    #[test]
    fn an_answer_that_is_not_yes_or_no_is_refused() {
        let with = |v: Value| answer_in(&json!({"cmd": "group-join", "reach": v}), "reach");
        assert_eq!(with(json!(true)).unwrap(), Some(true));
        assert_eq!(with(json!(false)).unwrap(), Some(false));
        assert_eq!(with(Value::Null).unwrap(), None);
        assert_eq!(
            answer_in(&json!({"cmd": "group-join"}), "reach").unwrap(),
            None
        );
        for odd in [
            json!("no"),
            json!("false"),
            json!(0),
            json!([false]),
            json!({}),
        ] {
            let why = with(odd.clone()).expect_err(&odd.to_string()).to_string();
            assert!(why.contains("true or false"), "{why}");
        }
    }
}
