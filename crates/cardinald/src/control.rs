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
use cardinal_space::files::Files;
use cardinal_space::state::State;
use cardinal_space::{NodeId, SpaceId, ROOT};
#[cfg(any(test, debug_assertions, feature = "by-name"))]
use serde_json::json;
#[cfg(any(test, debug_assertions, feature = "by-name"))]
use serde_json::Value;

use crate::api::client::{Pages, Paging};
use crate::api::typed::Ask;
use crate::api::{self, status};
use crate::core::short;
use crate::daemon::{Daemon, PairState};
use crate::net;
use crate::transport::{self, Listener, Reader, Received, Writer, MAX_MESSAGE};

/// The version of this interface. A client compares it with `hello`'s.
const API: u64 = cardinal_interface::VERSION;
/// How long news waits, so that a burst of changes is one event.
const NEWS_GATHERS: Duration = Duration::from_millis(100);

/// Whether [`request`] shows each request and reply on standard error, in
/// the text rendering with the tables' names (`cardinal --trace`).
static TRACE: AtomicBool = AtomicBool::new(false);

/// Shows every request [`request`] sends, and its reply, on standard error.
pub fn trace(on: bool) {
    TRACE.store(on, Ordering::Relaxed);
}

#[cfg(any(test, debug_assertions, feature = "by-name"))]
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

#[cfg(any(test, debug_assertions, feature = "by-name"))]
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

/// Sends a typed request to a running daemon and returns its reply, typed,
/// or how it failed. A request whose answer comes in pages is asked for
/// page after page, and the reply holds every page's items, unless `args`
/// asks for one page itself, with `limit`, `after` or `before`; as
/// [`request`] does by name.
pub async fn ask<A: Ask>(
    socket: &std::path::Path,
    args: &A,
) -> anyhow::Result<Result<A::Reply, api::typed::Failed>> {
    let mut pages = Box::new(Pages::new(args));
    asking(socket, &mut *pages).await?;
    Ok(pages.done())
}

/// [`ask`], written once for every request: each page asked in turn.
/// Boxed, so that each request's [`ask`] only waits for it.
fn asking<'a>(
    socket: &'a std::path::Path,
    p: &'a mut (dyn Paging + Send),
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    Box::pin(async move {
        while let Some(msg) = p.next()? {
            let reply = ask_one(socket, p.request(), &msg).await?;
            if !p.took(&reply)? {
                break;
            }
        }
        Ok(())
    })
}

/// [`ask`], one page of it: its reply's bytes.
async fn ask_one(
    socket: &std::path::Path,
    spec: &'static api::Request,
    msg: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let tracing = TRACE.load(Ordering::Relaxed);
    if tracing {
        eprintln!("> {}", api::render_request(msg));
    }
    let (mut r, mut w) = transport::connect(socket).await?;
    w.send(msg).await?;
    let reply = match r.recv().await? {
        Some(Received::Message(m)) => m,
        Some(Received::TooLarge) => anyhow::bail!("the daemon's reply was larger than a message"),
        None => anyhow::bail!("the daemon closed the connection"),
    };
    if tracing {
        eprintln!("< {}", api::render_reply(spec, &reply));
    }
    Ok(reply)
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
        // read straight from the bytes: the request's number, then its
        // arguments, with no tree of the encoding between
        let spec = match api::request_of(&msg) {
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
        // the two requests after which a connection is a stream
        if spec.n == api::WatchArgs::REQUEST.n {
            let a = match api::WatchArgs::read_request(&msg) {
                Ok(a) => a,
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
            // A window watching: "on while open" is on while it does.
            let _window = (a.window == Some(true)).then(|| crate::bluetooth::window(&d));
            if w.send(&api::typed::reply_message("watch", &api::Done {}))
                .await
                .is_ok()
            {
                watch(&d, r, w).await;
            }
            return;
        }
        if spec.n == api::CallMediaArgs::REQUEST.n {
            if let Err(refused) = api::CallMediaArgs::read_request(&msg) {
                if w.send(&api::error_reply(refused.status, &refused.why))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
            crate::calls::media(&d, r, w).await;
            return;
        }
        // Every request is typed, answered on its own way, with no names.
        // One with no answering is a stream's, answered above, or one no
        // longer answered, refused by `request_of`.
        let reply = match typed::answerer(spec.n) {
            Some(answer) => answer(&d, &msg).await,
            None => api::error_reply(
                status::FAILED,
                &format!("internal: {} has no answer", spec.name),
            ),
        };
        if w.send(&reply).await.is_err() {
            return;
        }
    }
}

/// The reply the way by name gives to a request's message, as the service
/// answered it before its request was typed: the handlers typed since are
/// kept by name for it. Only to show the typed way sends the same bytes,
/// and to measure the two.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[doc(hidden)]
pub async fn by_name(d: &Arc<Daemon>, msg: &[u8]) -> Vec<u8> {
    let (spec, req) = match api::decode_request(msg) {
        Ok(x) => x,
        Err(refused) => return api::error_reply(refused.status, &refused.why),
    };
    // on the heap: the handlers by name, all in one, make a large future,
    // which a caller holding it on its stack (a test) would overflow
    let reply = match Box::pin(handle(d, &req))
        .await
        .map_err(|e| capitalized(spec.name, e))
    {
        Ok(v) => match api::page(spec, &req, v) {
            Ok(v) => api::encode_reply(spec, Ok(&v)),
            Err((st, why, item)) => api::error_reply_with(st, &why, &item),
        },
        Err(e) => failed(&e),
    };
    checked(spec, reply)
}

/// A reply that failed, as a message.
fn failed(e: &anyhow::Error) -> Vec<u8> {
    let st = if e.is::<crate::recovery::NeedsWords>() {
        status::NEEDS_WORDS
    } else if e.is::<crate::contacts::NeedsFor>() {
        status::NEEDS_FOR
    } else {
        status::FAILED
    };
    api::error_reply(st, &format!("{e:#}"))
}

/// A reply, or error 4 where it would be larger than a message may be.
fn checked(spec: &api::Request, reply: Vec<u8>) -> Vec<u8> {
    if reply.len() <= MAX_MESSAGE {
        return reply;
    }
    let why = format!(
        "the answer to {} would be {} bytes, and a message is at most {MAX_MESSAGE}",
        spec.name,
        reply.len()
    );
    api::error_reply(status::TOO_LARGE, &why)
}

/// The clock a reply reads its times by. Where the tests run, a request
/// that changes nothing is answered twice, by name and typed, and the two
/// compared byte for byte (`typed::answering`): the clock is held still
/// for the length of that, so that a time in milliseconds (`status`'s
/// copies, when a contact's device was last heard) reads the same both
/// ways. Elsewhere it is the clock.
pub mod clock {
    use std::time::{Duration, Instant};

    #[cfg(any(test, debug_assertions))]
    tokio::task_local! {
        static STILL: (u64, Instant);
    }

    /// Milliseconds since 1970.
    pub fn now_ms() -> u64 {
        #[cfg(any(test, debug_assertions))]
        if let Ok((ms, _)) = STILL.try_with(|s| *s) {
            return ms;
        }
        crate::core::now_ms()
    }

    /// How long ago `t` was.
    pub fn since(t: Instant) -> Duration {
        #[cfg(any(test, debug_assertions))]
        if let Ok((_, now)) = STILL.try_with(|s| *s) {
            return now.saturating_duration_since(t);
        }
        t.elapsed()
    }

    /// `f`, with the clock held still while it runs (where it is held
    /// still already, where it was); on the heap, since what is answered
    /// twice can be large.
    #[cfg(any(test, debug_assertions))]
    pub async fn still<F: std::future::Future>(f: F) -> F::Output {
        let now = STILL
            .try_with(|s| *s)
            .unwrap_or_else(|_| (crate::core::now_ms(), Instant::now()));
        STILL.scope(now, Box::pin(f)).await
    }
}

/// The requests answered typed (`api::typed`): each from its arguments as
/// they came to the reply's bytes, with no tree of names between. Each in
/// two steps, which `benches/interface.rs` measures apart: the handler's
/// answer, all of it, and then the reply's bytes, a page of it.
pub mod typed {
    use std::sync::Arc;

    use crate::api::typed::Ask;
    use crate::api::typed::Reference;
    use crate::api::{self, CallArgs, FilesArgs, FilesReply, MessagesArgs, MessagesReply};
    use crate::api::{AcceptArgs, AcceptReply, InviteArgs, InviteReply};
    use crate::api::{AppAnswerArgs, AppJoinArgs, AppJoinReply, AppOffersArgs, AppOffersReply};
    use crate::api::{AppQuestionsArgs, AppQuestionsReply, ApprovalRevokeArgs, ApprovalsArgs};
    use crate::api::{ApprovalsReply, ContactArgs, ContactReply, DebugTreeArgs, DebugTreeReply};
    use crate::api::{
        BluetoothArgs, BluetoothReply, HostArgs, HostOffArgs, HostReply, HostsReply, NetworkArgs,
        NetworkReply, PeerAddArgs, PeerAddReply, PeerRemoveArgs, RouterArgs, RouterReply,
    };
    use crate::api::{CallAnswerArgs, CallEndArgs, CallStartArgs};
    use crate::api::{
        CancelInvitationArgs, GroupConfirmMoveArgs, GroupConfirmMoveReply, GroupConnectArgs,
        GroupConnectReply, GroupLeavingArgs, GroupLeavingReply, GroupMovedSeenArgs,
        GroupPostAgainArgs, GroupPostAgainReply, HelloArgs, HelloReply, IntroduceArgs,
        IntroductionAcceptArgs, IntroductionAcceptReply, IntroductionDeclineArgs, ReadMarkersArgs,
        ReadMarkersReply,
    };
    use crate::api::{
        Checking, ClipArgs, ClipCopyArgs, ClipCopyReply, ClipReply, ConditionsArgs,
        ConditionsReply, DeviceRenameArgs, DeviceRenameReply, MeArgs, MeReply, NetworkChangedArgs,
        PairShowArgs, PairShowReply, PairStatusArgs, PairStatusReply, PairTypeArgs, PairTypeReply,
        WakeArgs,
    };
    use crate::api::{ConflictsArgs, ConflictsReply, DevicesArgs, DevicesReply};
    use crate::api::{ContactStatusArgs, ContactStatusReply, StatusArgs, StatusReply};
    use crate::api::{ContactsArgs, ContactsReply, ConversationsArgs, ConversationsReply};
    use crate::api::{
        CopyArgs, Done, FlushArgs, FlushReply, MkdirArgs, MountArgs, MoveArgs, PathReply, PinArgs,
        PinReply, PutArgs, RemoveArgs, RestoreArgs, RestoreReply, RetentionArgs, RetentionReply,
        SaveArgs, SaveReply, ShareArgs, ShareReply, UnmountArgs, UnpinArgs, WriteArgs,
    };
    use crate::api::{
        DeleteMessageArgs, EditMessageArgs, MarkReadArgs, MarkReadReply, ReactArgs,
        SaveAttachmentArgs, SayArgs, SayReply,
    };
    use crate::api::{
        DeletedArgs, DeletedReply, HistoryArgs, HistoryReply, IntroductionsArgs,
        IntroductionsReply, InvitationsArgs, InvitationsReply, PeerListArgs, PeerListReply,
        SpaceUsageArgs, SpaceUsageReply,
    };
    use crate::api::{
        FreeSpaceArgs, FreeSpaceReply, HistoryEmptyArgs, HistoryEmptyReply, KeepOldArgs,
        KeepOldReply, ReloadArgs, StopArgs,
    };
    use crate::api::{
        GroupAddArgs, GroupCreateArgs, GroupCreateReply, GroupDeclineArgs, GroupJoinArgs,
        GroupJoinReply, GroupLeaveArgs, GroupLeaveReply, GroupMemberArgs, GroupMembersArgs,
        GroupMembersReply, GroupReachArgs, GroupReachReply, GroupRejoinArgs, GroupRemoveArgs,
        GroupRemoveReply, GroupRoleArgs, GroupRoleReply, GroupSetArgs, GroupsArgs, GroupsReply,
    };
    use crate::api::{
        GuardiansArgs, GuardiansAskArgs, GuardiansObjectArgs, GuardiansReply, GuardiansSetArgs,
        GuardiansSetReply, GuardingAcceptArgs, GuardingAcceptReply, GuardingArgs,
        GuardingCautionArgs, GuardingCautionReply, GuardingConfirmArgs, GuardingConfirmChangeArgs,
        GuardingEndorseArgs, GuardingInviteArgs, GuardingInviteReply, GuardingNeverArgs,
        GuardingReply, NameReply,
    };
    use crate::api::{
        HostAcceptArgs, HostAcceptReply, HostEndArgs, HostEndReply, HostOfferArgs, HostOfferReply,
        HostingArgs, HostingReply,
    };
    use crate::api::{InspectArgs, InspectEntriesArgs, InspectEntriesReply, InspectEntryArgs};
    use crate::api::{InspectEntryReply, InspectIdentityArgs, InspectIdentityReply};
    use crate::api::{InspectNodeArgs, InspectNodeReply, InspectNodesArgs, InspectNodesReply};
    use crate::api::{InspectOffArgs, InspectOffReply, InspectOnArgs, InspectOnReply};
    use crate::api::{InspectReply, InspectSpaceArgs, InspectSpaceReply};
    use crate::api::{
        KeepWorkArgs, KeepWorkReply, KeptChangesReply, LostDevicesReply, RecoverArgs,
        RecoverCancelArgs, RecoverCancelReply, RecoverFinishArgs, RecoverFinishReply,
        RecoverInviteArgs, RecoverInviteReply, RecoverKeptSeenArgs, RecoverLostAtArgs,
        RecoverReply, RecoverStartArgs, RecoverStartReply, RecoverStopWaitingArgs,
        RecoverStopWaitingReply, RecoverUndoArgs, RecoverUndoReply, RecoveryCheckArgs,
        RecoverySheetArgs, RecoverySheetReply, RestoreFromHostArgs, RestoreFromHostReply,
    };
    use crate::api::{RemoveDeviceArgs, RemoveDeviceReply, SetupBeginArgs, SetupBeginReply};
    use crate::api::{SetupFinishArgs, SetupFinishReply, SpeedtestArgs, SpeedtestReply};
    use crate::api::{UndeleteArgs, UndeleteReply};
    use crate::daemon::Daemon;
    use crate::daemon::PairState;
    use cardinal_space::account;

    /// How a typed request is answered, from its message to its reply's.
    pub type Answerer = for<'a> fn(
        &'a Arc<Daemon>,
        &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>,
    >;

    /// Every request's answering, by its number, made from the interface's
    /// list of every request (`each_request!`): `answering::<Args>` for
    /// each that is answered by a reply, which takes `Args: Answer`, so a
    /// request without a handler does not compile; none for a stream's
    /// (answered by the connection itself) or one no longer answered.
    macro_rules! answerers {
        ($($how:ident $x:ident,)*) => {
            static ANSWERERS: &[(u64, Option<Answerer>)] = &[$(answerers!(@one $how $x)),*];
        };
        (@one ask $args:ident) => {
            (<api::$args as Ask>::REQUEST.n, Some(answering::<api::$args> as Answerer))
        };
        (@one stream $args:ident) => { (<api::$args as Ask>::REQUEST.n, None) };
        (@one gone $row:ident) => { (api::$row.n, None) };
    }
    cardinal_interface::each_request!(answerers);

    /// How the request numbered `n` is answered: `None` for a stream's, one
    /// no longer answered, or a number no request has.
    pub fn answerer(n: u64) -> Option<Answerer> {
        ANSWERERS
            .iter()
            .find(|(m, _)| *m == n)
            .and_then(|(_, a)| *a)
    }

    /// How a typed request is answered: its handler, given its arguments
    /// as they came. [`ANSWERERS`] takes each request's answering from
    /// here, so a typed request with no handler does not compile.
    pub trait Answer: Ask {
        fn answer(
            d: &Arc<Daemon>,
            a: &Self,
        ) -> impl std::future::Future<Output = anyhow::Result<Self::Answered>> + Send;
    }

    /// The reply to `A`'s request `msg`: its arguments as they came, read
    /// straight from its bytes, the handler's answer, and the reply's
    /// bytes; or the message refusing it. Where the tests run, a request
    /// that changes nothing is answered by name too, beside, and fails if
    /// the two are not the same bytes.
    pub fn answering<'a, A: Answer>(
        d: &'a Arc<Daemon>,
        msg: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>> {
        Box::pin(async move {
            let a = match A::read_request(msg) {
                Ok(a) => a,
                Err(refused) => return api::error_reply(refused.status, &refused.why),
            };
            // not in the benchmark's build (`by-name` alone), which measures
            // the typed way only; with the clock held still, so that a
            // time read twice is the same
            #[cfg(any(test, debug_assertions))]
            if a.reads() {
                return super::clock::still(async {
                    let reply = answer_of(d, &a).await;
                    beside(d, &a, reply).await
                })
                .await;
            }
            answer_of(d, &a).await
        })
    }

    /// The reply to `a`, as a message.
    pub async fn answer_of<A: Answer>(d: &Arc<Daemon>, a: &A) -> Vec<u8> {
        let reply = A::answer(d, a).await.map(|reply| a.reply_bytes(reply));
        answered(A::REQUEST, reply)
    }

    /// The reply's bytes, or the message saying why there is none:
    /// [`answer_of`], written once for every request.
    #[inline(never)]
    fn answered(spec: &'static api::Request, reply: anyhow::Result<Vec<u8>>) -> Vec<u8> {
        let reply = match reply {
            Ok(reply) => reply,
            Err(e) => super::failed(&super::capitalized(spec.name, e)),
        };
        super::checked(spec, reply)
    }

    /// `reply`, typed, against the request's answer by name: the same
    /// bytes, or an error that says how they differ. What changes between
    /// two asks (a call's seconds, the frames a live call counts) can make
    /// two answers differ that are not wrong: the two ways are asked in
    /// turn, a few times, until one answer is the same as the one before
    /// it, the other way's.
    #[cfg(any(test, debug_assertions))]
    async fn beside<A: Answer>(d: &Arc<Daemon>, a: &A, reply: Vec<u8>) -> Vec<u8> {
        const ASKS: usize = 8;
        let Ok(msg) = a.encode() else {
            return reply;
        };
        let mut typed = reply;
        let mut old = super::by_name(d, &msg).await;
        for _ in 0..ASKS {
            if old == typed {
                return typed;
            }
            typed = answer_of(d, a).await;
            if old == typed {
                return typed;
            }
            old = super::by_name(d, &msg).await;
        }
        if old == typed {
            return typed;
        }
        let spec = A::REQUEST;
        let why = format!(
            "internal: the typed reply to {} is not the bytes it was by name: typed {}, by \
             name {}",
            spec.name,
            api::render_reply(spec, &typed),
            api::render_reply(spec, &old)
        );
        tracing::error!("{why}");
        api::error_reply(api::status::FAILED, &why)
    }

    impl Answer for FilesArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<FilesReply> {
            files(d, a)
        }
    }

    /// `files`: the folder, all of it.
    pub fn files(d: &Arc<Daemon>, a: &FilesArgs) -> anyhow::Result<FilesReply> {
        crate::onefolder::list(d, a.path.as_deref().unwrap_or(""))
    }

    impl Answer for MessagesArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<MessagesReply> {
            messages(d, a)
        }
    }

    /// `messages`: the conversation, all of it before `before`.
    pub fn messages(d: &Arc<Daemon>, a: &MessagesArgs) -> anyhow::Result<MessagesReply> {
        let before = a.before.as_ref().map(|b| b.as_ref());
        match (&a.group, &a.who) {
            (Some(group), _) => crate::groups::messages(d, group.as_ref(), before),
            (None, Some(who)) => crate::contacts::messages(d, who.as_ref(), before),
            (None, None) => anyhow::bail!("missing argument who"),
        }
    }

    impl Answer for CallArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<api::CallReply> {
            call(d, a)
        }
    }

    /// `call`: what is known of the call under way.
    pub fn call(d: &Arc<Daemon>, _: &CallArgs) -> anyhow::Result<api::CallReply> {
        Ok(crate::calls::current(d))
    }

    /// The reply to a typed request's message, or `None` for a request not
    /// typed: as the service answers it.
    pub async fn reply(d: &Arc<Daemon>, msg: &[u8]) -> Option<Vec<u8>> {
        let spec = match api::request_of(msg) {
            Ok(x) => x,
            Err(refused) => return Some(api::error_reply(refused.status, &refused.why)),
        };
        let answer = answerer(spec.n)?;
        Some(answer(d, msg).await)
    }

    /// An argument a request cannot go without, as the handlers by name
    /// said it was missing.
    fn needed<T>(v: Option<T>, name: &str) -> anyhow::Result<T> {
        v.ok_or_else(|| anyhow::anyhow!("missing argument {name}"))
    }

    // ---- The service, this device, and the person's devices ----

    impl Answer for ConditionsArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<ConditionsReply> {
            if let Some(plugged_in) = a.plugged_in {
                let metered = a.metered.unwrap_or(false);
                d.conditions.tell(crate::conditions::Told {
                    plugged_in,
                    metered,
                });
                d.bump();
            }
            Ok(d.conditions.reply())
        }
    }

    impl Answer for NetworkChangedArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Checking> {
            let checking = d.network_changed(a.why.as_deref().unwrap_or("told"));
            Ok(Checking {
                checking: checking as u64,
            })
        }
    }

    /// The device woke (D86): what a network change does, said by
    /// whatever sees it wake, as Android does for the app.
    impl Answer for WakeArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<Checking> {
            let checking = d.network_changed("woke");
            Ok(Checking {
                checking: checking as u64,
            })
        }
    }

    impl Answer for StatusArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<StatusReply> {
            Ok(super::status_reply(d))
        }
    }

    impl Answer for ContactStatusArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<ContactStatusReply> {
            // looking is done with the first page, never again for the next
            let first = a.after.unwrap_or(0) == 0;
            let look = first && a.look == Some(true);
            let at = match a.at.as_deref().filter(|_| first) {
                Some(at) => Some(at.parse().map_err(|_| {
                    anyhow::anyhow!("{at} is not an address; it looks like 192.168.1.20:7171")
                })?),
                None => None,
            };
            let who = needed(a.who.as_ref(), "who")?;
            crate::contacts::reaching(d, who.as_ref(), &who.held(), look, at).await
        }
    }

    impl Answer for HelloArgs {
        async fn answer(_: &Arc<Daemon>, _: &Self) -> anyhow::Result<HelloReply> {
            Ok(HelloReply {
                api: super::API,
                version: env!("CARGO_PKG_VERSION").into(),
            })
        }
    }

    impl Answer for ReadMarkersArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<ReadMarkersReply> {
            crate::settings::read_markers(d, a.on)
        }
    }

    impl Answer for CancelInvitationArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            crate::contacts::cancel_invitation(d, needed(a.id.as_ref(), "id")?.as_ref())
        }
    }

    impl Answer for IntroduceArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            let who = needed(a.who.as_ref(), "who")?;
            let to = needed(a.to.as_ref(), "to")?;
            crate::introductions::introduce(d, who.as_ref(), to.as_ref(), a.note.as_deref())
        }
    }

    impl Answer for IntroductionAcceptArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<IntroductionAcceptReply> {
            crate::introductions::accept(d, needed(a.id.as_ref(), "id")?.as_ref()).await
        }
    }

    impl Answer for IntroductionDeclineArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            crate::introductions::decline(d, needed(a.id.as_ref(), "id")?.as_ref())
        }
    }

    impl Answer for GroupConnectArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupConnectReply> {
            let group = needed(a.group.as_ref(), "group")?;
            let who = needed(a.who.as_ref(), "who")?;
            crate::introductions::ask_in_group(d, group.as_ref(), who.as_ref(), a.note.as_deref())
        }
    }

    impl Answer for GroupPostAgainArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupPostAgainReply> {
            crate::groups::post_again(d, needed(a.group.as_ref(), "group")?.as_ref())
        }
    }

    impl Answer for GroupMovedSeenArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            crate::groups::moved_seen(d, needed(a.group.as_ref(), "group")?.as_ref())
        }
    }

    impl Answer for GroupConfirmMoveArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupConfirmMoveReply> {
            let group = needed(a.group.as_ref(), "group")?;
            let none = Vec::new();
            let moves = a.moves.as_ref().unwrap_or(&none);
            let to = a.to.as_ref().unwrap_or(&none);
            crate::groups::confirm_move(d, group.as_ref(), moves, to)
        }
    }

    impl Answer for GroupLeavingArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupLeavingReply> {
            crate::groups::leaving(d, needed(a.group.as_ref(), "group")?.as_ref())
        }
    }

    // ---- Guardians ----

    impl Answer for GuardiansArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<GuardiansReply> {
            crate::guardians::show(d)
        }
    }

    impl Answer for GuardiansSetArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GuardiansSetReply> {
            let none = Vec::new();
            let who = a.who.as_ref().unwrap_or(&none);
            crate::guardians::set(d, who, a.threshold, a.delay, a.words.as_deref())
        }
    }

    impl Answer for GuardiansObjectArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            crate::guardians::object(d, a.fingerprint.as_deref())
        }
    }

    impl Answer for GuardiansAskArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<NameReply> {
            crate::guardians::ask(d, needed(a.who.as_ref(), "who")?.as_ref())
        }
    }

    impl Answer for GuardingArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<GuardingReply> {
            Ok(crate::guardians::list(d))
        }
    }

    impl Answer for GuardingInviteArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GuardingInviteReply> {
            let who = needed(a.who.as_ref(), "who")?;
            crate::guardians::invite(d, who.as_ref(), a.at.as_deref()).await
        }
    }

    impl Answer for GuardingAcceptArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GuardingAcceptReply> {
            crate::guardians::accept_role(d, needed(a.who.as_ref(), "who")?.as_ref()).await
        }
    }

    impl Answer for GuardingConfirmChangeArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GuardingReply> {
            let understood = a.understood == Some(true);
            let who = needed(a.who.as_ref(), "who")?;
            let fp = a.fingerprint.as_deref();
            crate::guardians::confirm_change(d, who.as_ref(), fp, understood).await
        }
    }

    impl Answer for GuardingNeverArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GuardingReply> {
            let who = needed(a.who.as_ref(), "who")?;
            let fp = needed(a.fingerprint.as_deref(), "fingerprint")?;
            crate::guardians::never(d, who.as_ref(), fp)
        }
    }

    impl Answer for GuardingCautionArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GuardingCautionReply> {
            crate::guardians::caution_for(d, needed(a.who.as_ref(), "who")?.as_ref())
        }
    }

    impl Answer for GuardingEndorseArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GuardingReply> {
            let understood = a.understood == Some(true);
            let who = needed(a.who.as_ref(), "who")?;
            let fp = needed(a.fingerprint.as_deref(), "fingerprint")?;
            crate::guardians::endorse(d, who.as_ref(), fp, understood).await
        }
    }

    impl Answer for GuardingConfirmArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GuardingReply> {
            let understood = a.understood == Some(true);
            let who = needed(a.who.as_ref(), "who")?;
            let fp = needed(a.fingerprint.as_deref(), "fingerprint")?;
            crate::guardians::confirm(d, who.as_ref(), fp, understood).await
        }
    }

    // ---- Recovery ----

    impl Answer for RecoverArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<RecoverReply> {
            crate::recovering::status(d)
        }
    }

    impl Answer for RecoverStartArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RecoverStartReply> {
            crate::recovering::start(d, a.code.as_deref(), a.identity.as_ref()).await
        }
    }

    impl Answer for RecoverInviteArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RecoverInviteReply> {
            crate::recovering::invite(d, a.at.as_deref()).await
        }
    }

    impl Answer for RecoverLostAtArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<LostDevicesReply> {
            crate::recovering::set_lost_at(d, a.lost_at)
        }
    }

    impl Answer for RecoverCancelArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<RecoverCancelReply> {
            crate::recovering::cancel(d).await
        }
    }

    impl Answer for RecoverFinishArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RecoverFinishReply> {
            let without = a.without_account == Some(true);
            crate::recovering::finish(d, without, a.lost_at).await
        }
    }

    impl Answer for KeepWorkArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<KeepWorkReply> {
            let name = needed(a.name.as_deref(), "name")?;
            crate::recovering::keep_work(d, name, a.up_to.as_deref())
        }
    }

    impl Answer for RecoveryCheckArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            crate::recovery::root_from_words(d, needed(a.words.as_deref(), "words")?)?;
            Ok(Done {})
        }
    }

    impl Answer for RecoverySheetArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<RecoverySheetReply> {
            Ok(RecoverySheetReply {
                hosts: crate::host::hosts(d)?,
            })
        }
    }

    impl Answer for RestoreFromHostArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RestoreFromHostReply> {
            let words = needed(a.words.as_deref(), "words")?;
            let at = needed(a.at.as_deref(), "at")?;
            let key = needed(a.key.as_ref(), "key")?;
            crate::host::restore(d, words, at, key).await
        }
    }

    impl Answer for RecoverUndoArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RecoverUndoReply> {
            crate::recovering::undo_kept(d, needed(a.to.as_ref(), "to")?).await
        }
    }

    impl Answer for RecoverKeptSeenArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<KeptChangesReply> {
            let none = Vec::new();
            crate::recovering::kept_seen(d, a.to.as_ref().unwrap_or(&none))
        }
    }

    impl Answer for RecoverStopWaitingArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RecoverStopWaitingReply> {
            let all = a.all == Some(true);
            let who = a.who.as_ref().map(|w| w.as_ref());
            crate::recovering::stop_waiting(d, who, all).await
        }
    }

    // ---- Hosting contacts ----

    impl Answer for HostOfferArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<HostOfferReply> {
            let who = needed(a.who.as_ref(), "who")?;
            let none = Vec::new();
            let devices = a.devices.as_ref().unwrap_or(&none);
            crate::hosting::offer(d, who.as_ref(), devices, a.envelopes, a.relay_mb)
        }
    }

    impl Answer for HostAcceptArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<HostAcceptReply> {
            crate::hosting::accept(d, needed(a.who.as_ref(), "who")?.as_ref())
        }
    }

    impl Answer for HostEndArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<HostEndReply> {
            crate::hosting::end(d, needed(a.who.as_ref(), "who")?.as_ref())
        }
    }

    impl Answer for HostingArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<HostingReply> {
            Ok(crate::hosting::list(d))
        }
    }

    // ---- The service, and freeing space ----

    impl Answer for StopArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<Done> {
            let _ = d.stopping.send(true);
            Ok(Done {})
        }
    }

    impl Answer for ReloadArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<Done> {
            super::reload(d)?;
            Ok(Done {})
        }
    }

    impl Answer for KeepOldArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<KeepOldReply> {
            let keep = crate::cleanup::Keep::parse(needed(a.keep.as_deref(), "keep")?)?;
            // for one space, in place of the device's period; without
            // one, the device's, for every space not set otherwise
            match a.space.as_ref() {
                None => d.config().keep_old = keep.to_string(),
                Some(Reference::Typed(t)) if t.is_empty() => d.config().keep_old = keep.to_string(),
                Some(s) => {
                    let space = hex::encode(super::space_held_ref(d, s.as_ref())?);
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
            Ok(KeepOldReply {
                keep: keep.to_string(),
            })
        }
    }

    impl Answer for FreeSpaceArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<FreeSpaceReply> {
            let d2 = d.clone();
            if a.unnamed == Some(true) {
                let delete = a.delete == Some(true);
                let found =
                    tokio::task::spawn_blocking(move || crate::cleanup::unnamed(&d2, delete))
                        .await??;
                return Ok(FreeSpaceReply {
                    objects: found.objects,
                    bytes: found.bytes,
                    deleted: Some(found.deleted),
                    unsure: Some(found.unsure),
                    left: None,
                    only_here: None,
                    unchecked: None,
                });
            }
            let dry_run = a.dry_run.unwrap_or(false);
            let f = tokio::task::spawn_blocking(move || crate::cleanup::pass(&d2, true, dry_run))
                .await??;
            let old = crate::cleanup::shown(d);
            Ok(FreeSpaceReply {
                objects: f.objects,
                bytes: f.bytes,
                left: Some(f.left),
                only_here: old.only_here,
                unchecked: old.unchecked,
                deleted: None,
                unsure: None,
            })
        }
    }

    impl Answer for HistoryEmptyArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<HistoryEmptyReply> {
            let empty = match a.space.as_ref() {
                None => crate::cleanup::Empty::All,
                Some(Reference::Typed(t)) if t.is_empty() => crate::cleanup::Empty::All,
                Some(s) => crate::cleanup::Empty::Space(super::space_held_ref(d, s.as_ref())?),
            };
            let d2 = d.clone();
            let f = tokio::task::spawn_blocking(move || {
                crate::cleanup::pass_emptying(&d2, empty, false)
            })
            .await??;
            Ok(HistoryEmptyReply {
                objects: f.objects,
                bytes: f.bytes,
                left: f.left,
            })
        }
    }

    impl Answer for MeArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<MeReply> {
            crate::names::me(d, a.name.as_deref())
        }
    }

    impl Answer for PairShowArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PairShowReply> {
            // what to call this device, where the window knows better
            if let Some(name) = super::device_name_given(a.device.as_deref())? {
                super::rename_this_device(d, &name)?;
            }
            let s = crate::pair::show(d).await?;
            Ok(PairShowReply {
                code: s.code,
                addrs: s.addrs.iter().map(|a| a.to_string()).collect(),
            })
        }
    }

    impl Answer for PairStatusArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<PairStatusReply> {
            let ps = d.pairing.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let state = |state: &'static str| {
                cardinal_interface::new!(PairStatusReply {
                    state: state.into()
                })
            };
            let power = |p| super::joins_as_name(p).map(Into::into);
            Ok(match ps {
                PairState::Idle => state("idle"),
                PairState::Showing { code } => PairStatusReply {
                    code: Some(code),
                    ..state("showing")
                },
                PairState::Joining {
                    admin_name,
                    power: p,
                    ..
                } => PairStatusReply {
                    admin: Some(admin_name),
                    power: power(p),
                    ..state("joining")
                },
                PairState::Joined {
                    admin_name,
                    power: p,
                } => PairStatusReply {
                    admin: Some(admin_name),
                    files: Some(d.core().files_id().is_some()),
                    power: power(p),
                    ..state("joined")
                },
                PairState::Failed(e) => PairStatusReply {
                    error: Some(e),
                    ..state("failed")
                },
            })
        }
    }

    impl Answer for PairTypeArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PairTypeReply> {
            let code = needed(a.code.as_deref(), "code")?;
            let at = match a.at.as_deref() {
                Some(at) => Some(
                    tokio::net::lookup_host(at)
                        .await
                        .ok()
                        .and_then(|mut i| i.next())
                        .ok_or_else(|| anyhow::anyhow!("{at} is not an address (ip:port)"))?,
                ),
                None => None,
            };
            let admin = a.admin.unwrap_or(false);
            let device = super::device_name_given(a.device.as_deref())?;
            let words = a.words.as_deref();
            let name = crate::pair::type_code(d, code, at, admin, words, device.as_deref()).await?;
            Ok(PairTypeReply { name })
        }
    }

    // ---- The clipboard ----

    impl Answer for ClipCopyArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<ClipCopyReply> {
            crate::clipboard::copy(d, needed(a.text.as_deref(), "text")?).await
        }
    }

    impl Answer for ClipArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<ClipReply> {
            Ok(crate::clipboard::paste(d))
        }
    }

    // ---- The one folder ----

    impl Answer for MkdirArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PathReply> {
            crate::onefolder::mkdir(d, needed(a.path.as_deref(), "path")?)
        }
    }

    impl Answer for MoveArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PathReply> {
            let (from, to) = (
                needed(a.from.as_deref(), "from")?,
                needed(a.to.as_deref(), "to")?,
            );
            crate::onefolder::move_to(d, from, to).await
        }
    }

    impl Answer for RemoveArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PathReply> {
            crate::onefolder::remove(d, needed(a.path.as_deref(), "path")?)
        }
    }

    impl Answer for CopyArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PathReply> {
            let (from, to) = (
                needed(a.from.as_deref(), "from")?,
                needed(a.to.as_deref(), "to")?,
            );
            crate::onefolder::copy(d, from, to).await
        }
    }

    impl Answer for PutArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PathReply> {
            let (from, to) = (
                needed(a.from.as_deref(), "from")?,
                needed(a.to.as_deref(), "to")?,
            );
            crate::onefolder::put(d, from, to).await
        }
    }

    impl Answer for SaveArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<SaveReply> {
            let (path, to) = (
                needed(a.path.as_deref(), "path")?,
                needed(a.to.as_deref(), "to")?,
            );
            crate::onefolder::save(d, path, to, a.version).await
        }
    }

    impl Answer for WriteArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PathReply> {
            let from = needed(a.from.as_deref(), "from")?;
            let path = needed(a.path.as_deref(), "path")?;
            crate::onefolder::write(d, from, path).await
        }
    }

    impl Answer for ShareArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<ShareReply> {
            let paths = a.paths.clone().unwrap_or_default();
            // `share`'s lookups still take a ref as held by name
            let who = a.who.as_ref().map(Reference::held);
            let group = a.group.as_ref().map(Reference::held);
            let text = a.text.as_deref();
            crate::onefolder::share(d, who.as_deref(), group.as_deref(), &paths, text).await
        }
    }

    impl Answer for MountArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PathReply> {
            let path = super::mount_at(d, a.path.as_deref()).await?;
            Ok(PathReply {
                path: path.to_string_lossy().into_owned(),
            })
        }
    }

    impl Answer for UnmountArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<Done> {
            super::unmount(d).await?;
            Ok(Done {})
        }
    }

    impl Answer for FlushArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<FlushReply> {
            let entries = super::flush(d).await? as u64;
            Ok(FlushReply { entries })
        }
    }

    impl Answer for RestoreArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RestoreReply> {
            let path = needed(a.path.as_deref(), "path")?;
            let version = a
                .version
                .ok_or_else(|| anyhow::anyhow!("missing --version"))?;
            crate::file_history::restore(d, path, version).await
        }
    }

    impl Answer for PinArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PinReply> {
            let (path, on_demand) = super::pin(d, needed(a.path.as_deref(), "path")?, true)?;
            Ok(PinReply { on_demand, path })
        }
    }

    impl Answer for UnpinArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PinReply> {
            let (path, on_demand) = super::pin(d, needed(a.path.as_deref(), "path")?, false)?;
            Ok(PinReply { on_demand, path })
        }
    }

    impl Answer for RetentionArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RetentionReply> {
            let mode = needed(a.mode.clone(), "mode")?;
            super::set_retention(d, &mode)?;
            Ok(RetentionReply { retention: mode })
        }
    }

    // ---- People, conversations and invitations ----

    /// How a contact made by an invitation is regarded: trusted unless
    /// `hosts_only`, introducing unless `no_introductions`.
    fn regard(hosts_only: Option<bool>, no_introductions: Option<bool>) -> account::Regard {
        account::Regard {
            trusted: hosts_only != Some(true),
            introductions: no_introductions != Some(true),
        }
    }

    impl Answer for InviteArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<InviteReply> {
            let regard = regard(a.hosts_only, a.no_introductions);
            crate::contacts::invite(d, a.address.as_deref(), a.name.as_deref(), regard)
        }
    }

    impl Answer for AcceptArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<AcceptReply> {
            let met = account::Met {
                how: account::MET_THEIR_INVITATION,
                via: a.via.clone(),
                ..Default::default()
            };
            // the person's own accept: the only one that takes a recovery's;
            // `for`, whom a recovery invitation made for whomever this
            // guardian names is for, as their contacts call them
            let whom = match &a.r#for {
                Some(w) => Some(crate::contacts::find_ref(d, w.as_ref())?.identity),
                None => None,
            };
            let code = needed(a.code.as_deref(), "code")?;
            let regard = regard(a.hosts_only, a.no_introductions);
            crate::contacts::accept_for(d, code, a.name.as_deref(), regard, met, true, whom).await
        }
    }

    // ---- Messages, with a contact or in a group ----

    impl Answer for SayArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<SayReply> {
            let reply_to = a.reply_to.as_ref().map(Reference::as_ref);
            let attach = a.attach.as_deref().unwrap_or_default();
            match &a.group {
                Some(group) => {
                    let text = needed(a.text.as_deref(), "text")?;
                    crate::groups::say(d, group.as_ref(), text, reply_to, attach).await?;
                    Ok(SayReply::new())
                }
                None => {
                    let who = needed(a.who.as_ref(), "who")?;
                    let text = needed(a.text.as_deref(), "text")?;
                    crate::contacts::say(d, who.as_ref(), text, reply_to, attach).await
                }
            }
        }
    }

    impl Answer for SaveAttachmentArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<api::SaveReply> {
            let index = a.index.unwrap_or(0) as usize;
            let (place, id, to) = match &a.group {
                Some(group) => (
                    group,
                    needed(a.id.as_ref(), "id")?,
                    needed(a.to.as_deref(), "to")?,
                ),
                None => (
                    needed(a.who.as_ref(), "who")?,
                    needed(a.id.as_ref(), "id")?,
                    needed(a.to.as_deref(), "to")?,
                ),
            };
            match a.group {
                Some(_) => {
                    crate::groups::save_attachment(d, place.as_ref(), id.as_ref(), index, to).await
                }
                None => {
                    crate::contacts::save_attachment(d, place.as_ref(), id.as_ref(), index, to)
                        .await
                }
            }
        }
    }

    impl Answer for EditMessageArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            match &a.group {
                Some(group) => {
                    let id = needed(a.id.as_ref(), "id")?;
                    let text = needed(a.text.as_deref(), "text")?;
                    crate::groups::edit_message(d, group.as_ref(), id.as_ref(), text)?;
                }
                None => {
                    let who = needed(a.who.as_ref(), "who")?;
                    let id = needed(a.id.as_ref(), "id")?;
                    let text = needed(a.text.as_deref(), "text")?;
                    crate::contacts::edit_message(d, who.as_ref(), id.as_ref(), text)?;
                }
            }
            Ok(Done {})
        }
    }

    impl Answer for DeleteMessageArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            match &a.group {
                Some(group) => {
                    let id = needed(a.id.as_ref(), "id")?;
                    crate::groups::delete_message(d, group.as_ref(), id.as_ref())?;
                }
                None => {
                    let who = needed(a.who.as_ref(), "who")?;
                    let id = needed(a.id.as_ref(), "id")?;
                    crate::contacts::delete_message(d, who.as_ref(), id.as_ref())?;
                }
            }
            Ok(Done {})
        }
    }

    impl Answer for ReactArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            match &a.group {
                Some(group) => {
                    let id = needed(a.id.as_ref(), "id")?;
                    let text = needed(a.text.as_deref(), "text")?;
                    crate::groups::react(d, group.as_ref(), id.as_ref(), text)?;
                }
                None => {
                    let who = needed(a.who.as_ref(), "who")?;
                    let id = needed(a.id.as_ref(), "id")?;
                    let text = needed(a.text.as_deref(), "text")?;
                    crate::contacts::react(d, who.as_ref(), id.as_ref(), text)?;
                }
            }
            Ok(Done {})
        }
    }

    impl Answer for MarkReadArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<MarkReadReply> {
            match &a.group {
                Some(group) => crate::groups::mark_read(d, group.as_ref()),
                None => crate::contacts::mark_read(d, needed(a.who.as_ref(), "who")?.as_ref()),
            }
        }
    }

    // ---- Groups ----

    impl Answer for GroupsArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<GroupsReply> {
            Ok(crate::groups::list(d))
        }
    }

    impl Answer for GroupCreateArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupCreateReply> {
            let for_call = a.for_call.unwrap_or(false);
            let history = a.history.unwrap_or(true);
            let people = a.people.as_deref().unwrap_or_default();
            let name = needed(a.name.as_deref(), "name")?;
            crate::groups::create(d, name, people, for_call, history)
        }
    }

    impl Answer for GroupAddArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            let group = needed(a.group.as_ref(), "group")?;
            let people = a.people.as_deref().unwrap_or_default();
            crate::groups::add(d, group.as_ref(), people, a.shown.as_deref())?;
            Ok(Done {})
        }
    }

    impl Answer for GroupRemoveArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupRemoveReply> {
            let group = needed(a.group.as_ref(), "group")?;
            let who = needed(a.who.as_ref(), "who")?;
            crate::groups::remove(d, group.as_ref(), who).await
        }
    }

    impl Answer for GroupRoleArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupRoleReply> {
            let group = needed(a.group.as_ref(), "group")?;
            let who = needed(a.who.as_ref(), "who")?;
            let role = needed(a.role.as_deref(), "role")?;
            crate::groups::set_role(d, group.as_ref(), who, role).await
        }
    }

    impl Answer for GroupLeaveArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupLeaveReply> {
            let anyway = a.anyway == Some(true);
            let group = needed(a.group.as_ref(), "group")?;
            let admins = a.admins.as_deref().unwrap_or_default();
            crate::groups::leave(d, group.as_ref(), admins, anyway)
        }
    }

    impl Answer for GroupRejoinArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupCreateReply> {
            crate::groups::rejoin(d, needed(a.group.as_ref(), "group")?)
        }
    }

    impl Answer for GroupJoinArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupJoinReply> {
            let group = needed(a.group.as_ref(), "group")?;
            crate::groups::join(d, group.as_ref(), a.reach).await
        }
    }

    impl Answer for GroupReachArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupReachReply> {
            let share = a
                .share
                .ok_or_else(|| anyhow::anyhow!("say whether to share: share"))?;
            match a.host.as_deref() {
                Some(host) if !share => {
                    let group = needed(a.group.as_ref(), "group")?;
                    crate::groups::no_host(d, group.as_ref(), host).await
                }
                Some(_) => anyhow::bail!("a host is taken out with share false"),
                None => {
                    let group = needed(a.group.as_ref(), "group")?;
                    crate::groups::set_reach(d, group.as_ref(), share).await
                }
            }
        }
    }

    impl Answer for GroupDeclineArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            crate::groups::decline(d, needed(a.group.as_ref(), "group")?.as_ref())?;
            Ok(Done {})
        }
    }

    impl Answer for GroupMembersArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<GroupMembersReply> {
            crate::groups::members(d, needed(a.group.as_ref(), "group")?.as_ref())
        }
    }

    impl Answer for GroupSetArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            let group = needed(a.group.as_ref(), "group")?;
            let (name, introductions) = (a.name.as_deref(), a.introductions);
            crate::groups::set(d, group.as_ref(), name, introductions, a.for_call)?;
            Ok(Done {})
        }
    }

    impl Answer for GroupMemberArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            let group = needed(a.group.as_ref(), "group")?;
            let who = needed(a.who.as_ref(), "who")?;
            let (shown, introduce) = (a.shown.as_deref(), a.introduce);
            crate::groups::set_member(d, group.as_ref(), who, shown, introduce)?;
            Ok(Done {})
        }
    }

    // ---- Calls ----

    /// The formats a call offers or takes: by name, of the draft, or 32
    /// bytes each; neither, voice.
    fn formats(
        formats: &Option<Vec<bytes::Bytes>>,
        names: &Option<Vec<String>>,
    ) -> anyhow::Result<Option<Vec<crate::calls::Format>>> {
        if let Some(names) = names {
            return Ok(Some(
                names
                    .iter()
                    .map(|n| crate::calls::draft_format(n))
                    .collect(),
            ));
        }
        let Some(list) = formats else {
            return Ok(None);
        };
        list.iter()
            .map(|f| {
                <[u8; 32]>::try_from(&f[..])
                    .map_err(|_| anyhow::anyhow!("a format is 32 bytes of hex"))
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .map(Some)
    }

    impl Answer for CallStartArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            if let Some(ring) = &a.ring {
                anyhow::ensure!(
                    a.who.is_none(),
                    "`ring` names members of a group: it is not for a call with one person"
                );
                anyhow::ensure!(!ring.is_empty(), "`ring` names someone to ring");
                let group = needed(a.group.as_ref(), "group")?;
                crate::calls::start_group(d, group.as_ref(), Some(ring)).await?;
            } else if let Some(group) = &a.group {
                crate::calls::start_group(d, group.as_ref(), None).await?;
            } else {
                let who = needed(a.who.as_ref(), "who")?;
                let formats = formats(&a.formats, &a.format_names)?;
                crate::calls::start(d, who.as_ref(), formats).await?;
            }
            Ok(Done {})
        }
    }

    impl Answer for CallAnswerArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            let formats = formats(&a.formats, &a.format_names)?;
            crate::calls::answer(d, formats, a.reach, a.join).await?;
            Ok(Done {})
        }
    }

    impl Answer for CallEndArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<Done> {
            crate::calls::end(d).await?;
            Ok(Done {})
        }
    }

    // ---- Listings ----

    impl Answer for ContactsArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<ContactsReply> {
            Ok(crate::contacts::list(d, a.all == Some(true)))
        }
    }

    impl Answer for ConversationsArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<ConversationsReply> {
            Ok(crate::contacts::conversations(d))
        }
    }

    impl Answer for ConflictsArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<ConflictsReply> {
            Ok(ConflictsReply {
                conflicts: super::conflict_list(d)?,
                // the page says
                more: false,
                next: None,
            })
        }
    }

    impl Answer for DevicesArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<DevicesReply> {
            Ok(DevicesReply {
                devices: super::device_list(d),
                // the page says
                more: false,
                next: None,
            })
        }
    }

    impl Answer for InvitationsArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<InvitationsReply> {
            Ok(crate::contacts::invitations(d))
        }
    }

    impl Answer for IntroductionsArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<IntroductionsReply> {
            Ok(crate::introductions::list(d))
        }
    }

    impl Answer for HistoryArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<HistoryReply> {
            crate::file_history::history(d, needed(a.path.as_deref(), "path")?)
        }
    }

    impl Answer for DeletedArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<DeletedReply> {
            let path = a.path.as_deref().unwrap_or("");
            crate::file_history::deleted(d, path, a.hidden.unwrap_or(false))
        }
    }

    impl Answer for SpaceUsageArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<SpaceUsageReply> {
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || crate::cleanup::usage_of(&d2)).await?
        }
    }

    impl Answer for PeerListArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<PeerListReply> {
            let peers = d.config().peers.clone();
            let book = d.book.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let names = d.core().device_names();
            let peers = peers
                .iter()
                .map(|p| {
                    let dev = book.manual.get(p).and_then(|h| {
                        let b = hex::decode(h).ok()?;
                        <[u8; 32]>::try_from(&b[..]).ok()
                    });
                    api::Peer {
                        addr: p.clone(),
                        device: dev.map(|k| {
                            names
                                .get(&k)
                                .cloned()
                                .unwrap_or_else(|| super::account::short_key(&k))
                        }),
                    }
                })
                .collect();
            Ok(PeerListReply {
                peers,
                // the page says
                more: false,
                next: None,
            })
        }
    }

    // ---- Networks, hosts and peers ----

    impl Answer for RouterArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RouterReply> {
            if let Some(on) = a.on {
                let here = a.this_device == Some(true);
                crate::portmap::set_on(d, on, here)?;
            }
            let r = crate::portmap::router(d);
            Ok(RouterReply {
                error: r.error,
                everywhere: r.everywhere,
                external: r.external,
                named: r.named,
                network: r.network,
                on: r.on,
                protocol: r.protocol,
                seconds_left: r.seconds_left,
                this_device: r.this_device,
            })
        }
    }

    impl Answer for BluetoothArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<BluetoothReply> {
            let b = match a.mode.as_deref() {
                Some(m) => {
                    let m = crate::bluetooth::Mode::parse(m)
                        .ok_or_else(|| anyhow::anyhow!("Bluetooth is `off`, `open` or `always`"))?;
                    crate::bluetooth::set(d, m)?
                }
                None => crate::bluetooth::check(d).await,
            };
            Ok(BluetoothReply {
                available: b.available,
                channels_in: b.channels_in,
                error: b.error,
                mode: b.mode,
                on: b.on,
                psm: b.psm,
                radio: b.radio,
                recognized: b.recognized,
                seen: b.seen,
                why_not: b.why_not,
                windows: b.windows,
                too_old: b.too_old,
            })
        }
    }

    impl Answer for NetworkArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<NetworkReply> {
            let n = match a.mine {
                Some(mine) => crate::networks::mark(d, mine, a.name.as_deref())?,
                None => crate::networks::network(d),
            };
            Ok(NetworkReply {
                answered: n.answered,
                ask: n.ask,
                known: n.known,
                mine: n.mine,
                name: n.name,
                router: n.router,
                routers: n.routers,
            })
        }
    }

    impl Answer for HostArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<HostReply> {
            let addresses = a.addresses.as_deref().unwrap_or_default();
            crate::host::enable(d, addresses)
        }
    }

    impl Answer for HostOffArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<HostsReply> {
            crate::host::disable(d)
        }
    }

    impl Answer for PeerAddArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<PeerAddReply> {
            let addr = needed(a.addr.as_deref(), "addr")?.trim().to_owned();
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
            Ok(PeerAddReply { addr })
        }
    }

    impl Answer for PeerRemoveArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            let addr = needed(a.addr.as_deref(), "addr")?;
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
            Ok(Done {})
        }
    }

    // ---- Setting up, this person's devices, and their contacts ----

    impl Answer for SetupBeginArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<SetupBeginReply> {
            super::setup_begin(d)
        }
    }

    impl Answer for SetupFinishArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<SetupFinishReply> {
            super::setup_finish(d, a)
        }
    }

    impl Answer for RemoveDeviceArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<RemoveDeviceReply> {
            let who = needed(a.who.as_ref(), "who")?;
            let lost = a.lost.unwrap_or(false);
            super::remove_device(d, who.as_ref(), a.words.as_deref(), lost).await
        }
    }

    /// `contact`: a new name, a picture, a category, or a setting, in that
    /// order of what is given.
    impl Answer for ContactArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<ContactReply> {
            let who = || needed(a.who.as_ref(), "who").map(Reference::as_ref);
            if let Some(name) = a.name.as_deref() {
                return crate::contacts::rename(d, who()?, name);
            }
            if let Some(from) = a.picture.as_deref() {
                return crate::names::set_picture(d, who()?, from).await;
            }
            if let Some(category) = a.category.as_deref() {
                return crate::contacts::set_category(d, who()?, category);
            }
            match needed(a.setting.as_deref(), "setting")? {
                "name-hosts" => crate::contacts::name_hosts(d, who()?, true).await,
                "no-hosts" => crate::contacts::name_hosts(d, who()?, false).await,
                "no-host" => {
                    let who = who()?;
                    crate::contacts::no_host(d, who, needed(a.host.as_deref(), "host")?).await
                }
                setting => crate::contacts::set(d, who()?, setting),
            }
        }
    }

    // ---- Inspection (`inspect.rs`): the person turns it on, on this
    // device, and only whoever holds the token it gives may look ----

    impl Answer for InspectOnArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<InspectOnReply> {
            let minutes = a.minutes.unwrap_or(crate::inspect::DEFAULT_MINUTES);
            let (token, until) = d.inspection.grant(minutes)?;
            d.bump();
            Ok(InspectOnReply { token, until })
        }
    }

    impl Answer for InspectOffArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<InspectOffReply> {
            let was = d.inspection.revoke();
            d.bump();
            Ok(InspectOffReply { was_on: was })
        }
    }

    impl Answer for InspectArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<InspectReply> {
            crate::inspect::answers::overview(d, a)
        }
    }

    impl Answer for InspectIdentityArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<InspectIdentityReply> {
            crate::inspect::answers::identity(d, a)
        }
    }

    impl Answer for InspectSpaceArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<InspectSpaceReply> {
            crate::inspect::answers::space(d, a)
        }
    }

    impl Answer for InspectEntriesArgs {
        async fn answer(
            d: &Arc<Daemon>,
            a: &Self,
        ) -> anyhow::Result<api::typed::Precut<InspectEntriesReply>> {
            crate::inspect::answers::entries(d, a)
        }
    }

    impl Answer for InspectEntryArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<InspectEntryReply> {
            crate::inspect::answers::entry(d, a)
        }
    }

    impl Answer for InspectNodesArgs {
        async fn answer(
            d: &Arc<Daemon>,
            a: &Self,
        ) -> anyhow::Result<api::typed::Precut<InspectNodesReply>> {
            crate::inspect::answers::nodes(d, a)
        }
    }

    impl Answer for InspectNodeArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<InspectNodeReply> {
            crate::inspect::answers::node(d, a)
        }
    }

    // ---- Measuring, and the files brought back ----

    impl Answer for DebugTreeArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<DebugTreeReply> {
            super::debug_tree(d)
        }
    }

    impl Answer for SpeedtestArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<SpeedtestReply> {
            super::speedtest(d, needed(a.device.as_ref(), "device")?.as_ref()).await
        }
    }

    impl Answer for UndeleteArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<UndeleteReply> {
            let path = needed(a.path.as_deref(), "path")?;
            crate::file_history::undelete(d, path, a.id.as_ref().map(Reference::as_ref)).await
        }
    }

    // ---- What programs ask the person ----

    impl Answer for AppQuestionsArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<AppQuestionsReply> {
            Ok(cardinal_interface::new!(AppQuestionsReply {
                questions: crate::apps::questions(d),
                more: false
            }))
        }
    }

    impl Answer for AppAnswerArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            crate::apps::answer(d, a)
        }
    }

    impl Answer for ApprovalsArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<ApprovalsReply> {
            Ok(cardinal_interface::new!(ApprovalsReply {
                approvals: crate::apps::list_approvals(d),
                more: false
            }))
        }
    }

    impl Answer for ApprovalRevokeArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<Done> {
            crate::apps::revoke(d, needed(a.id.as_ref(), "id")?.as_ref())
        }
    }

    impl Answer for AppOffersArgs {
        async fn answer(d: &Arc<Daemon>, _: &Self) -> anyhow::Result<AppOffersReply> {
            Ok(cardinal_interface::new!(AppOffersReply {
                offers: crate::apps::list_offers(d),
                more: false
            }))
        }
    }

    impl Answer for AppJoinArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<AppJoinReply> {
            crate::apps::join(d, needed(a.space.as_ref(), "space")?.as_ref())
        }
    }

    impl Answer for DeviceRenameArgs {
        async fn answer(d: &Arc<Daemon>, a: &Self) -> anyhow::Result<DeviceRenameReply> {
            let device = needed(a.device.as_ref(), "device")?;
            let name = needed(a.name.as_deref(), "name")?;
            super::rename_device(d, device.as_ref(), name)
        }
    }
}

/// An error of the guardians' and recovery requests, starting with a
/// capital letter, as a window shows it word for word. Others are as
/// they were.
fn capitalized(cmd: &str, e: anyhow::Error) -> anyhow::Error {
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
#[cfg(any(test, debug_assertions, feature = "by-name"))]
fn strings(req: &Value, name: &str) -> Vec<String> {
    let list = req.get(name).and_then(|v| v.as_array());
    let items = list.into_iter().flatten();
    items
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect()
}

/// What a client knows of this device's power and network
/// (`apps.md#the-local-interface`), and what the service makes of it.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
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
#[cfg(any(test, debug_assertions, feature = "by-name"))]
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
#[cfg(any(test, debug_assertions, feature = "by-name"))]
fn space_held(d: &Daemon, s: &str) -> anyhow::Result<cardinal_space::SpaceId> {
    space_starting(d, crate::api::id_hex(s).trim().to_ascii_lowercase())
}

/// The space held here whose id starts with `s`, a `ref` as it came. An
/// old oddity, kept (DEVIATIONS.md): an id given as bytes is the start of
/// one here too, as the way by name read its hex.
fn space_held_ref(d: &Daemon, s: api::Ref<'_>) -> anyhow::Result<cardinal_space::SpaceId> {
    let s = match s {
        api::Ref::Typed(t) => t.trim().to_ascii_lowercase(),
        api::Ref::Id(id) => id.hex().into_owned(),
    };
    space_starting(d, s)
}

fn space_starting(d: &Daemon, s: String) -> anyhow::Result<cardinal_space::SpaceId> {
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

#[cfg(any(test, debug_assertions, feature = "by-name"))]
fn arg<'a>(req: &'a Value, name: &str) -> anyhow::Result<&'a str> {
    req.get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing argument {name}"))
}

/// How someone added by this request starts out.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
fn regard(req: &Value) -> account::Regard {
    let says = |name| req.get(name).and_then(|v| v.as_bool()) == Some(true);
    account::Regard {
        trusted: !says("hosts_only"),
        introductions: !says("no_introductions"),
    }
}

/// The power a pairing joins this device at, as `pair-status` says it:
/// `device` or `admin`, as the admin device named it.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
fn joins_as(p: Option<cardinal_identity::Power>) -> Value {
    match p {
        Some(cardinal_identity::Power::Admin) => json!("admin"),
        Some(cardinal_identity::Power::Device) => json!("device"),
        _ => Value::Null,
    }
}

/// [`joins_as`], typed.
fn joins_as_name(p: Option<cardinal_identity::Power>) -> Option<&'static str> {
    match p {
        Some(cardinal_identity::Power::Admin) => Some("admin"),
        Some(cardinal_identity::Power::Device) => Some("device"),
        _ => None,
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

#[cfg(any(test, debug_assertions, feature = "by-name"))]
async fn handle(d: &Arc<Daemon>, req: &Value) -> anyhow::Result<Value> {
    let cmd = arg(req, "cmd")?;
    match cmd {
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "hello" => Ok(json!({"api": API, "version": env!("CARGO_PKG_VERSION")})),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "setup-begin" => setup_begin_by_name(d),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "setup-finish" => setup_finish_by_name(d, req),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "status" => Ok(status(d)),
        // Inspection (`inspect.rs`): the person turns it on, on this
        // device, and only whoever holds the token it gives may look.
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "inspect-on" => {
            let minutes = req.get("minutes").and_then(Value::as_u64);
            let (token, until) = d
                .inspection
                .grant_by_name(minutes.unwrap_or(crate::inspect::DEFAULT_MINUTES))?;
            d.bump();
            Ok(json!({"token": token, "until": until}))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "inspect-off" => {
            let was = d.inspection.revoke();
            d.bump();
            Ok(json!({"was_on": was}))
        }
        // One request for each view, which `inspect.rs` tells by `what`.
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "inspect" | "inspect-identity" | "inspect-space" | "inspect-entries" | "inspect-entry"
        | "inspect-nodes" | "inspect-node" => {
            d.inspection
                .check_by_name(req.get("token").and_then(Value::as_str))?;
            let mut req = req.clone();
            req["what"] = json!(cmd.strip_prefix("inspect-").unwrap_or("overview"));
            crate::inspect::by_name::handle(d, &req)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "devices" => Ok(json!({"devices": devices(d)})),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "stop" => {
            let _ = d.stopping.send(true);
            Ok(json!({}))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "reload" => {
            reload(d)?;
            Ok(json!({}))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "remove-device" => {
            let lost = req.get("lost").and_then(|v| v.as_bool()).unwrap_or(false);
            remove_device_by_name(d, arg(req, "who")?, words(req), lost).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "invite" => {
            let address = req.get("address").and_then(|v| v.as_str());
            let name = req.get("name").and_then(|v| v.as_str());
            crate::contacts::invite_by_name(d, address, name, regard(req))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
                Some(w) => Some(crate::contacts::find_by_name(d, w)?.identity),
                None => None,
            };
            crate::contacts::accept_for_by_name(
                d,
                arg(req, "code")?,
                name,
                regard(req),
                met,
                true,
                whom,
            )
            .await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "invitations" => Ok(crate::contacts::invitations_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "cancel-invitation" => crate::contacts::cancel_invitation_by_name(d, arg(req, "id")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "contacts" => {
            let all = req.get("all").and_then(|v| v.as_bool()) == Some(true);
            Ok(crate::contacts::list_by_name(d, all))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "contact" => match (
            req.get("name").and_then(|v| v.as_str()),
            req.get("category").and_then(|v| v.as_str()),
        ) {
            (Some(name), _) => crate::contacts::rename_by_name(d, arg(req, "who")?, name),
            (None, _) if req.get("picture").is_some() => {
                let from = req.get("picture").and_then(|v| v.as_str()).unwrap_or("");
                crate::names::set_picture_by_name(d, arg(req, "who")?, from).await
            }
            (None, Some(category)) => {
                crate::contacts::set_category_by_name(d, arg(req, "who")?, category)
            }
            (None, None) => match arg(req, "setting")? {
                "name-hosts" => {
                    crate::contacts::name_hosts_by_name(d, arg(req, "who")?, true).await
                }
                "no-hosts" => crate::contacts::name_hosts_by_name(d, arg(req, "who")?, false).await,
                "no-host" => {
                    crate::contacts::no_host_by_name(d, arg(req, "who")?, arg(req, "host")?).await
                }
                setting => crate::contacts::set_by_name(d, arg(req, "who")?, setting),
            },
        },
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "say" if req.get("group").is_some() => {
            let reply_to = req.get("reply_to").and_then(|v| v.as_str());
            let attach = strings(req, "attach");
            crate::groups::say_by_name(d, arg(req, "group")?, arg(req, "text")?, reply_to, &attach)
                .await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "mark-read" if req.get("group").is_some() => {
            crate::groups::mark_read_by_name(d, arg(req, "group")?)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "react" if req.get("group").is_some() => {
            crate::groups::react_by_name(d, arg(req, "group")?, arg(req, "id")?, arg(req, "text")?)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "edit-message" if req.get("group").is_some() => crate::groups::edit_message_by_name(
            d,
            arg(req, "group")?,
            arg(req, "id")?,
            arg(req, "text")?,
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "delete-message" if req.get("group").is_some() => {
            crate::groups::delete_message_by_name(d, arg(req, "group")?, arg(req, "id")?)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "groups" => Ok(crate::groups::list_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "introductions" => Ok(crate::introductions::list_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "introduce" => {
            let note = req.get("note").and_then(|v| v.as_str());
            crate::introductions::introduce_by_name(d, arg(req, "who")?, arg(req, "to")?, note)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "introduction-accept" => crate::introductions::accept_by_name(d, arg(req, "id")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "introduction-decline" => crate::introductions::decline_by_name(d, arg(req, "id")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-connect" => {
            let note = req.get("note").and_then(|v| v.as_str());
            crate::introductions::ask_in_group_by_name(
                d,
                arg(req, "group")?,
                arg(req, "who")?,
                note,
            )
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-create" => {
            let for_call = answer_in(req, "for_call")?.unwrap_or(false);
            let history = answer_in(req, "history")?.unwrap_or(true);
            let people = strings(req, "people");
            crate::groups::create_by_name(d, arg(req, "name")?, &people, for_call, history)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-add" => {
            let shown = req.get("shown").and_then(|v| v.as_str());
            crate::groups::add_by_name(d, arg(req, "group")?, &strings(req, "people"), shown)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-remove" => {
            crate::groups::remove_by_name(d, arg(req, "group")?, arg(req, "who")?).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-role" => {
            let (group, who) = (arg(req, "group")?, arg(req, "who")?);
            crate::groups::set_role_by_name(d, group, who, arg(req, "role")?).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-post-again" => crate::groups::post_again_by_name(d, arg(req, "group")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-moved-seen" => crate::groups::moved_seen_by_name(d, arg(req, "group")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-confirm-move" => crate::groups::confirm_move_by_name(
            d,
            arg(req, "group")?,
            &strings(req, "moves"),
            &strings(req, "to"),
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-leave" => {
            let anyway = req.get("anyway").and_then(|v| v.as_bool()) == Some(true);
            crate::groups::leave_by_name(d, arg(req, "group")?, &strings(req, "admins"), anyway)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-leaving" => crate::groups::leaving_by_name(d, arg(req, "group")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-rejoin" => crate::groups::rejoin_by_name(d, arg(req, "group")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-join" => {
            let reach = answer_in(req, "reach")?;
            crate::groups::join_by_name(d, arg(req, "group")?, reach).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-reach" => {
            let share = req.get("share").and_then(|v| v.as_bool());
            let share = share.ok_or_else(|| anyhow::anyhow!("say whether to share: share"))?;
            match req.get("host").and_then(|v| v.as_str()) {
                Some(host) if !share => {
                    crate::groups::no_host_by_name(d, arg(req, "group")?, host).await
                }
                Some(_) => anyhow::bail!("a host is taken out with share false"),
                None => crate::groups::set_reach_by_name(d, arg(req, "group")?, share).await,
            }
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-decline" => crate::groups::decline_by_name(d, arg(req, "group")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-members" => crate::groups::members_by_name(d, arg(req, "group")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-set" => {
            let name = req.get("name").and_then(|v| v.as_str());
            let introductions = req.get("introductions").and_then(|v| v.as_bool());
            let for_call = answer_in(req, "for_call")?;
            crate::groups::set_by_name(d, arg(req, "group")?, name, introductions, for_call)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "group-member" => {
            let shown = req.get("shown").and_then(|v| v.as_str());
            let introduce = req.get("introduce").and_then(|v| v.as_bool());
            crate::groups::set_member_by_name(
                d,
                arg(req, "group")?,
                arg(req, "who")?,
                shown,
                introduce,
            )
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
            crate::contacts::say_by_name(d, arg(req, "who")?, arg(req, "text")?, reply_to, &attach)
                .await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "save-attachment" if req.get("group").is_some() => {
            let index = req.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let (group, id, to) = (arg(req, "group")?, arg(req, "id")?, arg(req, "to")?);
            crate::groups::save_attachment_by_name(d, group, id, index, to).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "save-attachment" => {
            let index = req.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let (who, id, to) = (arg(req, "who")?, arg(req, "id")?, arg(req, "to")?);
            crate::contacts::save_attachment_by_name(d, who, id, index, to).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "edit-message" => crate::contacts::edit_message_by_name(
            d,
            arg(req, "who")?,
            arg(req, "id")?,
            arg(req, "text")?,
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "delete-message" => {
            crate::contacts::delete_message_by_name(d, arg(req, "who")?, arg(req, "id")?)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "react" => {
            crate::contacts::react_by_name(d, arg(req, "who")?, arg(req, "id")?, arg(req, "text")?)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "call-start" if req.get("ring").is_some_and(|r| !r.is_null()) => {
            anyhow::ensure!(
                req.get("who").is_none_or(Value::is_null),
                "`ring` names members of a group: it is not for a call with one person"
            );
            let ring = strings(req, "ring");
            anyhow::ensure!(!ring.is_empty(), "`ring` names someone to ring");
            crate::calls::start_group_by_name(d, arg(req, "group")?, Some(&ring)).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "call-start" if req.get("group").is_some() => {
            crate::calls::start_group_by_name(d, arg(req, "group")?, None).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "call-start" => crate::calls::start_by_name(d, arg(req, "who")?, formats(req)?).await,
        // What programs ask through the application interface, and the
        // person's approvals (`apps.rs`).
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "app-questions" => Ok(crate::apps::questions_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "app-answer" => crate::apps::answer_by_name(d, req),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "approvals" => Ok(crate::apps::list_approvals_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "approval-revoke" => crate::apps::revoke_by_name(d, arg(req, "id")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "app-offers" => Ok(crate::apps::list_offers_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "app-join" => crate::apps::join_by_name(d, arg(req, "space")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "call-answer" => {
            let reach = answer_in(req, "reach")?;
            let join = answer_in(req, "join")?;
            crate::calls::answer_by_name(d, formats(req)?, reach, join).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "call-end" => crate::calls::end_by_name(d).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "conversations" => Ok(crate::contacts::conversations_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "mark-read" => crate::contacts::mark_read_by_name(d, arg(req, "who")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "read-markers" => {
            let on = req.get("on").and_then(|v| v.as_bool());
            crate::settings::read_markers_by_name(d, on)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recovery-check" => {
            crate::recovery::root_from_words(d, arg(req, "words")?)?;
            Ok(json!({}))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
            crate::host::enable_by_name(d, &addresses)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "host-off" => crate::host::disable_by_name(d),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "host-offer" => {
            let devices = strings(req, "devices");
            let n = |k: &str| req.get(k).and_then(|v| v.as_u64());
            let who = arg(req, "who")?;
            crate::hosting::offer_by_name(d, who, &devices, n("envelopes"), n("relay_mb"))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "host-accept" => crate::hosting::accept_by_name(d, arg(req, "who")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "host-end" => crate::hosting::end_by_name(d, arg(req, "who")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "hosting" => Ok(crate::hosting::list_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "router" => {
            if let Some(on) = req.get("on").and_then(|v| v.as_bool()) {
                let here = req.get("this_device").and_then(|v| v.as_bool()) == Some(true);
                crate::portmap::set_on(d, on, here)?;
            }
            Ok(crate::portmap::status(d))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "bluetooth" => match req.get("mode").and_then(|v| v.as_str()) {
            Some(m) => {
                let m = crate::bluetooth::Mode::parse(m)
                    .ok_or_else(|| anyhow::anyhow!("Bluetooth is `off`, `open` or `always`"))?;
                crate::bluetooth::set_by_name(d, m)
            }
            None => Ok(crate::bluetooth::check_by_name(d).await),
        },
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "network" => match req.get("mine").and_then(|v| v.as_bool()) {
            Some(mine) => {
                let name = req.get("name").and_then(|v| v.as_str());
                crate::networks::mark_by_name(d, mine, name)
            }
            None => Ok(crate::networks::status(d)),
        },
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recovery-sheet" => crate::host::sheet(d),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guardians" => crate::guardians::show_by_name(d),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guardians-set" => crate::guardians::set_by_name(
            d,
            &strings(req, "who"),
            req.get("threshold").and_then(Value::as_u64),
            req.get("delay").and_then(Value::as_u64),
            words(req),
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guardians-object" => {
            crate::guardians::object_by_name(d, req.get("fingerprint").and_then(Value::as_str))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guarding" => Ok(crate::guardians::list_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guarding-invite" => {
            crate::guardians::invite_by_name(
                d,
                arg(req, "who")?,
                req.get("at").and_then(Value::as_str),
            )
            .await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guarding-accept" => crate::guardians::accept_role_by_name(d, arg(req, "who")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guardians-ask" => crate::guardians::ask_by_name(d, arg(req, "who")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guarding-confirm-change" => {
            let understood = req.get("understood").and_then(Value::as_bool) == Some(true);
            let fp = req.get("fingerprint").and_then(Value::as_str);
            crate::guardians::confirm_change_by_name(d, arg(req, "who")?, fp, understood).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guarding-never" => {
            crate::guardians::never_by_name(d, arg(req, "who")?, arg(req, "fingerprint")?)
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guarding-caution" => crate::guardians::caution_for_by_name(d, arg(req, "who")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guarding-endorse" => {
            let understood = req.get("understood").and_then(Value::as_bool) == Some(true);
            crate::guardians::endorse_by_name(
                d,
                arg(req, "who")?,
                arg(req, "fingerprint")?,
                understood,
            )
            .await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "guarding-confirm" => {
            let understood = req.get("understood").and_then(Value::as_bool) == Some(true);
            crate::guardians::confirm_by_name(
                d,
                arg(req, "who")?,
                arg(req, "fingerprint")?,
                understood,
            )
            .await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover" => crate::recovering::status_by_name(d),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "keep-work" => crate::recovering::keep_work_by_name(
            d,
            arg(req, "name")?,
            req.get("up_to").and_then(Value::as_str),
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover-start" => {
            let opt = |k: &str| req.get(k).and_then(Value::as_str);
            crate::recovering::start_by_name(d, opt("code"), opt("identity")).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover-invite" => {
            crate::recovering::invite_by_name(d, req.get("at").and_then(Value::as_str)).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover-lost-at" => {
            crate::recovering::set_lost_at_by_name(d, req.get("lost_at").and_then(Value::as_u64))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover-cancel" => crate::recovering::cancel_by_name(d).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover-undo" => crate::recovering::undo_kept_by_name(d, arg(req, "to")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover-kept-seen" => crate::recovering::kept_seen_by_name(d, &strings(req, "to")),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover-stop-waiting" => {
            let all = req.get("all").and_then(Value::as_bool) == Some(true);
            crate::recovering::stop_waiting_by_name(d, req.get("who").and_then(Value::as_str), all)
                .await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "recover-finish" => {
            let without = req.get("without_account").and_then(Value::as_bool) == Some(true);
            let lost_at = req.get("lost_at").and_then(Value::as_u64);
            crate::recovering::finish_by_name(d, without, lost_at).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "restore-from-host" => {
            crate::host::restore_by_name(d, arg(req, "words")?, arg(req, "at")?, arg(req, "key")?)
                .await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "conflicts" => conflicts(d),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "debug-tree" => debug_tree_by_name(d),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "space-usage" => {
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || crate::cleanup::usage_of_by_name(&d2)).await?
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "history" => crate::file_history::history_by_name(d, arg(req, "path")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "deleted" => crate::file_history::deleted_by_name(
            d,
            req.get("path").and_then(Value::as_str).unwrap_or(""),
            req.get("hidden").and_then(Value::as_bool).unwrap_or(false),
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "undelete" => {
            let id = req.get("id").and_then(Value::as_str);
            crate::file_history::undelete_by_name(d, arg(req, "path")?, id).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "speedtest" => speedtest_by_name(d, arg(req, "device")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "me" => crate::names::me_by_name(d, req.get("name").and_then(|v| v.as_str())),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "network-changed" => Ok(
            d.network_changed_by_name(req.get("why").and_then(|v| v.as_str()).unwrap_or("told"))
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "wake" => Ok(d.network_changed_by_name("woke")),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "pair-show" => {
            // what to call this device, where the window knows better
            if let Some(name) = device_name_by_name(req)? {
                rename_this_device(d, &name)?;
            }
            let s = crate::pair::show(d).await?;
            Ok(
                json!({"code": s.code, "addrs": s.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>() }),
            )
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
            let device = device_name_by_name(req)?;
            let name =
                crate::pair::type_code(d, code, at, admin, words(req), device.as_deref()).await?;
            Ok(json!({"name": name}))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "device-rename" => rename_device_by_name(d, arg(req, "device")?, arg(req, "name")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "messages" if req.get("group").is_some() => crate::groups::messages_by_name(
            d,
            arg(req, "group")?,
            req.get("before").and_then(Value::as_str),
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "call" => Ok(crate::calls::current_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "conditions" => conditions(d, req),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "clip-copy" => crate::clipboard::copy_by_name(d, arg(req, "text")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "clip" => Ok(crate::clipboard::paste_by_name(d)),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "files" => {
            crate::onefolder::list_by_name(d, req.get("path").and_then(Value::as_str).unwrap_or(""))
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "mkdir" => crate::onefolder::mkdir_by_name(d, arg(req, "path")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "move" => crate::onefolder::move_to_by_name(d, arg(req, "from")?, arg(req, "to")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "remove" => crate::onefolder::remove_by_name(d, arg(req, "path")?),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "copy" => crate::onefolder::copy_by_name(d, arg(req, "from")?, arg(req, "to")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "put" => crate::onefolder::put_by_name(d, arg(req, "from")?, arg(req, "to")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "save" => {
            let version = req.get("version").and_then(Value::as_u64);
            crate::onefolder::save_by_name(d, arg(req, "path")?, arg(req, "to")?, version).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "write" => crate::onefolder::write_by_name(d, arg(req, "from")?, arg(req, "path")?).await,
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
            crate::onefolder::share_by_name(d, who, group, &paths, text).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "messages" => crate::contacts::messages_by_name(
            d,
            arg(req, "who")?,
            req.get("before").and_then(Value::as_str),
        ),
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
        "restore" => {
            let path = arg(req, "path")?.to_owned();
            let version = req
                .get("version")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("missing --version"))?;
            crate::file_history::restore_by_name(d, &path, version).await
        }
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        #[cfg(any(test, debug_assertions, feature = "by-name"))]
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
        other => anyhow::bail!("unknown command {other:?}"),
    }
}

/// Shows the one folder at `path`, or where it was last, or at
/// ~/Cardinal; where.
async fn mount_at(d: &Arc<Daemon>, path: Option<&str>) -> anyhow::Result<std::path::PathBuf> {
    let path = path
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
    Ok(path)
}

/// Shows the one folder nowhere, from now on.
async fn unmount(d: &Arc<Daemon>) -> anyhow::Result<()> {
    let d2 = d.clone();
    tokio::task::spawn_blocking(move || {
        d2.unmount();
        d2.config().mount = None;
        d2.save_config()
    })
    .await?
}

/// Writes what the folder shown holds that is not written yet: how many
/// entries.
async fn flush(d: &Arc<Daemon>) -> anyhow::Result<usize> {
    let d2 = d.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
        let m = d2.mount.lock().unwrap_or_else(|e| e.into_inner());
        match m.as_ref() {
            Some(m) => m.flush(),
            None => Ok(0),
        }
    })
    .await?
}

/// Keeps `path` on this device, or (`on` false) no longer: the path as
/// kept, and whether this device keeps only what is pinned.
fn pin(d: &Arc<Daemon>, path: &str, on: bool) -> anyhow::Result<(String, bool)> {
    let path = path.trim_matches('/').to_owned();
    {
        let mut c = d.config();
        c.pins.retain(|p| *p != path);
        if on {
            c.pins.push(path.clone());
        }
    }
    d.save_config()?;
    d.bump();
    let on_demand = d.config().on_demand();
    Ok((path, on_demand))
}

/// What this device keeps of the one folder: `full` or `on-demand`.
fn set_retention(d: &Arc<Daemon>, mode: &str) -> anyhow::Result<()> {
    if mode != "full" && mode != "on-demand" {
        anyhow::bail!("retention is `full` or `on-demand`");
    }
    d.config().retention = mode.to_owned();
    d.save_config()?;
    d.bump();
    // Record it in the account space for the other devices.
    d.housekeeping();
    Ok(())
}

/// Measures the link to one of the person's devices (`speedtest.rs`).
async fn speedtest(d: &Arc<Daemon>, asked: api::Ref<'_>) -> anyhow::Result<api::SpeedtestReply> {
    let me = d.keys.key();
    let (key, name, x) = {
        let core = d.core();
        let ident = core
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone yet"))?;
        let names = core.device_names();
        let st = ident.state();
        // text as typed, lower case; an id given as bytes is matched as one
        let w = match asked {
            api::Ref::Typed(t) => t.to_lowercase(),
            api::Ref::Id(_) => String::new(),
        };
        let who = asked.to_string();
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
    Ok(api::SpeedtestReply {
        device: name,
        ms: m.phase.as_millis() as u64,
        receive: m.receive.round() as u64,
        received_bytes: m.received,
        rtt_median_us: m.rtt_median.as_micros() as u64,
        rtt_min_us: m.rtt_min.as_micros() as u64,
        send: m.send.round() as u64,
        sent_bytes: m.sent,
    })
}
/// Measures the link to one of the person's devices (`speedtest.rs`).
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
async fn speedtest_by_name(d: &Arc<Daemon>, who: &str) -> anyhow::Result<Value> {
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
fn setup_begin(d: &Daemon) -> anyhow::Result<api::SetupBeginReply> {
    let prepared = crate::setup::prepare(&d.paths)?;
    let phrase = prepared.phrase().to_words();
    let words: Vec<&str> = phrase.split(' ').collect();
    let r: [u8; 2] = cardinal_crypto::random_bytes();
    let (a, mut b) = (r[0] as usize % words.len(), r[1] as usize % words.len());
    if b == a {
        b = (a + 7) % words.len();
    }
    let ask = [a.min(b), a.max(b)];
    let reply = api::SetupBeginReply {
        ask: ask.iter().map(|&n| n as u64).collect(),
        words: words.iter().map(|&w| w.to_owned()).collect(),
    };
    *d.setting_up.lock().unwrap_or_else(|e| e.into_inner()) = Some((prepared, ask));
    Ok(reply)
}
/// Makes an identity for a client to set up, and says which two of its words
/// to ask for back. Nothing is saved until [`setup_finish`].
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn setup_begin_by_name(d: &Daemon) -> anyhow::Result<Value> {
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
fn setup_finish(
    d: &Arc<Daemon>,
    a: &api::SetupFinishArgs,
) -> anyhow::Result<api::SetupFinishReply> {
    let mut held = d.setting_up.lock().unwrap_or_else(|e| e.into_inner());
    let (prepared, ask) = held
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("nothing is being set up"))?;
    let words_are = prepared.phrase().to_words();
    let words: Vec<&str> = words_are.split(' ').collect();
    let none = Vec::new();
    let answers = a.answers.as_ref().unwrap_or(&none);
    let matches = ask.iter().enumerate().all(|(i, at)| {
        let answer = answers.get(i).map_or("", String::as_str);
        answer.trim().eq_ignore_ascii_case(words[*at])
    });
    anyhow::ensure!(matches, "that does not match; check what you wrote down");
    let mut config = crate::config::Config::load(&d.paths.config())?;
    // `name` is the person's, the name they suggest for themselves; the
    // device keeps its machine's name unless the window knows a better one.
    if let Some(device) = device_name_given(a.device.as_deref())? {
        config.name = device;
    }
    let person = a
        .name
        .as_deref()
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
    Ok(api::SetupFinishReply {
        device: config.name,
        name: person,
    })
}
/// Saves the identity once its person has shown they have the words.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn setup_finish_by_name(d: &Arc<Daemon>, req: &Value) -> anyhow::Result<Value> {
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
    if let Some(device) = device_name_by_name(req)? {
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

/// What to call this device, where a request says.
fn device_name_given(name: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(name) = name else {
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

/// The person's devices, this one first and then by name, as `devices`
/// gives them.
pub(crate) fn device_list(d: &Daemon) -> Vec<api::Device> {
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
    let mut v: Vec<api::Device> = st
        .keys
        .values()
        .map(|k| {
            let x = k.link_key.as_ref().map(|l| *l.x25519());
            let online = k.key == me || x.is_some_and(|x| d.is_online(&x));
            let carrier = x.and_then(|x| d.session_carrier(&x));
            let (dials, redial) = d.dialled(&k.key);
            let through = x
                .and_then(|x| d.relayed_through(&x))
                .and_then(|h| by_link.get(&h))
                .cloned();
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
            api::Device {
                name: name_of(&k.key),
                // what it sent that this device cannot read, or the other
                // way round (`unreadable.rs`)
                unreadable: d.unreadable.of(&k.key, &name_of(&k.key)),
                key: api::short_id(&k.key),
                power: power_name(k.power).into(),
                this: k.key == me,
                online,
                addr: if k.key == me || carrier == Some("relay") {
                    None
                } else {
                    addr
                },
                carrier: carrier.map(Into::into),
                through,
                // how often this device dialled it, and the wait before
                // the next try (`redial.rs`)
                dials: Some(dials),
                redial_s: redial.map(|w| w.as_secs()),
                // what this device's fetcher thinks of it as a source
                fetch: x.and_then(|x| stats.get(&x)).map(|s| api::Fetch {
                    rate: s.rate as u64,
                    latency_ms: (s.latency * 1000.0) as u64,
                    replies: s.samples,
                    received: s.bytes_total,
                }),
            }
        })
        .collect();
    v.sort_by_key(|x| (!x.this, x.name.clone()));
    v
}

/// [`device_list`] as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
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

/// Where this device stands, as `status` gives it: all of it, which the
/// page cuts.
pub(crate) fn status_reply(d: &Arc<Daemon>) -> api::StatusReply {
    let cfg = d.config().clone();
    let (identity, spaces, conflicts, files) = {
        let core = d.core();
        let identity = core.identity.as_ref().map(|i| api::short_id(&i.id()));
        let files = core.files_id();
        let spaces: Vec<api::SpaceShown> = core
            .spaces
            .values()
            .map(|h| api::SpaceShown {
                id: api::short_id(&h.id),
                kind: match h.profile() {
                    Some(cardinal_space::Profile::ACCOUNT) => "account",
                    Some(cardinal_space::Profile::FILES) => "files",
                    Some(_) => "other",
                    None => "arriving",
                }
                .into(),
                entries: h.set_len() as u64,
                // set aside for want of a witness (`spaces.md#authors`)
                set_aside: h
                    .space
                    .as_ref()
                    .map_or(0, |s| s.validity().unwitnessed.len())
                    as u64,
                valid: h.space.as_ref().map_or(0, |s| s.validity().valid.len()) as u64,
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
    let identity_id = d.core().identity.as_ref().map(|i| i.id());
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
    let pairing = |state: &'static str| api::Pairing {
        admin: None,
        code: None,
        error: None,
        state: state.into(),
        power: None,
    };
    let pairing = match d.pairing.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        PairState::Idle => None,
        PairState::Showing { code } => Some(api::Pairing {
            code: Some(code),
            ..pairing("showing")
        }),
        PairState::Joining {
            admin_name, power, ..
        } => Some(api::Pairing {
            admin: Some(admin_name),
            power: joins_as_name(power).map(Into::into),
            ..pairing("joining")
        }),
        PairState::Joined { .. } => None,
        PairState::Failed(e) => Some(api::Pairing {
            error: Some(e),
            ..pairing("failed")
        }),
    };
    // each lock taken and let go before the next: a guard in the reply's
    // expression would be held to its end
    let read_markers = crate::settings::read_markers_on(&d.core());
    let removed = d.core().removed();
    let mount_unavailable = d
        .mount_unavailable
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    api::StatusReply {
        name: cfg.name.clone(),
        router: crate::portmap::router(d),
        bluetooth: crate::bluetooth::shown(d),
        network: crate::networks::network(d),
        read_markers,
        home: d.paths.home.display().to_string(),
        identity,
        identity_id,
        devices: device_list(d),
        hosts: crate::host::hosts(d).ok().map(|h| h.len() as u64),
        // the person's devices with a mailbox, reachable from outside: an
        // explicit host, or one that names itself (D72)
        always_on: always_on(d),
        spaces,
        files_ready: files.is_some(),
        // whether this device may be inspected now, and until when
        inspection: d.inspection.shown(),
        mount: cfg.mount_here().map(|p| p.display().to_string()),
        mounted,
        removed,
        mount_unavailable,
        pending_changes: pending,
        not_saved: not_saved as u64,
        not_saved_undone: undone as u64,
        retention: cfg.retention.clone(),
        conflicts: conflicts as u64,
        // the setting, which is what main sent: the address it listens at
        // was written first under the same name, and the setting replaced it
        listen: cfg.listen.clone(),
        moved_from: cfg.this_run.moved_from.map(u64::from),
        left_behind: cfg.this_run.left_behind.clone(),
        progress: api::ProgressShown {
            bytes_fetched: progress.bytes_fetched,
            bytes_pending: progress.bytes_pending,
            bytes_wanted: progress.bytes_wanted,
            files_pending: progress.files_pending,
            last_error: progress.last_error,
            rate: progress.rate,
        },
        copies: crate::copies::shown(d),
        conditions: d.conditions.shown(),
        redial: d.redial(),
        carrying_calls: crate::calls::carried(d) as u64,
        old: crate::cleanup::shown(d),
        pairing,
        peers: cfg.peers,
        uptime_s: d.uptime().as_secs(),
        // the page says
        more: false,
        next: None,
    }
}

/// `status` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
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

/// The files that conflict, each with its versions and the copies that
/// show them, as `conflicts` gives them.
fn conflict_list(d: &Daemon) -> anyhow::Result<Vec<api::Conflict>> {
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
        let versions = f
            .content(&n.id)
            .iter()
            .map(|v| api::Version {
                device: names
                    .get(&v.device)
                    .cloned()
                    .unwrap_or_else(|| account::short_key(&v.device)),
                time: v.time,
                size: v.content.as_ref().map(|c| c.size()),
                ..cardinal_interface::new!(api::Version {
                    device: String::new()
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
        out.push(api::Conflict {
            copies,
            delete_conflict: n.delete_conflict,
            path,
            versions,
        });
    }
    Ok(out)
}

/// `conflicts` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
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

/// `debug-tree`: the mounted folder's tree as the service holds it, and
/// what keeps it from settling.
fn debug_tree(d: &Daemon) -> anyhow::Result<api::DebugTreeReply> {
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
        let mut out = [0u8; 16];
        out.copy_from_slice(&h.finalize().as_bytes()[..16]);
        out
    };
    let epoch = {
        let core = d.core();
        core.spaces[&files]
            .space
            .as_ref()
            .and_then(|s| s.current_epoch())
    };
    let (state, snap) = {
        let core = d.core();
        let h = &core.spaces[&files];
        let sp = h.space.as_ref();
        (
            sp.map(|s| {
                let mut out = [0u8; 8];
                out.copy_from_slice(&blake3::hash(&s.state().canonical().encode()).as_bytes()[..8]);
                out
            }),
            sp.map(|s| crate::fs::tree::Snapshot::take(s, h.version, &core.device_names())),
        )
    };
    let start = |n: &NodeId| {
        let mut out = [0u8; 6];
        out.copy_from_slice(&n[..6]);
        out
    };
    let mut reply = cardinal_interface::new!(api::DebugTreeReply {
        heads,
        mounted: false,
        more: false
    });
    reply.epoch = epoch;
    let m = d.mount.lock().unwrap_or_else(|e| e.into_inner());
    let Some(m) = m.as_ref() else {
        return Ok(reply);
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
            items.push(api::TreeItem {
                dirty: x.dirty.any_change(),
                ino: x.ino,
                kind: kind.into(),
                local: x.local,
                node: x.node.as_ref().map(start),
                path: t.path(*c),
                size: x.size,
            });
            stack.push(*c);
        }
    }
    // What keeps a device from settling, and what its state holds that its
    // tree does not show.
    let stuck: Vec<api::StuckItem> = t
        .inodes
        .values()
        .filter(|x| x.parent != 0 && !x.local && (x.node.is_none() || x.dirty.any_change()))
        .map(|x| api::StuckItem {
            dirty: format!("{:?}", x.dirty),
            kind: format!("{:?}", x.kind),
            opens: x.opens as u64,
            path: t.path(x.ino),
            staged: x.staged.is_some(),
        })
        .collect();
    let unshown: Vec<api::UnshownNode> = snap
        .iter()
        .flat_map(|s| s.entries.iter())
        .filter(|e| e.version.is_none() && !t.by_node.contains_key(&e.node))
        .map(|e| api::UnshownNode {
            name: e.name.clone(),
            node: start(&e.node),
        })
        .collect();
    reply.state = state;
    reply.mounted = true;
    reply.pending = Some(t.has_pending());
    reply.items = Some(items);
    reply.stuck = Some(stuck);
    reply.unshown = Some(unshown);
    reply.deleted = Some(t.deleted.len() as u64);
    reply.settle = Some(t.settle.len() as u64);
    Ok(reply)
}

/// For tests: a digest of the files space's heads, whether the mount has
/// changes to commit, and every item the mount shows, with whether it is
/// local (`fs/local.rs`).
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn debug_tree_by_name(d: &Daemon) -> anyhow::Result<Value> {
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
#[cfg(any(test, debug_assertions, feature = "by-name"))]
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
fn find_device(d: &Daemon, asked: api::Ref) -> anyhow::Result<([u8; 32], String)> {
    let core = d.core();
    let ident = core
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this device does not belong to anyone"))?;
    let names = core.device_names();
    let st = ident.state();
    let w = match asked {
        api::Ref::Typed(t) => t.trim().to_lowercase(),
        api::Ref::Id(_) => String::new(),
    };
    let who = asked.to_string();
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
fn rename_device(
    d: &Arc<Daemon>,
    which: api::Ref,
    name: &str,
) -> anyhow::Result<api::DeviceRenameReply> {
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
    Ok(api::DeviceRenameReply {
        key: api::short_id(&key),
        name: name.to_owned(),
    })
}

async fn remove_device(
    d: &Arc<Daemon>,
    who: api::Ref<'_>,
    words: Option<&str>,
    lost: bool,
) -> anyhow::Result<api::RemoveDeviceReply> {
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
    Ok(api::RemoveDeviceReply {
        dropped: dropped as u64,
        name,
    })
}
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
async fn remove_device_by_name(
    d: &Arc<Daemon>,
    who: &str,
    words: Option<&str>,
    lost: bool,
) -> anyhow::Result<Value> {
    let me = d.keys.key();
    let (key, name) = find_device_by_name(d, who)?;
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
#[cfg(any(test, debug_assertions, feature = "by-name"))]
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

// ---- The handlers as they were by name ----
//
// What main had, whole, kept only to show that the typed handlers send the
// same bytes (`control::typed::answering`, `api/same_bytes.rs`), and to
// measure the two. They go with the way by name.

/// `device_name` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn device_name_by_name(req: &Value) -> anyhow::Result<Option<String>> {
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

/// `find_device` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn find_device_by_name(d: &Daemon, who: &str) -> anyhow::Result<([u8; 32], String)> {
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

/// `rename_device` as main had it, by name.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(dead_code, clippy::all)]
fn rename_device_by_name(d: &Arc<Daemon>, which: &str, name: &str) -> anyhow::Result<Value> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "a name cannot be empty");
    anyhow::ensure!(
        !name.chars().any(char::is_control),
        "a device's name is one line"
    );
    let (key, _) = find_device_by_name(d, which)?;
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
