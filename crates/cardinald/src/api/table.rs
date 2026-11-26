//! Every request of the local interface, its number, and the numbers and
//! types of its arguments and its reply's fields (`apps.md`, Requests).
//! Numbers are only ever added: one given here is never given to anything
//! else, nor its type changed.
//!
//! A request's arguments are numbered from 1, after key 0, its number. A
//! reply's fields are numbered from 2, after key 0, the status, and key 1,
//! why an error happened. A record inside a reply numbers its fields from
//! one. Field numbers are in alphabetical order of the names as first
//! given, and what is added later comes after. A field whose type had to
//! change keeps its number, no longer used, and its name is given again
//! with a new number and the new type.

/// What a field holds.
#[derive(Debug)]
pub enum Ty {
    /// Text.
    Text,
    /// Bytes: a key, an id or a hash. The service holds them as hex.
    Bytes,
    /// An unsigned integer.
    Uint,
    /// An integer.
    Int,
    /// 0 or 1.
    Bool,
    /// What a person may type or a client may hold: text (a name, or the
    /// start of an id in hex), or the bytes of the id.
    Ref,
    /// A kind or a profile (`encoding.md#kinds`): a small unsigned
    /// integer, or the 32 bytes that name it.
    Kind,
    /// An integer or text, as the record it is in says.
    Scalar,
    /// A list of what this says.
    List(&'static Ty),
    /// A record.
    Rec(&'static Rec),
    /// A list of records.
    Recs(&'static Rec),
    /// A number no longer used: what it held is no longer sent, and the
    /// number stays taken, its type with it.
    Gone(&'static Ty),
}

/// A numbered field.
#[derive(Debug)]
pub struct Field {
    pub n: u64,
    pub name: &'static str,
    pub ty: Ty,
}

/// A record held inside a reply.
#[derive(Debug)]
pub struct Rec {
    pub name: &'static str,
    pub fields: &'static [Field],
}

/// A request: its number, its name, its arguments and its reply's fields.
/// The events of `watch` and the frames of `call-media` are written the
/// same way, with their fields as `args`.
#[derive(Debug)]
pub struct Request {
    pub n: u64,
    pub name: &'static str,
    pub args: &'static [Field],
    pub reply: &'static [Field],
    /// Whether its answer comes in pages, and how (`apps.md`, Pages).
    pub page: Page,
    /// A request no longer answered: the service says it has no such
    /// request, and its number stays taken.
    pub gone: bool,
}

/// How a request's answer comes in pages (`apps.md`, Pages). The lists of
/// a paged reply are its fields that are lists, in the order of their
/// numbers; its other fields come whole on every page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    /// It does not: what it answers does not grow with what the person
    /// holds, or it does something, which a second page would do again.
    Whole,
    /// By position, through the reply's lists in turn: `after` is how many
    /// items came before the page, and `next` the `after` of the next.
    After,
    /// Back from the newest of the one list `list`, oldest first within a
    /// page: `before` is the id (field `id` of its records) of the oldest
    /// item had, and `next` the oldest of this page.
    Before { list: &'static str },
}

macro_rules! f {
    ($n:literal $name:literal (gone $t:tt)) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Gone(&f!(0 "" $t).ty),
        }
    };
    ($n:literal $name:literal T) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Text,
        }
    };
    ($n:literal $name:literal B) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Bytes,
        }
    };
    ($n:literal $name:literal U) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Uint,
        }
    };
    ($n:literal $name:literal I) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Int,
        }
    };
    ($n:literal $name:literal BOOL) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Bool,
        }
    };
    ($n:literal $name:literal REF) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Ref,
        }
    };
    ($n:literal $name:literal KIND) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Kind,
        }
    };
    ($n:literal $name:literal SCALAR) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Scalar,
        }
    };
    ($n:literal $name:literal [T]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Text),
        }
    };
    ($n:literal $name:literal [B]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Bytes),
        }
    };
    ($n:literal $name:literal [U]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Uint),
        }
    };
    ($n:literal $name:literal [REF]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Ref),
        }
    };
    ($n:literal $name:literal [SCALAR]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Scalar),
        }
    };
    ($n:literal $name:literal [[U]]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::List(&Ty::Uint)),
        }
    };
    ($n:literal $name:literal {$r:ident}) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Rec(&$r),
        }
    };
    ($n:literal $name:literal [$r:ident]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Recs(&$r),
        }
    };
}

macro_rules! rec {
    ($id:ident $name:literal: $($n:literal $f:literal $t:tt),* $(,)?) => {
        pub static $id: Rec = Rec { name: $name, fields: &[$(f!($n $f $t)),*] };
    };
}

macro_rules! req {
    ($n:literal $name:literal ($($an:literal $af:literal $at:tt),*) -> ($($rn:literal $rf:literal $rt:tt),*)) => {
        Request {
            n: $n,
            name: $name,
            args: &[$(f!($an $af $at)),*],
            reply: &[$(f!($rn $rf $rt)),*],
            page: Page::Whole,
            gone: false,
        }
    };
}

/// A request whose answer comes in pages, written as `req!` writes one
/// after how: `after`, or `before` and the list paged.
macro_rules! paged {
    (after $($t:tt)*) => {
        Request {
            page: Page::After,
            ..req!($($t)*)
        }
    };
    (before $list:literal $($t:tt)*) => {
        Request {
            page: Page::Before { list: $list },
            ..req!($($t)*)
        }
    };
}

/// A request no longer answered, whose number stays taken: written as
/// `req!` writes one.
macro_rules! gone {
    ($($t:tt)*) => {
        Request { gone: true, ..req!($($t)*) }
    };
}

// ---- Records in replies ----

rec!(APP_QUESTION "app question":
    1 "asks" T, 2 "id" U, 3 "name" T, 4 "program" T, 5 "role" T, 6 "what" T);
rec!(APPROVAL "approval":
    1 "change" BOOL, 2 "covers" T, 3 "device" T, 4 "family" B, 5 "id" B, 6 "name" T,
    7 "program" T, 8 "revoked" BOOL, 9 "this_device" BOOL);
rec!(APP_OFFER "app offer":
    1 "application" T, 2 "from" T, 3 "name" T, 4 "sentence" T, 5 "space" B);

rec!(ATTACHMENT "attachment": 1 "name" T, 2 "size" U, 3 "type" T);
rec!(BLUETOOTH "bluetooth":
    1 "available" BOOL, 2 "channels_in" U, 3 "error" T, 4 "mode" T, 5 "on" BOOL, 6 "psm" U,
    7 "radio" T, 8 "recognized" U, 9 "seen" U, 10 "why_not" T, 11 "windows" U,
    12 "too_old" BOOL);
rec!(CALL "call":
    1 "frames" {CALL_FRAMES}, 2 "group" B, 3 "id" B, 4 "linked" U, 5 "name" T, 6 "offered" [B],
    7 "people" U, 8 "picture" T, 9 "seconds" U, 10 "state" T, 11 "taken" [B], 12 "who" B,
    13 "voices" [VOICE], 14 "they_take" [B], 15 "camera" BOOL, 16 "caller" {MEMBER},
    17 "admins" [MEMBER], 18 "joins" BOOL, 19 "reach" {GROUP_REACH}, 20 "for_call" BOOL);
rec!(CALL_ENDED "call ended":
    1 "group" B, 2 "how" T, 3 "id" B, 4 "name" T, 5 "who" B, 6 "at" U);
rec!(CONDITIONS "conditions": 1 "helps" BOOL, 2 "metered" BOOL, 3 "plugged_in" BOOL);
rec!(CONFLICT "conflict":
    1 "copies" [T], 2 "delete_conflict" BOOL, 3 "path" T, 4 "versions" [VERSION]);
rec!(CONTACT "contact":
    1 "category" T, 2 "connected" BOOL, 3 "identity" B, 4 "introductions" BOOL, 5 "met" {MET},
    6 "name" T, 7 "nearby" BOOL, 8 "own" BOOL, 9 "picture" T, 10 "recovered" T,
    11 "refused" BOOL, 12 "relayed" BOOL, 13 "suggested" T, 14 "trusted" BOOL,
    15 "recovered_seen" U, 16 "recovered_new_guardians" BOOL, 17 "recovered_delay" U,
    18 "unreadable" T);
rec!(CONTACT_REACH "contact reach":
    1 "named" [T], 2 "said_no" BOOL, 3 "shared" BOOL, 4 "waiting" BOOL);
rec!(CONVERSATION "conversation":
    1 "connected" BOOL, 2 "id" B, 3 "introductions" BOOL, 4 "last" {LAST}, 5 "name" T,
    6 "nearby" BOOL, 7 "own" BOOL, 8 "picture" T, 9 "reach" {CONTACT_REACH}, 10 "relayed" BOOL,
    11 "suggested" T, 12 "trusted" BOOL, 13 "unread" U);
rec!(COPIES "copies":
    1 "blobs" U, 2 "count" U, 3 "eligible" U, 4 "holders" [HOLDER], 5 "interval_ms" U,
    6 "now" U, 7 "older_than_ms" U);
rec!(DEVICE "device":
    1 "addr" T, 2 "carrier" T, 3 "fetch" {FETCH}, 4 "key" B, 5 "name" T, 6 "online" BOOL,
    7 "power" T, 8 "this" BOOL, 9 "through" T, 10 "unreadable" {UNREADABLE}, 11 "dials" U,
    12 "redial_s" U);
rec!(ENDPOINT "endpoint": 1 "endpoint" T, 2 "local" BOOL, 3 "tried" BOOL, 4 "why_not" T);
rec!(FETCH "fetch": 1 "latency_ms" U, 2 "rate" U, 3 "received" U, 4 "replies" U);
rec!(FILE "file":
    1 "added_by" T, 2 "category" BOOL, 3 "folder" BOOL, 4 "mine" BOOL, 5 "name" T, 6 "size" U,
    7 "time" U, 8 "versions" U, 9 "who" B, 10 "group" B);
rec!(CALL_FRAMES "frames": 1 "in" U, 2 "new" U);
rec!(GROUP "group":
    1 "admin" BOOL, 2 "did_not_stand" [B], 3 "did_not_stand_changes" [GROUP_CHANGE],
    4 "ended" T, 5 "group" B, 6 "held_back" U, 7 "introductions" BOOL, 8 "last" {LAST},
    9 "members" U, 10 "moved" {GROUP_CHANGE}, 11 "name" T, 12 "not_posted" U, 13 "public" BOOL,
    14 "reach" {GROUP_REACH}, 15 "role" T, 16 "unread" U, 17 "was" B, 18 "confirm" [B],
    19 "to_confirm" [GROUP_CHANGE], 20 "for_call" BOOL, 21 "last_call" {CALL_ENDED});
rec!(GROUP_CHANGE "group change":
    1 "at" U, 2 "by" T, 3 "group" B, 4 "roles" [ROLE_CHANGE], 5 "seen" U, 6 "taken_out" [T],
    7 "device" T, 8 "to" B);
rec!(GROUP_REACH "group reach":
    1 "added" [T], 2 "ask" BOOL, 3 "public" BOOL, 4 "said_no" BOOL, 5 "set" BOOL,
    6 "shared" BOOL, 7 "waiting" BOOL, 8 "what" [T], 9 "who" [T], 10 "named" [T]);
rec!(GROUP_SHOWN "group shown": 1 "group" B, 2 "name" T, 3 "what" [T]);
rec!(GUARDIAN_CHANGE "guardian change":
    1 "caution" T, 2 "confirm_delay" U, 3 "confirm_delay_text" T, 4 "confirm_from_ms" U,
    5 "confirmed" U, 6 "confirmed_by_me" BOOL, 7 "delay" U, 8 "delay_text" T,
    9 "fingerprint" T, 10 "guardians" U, 11 "id" B, 12 "in_effect" BOOL, 13 "names" [T],
    14 "needed" U, 15 "never" BOOL, 16 "objected" BOOL, 17 "threshold" U,
    18 "waits_until_ms" U);
rec!(GUARDED "guarded":
    1 "account_copy" BOOL, 2 "changes" [GUARDIAN_CHANGE], 3 "delay" U, 4 "delay_text" T,
    5 "guardians" U, 6 "helpers" U, 7 "id" B, 8 "name" T, 9 "never" [T], 10 "persona" B,
    11 "persona_at" T, 12 "recoveries" [RECOVERY], 13 "threshold" U, 14 "waiting" U,
    15 "warning" T);
rec!(HOLDER "holder":
    1 "checking" BOOL, 2 "counted" BOOL, 3 "key" B, 4 "last_check" U, 5 "last_fail" U,
    6 "last_pass" U, 7 "missed" U, 8 "name" T, 9 "online" BOOL, 10 "reason" T, 11 "state" T,
    12 "this" BOOL);
rec!(HOST "host": 1 "addresses" [T], 2 "key" (gone T), 3 "name" T, 4 "key" B);
rec!(HOSTABLE "hostable": 1 "name" T, 2 "outside" BOOL, 3 "sees" T, 4 "services" [T]);
rec!(HOSTING "hosting":
    1 "accepted" BOOL, 2 "devices" [T], 3 "ended" BOOL, 4 "envelopes" U, 5 "mine" BOOL,
    6 "name" T, 7 "relay_bytes" U, 8 "sees" T, 9 "waiting" U, 10 "who" B,
    11 "serving" [HOSTABLE], 12 "offered_at" U, 13 "after" B, 14 "accepted_at" U,
    15 "ended_at" U, 16 "ended_by" B, 17 "declined" BOOL);
rec!(INSPECTION "inspection": 1 "on" BOOL, 2 "until" U);
rec!(INTRODUCTION "introduction":
    1 "from" T, 2 "group" T, 3 "id" B, 4 "kind" T, 5 "name" T, 6 "note" T);
rec!(INVITATION "invitation":
    1 "cancelled" BOOL, 2 "expired" BOOL, 3 "hosts_only" BOOL, 4 "id" B, 5 "made" U,
    6 "name" T, 7 "outstanding" BOOL, 8 "used" U, 9 "uses" U);
rec!(LAST "last message": 1 "from" T, 2 "mine" BOOL, 3 "text" T, 4 "time" U);
rec!(KEPT_CHANGE "kept change":
    1 "at" U, 2 "by" T, 3 "can_undo" BOOL, 4 "device" T, 5 "group" B, 6 "handed_to" T,
    7 "name" T, 8 "roles" [ROLE_CHANGE], 9 "taken_out" [T], 10 "to" B, 11 "undo" T,
    12 "undone" B);
rec!(LOST_DEVICE "lost device": 1 "key" B, 2 "name" T, 3 "set_aside" U);
rec!(MEMBER "member":
    1 "contact" BOOL, 2 "id" B, 3 "introduce" BOOL, 4 "left" BOOL, 5 "name" T, 6 "own" BOOL,
    7 "picture" T, 8 "role" T, 9 "shown" T, 10 "suggested" T, 11 "taken_out" BOOL,
    12 "you" BOOL, 13 "reach" T, 14 "reaches_you" BOOL, 15 "through" T);
rec!(MESSAGE "message":
    1 "attachments" [ATTACHMENT], 2 "edited" BOOL, 3 "from" T, 4 "id" B, 5 "mine" BOOL,
    6 "picture" T, 7 "reactions" [REACTION], 8 "read_by" U, 9 "reply_to" B, 10 "state" T,
    11 "text" T, 12 "time" U);
rec!(NO_LONGER_NEEDED "no longer needed": 1 "at_ms" U, 2 "id" B, 3 "name" T, 4 "text" T);
rec!(MET "met": 1 "by" T, 2 "group" T, 3 "how" T, 4 "via" T);
rec!(KNOWN_PATH "known path":
    1 "addr" T, 2 "checking" BOOL, 3 "confirmed_s_ago" U, 4 "misses" U, 5 "next_check_s" U,
    6 "probes" U, 7 "wait_s" U);
rec!(NEARBY "nearby": 1 "they_give_secret" BOOL, 2 "you_give_secret" BOOL);
rec!(NETWORK "network":
    1 "answered" BOOL, 2 "ask" BOOL, 3 "known" BOOL, 4 "mine" BOOL, 5 "name" T, 6 "router" T,
    7 "routers" BOOL);
rec!(OFFER "offer":
    1 "from" T, 2 "group" B, 3 "members" U, 4 "name" T, 5 "public" BOOL, 6 "reach" {GROUP_REACH},
    7 "for_call" BOOL, 8 "last_call" {CALL_ENDED});
rec!(OLD "old versions":
    1 "at" U, 2 "bytes" U, 3 "keep" T, 4 "only_here" {ONLY_HERE}, 5 "unchecked" BOOL);
rec!(ONLY_HERE "only here": 1 "bytes" U, 2 "files" U);
rec!(PAIR_AGAIN "pair again": 1 "key" B, 2 "name" T);
rec!(PAIRING "pairing": 1 "admin" T, 2 "code" T, 3 "error" T, 4 "state" T, 5 "power" T);
rec!(PEER "peer": 1 "addr" T, 2 "device" T);
rec!(PLACE "place": 1 "kind" T, 2 "name" T, 3 "who" B, 4 "group" B);
rec!(PROGRESS "progress":
    1 "bytes_fetched" U, 2 "bytes_pending" U, 3 "bytes_wanted" U, 4 "files_pending" U,
    5 "last_error" T, 6 "rate" U);
rec!(REACTION "reaction": 1 "count" U, 2 "mine" BOOL, 3 "text" T);
rec!(RECOVERY "recovery":
    1 "caution" T, 2 "confirm_from_ms" U, 3 "confirmed" U, 4 "confirmed_by_me" BOOL,
    5 "endorsed" U, 6 "endorsed_by_me" BOOL, 7 "fingerprint" T, 8 "id" B, 9 "in_effect" BOOL,
    10 "keeps_keys" BOOL, 11 "objected" BOOL, 12 "pending" BOOL);
rec!(RELAYED_FOR "relayed for": 1 "a" T, 2 "a_id" B, 3 "b" T, 4 "b_id" B);
rec!(REJOIN "rejoin": 1 "group" B, 2 "members" U, 3 "name" T);
rec!(ROLE_CHANGE "role change": 1 "from" T, 2 "name" T, 3 "to" T);
rec!(REDIAL "redial": 1 "alone" BOOL, 2 "helps" BOOL, 3 "sparing" {SPARING});
rec!(SPARING "sparing": 1 "next_s" U, 2 "wait_s" U);
rec!(ROUTER "router":
    1 "error" T, 2 "everywhere" BOOL, 3 "external" T, 4 "named" [T], 5 "network" {NETWORK},
    6 "on" BOOL, 7 "protocol" T, 8 "seconds_left" U, 9 "this_device" BOOL);
rec!(SESSION_DEVICE "contact's device":
    1 "addr" T, 2 "bytes_received" U, 3 "bytes_sent" U, 4 "carrier" T, 5 "heard_ms_ago" U,
    6 "kept_in_touch" BOOL, 7 "key" B, 8 "online" BOOL, 9 "open_for_s" U, 10 "opened_by" T,
    11 "packets_dropped" U, 12 "packets_lost" U, 13 "route" T, 14 "rtt_ms" U,
    15 "they_see_you_at" T, 16 "through" T, 17 "unreadable" {UNREADABLE},
    18 "kept_alive_s" U, 19 "path" {KNOWN_PATH}, 20 "neighbour" BOOL);
rec!(SET_ASIDE "set aside": 1 "entry" B, 2 "space" B, 3 "time_ms" U);
rec!(SPACE_USAGE "space usage":
    1 "full" BOOL, 2 "history_bytes" U, 3 "history_days" U, 4 "live_bytes" U, 5 "log_bytes" U,
    6 "name" T, 7 "retention" T, 8 "space" B);
rec!(SPACE "space": 1 "entries" U, 2 "id" B, 3 "kind" T, 4 "set_aside" U, 5 "valid" U);
rec!(STEP "step": 1 "at" U, 2 "ok" BOOL, 3 "text" T);
rec!(SUCCESSION "succession": 1 "id" T, 2 "space" T);
rec!(THEIR_REACH "reach seen":
    1 "device" B, 2 "endpoints" [ENDPOINT], 3 "host" B, 4 "session" BOOL, 5 "this_device" BOOL);
rec!(TREE_ITEM "tree item":
    1 "dirty" BOOL, 2 "ino" U, 3 "kind" T, 4 "local" BOOL, 5 "node" B, 6 "path" T, 7 "size" U);
rec!(STUCK_ITEM "stuck item":
    1 "dirty" T, 2 "kind" T, 3 "opens" U, 4 "path" T, 5 "staged" BOOL);
rec!(UNREADABLE "unreadable":
    1 "reason" T, 2 "retry_in_s" U, 3 "says" T, 4 "since" U, 5 "theirs" BOOL, 6 "version" T);
rec!(UNSHOWN_NODE "unshown node": 1 "name" T, 2 "node" B);
rec!(VERSION "version":
    1 "current" BOOL, 2 "device" T, 3 "here" BOOL, 4 "size" U, 5 "time" U, 6 "version" U,
    7 "by" T);
rec!(DELETED_FILE "deleted file":
    1 "by" T, 2 "folder" BOOL, 3 "id" B, 4 "mine" BOOL, 5 "name" T, 6 "size" U, 7 "time" U);

// ---- Records of inspection ----

rec!(VALUE "value":
    1 "cut" BOOL, 2 "fields" [VALUE_FIELD], 3 "data" B, 4 "inner" {VALUE}, 5 "items" [VALUE],
    6 "len" U, 7 "n" U, 8 "shape" {SHAPE}, 9 "t" T, 10 "v" SCALAR, 11 "what" T,
    12 "withheld" T);
rec!(VALUE_FIELD "value field": 1 "k" U, 2 "v" {VALUE});
rec!(SHAPE "shape": 1 "here" BOOL, 2 "id" B, 3 "is" T, 4 "levels" U, 5 "size" U);
rec!(ATTACHED_LOG "attached log": 1 "bytes" U, 2 "entries" U, 3 "id" B);
rec!(ENCRYPTION_KEY "encryption key": 1 "entry" B, 2 "len" U, 3 "x25519" B);
rec!(EPOCH "epoch": 1 "entries" U, 2 "held" BOOL, 3 "id" B, 4 "started_by" {STARTED_BY});
rec!(IDENTITY_ENTRY "identity entry":
    1 "body" U, 2 "bytes" U, 3 "header" {VALUE}, 4 "id" B, 5 "in_effect" BOOL, 6 "ops" [OP],
    7 "parents" [B], 8 "signatures" U, 9 "signer" B, 10 "signer_power" T, 11 "valid" BOOL);
rec!(INSPECT_DEVICE "this device": 1 "key" B, 2 "link_x25519" B, 3 "name" T);
rec!(INSPECT_ENTRY "entry":
    1 "accepted" BOOL, 2 "author" B, 3 "author_ok" BOOL, 4 "bytes" U, 5 "entry" B,
    6 "epoch" B, 7 "genesis" BOOL, 8 "open_key" BOOL, 9 "parents" [B], 10 "position" U,
    11 "sealed_id" B, 12 "signer" B, 13 "starts_epoch" BOOL, 14 "time" U,
    15 "unwitnessed" BOOL, 16 "valid" BOOL, 17 "weigh" {WEIGH}, 18 "wraps" U);
rec!(INSPECT_IDENTITY "identity":
    1 "bytes" U, 2 "contested" BOOL, 3 "encryption_key" {ENCRYPTION_KEY},
    4 "encryption_keys_held" U, 5 "entries" U, 6 "frozen" BOOL, 7 "heads" [B], 8 "id" B,
    9 "keys" [INSPECT_KEY], 10 "recovery_policies" U, 11 "removed" [B]);
rec!(INSPECT_KEY "key":
    1 "added_in" B, 2 "key" B, 3 "link_key" {LINK_KEY}, 4 "name" T, 5 "power" T,
    6 "recovery_key" U, 7 "this_device" BOOL);
rec!(INSPECT_SPACE "space held":
    1 "account" BOOL, 2 "bytes" U, 3 "entries" U, 4 "epochs" U, 5 "files" BOOL, 6 "id" B,
    7 "label" T, 8 "members" U, 9 "my_role" U, 10 "nodes" U, 11 "opened" BOOL, 12 "pending" U,
    13 "profile" KIND, 14 "sealed" U, 15 "successor" B, 16 "valid" U);
rec!(KIND_COUNT "kind count":
    1 "bytes" U, 2 "conflicts" U, 3 "deleted" U, 4 "kind" KIND, 5 "nodes" U);
rec!(LINK_KEY "link key": 1 "len" U, 2 "x25519" B);
rec!(NODE_BRIEF "node":
    1 "bytes" U, 2 "children" U, 3 "created" U, 4 "created_in" B, 5 "creator" B,
    6 "delete_conflict" BOOL, 7 "deleted" BOOL, 8 "fields" [[U]], 9 "id" B, 10 "kind" KIND,
    11 "name" T, 12 "parent" B, 13 "position" U);
rec!(NODE_FIELD "node field":
    1 "conflict" BOOL, 2 "k" U, 3 "values" [NODE_VALUE]);
rec!(NODE_HISTORY "node history":
    1 "accepted" BOOL, 2 "author" B, 3 "bytes" U, 4 "entry" B, 5 "index" U, 6 "op" U,
    7 "time" U, 8 "valid" BOOL);
rec!(NODE_VALUE "node value": 1 "entry" B, 2 "op" U, 3 "v" {VALUE});
rec!(OP "op":
    1 "bytes" U, 2 "creates" B, 3 "index" U, 4 "kind" KIND, 5 "op" {VALUE}, 6 "reach" BOOL);
rec!(OTHER_LOG "other log": 1 "bytes" U, 2 "entries" U, 3 "id" B, 4 "name" T);
rec!(POLICY "policy": 1 "history_shared" BOOL, 2 "public" BOOL, 3 "rotate_after" U);
rec!(REACH_NODE "reach node":
    1 "bytes" U, 2 "fields" [NODE_FIELD], 3 "id" B, 4 "identity" B);
rec!(ROOT "root": 1 "children" U, 2 "id" B);
rec!(SIGNATURE "signature": 1 "key" B, 2 "signature" (gone U), 3 "signature" B);
rec!(SPACE_MEMBER "space member":
    1 "added_by" B, 2 "identity" B, 3 "left" BOOL, 4 "log_held" BOOL, 5 "name" T,
    6 "reach_node" B, 7 "role" U);
rec!(STARTED_BY "started by": 1 "author" B, 2 "entry" B, 3 "time" U);
rec!(STATS "stats": 1 "appended" U, 2 "recomputed" U);
rec!(STORE "store": 1 "bytes" U, 2 "objects" U);
rec!(VOICE "voice":
    1 "contact" BOOL, 2 "identity" B, 3 "name" T, 4 "picture" T, 5 "voice" B, 6 "you" BOOL,
    7 "camera" BOOL);
rec!(WEIGH "weight":
    1 "aead" U, 2 "ciphertext" U, 3 "fields" U, 4 "header" U, 5 "ops" [WEIGHED_OP],
    6 "sealed" U, 7 "signature" U, 8 "wraps" U);
rec!(WEIGHED_OP "weighed op": 1 "bytes" U, 2 "kind" KIND, 3 "op" KIND, 4 "reach" BOOL);

/// The reply of the requests that answer with what this person guards.
macro_rules! guarding_reply {
    ($name:literal $n:literal ($($an:literal $af:literal $at:tt),*)) => {
        req!($n $name ($($an $af $at),*) -> (
            2 "accepted" [T], 3 "asked" [T], 4 "guarding" [GUARDED], 5 "named_in_change" [T],
            6 "now_ms" U, 7 "no_longer_needed" [NO_LONGER_NEEDED]))
    };
}

/// Every request, by number. Numbers are grouped by what they are about,
/// with room in each group.
pub static REQUESTS: &[Request] = &[
    // ---- The service, this device, and the person's devices: 1 to 29 ----
    req!(1 "hello" () -> (2 "api" U, 3 "version" T)),
    paged!(after 2 "status" (1 "after" U, 2 "limit" U) -> (
        2 "bluetooth" {BLUETOOTH}, 3 "carrying_calls" U, 4 "conditions" {CONDITIONS},
        5 "conflicts" U, 6 "copies" {COPIES}, 7 "devices" [DEVICE], 8 "files_ready" BOOL,
        9 "home" T, 10 "hosts" U, 11 "identity" B, 12 "identity_id" B,
        13 "inspection" {INSPECTION}, 14 "left_behind" [T], 15 "listen" T, 16 "mount" T,
        17 "mount_unavailable" T, 18 "mounted" T, 19 "moved_from" U, 20 "name" T,
        21 "network" {NETWORK}, 22 "not_saved" U, 23 "not_saved_undone" U, 24 "old" {OLD},
        25 "pairing" {PAIRING}, 26 "peers" [T], 27 "pending_changes" BOOL,
        28 "progress" {PROGRESS}, 29 "read_markers" BOOL, 30 "removed" BOOL, 31 "retention" T,
        32 "router" {ROUTER}, 33 "spaces" [SPACE], 34 "uptime_s" U, 35 "more" BOOL,
        36 "next" U, 37 "redial" {REDIAL}, 38 "always_on" [T])),
    req!(3 "watch" (1 "window" BOOL) -> ()),
    req!(4 "stop" () -> ()),
    req!(5 "reload" () -> ()),
    req!(6 "conditions" (1 "plugged_in" BOOL, 2 "metered" BOOL) -> (
        2 "helps" BOOL, 3 "metered" BOOL, 4 "plugged_in" BOOL)),
    req!(7 "network-changed" (1 "why" T) -> (2 "checking" U)),
    req!(8 "setup-begin" () -> (2 "ask" [U], 3 "words" [T])),
    req!(9 "setup-finish" (1 "name" T, 2 "answers" [T], 3 "device" T) -> (
        2 "device" T, 3 "name" T)),
    req!(10 "me" (1 "name" T) -> (2 "name" T, 3 "set" BOOL)),
    paged!(after 11 "devices" (1 "after" U, 2 "limit" U) -> (
        2 "devices" [DEVICE], 3 "more" BOOL, 4 "next" U)),
    req!(12 "device-rename" (1 "device" REF, 2 "name" T) -> (2 "key" B, 3 "name" T)),
    req!(13 "remove-device" (1 "who" REF, 2 "lost" BOOL, 3 "words" T) -> (
        2 "dropped" U, 3 "name" T)),
    req!(14 "pair-show" (1 "admin" (gone BOOL), 2 "device" T) -> (2 "addrs" [T], 3 "code" T)),
    req!(15 "pair-status" () -> (
        2 "admin" T, 3 "code" T, 4 "error" T, 5 "files" BOOL, 6 "state" T, 7 "power" T)),
    req!(16 "pair-type" (1 "code" T, 2 "at" T, 3 "admin" BOOL, 4 "words" T, 5 "device" T) -> (
        2 "name" T)),
    // ---- People, conversations and invitations: 30 to 69 ----
    paged!(after 30 "contacts" (1 "all" BOOL, 2 "after" U, 3 "limit" U) -> (
        2 "contacts" [CONTACT], 3 "more" BOOL, 4 "next" U)),
    req!(31 "contact" (
        1 "who" REF, 2 "setting" T, 3 "name" T, 4 "picture" T, 5 "category" T, 6 "host" T
    ) -> (
        2 "category" T, 3 "name" T, 4 "own" BOOL, 5 "picture" T, 6 "reach" [GROUP_SHOWN],
        7 "suggested" T, 8 "named" T)),
    paged!(after 32 "contact-status" (
        1 "who" REF, 2 "look" BOOL, 3 "at" T, 4 "after" U, 5 "limit" U
    ) -> (
        2 "devices" [SESSION_DEVICE], 3 "direct_sessions" BOOL, 4 "identity" B,
        5 "in_use_for_s" U, 6 "introductions" BOOL, 7 "last_look" [STEP], 8 "look_every_s" U,
        9 "looked_for" T, 10 "looked_s_ago" U, 11 "looking" BOOL, 12 "looking_since" U,
        13 "looks_without_session" U, 14 "name" T, 15 "nearby" {NEARBY},
        16 "nearby_tries" [STEP], 17 "own" BOOL, 18 "refused" BOOL, 19 "router" {ROUTER},
        20 "sessions" [STEP], 21 "suggested" T, 22 "their_reach" [THEIR_REACH],
        23 "trusted" BOOL, 24 "your_reach" [THEIR_REACH], 25 "more" BOOL, 26 "next" U)),
    paged!(after 33 "conversations" (1 "after" U, 2 "limit" U) -> (
        2 "conversations" [CONVERSATION], 3 "more" BOOL, 4 "next" U)),
    paged!(before "messages" 34 "messages" (
        1 "who" REF, 2 "group" REF, 3 "before" REF, 4 "limit" U
    ) -> (2 "group" B, 3 "messages" [MESSAGE], 4 "name" T, 5 "more" BOOL, 6 "next" B)),
    req!(35 "say" (1 "who" REF, 2 "text" T, 3 "reply_to" REF, 4 "attach" [T], 5 "group" REF) -> (
        2 "reachable" BOOL)),
    req!(36 "save-attachment" (
        1 "who" REF, 2 "id" REF, 3 "index" U, 4 "to" T, 5 "group" REF
    ) -> (2 "path" T, 3 "size" U)),
    req!(37 "edit-message" (1 "who" REF, 2 "id" REF, 3 "text" T, 4 "group" REF) -> ()),
    req!(38 "delete-message" (1 "who" REF, 2 "id" REF, 3 "group" REF) -> ()),
    req!(39 "react" (1 "who" REF, 2 "id" REF, 3 "text" T, 4 "group" REF) -> ()),
    req!(40 "mark-read" (1 "who" REF, 2 "group" REF) -> (
        2 "kept" BOOL, 3 "marked" BOOL, 4 "why" T)),
    req!(41 "read-markers" (1 "on" BOOL) -> (2 "on" BOOL)),
    req!(42 "invite" (
        1 "address" T, 2 "name" T, 3 "hosts_only" BOOL, 4 "no_introductions" BOOL
    ) -> (2 "code" T)),
    req!(43 "accept" (
        1 "code" T, 2 "name" T, 3 "via" T, 4 "hosts_only" BOOL, 5 "no_introductions" BOOL,
        6 "for" REF
    ) -> (2 "name" T, 3 "recovery_of" B)),
    paged!(after 44 "invitations" (1 "after" U, 2 "limit" U) -> (
        2 "invitations" [INVITATION], 3 "more" BOOL, 4 "next" U)),
    req!(45 "cancel-invitation" (1 "id" REF) -> ()),
    paged!(after 46 "introductions" (1 "after" U, 2 "limit" U) -> (
        2 "introductions" [INTRODUCTION], 3 "more" BOOL, 4 "next" U)),
    req!(47 "introduce" (1 "who" REF, 2 "to" REF, 3 "note" T) -> ()),
    req!(48 "introduction-accept" (1 "id" REF) -> (2 "name" T, 3 "recovery_of" B)),
    req!(49 "introduction-decline" (1 "id" REF) -> ()),
    // ---- Groups: 70 to 99 ----
    paged!(after 70 "groups" (1 "after" U, 2 "limit" U) -> (
        2 "groups" [GROUP], 3 "offers" [OFFER], 4 "more" BOOL, 5 "next" U,
        6 "rejoin" [REJOIN])),
    req!(71 "group-create" (1 "name" T, 2 "people" [REF], 3 "for_call" BOOL, 4 "history" BOOL) -> (
        2 "group" B, 3 "name" T)),
    req!(72 "group-join" (1 "group" REF, 2 "reach" BOOL) -> (
        2 "group" B, 3 "name" T, 4 "shared" BOOL, 5 "waiting" BOOL)),
    req!(73 "group-decline" (1 "group" REF) -> ()),
    req!(74 "group-leave" (1 "group" REF, 2 "admins" [REF], 3 "anyway" BOOL) -> (
        2 "admins" [T])),
    req!(75 "group-reach" (1 "group" REF, 2 "share" BOOL, 3 "host" T) -> (
        2 "shared" BOOL, 3 "waiting" BOOL, 4 "taken_out" BOOL)),
    req!(76 "group-add" (1 "group" REF, 2 "people" [REF], 3 "shown" T) -> ()),
    req!(77 "group-remove" (1 "group" REF, 2 "who" REF) -> (
        2 "group" B, 3 "left_out" [B], 4 "was" B)),
    paged!(after 78 "group-members" (1 "group" REF, 2 "after" U, 3 "limit" U) -> (
        2 "group" B, 3 "members" [MEMBER], 4 "name" T, 5 "more" BOOL, 6 "next" U)),
    req!(79 "group-set" (1 "group" REF, 2 "name" T, 3 "introductions" BOOL, 4 "for_call" BOOL) -> ()),
    req!(80 "group-member" (1 "group" REF, 2 "who" REF, 3 "shown" T, 4 "introduce" BOOL) -> ()),
    req!(81 "group-connect" (1 "group" REF, 2 "who" REF, 3 "note" T) -> (2 "asked" BOOL)),
    req!(82 "group-role" (1 "group" REF, 2 "who" REF, 3 "role" T) -> (2 "group" B, 3 "was" B)),
    req!(83 "group-post-again" (1 "group" REF) -> (2 "posted" U)),
    req!(84 "group-moved-seen" (1 "group" REF) -> ()),
    req!(85 "group-confirm-move" (1 "group" REF, 2 "moves" [B], 3 "to" [B]) -> (2 "kept" U)),
    req!(86 "group-leaving" (1 "group" REF) -> (
        2 "admins" [T], 3 "choose_admin" BOOL, 4 "group" B, 5 "name" T,
        6 "relayed_for" [RELAYED_FOR])),
    req!(87 "group-rejoin" (1 "group" REF) -> (2 "group" B, 3 "name" T)),
    // ---- Calls and the clipboard: 100 to 119 ----
    req!(100 "call" () -> (2 "call" {CALL}, 3 "ended" {CALL_ENDED})),
    req!(101 "call-start" (
        1 "who" REF, 2 "group" REF, 3 "formats" [B], 4 "format_names" [T], 5 "ring" [REF]
    ) -> ()),
    req!(102 "call-answer" (1 "formats" [B], 2 "format_names" [T], 3 "reach" BOOL, 4 "join" BOOL) -> ()),
    req!(103 "call-end" () -> ()),
    req!(104 "call-media" () -> ()),
    req!(105 "clip-copy" (1 "text" T) -> (2 "devices" U)),
    req!(106 "clip" () -> (2 "from" T, 3 "here" BOOL, 4 "seconds" U, 5 "text" T)),
    // ---- The one folder: 120 to 149 ----
    paged!(after 120 "files" (1 "path" T, 2 "after" U, 3 "limit" U) -> (
        2 "files" [FILE], 3 "path" T, 4 "place" {PLACE}, 5 "more" BOOL, 6 "next" U)),
    req!(121 "mkdir" (1 "path" T) -> (2 "path" T)),
    req!(122 "move" (1 "from" T, 2 "to" T) -> (2 "path" T)),
    req!(123 "remove" (1 "path" T) -> (2 "path" T)),
    req!(124 "copy" (1 "from" T, 2 "to" T) -> (2 "path" T)),
    req!(125 "put" (1 "from" T, 2 "to" T) -> (2 "path" T)),
    req!(126 "save" (1 "path" T, 2 "to" T, 3 "version" U) -> (2 "path" T, 3 "size" U)),
    req!(127 "write" (1 "from" T, 2 "path" T) -> (2 "path" T)),
    req!(128 "share" (1 "who" REF, 2 "paths" [T], 3 "text" T, 4 "group" REF) -> (2 "message" BOOL, 3 "path" T)),
    req!(129 "mount" (1 "path" T) -> (2 "path" T)),
    req!(130 "unmount" () -> ()),
    req!(131 "flush" () -> (2 "entries" U)),
    paged!(after 132 "conflicts" (1 "after" U, 2 "limit" U) -> (
        2 "conflicts" [CONFLICT], 3 "more" BOOL, 4 "next" U)),
    paged!(after 133 "history" (1 "path" T, 2 "after" U, 3 "limit" U) -> (
        2 "path" T, 3 "versions" [VERSION], 4 "more" BOOL, 5 "next" U)),
    req!(134 "restore" (1 "path" T, 2 "version" U) -> (2 "path" T, 3 "version" U)),
    req!(135 "pin" (1 "path" T) -> (2 "on_demand" BOOL, 3 "path" T)),
    req!(136 "unpin" (1 "path" T) -> (2 "on_demand" BOOL, 3 "path" T)),
    req!(137 "retention" (1 "mode" T) -> (2 "retention" T)),
    req!(138 "keep-old" (1 "keep" T, 2 "space" REF) -> (2 "keep" T)),
    req!(139 "free-space" (1 "dry_run" BOOL, 2 "unnamed" BOOL, 3 "delete" BOOL) -> (
        2 "bytes" U, 3 "deleted" BOOL, 4 "left" U, 5 "objects" U, 6 "only_here" {ONLY_HERE},
        7 "unchecked" BOOL, 8 "unsure" [T])),
    paged!(after 140 "space-usage" (1 "after" U, 2 "limit" U) -> (
        2 "spaces" [SPACE_USAGE], 3 "more" BOOL, 4 "next" U)),
    req!(141 "history-empty" (1 "space" REF) -> (2 "bytes" U, 3 "left" U, 4 "objects" U)),
    // ---- Guardians and recovery: 150 to 179 ----
    req!(150 "guardians" () -> (
        2 "asked" [T], 3 "changes" [GUARDIAN_CHANGE], 4 "copy_full" [T], 5 "data" BOOL,
        6 "delay" U, 7 "delay_text" T, 8 "frozen" BOOL, 9 "guardians" U, 10 "names" [T],
        11 "ready" [T], 12 "recoveries" [RECOVERY], 13 "threshold" U)),
    req!(151 "guardians-set" (1 "who" [REF], 2 "threshold" U, 3 "delay" U, 4 "words" T) -> (
        2 "delay" U, 3 "delay_text" T, 4 "names" [T], 5 "pending" BOOL, 6 "threshold" U)),
    req!(152 "guardians-object" (1 "fingerprint" T) -> ()),
    req!(153 "guardians-ask" (1 "who" REF) -> (2 "name" T)),
    guarding_reply!("guarding" 154 ()),
    req!(155 "guarding-invite" (1 "who" REF, 2 "at" T) -> (2 "code" T, 3 "name" T)),
    req!(156 "guarding-accept" (1 "who" REF) -> (2 "already" BOOL, 3 "name" T, 4 "persona" B)),
    guarding_reply!("guarding-confirm-change" 157 (
        1 "who" REF, 2 "fingerprint" T, 3 "understood" BOOL)),
    guarding_reply!("guarding-never" 158 (1 "who" REF, 2 "fingerprint" T)),
    req!(159 "guarding-caution" (1 "who" REF) -> (2 "caution" T, 3 "name" T)),
    guarding_reply!("guarding-endorse" 160 (1 "who" REF, 2 "fingerprint" T, 3 "understood" BOOL)),
    guarding_reply!("guarding-confirm" 161 (1 "who" REF, 2 "fingerprint" T, 3 "understood" BOOL)),
    req!(162 "recover" () -> (
        2 "asked" BOOL, 3 "confirmed" U, 4 "endorsed" U, 5 "fingerprint" T, 6 "guardians" U,
        7 "held" U, 8 "helper" BOOL, 9 "identity" B, 10 "in_effect" BOOL, 11 "lost_at" U,
        12 "lost_devices" [LOST_DEVICE], 13 "pair_again" [PAIR_AGAIN], 14 "proposed" U,
        15 "successions" (gone [SUCCESSION]), 16 "threshold" U, 17 "under_way" BOOL,
        18 "finished" BOOL, 19 "words" T, 20 "kept_changes" [KEPT_CHANGE], 21 "not_heard" [T])),
    req!(163 "recover-start" (1 "code" T, 2 "identity" REF) -> (
        2 "fingerprint" T, 3 "identity" B)),
    req!(164 "recover-invite" (1 "at" T) -> (2 "code" T, 3 "fingerprint" T)),
    gone!(165 "recover-keep-succession" (1 "id" T, 2 "keep" BOOL) -> (
        2 "answered" U, 3 "kept" BOOL)),
    req!(166 "recover-lost-at" (1 "lost_at" U) -> (2 "lost_devices" [LOST_DEVICE])),
    req!(167 "recover-cancel" () -> (2 "fingerprint" T)),
    req!(168 "recover-finish" (1 "without_account" BOOL, 2 "lost_at" U) -> (
        2 "account" BOOL, 3 "lost_devices" [LOST_DEVICE], 4 "pair_again" [PAIR_AGAIN],
        5 "words" T, 6 "not_heard" [T])),
    req!(169 "keep-work" (1 "name" T, 2 "up_to" T) -> (2 "kept" U, 3 "set_aside" [SET_ASIDE])),
    req!(170 "recovery-check" (1 "words" T) -> ()),
    req!(171 "recovery-sheet" () -> (2 "hosts" [HOST])),
    req!(172 "restore-from-host" (1 "words" T, 2 "at" T, 3 "key" (gone T), 4 "key" B) -> (2 "at" T)),
    req!(173 "recover-undo" (1 "to" B) -> (2 "group" B, 3 "kept_changes" [KEPT_CHANGE])),
    req!(174 "recover-kept-seen" (1 "to" [B]) -> (2 "kept_changes" [KEPT_CHANGE])),
    // ---- Networks, hosts and peers: 180 to 199 ----
    req!(180 "router" (1 "on" BOOL, 2 "this_device" BOOL) -> (
        2 "error" T, 3 "everywhere" BOOL, 4 "external" T, 5 "named" [T], 6 "network" {NETWORK},
        7 "on" BOOL, 8 "protocol" T, 9 "seconds_left" U, 10 "this_device" BOOL)),
    req!(181 "bluetooth" (1 "mode" T) -> (
        2 "available" BOOL, 3 "channels_in" U, 4 "error" T, 5 "mode" T, 6 "on" BOOL, 7 "psm" U,
        8 "radio" T, 9 "recognized" U, 10 "seen" U, 11 "why_not" T, 12 "windows" U,
        13 "too_old" BOOL)),
    req!(182 "network" (1 "mine" BOOL, 2 "name" T) -> (
        2 "answered" BOOL, 3 "ask" BOOL, 4 "known" BOOL, 5 "mine" BOOL, 6 "name" T,
        7 "router" T, 8 "routers" BOOL)),
    req!(183 "host" (1 "addresses" [T]) -> (2 "hosts" [HOST], 3 "warnings" [T])),
    req!(184 "host-off" () -> (2 "hosts" [HOST])),
    req!(185 "peer-add" (1 "addr" T) -> (2 "addr" T)),
    req!(186 "peer-remove" (1 "addr" T) -> ()),
    paged!(after 187 "peer-list" (1 "after" U, 2 "limit" U) -> (
        2 "peers" [PEER], 3 "more" BOOL, 4 "next" U)),
    req!(188 "host-offer" (1 "who" REF, 2 "devices" [T], 3 "envelopes" U, 4 "relay_mb" U) -> (
        2 "devices" [T], 3 "sees" T, 4 "on" [HOSTABLE])),
    req!(189 "host-accept" (1 "who" REF) -> (2 "sees" T)),
    req!(190 "host-end" (1 "who" REF) -> (2 "ended" BOOL)),
    req!(191 "hosting" () -> (
        2 "can" [T], 3 "hosting" [HOSTING], 4 "why_not" T, 5 "devices" [HOSTABLE])),
    // ---- Inspection and measuring: 200 to 219 ----
    req!(200 "inspect-on" (1 "minutes" U) -> (2 "token" B, 3 "until" U)),
    req!(201 "inspect-off" () -> (2 "was_on" BOOL)),
    paged!(after 202 "inspect" (1 "token" REF, 2 "after" U, 3 "limit" U) -> (
        2 "device" {INSPECT_DEVICE}, 3 "identity" {INSPECT_IDENTITY}, 4 "others" [OTHER_LOG],
        5 "spaces" [INSPECT_SPACE], 6 "store" {STORE}, 7 "version" T, 8 "more" BOOL,
        9 "next" U)),
    paged!(after 203 "inspect-identity" (
        1 "token" REF, 2 "who" REF, 3 "entry" REF, 4 "path" [SCALAR], 5 "value_bytes" U,
        6 "items" U, 7 "after" U, 8 "limit" U
    ) -> (
        2 "attached" [ATTACHED_LOG], 3 "entries" [IDENTITY_ENTRY], 4 "id" B, 5 "stalled" [B],
        6 "value" {VALUE}, 7 "more" BOOL, 8 "next" U)),
    paged!(after 204 "inspect-space" (
        1 "token" REF, 2 "space" REF, 3 "value_bytes" U, 4 "items" U, 5 "after" U, 6 "limit" U
    ) -> (
        2 "account" BOOL, 3 "bytes" U, 4 "conflicts" U, 5 "created" U, 6 "creator" B,
        7 "current_epoch" B, 8 "entries" U, 9 "epochs" [EPOCH], 10 "files" BOOL, 11 "heads" [B],
        12 "id" B, 13 "kinds" [KIND_COUNT], 14 "label" T, 15 "members" [SPACE_MEMBER],
        16 "my_role" U, 17 "nodes" U, 18 "opened" BOOL, 19 "owner" B, 20 "pending" U,
        21 "policy" {POLICY}, 22 "profile" KIND, 23 "reach" [REACH_NODE], 24 "rejected" U,
        25 "root" {ROOT}, 26 "sealed" U, 27 "stats" {STATS}, 28 "successor" B,
        29 "unwitnessed" U, 30 "valid" U, 31 "more" BOOL, 32 "next" U)),
    paged!(after 205 "inspect-entries" (
        1 "token" REF, 2 "space" REF, 3 "view" T, 4 "offset" (gone U), 5 "count" (gone U),
        6 "after" U, 7 "limit" U
    ) -> (
        2 "entries" [INSPECT_ENTRY], 3 "offset" (gone U), 4 "pending" U, 5 "total" U,
        6 "more" BOOL, 7 "next" U)),
    paged!(after 206 "inspect-entry" (
        1 "token" REF, 2 "space" REF, 3 "entry" REF, 4 "sealed_id" REF, 5 "path" [SCALAR],
        6 "value_bytes" U, 7 "items" U, 8 "after" U, 9 "limit" U
    ) -> (
        2 "accepted" BOOL, 3 "children" [B], 4 "entry" B, 5 "header" {VALUE}, 6 "ops" [OP],
        7 "position" U, 8 "sealed" {VALUE}, 9 "sealed_id" B, 10 "signatures" [SIGNATURE],
        11 "valid" BOOL, 12 "weigh" {WEIGH}, 13 "value" {VALUE}, 14 "more" BOOL, 15 "next" U)),
    paged!(after 207 "inspect-nodes" (
        1 "token" REF, 2 "space" REF, 3 "kind" KIND, 4 "parent" REF, 5 "offset" (gone U),
        6 "count" (gone U), 7 "after" U, 8 "limit" U
    ) -> (
        2 "nodes" [NODE_BRIEF], 3 "offset" (gone U), 4 "total" U, 5 "more" BOOL, 6 "next" U)),
    paged!(after 208 "inspect-node" (
        1 "token" REF, 2 "space" REF, 3 "node" REF, 4 "path" [SCALAR], 5 "value_bytes" U,
        6 "items" U, 7 "after" U, 8 "limit" U
    ) -> (
        2 "bytes" U, 3 "children" U, 4 "created" U, 5 "created_in" B, 6 "creator" B,
        7 "delete_conflict" BOOL, 8 "deleted" BOOL, 9 "fields" [[U]],
        10 "history" [NODE_HISTORY], 11 "id" B, 12 "kind" KIND, 13 "name" T, 14 "parent" B,
        15 "position" U, 16 "special" T, 17 "values" [NODE_FIELD], 18 "value" {VALUE},
        19 "more" BOOL, 20 "next" U)),
    paged!(after 209 "debug-tree" (1 "after" U, 2 "limit" U) -> (
        2 "deleted" U, 3 "epoch" B, 4 "heads" B, 5 "items" [TREE_ITEM], 6 "mounted" BOOL,
        7 "pending" BOOL, 8 "settle" U, 9 "state" B, 10 "stuck" [STUCK_ITEM],
        11 "unshown" [UNSHOWN_NODE], 12 "more" BOOL, 13 "next" U)),
    req!(210 "speedtest" (1 "device" REF) -> (
        2 "device" T, 3 "ms" U, 4 "receive" U, 5 "received_bytes" U, 6 "rtt_median_us" U,
        7 "rtt_min_us" U, 8 "send" U, 9 "sent_bytes" U)),
    // ---- Applications: 220 to 239 ----
    paged!(after 220 "app-questions" (1 "after" U, 2 "limit" U) -> (
        2 "questions" [APP_QUESTION], 3 "more" BOOL, 4 "next" U)),
    req!(221 "app-answer" (1 "id" U, 2 "yes" BOOL, 3 "people" [REF], 4 "role" T) -> ()),
    paged!(after 222 "approvals" (1 "after" U, 2 "limit" U) -> (
        2 "approvals" [APPROVAL], 3 "more" BOOL, 4 "next" U)),
    req!(223 "approval-revoke" (1 "id" REF) -> ()),
    paged!(after 224 "app-offers" (1 "after" U, 2 "limit" U) -> (
        2 "offers" [APP_OFFER], 3 "more" BOOL, 4 "next" U)),
    req!(225 "app-join" (1 "space" REF) -> (2 "space" B, 3 "name" T)),
    req!(226 "wake" () -> (2 "checking" U)),
    paged!(after 227 "deleted" (1 "path" T, 2 "after" U, 3 "limit" U, 4 "hidden" BOOL) -> (
        2 "files" [DELETED_FILE], 3 "path" T, 4 "more" BOOL, 5 "next" U)),
    req!(228 "undelete" (1 "path" T, 2 "id" REF) -> (2 "id" B, 3 "path" T)),
];

// ---- What the service's program says without starting ----

rec!(DATA_HELD "data held":
    1 "bytes" U, 2 "identity" BOOL, 3 "local" U, 4 "local_bytes" U, 5 "objects" U,
    6 "other" BOOL, 7 "spaces" U, 8 "unsaved" U, 9 "unsaved_bytes" U);

/// What the service's program says without starting (`apps.md`, The local
/// interface), by the option that asks it: one record on its standard
/// output, numbered as a reply is, with nothing after it. `--store` says
/// which data is there and what it holds, counted without reading any of
/// it; `--clear` removes data this version cannot read, or fails, saying
/// why.
pub static PROGRAM: &[Request] = &[
    req!(1 "--store" () -> (
        2 "holds" {DATA_HELD}, 3 "refusal" T, 4 "store" T, 5 "written_by" T)),
    req!(2 "--clear" () -> ()),
];

/// What an error's reply says besides why, in key 1, numbered as a reply's
/// fields are (`apps.md`, Errors): of error 4 to a paged request, which item
/// was too large for a message on its own, by its place in the answer as
/// `after` counts (`at`), and by its `id` where it has one, so that a
/// client can ask for what comes after it.
pub static ERROR_FIELDS: &[Field] = &[f!(2 "at" U), f!(3 "id" B)];

/// The events of a `watch` connection: key 0 says which.
pub static EVENTS: &[Request] = &[req!(1 "changed" (1 "seq" U) -> ())];

/// The frames of a `call-media` connection, both ways: key 0 says which.
/// `from` is the voice a frame of a group call is, from the service, or
/// the sender a window's level or key picture is asked of.
pub static FRAMES: &[Request] = &[
    req!(1 "audio" (1 "audio" B, 3 "from" B) -> ()),
    req!(2 "frame" (1 "frame" B, 2 "format" B, 3 "from" B, 4 "size" U) -> ()),
    req!(3 "viewport" (1 "width" U, 2 "height" U, 3 "from" B) -> ()),
    req!(4 "level" (1 "level" U, 3 "from" B) -> ()),
    req!(5 "asked" (1 "small" BOOL, 2 "large" BOOL) -> ()),
    req!(6 "key" (3 "from" B, 4 "size" U) -> ()),
    req!(7 "camera" (1 "camera" BOOL) -> ()),
];
