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

use std::borrow::Cow;

use super::typed::{Fields, Reference};

/// What a field holds.
#[derive(Debug)]
pub enum Ty {
    /// Text.
    Text,
    /// Bytes: a key, an id or a hash. Typed, they are bytes; by name, the
    /// service holds them as hex.
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
    /// How a typed request is answered, from its message to its reply's;
    /// `None` for one answered by name, or by the connection itself.
    pub answer: Option<Answerer>,
}

/// How a typed request is answered (`control::typed::answering`).
pub type Answerer =
    for<'a> fn(
        &'a std::sync::Arc<crate::daemon::Daemon>,
        cardinal_encoding::Record,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>>;

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

/// A record of the interface, typed (`api::typed`): one declaration gives
/// the struct, its row in the tables, and its encoding both ways, so what
/// the tables say and what the service sends cannot differ. Each field is
/// its number, its name (the Rust name without `r#`), and its Rust type,
/// which says its type in the tables ([`typed::Wire`](super::typed::Wire)),
/// in the order of the numbers.
///
/// `typed!(STATIC "record name" Name { 1 field: Type, ... })` declares a
/// record held in replies, with its row as `STATIC`;
/// `typed!(fields Name { ... })` the arguments or the reply of a request,
/// which [`asks!`] then numbers.
///
/// - A field that is not an `Option` is one the service always sends: the
///   handler must give it, since `Name::new` takes these fields, in order,
///   and there is no `Default`; read back, its absence is an error. A
///   field added to a record after it was first released is an `Option`
///   for ever, so that a newer client reads an older service.
/// - `n gone name: Type` is a number no longer used: it keeps its row, with
///   the type it had, and no struct field; it is never sent, and what
///   comes under it is passed over.
#[macro_export]
#[doc(hidden)]
macro_rules! typed {
    (
        $(#[$m:meta])*
        $stat:ident $title:literal $name:ident { $($body:tt)* }
    ) => {
        $crate::typed!(fields $(#[$m])* $name { $($body)* });

        #[doc = concat!("The *", $title, "* record's row in the tables.")]
        pub static $stat: $crate::api::table::Rec = $crate::api::table::Rec {
            name: $title,
            fields: <$name as $crate::api::typed::Fields>::FIELDS,
        };

        impl $crate::api::typed::Wire for $name {
            const TY: $crate::api::table::Ty = $crate::api::table::Ty::Rec(&$stat);
            const LIST: $crate::api::table::Ty = $crate::api::table::Ty::Recs(&$stat);
            fn encode_into(&self, out: &mut Vec<u8>) {
                use $crate::api::typed::Fields;
                $crate::api::typed::record_header(self.present_except(&[]), out);
                self.encode_fields_except(&[], out);
            }
            fn encoded_len(&self) -> usize {
                $crate::api::typed::Fields::record_len_except(self, &[])
            }
            fn check(&self, at: &$crate::api::typed::At) -> Result<(), String> {
                match $crate::api::typed::Fields::invalid(self, at).into_iter().next() {
                    Some((_, _, e)) => Err(e),
                    None => Ok(()),
                }
            }
            fn take(
                v: cardinal_encoding::Value,
                at: &$crate::api::typed::At,
            ) -> Result<Self, String> {
                match v {
                    cardinal_encoding::Value::Record(r) => {
                        <$name as $crate::api::typed::Fields>::take_fields(r, at)
                    }
                    _ => Err(format!("{at} should be a record")),
                }
            }
        }
    };
    (fields $(#[$m:meta])* $name:ident { $($body:tt)* }) => {
        $crate::typed!(@munch [$(#[$m])* $name] [] [] [] [] [] $($body)*);
    };
    // A number no longer used.
    (@munch $h:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $n:literal gone $f:ident : $t:ty $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h [$($s)*] [$($r)*] [$($o)*] [$($l)*]
            [$($a)* ($n $f (gone $t))] $($($rest)*)?);
    };
    // A field sent only when it is `Some`.
    (@munch $h:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $(#[$fm:meta])* $n:literal $f:ident : Option<$t:ty> $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h
            [$($s)* ($(#[$fm])* $f : Option<$t>)] [$($r)*] [$($o)* $f]
            [$($l)* ($n $f)] [$($a)* ($n $f (Option<$t>))] $($($rest)*)?);
    };
    // A field always sent.
    (@munch $h:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $(#[$fm:meta])* $n:literal $f:ident : $t:ty $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h
            [$($s)* ($(#[$fm])* $f : $t)] [$($r)* ($f : $t)] [$($o)*]
            [$($l)* ($n $f)] [$($a)* ($n $f ($t))] $($($rest)*)?);
    };
    (@row ($n:literal $f:ident (gone $t:ty))) => {
        $crate::api::table::Field {
            n: $n,
            name: $crate::api::typed::field_name(stringify!($f)),
            ty: $crate::api::table::Ty::Gone(&<$t as $crate::api::typed::Wire>::TY),
        }
    };
    (@row ($n:literal $f:ident ($t:ty))) => {
        $crate::api::table::Field {
            n: $n,
            name: $crate::api::typed::field_name(stringify!($f)),
            ty: <$t as $crate::api::typed::Wire>::TY,
        }
    };
    (@munch [$(#[$m:meta])* $name:ident]
        [$(($(#[$fm:meta])* $sf:ident : $st:ty))*]
        [$(($rf:ident : $rt:ty))*]
        [$($of:ident)*]
        [$(($ln:literal $lf:ident))*]
        [$($a:tt)*]
    ) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name {
            $( $(#[$fm])* pub $sf: $st, )*
        }

        impl $name {
            /// It, with the fields it always has, in order; the others
            /// absent.
            #[allow(clippy::new_without_default, clippy::too_many_arguments)]
            pub fn new($($rf: $rt),*) -> Self {
                $name { $($rf,)* $($of: None,)* }
            }
        }

        impl $crate::api::typed::Fields for $name {
            const FIELDS: &'static [$crate::api::table::Field] = &[
                $( $crate::typed!(@row $a) ),*
            ];

            #[allow(unused_mut)]
            fn present_except(&self, skip: &[u64]) -> u64 {
                let mut n = 0;
                $( if $crate::api::typed::Wire::sent(&self.$lf) && !skip.contains(&$ln) {
                    n += 1;
                } )*
                let _ = skip;
                n
            }

            fn encode_fields_except(&self, skip: &[u64], out: &mut Vec<u8>) {
                $( if $crate::api::typed::Wire::sent(&self.$lf) && !skip.contains(&$ln) {
                    $crate::api::typed::key($ln, out);
                    $crate::api::typed::Wire::encode_into(&self.$lf, out);
                } )*
                let _ = (skip, out);
            }

            #[allow(unused_mut)]
            fn fields_len_except(&self, skip: &[u64]) -> usize {
                let mut n = 0;
                $( if $crate::api::typed::Wire::sent(&self.$lf) && !skip.contains(&$ln) {
                    n += $crate::api::typed::key_len($ln)
                        + $crate::api::typed::Wire::encoded_len(&self.$lf);
                } )*
                let _ = skip;
                n
            }

            #[allow(unused_mut)]
            fn invalid(
                &self,
                at: &$crate::api::typed::At,
            ) -> Vec<(u64, &'static str, String)> {
                let mut out = Vec::new();
                $( if $crate::api::typed::Wire::sent(&self.$lf) {
                    let name = $crate::api::typed::field_name(stringify!($lf));
                    let at = $crate::api::typed::At::Field(at, name);
                    if let Err(e) = $crate::api::typed::Wire::check(&self.$lf, &at) {
                        out.push(($ln, name, e));
                    }
                } )*
                let _ = at;
                // in the order of their names, as the tables by name met them
                out.sort_by_key(|(_, name, _)| *name);
                out
            }

            #[allow(unused_mut, unused_variables)]
            fn take_fields(
                mut r: cardinal_encoding::Record,
                at: &$crate::api::typed::At,
            ) -> Result<Self, String> {
                Ok($name { $(
                    $lf: {
                        let at = $crate::api::typed::At::Field(
                            at,
                            $crate::api::typed::field_name(stringify!($lf)),
                        );
                        match r.remove($ln) {
                            Some(v) => $crate::api::typed::Wire::take(v, &at)?,
                            None => $crate::api::typed::Wire::absent(&at)?,
                        }
                    },
                )* })
            }
        }

        const _: () = $crate::api::typed::ascending(
            <$name as $crate::api::typed::Fields>::FIELDS,
        );
    };
}

/// A typed request: its row, `ROW`, for [`REQUESTS`], from its typed
/// arguments and reply; how it is answered; and how it pages.
///
/// `asks!(ROW: n "name" Args -> Reply, how)`, where `how` is
///
/// - `reads`: it changes nothing, so where the tests run the service
///   answers it by name too and fails it if the two differ;
/// - `reads unless field`: the same while `field` is not given;
/// - `writes`: answered once; same-bytes cases written by hand cover it;
/// - `stream`: answered by the connection itself, which then carries a
///   stream (`watch`, `call-media`).
///
/// Every request but a stream is answered by `impl Answer for Args`
/// (`control::typed`): one declared without it does not compile. A paged
/// one says how after `how`: `after list` (by position) or `before list
/// by id` (back from the newest, `next` the `id` of the oldest given);
/// its arguments then have `after` or `before`, and `limit`, and its
/// reply the list, `more` and `next`, which the page is cut by.
macro_rules! asks {
    ($row:ident: $n:literal $name:literal $args:ident -> $reply:ident,
        $how:ident $(unless $unless:ident)? $(, $($page:tt)*)?) => {
        #[doc = concat!("The row of `", $name, "`, typed.")]
        pub const $row: Request = Request {
            n: $n,
            name: $name,
            args: <$args as Fields>::FIELDS,
            reply: <$reply as Fields>::FIELDS,
            page: asks!(@page $($($page)*)?),
            gone: false,
            answer: asks!(@answer $how $args),
        };

        impl super::typed::Ask for $args {
            const REQUEST: &'static Request = &$row;
            type Reply = $reply;
            asks!(@reads $how $($unless)?);
            asks!(@paging $args $reply $($($page)*)?);
        }
    };
    (@answer stream $args:ident) => { None };
    (@answer $how:ident $args:ident) => {
        Some(crate::control::typed::answering::<$args> as super::table::Answerer)
    };
    (@reads reads) => {
        fn reads(&self) -> bool {
            true
        }
    };
    (@reads reads $unless:ident) => {
        fn reads(&self) -> bool {
            self.$unless.is_none()
        }
    };
    (@reads writes) => {};
    (@reads stream) => {};
    (@page) => { Page::Whole };
    (@page after $list:ident $($rest:tt)*) => { Page::After };
    (@page before $list:ident $($rest:tt)*) => { Page::Before { list: stringify!($list) } };
    (@paging $args:ident $reply:ident) => {};
    (@id) => { |_| None };
    (@id $id:ident) => { |x| Some(&x.$id[..]) };
    (@paging $args:ident $reply:ident after $list:ident $(by $id:ident)?) => {
        fn reply_bytes(&self, mut reply: $reply) -> Vec<u8> {
            // beside the reply's other fields: without the list, `more`, `next`
            const SKIP: [u64; 3] = super::typed::paged_numbers(
                <$reply as Fields>::FIELDS,
                stringify!($list),
            );
            let base = reply.record_len_except(&SKIP);
            match super::typed::page_after(
                Self::REQUEST,
                stringify!($list),
                &mut reply.$list,
                base,
                self.after,
                self.limit,
                asks!(@id $($id)?),
            ) {
                Ok(cut) => {
                    reply.more = cut.more;
                    reply.next = cut.next;
                    super::typed::reply_message(Self::REQUEST.name, &reply)
                }
                Err(super::typed::Unpaged(msg)) => msg,
            }
        }
        fn one_page(&self) -> bool {
            self.after.is_some() || self.limit.is_some()
        }
        fn next_page(&self, had: &$reply) -> Option<Self> {
            let next = had.next.filter(|_| had.more)?;
            Some($args {
                after: Some(next),
                ..self.clone()
            })
        }
        fn join(all: &mut $reply, page: $reply) -> bool {
            let grew = !page.$list.is_empty();
            all.$list.extend(page.$list);
            (all.more, all.next) = (page.more, page.next);
            grew
        }
        fn whole(all: &mut $reply) {
            (all.more, all.next) = (false, None);
        }
    };
    (@paging $args:ident $reply:ident before $list:ident by $id:ident) => {
        fn reply_bytes(&self, mut reply: $reply) -> Vec<u8> {
            const SKIP: [u64; 3] = super::typed::paged_numbers(
                <$reply as Fields>::FIELDS,
                stringify!($list),
            );
            let base = reply.record_len_except(&SKIP);
            match super::typed::page_before(
                Self::REQUEST,
                stringify!($list),
                &mut reply.$list,
                base,
                self.limit,
                |x| Some(&x.$id[..]),
            ) {
                Ok(more) => {
                    reply.more = more;
                    reply.next = more.then(|| reply.$list.first().map(|x| x.$id)).flatten();
                    super::typed::reply_message(Self::REQUEST.name, &reply)
                }
                Err(super::typed::Unpaged(msg)) => msg,
            }
        }
        fn one_page(&self) -> bool {
            self.before.is_some() || self.limit.is_some()
        }
        fn next_page(&self, had: &$reply) -> Option<Self> {
            let next = had.next.filter(|_| had.more)?;
            Some($args {
                before: Some(super::typed::Reference::Id(next.to_vec())),
                ..self.clone()
            })
        }
        fn join(all: &mut $reply, mut page: $reply) -> bool {
            let grew = !page.$list.is_empty();
            page.$list.append(&mut all.$list);
            all.$list = page.$list;
            (all.more, all.next) = (page.more, page.next);
            grew
        }
        fn whole(all: &mut $reply) {
            (all.more, all.next) = (false, None);
        }
    };
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
            answer: None,
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

typed!(ATTACHMENT "attachment" Attachment {
    1 name: String,
    2 size: Option<u64>,
    3 r#type: String,
});
typed!(
    /// Where Bluetooth stands on this device.
    BLUETOOTH "bluetooth" BluetoothShown {
        /// Whether the radio could be used, the last time it was asked.
        1 available: Option<bool>,
        2 channels_in: u64,
        3 error: Option<String>,
        /// `off`, `open` or `always`.
        4 mode: Cow<'static, str>,
        5 on: bool,
        6 psm: Option<u64>,
        7 radio: Option<String>,
        8 recognized: u64,
        9 seen: u64,
        10 why_not: Option<String>,
        11 windows: u64,
        /// This device's Bluetooth cannot send extended advertisements.
        12 too_old: Option<bool>,
    }
);
typed!(
    /// The call under way (`apps.md`, *call*).
    CALL "call" Call {
        /// In a group: how many frames came, and how many of them new.
        1 frames: Option<CallFrames>,
        /// In a group: the group's id.
        2 group: Option<[u8; 32]>,
        3 id: [u8; 16],
        4 linked: Option<u64>,
        5 name: String,
        6 offered: Option<Vec<[u8; 32]>>,
        7 people: Option<u64>,
        8 picture: Option<String>,
        9 seconds: Option<u64>,
        /// `calling`, `ringing` or `live`.
        10 state: Cow<'static, str>,
        11 taken: Option<Vec<[u8; 32]>>,
        /// The start of the other person's id (or the ringer's, in a group).
        12 who: [u8; 8],
        13 voices: Option<Vec<Voice>>,
        14 they_take: Option<Vec<[u8; 32]>>,
        15 camera: Option<bool>,
        16 caller: Option<Member>,
        17 admins: Option<Vec<Member>>,
        18 joins: Option<bool>,
        19 reach: Option<GroupReach>,
        20 for_call: Option<bool>,
    }
);
typed!(
    /// How the last call ended.
    CALL_ENDED "call ended" CallEnded {
        1 group: Option<[u8; 32]>,
        2 how: Cow<'static, str>,
        3 id: [u8; 16],
        4 name: String,
        5 who: [u8; 8],
        6 at: u64,
    }
);
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
typed!(
    /// An entry of a folder of the one folder.
    FILE "file" File {
        1 added_by: Option<String>,
        2 category: Option<bool>,
        3 folder: bool,
        4 mine: Option<bool>,
        5 name: String,
        6 size: Option<u64>,
        7 time: Option<u64>,
        8 versions: Option<u64>,
        /// A contact's shared folder: the start of their id.
        9 who: Option<[u8; 8]>,
        /// A group's shared folder: its id.
        10 group: Option<[u8; 32]>,
    }
);
typed!(CALL_FRAMES "frames" CallFrames {
    1 r#in: u64,
    2 new: u64,
});
rec!(GROUP "group":
    1 "admin" BOOL, 2 "did_not_stand" [B], 3 "did_not_stand_changes" [GROUP_CHANGE],
    4 "ended" T, 5 "group" B, 6 "held_back" U, 7 "introductions" BOOL, 8 "last" {LAST},
    9 "members" U, 10 "moved" {GROUP_CHANGE}, 11 "name" T, 12 "not_posted" U, 13 "public" BOOL,
    14 "reach" {GROUP_REACH}, 15 "role" T, 16 "unread" U, 17 "was" B, 18 "confirm" [B],
    19 "to_confirm" [GROUP_CHANGE], 20 "for_call" BOOL, 21 "last_call" {CALL_ENDED});
rec!(GROUP_CHANGE "group change":
    1 "at" U, 2 "by" T, 3 "group" B, 4 "roles" [ROLE_CHANGE], 5 "seen" U, 6 "taken_out" [T],
    7 "device" T, 8 "to" B);
typed!(
    /// What this person's reach node says in a group, and to whom.
    GROUP_REACH "group reach" GroupReach {
        1 added: Vec<String>,
        2 ask: bool,
        3 public: bool,
        4 said_no: bool,
        5 set: bool,
        6 shared: bool,
        7 waiting: bool,
        8 what: Vec<String>,
        9 who: Vec<String>,
        10 named: Option<Vec<String>>,
    }
);
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
typed!(
    /// A host of this person's, as the recovery sheet names it.
    HOST "host" Host {
        1 addresses: Vec<String>,
        2 gone key: String,
        3 name: String,
        /// Its link key's X25519 half.
        4 key: [u8; 32],
    }
);
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
typed!(
    /// A member of a group, as this person sees them.
    MEMBER "member" Member {
        1 contact: bool,
        /// The start of their id.
        2 id: [u8; 8],
        3 introduce: bool,
        4 left: bool,
        5 name: String,
        6 own: Option<bool>,
        7 picture: Option<String>,
        /// `owner`, `admin`, `member`, `reader` or `taken out`.
        8 role: Cow<'static, str>,
        9 shown: Option<String>,
        10 suggested: Option<String>,
        11 taken_out: Option<bool>,
        12 you: bool,
        13 reach: Option<String>,
        14 reaches_you: Option<bool>,
        15 through: Option<String>,
    }
);
typed!(
    /// A message of a conversation, with a contact or in a group.
    MESSAGE "message" Message {
        1 attachments: Vec<Attachment>,
        2 edited: bool,
        /// In a group: who said it, by the name this person sees.
        3 from: Option<String>,
        4 id: [u8; 16],
        5 mine: bool,
        6 picture: Option<String>,
        7 reactions: Vec<Reaction>,
        /// In a group, of this person's own: how many of the others read it.
        8 read_by: Option<u64>,
        9 reply_to: Option<[u8; 16]>,
        /// Of this person's own: `sent`, `waiting` or `read`.
        10 state: Option<Cow<'static, str>>,
        11 text: String,
        12 time: Option<u64>,
    }
);
rec!(NO_LONGER_NEEDED "no longer needed": 1 "at_ms" U, 2 "id" B, 3 "name" T, 4 "text" T);
rec!(MET "met": 1 "by" T, 2 "group" T, 3 "how" T, 4 "via" T);
rec!(KNOWN_PATH "known path":
    1 "addr" T, 2 "checking" BOOL, 3 "confirmed_s_ago" U, 4 "misses" U, 5 "next_check_s" U,
    6 "probes" U, 7 "wait_s" U);
rec!(NEARBY "nearby": 1 "they_give_secret" BOOL, 2 "you_give_secret" BOOL);
typed!(
    /// The network this device is on, by its router, and what its person
    /// said of it.
    NETWORK "network" Network {
        1 answered: Option<bool>,
        2 ask: bool,
        3 known: bool,
        4 mine: bool,
        5 name: Option<String>,
        6 router: Option<String>,
        7 routers: bool,
    }
);
rec!(OFFER "offer":
    1 "from" T, 2 "group" B, 3 "members" U, 4 "name" T, 5 "public" BOOL, 6 "reach" {GROUP_REACH},
    7 "for_call" BOOL, 8 "last_call" {CALL_ENDED});
rec!(OLD "old versions":
    1 "at" U, 2 "bytes" U, 3 "keep" T, 4 "only_here" {ONLY_HERE}, 5 "unchecked" BOOL);
rec!(ONLY_HERE "only here": 1 "bytes" U, 2 "files" U);
rec!(PAIR_AGAIN "pair again": 1 "key" B, 2 "name" T);
rec!(PAIRING "pairing": 1 "admin" T, 2 "code" T, 3 "error" T, 4 "state" T, 5 "power" T);
rec!(PEER "peer": 1 "addr" T, 2 "device" T);
typed!(
    /// What a folder of the one folder is.
    PLACE "place" Place {
        /// `mine`, `category` or `shared`.
        1 kind: Cow<'static, str>,
        2 name: Option<String>,
        3 who: Option<[u8; 8]>,
        4 group: Option<[u8; 32]>,
    }
);
rec!(PROGRESS "progress":
    1 "bytes_fetched" U, 2 "bytes_pending" U, 3 "bytes_wanted" U, 4 "files_pending" U,
    5 "last_error" T, 6 "rate" U);
typed!(REACTION "reaction" Reaction {
    1 count: u64,
    2 mine: bool,
    3 text: String,
});
rec!(RECOVERY "recovery":
    1 "caution" T, 2 "confirm_from_ms" U, 3 "confirmed" U, 4 "confirmed_by_me" BOOL,
    5 "endorsed" U, 6 "endorsed_by_me" BOOL, 7 "fingerprint" T, 8 "id" B, 9 "in_effect" BOOL,
    10 "keeps_keys" BOOL, 11 "objected" BOOL, 12 "pending" BOOL);
rec!(RELAYED_FOR "relayed for": 1 "a" T, 2 "a_id" B, 3 "b" T, 4 "b_id" B);
rec!(REJOIN "rejoin": 1 "group" B, 2 "members" U, 3 "name" T);
rec!(ROLE_CHANGE "role change": 1 "from" T, 2 "name" T, 3 "to" T);
rec!(REDIAL "redial": 1 "alone" BOOL, 2 "helps" BOOL, 3 "sparing" {SPARING});
rec!(SPARING "sparing": 1 "next_s" U, 2 "wait_s" U);
typed!(
    /// What this device asks of routers, and what the router gave.
    ROUTER "router" Router {
        1 error: Option<String>,
        2 everywhere: bool,
        3 external: Option<String>,
        4 named: Vec<String>,
        5 network: Network,
        6 on: bool,
        7 protocol: Option<Cow<'static, str>>,
        8 seconds_left: Option<u64>,
        9 this_device: bool,
    }
);
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
typed!(
    /// Who a voice heard on a group call is.
    VOICE "voice" Voice {
        1 contact: bool,
        /// The start of the person's id.
        2 identity: [u8; 8],
        3 name: String,
        4 picture: Option<String>,
        5 voice: [u8; 8],
        6 you: bool,
        7 camera: bool,
    }
);
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

// ---- Typed requests (`api::typed`) ----

typed!(
    fields
    /// The reply of a request that says only that it was done.
    Done {}
);

typed!(fields WatchArgs {
    /// A window watching: while one does, Cardinal is open.
    1 window: Option<bool>,
});
asks!(WATCH: 3 "watch" WatchArgs -> Done, stream);

typed!(fields CallMediaArgs {});
asks!(CALL_MEDIA: 104 "call-media" CallMediaArgs -> Done, stream);

// ---- The service, this device, and the person's devices ----

typed!(fields ConditionsArgs {
    1 plugged_in: Option<bool>,
    2 metered: Option<bool>,
});
typed!(fields ConditionsReply {
    2 helps: bool,
    3 metered: bool,
    4 plugged_in: Option<bool>,
});
asks!(CONDITIONS_NOW: 6 "conditions" ConditionsArgs -> ConditionsReply, reads unless plugged_in);

typed!(fields NetworkChangedArgs {
    1 why: Option<String>,
});
typed!(
    fields
    /// How many sessions are checked.
    Checking {
        2 checking: u64,
    }
);
asks!(NETWORK_CHANGED: 7 "network-changed" NetworkChangedArgs -> Checking, writes);

typed!(fields MeArgs {
    1 name: Option<String>,
});
typed!(fields MeReply {
    2 name: String,
    3 set: bool,
});
asks!(ME: 10 "me" MeArgs -> MeReply, reads unless name);

typed!(fields DeviceRenameArgs {
    1 device: Option<Reference>,
    2 name: Option<String>,
});
typed!(fields DeviceRenameReply {
    /// The start of the device's key.
    2 key: [u8; 8],
    3 name: String,
});
asks!(DEVICE_RENAME: 12 "device-rename" DeviceRenameArgs -> DeviceRenameReply, writes);

typed!(fields PairShowArgs {
    1 gone admin: bool,
    2 device: Option<String>,
});
typed!(fields PairShowReply {
    2 addrs: Vec<String>,
    3 code: String,
});
asks!(PAIR_SHOW: 14 "pair-show" PairShowArgs -> PairShowReply, writes);

typed!(fields PairStatusArgs {});
typed!(fields PairStatusReply {
    2 admin: Option<String>,
    3 code: Option<String>,
    4 error: Option<String>,
    5 files: Option<bool>,
    /// `idle`, `showing`, `joining`, `joined` or `failed`.
    6 state: Cow<'static, str>,
    /// `device` or `admin`.
    7 power: Option<Cow<'static, str>>,
});
asks!(PAIR_STATUS: 15 "pair-status" PairStatusArgs -> PairStatusReply, reads);

typed!(fields PairTypeArgs {
    1 code: Option<String>,
    2 at: Option<String>,
    3 admin: Option<bool>,
    4 words: Option<String>,
    5 device: Option<String>,
});
typed!(fields PairTypeReply {
    2 name: String,
});
asks!(PAIR_TYPE: 16 "pair-type" PairTypeArgs -> PairTypeReply, writes);

typed!(fields WakeArgs {});
asks!(WAKE: 226 "wake" WakeArgs -> Checking, writes);

// ---- The clipboard ----

typed!(fields ClipCopyArgs {
    1 text: Option<String>,
});
typed!(fields ClipCopyReply {
    2 devices: u64,
});
asks!(CLIP_COPY: 105 "clip-copy" ClipCopyArgs -> ClipCopyReply, writes);

typed!(fields ClipArgs {});
typed!(fields ClipReply {
    2 from: Option<String>,
    3 here: Option<bool>,
    4 seconds: Option<u64>,
    /// None when nothing was copied in the last ten minutes.
    5 text: Option<String>,
});
asks!(CLIP: 106 "clip" ClipArgs -> ClipReply, reads);

// ---- The one folder ----

typed!(
    fields
    /// The path in the one folder a request made or changed.
    PathReply {
        2 path: String,
    }
);
typed!(fields MkdirArgs {
    1 path: Option<String>,
});
asks!(MKDIR: 121 "mkdir" MkdirArgs -> PathReply, writes);
typed!(fields MoveArgs {
    1 from: Option<String>,
    2 to: Option<String>,
});
asks!(MOVE: 122 "move" MoveArgs -> PathReply, writes);
typed!(fields RemoveArgs {
    1 path: Option<String>,
});
asks!(REMOVE: 123 "remove" RemoveArgs -> PathReply, writes);
typed!(fields CopyArgs {
    1 from: Option<String>,
    2 to: Option<String>,
});
asks!(COPY: 124 "copy" CopyArgs -> PathReply, writes);
typed!(fields PutArgs {
    1 from: Option<String>,
    2 to: Option<String>,
});
asks!(PUT: 125 "put" PutArgs -> PathReply, writes);
typed!(fields SaveArgs {
    1 path: Option<String>,
    2 to: Option<String>,
    3 version: Option<u64>,
});
typed!(fields SaveReply {
    2 path: String,
    3 size: u64,
});
asks!(SAVE: 126 "save" SaveArgs -> SaveReply, writes);
typed!(fields WriteArgs {
    1 from: Option<String>,
    2 path: Option<String>,
});
asks!(WRITE: 127 "write" WriteArgs -> PathReply, writes);
typed!(fields ShareArgs {
    1 who: Option<Reference>,
    2 paths: Option<Vec<String>>,
    3 text: Option<String>,
    4 group: Option<Reference>,
});
typed!(fields ShareReply {
    2 message: bool,
    3 path: String,
});
asks!(SHARE: 128 "share" ShareArgs -> ShareReply, writes);
typed!(fields MountArgs {
    1 path: Option<String>,
});
asks!(MOUNT: 129 "mount" MountArgs -> PathReply, writes);
typed!(fields UnmountArgs {});
asks!(UNMOUNT: 130 "unmount" UnmountArgs -> Done, writes);
typed!(fields FlushArgs {});
typed!(fields FlushReply {
    2 entries: u64,
});
asks!(FLUSH: 131 "flush" FlushArgs -> FlushReply, writes);
typed!(fields RestoreArgs {
    1 path: Option<String>,
    2 version: Option<u64>,
});
typed!(fields RestoreReply {
    2 path: String,
    3 version: u64,
});
asks!(RESTORE: 134 "restore" RestoreArgs -> RestoreReply, writes);
typed!(fields PinArgs {
    1 path: Option<String>,
});
typed!(fields PinReply {
    2 on_demand: bool,
    3 path: String,
});
asks!(PIN: 135 "pin" PinArgs -> PinReply, writes);
typed!(fields UnpinArgs {
    1 path: Option<String>,
});
asks!(UNPIN: 136 "unpin" UnpinArgs -> PinReply, writes);
typed!(fields RetentionArgs {
    1 mode: Option<String>,
});
typed!(fields RetentionReply {
    2 retention: String,
});
asks!(RETENTION: 137 "retention" RetentionArgs -> RetentionReply, writes);

// ---- People, conversations and invitations ----

typed!(fields InviteArgs {
    1 address: Option<String>,
    2 name: Option<String>,
    3 hosts_only: Option<bool>,
    4 no_introductions: Option<bool>,
});
typed!(fields InviteReply {
    2 code: String,
});
asks!(INVITE: 42 "invite" InviteArgs -> InviteReply, writes);
typed!(fields AcceptArgs {
    1 code: Option<String>,
    2 name: Option<String>,
    3 via: Option<String>,
    4 hosts_only: Option<bool>,
    5 no_introductions: Option<bool>,
    6 r#for: Option<Reference>,
});
typed!(
    fields
    /// Whom an invitation made a contact of, by the name this person gave
    /// them; of a recovery's, whose recovery it helps.
    AcceptReply {
        2 name: String,
        3 recovery_of: Option<[u8; 32]>,
    }
);
asks!(ACCEPT: 43 "accept" AcceptArgs -> AcceptReply, writes);

// ---- Groups ----

typed!(fields GroupCreateArgs {
    1 name: Option<String>,
    2 people: Option<Vec<Reference>>,
    3 for_call: Option<bool>,
    4 history: Option<bool>,
});
typed!(
    fields
    /// A group, by its id, and what it is called.
    GroupCreateReply {
        2 group: [u8; 32],
        3 name: String,
    }
);
asks!(GROUP_CREATE: 71 "group-create" GroupCreateArgs -> GroupCreateReply, writes);
typed!(fields GroupJoinArgs {
    1 group: Option<Reference>,
    2 reach: Option<bool>,
});
typed!(
    fields
    /// Nothing, of a group joined already.
    GroupJoinReply {
        2 group: Option<[u8; 32]>,
        3 name: Option<String>,
        4 shared: Option<bool>,
        5 waiting: Option<bool>,
    }
);
asks!(GROUP_JOIN: 72 "group-join" GroupJoinArgs -> GroupJoinReply, writes);
typed!(fields GroupDeclineArgs {
    1 group: Option<Reference>,
});
asks!(GROUP_DECLINE: 73 "group-decline" GroupDeclineArgs -> Done, writes);
typed!(fields GroupLeaveArgs {
    1 group: Option<Reference>,
    2 admins: Option<Vec<Reference>>,
    3 anyway: Option<bool>,
});
typed!(
    fields
    /// Whom leaving made admins, by the names this person sees.
    GroupLeaveReply {
        2 admins: Vec<String>,
    }
);
asks!(GROUP_LEAVE: 74 "group-leave" GroupLeaveArgs -> GroupLeaveReply, writes);
typed!(fields GroupReachArgs {
    1 group: Option<Reference>,
    2 share: Option<bool>,
    3 host: Option<String>,
});
typed!(
    fields
    /// Of a share or not: whether the hosts are named, or waiting to be;
    /// of one host taken out: whether it was named there.
    GroupReachReply {
        2 shared: Option<bool>,
        3 waiting: Option<bool>,
        4 taken_out: Option<bool>,
    }
);
asks!(GROUP_REACH_SET: 75 "group-reach" GroupReachArgs -> GroupReachReply, writes);
typed!(fields GroupAddArgs {
    1 group: Option<Reference>,
    2 people: Option<Vec<Reference>>,
    3 shown: Option<String>,
});
asks!(GROUP_ADD: 76 "group-add" GroupAddArgs -> Done, writes);
typed!(fields GroupRemoveArgs {
    1 group: Option<Reference>,
    2 who: Option<Reference>,
});
typed!(
    fields
    /// The group that stands in its place, those it left out, and the one
    /// it was.
    GroupRemoveReply {
        2 group: [u8; 32],
        3 left_out: Vec<[u8; 32]>,
        4 was: [u8; 32],
    }
);
asks!(GROUP_REMOVE: 77 "group-remove" GroupRemoveArgs -> GroupRemoveReply, writes);
typed!(fields GroupSetArgs {
    1 group: Option<Reference>,
    2 name: Option<String>,
    3 introductions: Option<bool>,
    4 for_call: Option<bool>,
});
asks!(GROUP_SET: 79 "group-set" GroupSetArgs -> Done, writes);
typed!(fields GroupMemberArgs {
    1 group: Option<Reference>,
    2 who: Option<Reference>,
    3 shown: Option<String>,
    4 introduce: Option<bool>,
});
asks!(GROUP_MEMBER: 80 "group-member" GroupMemberArgs -> Done, writes);
typed!(fields GroupRoleArgs {
    1 group: Option<Reference>,
    2 who: Option<Reference>,
    3 role: Option<String>,
});
typed!(
    fields
    /// The group, and of a role lowered, the one it succeeded.
    GroupRoleReply {
        2 group: [u8; 32],
        3 was: Option<[u8; 32]>,
    }
);
asks!(GROUP_ROLE: 82 "group-role" GroupRoleArgs -> GroupRoleReply, writes);
typed!(fields GroupRejoinArgs {
    1 group: Option<Reference>,
});
asks!(GROUP_REJOIN: 87 "group-rejoin" GroupRejoinArgs -> GroupCreateReply, writes);

// ---- Networks, hosts and peers ----

typed!(fields RouterArgs {
    1 on: Option<bool>,
    2 this_device: Option<bool>,
});
typed!(
    fields
    /// [`Router`], as a reply.
    RouterReply {
        2 error: Option<String>,
        3 everywhere: bool,
        4 external: Option<String>,
        5 named: Vec<String>,
        6 network: Network,
        7 on: bool,
        8 protocol: Option<Cow<'static, str>>,
        9 seconds_left: Option<u64>,
        10 this_device: bool,
    }
);
asks!(ROUTER_NOW: 180 "router" RouterArgs -> RouterReply, reads unless on);

typed!(fields BluetoothArgs {
    1 mode: Option<String>,
});
typed!(
    fields
    /// [`BluetoothShown`], as a reply.
    BluetoothReply {
        2 available: Option<bool>,
        3 channels_in: u64,
        4 error: Option<String>,
        5 mode: Cow<'static, str>,
        6 on: bool,
        7 psm: Option<u64>,
        8 radio: Option<String>,
        9 recognized: u64,
        10 seen: u64,
        11 why_not: Option<String>,
        12 windows: u64,
        13 too_old: Option<bool>,
    }
);
asks!(BLUETOOTH_NOW: 181 "bluetooth" BluetoothArgs -> BluetoothReply, reads unless mode);

typed!(fields NetworkArgs {
    1 mine: Option<bool>,
    2 name: Option<String>,
});
typed!(
    fields
    /// [`Network`], as a reply.
    NetworkReply {
        2 answered: Option<bool>,
        3 ask: bool,
        4 known: bool,
        5 mine: bool,
        6 name: Option<String>,
        7 router: Option<String>,
        8 routers: bool,
    }
);
asks!(NETWORK_NOW: 182 "network" NetworkArgs -> NetworkReply, reads unless mine);

typed!(fields HostArgs {
    1 addresses: Option<Vec<String>>,
});
typed!(fields HostReply {
    2 hosts: Vec<Host>,
    3 warnings: Vec<String>,
});
asks!(HOST_ON: 183 "host" HostArgs -> HostReply, writes);
typed!(fields HostOffArgs {});
typed!(
    fields
    /// The hosts the recovery sheet names.
    HostsReply {
        2 hosts: Vec<Host>,
    }
);
asks!(HOST_OFF: 184 "host-off" HostOffArgs -> HostsReply, writes);

typed!(fields PeerAddArgs {
    1 addr: Option<String>,
});
typed!(fields PeerAddReply {
    2 addr: String,
});
asks!(PEER_ADD: 185 "peer-add" PeerAddArgs -> PeerAddReply, writes);
typed!(fields PeerRemoveArgs {
    1 addr: Option<String>,
});
asks!(PEER_REMOVE: 186 "peer-remove" PeerRemoveArgs -> Done, writes);

typed!(fields MessagesArgs {
    1 who: Option<Reference>,
    2 group: Option<Reference>,
    3 before: Option<Reference>,
    4 limit: Option<u64>,
});
typed!(fields MessagesReply {
    2 group: Option<[u8; 32]>,
    3 messages: Vec<Message>,
    4 name: Option<String>,
    5 more: bool,
    6 next: Option<[u8; 16]>,
});
asks!(MESSAGES: 34 "messages" MessagesArgs -> MessagesReply, reads, before messages by id);

typed!(fields CallStartArgs {
    1 who: Option<Reference>,
    2 group: Option<Reference>,
    /// Each 32 bytes; another length is refused by the handler, as it was.
    3 formats: Option<Vec<bytes::Bytes>>,
    4 format_names: Option<Vec<String>>,
    5 ring: Option<Vec<Reference>>,
});
asks!(CALL_START: 101 "call-start" CallStartArgs -> Done, writes);
typed!(fields CallAnswerArgs {
    1 formats: Option<Vec<bytes::Bytes>>,
    2 format_names: Option<Vec<String>>,
    3 reach: Option<bool>,
    4 join: Option<bool>,
});
asks!(CALL_ANSWER: 102 "call-answer" CallAnswerArgs -> Done, writes);
typed!(fields CallEndArgs {});
asks!(CALL_END: 103 "call-end" CallEndArgs -> Done, writes);

typed!(fields CallArgs {});
typed!(fields CallReply {
    2 call: Option<Call>,
    3 ended: Option<CallEnded>,
});
asks!(CALL_NOW: 100 "call" CallArgs -> CallReply, reads);

typed!(fields FilesArgs {
    1 path: Option<String>,
    2 after: Option<u64>,
    3 limit: Option<u64>,
});
typed!(fields FilesReply {
    2 files: Vec<File>,
    3 path: String,
    4 place: Place,
    5 more: bool,
    6 next: Option<u64>,
});
asks!(FILES: 120 "files" FilesArgs -> FilesReply, reads, after files);

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
    WATCH,
    req!(4 "stop" () -> ()),
    req!(5 "reload" () -> ()),
    CONDITIONS_NOW,
    NETWORK_CHANGED,
    req!(8 "setup-begin" () -> (2 "ask" [U], 3 "words" [T])),
    req!(9 "setup-finish" (1 "name" T, 2 "answers" [T], 3 "device" T) -> (
        2 "device" T, 3 "name" T)),
    ME,
    paged!(after 11 "devices" (1 "after" U, 2 "limit" U) -> (
        2 "devices" [DEVICE], 3 "more" BOOL, 4 "next" U)),
    DEVICE_RENAME,
    req!(13 "remove-device" (1 "who" REF, 2 "lost" BOOL, 3 "words" T) -> (
        2 "dropped" U, 3 "name" T)),
    PAIR_SHOW,
    PAIR_STATUS,
    PAIR_TYPE,
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
    MESSAGES,
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
    INVITE,
    ACCEPT,
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
    GROUP_CREATE,
    GROUP_JOIN,
    GROUP_DECLINE,
    GROUP_LEAVE,
    GROUP_REACH_SET,
    GROUP_ADD,
    GROUP_REMOVE,
    paged!(after 78 "group-members" (1 "group" REF, 2 "after" U, 3 "limit" U) -> (
        2 "group" B, 3 "members" [MEMBER], 4 "name" T, 5 "more" BOOL, 6 "next" U)),
    GROUP_SET,
    GROUP_MEMBER,
    req!(81 "group-connect" (1 "group" REF, 2 "who" REF, 3 "note" T) -> (2 "asked" BOOL)),
    GROUP_ROLE,
    req!(83 "group-post-again" (1 "group" REF) -> (2 "posted" U)),
    req!(84 "group-moved-seen" (1 "group" REF) -> ()),
    req!(85 "group-confirm-move" (1 "group" REF, 2 "moves" [B], 3 "to" [B]) -> (2 "kept" U)),
    req!(86 "group-leaving" (1 "group" REF) -> (
        2 "admins" [T], 3 "choose_admin" BOOL, 4 "group" B, 5 "name" T,
        6 "relayed_for" [RELAYED_FOR])),
    GROUP_REJOIN,
    // ---- Calls and the clipboard: 100 to 119 ----
    CALL_NOW,
    CALL_START,
    CALL_ANSWER,
    CALL_END,
    CALL_MEDIA,
    CLIP_COPY,
    CLIP,
    // ---- The one folder: 120 to 149 ----
    FILES,
    MKDIR,
    MOVE,
    REMOVE,
    COPY,
    PUT,
    SAVE,
    WRITE,
    SHARE,
    MOUNT,
    UNMOUNT,
    FLUSH,
    paged!(after 132 "conflicts" (1 "after" U, 2 "limit" U) -> (
        2 "conflicts" [CONFLICT], 3 "more" BOOL, 4 "next" U)),
    paged!(after 133 "history" (1 "path" T, 2 "after" U, 3 "limit" U) -> (
        2 "path" T, 3 "versions" [VERSION], 4 "more" BOOL, 5 "next" U)),
    RESTORE,
    PIN,
    UNPIN,
    RETENTION,
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
    req!(175 "recover-stop-waiting" (1 "all" BOOL, 2 "who" REF) -> (
        2 "not_heard" [T], 3 "stopped" [T])),
    // ---- Networks, hosts and peers: 180 to 199 ----
    ROUTER_NOW,
    BLUETOOTH_NOW,
    NETWORK_NOW,
    HOST_ON,
    HOST_OFF,
    PEER_ADD,
    PEER_REMOVE,
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
    WAKE,
    paged!(after 227 "deleted" (1 "path" T, 2 "after" U, 3 "limit" U, 4 "hidden" BOOL) -> (
        2 "files" [DELETED_FILE], 3 "path" T, 4 "more" BOOL, 5 "next" U)),
    req!(228 "undelete" (1 "path" T, 2 "id" REF) -> (2 "id" B, 3 "path" T)),
];

// ---- What the service's program says without starting ----

typed!(DATA_HELD "data held" DataHeld {
    1 bytes: u64,
    2 identity: bool,
    3 local: u64,
    4 local_bytes: u64,
    5 objects: u64,
    6 other: bool,
    7 spaces: u64,
    8 unsaved: u64,
    9 unsaved_bytes: u64,
});

typed!(
    fields
    /// `--store`: which data is there (`empty`, `current`, `other` or
    /// `unreadable`) and what it holds; of another version's, who wrote it
    /// and the refusal in words.
    StoreReply {
        2 holds: DataHeld,
        3 refusal: Option<String>,
        4 store: Cow<'static, str>,
        5 written_by: Option<Cow<'static, str>>,
    }
);

/// What the service's program says when asked, typed: its row, `ROW`, for
/// [`PROGRAM`], from its reply's declaration. The program writes it and
/// exits; nothing answers it on the socket.
macro_rules! program {
    ($row:ident: $n:literal $name:literal -> $reply:ident) => {
        #[doc = concat!("The row of `", $name, "`, typed.")]
        pub const $row: Request = Request {
            n: $n,
            name: $name,
            args: &[],
            reply: <$reply as Fields>::FIELDS,
            page: Page::Whole,
            gone: false,
            answer: None,
        };
    };
}

program!(PROGRAM_STORE: 1 "--store" -> StoreReply);
program!(PROGRAM_CLEAR: 2 "--clear" -> Done);

/// What the service's program says without starting (`apps.md`, The local
/// interface), by the option that asks it: one record on its standard
/// output, numbered as a reply is, with nothing after it. `--store` says
/// which data is there and what it holds, counted without reading any of
/// it; `--clear` removes data this version cannot read, or fails, saying
/// why.
pub static PROGRAM: &[Request] = &[PROGRAM_STORE, PROGRAM_CLEAR];

typed!(
    fields
    /// What an error's reply says besides why, in key 1, numbered as a
    /// reply's fields are (`apps.md`, Errors): of error 4 to a paged
    /// request, which item was too large for a message on its own, by its
    /// place in the answer as `after` counts (`at`), and by its `id` where
    /// it has one, so that a client can ask for what comes after it.
    ErrorMore {
        2 at: Option<u64>,
        3 id: Option<bytes::Bytes>,
    }
);

/// [`ErrorMore`]'s fields, as the tables give them.
pub static ERROR_FIELDS: &[Field] = <ErrorMore as Fields>::FIELDS;

/// A message of a stream, typed: its row, `ROW`, for [`EVENTS`] or
/// [`FRAMES`], from its typed fields.
macro_rules! streams {
    ($row:ident: $n:literal $name:literal $fields:ident) => {
        #[doc = concat!("The row of `", $name, "`, typed.")]
        pub const $row: Request = Request {
            n: $n,
            name: $name,
            args: <$fields as Fields>::FIELDS,
            reply: &[],
            page: Page::Whole,
            gone: false,
            answer: None,
        };

        impl super::typed::Streamed for $fields {
            const KIND: &'static Request = &$row;
        }
    };
}

// ---- The events of `watch` ----

typed!(
    fields
    /// Something changed, and this is the count of changes.
    Changed {
        1 seq: u64,
    }
);
streams!(EVENT_CHANGED: 1 "changed" Changed);

/// The events of a `watch` connection: key 0 says which.
pub static EVENTS: &[Request] = &[EVENT_CHANGED];

// ---- The frames of `call-media` ----

typed!(
    fields
    /// Audio of the call, in the codec its client chose; from the service,
    /// in a group, the voice it is.
    AudioFrame {
        1 audio: bytes::Bytes,
        3 from: Option<[u8; 8]>,
    }
);
streams!(FRAME_AUDIO: 1 "audio" AudioFrame);
typed!(
    fields
    /// A frame of another format the call took.
    OtherFrame {
        1 frame: bytes::Bytes,
        2 format: [u8; 32],
        3 from: Option<[u8; 8]>,
        4 size: Option<u64>,
    }
);
streams!(FRAME_OTHER: 2 "frame" OtherFrame);
typed!(
    fields
    /// The shape of a window's viewport (`basics/video.md`): from the
    /// window, its own; from the service, a receiver's, `from` in a group.
    ViewportFrame {
        1 width: u64,
        2 height: u64,
        3 from: Option<[u8; 8]>,
    }
);
streams!(FRAME_VIEWPORT: 3 "viewport" ViewportFrame);
typed!(
    fields
    /// From the window, in a group: the level it asks of the sender `from`
    /// (`basics/video.md#groups`).
    LevelFrame {
        1 level: u64,
        3 from: Option<[u8; 8]>,
    }
);
streams!(FRAME_LEVEL: 4 "level" LevelFrame);
typed!(
    fields
    /// To the window, in a group: whether small and large pictures of its
    /// own are asked for.
    AskedFrame {
        1 small: bool,
        2 large: bool,
    }
);
streams!(FRAME_ASKED: 5 "asked" AskedFrame);
typed!(
    fields
    /// A key picture of the size `size`: from the window, asked of the
    /// sender `from`; to it, asked of its own.
    KeyFrame {
        3 from: Option<[u8; 8]>,
        4 size: u64,
    }
);
streams!(FRAME_KEY: 6 "key" KeyFrame);
typed!(
    fields
    /// From the window: whether this person's camera is on
    /// (`basics/video.md#cameras`).
    CameraFrame {
        1 camera: bool,
    }
);
streams!(FRAME_CAMERA: 7 "camera" CameraFrame);

/// The frames of a `call-media` connection, both ways: key 0 says which.
/// `from` is the voice a frame of a group call is, from the service, or
/// the sender a window's level or key picture is asked of.
pub static FRAMES: &[Request] = &[
    FRAME_AUDIO,
    FRAME_OTHER,
    FRAME_VIEWPORT,
    FRAME_LEVEL,
    FRAME_ASKED,
    FRAME_KEY,
    FRAME_CAMERA,
];
