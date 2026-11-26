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

use super::typed::{Fields, Kind, Reference, Scalar};

/// What a field holds.
#[derive(Debug)]
pub enum Ty {
    /// Text.
    Text,
    /// Bytes: a key, an id or a hash. Typed, they are bytes; by name, the
    /// service holds them as hex.
    Bytes,
    /// Bytes of exactly this length (an id, a key, a hash): `bytes` in the
    /// tables, and read back only at that length.
    BytesOf(usize),
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
    /// Whether it is read back as an `Option`, its absence no error: of a
    /// typed record's field, where the tests run, to hold the fields added
    /// since the last release to that (`api::tests`).
    #[cfg(test)]
    pub optional: bool,
    /// The values a text field holds, where they are a closed set its
    /// declaration names (`where "a" | "b"`): for generators, in the export,
    /// and where the tests run, a reply holding another is this build's
    /// mistake. On the wire it is text all the same.
    #[cfg(any(test, debug_assertions))]
    pub known: &'static [&'static str],
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
#[derive(Debug, Clone, Copy)]
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
    /// Whether the connection carries a stream after it (`watch`,
    /// `call-media`), answered by the connection itself rather than by a
    /// reply's handler.
    pub stream: bool,
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
        $crate::typed!(@munch [$(#[$m])* $name] [$stat $title] [] [] [] [] [] $($body)*);
    };
    (fields $(#[$m:meta])* $name:ident { $($body:tt)* }) => {
        $crate::typed!(@munch [$(#[$m])* $name] [] [] [] [] [] [] $($body)*);
    };
    // A number no longer used.
    (@munch $h:tt $st:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $n:literal gone $f:ident : $t:ty $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h $st [$($s)*] [$($r)*] [$($o)*] [$($l)*]
            [$($a)* ($n $f (gone $t))] $($($rest)*)?);
    };
    // A field sent only when it is `Some`, of a record that holds itself
    // (or one that holds it): its row names the record, `as {ROW}` or a
    // list of them `as [ROW]`, since the row cannot be had from the type.
    (@munch $h:tt $st:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $(#[$fm:meta])* $n:literal $f:ident : Option<$t:ty> as $row:tt $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h $st
            [$($s)* ($(#[$fm])* $f : Option<$t>)] [$($r)*] [$($o)* $f]
            [$($l)* ($n $f)] [$($a)* ($n $f (as $row ?))] $($($rest)*)?);
    };
    // A field always sent, of a record that holds itself.
    (@munch $h:tt $st:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $(#[$fm:meta])* $n:literal $f:ident : $t:ty as $row:tt $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h $st
            [$($s)* ($(#[$fm])* $f : $t)] [$($r)* ($f : $t)] [$($o)*]
            [$($l)* ($n $f)] [$($a)* ($n $f (as $row))] $($($rest)*)?);
    };
    // A field of text sent only when it is `Some`, whose values are a
    // closed set: `where "a" | "b"`.
    (@munch $h:tt $st:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $(#[$fm:meta])* $n:literal $f:ident : Option<$t:ty> where $($k:literal)|+
        $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h $st
            [$($s)* ($(#[$fm])* $f : Option<$t>)] [$($r)*] [$($o)* $f]
            [$($l)* ($n $f)] [$($a)* ($n $f (Option<$t>) [$($k),+])] $($($rest)*)?);
    };
    // A field of text always sent, whose values are a closed set.
    (@munch $h:tt $st:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $(#[$fm:meta])* $n:literal $f:ident : $t:ty where $($k:literal)|+ $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h $st
            [$($s)* ($(#[$fm])* $f : $t)] [$($r)* ($f : $t)] [$($o)*]
            [$($l)* ($n $f)] [$($a)* ($n $f ($t) [$($k),+])] $($($rest)*)?);
    };
    // A field sent only when it is `Some`.
    (@munch $h:tt $st:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $(#[$fm:meta])* $n:literal $f:ident : Option<$t:ty> $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h $st
            [$($s)* ($(#[$fm])* $f : Option<$t>)] [$($r)*] [$($o)* $f]
            [$($l)* ($n $f)] [$($a)* ($n $f (Option<$t>))] $($($rest)*)?);
    };
    // A field always sent.
    (@munch $h:tt $st:tt [$($s:tt)*] [$($r:tt)*] [$($o:tt)*] [$($l:tt)*] [$($a:tt)*]
        $(#[$fm:meta])* $n:literal $f:ident : $t:ty $(, $($rest:tt)*)?
    ) => {
        $crate::typed!(@munch $h $st
            [$($s)* ($(#[$fm])* $f : $t)] [$($r)* ($f : $t)] [$($o)*]
            [$($l)* ($n $f)] [$($a)* ($n $f ($t))] $($($rest)*)?);
    };
    (@row ($n:literal $f:ident (as {$row:ident} $($opt:tt)?))) => {
        $crate::table::Field {
            n: $n,
            name: $crate::typed::field_name(stringify!($f)),
            ty: $crate::table::Ty::Rec(&$row),
            #[cfg(test)]
            optional: $crate::typed!(@opt $($opt)?),
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    (@row ($n:literal $f:ident (as [$row:ident] $($opt:tt)?))) => {
        $crate::table::Field {
            n: $n,
            name: $crate::typed::field_name(stringify!($f)),
            ty: $crate::table::Ty::Recs(&$row),
            #[cfg(test)]
            optional: $crate::typed!(@opt $($opt)?),
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    (@opt ?) => { true };
    (@opt) => { false };
    (@row ($n:literal $f:ident (gone $t:ty))) => {
        $crate::table::Field {
            n: $n,
            name: $crate::typed::field_name(stringify!($f)),
            ty: $crate::table::Ty::Gone(&<$t as $crate::typed::Wire>::TY),
            #[cfg(test)]
            optional: true,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    (@row ($n:literal $f:ident ($t:ty) [$($k:literal),+])) => {
        $crate::table::Field {
            n: $n,
            name: $crate::typed::field_name(stringify!($f)),
            ty: <$t as $crate::typed::Wire>::TY,
            #[cfg(test)]
            optional: <$t as $crate::typed::Wire>::OPTIONAL,
            #[cfg(any(test, debug_assertions))]
            known: &[$($k),+],
        }
    };
    (@row ($n:literal $f:ident ($t:ty))) => {
        $crate::table::Field {
            n: $n,
            name: $crate::typed::field_name(stringify!($f)),
            ty: <$t as $crate::typed::Wire>::TY,
            #[cfg(test)]
            optional: <$t as $crate::typed::Wire>::OPTIONAL,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    // A record held in replies: its row, `$stat`, written out in the
    // static itself, so that a record that holds itself can name its own
    // row; and its place as a field or a list's item.
    (@munch [$(#[$m:meta])* $name:ident] [$stat:ident $title:literal]
        $s:tt $r:tt $o:tt $l:tt [$($a:tt)*]
    ) => {
        // read where it is held, once (`typed::record_read`)
        $crate::typed!(@body [$(#[$m])* $name] ($stat.fields) [inline] $s $r $o $l);

        #[doc = concat!("The *", $title, "* record's row in the tables.")]
        pub static $stat: $crate::table::Rec = $crate::table::Rec {
            name: $title,
            // an item of its own, which every crate that names a row
            // names, rather than a copy of it in each
            fields: {
                static FIELDS: [$crate::table::Field; $crate::typed!(@count $($a)*)] =
                    [ $( $crate::typed!(@row $a) ),* ];
                &FIELDS
            },
        };

        impl $crate::typed::Wire for $name {
            const TY: $crate::table::Ty = $crate::table::Ty::Rec(&$stat);
            const LIST: $crate::table::Ty = $crate::table::Ty::Recs(&$stat);
            #[inline]
            fn encode_into(&self, out: &mut Vec<u8>) {
                $crate::typed::record_into(self, out)
            }
            #[inline]
            fn encoded_len(&self) -> usize {
                $crate::typed::record_len(self)
            }
            #[inline]
            fn measured(&self) -> (usize, bool) {
                $crate::typed::record_measured(self)
            }
            #[inline]
            fn check(&self, at: &$crate::typed::At) -> Result<(), String> {
                $crate::typed::record_check(self, at)
            }
            #[inline]
            fn take(
                v: $crate::__private::Value,
                at: &$crate::typed::At,
            ) -> Result<Self, String> {
                $crate::typed::record_take(v, at)
            }
            #[inline]
            fn read(
                c: &mut $crate::__private::Cursor<'_>,
                depth: usize,
                at: &$crate::typed::At,
            ) -> Result<Self, $crate::typed::Bad> {
                $crate::typed::record_read(c, depth, at)
            }
        }
    };
    // The arguments or the reply of a request: its rows in a static of
    // their own, so that every crate that names them names the one.
    (@munch [$(#[$m:meta])* $name:ident] [] $s:tt $r:tt $o:tt $l:tt [$($a:tt)*]) => {
        // read from a whole message, once
        $crate::typed!(@body [$(#[$m])* $name] ({
            static FIELDS: [$crate::table::Field; $crate::typed!(@count $($a)*)] =
                [ $( $crate::typed!(@row $a) ),* ];
            &FIELDS
        }) [inline] $s $r $o $l);
    };
    // A record that always has none of its fields is had with `new()`;
    // one that has some, with `new!`, which names them.
    (@new $name:ident []) => {
        impl $name {
            /// It, with none of its fields: all are sent only when they
            /// are `Some`.
            #[allow(clippy::new_without_default)]
            #[inline]
            pub fn new() -> Self {
                Self::__new()
            }
        }
    };
    (@new $name:ident [$($rf:ident)+]) => {};
    // How many rows: one for each field, gone or not.
    (@count $($a:tt)*) => { <[()]>::len(&[$($crate::typed!(@unit $a)),*]) };
    (@unit $a:tt) => { () };
    (@body [$(#[$m:meta])* $name:ident] ($fields:expr) [$inl:meta]
        [$(($(#[$fm:meta])* $sf:ident : $st:ty))*]
        [$(($rf:ident : $rt:ty))*]
        [$($of:ident)*]
        [$(($ln:literal $lf:ident))*]
    ) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name {
            $( $(#[$fm])* pub $sf: $st, )*
        }

        impl $name {
            /// It, with the fields it always has, in order; the others
            /// absent. Made by [`new!`](crate::new), which names each.
            #[doc(hidden)]
            #[allow(clippy::too_many_arguments)]
            pub fn __new($($rf: $rt),*) -> Self {
                $name { $($rf,)* $($of: None,)* }
            }
        }

        $crate::typed!(@new $name [$($rf)*]);

        impl $crate::typed::Fields for $name {
            const FIELDS: &'static [$crate::table::Field] = $fields;
            const REQUIRED: &'static [&'static str] =
                &[$($crate::typed::field_name(stringify!($rf))),*];

            #[inline]

            fn each<V: $crate::typed::Visit>(&self, v: &mut V) {
                $( v.field(
                    const {
                        &<$name as $crate::typed::Fields>::FIELDS[
                            $crate::typed::index(
                                <$name as $crate::typed::Fields>::FIELDS,
                                $ln,
                            )
                        ]
                    },
                    &self.$lf,
                ); )*
                let _ = v;
            }

            #[inline]
            #[allow(unused_mut, unused_variables)]
            fn take_fields(
                mut r: $crate::__private::Record,
                at: &$crate::typed::At,
            ) -> Result<Self, String> {
                Ok($name { $(
                    $lf: $crate::typed::take_field(
                        &mut r,
                        const {
                            &<$name as $crate::typed::Fields>::FIELDS[
                                $crate::typed::index(
                                    <$name as $crate::typed::Fields>::FIELDS,
                                    $ln,
                                )
                            ]
                        },
                        at,
                    )?,
                )* })
            }

            // once for each record: a record held in others in the one
            // place it is read from wherever it is held, the arguments or
            // the reply of a request where a whole message is read
            #[$inl]
            #[allow(unused_variables)]
            fn read_fields(
                w: &mut $crate::typed::Walk,
                at: &$crate::typed::At,
            ) -> Result<Self, $crate::typed::Bad> {
                // in the order of their numbers, as they come
                Ok($name { $(
                    $lf: $crate::typed::read_field(
                        w,
                        const {
                            &<$name as $crate::typed::Fields>::FIELDS[
                                $crate::typed::index(
                                    <$name as $crate::typed::Fields>::FIELDS,
                                    $ln,
                                )
                            ]
                        },
                        at,
                    )?,
                )* })
            }
        }

        const _: () = $crate::typed::ascending(
            <$name as $crate::typed::Fields>::FIELDS,
        );
    };
}

/// A typed record, with the fields it always has given by name:
/// `new!(Message { attachments, edited: false, id, mine: true, reactions,
/// text })`, each once, in the order of their numbers (as the declaration
/// lists them), the others absent; a field given by its own name may be
/// written alone. A name missing, one too many, or one out of its place
/// does not compile, so two fields of one type cannot be given each
/// other's values; it costs nothing beyond the record itself. A field
/// sent only when it is `Some` is set after, by name:
/// `Message { from: Some(f), ..new!(Message { .. }) }`. A record that
/// always has none of its fields is also `Name::new()`.
///
/// ```
/// use cardinal_interface::{new, ViewportFrame};
/// let (width, height) = (1280, 720);
/// let v = new!(ViewportFrame { width, height });
/// let from = ViewportFrame { from: Some([1; 8]), ..new!(ViewportFrame { width: 3, height: 4 }) };
/// assert_eq!((v.width, v.height, from.from), (1280, 720, Some([1; 8])));
/// ```
///
/// Two fields of one type in each other's places do not compile:
///
/// ```compile_fail
/// use cardinal_interface::{new, ViewportFrame};
/// let v = new!(ViewportFrame { height: 720, width: 1280 });
/// ```
///
/// Nor does one missing, or one it does not always have:
///
/// ```compile_fail
/// use cardinal_interface::{new, ViewportFrame};
/// let v = new!(ViewportFrame { width: 1280 });
/// ```
///
/// ```compile_fail
/// use cardinal_interface::{new, ViewportFrame};
/// let v = new!(ViewportFrame { width: 1280, height: 720, from: None });
/// ```
#[macro_export]
macro_rules! new {
    (@value $f:ident $v:expr) => { $v };
    (@value $f:ident) => { $f };
    ($t:path { $($f:ident $(: $v:expr)?),* $(,)? }) => {{
        const _: () = $crate::typed::named(
            <$t as $crate::typed::Fields>::REQUIRED,
            &[$(stringify!($f)),*],
        );
        <$t>::__new($($crate::new!(@value $f $($v)?)),*)
    }};
}

/// A typed request: its row, `ROW`, for [`REQUESTS`], from its typed
/// arguments and reply; how it is answered; and how it pages.
///
/// `asks!(ROW: n "name" Args -> Reply, how)`, where `how` is
///
/// - `reads`: it changes nothing, so where the tests run the service
///   answers it by name too and fails it if the two differ;
/// - `reads unless field`: the same while `field` is not given (`reads
///   unless a or b`: while neither is);
/// - `writes`: answered once; same-bytes cases written by hand cover it;
/// - `stream`: answered by the connection itself, which then carries a
///   stream (`watch`, `call-media`).
///
/// Nothing here knows how a request is answered: [`each_request!`] lists
/// every request with whether it is a stream, and the service makes its
/// answering from that list, so that a request it has no handler for does
/// not compile there (`cardinald`'s `control::typed`). A paged
/// one says how after `how`: `after list` (by position; `after list by
/// id` where an item too large names its `id`), `after a, b, c` (by
/// position through several lists in turn, each a `Vec` or an
/// `Option<Vec>`, as `groups` is), or `before list by id` (back from the
/// newest, `next` the `id` of the oldest given);
/// its arguments then have `after` or `before`, and `limit`, and its
/// reply the list, `more` and `next`, which the page is cut by.
macro_rules! asks {
    ($row:ident: $n:literal $name:literal $args:ident -> $reply:ident,
        $how:ident $(unless $unless:ident $(or $or:ident)*)? $(, $($page:tt)*)?) => {
        #[doc = concat!("The row of `", $name, "`, typed.")]
        pub static $row: Request = Request {
            n: $n,
            name: $name,
            args: <$args as Fields>::FIELDS,
            reply: <$reply as Fields>::FIELDS,
            page: asks!(@page $($($page)*)?),
            gone: false,
            stream: asks!(@stream $how),
        };

        impl super::typed::Ask for $args {
            const REQUEST: &'static Request = &$row;
            type Reply = $reply;
            const STREAM: bool = asks!(@stream $how);
            const LISTS: &'static [(&'static str, Option<&'static str>)] =
                asks!(@lists $($($page)*)?);
            asks!(@reads $how $($unless $($or)*)?);
            asks!(@paging $args $reply $($($page)*)?);
        }
    };
    (@stream stream) => { true };
    (@stream $how:ident) => { false };
    // The lists a paged reply is paged through, in turn, each with the
    // field of its records that names one too large.
    (@lists) => { &[] };
    (@lists after $list:ident $(by $id:ident)? precut) => {
        &[(stringify!($list), asks!(@by $($id)?))]
    };
    (@lists after $($list:ident $(by $id:ident)?),+) => {
        &[$((stringify!($list), asks!(@by $($id)?))),+]
    };
    (@lists before $list:ident by $id:ident) => { &[(stringify!($list), Some(stringify!($id)))] };
    (@by) => { None };
    (@by $id:ident) => { Some(stringify!($id)) };
    (@reads reads) => {
        const READS: bool = true;
        #[inline]
        fn reads(&self) -> bool {
            true
        }
    };
    (@reads reads $unless:ident $($or:ident)*) => {
        const READS: bool = true;
        const UNLESS: &'static [&'static str] = &[stringify!($unless) $(, stringify!($or))*];
        #[inline]
        fn reads(&self) -> bool {
            self.$unless.is_none() $(&& self.$or.is_none())*
        }
    };
    (@reads writes) => {};
    (@reads stream) => {};
    (@page) => { Page::Whole };
    (@page after $list:ident $($rest:tt)*) => { Page::After };
    (@page before $list:ident $($rest:tt)*) => { Page::Before { list: stringify!($list) } };
    (@paging $args:ident $reply:ident) => {
        type Answered = $reply;
        #[inline]
        fn reply_bytes(&self, reply: $reply) -> Vec<u8> {
            super::typed::reply_message(Self::REQUEST.name, &reply)
        }
    };
    (@id) => { |_| None };
    (@id $id:ident) => { |x| Some(&x.$id[..]) };
    // An item of a list paged in turn, by its place in that list, named
    // by its id where it has one.
    (@item_id $list:expr, $i:expr) => { None };
    (@item_id $list:expr, $i:expr, $id:ident) => {
        $list.item($i).map(|x| &x.$id[..])
    };
    // A reply its handler cut itself, from where the page begins
    // (`Precut`): the old pager's `_page_from` and `_page_total`.
    (@paging $args:ident $reply:ident after $list:ident $(by $id:ident)? precut) => {
        type Answered = super::typed::Precut<$reply>;
        #[inline]
        fn reply_bytes(&self, cut: super::typed::Precut<$reply>) -> Vec<u8> {
            let super::typed::Precut { mut reply, from, total } = cut;
            const SKIP: [u64; 3] = super::typed::paged_numbers(
                <$reply as Fields>::FIELDS,
                stringify!($list),
            );
            let base = super::typed::record_len_except(&reply, &SKIP);
            match super::typed::page_precut(
                Self::REQUEST,
                stringify!($list),
                &mut reply.$list,
                base,
                self.after,
                self.limit,
                from,
                total,
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
        asks!(@pages $args $reply $list);
    };
    (@paging $args:ident $reply:ident after $list:ident $(by $id:ident)?) => {
        type Answered = $reply;
        #[inline]
        fn reply_bytes(&self, mut reply: $reply) -> Vec<u8> {
            // beside the reply's other fields: without the list, `more`, `next`
            const SKIP: [u64; 3] = super::typed::paged_numbers(
                <$reply as Fields>::FIELDS,
                stringify!($list),
            );
            let base = super::typed::record_len_except(&reply, &SKIP);
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
        asks!(@pages $args $reply $list);
    };
    // How a client asks for one list page after page.
    (@pages $args:ident $reply:ident $list:ident) => {
        const ONE_PAGE: &'static [&'static str] = &["after", "limit"];
        #[inline]
        fn one_page(&self) -> bool {
            self.after.is_some() || self.limit.is_some()
        }
        #[inline]
        fn next_page(&self, had: &$reply) -> Option<Self> {
            let next = had.next.filter(|_| had.more)?;
            Some($args {
                after: Some(next),
                ..self.clone()
            })
        }
        #[inline]
        fn join(all: &mut $reply, page: $reply) -> bool {
            let grew = !page.$list.is_empty();
            all.$list.extend(page.$list);
            (all.more, all.next) = (page.more, page.next);
            grew
        }
        #[inline]
        fn whole(all: &mut $reply) {
            (all.more, all.next) = (false, None);
        }
        #[inline]
        fn past(&self, failed: &super::typed::Failed) -> Option<Self> {
            Some($args {
                after: Some(super::typed::past_after(failed, self.after)?),
                ..self.clone()
            })
        }
    };
    (@paging $args:ident $reply:ident
        after $first:ident $(by $fid:ident)?, $($list:ident $(by $id:ident)?),+) => {
        type Answered = $reply;
        #[inline]
        fn reply_bytes(&self, mut reply: $reply) -> Vec<u8> {
            use super::typed::PagedList;
            // beside the reply's other fields: without its lists, `more`, `next`
            const LISTS: &[u64] = &[
                super::typed::number(<$reply as Fields>::FIELDS, stringify!($first)),
                $(super::typed::number(<$reply as Fields>::FIELDS, stringify!($list)),)+
            ];
            const MORE_NEXT: [u64; 2] = [
                super::typed::number(<$reply as Fields>::FIELDS, "more"),
                super::typed::number(<$reply as Fields>::FIELDS, "next"),
            ];
            let skip: Vec<u64> = LISTS.iter().chain(&MORE_NEXT).copied().collect();
            let base = super::typed::record_len_except(&reply, &skip);
            let mut items = Vec::new();
            reply.$first.lens(stringify!($first), &mut items);
            $(reply.$list.lens(stringify!($list), &mut items);)+
            match super::typed::cut_after(Self::REQUEST, &items, base, self.after, self.limit) {
                Ok((start, taken, cut)) => {
                    let mut at = 0;
                    reply.$first.keep(&mut at, start, taken);
                    $(reply.$list.keep(&mut at, start, taken);)+
                    reply.more = cut.more;
                    reply.next = cut.next;
                    super::typed::reply_message(Self::REQUEST.name, &reply)
                }
                Err(super::typed::TooLarge { list, at, n }) => {
                    // its id, where its list's records have one
                    let mut id: Option<&[u8]> = None;
                    let mut from = 0;
                    {
                        let count = reply.$first.count();
                        if (from..from + count).contains(&at) {
                            id = asks!(@item_id reply.$first, at - from $(, $fid)?);
                        }
                        from += count;
                    }
                    $({
                        let count = reply.$list.count();
                        if (from..from + count).contains(&at) {
                            id = asks!(@item_id reply.$list, at - from $(, $id)?);
                        }
                        from += count;
                    })+
                    let _ = from;
                    super::typed::too_large(Self::REQUEST, list, at, n, id).0
                }
            }
        }
        const ONE_PAGE: &'static [&'static str] = &["after", "limit"];
        #[inline]
        fn one_page(&self) -> bool {
            self.after.is_some() || self.limit.is_some()
        }
        #[inline]
        fn next_page(&self, had: &$reply) -> Option<Self> {
            let next = had.next.filter(|_| had.more)?;
            Some($args {
                after: Some(next),
                ..self.clone()
            })
        }
        #[inline]
        fn join(all: &mut $reply, page: $reply) -> bool {
            use super::typed::PagedList;
            let mut grew = all.$first.extend_with(page.$first);
            $(grew |= all.$list.extend_with(page.$list);)+
            (all.more, all.next) = (page.more, page.next);
            grew
        }
        #[inline]
        fn whole(all: &mut $reply) {
            (all.more, all.next) = (false, None);
        }
        #[inline]
        fn past(&self, failed: &super::typed::Failed) -> Option<Self> {
            Some($args {
                after: Some(super::typed::past_after(failed, self.after)?),
                ..self.clone()
            })
        }
    };
    (@paging $args:ident $reply:ident before $list:ident by $id:ident) => {
        type Answered = $reply;
        #[inline]
        fn reply_bytes(&self, mut reply: $reply) -> Vec<u8> {
            const SKIP: [u64; 3] = super::typed::paged_numbers(
                <$reply as Fields>::FIELDS,
                stringify!($list),
            );
            let base = super::typed::record_len_except(&reply, &SKIP);
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
        const ONE_PAGE: &'static [&'static str] = &["before", "limit"];
        #[inline]
        fn one_page(&self) -> bool {
            self.before.is_some() || self.limit.is_some()
        }
        #[inline]
        fn next_page(&self, had: &$reply) -> Option<Self> {
            let next = had.next.filter(|_| had.more)?;
            Some($args {
                before: Some(super::typed::Reference::Id(next.to_vec())),
                ..self.clone()
            })
        }
        #[inline]
        fn join(all: &mut $reply, mut page: $reply) -> bool {
            let grew = !page.$list.is_empty();
            page.$list.append(&mut all.$list);
            all.$list = page.$list;
            (all.more, all.next) = (page.more, page.next);
            grew
        }
        #[inline]
        fn whole(all: &mut $reply) {
            (all.more, all.next) = (false, None);
        }
        #[inline]
        fn past(&self, failed: &super::typed::Failed) -> Option<Self> {
            Some($args {
                before: Some(super::typed::past_before(failed, &self.before)?),
                ..self.clone()
            })
        }
    };
}

macro_rules! f {
    ($n:literal $name:literal (gone $t:tt)) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Gone(&f!(0 "" $t).ty),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal T) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Text,
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal B) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Bytes,
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal U) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Uint,
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal I) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Int,
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal BOOL) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Bool,
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal REF) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Ref,
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal KIND) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Kind,
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal SCALAR) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Scalar,
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal [T]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Text),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal [B]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Bytes),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal [U]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Uint),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal [REF]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Ref),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal [SCALAR]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::Scalar),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal [[U]]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::List(&Ty::List(&Ty::Uint)),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal {$r:ident}) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Rec(&$r),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
    };
    ($n:literal $name:literal [$r:ident]) => {
        Field {
            n: $n,
            name: $name,
            ty: Ty::Recs(&$r),
            #[cfg(test)]
            optional: false,
            #[cfg(any(test, debug_assertions))]
            known: &[],
        }
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
            stream: false,
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

typed!(
    /// What a program asks the person, waiting for their answer.
    APP_QUESTION "app question" AppQuestion {
        /// `family`, `new-space` or `share`.
        1 asks: Cow<'static, str> where "family" | "new-space" | "share",
        2 id: u64,
        3 name: String,
        4 program: String,
        /// Of `share`: `reader` or `writer`.
        5 role: Option<Cow<'static, str>> where "reader" | "writer",
        6 what: String,
    }
);
typed!(
    /// An approval of the person's, made on one of their devices.
    APPROVAL "approval" ApprovalShown {
        1 change: bool,
        /// The family's title, or the start of its root in hex.
        2 covers: String,
        3 device: Option<String>,
        4 family: [u8; 32],
        5 id: [u8; 16],
        6 name: String,
        7 program: String,
        8 revoked: bool,
        9 this_device: bool,
    }
);
typed!(
    /// A space of an application offered to this person.
    APP_OFFER "app offer" AppOffer {
        1 application: Option<String>,
        2 from: String,
        3 name: String,
        4 sentence: Option<String>,
        5 space: [u8; 32],
    }
);

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
        4 mode: Cow<'static, str> where "off" | "open" | "always",
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
        10 state: Cow<'static, str> where "calling" | "ringing" | "live",
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
        2 how: Cow<'static, str> where "missed" | "answered_elsewhere" | "declined_elsewhere"
            | "declined" | "over" | "not_answered" | "they_declined" | "busy" | "cancelled",
        3 id: [u8; 16],
        4 name: String,
        5 who: [u8; 8],
        /// Added after v0.1.27: an `Option` for ever, though always sent.
        6 at: Option<u64>,
    }
);
typed!(
    /// What this device knows of its power and its network.
    CONDITIONS "conditions" ConditionsShown {
        1 helps: bool,
        2 metered: bool,
        /// Unknown where nothing says.
        3 plugged_in: Option<bool>,
    }
);
typed!(
    /// A file whose versions conflict.
    CONFLICT "conflict" Conflict {
        /// The copies that show each version, by path.
        1 copies: Vec<String>,
        2 delete_conflict: bool,
        3 path: String,
        4 versions: Vec<Version>,
    }
);
typed!(
    /// A contact of this person's.
    CONTACT "contact" Contact {
        1 category: String,
        2 connected: bool,
        /// The start of their identity.
        3 identity: [u8; 8],
        4 introductions: bool,
        5 met: Option<Met>,
        /// What this person calls them.
        6 name: String,
        7 nearby: bool,
        /// Whether that name is this person's own.
        8 own: bool,
        9 picture: Option<String>,
        /// What is said of them, recovered by guardians.
        10 recovered: Option<String>,
        11 refused: bool,
        12 relayed: bool,
        13 suggested: Option<String>,
        14 trusted: bool,
        15 recovered_seen: Option<u64>,
        16 recovered_new_guardians: Option<bool>,
        17 recovered_delay: Option<u64>,
        18 unreadable: Option<String>,
    }
);
typed!(
    /// What this person's reach node says in a relationship.
    CONTACT_REACH "contact reach" ContactReach {
        1 named: Vec<String>,
        2 said_no: bool,
        3 shared: bool,
        4 waiting: bool,
    }
);
typed!(
    /// A contact's conversation, as the list of them shows it.
    CONVERSATION "conversation" Conversation {
        1 connected: bool,
        /// The start of their identity.
        2 id: [u8; 8],
        3 introductions: bool,
        4 last: Option<Last>,
        5 name: String,
        6 nearby: bool,
        7 own: bool,
        8 picture: Option<String>,
        9 reach: ContactReach,
        10 relayed: bool,
        11 suggested: Option<String>,
        12 trusted: bool,
        13 unread: u64,
    }
);
typed!(
    /// The copies of the files on the devices meant to keep everything.
    COPIES "copies" Copies {
        1 blobs: u64,
        2 count: u64,
        3 eligible: u64,
        4 holders: Vec<Holder>,
        5 interval_ms: u64,
        6 now: u64,
        7 older_than_ms: u64,
    }
);
typed!(
    /// One of the person's devices.
    DEVICE "device" Device {
        /// Where its session runs, or where it was last known.
        1 addr: Option<String>,
        2 carrier: Option<Cow<'static, str>>,
        /// What this device's fetcher thinks of it as a source.
        3 fetch: Option<Fetch>,
        /// The start of its key.
        4 key: [u8; 8],
        5 name: String,
        6 online: bool,
        /// `device`, `admin` or `root`.
        7 power: Cow<'static, str> where "device" | "admin" | "root",
        8 this: bool,
        /// The device a relayed session with it runs through.
        9 through: Option<String>,
        10 unreadable: Option<Unreadable>,
        11 dials: Option<u64>,
        12 redial_s: Option<u64>,
    }
);
typed!(
    /// An address a reach node gives, and whether it was tried.
    ENDPOINT "endpoint" EndpointSeen {
        1 endpoint: String,
        2 local: bool,
        3 tried: bool,
        4 why_not: Option<Cow<'static, str>>,
    }
);
typed!(
    /// What this device's fetcher thinks of another as a source.
    FETCH "fetch" Fetch {
        1 latency_ms: u64,
        2 rate: u64,
        3 received: u64,
        4 replies: u64,
    }
);
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
typed!(
    /// A group this person is in, as the list of them shows it.
    GROUP "group" Group {
        /// Whether this person may manage it.
        1 admin: bool,
        /// The successors that did not stand.
        2 did_not_stand: Vec<[u8; 32]>,
        3 did_not_stand_changes: Vec<GroupChange>,
        /// Why it ended, where nothing stands in its place.
        4 ended: Option<String>,
        5 group: [u8; 32],
        6 held_back: u64,
        7 introductions: bool,
        8 last: Option<Last>,
        9 members: u64,
        /// Who moved it here, and what that changed.
        10 moved: Option<GroupChange>,
        11 name: String,
        12 not_posted: u64,
        13 public: bool,
        14 reach: GroupReach,
        15 role: Option<Cow<'static, str>>,
        16 unread: u64,
        /// The group it succeeded.
        17 was: Option<[u8; 32]>,
        18 confirm: Option<Vec<[u8; 32]>>,
        19 to_confirm: Option<Vec<GroupChange>>,
        20 for_call: Option<bool>,
        21 last_call: Option<CallEnded>,
    }
);
typed!(
    /// What a group's move changed: who was taken out, and whose role.
    GROUP_CHANGE "group change" GroupChange {
        1 at: Option<u64>,
        2 by: Option<String>,
        3 group: Option<[u8; 32]>,
        4 roles: Vec<RoleChange>,
        5 seen: Option<u64>,
        6 taken_out: Vec<String>,
        7 device: Option<String>,
        8 to: Option<[u8; 32]>,
    }
);
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
typed!(
    /// A group where someone refused still reads where this person's hosts
    /// are, and what they see there.
    GROUP_SHOWN "group shown" GroupShown {
        1 group: [u8; 32],
        2 name: String,
        3 what: Vec<String>,
    }
);
typed!(
    /// A change of guardians under way: to the person whose it is (in
    /// `guardians`), or to one of their guardians (in `guarding`), each
    /// with fields of its own.
    GUARDIAN_CHANGE "guardian change" GuardianChange {
        /// To a guardian, before it is in effect.
        1 caution: Option<String>,
        2 confirm_delay: u64,
        3 confirm_delay_text: String,
        /// To a guardian: from when they may confirm it.
        4 confirm_from_ms: Option<u64>,
        5 confirmed: u64,
        6 confirmed_by_me: Option<bool>,
        7 delay: u64,
        8 delay_text: String,
        9 fingerprint: String,
        10 guardians: u64,
        /// Its entry: whole to the person, its first eight bytes to a
        /// guardian.
        11 id: bytes::Bytes,
        12 in_effect: Option<bool>,
        /// To the person: whom it names.
        13 names: Option<Vec<String>>,
        14 needed: Option<u64>,
        15 never: Option<bool>,
        16 objected: bool,
        17 threshold: u64,
        18 waits_until_ms: Option<u64>,
    }
);
typed!(
    /// Someone this person guards.
    GUARDED "guarded" Guarded {
        1 account_copy: bool,
        2 changes: Vec<GuardianChange>,
        3 delay: u64,
        4 delay_text: String,
        5 guardians: u64,
        6 helpers: u64,
        7 id: [u8; 32],
        8 name: String,
        9 never: Vec<String>,
        10 persona: [u8; 32],
        /// Where the persona's service listens, where it runs here.
        11 persona_at: Option<String>,
        12 recoveries: Vec<RecoveryShown>,
        13 threshold: u64,
        14 waiting: u64,
        15 warning: Option<String>,
    }
);
typed!(
    /// A device meant to keep everything, as a copy of the files.
    HOLDER "holder" Holder {
        1 checking: bool,
        2 counted: bool,
        /// The start of its key.
        3 key: [u8; 8],
        4 last_check: Option<u64>,
        5 last_fail: Option<u64>,
        6 last_pass: Option<u64>,
        7 missed: u64,
        8 name: String,
        9 online: bool,
        /// Why it does not count, where it does not.
        10 reason: Option<String>,
        11 state: Cow<'static, str>,
        12 this: bool,
    }
);
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
typed!(
    /// A device that serves, or can: whether it is reached from outside
    /// its network, what it gives, and what it sees.
    HOSTABLE "hostable" Hostable {
        1 name: String,
        2 outside: bool,
        3 sees: Cow<'static, str>,
        4 services: Vec<Cow<'static, str>>,
    }
);
typed!(
    /// A hosting between this person and a contact, or an offer of one.
    HOSTING "hosting" Hosting {
        1 accepted: bool,
        2 devices: Vec<String>,
        3 ended: bool,
        4 envelopes: Option<u64>,
        /// This person hosts them.
        5 mine: bool,
        6 name: String,
        7 relay_bytes: Option<u64>,
        8 sees: Cow<'static, str>,
        /// Envelopes held for them on this device, where it serves them.
        9 waiting: Option<u64>,
        10 who: [u8; 32],
        11 serving: Vec<Hostable>,
        12 offered_at: Option<u64>,
        /// The message in the conversation it comes just after.
        13 after: Option<[u8; 16]>,
        14 accepted_at: Option<u64>,
        15 ended_at: Option<u64>,
        16 ended_by: Option<[u8; 32]>,
        17 declined: bool,
    }
);
typed!(
    /// Whether this device may be inspected now, and until when.
    INSPECTION "inspection" Inspection {
        1 on: bool,
        2 until: Option<u64>,
    }
);
typed!(
    /// An introduction waiting for this person.
    INTRODUCTION "introduction" Introduction {
        /// Who introduces, by what this person calls them.
        1 from: String,
        /// The group it comes through.
        2 group: Option<String>,
        3 id: [u8; 16],
        /// `meet` or `introduced`.
        4 kind: Cow<'static, str> where "meet" | "introduced",
        5 name: String,
        6 note: Option<String>,
    }
);
typed!(
    /// An invitation this person made.
    INVITATION "invitation" Invitation {
        1 cancelled: bool,
        2 expired: bool,
        3 hosts_only: bool,
        4 id: [u8; 16],
        5 made: Option<u64>,
        6 name: Option<String>,
        7 outstanding: bool,
        8 used: u64,
        9 uses: u64,
    }
);
typed!(
    /// The last message of a conversation.
    LAST "last message" Last {
        /// In a group: who said it.
        1 from: Option<String>,
        2 mine: bool,
        3 text: String,
        4 time: Option<u64>,
    }
);
typed!(
    /// A group change kept after a recovery by guardians (D84).
    KEPT_CHANGE "kept change" KeptChange {
        1 at: Option<u64>,
        2 by: String,
        3 can_undo: bool,
        4 device: Option<String>,
        /// The group it left.
        5 group: [u8; 32],
        6 handed_to: Option<String>,
        7 name: String,
        8 roles: Vec<RoleChange>,
        9 taken_out: Vec<String>,
        /// The group it moved to.
        10 to: [u8; 32],
        11 undo: String,
        /// The group an undo made.
        12 undone: Option<[u8; 32]>,
    }
);
typed!(
    /// A device a recovery removed.
    LOST_DEVICE "lost device" LostDevice {
        /// The start of its key.
        1 key: [u8; 8],
        2 name: Option<String>,
        /// What it wrote that is set aside in the spaces held now.
        3 set_aside: Option<u64>,
    }
);
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
        8 role: Cow<'static, str> where "owner" | "admin" | "member" | "reader" | "taken out",
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
        10 state: Option<Cow<'static, str>> where "sent" | "waiting" | "read",
        11 text: String,
        12 time: Option<u64>,
    }
);
typed!(
    /// Someone who no longer needs this person as a guardian.
    NO_LONGER_NEEDED "no longer needed" NoLongerNeeded {
        1 at_ms: u64,
        2 id: [u8; 32],
        3 name: String,
        4 text: String,
    }
);
typed!(
    /// How two people met.
    MET "met" Met {
        /// Who introduced them.
        1 by: Option<String>,
        /// The group the introduction came through.
        2 group: Option<String>,
        3 how: Cow<'static, str>,
        4 via: Option<String>,
    }
);
typed!(
    /// The last address a direct session with a device worked at.
    KNOWN_PATH "known path" KnownPath {
        1 addr: String,
        2 checking: bool,
        3 confirmed_s_ago: Option<u64>,
        4 misses: u64,
        5 next_check_s: u64,
        6 probes: u64,
        7 wait_s: u64,
    }
);
typed!(
    /// Whether each gave the other a presence secret (D74).
    NEARBY "nearby" Nearby {
        1 they_give_secret: bool,
        2 you_give_secret: bool,
    }
);
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
typed!(
    /// A group offered to this person.
    OFFER "offer" Offer {
        1 from: String,
        2 group: [u8; 32],
        3 members: u64,
        4 name: String,
        5 public: bool,
        6 reach: GroupReach,
        7 for_call: Option<bool>,
        8 last_call: Option<CallEnded>,
    }
);
typed!(
    /// What deleted files and old versions take, and how long they stay.
    OLD "old versions" OldVersions {
        1 at: Option<u64>,
        2 bytes: Option<u64>,
        3 keep: String,
        4 only_here: Option<OnlyHere>,
        5 unchecked: Option<bool>,
    }
);
typed!(
    /// Over the budget, and on no device that keeps everything yet.
    ONLY_HERE "only here" OnlyHere {
        1 bytes: u64,
        2 files: u64,
    }
);
typed!(
    /// A device to pair again after a recovery.
    PAIR_AGAIN "pair again" PairAgain {
        /// The start of its key.
        1 key: [u8; 8],
        2 name: Option<String>,
    }
);
typed!(
    /// Pairing under way on this device.
    PAIRING "pairing" Pairing {
        1 admin: Option<String>,
        2 code: Option<String>,
        3 error: Option<String>,
        /// `showing`, `joining` or `failed`.
        4 state: Cow<'static, str> where "showing" | "joining" | "failed",
        5 power: Option<Cow<'static, str>>,
    }
);
typed!(
    /// An address this device looks for the person's devices at.
    PEER "peer" Peer {
        1 addr: String,
        /// The device found there, by name.
        2 device: Option<String>,
    }
);
typed!(
    /// What a folder of the one folder is.
    PLACE "place" Place {
        /// `mine`, `category` or `shared`.
        1 kind: Cow<'static, str> where "mine" | "category" | "shared",
        2 name: Option<String>,
        3 who: Option<[u8; 8]>,
        4 group: Option<[u8; 32]>,
    }
);
typed!(
    /// Fetching the files' content in the background.
    PROGRESS "progress" ProgressShown {
        1 bytes_fetched: u64,
        2 bytes_pending: u64,
        3 bytes_wanted: u64,
        4 files_pending: u64,
        5 last_error: Option<String>,
        6 rate: u64,
    }
);
typed!(REACTION "reaction" Reaction {
    1 count: u64,
    2 mine: bool,
    3 text: String,
});
typed!(
    /// A recovery: of this person (in `guardians`), or of someone they
    /// guard (in `guarding`), each with fields of its own.
    RECOVERY "recovery" RecoveryShown {
        1 caution: Option<String>,
        2 confirm_from_ms: Option<u64>,
        3 confirmed: u64,
        4 confirmed_by_me: Option<bool>,
        5 endorsed: u64,
        6 endorsed_by_me: Option<bool>,
        7 fingerprint: String,
        /// Of this person's: its entry.
        8 id: Option<[u8; 32]>,
        9 in_effect: bool,
        10 keeps_keys: Option<bool>,
        11 objected: bool,
        12 pending: Option<bool>,
    }
);
typed!(
    /// Two members whose messages this person's devices have been passing
    /// on, and who name no host in the group.
    RELAYED_FOR "relayed for" RelayedFor {
        1 a: String,
        /// The start of their identity.
        2 a_id: [u8; 8],
        3 b: String,
        4 b_id: [u8; 8],
    }
);
typed!(
    /// A group this person left and can come back to.
    REJOIN "rejoin" Rejoin {
        1 group: [u8; 32],
        2 members: u64,
        3 name: String,
    }
);
typed!(
    /// A role a group's move changed.
    ROLE_CHANGE "role change" RoleChange {
        1 from: Cow<'static, str>,
        2 name: String,
        3 to: Cow<'static, str>,
    }
);
typed!(
    /// When the reconnect loop dials next.
    REDIAL "redial" Redial {
        1 alone: bool,
        2 helps: bool,
        3 sparing: Option<Sparing>,
    }
);
typed!(
    /// A device sparing its battery: when it dials next, and the wait.
    SPARING "sparing" Sparing {
        1 next_s: u64,
        2 wait_s: u64,
    }
);
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
typed!(
    /// One of a contact's devices, and the session with it, if any.
    SESSION_DEVICE "contact's device" SessionDevice {
        1 addr: Option<String>,
        2 bytes_received: Option<u64>,
        3 bytes_sent: Option<u64>,
        4 carrier: Option<Cow<'static, str>>,
        5 heard_ms_ago: Option<u64>,
        6 kept_in_touch: bool,
        /// The start of its key.
        7 key: [u8; 8],
        8 online: bool,
        9 open_for_s: Option<u64>,
        /// `you` or `them`.
        10 opened_by: Option<Cow<'static, str>> where "you" | "them",
        11 packets_dropped: Option<u64>,
        12 packets_lost: Option<u64>,
        /// `direct` or `relay`.
        13 route: Option<Cow<'static, str>> where "direct" | "relay",
        14 rtt_ms: Option<u64>,
        15 they_see_you_at: Option<String>,
        16 through: Option<String>,
        17 unreadable: Option<Unreadable>,
        18 kept_alive_s: Option<u64>,
        19 path: Option<KnownPath>,
        20 neighbour: bool,
    }
);
typed!(
    /// An entry set aside for want of a witness: the starts of its id and
    /// its space's.
    SET_ASIDE "set aside" SetAside {
        1 entry: [u8; 8],
        2 space: [u8; 8],
        3 time_ms: Option<u64>,
    }
);
typed!(
    /// What a space held here takes.
    SPACE_USAGE "space usage" SpaceUsage {
        1 full: bool,
        2 history_bytes: u64,
        3 history_days: Option<u64>,
        4 live_bytes: u64,
        5 log_bytes: u64,
        6 name: String,
        /// `on-demand`, `history`, `full` or `history-days`.
        7 retention: Cow<'static, str> where "on-demand" | "history" | "full" | "history-days",
        8 space: [u8; 32],
    }
);
typed!(
    /// A space this device holds, as `status` gives it.
    SPACE "space" SpaceShown {
        1 entries: u64,
        /// The start of its id.
        2 id: [u8; 8],
        /// `account`, `files`, `other` or `arriving`.
        3 kind: Cow<'static, str> where "account" | "files" | "other" | "arriving",
        4 set_aside: u64,
        5 valid: u64,
    }
);
typed!(
    /// A step of looking for someone, or of their sessions.
    STEP "step" Step {
        /// In milliseconds since 1970.
        1 at: u64,
        2 ok: Option<bool>,
        3 text: String,
    }
);
typed!(
    /// No longer sent: a succession a recovery asked about.
    SUCCESSION "succession" Succession {
        1 id: String,
        2 space: String,
    }
);
typed!(
    /// A host a reach node names, as this device sees it.
    THEIR_REACH "reach seen" ReachSeen {
        /// The start of the key of the device it is, where it is theirs.
        1 device: Option<[u8; 8]>,
        2 endpoints: Vec<EndpointSeen>,
        /// The start of its link key.
        3 host: [u8; 8],
        4 session: bool,
        5 this_device: bool,
    }
);
typed!(
    /// An item of the mounted folder's tree.
    TREE_ITEM "tree item" TreeItem {
        1 dirty: bool,
        2 ino: u64,
        /// `dir`, `file`, `link` or `conflict`.
        3 kind: Cow<'static, str> where "dir" | "file" | "link" | "conflict",
        4 local: bool,
        /// The start of its node's id.
        5 node: Option<[u8; 6]>,
        6 path: String,
        7 size: u64,
    }
);
typed!(
    /// An item of the tree that keeps the device from settling.
    STUCK_ITEM "stuck item" StuckItem {
        1 dirty: String,
        2 kind: String,
        3 opens: u64,
        4 path: String,
        5 staged: bool,
    }
);
typed!(
    /// What a device sent that this one cannot read, or the other way round.
    UNREADABLE "unreadable" Unreadable {
        1 reason: String,
        2 retry_in_s: u64,
        /// A sentence for the person.
        3 says: String,
        4 since: u64,
        5 theirs: bool,
        6 version: Option<String>,
    }
);
typed!(
    /// A file the state holds that the tree does not show.
    UNSHOWN_NODE "unshown node" UnshownNode {
        1 name: String,
        /// The start of its node's id.
        2 node: [u8; 6],
    }
);
typed!(
    /// A version of a file of the one folder: of its history, all of it;
    /// of a conflict, its device, time and size.
    VERSION "version" Version {
        1 current: Option<bool>,
        2 device: String,
        /// Whether its content is on this device.
        3 here: Option<bool>,
        4 size: Option<u64>,
        5 time: Option<u64>,
        6 version: Option<u64>,
        /// Who wrote it, where someone else did.
        7 by: Option<String>,
    }
);
typed!(
    /// A file or folder deleted from the one folder, which can be had back.
    DELETED_FILE "deleted file" DeletedFile {
        1 by: Option<String>,
        2 folder: bool,
        3 id: [u8; 16],
        4 mine: Option<bool>,
        5 name: String,
        6 size: Option<u64>,
        7 time: Option<u64>,
    }
);

// ---- Records of inspection ----

typed!(
    /// A value of the base encoding, rendered: what it is (`t`: `int`,
    /// `bytes`, `text`, `list`, `record`, `secret`, `deep`, `cleared`),
    /// how long it is, and as much of it as was asked for. It holds values
    /// of its own, so its rows are named outright.
    VALUE "value" InspectValue {
        1 cut: Option<bool>,
        2 fields: Option<Vec<ValueField>> as [VALUE_FIELD],
        3 data: Option<bytes::Bytes>,
        /// The record bytes encode.
        4 inner: Option<Box<InspectValue>> as {VALUE},
        5 items: Option<Vec<InspectValue>> as [VALUE],
        6 len: Option<u64>,
        7 n: Option<u64>,
        8 shape: Option<Shape>,
        9 t: Cow<'static, str> where "int" | "bytes" | "text" | "list" | "record" | "secret" | "deep" | "cleared",
        10 v: Option<Scalar>,
        /// Of a secret: what it is.
        11 what: Option<String>,
        12 withheld: Option<Cow<'static, str>>,
    }
);
typed!(
    /// A field of a rendered record: its key, and its value.
    VALUE_FIELD "value field" ValueField {
        1 k: u64,
        2 v: InspectValue as {VALUE},
    }
);
typed!(
    /// What shape a record has that the explorer can name.
    SHAPE "shape" Shape {
        1 here: Option<bool>,
        2 id: Option<[u8; 32]>,
        /// `blob reference` or `epoch key`.
        3 is: Cow<'static, str> where "blob reference" | "epoch key",
        4 levels: Option<u64>,
        5 size: Option<u64>,
    }
);
typed!(ATTACHED_LOG "attached log" AttachedLog {
    1 bytes: u64,
    2 entries: u64,
    3 id: [u8; 32],
});
typed!(ENCRYPTION_KEY "encryption key" EncryptionKey {
    1 entry: [u8; 32],
    2 len: u64,
    3 x25519: [u8; 32],
});
typed!(EPOCH "epoch" InspectEpoch {
    1 entries: u64,
    2 held: bool,
    3 id: [u8; 16],
    4 started_by: Option<StartedBy>,
});
/// An epoch of a space as inspection shows it, and how many of its
/// sealed entries wait here to be opened. An old oddity, kept to the byte
/// (DEVIATIONS.md, Old oddities kept): by name an epoch with entries
/// waiting said so in a field that has no number, so that the reply was
/// this build's mistake, which fails the request where the tests run and
/// leaves out the whole list of epochs elsewhere; the old pager counted
/// such an epoch as no bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct EpochShown {
    pub epoch: InspectEpoch,
    pub pending: Option<u64>,
}

impl std::ops::Deref for EpochShown {
    type Target = InspectEpoch;
    fn deref(&self) -> &InspectEpoch {
        &self.epoch
    }
}

impl super::typed::Wire for EpochShown {
    const TY: Ty = Ty::Rec(&EPOCH);
    const LIST: Ty = Ty::Recs(&EPOCH);
    #[inline]
    fn check(&self, at: &super::typed::At) -> Result<(), String> {
        match self.pending {
            Some(_) => Err(format!("{at}.pending has no number")),
            None => self.epoch.check(at),
        }
    }
    #[inline]
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.epoch.encode_into(out)
    }
    #[inline]
    fn encoded_len(&self) -> usize {
        match self.pending {
            Some(_) => 0,
            None => self.epoch.encoded_len(),
        }
    }
    #[inline]
    fn take(v: cardinal_encoding::Value, at: &super::typed::At) -> Result<Self, String> {
        Ok(EpochShown {
            epoch: InspectEpoch::take(v, at)?,
            pending: None,
        })
    }
    #[inline]
    fn read(
        c: &mut cardinal_encoding::Cursor<'_>,
        depth: usize,
        at: &super::typed::At,
    ) -> Result<Self, super::typed::Bad> {
        Ok(EpochShown {
            epoch: InspectEpoch::read(c, depth, at)?,
            pending: None,
        })
    }
}

typed!(IDENTITY_ENTRY "identity entry" IdentityEntry {
    1 body: u64,
    2 bytes: u64,
    3 header: InspectValue,
    4 id: [u8; 32],
    5 in_effect: bool,
    6 ops: Vec<InspectOp>,
    7 parents: Vec<[u8; 32]>,
    8 signatures: u64,
    9 signer: [u8; 32],
    10 signer_power: Option<String>,
    11 valid: bool,
});
typed!(INSPECT_DEVICE "this device" InspectDevice {
    1 key: [u8; 32],
    2 link_x25519: [u8; 32],
    3 name: Option<String>,
});
typed!(
    /// An entry of a space: as a host holds it, sealed, or as a member
    /// reads it.
    INSPECT_ENTRY "entry" InspectEntry {
        1 accepted: Option<bool>,
        2 author: Option<[u8; 32]>,
        3 author_ok: Option<bool>,
        4 bytes: Option<u64>,
        5 entry: Option<[u8; 32]>,
        6 epoch: Option<[u8; 16]>,
        7 genesis: Option<bool>,
        8 open_key: Option<bool>,
        9 parents: Option<Vec<[u8; 32]>>,
        10 position: Option<u64>,
        11 sealed_id: Option<[u8; 32]>,
        12 signer: Option<[u8; 32]>,
        13 starts_epoch: Option<bool>,
        14 time: Option<u64>,
        15 unwitnessed: Option<bool>,
        16 valid: Option<bool>,
        17 weigh: Weight,
        18 wraps: Option<u64>,
    }
);
typed!(INSPECT_IDENTITY "identity" InspectIdentity {
    1 bytes: u64,
    2 contested: bool,
    3 encryption_key: Option<EncryptionKey>,
    4 encryption_keys_held: u64,
    5 entries: u64,
    6 frozen: bool,
    7 heads: Vec<[u8; 32]>,
    8 id: [u8; 32],
    9 keys: Vec<InspectKey>,
    10 recovery_policies: u64,
    11 removed: Vec<[u8; 32]>,
});
typed!(INSPECT_KEY "key" InspectKey {
    1 added_in: [u8; 32],
    2 key: [u8; 32],
    3 link_key: Option<LinkKey>,
    4 name: Option<String>,
    5 power: String,
    6 recovery_key: Option<u64>,
    7 this_device: bool,
});
typed!(
    /// A space held here, in brief: what an overview lists, and what a
    /// space's view begins with.
    INSPECT_SPACE "space held" InspectSpace {
        1 account: bool,
        2 bytes: u64,
        3 entries: Option<u64>,
        4 epochs: Option<u64>,
        5 files: bool,
        6 id: [u8; 32],
        7 label: Option<String>,
        8 members: Option<u64>,
        9 my_role: Option<u64>,
        10 nodes: Option<u64>,
        11 opened: bool,
        12 pending: u64,
        13 profile: Option<Kind>,
        14 sealed: u64,
        15 successor: Option<[u8; 32]>,
        16 valid: Option<u64>,
    }
);
typed!(KIND_COUNT "kind count" KindCount {
    1 bytes: u64,
    2 conflicts: u64,
    3 deleted: u64,
    4 kind: Kind,
    5 nodes: u64,
});
typed!(LINK_KEY "link key" LinkKey {
    1 len: u64,
    2 x25519: [u8; 32],
});
typed!(
    /// A node of a space, in brief.
    NODE_BRIEF "node" NodeBrief {
        1 bytes: u64,
        2 children: u64,
        3 created: Option<u64>,
        4 created_in: [u8; 32],
        5 creator: [u8; 32],
        6 delete_conflict: bool,
        7 deleted: bool,
        /// Each field: its key, its values' bytes, how many values.
        8 fields: Vec<Vec<u64>>,
        9 id: [u8; 16],
        10 kind: Kind,
        11 name: String,
        12 parent: [u8; 16],
        13 position: Option<u64>,
    }
);
typed!(NODE_FIELD "node field" NodeField {
    1 conflict: bool,
    2 k: u64,
    3 values: Vec<NodeValue>,
});
typed!(NODE_HISTORY "node history" NodeHistory {
    1 accepted: bool,
    2 author: [u8; 32],
    3 bytes: u64,
    4 entry: [u8; 32],
    5 index: u64,
    6 op: Option<u64>,
    7 time: Option<u64>,
    8 valid: bool,
});
typed!(NODE_VALUE "node value" NodeValue {
    1 entry: [u8; 32],
    2 op: u64,
    3 v: InspectValue,
});
typed!(
    /// An op, rendered, and what it is about: the kind of the node it makes
    /// or names, or `reach` for its author's reach node.
    OP "op" InspectOp {
        1 bytes: u64,
        2 creates: Option<[u8; 16]>,
        3 index: Option<u64>,
        4 kind: Option<Kind>,
        5 op: InspectValue,
        6 reach: Option<bool>,
    }
);
typed!(OTHER_LOG "other log" OtherLog {
    1 bytes: u64,
    2 entries: u64,
    3 id: [u8; 32],
    4 name: Option<String>,
});
typed!(POLICY "policy" PolicyShown {
    1 history_shared: bool,
    2 public: bool,
    3 rotate_after: u64,
});
typed!(REACH_NODE "reach node" ReachNode {
    1 bytes: u64,
    2 fields: Vec<NodeField>,
    3 id: [u8; 16],
    4 identity: Option<[u8; 32]>,
});
typed!(ROOT "root" RootShown {
    1 children: u64,
    2 id: [u8; 16],
});
typed!(SIGNATURE "signature" SignatureShown {
    1 key: [u8; 32],
    2 gone signature: u64,
    3 signature: bytes::Bytes,
});
typed!(SPACE_MEMBER "space member" SpaceMember {
    1 added_by: Option<[u8; 32]>,
    2 identity: [u8; 32],
    3 left: bool,
    4 log_held: bool,
    5 name: Option<String>,
    6 reach_node: [u8; 16],
    7 role: u64,
});
typed!(STARTED_BY "started by" StartedBy {
    1 author: [u8; 32],
    2 entry: [u8; 32],
    3 time: Option<u64>,
});
typed!(STATS "stats" StatsShown {
    1 appended: u64,
    2 recomputed: u64,
});
typed!(STORE "store" StoreShown {
    1 bytes: u64,
    2 objects: u64,
});
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
typed!(
    /// Where an entry's bytes go, from its sealed form in.
    WEIGH "weight" Weight {
        1 aead: u64,
        2 ciphertext: u64,
        3 fields: Option<u64>,
        4 header: u64,
        5 ops: Option<Vec<WeighedOp>>,
        6 sealed: u64,
        7 signature: Option<u64>,
        8 wraps: u64,
    }
);
typed!(WEIGHED_OP "weighed op" WeighedOp {
    1 bytes: u64,
    2 kind: Option<Kind>,
    3 op: Option<Kind>,
    4 reach: Option<bool>,
});

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

typed!(fields StatusArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(
    fields
    /// Where this device stands: its settings, its spaces, its devices,
    /// and what it is doing.
    StatusReply {
        2 bluetooth: BluetoothShown,
        3 carrying_calls: u64,
        4 conditions: ConditionsShown,
        5 conflicts: u64,
        /// Before the files space is known, none.
        6 copies: Option<Copies>,
        7 devices: Vec<Device>,
        8 files_ready: bool,
        9 home: String,
        /// The hosts the recovery sheet names, where it can be made.
        10 hosts: Option<u64>,
        /// The start of the person's identity.
        11 identity: Option<[u8; 8]>,
        12 identity_id: Option<[u8; 32]>,
        13 inspection: Inspection,
        14 left_behind: Vec<String>,
        15 listen: String,
        16 mount: Option<String>,
        17 mount_unavailable: Option<String>,
        18 mounted: Option<String>,
        19 moved_from: Option<u64>,
        20 name: String,
        21 network: Network,
        22 not_saved: u64,
        23 not_saved_undone: u64,
        24 old: OldVersions,
        25 pairing: Option<Pairing>,
        26 peers: Vec<String>,
        27 pending_changes: bool,
        28 progress: ProgressShown,
        29 read_markers: bool,
        30 removed: bool,
        31 retention: String,
        32 router: Router,
        33 spaces: Vec<SpaceShown>,
        34 uptime_s: u64,
        35 more: bool,
        36 next: Option<u64>,
        37 redial: Redial,
        /// The person's devices with a mailbox, reachable from outside.
        38 always_on: Vec<String>,
    }
);
asks!(STATUS: 2 "status" StatusArgs -> StatusReply, reads,
    after devices, left_behind, peers, spaces, always_on);

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
    6 state: Cow<'static, str> where "idle" | "showing" | "joining" | "joined" | "failed",
    /// `device` or `admin`.
    7 power: Option<Cow<'static, str>> where "device" | "admin",
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

// ---- Messages, with a contact or in a group ----

typed!(fields SayArgs {
    1 who: Option<Reference>,
    2 text: Option<String>,
    3 reply_to: Option<Reference>,
    4 attach: Option<Vec<String>>,
    5 group: Option<Reference>,
});
typed!(
    fields
    /// To a contact: whether it can reach them now.
    SayReply {
        2 reachable: Option<bool>,
    }
);
asks!(SAY: 35 "say" SayArgs -> SayReply, writes);
typed!(fields SaveAttachmentArgs {
    1 who: Option<Reference>,
    2 id: Option<Reference>,
    3 index: Option<u64>,
    4 to: Option<String>,
    5 group: Option<Reference>,
});
asks!(SAVE_ATTACHMENT: 36 "save-attachment" SaveAttachmentArgs -> SaveReply, writes);
typed!(fields EditMessageArgs {
    1 who: Option<Reference>,
    2 id: Option<Reference>,
    3 text: Option<String>,
    4 group: Option<Reference>,
});
asks!(EDIT_MESSAGE: 37 "edit-message" EditMessageArgs -> Done, writes);
typed!(fields DeleteMessageArgs {
    1 who: Option<Reference>,
    2 id: Option<Reference>,
    3 group: Option<Reference>,
});
asks!(DELETE_MESSAGE: 38 "delete-message" DeleteMessageArgs -> Done, writes);
typed!(fields ReactArgs {
    1 who: Option<Reference>,
    2 id: Option<Reference>,
    3 text: Option<String>,
    4 group: Option<Reference>,
});
asks!(REACT: 39 "react" ReactArgs -> Done, writes);
typed!(fields MarkReadArgs {
    1 who: Option<Reference>,
    2 group: Option<Reference>,
});
typed!(
    fields
    /// Whether this person's marker moved, which the others see, or the
    /// place only their own devices keep, and why.
    MarkReadReply {
        2 kept: bool,
        3 marked: bool,
        4 why: Option<String>,
    }
);
asks!(MARK_READ: 40 "mark-read" MarkReadArgs -> MarkReadReply, writes);

// ---- Groups ----

typed!(fields GroupsArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields GroupsReply {
    2 groups: Vec<Group>,
    3 offers: Vec<Offer>,
    4 more: bool,
    5 next: Option<u64>,
    6 rejoin: Option<Vec<Rejoin>>,
});
asks!(GROUPS: 70 "groups" GroupsArgs -> GroupsReply, reads, after groups, offers, rejoin);
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
typed!(fields GroupMembersArgs {
    1 group: Option<Reference>,
    2 after: Option<u64>,
    3 limit: Option<u64>,
});
typed!(fields GroupMembersReply {
    2 group: [u8; 32],
    3 members: Vec<Member>,
    4 name: String,
    5 more: bool,
    6 next: Option<u64>,
});
asks!(GROUP_MEMBERS: 78 "group-members" GroupMembersArgs -> GroupMembersReply, reads, after members by id);
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

// ---- The service, people, introductions and groups: the rest ----

typed!(fields HelloArgs {});
typed!(fields HelloReply {
    2 api: u64,
    3 version: Cow<'static, str>,
});
asks!(HELLO: 1 "hello" HelloArgs -> HelloReply, reads);

typed!(fields ReadMarkersArgs {
    1 on: Option<bool>,
});
typed!(fields ReadMarkersReply {
    2 on: bool,
});
asks!(READ_MARKERS: 41 "read-markers" ReadMarkersArgs -> ReadMarkersReply, reads unless on);

typed!(fields CancelInvitationArgs {
    1 id: Option<Reference>,
});
asks!(CANCEL_INVITATION: 45 "cancel-invitation" CancelInvitationArgs -> Done, writes);

typed!(fields IntroduceArgs {
    1 who: Option<Reference>,
    2 to: Option<Reference>,
    3 note: Option<String>,
});
asks!(INTRODUCE: 47 "introduce" IntroduceArgs -> Done, writes);

typed!(fields IntroductionAcceptArgs {
    1 id: Option<Reference>,
});
typed!(
    fields
    /// Where both said yes: whom the invitation made a contact of.
    IntroductionAcceptReply {
        2 name: Option<String>,
        3 recovery_of: Option<[u8; 32]>,
    }
);
asks!(INTRODUCTION_ACCEPT: 48 "introduction-accept" IntroductionAcceptArgs -> IntroductionAcceptReply,
    writes);
typed!(fields IntroductionDeclineArgs {
    1 id: Option<Reference>,
});
asks!(INTRODUCTION_DECLINE: 49 "introduction-decline" IntroductionDeclineArgs -> Done, writes);

typed!(fields GroupConnectArgs {
    1 group: Option<Reference>,
    2 who: Option<Reference>,
    3 note: Option<String>,
});
typed!(
    fields
    /// Asked already, and not answered.
    GroupConnectReply {
        2 asked: Option<bool>,
    }
);
asks!(GROUP_CONNECT: 81 "group-connect" GroupConnectArgs -> GroupConnectReply, writes);

typed!(fields GroupPostAgainArgs {
    1 group: Option<Reference>,
});
typed!(fields GroupPostAgainReply {
    2 posted: u64,
});
asks!(GROUP_POST_AGAIN: 83 "group-post-again" GroupPostAgainArgs -> GroupPostAgainReply, writes);

typed!(fields GroupMovedSeenArgs {
    1 group: Option<Reference>,
});
asks!(GROUP_MOVED_SEEN: 84 "group-moved-seen" GroupMovedSeenArgs -> Done, writes);

typed!(fields GroupConfirmMoveArgs {
    1 group: Option<Reference>,
    2 moves: Option<Vec<bytes::Bytes>>,
    3 to: Option<Vec<bytes::Bytes>>,
});
typed!(fields GroupConfirmMoveReply {
    2 kept: u64,
});
asks!(GROUP_CONFIRM_MOVE: 85 "group-confirm-move" GroupConfirmMoveArgs -> GroupConfirmMoveReply,
    writes);

typed!(fields GroupLeavingArgs {
    1 group: Option<Reference>,
});
typed!(
    fields
    /// What leaving a group would leave behind (D89).
    GroupLeavingReply {
        2 admins: Vec<String>,
        3 choose_admin: bool,
        4 group: [u8; 32],
        5 name: String,
        6 relayed_for: Vec<RelayedFor>,
    }
);
asks!(GROUP_LEAVING: 86 "group-leaving" GroupLeavingArgs -> GroupLeavingReply, reads);

// ---- Guardians: of this person, and those this person guards ----

typed!(fields GuardiansArgs {});
typed!(
    fields
    /// This person's guardians, and what is under way.
    GuardiansReply {
        2 asked: Vec<String>,
        3 changes: Vec<GuardianChange>,
        4 copy_full: Vec<String>,
        5 data: bool,
        6 delay: u64,
        7 delay_text: String,
        8 frozen: bool,
        9 guardians: u64,
        10 names: Vec<String>,
        11 ready: Vec<String>,
        12 recoveries: Vec<RecoveryShown>,
        13 threshold: u64,
    }
);
asks!(GUARDIANS: 150 "guardians" GuardiansArgs -> GuardiansReply, reads);

typed!(fields GuardiansSetArgs {
    1 who: Option<Vec<Reference>>,
    2 threshold: Option<u64>,
    3 delay: Option<u64>,
    4 words: Option<String>,
});
typed!(fields GuardiansSetReply {
    2 delay: u64,
    3 delay_text: String,
    4 names: Vec<String>,
    5 pending: bool,
    6 threshold: u64,
});
asks!(GUARDIANS_SET: 151 "guardians-set" GuardiansSetArgs -> GuardiansSetReply, writes);

typed!(fields GuardiansObjectArgs {
    1 fingerprint: Option<String>,
});
asks!(GUARDIANS_OBJECT: 152 "guardians-object" GuardiansObjectArgs -> Done, writes);

typed!(fields GuardiansAskArgs {
    1 who: Option<Reference>,
});
typed!(fields NameReply {
    2 name: String,
});
asks!(GUARDIANS_ASK: 153 "guardians-ask" GuardiansAskArgs -> NameReply, writes);

typed!(
    fields
    /// Those this person guards, and what they are asked.
    GuardingReply {
        2 accepted: Vec<String>,
        3 asked: Vec<String>,
        4 guarding: Vec<Guarded>,
        5 named_in_change: Vec<String>,
        6 now_ms: u64,
        7 no_longer_needed: Vec<NoLongerNeeded>,
    }
);
typed!(fields GuardingArgs {});
asks!(GUARDING: 154 "guarding" GuardingArgs -> GuardingReply, reads);

typed!(fields GuardingInviteArgs {
    1 who: Option<Reference>,
    2 at: Option<String>,
});
typed!(fields GuardingInviteReply {
    2 code: String,
    3 name: String,
});
asks!(GUARDING_INVITE: 155 "guarding-invite" GuardingInviteArgs -> GuardingInviteReply, writes);

typed!(fields GuardingAcceptArgs {
    1 who: Option<Reference>,
});
typed!(fields GuardingAcceptReply {
    2 already: bool,
    3 name: String,
    4 persona: [u8; 32],
});
asks!(GUARDING_ACCEPT: 156 "guarding-accept" GuardingAcceptArgs -> GuardingAcceptReply, writes);

typed!(fields GuardingConfirmChangeArgs {
    1 who: Option<Reference>,
    2 fingerprint: Option<String>,
    3 understood: Option<bool>,
});
asks!(GUARDING_CONFIRM_CHANGE: 157 "guarding-confirm-change" GuardingConfirmChangeArgs
    -> GuardingReply, writes);

typed!(fields GuardingNeverArgs {
    1 who: Option<Reference>,
    2 fingerprint: Option<String>,
});
asks!(GUARDING_NEVER: 158 "guarding-never" GuardingNeverArgs -> GuardingReply, writes);

typed!(fields GuardingCautionArgs {
    1 who: Option<Reference>,
});
typed!(fields GuardingCautionReply {
    2 caution: String,
    3 name: String,
});
asks!(GUARDING_CAUTION: 159 "guarding-caution" GuardingCautionArgs -> GuardingCautionReply, reads);

typed!(fields GuardingEndorseArgs {
    1 who: Option<Reference>,
    2 fingerprint: Option<String>,
    3 understood: Option<bool>,
});
asks!(GUARDING_ENDORSE: 160 "guarding-endorse" GuardingEndorseArgs -> GuardingReply, writes);

typed!(fields GuardingConfirmArgs {
    1 who: Option<Reference>,
    2 fingerprint: Option<String>,
    3 understood: Option<bool>,
});
asks!(GUARDING_CONFIRM: 161 "guarding-confirm" GuardingConfirmArgs -> GuardingReply, writes);

// ---- Recovery ----

typed!(fields RecoverArgs {});
typed!(
    fields
    /// What is under way on this device, or what the last recovery left.
    RecoverReply {
        2 asked: Option<bool>,
        3 confirmed: Option<u64>,
        4 endorsed: Option<u64>,
        5 fingerprint: Option<String>,
        6 guardians: Option<u64>,
        7 held: Option<u64>,
        8 helper: Option<bool>,
        9 identity: Option<[u8; 32]>,
        10 in_effect: Option<bool>,
        11 lost_at: Option<u64>,
        12 lost_devices: Option<Vec<LostDevice>>,
        13 pair_again: Option<Vec<PairAgain>>,
        14 proposed: Option<u64>,
        15 gone successions: Vec<Succession>,
        16 threshold: Option<u64>,
        17 under_way: bool,
        18 finished: Option<bool>,
        19 words: Option<String>,
        20 kept_changes: Option<Vec<KeptChange>>,
        21 not_heard: Option<Vec<String>>,
    }
);
asks!(RECOVER: 162 "recover" RecoverArgs -> RecoverReply, writes);

typed!(fields RecoverStartArgs {
    1 code: Option<String>,
    2 identity: Option<Reference>,
});
typed!(fields RecoverStartReply {
    2 fingerprint: String,
    3 identity: Option<[u8; 32]>,
});
asks!(RECOVER_START: 163 "recover-start" RecoverStartArgs -> RecoverStartReply, writes);

typed!(fields RecoverInviteArgs {
    1 at: Option<String>,
});
typed!(fields RecoverInviteReply {
    2 code: String,
    3 fingerprint: String,
});
asks!(RECOVER_INVITE: 164 "recover-invite" RecoverInviteArgs -> RecoverInviteReply, writes);

typed!(fields RecoverLostAtArgs {
    1 lost_at: Option<u64>,
});
typed!(fields LostDevicesReply {
    2 lost_devices: Vec<LostDevice>,
});
asks!(RECOVER_LOST_AT: 166 "recover-lost-at" RecoverLostAtArgs -> LostDevicesReply, writes);

typed!(fields RecoverCancelArgs {});
typed!(fields RecoverCancelReply {
    2 fingerprint: Option<String>,
});
asks!(RECOVER_CANCEL: 167 "recover-cancel" RecoverCancelArgs -> RecoverCancelReply, writes);

typed!(fields RecoverFinishArgs {
    1 without_account: Option<bool>,
    2 lost_at: Option<u64>,
});
typed!(fields RecoverFinishReply {
    2 account: bool,
    3 lost_devices: Vec<LostDevice>,
    4 pair_again: Vec<PairAgain>,
    5 words: String,
    /// Added after v0.1.27: an `Option` for ever, though always sent.
    6 not_heard: Option<Vec<String>>,
});
asks!(RECOVER_FINISH: 168 "recover-finish" RecoverFinishArgs -> RecoverFinishReply, writes);

typed!(fields KeepWorkArgs {
    1 name: Option<String>,
    2 up_to: Option<String>,
});
typed!(fields KeepWorkReply {
    2 kept: u64,
    3 set_aside: Vec<SetAside>,
});
asks!(KEEP_WORK: 169 "keep-work" KeepWorkArgs -> KeepWorkReply, writes);

typed!(fields RecoveryCheckArgs {
    1 words: Option<String>,
});
asks!(RECOVERY_CHECK: 170 "recovery-check" RecoveryCheckArgs -> Done, reads);

typed!(fields RecoverySheetArgs {});
typed!(fields RecoverySheetReply {
    2 hosts: Vec<Host>,
});
asks!(RECOVERY_SHEET: 171 "recovery-sheet" RecoverySheetArgs -> RecoverySheetReply, reads);

typed!(fields RestoreFromHostArgs {
    1 words: Option<String>,
    2 at: Option<String>,
    3 gone key: String,
    4 key: Option<bytes::Bytes>,
});
typed!(fields RestoreFromHostReply {
    2 at: String,
});
asks!(RESTORE_FROM_HOST: 172 "restore-from-host" RestoreFromHostArgs -> RestoreFromHostReply,
    writes);

typed!(fields RecoverUndoArgs {
    1 to: Option<bytes::Bytes>,
});
typed!(fields RecoverUndoReply {
    2 group: [u8; 32],
    3 kept_changes: Vec<KeptChange>,
});
asks!(RECOVER_UNDO: 173 "recover-undo" RecoverUndoArgs -> RecoverUndoReply, writes);

typed!(fields RecoverKeptSeenArgs {
    1 to: Option<Vec<bytes::Bytes>>,
});
typed!(fields KeptChangesReply {
    2 kept_changes: Vec<KeptChange>,
});
asks!(RECOVER_KEPT_SEEN: 174 "recover-kept-seen" RecoverKeptSeenArgs -> KeptChangesReply, writes);

typed!(fields RecoverStopWaitingArgs {
    1 all: Option<bool>,
    2 who: Option<Reference>,
});
typed!(fields RecoverStopWaitingReply {
    2 not_heard: Vec<String>,
    3 stopped: Vec<String>,
});
asks!(RECOVER_STOP_WAITING: 175 "recover-stop-waiting" RecoverStopWaitingArgs
    -> RecoverStopWaitingReply, writes);

// ---- Hosting contacts ----

typed!(fields HostOfferArgs {
    1 who: Option<Reference>,
    2 devices: Option<Vec<String>>,
    3 envelopes: Option<u64>,
    4 relay_mb: Option<u64>,
});
typed!(fields HostOfferReply {
    2 devices: Vec<String>,
    3 sees: Cow<'static, str>,
    4 on: Vec<Hostable>,
});
asks!(HOST_OFFER: 188 "host-offer" HostOfferArgs -> HostOfferReply, writes);

typed!(fields HostAcceptArgs {
    1 who: Option<Reference>,
});
typed!(fields HostAcceptReply {
    2 sees: Cow<'static, str>,
});
asks!(HOST_ACCEPT: 189 "host-accept" HostAcceptArgs -> HostAcceptReply, writes);

typed!(fields HostEndArgs {
    1 who: Option<Reference>,
});
typed!(fields HostEndReply {
    2 ended: bool,
});
asks!(HOST_END: 190 "host-end" HostEndArgs -> HostEndReply, writes);

typed!(fields HostingArgs {});
typed!(
    fields
    /// Whom this person hosts, who hosts them, and the offers between,
    /// with the devices that can host someone now, or why none can.
    HostingReply {
        2 can: Vec<String>,
        3 hosting: Vec<Hosting>,
        4 why_not: Option<Cow<'static, str>>,
        5 devices: Vec<Hostable>,
    }
);
asks!(HOSTING_NOW: 191 "hosting" HostingArgs -> HostingReply, reads);

// ---- The service, and freeing space ----

typed!(fields StopArgs {});
asks!(STOP: 4 "stop" StopArgs -> Done, writes);

typed!(fields ReloadArgs {});
asks!(RELOAD: 5 "reload" ReloadArgs -> Done, writes);

typed!(fields KeepOldArgs {
    1 keep: Option<String>,
    2 space: Option<Reference>,
});
typed!(fields KeepOldReply {
    2 keep: String,
});
asks!(KEEP_OLD: 138 "keep-old" KeepOldArgs -> KeepOldReply, writes);

typed!(fields FreeSpaceArgs {
    1 dry_run: Option<bool>,
    /// Content that nothing names, in place of old versions.
    2 unnamed: Option<bool>,
    3 delete: Option<bool>,
});
typed!(
    fields
    /// What was freed: of old versions, with what is over the budget; of
    /// content nothing names, whether it was deleted and what is unsure.
    FreeSpaceReply {
        2 bytes: u64,
        3 deleted: Option<bool>,
        4 left: Option<u64>,
        5 objects: u64,
        6 only_here: Option<OnlyHere>,
        7 unchecked: Option<bool>,
        8 unsure: Option<Vec<String>>,
    }
);
asks!(FREE_SPACE: 139 "free-space" FreeSpaceArgs -> FreeSpaceReply, writes);

typed!(fields HistoryEmptyArgs {
    1 space: Option<Reference>,
});
typed!(fields HistoryEmptyReply {
    2 bytes: u64,
    3 left: u64,
    4 objects: u64,
});
asks!(HISTORY_EMPTY: 141 "history-empty" HistoryEmptyArgs -> HistoryEmptyReply, writes);

// ---- Reaching a contact ----

typed!(fields ContactStatusArgs {
    1 who: Option<Reference>,
    /// Look for them first.
    2 look: Option<bool>,
    /// Try them at this address first.
    3 at: Option<String>,
    4 after: Option<u64>,
    5 limit: Option<u64>,
});
typed!(
    fields
    /// Everything this device knows of reaching one contact.
    ContactStatusReply {
        2 devices: Vec<SessionDevice>,
        3 direct_sessions: bool,
        /// The start of their identity.
        4 identity: [u8; 8],
        5 in_use_for_s: Option<u64>,
        6 introductions: bool,
        7 last_look: Vec<Step>,
        8 look_every_s: u64,
        9 looked_for: Cow<'static, str>,
        10 looked_s_ago: Option<u64>,
        11 looking: bool,
        12 looking_since: Option<u64>,
        13 looks_without_session: u64,
        14 name: String,
        15 nearby: Nearby,
        16 nearby_tries: Vec<Step>,
        17 own: bool,
        18 refused: bool,
        19 router: Router,
        20 sessions: Vec<Step>,
        21 suggested: Option<String>,
        22 their_reach: Vec<ReachSeen>,
        23 trusted: bool,
        24 your_reach: Vec<ReachSeen>,
        25 more: bool,
        26 next: Option<u64>,
    }
);
asks!(CONTACT_STATUS: 32 "contact-status" ContactStatusArgs -> ContactStatusReply,
    reads unless look or at,
    after devices, last_look, nearby_tries, sessions, their_reach, your_reach);

// ---- Listings ----

typed!(fields ContactsArgs {
    1 all: Option<bool>,
    2 after: Option<u64>,
    3 limit: Option<u64>,
});
typed!(fields ContactsReply {
    2 contacts: Vec<Contact>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(CONTACTS: 30 "contacts" ContactsArgs -> ContactsReply, reads, after contacts);
typed!(fields ConversationsArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields ConversationsReply {
    2 conversations: Vec<Conversation>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(CONVERSATIONS: 33 "conversations" ConversationsArgs -> ConversationsReply, reads,
    after conversations by id);
typed!(fields ConflictsArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields ConflictsReply {
    2 conflicts: Vec<Conflict>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(CONFLICTS: 132 "conflicts" ConflictsArgs -> ConflictsReply, reads, after conflicts);
typed!(fields DevicesArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields DevicesReply {
    2 devices: Vec<Device>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(DEVICES: 11 "devices" DevicesArgs -> DevicesReply, reads, after devices);
typed!(fields InvitationsArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields InvitationsReply {
    2 invitations: Vec<Invitation>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(INVITATIONS: 44 "invitations" InvitationsArgs -> InvitationsReply, reads, after invitations by id);
typed!(fields IntroductionsArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields IntroductionsReply {
    2 introductions: Vec<Introduction>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(INTRODUCTIONS: 46 "introductions" IntroductionsArgs -> IntroductionsReply, reads,
    after introductions by id);
typed!(fields HistoryArgs {
    1 path: Option<String>,
    2 after: Option<u64>,
    3 limit: Option<u64>,
});
typed!(fields HistoryReply {
    2 path: String,
    3 versions: Vec<Version>,
    4 more: bool,
    5 next: Option<u64>,
});
asks!(HISTORY: 133 "history" HistoryArgs -> HistoryReply, reads, after versions);
typed!(fields SpaceUsageArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields SpaceUsageReply {
    2 spaces: Vec<SpaceUsage>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(SPACE_USAGE_NOW: 140 "space-usage" SpaceUsageArgs -> SpaceUsageReply, reads, after spaces);
typed!(fields PeerListArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields PeerListReply {
    2 peers: Vec<Peer>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(PEER_LIST: 187 "peer-list" PeerListArgs -> PeerListReply, reads, after peers);
typed!(fields DeletedArgs {
    1 path: Option<String>,
    2 after: Option<u64>,
    3 limit: Option<u64>,
    4 hidden: Option<bool>,
});
typed!(fields DeletedReply {
    2 files: Vec<DeletedFile>,
    3 path: String,
    4 more: bool,
    5 next: Option<u64>,
});
asks!(DELETED: 227 "deleted" DeletedArgs -> DeletedReply, reads, after files by id);

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

// ---- Setting up, removing a device, a contact's settings ----

typed!(fields SetupBeginArgs {});
typed!(fields SetupBeginReply {
    /// The places, from 0, of the two words the person is asked back.
    2 ask: Vec<u64>,
    3 words: Vec<String>,
});
asks!(SETUP_BEGIN: 8 "setup-begin" SetupBeginArgs -> SetupBeginReply, writes);
typed!(fields SetupFinishArgs {
    1 name: Option<String>,
    2 answers: Option<Vec<String>>,
    3 device: Option<String>,
});
typed!(fields SetupFinishReply {
    2 device: String,
    3 name: String,
});
asks!(SETUP_FINISH: 9 "setup-finish" SetupFinishArgs -> SetupFinishReply, writes);
typed!(fields RemoveDeviceArgs {
    1 who: Option<Reference>,
    2 lost: Option<bool>,
    3 words: Option<String>,
});
typed!(fields RemoveDeviceReply {
    2 dropped: u64,
    3 name: String,
});
asks!(REMOVE_DEVICE: 13 "remove-device" RemoveDeviceArgs -> RemoveDeviceReply, writes);
typed!(fields ContactArgs {
    1 who: Option<Reference>,
    2 setting: Option<String>,
    3 name: Option<String>,
    4 picture: Option<String>,
    5 category: Option<String>,
    6 host: Option<String>,
});
typed!(
    fields
    /// What changed: of a new name, the name (or, cleared, the name shown
    /// and whose it is); of a picture, the contact as shown; of a
    /// category, the category; of refusing, where they still read this
    /// person's hosts; of the hosts named to them, what is named now.
    ContactReply {
        2 category: Option<String>,
        3 name: Option<String>,
        4 own: Option<bool>,
        5 picture: Option<String>,
        6 reach: Option<Vec<GroupShown>>,
        7 suggested: Option<String>,
        8 named: Option<Cow<'static, str>>,
    }
);
asks!(CONTACT_CHANGE: 31 "contact" ContactArgs -> ContactReply, writes);

// ---- Inspection ----

typed!(fields InspectOnArgs {
    1 minutes: Option<u64>,
});
typed!(fields InspectOnReply {
    2 token: [u8; 32],
    3 until: u64,
});
asks!(INSPECT_ON: 200 "inspect-on" InspectOnArgs -> InspectOnReply, writes);
typed!(fields InspectOffArgs {});
typed!(fields InspectOffReply {
    2 was_on: bool,
});
asks!(INSPECT_OFF: 201 "inspect-off" InspectOffArgs -> InspectOffReply, writes);
typed!(fields InspectArgs {
    1 token: Option<Reference>,
    2 after: Option<u64>,
    3 limit: Option<u64>,
});
typed!(
    fields
    /// The overview: this device, its identity, the other logs and the
    /// spaces held here, and the store.
    InspectReply {
        2 device: InspectDevice,
        3 identity: Option<InspectIdentity>,
        4 others: Vec<OtherLog>,
        5 spaces: Vec<InspectSpace>,
        6 store: StoreShown,
        7 version: Cow<'static, str>,
        8 more: bool,
        9 next: Option<u64>,
    }
);
asks!(INSPECT: 202 "inspect" InspectArgs -> InspectReply, reads,
    after others by id, spaces by id);
typed!(fields InspectIdentityArgs {
    1 token: Option<Reference>,
    2 who: Option<Reference>,
    3 entry: Option<Reference>,
    4 path: Option<Vec<Scalar>>,
    5 value_bytes: Option<u64>,
    6 items: Option<u64>,
    7 after: Option<u64>,
    8 limit: Option<u64>,
});
typed!(
    fields
    /// An identity log, or (with `entry`) the value at `path` in one of
    /// its entries.
    InspectIdentityReply {
        2 attached: Option<Vec<AttachedLog>>,
        3 entries: Option<Vec<IdentityEntry>>,
        4 id: Option<[u8; 32]>,
        5 stalled: Option<Vec<[u8; 32]>>,
        6 value: Option<InspectValue>,
        7 more: bool,
        8 next: Option<u64>,
    }
);
asks!(INSPECT_IDENTITY_VIEW: 203 "inspect-identity" InspectIdentityArgs
    -> InspectIdentityReply, reads, after attached by id, entries by id, stalled);
typed!(fields InspectSpaceArgs {
    1 token: Option<Reference>,
    2 space: Option<Reference>,
    3 value_bytes: Option<u64>,
    4 items: Option<u64>,
    5 after: Option<u64>,
    6 limit: Option<u64>,
});
typed!(
    fields
    /// One space: what it is, who is in it, its epochs, and how its state
    /// is made up; of a space this device cannot open, its brief alone.
    InspectSpaceReply {
        2 account: bool,
        3 bytes: u64,
        4 conflicts: Option<u64>,
        5 created: Option<u64>,
        6 creator: Option<[u8; 32]>,
        7 current_epoch: Option<[u8; 16]>,
        8 entries: Option<u64>,
        9 epochs: Option<Vec<EpochShown>>,
        10 files: bool,
        11 heads: Option<Vec<[u8; 32]>>,
        12 id: [u8; 32],
        13 kinds: Option<Vec<KindCount>>,
        14 label: Option<String>,
        15 members: Option<Vec<SpaceMember>>,
        16 my_role: Option<u64>,
        17 nodes: Option<u64>,
        18 opened: bool,
        19 owner: Option<[u8; 32]>,
        20 pending: u64,
        21 policy: Option<PolicyShown>,
        22 profile: Option<Kind>,
        23 reach: Option<Vec<ReachNode>>,
        24 rejected: Option<u64>,
        25 root: Option<RootShown>,
        26 sealed: u64,
        27 stats: Option<StatsShown>,
        28 successor: Option<[u8; 32]>,
        29 unwitnessed: Option<u64>,
        30 valid: Option<u64>,
        31 more: bool,
        32 next: Option<u64>,
    }
);
asks!(INSPECT_SPACE_VIEW: 204 "inspect-space" InspectSpaceArgs -> InspectSpaceReply, reads,
    after epochs by id, heads, kinds, members, reach by id);
typed!(fields InspectEntriesArgs {
    1 token: Option<Reference>,
    2 space: Option<Reference>,
    /// `sealed`, as a host holds them, or else as a member reads them.
    3 view: Option<String>,
    4 gone offset: u64,
    5 gone count: u64,
    6 after: Option<u64>,
    7 limit: Option<u64>,
});
typed!(fields InspectEntriesReply {
    2 entries: Vec<InspectEntry>,
    3 gone offset: u64,
    4 pending: Option<u64>,
    5 total: u64,
    6 more: bool,
    7 next: Option<u64>,
});
asks!(INSPECT_ENTRIES: 205 "inspect-entries" InspectEntriesArgs -> InspectEntriesReply, reads,
    after entries precut);
typed!(fields InspectEntryArgs {
    1 token: Option<Reference>,
    2 space: Option<Reference>,
    3 entry: Option<Reference>,
    4 sealed_id: Option<Reference>,
    5 path: Option<Vec<Scalar>>,
    6 value_bytes: Option<u64>,
    7 items: Option<u64>,
    8 after: Option<u64>,
    9 limit: Option<u64>,
});
typed!(
    fields
    /// One entry whole, or (with `path`) the value at `path` within it.
    InspectEntryReply {
        2 accepted: Option<bool>,
        3 children: Option<Vec<[u8; 32]>>,
        4 entry: Option<[u8; 32]>,
        5 header: Option<InspectValue>,
        6 ops: Option<Vec<InspectOp>>,
        7 position: Option<u64>,
        8 sealed: Option<InspectValue>,
        9 sealed_id: Option<[u8; 32]>,
        10 signatures: Option<Vec<SignatureShown>>,
        11 valid: Option<bool>,
        12 weigh: Option<Weight>,
        13 value: Option<InspectValue>,
        14 more: bool,
        15 next: Option<u64>,
    }
);
asks!(INSPECT_ENTRY_VIEW: 206 "inspect-entry" InspectEntryArgs -> InspectEntryReply, reads,
    after children, ops, signatures);
typed!(fields InspectNodesArgs {
    1 token: Option<Reference>,
    2 space: Option<Reference>,
    3 kind: Option<Kind>,
    4 parent: Option<Reference>,
    5 gone offset: u64,
    6 gone count: u64,
    7 after: Option<u64>,
    8 limit: Option<u64>,
});
typed!(fields InspectNodesReply {
    2 nodes: Vec<NodeBrief>,
    3 gone offset: u64,
    4 total: u64,
    5 more: bool,
    6 next: Option<u64>,
});
asks!(INSPECT_NODES: 207 "inspect-nodes" InspectNodesArgs -> InspectNodesReply, reads,
    after nodes by id precut);
typed!(fields InspectNodeArgs {
    1 token: Option<Reference>,
    2 space: Option<Reference>,
    3 node: Option<Reference>,
    4 path: Option<Vec<Scalar>>,
    5 value_bytes: Option<u64>,
    6 items: Option<u64>,
    7 after: Option<u64>,
    8 limit: Option<u64>,
});
typed!(
    fields
    /// One node whole, or (with `path`) one of its values; the root and a
    /// reach node, which are no node of the state, as `special`.
    InspectNodeReply {
        2 bytes: Option<u64>,
        3 children: Option<u64>,
        4 created: Option<u64>,
        5 created_in: Option<[u8; 32]>,
        6 creator: Option<[u8; 32]>,
        7 delete_conflict: Option<bool>,
        8 deleted: Option<bool>,
        9 fields: Option<Vec<Vec<u64>>>,
        10 history: Option<Vec<NodeHistory>>,
        11 id: Option<[u8; 16]>,
        12 kind: Option<Kind>,
        13 name: Option<String>,
        14 parent: Option<[u8; 16]>,
        15 position: Option<u64>,
        16 special: Option<Cow<'static, str>>,
        17 values: Option<Vec<NodeField>>,
        18 value: Option<InspectValue>,
        19 more: bool,
        20 next: Option<u64>,
    }
);
asks!(INSPECT_NODE: 208 "inspect-node" InspectNodeArgs -> InspectNodeReply, reads,
    after fields, history, values);

// ---- Measuring, and the files brought back ----

typed!(fields DebugTreeArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(
    fields
    /// The mounted folder's tree as the service holds it; unmounted, the
    /// files space's heads and epoch alone.
    DebugTreeReply {
        2 deleted: Option<u64>,
        3 epoch: Option<[u8; 16]>,
        4 heads: [u8; 16],
        5 items: Option<Vec<TreeItem>>,
        6 mounted: bool,
        7 pending: Option<bool>,
        8 settle: Option<u64>,
        9 state: Option<[u8; 8]>,
        10 stuck: Option<Vec<StuckItem>>,
        11 unshown: Option<Vec<UnshownNode>>,
        12 more: bool,
        13 next: Option<u64>,
    }
);
asks!(DEBUG_TREE: 209 "debug-tree" DebugTreeArgs -> DebugTreeReply, reads,
    after items, stuck, unshown);
typed!(fields SpeedtestArgs {
    1 device: Option<Reference>,
});
typed!(fields SpeedtestReply {
    2 device: String,
    3 ms: u64,
    4 receive: u64,
    5 received_bytes: u64,
    6 rtt_median_us: u64,
    7 rtt_min_us: u64,
    8 send: u64,
    9 sent_bytes: u64,
});
// Changes nothing, but measures: a second answer is another measurement,
// never the same bytes, so it is answered once, as a writer is.
asks!(SPEEDTEST: 210 "speedtest" SpeedtestArgs -> SpeedtestReply, writes);
typed!(fields UndeleteArgs {
    1 path: Option<String>,
    2 id: Option<Reference>,
});
typed!(fields UndeleteReply {
    2 id: [u8; 16],
    3 path: String,
});
asks!(UNDELETE: 228 "undelete" UndeleteArgs -> UndeleteReply, writes);

// ---- Applications: what programs ask the person ----

typed!(fields AppQuestionsArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields AppQuestionsReply {
    2 questions: Vec<AppQuestion>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(APP_QUESTIONS: 220 "app-questions" AppQuestionsArgs -> AppQuestionsReply, reads,
    after questions);
typed!(fields AppAnswerArgs {
    1 id: Option<u64>,
    2 yes: Option<bool>,
    3 people: Option<Vec<Reference>>,
    4 role: Option<String>,
});
asks!(APP_ANSWER: 221 "app-answer" AppAnswerArgs -> Done, writes);
typed!(fields ApprovalsArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields ApprovalsReply {
    2 approvals: Vec<ApprovalShown>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(APPROVALS: 222 "approvals" ApprovalsArgs -> ApprovalsReply, reads, after approvals by id);
typed!(fields ApprovalRevokeArgs {
    1 id: Option<Reference>,
});
asks!(APPROVAL_REVOKE: 223 "approval-revoke" ApprovalRevokeArgs -> Done, writes);
typed!(fields AppOffersArgs {
    1 after: Option<u64>,
    2 limit: Option<u64>,
});
typed!(fields AppOffersReply {
    2 offers: Vec<AppOffer>,
    3 more: bool,
    4 next: Option<u64>,
});
asks!(APP_OFFERS: 224 "app-offers" AppOffersArgs -> AppOffersReply, reads, after offers);
typed!(fields AppJoinArgs {
    1 space: Option<Reference>,
});
typed!(fields AppJoinReply {
    2 space: [u8; 32],
    3 name: String,
});
asks!(APP_JOIN: 225 "app-join" AppJoinArgs -> AppJoinReply, writes);

/// A request no longer answered: its number stays taken.
pub static RECOVER_KEEP_SUCCESSION: Request = gone!(165 "recover-keep-succession" (
    1 "id" T, 2 "keep" BOOL) -> (2 "answered" U, 3 "kept" BOOL));

/// Every request, by number, as `$m!` takes them: each as `ask Args` (a
/// typed request answered by a reply), `stream Args` (one after which the
/// connection carries a stream, answered by the connection itself) or
/// `gone ROW` (a number no longer answered). Numbers are grouped by what
/// they are about, with room in each group.
///
/// This list is the one place the requests are listed: [`REQUESTS`] is
/// made from it here, and the service makes from it how each is answered,
/// so that a request it has no handler for does not compile; a client may
/// make from it whatever it needs of every request.
#[macro_export]
macro_rules! each_request {
    ($m:ident) => {
        $m! {
        // ---- The service, this device, and the person's devices: 1 to 29 ----
        ask HelloArgs,
        ask StatusArgs,
        stream WatchArgs,
        ask StopArgs,
        ask ReloadArgs,
        ask ConditionsArgs,
        ask NetworkChangedArgs,
        ask SetupBeginArgs,
        ask SetupFinishArgs,
        ask MeArgs,
        ask DevicesArgs,
        ask DeviceRenameArgs,
        ask RemoveDeviceArgs,
        ask PairShowArgs,
        ask PairStatusArgs,
        ask PairTypeArgs,
        // ---- People, conversations and invitations: 30 to 69 ----
        ask ContactsArgs,
        ask ContactArgs,
        ask ContactStatusArgs,
        ask ConversationsArgs,
        ask MessagesArgs,
        ask SayArgs,
        ask SaveAttachmentArgs,
        ask EditMessageArgs,
        ask DeleteMessageArgs,
        ask ReactArgs,
        ask MarkReadArgs,
        ask ReadMarkersArgs,
        ask InviteArgs,
        ask AcceptArgs,
        ask InvitationsArgs,
        ask CancelInvitationArgs,
        ask IntroductionsArgs,
        ask IntroduceArgs,
        ask IntroductionAcceptArgs,
        ask IntroductionDeclineArgs,
        // ---- Groups: 70 to 99 ----
        ask GroupsArgs,
        ask GroupCreateArgs,
        ask GroupJoinArgs,
        ask GroupDeclineArgs,
        ask GroupLeaveArgs,
        ask GroupReachArgs,
        ask GroupAddArgs,
        ask GroupRemoveArgs,
        ask GroupMembersArgs,
        ask GroupSetArgs,
        ask GroupMemberArgs,
        ask GroupConnectArgs,
        ask GroupRoleArgs,
        ask GroupPostAgainArgs,
        ask GroupMovedSeenArgs,
        ask GroupConfirmMoveArgs,
        ask GroupLeavingArgs,
        ask GroupRejoinArgs,
        // ---- Calls and the clipboard: 100 to 119 ----
        ask CallArgs,
        ask CallStartArgs,
        ask CallAnswerArgs,
        ask CallEndArgs,
        stream CallMediaArgs,
        ask ClipCopyArgs,
        ask ClipArgs,
        // ---- The one folder: 120 to 149 ----
        ask FilesArgs,
        ask MkdirArgs,
        ask MoveArgs,
        ask RemoveArgs,
        ask CopyArgs,
        ask PutArgs,
        ask SaveArgs,
        ask WriteArgs,
        ask ShareArgs,
        ask MountArgs,
        ask UnmountArgs,
        ask FlushArgs,
        ask ConflictsArgs,
        ask HistoryArgs,
        ask RestoreArgs,
        ask PinArgs,
        ask UnpinArgs,
        ask RetentionArgs,
        ask KeepOldArgs,
        ask FreeSpaceArgs,
        ask SpaceUsageArgs,
        ask HistoryEmptyArgs,
        // ---- Guardians and recovery: 150 to 179 ----
        ask GuardiansArgs,
        ask GuardiansSetArgs,
        ask GuardiansObjectArgs,
        ask GuardiansAskArgs,
        ask GuardingArgs,
        ask GuardingInviteArgs,
        ask GuardingAcceptArgs,
        ask GuardingConfirmChangeArgs,
        ask GuardingNeverArgs,
        ask GuardingCautionArgs,
        ask GuardingEndorseArgs,
        ask GuardingConfirmArgs,
        ask RecoverArgs,
        ask RecoverStartArgs,
        ask RecoverInviteArgs,
        gone RECOVER_KEEP_SUCCESSION,
        ask RecoverLostAtArgs,
        ask RecoverCancelArgs,
        ask RecoverFinishArgs,
        ask KeepWorkArgs,
        ask RecoveryCheckArgs,
        ask RecoverySheetArgs,
        ask RestoreFromHostArgs,
        ask RecoverUndoArgs,
        ask RecoverKeptSeenArgs,
        ask RecoverStopWaitingArgs,
        // ---- Networks, hosts and peers: 180 to 199 ----
        ask RouterArgs,
        ask BluetoothArgs,
        ask NetworkArgs,
        ask HostArgs,
        ask HostOffArgs,
        ask PeerAddArgs,
        ask PeerRemoveArgs,
        ask PeerListArgs,
        ask HostOfferArgs,
        ask HostAcceptArgs,
        ask HostEndArgs,
        ask HostingArgs,
        // ---- Inspection and measuring: 200 to 219 ----
        ask InspectOnArgs,
        ask InspectOffArgs,
        ask InspectArgs,
        ask InspectIdentityArgs,
        ask InspectSpaceArgs,
        ask InspectEntriesArgs,
        ask InspectEntryArgs,
        ask InspectNodesArgs,
        ask InspectNodeArgs,
        ask DebugTreeArgs,
        ask SpeedtestArgs,
        // ---- Applications: 220 to 239 ----
        ask AppQuestionsArgs,
        ask AppAnswerArgs,
        ask ApprovalsArgs,
        ask ApprovalRevokeArgs,
        ask AppOffersArgs,
        ask AppJoinArgs,
        ask WakeArgs,
        ask DeletedArgs,
        ask UndeleteArgs,
        }
    };
}

/// [`REQUESTS`], from [`each_request!`]; and a request listed as a
/// stream is declared one (`asks!(..., stream)`), and one not, not.
macro_rules! request_rows {
    ($($how:ident $x:ident,)*) => {
        /// Every request, by number ([`each_request!`]).
        pub static REQUESTS: &[Request] = &[$(request_rows!(@row $how $x)),*];
        $(request_rows!(@check $how $x);)*
    };
    (@row gone $row:ident) => { $row };
    (@row $how:ident $args:ident) => { *<$args as super::typed::Ask>::REQUEST };
    (@check gone $row:ident) => {};
    (@check ask $args:ident) => {
        const _: () = assert!(
            !<$args as super::typed::Ask>::STREAM,
            concat!(stringify!($args), " is a stream's: list it as `stream`")
        );
    };
    (@check stream $args:ident) => {
        const _: () = assert!(
            <$args as super::typed::Ask>::STREAM,
            concat!(stringify!($args), " is not a stream's: list it as `ask`")
        );
    };
}

each_request!(request_rows);

/// The requests this implementation answers that `apps.md` does not
/// describe in words, the node's own: marked in its tables (†), and in the
/// export.
pub static NODE_ONLY: &[&str] = &[
    "stop",
    "reload",
    "remove-device",
    "contacts",
    "read-markers",
    "group-post-again",
    "group-moved-seen",
    "mount",
    "unmount",
    "flush",
    "conflicts",
    "pin",
    "unpin",
    "retention",
    "keep-old",
    "free-space",
    "space-usage",
    "history-empty",
    "guardians",
    "guardians-set",
    "guardians-object",
    "guardians-ask",
    "guarding",
    "guarding-invite",
    "guarding-accept",
    "guarding-confirm-change",
    "guarding-never",
    "guarding-caution",
    "guarding-endorse",
    "guarding-confirm",
    "recover",
    "recover-start",
    "recover-invite",
    "recover-lost-at",
    "recover-undo",
    "recover-kept-seen",
    "recover-stop-waiting",
    "recover-cancel",
    "recover-finish",
    "keep-work",
    "recovery-check",
    "recovery-sheet",
    "restore-from-host",
    "router",
    "bluetooth",
    "network",
    "host",
    "host-off",
    "peer-add",
    "peer-remove",
    "peer-list",
    "inspect-on",
    "inspect-off",
    "inspect",
    "inspect-identity",
    "inspect-space",
    "inspect-entries",
    "inspect-entry",
    "inspect-nodes",
    "inspect-node",
    "debug-tree",
    "speedtest",
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
        4 store: Cow<'static, str> where "empty" | "current" | "other" | "unreadable",
        5 written_by: Option<Cow<'static, str>>,
    }
);

/// What the service's program says when asked, typed: its row, `ROW`, for
/// [`PROGRAM`], from its reply's declaration. The program writes it and
/// exits; nothing answers it on the socket.
macro_rules! program {
    ($row:ident: $n:literal $name:literal -> $reply:ident) => {
        #[doc = concat!("The row of `", $name, "`, typed.")]
        pub static $row: Request = Request {
            n: $n,
            name: $name,
            args: &[],
            reply: <$reply as Fields>::FIELDS,
            page: Page::Whole,
            gone: false,
            stream: false,
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

/// The messages of a stream, typed: each one's row, `ROW`, from its typed
/// fields; the table of them all, `TABLE` ([`EVENTS`], [`FRAMES`]); and
/// `Enum`, one of them read by its key 0, written once for every stream.
macro_rules! streams {
    (
        $(#[$m:meta])*
        $table:ident $enum:ident {
            $($n:literal $name:literal $variant:ident($fields:ident) as $row:ident),* $(,)?
        }
    ) => {
        $(
            #[doc = concat!("The row of `", $name, "`, typed.")]
            pub static $row: Request = Request {
                n: $n,
                name: $name,
                args: <$fields as Fields>::FIELDS,
                reply: &[],
                page: Page::Whole,
                gone: false,
                stream: false,
            };

            impl super::typed::Streamed for $fields {
                const KIND: &'static Request = &$row;
            }
        )*

        $(#[$m])*
        pub static $table: &[Request] = &[$($row),*];

        #[doc = concat!(
            "A message of the stream [`", stringify!($table), "`] lists, typed by its key 0."
        )]
        #[derive(Clone, Debug, PartialEq)]
        pub enum $enum {
            $(
                #[doc = concat!("`", $name, "`.")]
                $variant($fields),
            )*
        }

        impl $enum {
            /// A message off the wire, read straight from its bytes as the
            /// record its key 0 names; none, for one this build does not
            /// know (a later service's), passed over. One that is not one
            /// canonical record, has no number in key 0, or is not what
            /// its number says is [`Unreadable`](super::typed::Unreadable),
            /// in the words [`Self::read_tree`] says it in.
            pub fn read(msg: &[u8]) -> Result<Option<Self>, super::typed::Unreadable> {
                super::typed::read_message(msg, |w| {
                    Ok(match super::typed::kind_of(w)? {
                        $($n => Some($enum::$variant(<$fields as Fields>::read_fields(
                            w,
                            &super::typed::At::Top($name),
                        )?)),)*
                        _ => None,
                    })
                })
                .map_err(super::typed::Unreadable)
            }

            /// The same, the way through the encoding's tree: what
            /// [`Self::read`] is held to.
            pub fn read_tree(msg: &[u8]) -> Result<Option<Self>, super::typed::Unreadable> {
                let (n, r) = super::typed::stream_record(msg)?;
                let at = |name| super::typed::At::Top(name);
                Ok(match n {
                    $($n => Some($enum::$variant(
                        <$fields as Fields>::take_fields(r, &at($name))
                            .map_err(super::typed::Unreadable)?,
                    )),)*
                    _ => None,
                })
            }

            /// It as a message.
            pub fn message(&self) -> Vec<u8> {
                match self {
                    $($enum::$variant(m) => super::typed::Streamed::message(m),)*
                }
            }

            /// Its row.
            pub fn kind(&self) -> &'static Request {
                match self {
                    $($enum::$variant(_) => &$row,)*
                }
            }
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
streams! {
    /// The events of a `watch` connection: key 0 says which.
    EVENTS Event {
        1 "changed" Changed(Changed) as EVENT_CHANGED,
    }
}

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
typed!(
    fields
    /// From the window, in a group: the level it asks of the sender `from`
    /// (`basics/video.md#groups`).
    LevelFrame {
        1 level: u64,
        3 from: Option<[u8; 8]>,
    }
);
typed!(
    fields
    /// To the window, in a group: whether small and large pictures of its
    /// own are asked for.
    AskedFrame {
        1 small: bool,
        2 large: bool,
    }
);
typed!(
    fields
    /// A key picture of the size `size`: from the window, asked of the
    /// sender `from`; to it, asked of its own.
    KeyFrame {
        3 from: Option<[u8; 8]>,
        4 size: u64,
    }
);
typed!(
    fields
    /// From the window: whether this person's camera is on
    /// (`basics/video.md#cameras`).
    CameraFrame {
        1 camera: bool,
    }
);

streams! {
    /// The frames of a `call-media` connection, both ways: key 0 says which.
    /// `from` is the voice a frame of a group call is, from the service, or
    /// the sender a window's level or key picture is asked of.
    FRAMES Frame {
        1 "audio" Audio(AudioFrame) as FRAME_AUDIO,
        2 "frame" Other(OtherFrame) as FRAME_OTHER,
        3 "viewport" Viewport(ViewportFrame) as FRAME_VIEWPORT,
        4 "level" Level(LevelFrame) as FRAME_LEVEL,
        5 "asked" Asked(AskedFrame) as FRAME_ASKED,
        6 "key" Key(KeyFrame) as FRAME_KEY,
        7 "camera" Camera(CameraFrame) as FRAME_CAMERA,
    }
}
