//! A client's side of the local interface: a request asked with its
//! arguments' own type, and its reply read typed, page after page where it
//! comes in pages (`apps.md`, Pages), with no tree of names between.
//!
//! Nothing here does I/O. [`Pages`] is what is asked next and what is made
//! of each reply, for a client that carries the messages itself (the
//! command line does, over its asynchronous socket); [`ask`] carries them
//! through a [`Transport`] the client gives, one request's message out and
//! its reply's back, and is all most clients need:
//!
//! ```
//! # use cardinal_interface::client::{ask, Transport};
//! # struct Socket;
//! # impl Transport for Socket {
//! #     type Error = Box<dyn std::error::Error>;
//! #     fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>, Self::Error> {
//! #         Ok(cardinal_interface::error_reply(1, "no service here"))
//! #     }
//! # }
//! # let mut socket = Socket;
//! use cardinal_interface::{typed::Reference, MessagesArgs};
//!
//! let args = MessagesArgs {
//!     who: Some(Reference::Typed("Ana".into())),
//!     ..MessagesArgs::new()
//! };
//! match ask(&mut socket, &args)? {
//!     // every page, oldest first
//!     Ok(reply) => println!("{} messages", reply.messages.len()),
//!     // the service's answer that it could not
//!     Err(failed) => println!("{failed}"),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! A request whose reply comes in pages is asked for page after page, and
//! the reply holds every page's items, unless its arguments ask for one
//! page themselves (`limit`, `after` or `before`). The paging is written
//! once over `dyn` [`Paging`], so a client's code does not grow with each
//! request it asks.
//!
//! **An item too large for a message on its own** is error 4, which names
//! it by its place (`at`) and its `id` (`apps.md`, Pages). [`ask`] stops
//! there, and the reply is that failure. [`ask_past`] (or
//! [`Pages::past_too_large`]) goes on past it, as a window does: it asks
//! again from one more than its place, or before its id
//! ([`Ask::past`], made from each request's declaration), and the reply
//! holds every other item. The item left out cannot be had through the
//! interface at all, since no message can hold it: a client shows the
//! rest and says that so many were left out ([`Whole::left_out`], each the
//! error 4 that named one, with its `at`, `id` and why).
//!
//! **Replies are read straight from their bytes** ([`read_reply`](crate::typed::read_reply)), and a
//! stream's messages by their key 0 ([`Event::read`](crate::Event::read),
//! [`Frame::read`](crate::Frame::read)): no tree of the encoding between.

use cardinal_encoding::Cursor;

use crate::typed::{reply_done, reply_fields, Ask, At, Failed, Unencodable, Unreadable, Walk};
use crate::Request;

/// Carries one request's message to the service and its reply's back: a
/// socket, a named pipe, a test's own service. A message is at most
/// [`MAX_MESSAGE`](crate::MAX_MESSAGE) bytes either way.
pub trait Transport {
    /// How carrying a message can fail; and what a request that cannot be
    /// sent, or a reply that cannot be read, is said as.
    type Error: From<Unencodable> + From<Unreadable>;
    /// Sends `request` and returns the reply to it.
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// Asks `args` over `t`: the reply, every page of it joined, or how the
/// service said it failed. An error is the transport's, a request the
/// encoding cannot hold ([`Unencodable`]), or a reply that is not what the
/// request answers ([`Unreadable`]).
pub fn ask<A: Ask, T: Transport + ?Sized>(
    t: &mut T,
    args: &A,
) -> Result<Result<A::Reply, Failed>, T::Error> {
    let mut pages = Pages::new(args);
    asking(t, &mut pages)?;
    Ok(pages.done())
}

/// Asks `args` over `t` as [`ask`] does, going on past each item too large
/// for a message on its own: the reply holds every other item, and says
/// which were left out.
pub fn ask_past<A: Ask, T: Transport + ?Sized>(
    t: &mut T,
    args: &A,
) -> Result<Result<Whole<A::Reply>, Failed>, T::Error> {
    let mut pages = Pages::new(args).past_too_large();
    asking(t, &mut pages)?;
    Ok(pages.whole())
}

/// A reply, every page of it joined, and the items left out of it: each
/// too large for a message on its own, named by the error 4 that said so.
#[derive(Debug, Clone, PartialEq)]
pub struct Whole<R> {
    pub reply: R,
    pub left_out: Vec<Failed>,
}

/// [`ask`], written once for every request.
fn asking<T: Transport + ?Sized>(t: &mut T, p: &mut dyn Paging) -> Result<(), T::Error> {
    while let Some(msg) = p.next()? {
        let reply = t.exchange(&msg)?;
        if !p.took(&reply)? {
            break;
        }
    }
    Ok(())
}

/// A typed request asked page after page: what was asked last, and the
/// pages joined so far, or how one failed. What is done with an item too
/// large for a message on its own is `P`: by default [`Stop`], which ends
/// the asking with that refusal, as before, and costs nothing; or
/// [`GoPast`] ([`Pages::past_too_large`]).
pub struct Pages<A: Ask, P: Past<A> = Stop> {
    /// Whether the arguments asked for one page themselves.
    one_page: bool,
    asked: A,
    all: Option<A::Reply>,
    /// The refusal read last, which ended the asking unless it was gone
    /// past.
    failed: Option<Failed>,
    past: P,
}

/// What a request asked page after page does with an item too large for
/// a message on its own, which error 4 names.
pub trait Past<A> {
    /// Whether the refusal just read, `failed`, was gone past: `asked`
    /// then moved past the item, and the refusal taken out of `failed`.
    fn went_past(&mut self, asked: &mut A, failed: &mut Option<Failed>) -> bool;
    /// Whether what is asked next is `asked` again, moved past such an
    /// item, rather than the page after the last.
    fn moved(&mut self) -> bool;
}

/// An item too large ends the asking, as the reply's failure.
pub struct Stop;

impl<A> Past<A> for Stop {
    #[inline]
    fn went_past(&mut self, _: &mut A, _: &mut Option<Failed>) -> bool {
        false
    }
    #[inline]
    fn moved(&mut self) -> bool {
        false
    }
}

/// An item too large is left out, and the asking goes on past it, from one
/// more than its place or before its id ([`Ask::past`]); the refusals that
/// named the items left out are kept.
#[derive(Default)]
pub struct GoPast {
    left_out: Vec<Failed>,
    moved: bool,
}

impl<A: Ask> Past<A> for GoPast {
    fn went_past(&mut self, asked: &mut A, failed: &mut Option<Failed>) -> bool {
        let Some(next) = failed.as_ref().and_then(|f| asked.past(f)) else {
            return false;
        };
        *asked = next;
        self.left_out.extend(failed.take());
        self.moved = true;
        true
    }
    #[inline]
    fn moved(&mut self) -> bool {
        std::mem::take(&mut self.moved)
    }
}

/// What is done with a request asked page after page, whatever its type:
/// the message to send next, and what to make of its reply. A client that
/// carries messages itself drives it ([`Pages`] is one): `next` until it
/// gives none, each message's reply to `took` until it says to stop.
pub trait Paging {
    /// Its row.
    fn request(&self) -> &'static Request;
    /// The next page's request, as a message, if one is to be asked.
    fn next(&mut self) -> Result<Option<Vec<u8>>, Unencodable>;
    /// Takes the reply to the message [`Paging::next`] gave: whether to
    /// go on.
    fn took(&mut self, reply: &[u8]) -> Result<bool, Unreadable>;
}

impl<A: Ask> Pages<A> {
    /// `args`, not yet asked. An item too large for a message on its own
    /// ends the asking, as the reply's failure.
    pub fn new(args: &A) -> Self {
        Pages {
            one_page: args.one_page(),
            asked: args.clone(),
            all: None,
            failed: None,
            past: Stop,
        }
    }

    /// Goes on past each item too large for a message on its own, which
    /// error 4 names, leaving it out ([`Pages::left_out`]): from one more
    /// than its place, or before its id ([`Ask::past`]). Of a page asked
    /// for itself, the page is then the one from past it.
    pub fn past_too_large(self) -> Pages<A, GoPast> {
        Pages {
            one_page: self.one_page,
            asked: self.asked,
            all: self.all,
            failed: self.failed,
            past: GoPast::default(),
        }
    }
}

impl<A: Ask, P: Past<A>> Pages<A, P> {
    /// Asks page after page even where the arguments give `limit`, which
    /// is then the most each page holds: for a client that reads the
    /// pages as they come ([`Pages::so_far`]) and stops when it has enough.
    pub fn every_page(mut self) -> Self {
        self.one_page = false;
        self
    }

    /// The pages joined so far, if one has come.
    pub fn so_far(&self) -> Option<&A::Reply> {
        self.all.as_ref()
    }

    /// Whether the last page said more comes after it (or, back from the
    /// newest, before it).
    pub fn more(&self) -> bool {
        self.all
            .as_ref()
            .is_some_and(|all| self.asked.next_page(all).is_some())
    }

    /// The reply, every page joined, or how a page failed; once
    /// [`Paging::next`] has given none, or [`Paging::took`] said to stop.
    ///
    /// # Panics
    ///
    /// Before a reply was taken.
    #[inline(never)]
    pub fn done(self) -> Result<A::Reply, Failed> {
        if let Some(f) = self.failed {
            return Err(f);
        }
        let mut all = self.all.expect("a reply was read");
        if !self.one_page {
            A::whole(&mut all);
        }
        Ok(all)
    }
}

impl<A: Ask> Pages<A, GoPast> {
    /// The items left out so far, each too large for a message on its own:
    /// the error 4 that named it.
    pub fn left_out(&self) -> &[Failed] {
        &self.past.left_out
    }

    /// [`Pages::done`], with the items left out.
    ///
    /// # Panics
    ///
    /// Before a reply was taken.
    pub fn whole(mut self) -> Result<Whole<A::Reply>, Failed> {
        let left_out = std::mem::take(&mut self.past.left_out);
        self.done().map(|reply| Whole { reply, left_out })
    }
}

impl<A: Ask, P: Past<A>> Paging for Pages<A, P> {
    fn request(&self) -> &'static Request {
        A::REQUEST
    }
    fn next(&mut self) -> Result<Option<Vec<u8>>, Unencodable> {
        if self.failed.is_some() {
            return Ok(None);
        }
        if self.past.moved() {
            return self.asked.encode().map(Some);
        }
        match &self.all {
            None => self.asked.encode().map(Some),
            Some(_) if self.one_page => Ok(None),
            Some(all) => match self.asked.next_page(all) {
                Some(next) => {
                    let msg = next.encode()?;
                    self.asked = next;
                    Ok(Some(msg))
                }
                None => Ok(None),
            },
        }
    }
    fn took(&mut self, reply: &[u8]) -> Result<bool, Unreadable> {
        // a refusal is read into `failed` by code written once
        let mut c = Cursor::new(reply);
        let mut w = Walk::open(&mut c);
        if !reply_done(&mut w, reply, &mut self.failed)? {
            return Ok(self.past.went_past(&mut self.asked, &mut self.failed));
        }
        let page = reply_fields(&mut w, reply, &At::Top(A::REQUEST.name))?;
        match &mut self.all {
            None => {
                self.all = Some(page);
                Ok(true)
            }
            Some(all) => Ok(A::join(all, page)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed::Reference;
    use crate::{decode_record, File, FilesArgs, FilesReply, Message, MessagesArgs, MessagesReply};
    use crate::{Place, MAX_MESSAGE};

    /// A service of its own, in this crate alone: a folder of `entries`
    /// and a conversation of `said`, each answered and cut to its pages by
    /// the declarations, as the service answers them.
    struct Service {
        entries: Vec<File>,
        said: Vec<Message>,
        asked: Vec<Vec<u8>>,
    }

    impl Transport for Service {
        type Error = String;
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, String> {
            self.asked.push(request.to_vec());
            assert!(request.len() <= MAX_MESSAGE);
            let (spec, r) = decode_record(request).map_err(|e| e.why)?;
            let reply = match spec.name {
                "files" => {
                    let a = FilesArgs::from_request(r).map_err(|e| e.why)?;
                    let place = crate::new!(Place {
                        kind: "mine".into()
                    });
                    let reply = crate::new!(FilesReply {
                        files: self.entries.clone(),
                        path: String::new(),
                        place,
                        more: false
                    });
                    a.reply_bytes(reply)
                }
                "messages" => {
                    let a = MessagesArgs::from_request(r).map_err(|e| e.why)?;
                    // what the service holds before `before`, as its handler gives it
                    let upto = match &a.before {
                        Some(Reference::Id(id)) => {
                            self.said.iter().position(|m| m.id[..] == id[..]).unwrap()
                        }
                        _ => self.said.len(),
                    };
                    let mut reply = crate::new!(MessagesReply {
                        messages: self.said[..upto].to_vec(),
                        more: false
                    });
                    reply.name = Some("Ana".into());
                    a.reply_bytes(reply)
                }
                other => crate::error_reply(crate::status::UNKNOWN, other),
            };
            assert!(reply.len() <= MAX_MESSAGE);
            Ok(reply)
        }
    }

    impl From<Unencodable> for String {
        fn from(e: Unencodable) -> String {
            e.0
        }
    }

    impl From<Unreadable> for String {
        fn from(e: Unreadable) -> String {
            e.to_string()
        }
    }

    fn entry(i: usize) -> File {
        crate::new!(File {
            folder: false,
            name: format!("{i:05} {}", "x".repeat(200))
        })
    }

    fn said(i: u8, text: String) -> Message {
        crate::new!(Message {
            attachments: Vec::new(),
            edited: false,
            id: [i; 16],
            mine: i % 2 == 0,
            reactions: Vec::new(),
            text
        })
    }

    /// A folder too large for one message comes in pages, asked one after
    /// the other and joined in order, with no `more` or `next` left.
    #[test]
    fn a_paged_reply_is_asked_page_after_page_and_joined() {
        let n = MAX_MESSAGE / 200 * 3;
        let mut s = Service {
            entries: (0..n).map(entry).collect(),
            said: Vec::new(),
            asked: Vec::new(),
        };
        let files = ask(&mut s, &FilesArgs::new()).unwrap().unwrap();
        assert!(s.asked.len() >= 3, "{} pages", s.asked.len());
        assert_eq!(files.files.len(), n);
        assert!(files.files.iter().enumerate().all(|(i, f)| *f == entry(i)));
        assert_eq!((files.more, files.next), (false, None));
        // a page asked for itself is that page alone
        let one = FilesArgs {
            limit: Some(5),
            ..FilesArgs::new()
        };
        let files = ask(&mut s, &one).unwrap().unwrap();
        assert_eq!(files.files.len(), 5);
        assert_eq!((files.more, files.next), (true, Some(5)));
    }

    /// Back from the newest, by the id of the oldest had: every message,
    /// oldest first, the reply's other fields as the first page gave them.
    #[test]
    fn a_reply_paged_back_from_the_newest_is_joined_oldest_first() {
        let big = |i: u8| said(i, format!("{i} {}", "y".repeat(MAX_MESSAGE / 5)));
        let mut s = Service {
            entries: Vec::new(),
            said: (0..12).map(big).collect(),
            asked: Vec::new(),
        };
        let args = MessagesArgs {
            who: Some(Reference::Typed("Ana".into())),
            ..MessagesArgs::new()
        };
        let reply = ask(&mut s, &args).unwrap().unwrap();
        assert!(s.asked.len() > 2);
        assert_eq!(reply.messages, s.said);
        assert_eq!(reply.name.as_deref(), Some("Ana"));
        assert_eq!((reply.more, reply.next), (false, None));
    }

    /// The service's refusal is the reply's `Failed`; a reply that is not
    /// what was asked is the client's error, not a refusal.
    #[test]
    fn a_refusal_and_a_reply_that_cannot_be_read() {
        struct Refusing;
        impl Transport for Refusing {
            type Error = String;
            fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>, String> {
                Ok(crate::error_reply(crate::status::FAILED, "no such folder"))
            }
        }
        let failed = ask(&mut Refusing, &FilesArgs::new()).unwrap().unwrap_err();
        assert_eq!((failed.status, failed.why.as_str()), (1, "no such folder"));
        struct Garbled;
        impl Transport for Garbled {
            type Error = String;
            fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>, String> {
                // a reply that says it was done, without the files
                Ok(crate::__private::Record::new().with(0, 0u64).encode())
            }
        }
        let e = ask(&mut Garbled, &FilesArgs::new()).unwrap_err();
        assert!(e.contains("files.files is missing"), "{e}");
    }

    /// An item too large for a message on its own stops `ask`, as the
    /// reply's failure; `ask_past` goes on past it, after one more than its
    /// place, or before its id, and says which it left out.
    #[test]
    fn an_item_too_large_is_gone_past_where_asked() {
        let mut entries: Vec<File> = (0..2_000).map(entry).collect();
        entries[1_500] = crate::new!(File {
            folder: false,
            name: "y".repeat(MAX_MESSAGE)
        });
        let mut s = Service {
            entries,
            said: Vec::new(),
            asked: Vec::new(),
        };
        let failed = ask(&mut s, &FilesArgs::new()).unwrap().unwrap_err();
        assert_eq!(
            (failed.status, failed.at),
            (crate::status::TOO_LARGE, Some(1_500))
        );
        let whole = ask_past(&mut s, &FilesArgs::new()).unwrap().unwrap();
        assert_eq!(whole.reply.files.len(), 1_999);
        assert!(whole.reply.files.iter().all(|f| f.name.len() < 300));
        assert_eq!(whole.reply.files[1_500], entry(1_501));
        assert_eq!(whole.left_out.len(), 1);
        assert_eq!(whole.left_out[0].at, Some(1_500));
        assert_eq!((whole.reply.more, whole.reply.next), (false, None));

        // back from the newest: before the id of the one too large
        let small = |i: u8| said(i, format!("{i}"));
        let mut said_all: Vec<Message> = (0..10).map(small).collect();
        said_all[6] = said(6, "z".repeat(MAX_MESSAGE));
        let mut s = Service {
            entries: Vec::new(),
            said: said_all,
            asked: Vec::new(),
        };
        let args = MessagesArgs {
            who: Some(Reference::Typed("Ana".into())),
            limit: Some(2),
            ..MessagesArgs::new()
        };
        // a page asked for itself: the two newest
        let one = ask_past(&mut s, &args).unwrap().unwrap();
        assert_eq!(one.reply.messages, [small(8), small(9)]);
        assert!(one.reply.more);
        // page after page, two at a time, until enough
        s.asked.clear();
        let mut pages = Pages::new(&args).every_page().past_too_large();
        while let Some(msg) = pages.next().unwrap() {
            let reply = s.exchange(&msg).unwrap();
            if !pages.took(&reply).unwrap() {
                break;
            }
            if pages.so_far().is_some_and(|r| r.messages.len() >= 5) {
                break;
            }
        }
        assert!(pages.more(), "older ones are left");
        let whole = pages.whole().unwrap();
        let ids: Vec<u8> = whole.reply.messages.iter().map(|m| m.id[0]).collect();
        assert_eq!(ids, [4, 5, 7, 8, 9]);
        assert_eq!(whole.left_out.len(), 1);
        assert_eq!(whole.left_out[0].id.as_deref(), Some(&[6u8; 16][..]));
        // asked: the newest two; before 8, 7 alone (6 does not fit beside
        // it); before 7, error 4 for 6; before 6, two more
        assert_eq!(s.asked.len(), 4);
    }

    /// A listing whose every item is too large for a message is answered
    /// empty, every item left out, as the old pagers did; and an error 4
    /// naming an item before where the page began ends the asking.
    #[test]
    fn every_item_too_large_is_an_empty_answer() {
        let huge = |i: usize| {
            crate::new!(File {
                folder: false,
                name: format!("{i} {}", "z".repeat(MAX_MESSAGE))
            })
        };
        let mut s = Service {
            entries: (0..3).map(huge).collect(),
            said: Vec::new(),
            asked: Vec::new(),
        };
        let whole = ask_past(&mut s, &FilesArgs::new()).unwrap().unwrap();
        assert!(whole.reply.files.is_empty());
        let at: Vec<Option<u64>> = whole.left_out.iter().map(|f| f.at).collect();
        assert_eq!(at, [Some(0), Some(1), Some(2)]);
        // a service naming an item before the page: no going back
        struct Behind;
        impl Transport for Behind {
            type Error = String;
            fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>, String> {
                Ok(crate::typed::too_large_message("too large", 0, None))
            }
        }
        let args = FilesArgs {
            after: Some(5),
            ..FilesArgs::new()
        };
        let failed = ask_past(&mut Behind, &args).unwrap().unwrap_err();
        assert_eq!(
            (failed.status, failed.at),
            (crate::status::TOO_LARGE, Some(0))
        );
    }

    /// A refusal is what the reply said: an empty why stays empty, and is
    /// worded by its status's name only for a person.
    #[test]
    fn a_refusal_keeps_what_it_said() {
        struct Saying(&'static str);
        impl Transport for Saying {
            type Error = String;
            fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>, String> {
                Ok(crate::error_reply(crate::status::TOO_LARGE, self.0))
            }
        }
        let failed = ask(&mut Saying(""), &FilesArgs::new())
            .unwrap()
            .unwrap_err();
        assert_eq!((failed.why.as_str(), failed.words()), ("", "too large"));
        assert_eq!(failed.to_string(), "too large");
        let failed = ask(&mut Saying("too large"), &FilesArgs::new())
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (failed.why.as_str(), failed.words()),
            ("too large", "too large")
        );
        // an error without why, or whose `at` is not a uint, is unreadable
        struct Odd(crate::__private::Record);
        impl Transport for Odd {
            type Error = String;
            fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>, String> {
                Ok(self.0.encode())
            }
        }
        let r = crate::__private::Record::new().with(0, 1u64);
        let e = ask(&mut Odd(r.clone()), &FilesArgs::new()).unwrap_err();
        assert!(e.contains("error.why is missing"), "{e}");
        let e = ask(&mut Odd(r.with(1, "x").with(2, "two")), &FilesArgs::new()).unwrap_err();
        assert!(e.contains("error.at should be an unsigned integer"), "{e}");
    }

    /// A stream's message is read by its key 0 as its own record; one of a
    /// kind this build does not know is passed over, and one that is not
    /// what its kind says is unreadable.
    #[test]
    fn a_streams_message_is_read_by_its_key_0() {
        use crate::{AudioFrame, Event, Frame, ViewportFrame};
        let v = crate::new!(ViewportFrame {
            width: 640,
            height: 480
        });
        let msg = Frame::Viewport(v.clone()).message();
        assert_eq!(Frame::read(&msg).unwrap(), Some(Frame::Viewport(v)));
        let audio = AudioFrame {
            from: Some([2; 8]),
            ..crate::new!(AudioFrame {
                audio: crate::Bytes::from_static(b"opus")
            })
        };
        let msg = Frame::Audio(audio.clone()).message();
        assert_eq!(Frame::read(&msg).unwrap(), Some(Frame::Audio(audio)));
        assert_eq!(
            Event::read(&crate::event_message(7)).unwrap(),
            Some(Event::Changed(crate::Changed { seq: 7 }))
        );
        let later = crate::__private::Record::new().with(0, 99u64).with(1, "x");
        assert_eq!(Frame::read(&later.encode()).unwrap(), None);
        let wrong = crate::__private::Record::new()
            .with(0, 3u64)
            .with(1, "wide");
        let e = Frame::read(&wrong.encode()).unwrap_err();
        assert_eq!(e.0, "viewport.width should be an unsigned integer");
    }
}
