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

use crate::typed::{read_reply, Ask, Failed, Unencodable, Unreadable};
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
/// pages joined so far, or how one failed.
pub struct Pages<A: Ask> {
    /// Whether the arguments asked for one page themselves.
    one_page: bool,
    asked: A,
    all: Option<A::Reply>,
    failed: Option<Failed>,
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
    /// `args`, not yet asked.
    pub fn new(args: &A) -> Self {
        Pages {
            one_page: args.one_page(),
            asked: args.clone(),
            all: None,
            failed: None,
        }
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

impl<A: Ask> Paging for Pages<A> {
    fn request(&self) -> &'static Request {
        A::REQUEST
    }
    fn next(&mut self) -> Result<Option<Vec<u8>>, Unencodable> {
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
        let page = match read_reply::<A>(reply)? {
            Ok(r) => r,
            Err(f) => {
                self.failed = Some(f);
                return Ok(false);
            }
        };
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
                    let place = Place::new("mine".into());
                    let reply = FilesReply::new(self.entries.clone(), String::new(), place, false);
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
                    let mut reply = MessagesReply::new(self.said[..upto].to_vec(), false);
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
        File::new(false, format!("{i:05} {}", "x".repeat(200)))
    }

    fn said(i: u8, text: String) -> Message {
        Message::new(Vec::new(), false, [i; 16], i % 2 == 0, Vec::new(), text)
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
}
