//! The local interface's messages (`apps.md#the-local-interface`): each one
//! record in the base encoding, with numbered fields.
//!
//! What the messages are is declared in the `cardinal-interface` crate,
//! shared with the command line and with any Rust client: every typed
//! record, request, event and frame, the tables, the encoding both ways,
//! the paging and the text rendering by the tables' names. Everything of
//! it is here as it was, by the same paths (`api::typed`, `api::table`,
//! `api::FilesArgs`, ...). How a request is answered is the service's own
//! (`control::typed`), made from the crate's list of every request
//! (`each_request!`), so that one without a handler does not compile.
//!
//! Besides, where the tests run, in debug builds and with the `by-name`
//! feature, the way by name (`DEVIATIONS.md`, Typed records): a request and
//! its reply as JSON trees by the tables' names, the handlers kept from
//! before they were typed, and the client by name the tests use.

pub use cardinal_interface::*;

// What the way by name and the tests below take from here, as they did.
#[cfg(any(test, debug_assertions, feature = "by-name"))]
#[allow(unused_imports)]
use cardinal_encoding::{Record, Value};

#[cfg(all(unix, any(test, debug_assertions, feature = "by-name")))]
pub mod blocking;

#[cfg(any(test, debug_assertions, feature = "by-name"))]
mod by_name;
#[cfg(any(test, debug_assertions, feature = "by-name"))]
pub use by_name::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod same_bytes;
