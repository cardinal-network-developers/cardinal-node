//! The service alone, for a client to start: on Windows and Android there is
//! no command line for a person to use, and nothing else of `cardinal`
//! applies.
//!
//! `cardinald [--listen IP:PORT] [--name NAME] [--no-discovery]`
//!
//! Such a client has no `cardinal` to tell its person why the service will
//! not start on a store another version wrote, or to clear one. So two
//! options answer, and start nothing, with one record in the base encoding
//! on standard output and nothing after it, numbered as a reply is
//! (`apps.md`, The local interface; [`cardinald::api::PROGRAM`]): key 0 is
//! 0, or an error's number with why in key 1.
//!
//! - `cardinald --store` says which store the data directory holds
//!   (`empty`, `current`, `other`, or `unreadable` if its marker is there
//!   and cannot be read) and what it `holds`, counted without reading any
//!   of it; of another version's, whether that was `earlier`, `later` or
//!   `another` (`written_by`), and the `refusal` in words.
//! - `cardinald --clear` removes what the service wrote there, as `cardinal
//!   clear` does, and leaves the files kept on this device only. It
//!   refuses while a service runs on that directory. It removes only a
//!   store of another version's, one with an identity, a space or an
//!   object in it: nothing here asks the person first, so it must not be
//!   able to remove a store that works, or one whose marker cannot be
//!   read, or what lies in a directory that holds no store. `cardinal
//!   clear` does that, and asks.

use std::io::Write;

use cardinald::api::{self, status};
use cardinald::format::{self, Store};
use cardinald::paths::Paths;
use cardinald::Overrides;
use serde_json::{json, Value};

/// Writes a report on standard output, and nothing else.
fn write_out(report: &[u8]) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(report)?;
    out.flush()?;
    Ok(())
}

/// `--clear`'s answer as a record: done, or failed and why.
fn cleared(said: &Value) -> Vec<u8> {
    match said["error"].as_str() {
        None => {
            let spec = api::program("--clear").expect("the table has it");
            api::encode_reply(spec, Ok(&json!({})))
        }
        Some(why) => api::error_reply(status::FAILED, why),
    }
}

/// Removes what the service wrote, for `--clear`, unless one is running.
async fn clear(paths: &Paths) -> Value {
    let status = json!({"cmd": "status"});
    let answers = cardinald::control::request(&paths.socket, &status).await;
    let held = match cardinald::lock::held(paths) {
        Ok(held) => held,
        Err(e) => return json!({"ok": false, "error": cardinald::lock::cannot(paths, &e)}),
    };
    if answers.is_ok() || held {
        return json!({
            "ok": false,
            "error": "Cardinal is running on this data. Stop it first. Nothing was changed.",
        });
    }
    // Only what this version cannot read goes this way. A client offers it
    // when the service will not start, and a store that works is never
    // that. Nor is a directory with no store in it, or one whose marker
    // cannot be read.
    let refuse = |why: String| json!({"ok": false, "error": why});
    match format::of(paths) {
        Store::Current => {
            return refuse(
                "This version can read the Cardinal data here, so it is not removed this way. \
                 `cardinal clear` removes it, and asks first. Nothing was changed."
                    .into(),
            );
        }
        Store::Unreadable => return refuse(format::cannot_tell(&paths.home)),
        _ if !format::removable_unasked(paths) => {
            return refuse(
                "There is no Cardinal data here that this version cannot read. Nothing was \
                 changed."
                    .into(),
            );
        }
        _ => {}
    }
    match cardinald::clear::clear(paths, false) {
        Ok(()) => json!({"ok": true}),
        Err(e) if e.kind() == std::io::ErrorKind::ResourceBusy => json!({
            "ok": false,
            "error": "Cardinal is running on this data. Stop it first. Nothing was changed.",
        }),
        Err(e) => json!({"ok": false, "error": format!("Not all of it could be removed: {e}")}),
    }
}

fn main() -> anyhow::Result<()> {
    let mut o = Overrides {
        no_mount: !cfg!(feature = "mount"),
        ..Overrides::default()
    };
    let mut asked = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => o.listen = args.next(),
            "--name" => o.name = args.next(),
            "--no-discovery" => o.no_discovery = true,
            "--store" | "--clear" => asked = Some(arg),
            other => anyhow::bail!("{other} is not an option of cardinald"),
        }
    }
    let paths = Paths::from_env();
    if asked.as_deref() == Some("--store") {
        return write_out(&format::report(&paths));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    if asked.is_some() {
        let said = rt.block_on(clear(&paths));
        write_out(&cleared(&said))?;
        std::process::exit(if said["ok"] == true { 0 } else { 1 });
    }
    cardinald::init_logging();
    rt.block_on(cardinald::run(paths, o))
}
