//! The service alone, for a client to start: on Windows and Android there is
//! no command line for a person to use, and nothing else of `cardinal`
//! applies.
//!
//! `cardinald [--listen IP:PORT] [--name NAME] [--no-discovery]`
//!
//! Such a client has no `cardinal` to tell its person why the service will
//! not start on a store another version wrote, or to clear one. So two
//! options answer in one line of JSON, and start nothing:
//!
//! - `cardinald --store` says which store the data directory holds
//!   (`empty`, `current` or `other`) and what it `holds`, counted without
//!   reading any of it; of another version's, whether that was `earlier`,
//!   `later` or `another` (`written_by`), and the `refusal` in words.
//! - `cardinald --clear` removes what the service wrote there, as `cardinal
//!   clear` does, and leaves the files kept on this device only. It
//!   refuses while a service answers on that directory. It also refuses a
//!   store this version can read: nothing here asks the person first, so
//!   it must not be able to remove one that works. `cardinal clear` does
//!   that, and asks.

use cardinald::format::{self, Store};
use cardinald::paths::Paths;
use cardinald::Overrides;
use serde_json::{json, Value};

/// What the data directory holds, for `--store`.
fn store(paths: &Paths) -> Value {
    let found = cardinald::clear::found(paths);
    let mut out = json!({
        "store": "current",
        "holds": {
            "identity": found.identity,
            "spaces": found.spaces,
            "objects": found.objects.0,
            "bytes": found.objects.1,
            "unsaved": found.staged.0,
            "unsaved_bytes": found.staged.1,
            "local": found.local.0,
            "local_bytes": found.local.1,
            "other": found.other,
        },
    });
    match format::of(paths) {
        Store::Current => {}
        Store::Empty => out["store"] = json!("empty"),
        Store::Other(n) => {
            out["store"] = json!("other");
            out["written_by"] = json!(format::written_by(n));
            out["refusal"] = json!(format::refusal(&paths.home, n));
        }
    }
    out
}

/// Removes what the service wrote, for `--clear`, unless one is running.
async fn clear(paths: &Paths) -> Value {
    let status = json!({"cmd": "status"});
    if cardinald::control::request(&paths.socket, &status)
        .await
        .is_ok()
    {
        return json!({
            "ok": false,
            "error": "Cardinal is running on this data. Stop it first. Nothing was changed.",
        });
    }
    // Only what this version cannot read goes this way. A client offers it
    // when the service will not start, and a store that works is never that.
    if format::of(paths) == Store::Current {
        return json!({
            "ok": false,
            "error": "This version can read the Cardinal data here, so it is not removed this \
                      way. `cardinal clear` removes it, and asks first. Nothing was changed.",
        });
    }
    match cardinald::clear::clear(paths, false) {
        Ok(()) => json!({"ok": true}),
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
        println!("{}", store(&paths));
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    if asked.is_some() {
        let said = rt.block_on(clear(&paths));
        println!("{said}");
        std::process::exit(if said["ok"] == true { 0 } else { 1 });
    }
    cardinald::init_logging();
    rt.block_on(cardinald::run(paths, o))
}
