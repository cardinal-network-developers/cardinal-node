//! The recovery words in place of an admin device
//! (`identity.md#recovery-phrase`): alpha, the first and only admin
//! device, is lost. On beta, an ordinary device, the words check out,
//! remove alpha, and make a new device gamma an admin. Gamma, the new
//! admin, then needs no words.
//!
//! Skipped (with a message) when `/dev/fuse` or `fusermount3` is missing.

mod common;

use common::*;

/// The 24 words `cardinal init` printed, in order ("  1. word   9. ...").
fn words_from(init: &str) -> Vec<String> {
    let mut words = vec![String::new(); 24];
    for line in init.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        for pair in t.windows(2) {
            if let Some(n) = pair[0]
                .strip_suffix('.')
                .and_then(|n| n.parse::<usize>().ok())
            {
                if (1..=24).contains(&n) {
                    words[n - 1] = pair[1].to_owned();
                }
            }
        }
    }
    assert!(words.iter().all(|w| !w.is_empty()), "{init}");
    words
}

fn devices(d: &Dev) -> Vec<(String, String)> {
    d.status()["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["name"].as_str().unwrap_or("").to_owned(),
                x["power"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

fn out(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn words_stand_in_for_a_lost_admin() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is not available");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut a = Dev::new(root.path(), "alpha", free_port());
    let mut b = Dev::new(root.path(), "beta", free_port());
    let mut g = Dev::new(root.path(), "gamma", free_port());
    a.start();
    let init = a.cli(&["init", "--yes", "--name", "alpha"]);
    let words = words_from(&init);
    b.start();
    pair(&a, &b);
    assert!(devices(&b).contains(&("beta".into(), "device".into())));

    // Checking the words: typed whole, or four letters each over two lines.
    let whole = words.join(" ");
    let short: Vec<String> = words.iter().map(|w| w.chars().take(4).collect()).collect();
    let short = format!("{}\n{}\n", short[..10].join(" "), short[10..].join(" "));
    for typed in [format!("{whole}\n"), short] {
        let o = b.cli_input(&["recovery", "check"], &typed);
        assert!(o.status.success(), "{}", out(&o));
        assert!(
            out(&o).contains("These are your recovery words."),
            "{}",
            out(&o)
        );
    }
    // Two words swapped, three times: the checksum (almost always) says so.
    let mut swapped = words.clone();
    swapped.swap(3, 17);
    let o = b.cli_input(
        &["recovery", "check"],
        &format!("{}\n", swapped.join(" ")).repeat(3),
    );
    assert!(!o.status.success());
    eprintln!("---- swapped ----\n{}", out(&o));
    assert!(
        out(&o).contains("do not fit together") || out(&o).contains("not your recovery words"),
        "{}",
        out(&o)
    );
    // Someone else's words.
    let other = "zoo ".repeat(23) + "vote\n";
    let o = b.cli_input(&["recovery", "check"], &other.repeat(3));
    assert!(!o.status.success());
    assert!(
        out(&o).contains("not the ones for your identity"),
        "{}",
        out(&o)
    );

    // Alpha is lost. Beta cannot remove an admin device on its own.
    a.stop();
    let o = b.cli_input(&["remove-device", "alpha"], "");
    assert!(!o.status.success());
    eprintln!("---- without words ----\n{}", out(&o));
    assert!(
        out(&o).contains("Alpha is an admin device: no device can remove it."),
        "{}",
        out(&o)
    );
    assert!(devices(&b).iter().any(|(n, _)| n == "alpha"));

    // With the words, beta removes alpha, which leaves no admin device...
    let o = b.cli_input(&["remove-device", "alpha"], &format!("{whole}\n"));
    eprintln!("---- beta removes alpha ----\n{}", out(&o));
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("Removed \"alpha\""), "{}", out(&o));
    assert!(
        out(&o).contains("None of your devices is an admin device now"),
        "{}",
        out(&o)
    );

    // ...and adds gamma as an admin device in its place.
    g.start();
    let typed = pair_as(&b, &g, true, Some(&format!("{whole}\n")));
    eprintln!("---- beta adds gamma ----\n{typed}");
    assert!(typed.contains("This device cannot add devices"), "{typed}");
    assert!(typed.contains("Added \"gamma\""), "{typed}");
    wait("gamma is an admin device", 30, || {
        devices(&g).contains(&("gamma".into(), "admin".into()))
    });
    for d in [&b, &g] {
        wait(&format!("{} no longer lists alpha", d.name), 30, || {
            !devices(d).iter().any(|(n, _)| n == "alpha")
        });
    }

    // Gamma, the new admin, removes beta without any words.
    let o = g.cli_input(&["remove-device", "beta"], "");
    assert!(o.status.success(), "{}", out(&o));
    wait("gamma alone", 30, || {
        devices(&g) == vec![("gamma".to_owned(), "admin".to_owned())]
    });
}
