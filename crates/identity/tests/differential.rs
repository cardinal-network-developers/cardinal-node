//! Differential test: the Rust port of `world.py` and the Rust Datalog
//! evaluator against the reference Python model, on the model's scenarios
//! and on random histories from its fuzzer.
//!
//! Needs `python3` and the specification checkout (`core/model`, found next
//! to any ancestor of this crate, or at `$CARDINAL_CORE`). When either is
//! missing the test prints why and passes. The number of fuzzer histories
//! of each kind is `$CARDINAL_DIFF_CASES` (default 40), and the seed is
//! `$CARDINAL_DIFF_SEED` (default 1).

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use cardinal_identity::datalog::Val;
use cardinal_identity::model::{
    evaluate_identity, evaluate_space, intern_memberships, Entry, MembershipNames, Op, World,
};
use serde_json::Value as J;

fn sym(w: &mut World, v: &J) -> u32 {
    match v {
        J::String(s) => w.sym(s),
        J::Null => w.none(),
        other => panic!("expected a name, got {other}"),
    }
}

fn syms(w: &mut World, v: &J) -> Vec<u32> {
    v.as_array().unwrap().iter().map(|x| sym(w, x)).collect()
}

fn op(w: &mut World, v: &J) -> Op {
    let a = v.as_array().unwrap();
    let name = a[0].as_str().unwrap();
    match name {
        "add" => Op::Add {
            key: sym(w, &a[1]),
            power: a[2].as_i64().unwrap(),
        },
        "rem" => Op::Rem { key: sym(w, &a[1]) },
        "policy" => {
            let guardians = syms(w, &a[2]);
            Op::Policy {
                changes: if a[1].is_null() {
                    None
                } else {
                    Some(sym(w, &a[1]))
                },
                slots: guardians.len(),
                guardians,
                threshold: a[3].as_i64().unwrap(),
                controller: match a.get(4) {
                    Some(c) if !c.is_null() => Some(sym(w, c)),
                    _ => None,
                },
            }
        }
        "recover" => Op::Recover {
            root: sym(w, &a[1]),
            keeps: syms(w, &a[2]),
            policy: sym(w, &a[3]),
        },
        "confirm" => Op::Confirm {
            decision: sym(w, &a[1]),
        },
        "sek" => Op::Sek,
        "object" => Op::Object,
        "protocol" => Op::Protocol {
            declares: syms(w, &a[1]),
        },
        "ext" => Op::Ext {
            name: sym(w, &a[1]),
            critical: a[2].as_bool().unwrap(),
        },
        "create" => Op::Create,
        "add_member" => Op::AddMember {
            member: sym(w, &a[1]),
            role: a[2].as_i64().unwrap(),
        },
        "remove_member" => Op::RemoveMember {
            membership: sym(w, &a[1]),
        },
        "succeed" => Op::Succeed,
        "keep" => Op::Keep {
            key: sym(w, &a[1]),
            entries: syms(w, &a[2]),
        },
        "app" => Op::App,
        "reach" => Op::Reach,
        other => panic!("unknown model op {other}"),
    }
}

fn build(entries: &[J], n: usize) -> World {
    let mut w = World::new(MembershipNames::Model);
    for e in &entries[..n] {
        let opt = |w: &mut World, k: &str| {
            let v = &e[k];
            (!v.is_null()).then(|| sym(w, v))
        };
        let entry = Entry {
            id: sym(&mut w, &e["id"]),
            log: sym(&mut w, &e["log"]),
            parents: syms(&mut w, &e["parents"]),
            signer: sym(&mut w, &e["signer"]),
            ops: e["ops"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| op(&mut w, o))
                .collect(),
            author: opt(&mut w, "author"),
            head: opt(&mut w, "head"),
            membership: opt(&mut w, "membership"),
        };
        w.put(entry).expect("well-formed history");
    }
    intern_memberships(&mut w);
    w
}

fn val_json(w: &World, v: &Val) -> J {
    match v {
        Val::Int(i) => J::from(*i),
        Val::Sym(s) if *s == w.none() => J::Null,
        Val::Sym(s) => J::from(w.name(*s)),
    }
}

fn rel_json<'a>(w: &World, rel: impl Iterator<Item = &'a [Val]>) -> BTreeSet<String> {
    rel.map(|t| J::Array(t.iter().map(|v| val_json(w, v)).collect()).to_string())
        .collect()
}

fn expected_rel(v: &J) -> BTreeSet<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|t| t.to_string())
        .collect()
}

#[derive(Default, Debug)]
struct Stats {
    worlds: usize,
    entries: usize,
    identity_queries: usize,
    space_queries: usize,
    frozen: usize,
    contested: usize,
    stalled: usize,
    valid_tuples: usize,
}

fn run(json: &str, stats: &mut Stats) -> Vec<String> {
    let doc: J = serde_json::from_str(json).expect("helper output is JSON");
    let mut failures = Vec::new();
    for world in doc["worlds"].as_array().unwrap() {
        let name = world["name"].as_str().unwrap();
        let entries = world["entries"].as_array().unwrap();
        stats.worlds += 1;
        stats.entries += entries.len();
        let mut built: BTreeMap<usize, World> = BTreeMap::new();
        for (qn, q) in world["queries"].as_array().unwrap().iter().enumerate() {
            let n = q["n"].as_u64().unwrap() as usize;
            let w = built.entry(n).or_insert_with(|| build(entries, n));
            let log = w.get_sym(q["log"].as_str().unwrap()).unwrap();
            let ids: BTreeSet<u32> = match q["ids"].as_array() {
                Some(a) => a
                    .iter()
                    .map(|x| w.get_sym(x.as_str().unwrap()).unwrap())
                    .collect(),
                None => w.all(),
            };
            let expected = &q["result"];
            let mut diffs = Vec::new();
            if q["type"] == "identity" {
                stats.identity_queries += 1;
                let known: Option<BTreeSet<u32>> = q["known"].as_array().map(|a| {
                    a.iter()
                        .map(|x| w.get_sym(x.as_str().unwrap()).unwrap())
                        .collect()
                });
                let r = evaluate_identity(w, log, &ids, known.as_ref());
                for (k, v) in expected.as_object().unwrap() {
                    match k.as_str() {
                        "frozen" => {
                            if v.as_bool().unwrap() != r.frozen {
                                diffs.push(format!("frozen: python {v}, rust {}", r.frozen));
                            }
                        }
                        "contested" => {
                            if v.as_bool().unwrap() != r.contested {
                                diffs.push(format!("contested: python {v}, rust {}", r.contested));
                            }
                        }
                        "stalled" => {
                            let got: BTreeSet<String> = r
                                .stalled
                                .iter()
                                .map(|s| J::from(w.name(*s)).to_string())
                                .collect();
                            if got != expected_rel(v) {
                                diffs.push(format!("stalled: python {v}, rust {got:?}"));
                            }
                        }
                        rel => {
                            let got = rel_json(w, r.rel(rel));
                            let want = expected_rel(v);
                            if got != want {
                                diffs.push(format!(
                                    "{rel}: python only {:?}, rust only {:?}",
                                    want.difference(&got).collect::<Vec<_>>(),
                                    got.difference(&want).collect::<Vec<_>>()
                                ));
                            }
                        }
                    }
                }
                stats.frozen += r.frozen as usize;
                stats.contested += r.contested as usize;
                stats.stalled += (!r.stalled.is_empty()) as usize;
                stats.valid_tuples += r.rel("valid").count();
            } else {
                stats.space_queries += 1;
                let r = evaluate_space(w, log, &ids, false, None);
                for (k, v) in expected.as_object().unwrap() {
                    if k == "kept_frozen" {
                        let got: BTreeSet<String> = r
                            .kept_frozen
                            .iter()
                            .map(|s| J::from(w.name(*s)).to_string())
                            .collect();
                        if got != expected_rel(v) {
                            diffs.push(format!("kept_frozen: python {v}, rust {got:?}"));
                        }
                        continue;
                    }
                    let got = rel_json(w, r.rels[k.as_str()].iter().map(|t| &t[..]));
                    let want = expected_rel(v);
                    if got != want {
                        diffs.push(format!(
                            "{k}: python only {:?}, rust only {:?}",
                            want.difference(&got).collect::<Vec<_>>(),
                            got.difference(&want).collect::<Vec<_>>()
                        ));
                    }
                }
                stats.valid_tuples += r.unary("valid").len();
            }
            if !diffs.is_empty() {
                failures.push(format!(
                    "{name}, query {qn} ({} {}): {}",
                    q["type"],
                    q["log"],
                    diffs.join("; ")
                ));
            }
        }
    }
    failures
}

fn python(args: &[&str]) -> Option<String> {
    let model = cardinal_identity::testutil::core_path("model/world.py")?;
    let model = model.parent()?.to_path_buf();
    let helper = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/differential.py");
    let out = Command::new("python3")
        .arg("-B")
        .arg(helper)
        .arg(&model)
        .args(args)
        .output()
        .ok()?;
    assert!(
        out.status.success(),
        "differential.py failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).unwrap())
}

fn check(args: &[&str], label: &str) {
    let Some(json) = python(args) else {
        eprintln!("{label}: python3 or core/model not available; skipping");
        return;
    };
    let mut stats = Stats::default();
    let failures = run(&json, &mut stats);
    eprintln!("{label}: {stats:?}");
    assert!(
        failures.is_empty(),
        "{} of {} evaluations differ from the Python model:\n{}",
        failures.len(),
        stats.identity_queries + stats.space_queries,
        failures.join("\n")
    );
}

#[test]
fn scenarios_match_python_model() {
    check(&["--scenarios"], "scenarios");
}

#[test]
fn fuzzer_histories_match_python_model() {
    let n = std::env::var("CARDINAL_DIFF_CASES").unwrap_or_else(|_| "40".into());
    let seed = std::env::var("CARDINAL_DIFF_SEED").unwrap_or_else(|_| "1".into());
    let web = (n.parse::<usize>().unwrap_or(40) / 2).max(1).to_string();
    check(
        &[
            "--identity",
            &n,
            "--honest",
            &n,
            "--web",
            &web,
            "--space",
            &n,
            "--seed",
            &seed,
        ],
        "fuzzer",
    );
}
