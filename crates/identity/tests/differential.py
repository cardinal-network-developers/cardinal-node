"""Emit histories and the reference evaluator's results as JSON, for the
differential test in differential.rs.

    python3 -B differential.py MODEL_DIR [--scenarios] [--identity N]
        [--honest N] [--web N] [--space N] [--subsets K] [--seed S]

MODEL_DIR is core/model. Histories come from model/scenarios.py (every
evaluation a scenario makes is recorded) and from the generators of
model/fuzz.py. Each history is written once, with every entry in insertion
order, followed by the evaluations made on it and their results. Nothing
under MODEL_DIR is written.
"""

import json
import random
import sys

sys.dont_write_bytecode = True


def main(argv):
    model = argv[1]
    sys.path.insert(0, model)
    import world as W  # noqa: E402

    opts = {"--identity": 0, "--honest": 0, "--web": 0, "--space": 0, "--subsets": 2,
            "--seed": 1}
    scen = "--scenarios" in argv
    for i, a in enumerate(argv):
        if a in opts:
            opts[a] = int(argv[i + 1])

    def tup(v):
        if isinstance(v, (tuple, list, frozenset, set)):
            return [tup(x) for x in v]
        return v

    def entries_json(w):
        out = []
        for x, e in w.entries.items():
            out.append({"id": e.id, "log": e.log, "kind": w._kind[e.log],
                        "parents": list(e.parents), "signer": e.signer,
                        "ops": [tup(op) for op in e.ops], "author": e.author,
                        "head": e.head, "membership": e.membership})
        return out

    def rel(s):
        return sorted((tup(t) for t in s), key=lambda t: json.dumps(t))

    def ident_json(r):
        out = {k: rel(v) for k, v in r.items() if isinstance(v, (set, frozenset))
               and k != "stalled"}
        out["frozen"] = bool(r["frozen"])
        out["contested"] = bool(r["contested"])
        out["stalled"] = sorted(r["stalled"])
        return out

    def space_json(r):
        out = {k: rel(v) for k, v in r.items() if k != "kept_frozen"}
        out["kept_frozen"] = sorted(r["kept_frozen"])
        return out

    worlds = []

    # ------------------------------------------------------- scenarios
    if scen:
        import scenarios as S  # noqa: E402
        current = {}

        orig_ident, orig_sp = W.Builder.ident, W.Builder.sp

        def ident(self, log, ids=None, known=None):
            r = orig_ident(self, log, ids, known)
            q = {"type": "identity", "log": log, "n": len(self.w.entries),
                 "ids": sorted(ids) if ids else None,
                 "known": sorted(known) if known is not None else None,
                 "result": ident_json(r)}
            current.setdefault(id(self), (self, []))[1].append(q)
            return r

        def sp(self, space):
            r = orig_sp(self, space)
            q = {"type": "space", "log": space, "n": len(self.w.entries),
                 "ids": None, "known": None, "result": space_json(r)}
            current.setdefault(id(self), (self, []))[1].append(q)
            return r

        W.Builder.ident, W.Builder.sp = ident, sp
        S.Builder.ident, S.Builder.sp = ident, sp
        for fn in S.SCENARIOS:
            current.clear()
            fn()
            for b, qs in current.values():
                worlds.append({"name": "scenario " + fn.__name__,
                               "entries": entries_json(b.w), "queries": qs})
        W.Builder.ident, W.Builder.sp = orig_ident, orig_sp

    # ---------------------------------------------------------- fuzzer
    import fuzz as F  # noqa: E402

    def identity_queries(b, rng, logs):
        w = b.w
        qs = []
        exts = any(op[0] == "ext" for e in w.entries.values() for op in e.ops)
        for log in logs:
            sets = [None] + [sorted(F.closed_subset(w, rng, [log]))
                             for _ in range(opts["--subsets"])]
            for ids in sets:
                knowns = [None] + ([[]] if exts else [])
                for known in knowns:
                    r = W.evaluate_identity(
                        w, log, frozenset(ids if ids is not None else w.entries),
                        frozenset(known) if known is not None else None)
                    qs.append({"type": "identity", "log": log, "n": len(w.entries),
                               "ids": ids, "known": known, "result": ident_json(r)})
        return qs

    seed = opts["--seed"]
    for n in range(opts["--identity"]):
        rng = random.Random(f"id{seed}-{n}")
        b = F.identity_history(rng)
        worlds.append({"name": f"identity {seed}-{n}", "entries": entries_json(b.w),
                       "queries": identity_queries(b, rng, ["I"])})
    for n in range(opts["--honest"]):
        rng = random.Random(f"honest{seed}-{n}")
        b = F.honest_identity_history(rng)
        worlds.append({"name": f"honest {seed}-{n}", "entries": entries_json(b.w),
                       "queries": identity_queries(b, rng, ["I"])})
    for n in range(opts["--web"]):
        rng = random.Random(f"web{seed}-{n}")
        b, names = F.guardian_web(rng)
        worlds.append({"name": f"web {seed}-{n}", "entries": entries_json(b.w),
                       "queries": identity_queries(b, rng, list(names))})
    for n in range(opts["--space"]):
        rng = random.Random(f"space{seed}-{n}")
        b = F.space_history(rng)
        w = b.w
        qs = []
        full = F.space_ids(w)
        for ids in [full] + [sorted(F.closed_subset(w, rng, ["S"]) & set(full))
                             for _ in range(opts["--subsets"])]:
            r = W.evaluate_space(w, "S", ids)
            qs.append({"type": "space", "log": "S", "n": len(w.entries),
                       "ids": sorted(ids), "known": None, "result": space_json(r)})
        worlds.append({"name": f"space {seed}-{n}", "entries": entries_json(w),
                       "queries": qs})

    json.dump({"worlds": worlds}, sys.stdout)


if __name__ == "__main__":
    main(sys.argv)
