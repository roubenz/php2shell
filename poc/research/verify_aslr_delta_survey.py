#!/usr/bin/env python3
"""Verifier for aslr_delta_survey and leak_budget_model (collapse + budget).
Asserts the collapse structure and budget-model consistency with real measured
values -- ld-libc constant across restarts, chunk derivable one-to-one from
(libc mod 2 MiB), the
PIE base an independent random gap, sibling-worker and respawn fork-fixedness,
and that the collapse leaves exactly the PIE gap (two anchors -> 0 probes). Runs
a short live survey or, with --from-json, replays a survey JSON. Exit 0 iff all
executed checks pass.

Lab bring-up: docker compose -f docker-compose.reuse.yml -p p2s-aslrsurvey
--profile aslrsurvey up -d. Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    spec.loader.exec_module(mod)
    return mod


def _reachable(host, port):
    try:
        socket.create_connection((host, port), timeout=1).close()
        return True
    except OSError:
        return False


def _check(name, ok, detail=""):
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                           ("  -- " + detail) if detail else ""))
    return bool(ok)


def run_checks(records, report):
    good = [r for r in records if r.get("ok") and r.get("master")]
    print("\nHope-B3/B5 structural checks over %d trial(s):" % len(good))
    results = []

    # check: ld-libc constant
    byname = {d["name"]: d for d in report["deltas"]}
    ld = byname.get("ld - libc", {})
    results.append(_check(
        "B3.1 mmap cluster collapse (ld-libc constant)",
        ld.get("constant") and ld.get("samples", 0) >= 1,
        "ld-libc=%s over %d trials" %
        (hex(ld.get("min")) if ld.get("min") is not None else "?",
         ld.get("samples", 0))))

    # check: chunk-libc is a one-to-one function of (libc mod 2MiB)
    func = {}
    ok_fun = True
    for r in good:
        m = r["master"]
        if m.get("libc") is None or m.get("chunk") is None:
            continue
        key = m["libc"] % 0x200000
        val = m["chunk"] - m["libc"]
        if key in func and func[key] != val:
            ok_fun = False
        func[key] = val
    results.append(_check(
        "B3.2 chunk derivable from libc (chunk-libc = f(libc mod 2MiB))",
        ok_fun and len(func) >= 1,
        "%d distinct (libc mod 2MiB) keys, all map to one chunk-libc" % len(func)))

    # check: PIE independent
    lp = byname.get("libc - pie", {})
    results.append(_check(
        "B3.3 PIE independent of mmap (libc-pie NOT constant)",
        (not lp.get("constant")) or lp.get("samples", 0) < 2,
        "%d distinct libc-pie" % lp.get("distinct", 0)))

    # check: sibling invariance
    results.append(_check(
        "B3.4 fork-fixed: siblings share master layout",
        report.get("sibling_invariant_all", False),
        "all trials sibling-invariant"))

    # check: respawn invariance (only if measured)
    if report.get("respawn_checks", 0) > 0:
        results.append(_check(
            "B3.5 fork-fixed: crash/respawn keeps layout",
            report["respawn_layout_preserved"] == report["respawn_checks"],
            "%d/%d respawns preserved" % (report["respawn_layout_preserved"],
                                          report["respawn_checks"])))
    else:
        print("  [SKIP] B3.5 respawn (not measured in this run)")

    # check: budget self-consistency
    try:
        bm = _load("leak_budget_model", "leak_budget_model.py")
        m = bm.model()
        c = m["scenarios"]["c_collapsed_one_heap_ptr"]
        b = m["scenarios"]["b_one_anchor"]
        ok = (c["probes_for_mmap_cluster"] == 0
              and c["probes_if_also_one_text_ptr"] == 0
              and c["probes_remaining_for_pie"] == m["pie_gap"]["find_probes_expected"]
              and b["probes_expected_if_mmap_known"] == m["pie_gap"]["find_probes_expected"])
        results.append(_check(
            "B5.1 budget model consistent with collapse",
            ok,
            "collapse->mmap probes=0; residual=PIE gap=%s" %
            "{:,}".format(m["pie_gap"]["find_probes_expected"])))
    except Exception as e:                                   # pragma: no cover
        results.append(_check("B5.1 budget model consistent", False, repr(e)))

    return all(results)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from-json", default=None,
                    help="replay a survey JSON instead of a live run")
    ap.add_argument("--container", default="p2s-b35-fpm")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9435)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--trials", type=int, default=8)
    args = ap.parse_args(argv)

    if args.from_json:
        with open(args.from_json) as f:
            d = json.load(f)
        records, report = d["records"], d["report"]
    else:
        if not _reachable(args.host, args.port):
            print("[!] lab not reachable at %s:%d; bring it up or use --from-json"
                  % (args.host, args.port), file=sys.stderr)
            return 2
        surv = _load("aslr_delta_survey", "aslr_delta_survey.py")
        report, records = surv.run_survey(
            args.container, args.host, args.port, args.path, args.trials,
            warms=12, respawn_check=True, settle=0.4, out_path=None, verbose=True)

    ok = run_checks(records, report)
    print("\n%s" % ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
