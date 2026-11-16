#!/usr/bin/env python3
"""Closed-form exfil/brute-force budget model for php-fpm address discovery,
plus a side-channel tractability assessment. Consumes the measured numbers from
aslr_delta_survey.py.

Because the mmap cluster collapses totally (inter-library deltas constant across
restarts, chunk derivable from libc), discovery reduces to leaking exactly two
pointers: any mmap/heap pointer -> chunk + libc + every library, and any php-fpm
text pointer -> binbase; given both, brute probes to RCE = 0. The model prints,
for three knowledge scenarios, the probes and time to brute whichever gap cannot
be leaked (mapped-page oracle, fork-fixed stable target), at loopback / network /
crash-oracle rates. Pure ASLR side channels (cache/mmap/TLB timing) are not a
tractable app-independent remote leak source; the app-agnostic channel available
is the address-blind crash/liveness oracle.

Pure computation, no network. Pure stdlib, python3 -I safe, standalone. Lab use,
systems you own.
"""
from __future__ import annotations

import argparse
import math
import sys

# measured defaults (this lab; from aslr_delta_survey)
MMAP_RND_BITS = 32          # /proc/sys/vm/mmap_rnd_bits on this host
PIE_RND_BITS = 32           # x86-64 PIE uses the same mmap rnd on Linux
CLUSTER_PAGES = 8197        # contiguous mmap cluster footprint (~2^13)
PIE_PAGES = 5831            # php-fpm image footprint (~2^12.5)
EDGE_WALK_PROBES = 16       # binary-search an edge once inside a contiguous blob

RATES = {                   # probe/s for the time conversion
    "loopback_clean(3226/s)": 3226.0,   # measured clean-request ceiling
    "network_clean(100/s)": 100.0,      # assumed LAN clean-request oracle
    "crash_oracle(0.18/s)": 0.18,       # measured OOM-crash+respawn probe
}


def blob_search_probes(rnd_bits, blob_pages, edge_probes=EDGE_WALK_PROBES):
    """Probes to pin one contiguous blob of ``blob_pages`` placed at a random
    page offset within a 2**rnd_bits-page window, using a mapped-page oracle.

    Stride search at blob-size stride guarantees a hit in window/blob probes
    (expected half). Then an edge binary-search pins the exact base.
    Returns (expected, worst_case)."""
    window = 2 ** rnd_bits
    worst = max(1, window // max(1, blob_pages))      # guaranteed hit
    exp = max(1, worst // 2) + int(math.log2(max(2, blob_pages))) + edge_probes
    return exp, worst + int(math.log2(max(2, blob_pages))) + edge_probes


def fmt_time(probes, rate):
    s = probes / rate
    for unit, span in (("s", 60), ("min", 60), ("h", 24), ("d", 365), ("y", 1e9)):
        if s < span:
            return "%.1f %s" % (s, unit)
        s /= span
    return "%.1f y" % s


def model(mmap_rnd=MMAP_RND_BITS, pie_rnd=PIE_RND_BITS,
          cluster_pages=CLUSTER_PAGES, pie_pages=PIE_PAGES):
    mmap_exp, mmap_worst = blob_search_probes(mmap_rnd, cluster_pages)
    pie_exp, pie_worst = blob_search_probes(pie_rnd, pie_pages)
    return {
        "mmap_gap": {"rnd_bits": mmap_rnd, "blob_pages": cluster_pages,
                     "find_probes_expected": mmap_exp,
                     "find_probes_worst": mmap_worst},
        "pie_gap": {"rnd_bits": pie_rnd, "blob_pages": pie_pages,
                    "find_probes_expected": pie_exp,
                    "find_probes_worst": pie_worst},
        "scenarios": {
            # (a) nothing: must find BOTH independent gaps
            "a_nothing": {
                "desc": "no prior knowledge: brute-force the mmap cluster AND "
                        "the PIE (two independent gaps)",
                "probes_expected": mmap_exp + pie_exp,
                "probes_worst": mmap_worst + pie_worst,
                "note": "NO app-agnostic steerable oracle exists on fpm (crash "
                        "oracle is address-blind) -> realistically BLOCKED, not "
                        "merely this many probes.",
            },
            # (b) one anchor (one full address, in either gap)
            "b_one_anchor": {
                "desc": "one full address known (one gap solved); brute-force "
                        "the OTHER independent gap with a mapped-page oracle",
                "probes_expected_if_mmap_known": pie_exp,   # PIE remains
                "probes_expected_if_pie_known": mmap_exp,   # mmap remains
                "note": "an mmap anchor also yields chunk+libc+all libs FREE "
                        "(B3 collapse); a PIE anchor yields binbase only.",
            },
            # (c) collapsed deltas known + one mmap/heap pointer leaked
            "c_collapsed_one_heap_ptr": {
                "desc": "B3 deltas known + ONE heap/mmap pointer leaked: chunk + "
                        "libc + every library resolved by ARITHMETIC (0 probes)",
                "probes_for_mmap_cluster": 0,
                "probes_remaining_for_pie": pie_exp,
                "probes_if_also_one_text_ptr": 0,
                "note": "collapse reduces discovery to LEAKING EXACTLY TWO "
                        "pointers (one mmap/heap, one php-fpm-text); given both, "
                        "0 brute-force probes. Only an unleakable gap costs the "
                        "PIE search above.",
            },
        },
    }


def print_model(m):
    def line(label, probes):
        times = "  ".join("%s=%s" % (k, fmt_time(probes, r))
                          for k, r in RATES.items())
        print("    %-46s %12s probes | %s" % (label, "{:,}".format(probes), times))

    print("=" * 100)
    print("Hope-B5 LEAK / BRUTE-FORCE BUDGET MODEL  (php-fpm, fork-fixed ASLR, "
          "mapped-page oracle)")
    print("=" * 100)
    g = m["mmap_gap"]
    print("mmap gap : %d-bit window, %d-page contiguous cluster -> find ~%s probes "
          "(worst %s)" % (g["rnd_bits"], g["blob_pages"],
                          "{:,}".format(g["find_probes_expected"]),
                          "{:,}".format(g["find_probes_worst"])))
    g = m["pie_gap"]
    print("PIE  gap : %d-bit window, %d-page contiguous image   -> find ~%s probes "
          "(worst %s)" % (g["rnd_bits"], g["blob_pages"],
                          "{:,}".format(g["find_probes_expected"]),
                          "{:,}".format(g["find_probes_worst"])))
    print("-" * 100)
    s = m["scenarios"]
    print("(a) FROM NOTHING  [%s]" % s["a_nothing"]["desc"])
    line("both gaps (expected)", s["a_nothing"]["probes_expected"])
    print("    !! %s" % s["a_nothing"]["note"])
    print("(b) ONE ANCHOR    [%s]" % s["b_one_anchor"]["desc"])
    line("mmap known -> resolve PIE", s["b_one_anchor"]["probes_expected_if_mmap_known"])
    line("PIE known  -> resolve mmap", s["b_one_anchor"]["probes_expected_if_pie_known"])
    print("    -> %s" % s["b_one_anchor"]["note"])
    print("(c) B3 COLLAPSE + 1 HEAP PTR  [%s]" % s["c_collapsed_one_heap_ptr"]["desc"])
    line("mmap cluster (chunk+libc+libs)", s["c_collapsed_one_heap_ptr"]["probes_for_mmap_cluster"])
    line("+ PIE still unleaked", s["c_collapsed_one_heap_ptr"]["probes_remaining_for_pie"])
    line("+ also 1 php-fpm-text ptr -> RCE", s["c_collapsed_one_heap_ptr"]["probes_if_also_one_text_ptr"])
    print("    -> %s" % s["c_collapsed_one_heap_ptr"]["note"])
    print("=" * 100)
    print("VERDICT: the collapse makes discovery = leak exactly 2 pointers (one "
          "mmap/heap, one text); given both, RCE is arithmetic (minutes).")
    print("A single UNLEAKABLE gap costs a ~%s-probe mapped-page brute force: "
          "minutes on loopback, HOURS over a real network (clean-request "
          "oracle), WEEKS via the crash oracle." %
          "{:,}".format(m["pie_gap"]["find_probes_expected"]))
    print("But fpm exposes no steerable app-agnostic oracle, so from-nothing "
          "brute force is structurally blocked, not merely slow (see B6).")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hope-B5 fpm leak/brute-force budget "
                                             "model (+ B6 side-channel verdict in "
                                             "the module docstring).")
    ap.add_argument("--mmap-rnd-bits", type=int, default=MMAP_RND_BITS,
                    help="/proc/sys/vm/mmap_rnd_bits (32 this host, 28 stock)")
    ap.add_argument("--pie-rnd-bits", type=int, default=PIE_RND_BITS)
    ap.add_argument("--cluster-pages", type=int, default=CLUSTER_PAGES)
    ap.add_argument("--pie-pages", type=int, default=PIE_PAGES)
    ap.add_argument("--stock", action="store_true",
                    help="model a stock 28-bit-mmap_rnd server instead of 32")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    mmap_rnd = 28 if args.stock else args.mmap_rnd_bits
    pie_rnd = 28 if args.stock else args.pie_rnd_bits
    m = model(mmap_rnd, pie_rnd, args.cluster_pages, args.pie_pages)
    if args.json:
        import json
        print(json.dumps(m, indent=2))
    else:
        print_model(m)
        if not args.stock and (mmap_rnd, pie_rnd) == (32, 32):
            print("\n[stock 28-bit comparison]")
            print_model(model(28, 28, args.cluster_pages, args.pie_pages))
    return 0


if __name__ == "__main__":
    sys.exit(main())
