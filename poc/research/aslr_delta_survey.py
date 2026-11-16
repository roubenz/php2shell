#!/usr/bin/env python3
"""ASLR delta-collapse survey for php-fpm: how hard is discovering the two
addresses the fpm chain needs -- the php-fpm PIE base (binbase) and the first
~2 MiB ZendMM request chunk?

Over N master restarts of a dedicated 8.4.26 pool it records, from /proc/<pid>/
maps, the PIE base, libc, ld.so, [stack], [heap] and the 2 MiB chunk base, and
reports per-mapping and per-inter-mapping-delta distinct-value counts and
residual entropy: a constant delta means that mapping is derivable from its
anchor (collapse); a varying delta is an independent random gap. It also measures
sibling-worker and crash/respawn invariance within one master. Reads /proc as
ground truth (not an exploit, discloses nothing over the wire; FastCGI traffic
only warms workers).

Lab bring-up: docker compose -f docker-compose.reuse.yml -p p2s-aslrsurvey
--profile aslrsurvey up -d (container p2s-b35-fpm). Pure stdlib, python3 -I safe,
standalone. Lab use, systems you own.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import socket
import struct
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.proc_gdb import zendmm_chunk_bases  # noqa: E402
from common.zend_mm import CHUNK_SIZE  # noqa: E402

# Minimal FastCGI client -- warms a worker so a request-arena chunk exists
def _fcgi_rec(rtype, rid, content=b""):
    return struct.pack(">BBHHBx", 1, rtype, rid, len(content), 0) + content


def _fcgi_nv(pairs):
    out = bytearray()
    for k, v in pairs.items():
        for part in (k.encode(), v.encode()):
            n = len(part)
            out += struct.pack(">I", n | 0x80000000) if n > 127 else bytes([n])
            out += part
    return bytes(out)


def fcgi_warm(host, port, path, docroot="/var/www/html", timeout=5):
    """One GET over a fresh FastCGI connection. Returns True on a clean reply."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False
    try:
        params = {
            "SCRIPT_FILENAME": docroot + path, "SCRIPT_NAME": path,
            "REQUEST_METHOD": "GET", "QUERY_STRING": "",
            "SERVER_PROTOCOL": "HTTP/1.1", "GATEWAY_INTERFACE": "CGI/1.1",
        }
        pkt = (_fcgi_rec(1, 1, struct.pack(">HB5x", 1, 0))
               + _fcgi_rec(4, 1, _fcgi_nv(params)) + _fcgi_rec(4, 1, b"")
               + _fcgi_rec(5, 1, b""))
        s.sendall(pkt)
        got = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            got += d
        return b"fcgi" in got or b"\x03" in got  # body reflects PHP_SAPI
    except OSError:
        return False
    finally:
        s.close()


# docker helpers
def _dock(args, timeout=60):
    p = subprocess.run(["docker"] + args, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode("latin1", "replace"), \
        p.stderr.decode("latin1", "replace")


def restart_master(container):
    rc, _o, e = _dock(["restart", container])
    if rc != 0:
        raise RuntimeError("docker restart failed: " + e.strip())


def wait_ready(host, port, deadline_s=30):
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        try:
            socket.create_connection((host, port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def list_fpm_pids(container):
    """Return (master_pid, [worker_pids]) from /proc/*/comm inside container."""
    rc, out, _e = _dock(["exec", container, "sh", "-c",
                         'for p in /proc/[0-9]*; do printf "%s %s\\n" '
                         '"${p#/proc/}" "$(cat $p/comm 2>/dev/null)"; done'])
    master, workers = None, []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[1] != "php-fpm":
            continue
        pid = int(parts[0])
        if pid == 1 or master is None:
            # php-fpm pid 1 is the master in this container (foreground master).
            if pid == 1:
                master = 1
                continue
        workers.append(pid)
    # if master wasn't pid 1 for some reason, the lowest php-fpm pid is master
    if master is None and workers:
        master = min(workers)
        workers = [w for w in workers if w != master]
    return master, sorted(workers)


def read_maps(container, pid):
    rc, out, _e = _dock(["exec", container, "cat", "/proc/%d/maps" % pid])
    return out if rc == 0 else ""


def kill_worker(container, pid):
    _dock(["exec", container, "kill", "-9", str(pid)])


# maps parsing


def parse_maps(text):
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        rng = parts[0]
        if "-" not in rng:
            continue
        a, b = rng.split("-")
        start, end = int(a, 16), int(b, 16)
        perms = parts[1]
        path = parts[5] if len(parts) >= 6 else ""
        rows.append((start, end, perms, path))
    return rows


def _lowest(rows, pred):
    cand = [r[0] for r in rows if pred(r)]
    return min(cand) if cand else None


def extract_bases(text):
    """Return dict of named base addresses from one /proc/<pid>/maps text."""
    rows = parse_maps(text)
    if not rows:
        return {}
    pie = _lowest(rows, lambda r: r[3].endswith("php-fpm"))
    libc = _lowest(rows, lambda r: "libc.so" in r[3])
    ld = _lowest(rows, lambda r: "ld-linux" in r[3]
                 or os.path.basename(r[3]).startswith("ld-"))
    stack = _lowest(rows, lambda r: r[3] == "[stack]")
    heap = _lowest(rows, lambda r: r[3] == "[heap]")

    # ZendMM chunk(s): anonymous rw-p region(s) ~>=2 MiB in the mmap cluster
    # (within 4 GiB of libc, i.e. same top-down mmap arena, never the PIE/brk
    # region). The chunk base the exploit computes is a 2 MiB-aligned address
    # fully contained in the region; take the lowest such.
    dict_rows = [{"start": s, "end": e, "perm": pm, "off": "00000000",
                  "ino": "0", "path": pth} for (s, e, pm, pth) in rows]
    chunks = zendmm_chunk_bases(dict_rows, min_size=CHUNK_SIZE, max_size=4 * CHUNK_SIZE,
                                libc=libc, near_libc=(1 << 32), align="start",
                                require_fit=True, perm="rw")
    chunks.sort()
    return {
        "pie": pie, "libc": libc, "ld": ld, "stack": stack, "heap": heap,
        "chunk": chunks[0] if chunks else None,
        "chunk_count": len(chunks),
        "chunks": chunks,
    }


# entropy / delta stats
def _entropy_bits(values):
    """Shannon entropy (bits) of the observed value multiset (an N-sample LOWER
    bound on true entropy; all-distinct over N samples saturates at log2 N)."""
    if not values:
        return 0.0
    n = len(values)
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _field_bits(values, gran=0x1000):
    """Bit-width of the randomised field = bit_length of (range / granularity).
    A coarse structural read: how many page-granular positions the span covers."""
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return 0
    span = (max(vals) - min(vals)) // gran
    return span.bit_length()


def summarize_series(name, values, gran=0x1000):
    vals = [v for v in values if v is not None]
    distinct = sorted(set(vals))
    return {
        "name": name,
        "samples": len(vals),
        "distinct": len(distinct),
        "constant": len(distinct) <= 1,
        "min": (min(vals) if vals else None),
        "max": (max(vals) if vals else None),
        "range": ((max(vals) - min(vals)) if vals else None),
        "entropy_bits_observed": round(_entropy_bits(vals), 3),
        "field_bits_span": _field_bits(vals, gran),
    }


# survey
def one_trial(container, host, port, path, warms, respawn_check, verbose):
    # warm every worker so a request-arena chunk exists in each
    for _ in range(warms):
        fcgi_warm(host, port, path)
    master, workers = list_fpm_pids(container)
    if master is None or not workers:
        return {"ok": False, "error": "no fpm master/workers found"}

    master_bases = extract_bases(read_maps(container, master))
    worker_bases = {}
    for w in workers:
        wb = extract_bases(read_maps(container, w))
        if wb:
            worker_bases[w] = wb

    trial = {"ok": True, "master": master_bases, "workers": worker_bases}

    # (b) sibling invariance within this master
    def _col(key):
        return {w: wb.get(key) for w, wb in worker_bases.items()}
    sib = {}
    for key in ("pie", "libc", "ld", "stack", "chunk"):
        vals = [v for v in _col(key).values() if v is not None]
        sib[key] = {"distinct": len(set(vals)), "invariant": len(set(vals)) <= 1}
    trial["sibling_invariance"] = sib

    # (c) crash/respawn invariance: kill one worker, warm a respawn, re-read
    if respawn_check and workers:
        victim = workers[0]
        before = worker_bases.get(victim, {})
        kill_worker(container, victim)
        time.sleep(0.6)
        for _ in range(max(2, warms)):
            fcgi_warm(host, port, path)
        _m, w2 = list_fpm_pids(container)
        new = [p for p in w2 if p not in workers]
        after = extract_bases(read_maps(container, new[0])) if new else {}
        trial["respawn"] = {
            "victim": victim,
            "respawned_pid": (new[0] if new else None),
            "pie_same": before.get("pie") == after.get("pie"),
            "libc_same": before.get("libc") == after.get("libc"),
            "chunk_same": before.get("chunk") == after.get("chunk"),
            "before": {k: before.get(k) for k in ("pie", "libc", "chunk")},
            "after": {k: after.get(k) for k in ("pie", "libc", "chunk")},
        }
    if verbose:
        mb = master_bases
        print("    pie=%s libc=%s ld=%s chunk=%s stack=%s heap=%s "
              "sib_inv=%s" % (
                  _h(mb.get("pie")), _h(mb.get("libc")), _h(mb.get("ld")),
                  _h(mb.get("chunk")), _h(mb.get("stack")), _h(mb.get("heap")),
                  all(s["invariant"] for s in sib.values())))
    return trial


def _h(v):
    return ("0x%x" % v) if isinstance(v, int) else "None"


def run_survey(container, host, port, path, trials, warms, respawn_check,
               settle, out_path, verbose=True):
    records = []
    for i in range(1, trials + 1):
        if verbose:
            print("[trial %d/%d] restarting master..." % (i, trials))
        restart_master(container)
        if not wait_ready(host, port):
            print("    WARNING: fpm not ready after restart; skipping trial")
            continue
        time.sleep(settle)
        rec = one_trial(container, host, port, path, warms,
                        respawn_check=(respawn_check and i <= 10), verbose=verbose)
        rec["trial"] = i
        records.append(rec)

    report = build_report(records)
    if out_path:
        with open(out_path, "w") as f:
            json.dump({"records": records, "report": report}, f, indent=2)
        print("\n[+] raw+report written to %s" % out_path)
    print_report(report)
    return report, records


DELTAS = [
    ("libc - pie", "libc", "pie"),
    ("ld - libc", "ld", "libc"),
    ("chunk - libc", "chunk", "libc"),
    ("chunk - ld", "chunk", "ld"),
    ("stack - libc", "stack", "libc"),
    ("stack - pie", "stack", "pie"),
    ("heap - pie", "heap", "pie"),
    ("chunk - pie", "chunk", "pie"),
]


def build_report(records):
    good = [r for r in records if r.get("ok") and r.get("master")]
    series = {k: [r["master"].get(k) for r in good]
              for k in ("pie", "libc", "ld", "stack", "heap", "chunk")}
    abs_stats = {k: summarize_series(k, v) for k, v in series.items()}

    delta_stats = []
    for (nm, a, b) in DELTAS:
        vals = []
        for r in good:
            x, y = r["master"].get(a), r["master"].get(b)
            if x is not None and y is not None:
                vals.append(x - y)
        delta_stats.append(summarize_series(nm, vals, gran=0x1000))

    # fork-fixed facts
    sib_all = []
    for r in good:
        si = r.get("sibling_invariance", {})
        sib_all.append(all(v["invariant"] for v in si.values()) if si else None)
    respawns = [r["respawn"] for r in good if r.get("respawn")]
    respawn_ok = sum(1 for x in respawns
                     if x["pie_same"] and x["libc_same"] and x["chunk_same"])

    return {
        "trials_measured": len(good),
        "absolute_bases": abs_stats,
        "deltas": delta_stats,
        "sibling_invariant_trials": sib_all,
        "sibling_invariant_all": (all(x for x in sib_all if x is not None)
                                  and any(x is not None for x in sib_all)),
        "respawn_checks": len(respawns),
        "respawn_layout_preserved": respawn_ok,
        "clusters": classify_clusters(delta_stats),
    }


def classify_clusters(delta_stats):
    """Name the independent random gaps: a CONSTANT delta => same cluster."""
    byname = {d["name"]: d for d in delta_stats}
    return {
        "libc_chunk_ld_one_cluster": all(
            byname.get(n, {}).get("constant")
            for n in ("ld - libc", "chunk - libc")),
        "pie_independent_of_mmap": not byname.get("libc - pie", {}).get(
            "constant", False),
        "stack_independent": not byname.get("stack - libc", {}).get(
            "constant", False),
        "heap_tracks_pie": byname.get("heap - pie", {}).get("constant", False),
    }


def print_report(rep):
    print("\n" + "=" * 70)
    print("Hope-B3 ASLR-DELTA SURVEY  (trials measured: %d)" %
          rep["trials_measured"])
    print("=" * 70)
    print("\nABSOLUTE BASES (per master restart):")
    print("  %-7s %8s %7s  %-18s %-18s" %
          ("name", "distinct", "fbits", "min", "max"))
    for k, s in rep["absolute_bases"].items():
        print("  %-7s %8d %7d  %-18s %-18s" %
              (k, s["distinct"], s["field_bits_span"], _h(s["min"]), _h(s["max"])))
    print("\nINTER-MAPPING DELTAS (constant => one shared random gap / collapse):")
    print("  %-14s %8s %9s  %s" % ("delta", "distinct", "constant", "value/range"))
    for s in rep["deltas"]:
        v = (_h(s["min"]) if s["constant"]
             else "range=%s over %d vals" % (_h(s["range"]), s["distinct"]))
        print("  %-14s %8d %9s  %s" %
              (s["name"], s["distinct"], str(s["constant"]), v))
    c = rep["clusters"]
    print("\nCLUSTER STRUCTURE:")
    print("  libc/ld/chunk share ONE mmap gap : %s" %
          c["libc_chunk_ld_one_cluster"])
    print("  PIE base independent of mmap     : %s" % c["pie_independent_of_mmap"])
    print("  stack independent                : %s" % c["stack_independent"])
    print("  heap(brk) tracks PIE             : %s" % c["heap_tracks_pie"])
    print("\nFORK-FIXED ASLR:")
    print("  sibling-invariant on all trials  : %s" %
          rep["sibling_invariant_all"])
    print("  crash/respawn layout preserved   : %d/%d" %
          (rep["respawn_layout_preserved"], rep["respawn_checks"]))
    print("=" * 70)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Hope-B3 ASLR-delta collapse survey over fpm master restarts")
    ap.add_argument("--container", default="p2s-b35-fpm")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9435, help="published fpm port")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--warms", type=int, default=12,
                    help="warm requests per trial (>= worker count)")
    ap.add_argument("--settle", type=float, default=0.4)
    ap.add_argument("--no-respawn", action="store_true",
                    help="skip the crash/respawn invariance sub-check")
    ap.add_argument("--out", default=None, help="write raw+report JSON here")
    args = ap.parse_args(argv)

    if not wait_ready(args.host, args.port, deadline_s=5):
        print("[!] fpm not reachable at %s:%d -- bring the lab up:\n"
              "    docker compose -f docker-compose.reuse.yml -p p2s-aslrsurvey"
              " --profile aslrsurvey up -d"
              % (args.host, args.port), file=sys.stderr)
        return 2

    run_survey(args.container, args.host, args.port, args.path, args.trials,
               args.warms, respawn_check=not args.no_respawn,
               settle=args.settle, out_path=args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
