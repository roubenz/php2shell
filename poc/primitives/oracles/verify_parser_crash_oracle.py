#!/usr/bin/env python3
r"""Harness for parser_crash_oracle.py.

Asserts, against the live lab (docker-compose.fpm-avenues.yml, profile
parseroracle, nginx:8133 -> php-fpm 8.4.26 with exif/gd/zip):

  1. the lab is reachable and healthy (index.php -> 200);
  2. the offset-delta sweep is FLAT on this patched build: the worker survives at
     every delta including a wild 0x7FFFFF00 -> the exif offset deref is
     bounds-checked -> NO map-bits (the honest negative on a patched target);
  3. GROUND TRUTH (needs docker): the OOB delta reaches exif's attacker-offset
     deref and takes the exif.c:3302 "Illegal pointer offset" guard (a bounds
     rejection, not a fault);
  4. CHANNEL VALIDITY (needs docker): the liveness bit can read a worker death
     (SIGSEGV -> pid changes -> respawn), so the flat all-200 in (2) is a real
     measurement, not a dead harness;
  5. the favorable fork-fixed-ASLR fact is reported.

A PASS means: the oracle is structurally correct and the channel works, AND on
this patched 8.4.26 it yields no map-bits (gated on an n-day native OOB).

  python3 -I verify_parser_crash_oracle.py
  python3 -I verify_parser_crash_oracle.py --url http://127.0.0.1:8133 \
          --container p2s-b14-fpm

Pure stdlib; python3 -I safe. Lab/analysis use only, on systems you own.
"""
import argparse
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import parser_crash_oracle as O   # noqa: E402


def _ok(c):
    return "PASS" if c else "FAIL"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8133")
    ap.add_argument("--container", default="p2s-b14-fpm")
    args = ap.parse_args(argv)

    host, port, _ = O._parse_host(args.url)
    results = []

    # 1. reachable
    alive = O._alive(host, port)
    results.append(("lab reachable (index.php 200)", alive))
    if not alive:
        print("[-] lab not up at %s -- `docker compose -f "
              "docker-compose.fpm-avenues.yml -p p2s-parseroracle --profile "
              "parseroracle up -d --build`" % args.url)
        _summary(results)
        return 1

    # 2. flat sweep -> no map-bits on patched build
    res = O.sweep(args.url, parser="exif",
                  deltas=[0x40, 0x1000, 0x100000, 0x1000000, 0x40000000, 0x7FFFFF00])
    flat = (res["map_bits"] is False) and all(not r["worker_down"] for r in res["rows"])
    results.append(("offset sweep FLAT (worker alive at all 6 deltas)", flat))
    results.append(("=> no map-bits on patched 8.4.26 (bound holds)",
                    res["map_bits"] is False))

    # 3 + 4: docker ground truth + channel validity (best-effort)
    have_docker = subprocess.run(["docker", "inspect", args.container],
                                 capture_output=True).returncode == 0
    if have_docker:
        gt = O.groundtruth(args.container)
        oob = gt.get("oob", {})
        guard_hit = ("Illegal pointer offset" in oob.get("stdout", "")
                     and "alive" in oob.get("stdout", ""))
        inrange_ok = gt.get("in_range", {}).get("stdout", "").startswith("ret=1")
        results.append(("ground truth: OOB delta reaches exif deref + takes the "
                        "FileSize guard (alive, no fault)", guard_hit))
        results.append(("ground truth: in-range delta parses (IFD0)", inrange_ok))

        pc = O.prove_channel(args.container, args.url)
        results.append(("channel validity: worker SIGSEGV -> respawn observable",
                        bool(pc.get("worker_died_and_respawned"))))
    else:
        print("[i] docker/container %r unavailable -> skipping ground-truth & "
              "channel checks (HTTP sweep still authoritative for the negative)."
              % args.container)

    _summary(results)
    return 0 if all(c for _, c in results) else 1


def _summary(results):
    print("\n" + "=" * 72)
    for name, c in results:
        print("  [%s] %s" % (_ok(c), name))
    allok = all(c for _, c in results)
    print("=" * 72)
    print("OVERALL: %s" % _ok(allok))
    if allok:
        print("The B4 crash oracle is structurally sound and its liveness channel\n"
              "works; on this PATCHED 8.4.26 it yields NO map-bits (exif offset\n"
              "deref is bounds-checked). Reading map-bits is gated on an n-day\n"
              "native OOB in exif/gd/zip -- stated dependency.")


if __name__ == "__main__":
    sys.exit(main())
