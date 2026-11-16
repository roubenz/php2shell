#!/usr/bin/env python3
"""verify_wp_probe.py - self-test for the WordPress fingerprint parsers, plus an
optional live check.

Offline (no lab):
    python3 -I poc/primitives/oracles/verify_wp_probe.py
Live (WordPress lab):
    docker compose -f docker-compose.apps.yml --profile wp854 up -d
    python3 -I poc/primitives/oracles/verify_wp_probe.py --url http://127.0.0.1:19500/wordpress
"""
import argparse
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))  # poc/


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default=None, help="live WordPress base URL")
    args = ap.parse_args()

    p = subprocess.run([sys.executable, "-I", os.path.join(_HERE, "wp_probe.py")],
                       capture_output=True, text=True, timeout=30)
    sys.stdout.write(p.stdout)
    ok = p.returncode == 0

    if args.url:
        from common.http_urllib import http_full
        from primitives.oracles.wp_probe import detect_wordpress
        r = detect_wordpress(http_full, args.url)
        print(f"  live: is_wp={r['is_wp']} version={r['wp_version']} "
              f"endpoints={list(r['endpoints'])}")
        ok &= r["is_wp"]
    print("PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
