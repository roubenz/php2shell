#!/usr/bin/env python3
"""Driver for include_vectors.py: lands `id` (uid=www-data) through each
alternative inclusion vector and prints a PASS/FAIL per vector, resetting lab
state (poisoned log, dropped .user.ini/carrier) between vectors via `docker exec`
so they are judged independently.

Bring up the lab:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-incvec --profile incvec up -d --build
    python3 -I poc/routes/verify_include_vectors.py --port 8138
"""

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import include_vectors as iv  # noqa: E402


def _reset(container):
    """Best-effort lab reset: drop any .user.ini/carrier, truncate the log."""
    if not container:
        return
    try:
        subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             "rm -f /var/www/html/.user.ini /var/www/html/p2s_carrier.jpg "
             "/var/www/html/*.jpg; : > /var/log/php/error.log 2>/dev/null || true"],
            check=False, capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        pass


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8138)
    ap.add_argument("--base", default="/index.php")
    ap.add_argument("--param", default="page")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--vector", choices=iv.VECTORS, action="append",
                    help="limit to these vectors (repeatable; default: all)")
    ap.add_argument("--attempts", type=int, default=20)
    ap.add_argument("--container", default="p2s-a23-fpm",
                    help="fpm container for between-vector reset ('' to skip)")
    args = ap.parse_args(argv)

    # (label, vector, extra-kwargs). logpoison is split into its two sinks so the
    # html_errors-dependent (errorlog) and -independent (accesslog) paths are both
    # judged.
    all_tasks = [
        ("direct", "direct", {}),
        ("filter", "filter", {}),
        ("logpoison-errorlog", "logpoison",
         {"source": "errorlog", "log_paths": ["/var/log/php/error.log"]}),
        ("logpoison-accesslog", "logpoison",
         {"source": "accesslog", "log_paths": ["/var/log/php/access.log"]}),
        ("userini", "userini", {}),
    ]
    want = set(args.vector) if args.vector else None
    tasks = [t for t in all_tasks if want is None or t[1] in want]

    print(f"=== include-vectors verify  http://{args.host}:{args.port}{args.base} ===")
    results = {}
    for label, vec, kw in tasks:
        _reset(args.container)
        print(f"\n--- {label} ---")
        ok, out, hit = iv.run(
            args.host, args.port, args.cmd, vector=vec, base=args.base,
            param=args.param, attempts=args.attempts, verbose=True, **kw)
        uid_ok = ok and "uid=" in (out or "")
        results[label] = uid_ok
        print(f"    => {'PASS' if uid_ok else 'FAIL'}  hit={hit}  "
              f"out={(out or '').strip()!r}")

    _reset(args.container)
    print("\n=== SUMMARY ===")
    for label in results:
        print(f"  {label:22s}: {'PASS (uid=www-data)' if results[label] else 'FAIL'}")
    passed = [l for l, ok in results.items() if ok]
    print(f"\nRESULT: {len(passed)}/{len(results)} checks landed: {passed}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
