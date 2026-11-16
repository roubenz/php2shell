#!/usr/bin/env python3
"""HTTP client + lab recon helpers (project plumbing, stdlib only).

    http(url, data=None, headers=None, timeout=180) -> (status, body)
    http_full(url, ...) -> (status, headers_dict, body)   # also returns headers
    report(label, status, body, base, short_timeout=None, check_path="/index.php")
        Print a request's status/body tail, then whether the worker is alive.
    worker_alive(base, timeout=8) -> bool     GET base/index.php, true on HTTP 200.
    curl(args_list, timeout=90, service=None) -> bytes
        Run the curl binary, optionally inside a lab container.
    probe_php_version(base, service=None) -> (version, sapi)
        Read index.php's JSON {"php","sapi"}.
"""

import http.client
import json
import socket
import subprocess
import urllib.error
import urllib.request

# A target that dies mid-response surfaces as a transport/parse failure deep in
# http.client (IncompleteRead/BadStatusLine -> HTTPException) or, for a truncated
# chunked body, a bare ValueError from int(chunk_size, 16). Treat all of these as
# "request failed" and return (None, ...) rather than letting them escape.
_NET_ERRORS = (urllib.error.URLError, ConnectionError, socket.timeout, OSError,
               http.client.HTTPException, ValueError)


def _read(resp):
    try:
        return resp.read()
    except _NET_ERRORS:
        return b""


def http(url, data=None, headers=None, timeout=180):
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, _read(r)
    except urllib.error.HTTPError as e:
        return e.code, _read(e)
    except _NET_ERRORS as e:
        return None, str(e).encode()


def http_full(url, data=None, headers=None, timeout=60):
    """Like http(), but also returns the response headers (recon)."""
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), _read(r)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), _read(e)
    except _NET_ERRORS as e:
        return None, {}, str(e).encode()


def worker_alive(base, timeout=8):
    """True iff GET base/index.php returns HTTP 200."""
    s, _ = http(base.rstrip("/") + "/index.php", timeout=timeout)
    return s == 200


def report(label, status, body, base, short_timeout=None, check_path="/index.php"):
    tail = body[-300:].decode("utf-8", "replace").strip()
    print(f"[{label}] HTTP {status} ({len(body)} bytes)")
    if tail:
        print(f"[{label}] body tail: {tail!r}")
    s2, b2 = http(base.rstrip("/") + check_path, timeout=short_timeout or 15)
    alive = s2 == 200
    info = ""
    if alive:
        try:
            info = " " + json.loads(b2).get("php", "")
        except Exception:
            pass
    print(f"[{label}] worker alive after: {alive}{info}")
    if not alive:
        print(f"[{label}] worker died or hung - check `docker compose logs` "
              f"for a segfault / ASan report")


def curl(args_list, timeout=90, service=None):
    """Run curl (a fixed client: the HTTP_* strings it sends shift the target
    heap layout, so one client pins the grooming sequence). With service=NAME,
    run curl inside the lab container via docker compose exec."""
    prefix = ["curl", "-s", "-m", str(timeout)]
    if service is None:
        cmd = prefix + args_list
        kwargs = {"capture_output": True, "timeout": timeout + 10}
    else:
        cmd = ["docker", "compose", "exec", "-T", service] + prefix + args_list
        kwargs = {"capture_output": True, "timeout": timeout + 30}
    try:
        r = subprocess.run(cmd, **kwargs)
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"curl failed: {e}".encode()


def probe_php_version(base, service=None):
    """index.php answers {"ok":true,"php":"<version>",...}."""
    out = curl([f"{base.rstrip('/')}/index.php"], 15, service=service)
    try:
        info = json.loads(out.decode())
        return info.get("php"), info.get("sapi")
    except Exception:
        return None, None
