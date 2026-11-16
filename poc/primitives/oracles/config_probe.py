#!/usr/bin/env python3
# INDEX: non-destructive fingerprint + config read for the vuln checker | all | passive
"""Passive fingerprint + config read for the php2shell vulnerability checker.

Non-destructive: one GET, header/banner parse, plus an opportunistic read of any
JSON config the endpoint volunteers (the lab index.php, or an app status page)
or an operator-supplied phpinfo() page. No OOM, no bug interaction.

Signals, highest-confidence first:
  * X-Powered-By: PHP/x.y.z          -> version
  * Server / SAPI JSON field         -> SAPI (cli-server | fpm-fcgi | apache2handler)
  * Server: nginx|Apache             -> SAPI hint when no JSON (nginx->fpm, Apache->apache)
  * JSON {php,sapi,memory_limit,...} -> config facts (lab / status endpoints)
  * phpinfo() HTML                   -> version, SAPI, memory_limit, session.upload_progress.*,
                                        display_errors, expose_php

Config facts feed the soft/dangerous layers (memory_limit sizes the trigger;
upload_progress gates the CVE-2026-109619 path). stdlib only; python3 -I safe.
"""
from __future__ import annotations

import json
import re

CONFIG_KEYS = ("memory_limit", "post_max_size", "upload_progress",
               "max_file_uploads")

_VER_RE = re.compile(r"PHP/?\s*(\d+\.\d+\.\d+)", re.I)


def _version_tuple(s):
    """Bare X.Y.Z (for explicit PHP-version fields like the JSON 'php' key)."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _php_version(s):
    """A PHP version ONLY from a 'PHP/x.y.z' token -- never a bare X.Y.Z, so the
    webserver version in a Server header (Apache/2.4.x, nginx/1.27.x) is not
    misread as PHP's."""
    m = _VER_RE.search(s or "")
    return (tuple(int(x) for x in m.group(1).split("."))) if m else None


def sapi_from(server, powered_by, json_sapi):
    """Resolve SAPI. JSON 'sapi' is authoritative; otherwise the Server banner."""
    if json_sapi:
        js = json_sapi.lower()
        if "fpm" in js or "fcgi" in js:
            return "fpm"
        if "apache" in js:
            return "apache"
        if "cli" in js:
            return "cli-server"
    s = (server or "").lower()
    if "apache" in s:
        return "apache"
    if "nginx" in s:
        return "fpm"          # nginx front almost always fronts php-fpm
    if not server and powered_by:
        return None           # X-Powered-By but no Server: could be php -S or stripped proxy
    return None


def parse_phpinfo(html):
    """Pull the bug-relevant INI from a phpinfo() HTML page. Best-effort."""
    if isinstance(html, bytes):
        html = html.decode("latin1", "replace")
    out = {}
    vm = _VER_RE.search(html)
    if vm:
        out["php"] = vm.group(1)
    # phpinfo renders "<tr><td>name</td><td>local</td><td>master</td></tr>"
    def _cell(name):
        m = re.search(r"%s\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*</td>" % re.escape(name),
                      html, re.I)
        return m.group(1).strip() if m else None
    for ini in ("memory_limit", "post_max_size", "max_file_uploads",
                "display_errors", "expose_php",
                "session.upload_progress.enabled",
                "session.upload_progress.cleanup",
                "session.upload_progress.prefix",
                "session.upload_progress.name"):
        v = _cell(ini)
        if v is not None:
            out[ini] = v
    sm = re.search(r"Server API\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*</td>", html, re.I)
    if sm:
        out["sapi"] = sm.group(1).strip()
    return out


def read_fingerprint(status, headers, body):
    """Turn a (status, headers_dict, body) response into a fingerprint dict:
       {status, server, powered_by, version(tuple|None), sapi(str|None), config{}}.
    `config` carries whatever the endpoint volunteered (may be empty)."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    # PHP version only from a PHP/x.y.z token (X-Powered-By, or a PHP-naming
    # Server header); never from the webserver's own version.
    version = _php_version(powered) or _php_version(server)
    config = {}
    json_sapi = None
    # opportunistic JSON config (lab index.php / app status endpoints)
    if body:
        try:
            doc = json.loads(body)
            if isinstance(doc, dict):
                if not version and doc.get("php"):
                    version = _version_tuple(doc["php"])
                json_sapi = doc.get("sapi")
                for k in CONFIG_KEYS:
                    if k in doc:
                        config[k] = doc[k]
        except Exception:
            pass
    sapi = sapi_from(server, powered, json_sapi)
    return {"status": status, "server": server, "powered_by": powered,
            "version": version, "sapi": sapi, "config": config}


if __name__ == "__main__":
    # self-test against representative header/body shapes seen in the labs
    samples = [
        (200, {"X-Powered-By": "PHP/8.4.26"},
         b'{"php":"8.4.26","sapi":"cli-server","memory_limit":"16M","upload_progress":"1"}'),
        (200, {"Server": "nginx/1.27.5", "X-Powered-By": "PHP/8.4.27"},
         b'{"php":"8.4.27","sapi":"fpm-fcgi","memory_limit":"16M"}'),
        (200, {"Server": "Apache/2.4.69 (Debian)", "X-Powered-By": "PHP/8.4.26"},
         b'{"php":"8.4.26","sapi":"apache2handler","memory_limit":"128M"}'),
        (200, {"X-Powered-By": "PHP/8.5.11"}, b"<html>not json</html>"),
    ]
    for st, hd, bd in samples:
        fp = read_fingerprint(st, hd, bd)
        print(f"  ver={fp['version']} sapi={fp['sapi']!s:11} config={fp['config']}")
    print("ok")
