#!/usr/bin/env python3
"""docker-lab test plumbing (stdlib only).

Docker-exec wrappers (``_dx``/``sh``/``dexec``), container/worker
liveness probes (``container_up``/``worker_alive``), HTTP readiness polling
(``wait_ready``) and the /proc php-fpm base reader (``proc_binbase``).
Container, compose and profile names are always caller arguments. stdlib only.
"""
from __future__ import annotations

import subprocess


def _dx(container, *cmd):
    """docker exec `cmd` in `container`; return (rc, stdout+stderr)."""
    p = subprocess.run(["docker", "exec", container, *cmd],
                       capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def sh(*args, check=True):
    """Run `args`; return combined stdout+stderr as text. Raise on failure when check."""
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = r.stdout.decode(errors="replace")
    if check and r.returncode != 0:
        raise RuntimeError("cmd failed (%d): %s\n%s"
                           % (r.returncode, " ".join(args), out))
    return out


def dexec(container, *cmd, check=True):
    """docker exec `cmd` in `container` via sh(); return combined output text."""
    return sh("docker", "exec", container, *cmd, check=check)


def container_up(name):
    """True iff a docker container named `name` is listed by `docker ps`."""
    r = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                       capture_output=True, text=True)
    return name in r.stdout.split()


def wait_ready(host, port, tries=40, path="/plain.php"):
    """Poll http://host:port/path until it returns HTTP 200 (or `tries` elapse)."""
    import http.client
    import time
    for _ in range(tries):
        try:
            c = http.client.HTTPConnection(host, port, timeout=4)
            c.request("GET", path)
            r = c.getresponse()
            r.read()
            if r.status == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def proc_binbase(container):
    """Read the php-fpm base address from /proc/1/maps inside `container`."""
    rc, out = _dx(container, "sh", "-c",
                  "grep -m1 php-fpm /proc/1/maps | cut -d- -f1")
    if rc != 0 or not out.strip():
        return None
    try:
        return int(out.strip(), 16)
    except ValueError:
        return None


def worker_alive(container):
    """True iff a php-fpm 'pool www' worker process exists in `container`."""
    rc, out = _dx(container, "sh", "-c",
                  'for p in /proc/[0-9]*; do tr "\\0" " " < $p/cmdline '
                  '2>/dev/null; echo; done')
    return "pool www" in out
