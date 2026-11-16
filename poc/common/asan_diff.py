#!/usr/bin/env python3
"""Shared ASan differential test plumbing.

Canonical helpers for running a PHP source snippet inside an ASan-built docker
image and detecting a sanitizer hit in the output. ``run_asan`` runs the source
via a mounted temp file and returns (rc, combined_output); ``has_uaf`` reports
whether the output carries a use-after-free / AddressSanitizer report, optionally
gated on a specific stack frame. The image tag and the UAF-frame signature are
always caller arguments. stdlib only.
"""
from __future__ import annotations

import os
import subprocess
import tempfile


def run_asan(php_src, image, env=None, php_ini=None, timeout=120):
    """Run `php_src` under `image`; return (rc, stdout+stderr).

    `env`     -- dict of environment vars passed as `docker run -e K=V`.
    `php_ini` -- dict of php ini settings passed as `php -d k=v`.
    The source is written to a temp file and bind-mounted read-only at
    /tmp/t.php. Exec failures are returned as (-1, "[exec error: ...]").
    """
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
        f.write(php_src)
        local = f.name
    try:
        cmd = ["docker", "run", "--rm"]
        for k, v in (env or {}).items():
            cmd += ["-e", "%s=%s" % (k, v)]
        cmd += ["-v", "%s:/tmp/t.php:ro" % local, image, "php"]
        for k, v in (php_ini or {}).items():
            cmd += ["-d", "%s=%s" % (k, v)]
        cmd += ["/tmp/t.php"]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, (r.stdout.decode("utf-8", "replace")
                              + r.stderr.decode("utf-8", "replace"))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return -1, "[exec error: %r]" % e
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass


def has_uaf(out, frame=None):
    """True iff `out` carries an ASan/UAF report (optionally gated on `frame`)."""
    hit = ("heap-use-after-free" in out) or ("AddressSanitizer" in out)
    if frame is not None:
        hit = hit and (frame in out)
    return hit
