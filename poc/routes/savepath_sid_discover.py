#!/usr/bin/env python3
"""Point-and-shoot session save_path + sid autodiscovery (candidate table).

Builds the on-disk sess_<id> path guesses a session-file include chain needs
instead of a known session.save_path: (1) mints a 32-char hex sid
PHP accepts under strict_mode=Off regardless of its sid_bits_per_character;
(2) enumerates a distro/container save_path table expanded across Debian-style
hashed subdir depths (``N;[MODE;]path``).

A guess table, not a probe (nothing reads the target); confirmation is a read
strategy landing a marker. Widen with --save-path / --depth. -I safe.
"""

import argparse
import os
import sys

# Distro / container session.save_path defaults, cheapest/most common first.
SAVE_PATHS = [
    "/var/lib/php/sessions",   # Debian/Ubuntu (modern), RHEL
    "/var/lib/php/session",    # some RHEL packaging
    "/var/lib/php5/sessions",  # Debian/Ubuntu (php5 era)
    "/var/lib/php5",           # php5 bare
    "/var/lib/php7/sessions",  # some php7 packaging
    "/var/lib/php8/sessions",  # some php8 packaging
    "/var/lib/php",            # bare packaging
    "/var/lib/php-fpm/session",# RHEL/CentOS fpm
    "/var/lib/php-fpm",        # RHEL/CentOS fpm bare
    "/tmp",                    # PHP source default + Alpine + FreeBSD
    "/var/tmp",                # PHP source fallback
    "/dev/shm",                # common tmpfs performance override
    "/tmp/sessions",           # app-local tmp
    "/run/php",                # some systemd units
    "/var/sess",               # this project's labs
    "/var/cpanel/php/sessions",# cPanel
    "/var/lib/php/sessions/mod_php",  # Plesk mod_php
    "/opt/php/sessions",       # custom builds
    "/usr/local/php/sessions", # source-build prefix
    "/opt/bitnami/php/tmp/sessions",   # Bitnami stacks
    "/opt/lampp/temp",         # XAMPP/Linux
    "/app/sessions",           # containerised apps
    "/app/var/sessions",       # Symfony-ish containers
    "/var/opt/remi/php*/lib/php/session",  # Remi (literal; widen if used)
    "/var/www/sessions",       # app-local
]

# Debian hashed-subdir depths to try for each base (0 = flat sess_<id>).
HASH_DEPTHS = (0, 1, 2)

SID_CHARSET = "0123456789abcdef"  # hex: a subset of every PHP sid alphabet.


def mint_sid(length=32):
    """A client sid PHP accepts under use_strict_mode=Off, independent of the
    target's sid_length / sid_bits_per_character (hex within [22,256])."""
    length = max(22, min(256, length))
    raw = os.urandom(length)
    return "".join(SID_CHARSET[b & 0x0F] for b in raw)


def _hashed(base, sid, depth):
    """Debian 'N;path' layout: file under `depth` single-char subdirs of base."""
    base = base.rstrip("/")
    parts = [base] + [sid[i] for i in range(depth)]
    return "/".join(parts) + f"/sess_{sid}"


def sess_candidates(sid, save_paths=None, depths=HASH_DEPTHS):
    """Full ordered list of candidate on-disk sess_<id> paths for a sid.
    De-duplicated, preserving the (save_path, depth) priority order."""
    save_paths = save_paths or SAVE_PATHS
    out, seen = [], set()
    for sp in save_paths:
        for d in depths:
            p = _hashed(sp, sid, d)
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def discover(sid=None, save_paths=None, depths=HASH_DEPTHS, sid_length=32):
    """Return (sid, [candidate sess-file paths...]). Mints a sid if none given."""
    sid = sid or mint_sid(sid_length)
    return sid, sess_candidates(sid, save_paths=save_paths, depths=depths)


def _cli(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sid", help="use this sid instead of minting one")
    ap.add_argument("--sid-length", type=int, default=32,
                    help="minted sid length (default 32, clamped to 22..256)")
    ap.add_argument("--save-path", action="append",
                    help="extra save_path to prepend (repeatable)")
    ap.add_argument("--depth", type=int, action="append",
                    help="hashed-subdir depth to try (repeatable; default 0,1,2)")
    args = ap.parse_args(argv)

    save_paths = (args.save_path + SAVE_PATHS) if args.save_path else None
    depths = tuple(args.depth) if args.depth else HASH_DEPTHS
    sid, cands = discover(sid=args.sid, save_paths=save_paths, depths=depths,
                          sid_length=args.sid_length)
    print(f"sid: {sid}")
    print(f"{len(cands)} candidate sess-file paths:")
    for c in cands:
        print(f"  {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
