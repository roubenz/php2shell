<?php
/* rx.php -- a minimal reflect-unserialize sink, used ONLY to demonstrate the
 * CVE's index-relative R:<id>; source empirically (NOT a weaponisation surface).
 *
 * echo serialize(unserialize($_POST['cook'])) is the classic a7 reflection. It
 * lets the analysis module show two facts about R: that the whole thesis rests
 * on, directly on a live worker, with the attacker supplying zero absolute
 * address:
 *   1. R:<id>; selects its source value by INDEX in the decode var_hash
 *      (a:2:{i:0;s:3:"abc";i:1;R:2;} reflects back a reference to entry #2), and
 *   2. an R: back-reference onto a reclaimed slot (via the CachedData var_hash
 *      UAF) makes the engine stamp a LIVE, correctly-based heap pointer there
 *      (ZVAL_MAKE_REF) which reflects back -- an engine-SUPPLIED pointer value
 *      obtained index-relative, the exact value class the thesis wants to move.
 *
 * It performs no include and no write. The CachedData Serializable gadget (the
 * same one every a7 lab ships, lab/seo/html/gadget.php) is inlined so the R:
 * spray can reclaim; defining the gadget class is standard a7-lab harness, not
 * part of the modelled attacker surface.
 */
error_reporting(E_ALL & ~E_DEPRECATED);
ini_set('display_errors', '0');

class CachedData implements Serializable
{
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void { unserialize($data)->x = 0; }
}

header('Content-Type: text/plain');
if (isset($_POST['cook'])) {
    echo serialize(@unserialize($_POST['cook']));
}
