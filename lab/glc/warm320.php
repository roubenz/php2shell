<?php
/* glc lab bin-320 warm page (the flp warm page).
 *
 * Its only job is to WARM a worker so the request heap exists and the bin-320
 * small-bin free list is populated the way a live request leaves it -- the state
 * the probe inspects (shadow_key read, free-slot discovery) and drives (poison).
 * A burst of same-size (280-byte -> bin-320) allocations ensures that size class
 * has a chunk and a non-empty free list once the burst strings are released.
 *
 * Lab/analysis use only, on systems you own.
 */
header('Content-Type: text/plain');

$keep = [];
for ($i = 0; $i < 64; $i++) {
    $keep[$i] = str_repeat('A', 280);       // 280 B -> 320 size class (bin 16)
}
$sum = 0;
foreach ($keep as $s) { $sum += strlen($s); }
$keep = null;                               // release -> bin-320 free list repopulates

echo "glc warm " . PHP_VERSION . " " . php_sapi_name()
    . " pid=" . getmypid() . " sum=" . $sum . "\n";
