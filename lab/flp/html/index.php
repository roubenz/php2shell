<?php
// Free-list poison (flp) lab app. Benign. Its only job is to WARM a worker so
// the request heap exists and the small-bin free lists are populated the way a
// live request leaves them -- the state the probe inspects and drives. A burst
// of same-size (bin-320) allocations here ensures that size class has a chunk
// and a non-empty free list once the burst strings are released.
//
// Lab/analysis use only, on systems you own.
header('Content-Type: text/plain');

// Churn bin-320 (280-byte payloads round up to the 320 size class): allocate a
// batch, then let them fall out of scope so they return to the free list.
$keep = [];
for ($i = 0; $i < 64; $i++) {
    $keep[$i] = str_repeat('A', 280);
}
$sum = 0;
foreach ($keep as $s) { $sum += strlen($s); }
$keep = null;              // release -> bin-320 free list repopulates

echo "flp warm " . PHP_VERSION . " " . php_sapi_name() . " pid=" . getmypid() . " sum=" . $sum . "\n";
