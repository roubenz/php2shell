<?php
// Free-list-head SEAT (seat) lab app. Benign. Warms a worker so the request
// heap exists and the bin-320 free list is populated the way a live request
// leaves it (a burst of 280-byte strings -> round up to the 320 size class,
// then released so that size class has a chunk and a non-empty free list).
//
// Lab/analysis use only, on systems you own.
header('Content-Type: text/plain');

$keep = [];
for ($i = 0; $i < 64; $i++) {
    $keep[$i] = str_repeat('A', 280);
}
$sum = 0;
foreach ($keep as $s) { $sum += strlen($s); }
$keep = null;              // release -> bin-320 free list repopulates

echo "seat warm " . PHP_VERSION . " " . php_sapi_name() . " pid=" . getmypid() . " sum=" . $sum . "\n";
