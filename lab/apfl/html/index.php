<?php
// Apache free-list-poison -> libphp (apfl) lab app. Benign. Its only job is to
// WARM the single prefork worker so the request heap exists and the small-bin
// free lists are populated the way a live request leaves them -- the state the
// probe inspects and drives via the exported allocator symbols. A burst of
// same-size (bin-320) allocations ensures that size class has a chunk and a
// non-empty free list once the burst strings fall out of scope.
//
// Lab/analysis use only, on systems you own.
header('Content-Type: text/plain');

$keep = [];
for ($i = 0; $i < 64; $i++) {
    $keep[$i] = str_repeat('A', 280);   // 280 -> rounds up to the 320 size class
}
$sum = 0;
foreach ($keep as $s) { $sum += strlen($s); }
$keep = null;                           // release -> bin-320 free list repopulates

echo "apfl-warm ok sum=$sum pid=" . getmypid() . "\n";
