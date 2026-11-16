<?php
// OPcache SHM lab app. Benign. Its only job is to be COMPILED INTO SHM so the
// probe can observe a populated opcode cache: a user function whose op_array
// (and whose opline handlers) live in the opcache shared memory after the first
// request, and a hot loop so the tracing-JIT variant emits JIT'd code for it.
//
// Corrupting this function's cached zend_op->handler in SHM (were a write able
// to reach there) would redirect control the next time hot() is called -- the
// SHM code-exec target this lab studies. No validation re-runs on that cached
// op_array per request, unlike the file_cache .bin route.
//
// Lab/analysis use only, on systems you own.

function hot($n) {
    $s = 0;
    for ($i = 0; $i < $n; $i++) {
        $s += ($i * 3) ^ ($i >> 1);
    }
    return $s;
}

// opcache_get_status(true) exposes the SHM accounting (used/free, cached
// scripts, JIT buffer usage) so the probe can corroborate the /proc view.
$st = opcache_get_status(false);
$r = 0;
for ($k = 0; $k < 2000; $k++) { $r += hot(50); }  // make hot() JIT-hot

header('Content-Type: text/plain');
echo "osh index " . PHP_VERSION . " " . php_sapi_name() . "\n";
echo "opcache_enabled=" . var_export($st['opcache_enabled'] ?? null, true) . "\n";
echo "jit_on=" . var_export(($st['jit']['enabled'] ?? false), true) . "\n";
echo "hot=" . $r . "\n";
