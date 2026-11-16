<?php
// shmfl lab app. Benign. Its job is to be COMPILED INTO the opcache SHM so the
// probe can observe (and corrupt) a populated opcode cache: a user function
// `hot()` whose op_array -- and whose per-opline `handler` pointers -- live in
// the opcache shared memory after the first request.
//
// Corrupting this function's cached zend_op->handler in SHM redirects control the
// NEXT time hot() is called, with NO validation re-run on the cached op_array per
// request (unlike the file_cache .bin route). That is the SHM code-exec target
// the free-list poison reaches (its emalloc returns an address INSIDE the SHM --
// a reach a5's <=16 KiB forward write never had).
//
// `whoami` is a benign command endpoint the weaponization note targets (convert
// the cached user function to an internal function with handler=system). It is
// NOT wired to the exploit here; it only documents the exec last-mile.
//
// Lab/analysis use only, on systems you own.

function hot($n) {
    $s = 0;
    for ($i = 0; $i < $n; $i++) {
        $s += ($i * 3) ^ ($i >> 1);
    }
    return $s;
}

$st = opcache_get_status(false);
$r = 0;
for ($k = 0; $k < 2000; $k++) { $r += hot(50); }  // make hot() hot (JIT variant)

header('Content-Type: text/plain');
echo "shmfl index " . PHP_VERSION . " " . php_sapi_name() . "\n";
echo "opcache_enabled=" . var_export($st['opcache_enabled'] ?? null, true) . "\n";
echo "jit_on=" . var_export(($st['jit']['enabled'] ?? false), true) . "\n";
echo "hot=" . $r . "\n";
