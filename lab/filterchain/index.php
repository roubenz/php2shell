<?php
// filterchain lab -- include-sink-ONLY target for poc/php_filter_chain.py.
//
// The ONLY thing this app offers is a single unvalidated include() that honours
// PHP stream wrappers (php://filter/...). There is NO session, NO upload, NO
// writable path, NO log exposure -- nothing the php://filter *chain generator*
// could lean on except the include itself. If code runs here, it ran purely
// from bytes the attacker synthesised with convert.iconv.* | convert.base64-*
// read out of php://filter/.../resource=php://temp.
//
// Mirrors the incvec sink shape (same (1) include vector) with everything else
// stripped off, so a landing here is unambiguously include-sink-only.
//
// Lab/analysis use only, on systems you own.
error_reporting(E_ALL);

$p = $_GET['page'] ?? '';
if ($p !== '') {
    include($p);          // <-- the entire attack surface
    exit;
}
echo "filterchain lab " . PHP_VERSION . " " . php_sapi_name() . "\n";
