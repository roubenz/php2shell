<?php
/* GROUND-TRUTH sink (av6). The classic echoing sink: it serialize()s the
 * unserialized result straight into the body. The side-effect oracle does NOT
 * use this to exfil; the verifier uses it only to establish the TRUE bytes the
 * a7 R: read returns, so the side-effect-recovered bytes can be checked
 * against it. This is the channel the whole exercise is trying to AVOID.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
header('Content-Type: text/plain');
header('X-PHP-Version: ' . PHP_VERSION);
header('X-PHP-SAPI: ' . PHP_SAPI);
if (!isset($_POST['cook'])) {
    http_response_code(400);
    echo "missing cook\n";
    exit;
}
echo serialize(@unserialize($_POST['cook']));
