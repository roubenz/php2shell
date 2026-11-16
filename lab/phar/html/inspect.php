<?php
// phar-av2-lab TRIGGER endpoint (the vulnerable sink).
//
// Models a realistic archive/metadata inspector: given an uploaded file name,
// it opens the file as a Phar and reads its metadata to show the operator what
// the archive carries. On PHP 8.x this getMetadata() call is EXACTLY the gate
// that unserializes the phar metadata (plain fs-functions no longer do, post
// 8.0 lazy-metadata). allowed_classes defaults to TRUE, so the attacker's
// serialized object is instantiated here -> its __destruct POP chain fires.
//
// A real framework (Monolog) is autoloaded, so the Monolog file-write
// __destruct gadget is reachable in this scope.
require __DIR__ . '/vendor/autoload.php';
header('Content-Type: text/plain');

$f = (string)($_GET['f'] ?? '');
$path = __DIR__ . '/uploads/' . basename($f);   // confined to the upload dir
if ($f === '' || !is_file($path)) { echo "usage: /inspect.php?f=<uploaded name>\n"; return; }

echo "[inspect] opening phar: {$path}\n";
try {
    // fs-function on a phar:// path (the avenue's nominal trigger surface) --
    // on 8.x this alone does NOT unserialize (kept to show the surface):
    @file_exists('phar://' . $path . '/.x');

    // ...the actual 8.x trigger: reading metadata.
    $phar = new Phar($path, 0);
    $meta = $phar->getMetadata();            // <-- object injection fires here
    echo "[inspect] metadata type: " . gettype($meta) . "\n";
} catch (Throwable $e) {
    echo "[inspect] error: " . $e->getMessage() . "\n";
}
// $meta / its graph destruct at request end -> the POP chain's __destruct runs.
