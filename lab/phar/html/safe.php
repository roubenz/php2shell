<?php
// phar-av2-lab NEGATIVE CONTROL. Same attacker-controlled phar:// path, but the
// app only calls plain filesystem functions (file_exists/is_file/filesize) and
// never touches getMetadata(). On PHP 8.x this unserializes NOTHING, so the
// POP chain never fires -> no webshell. This endpoint exists to prove the 8.0
// lazy-metadata hardening is what gates the whole avenue on modern PHP.
require __DIR__ . '/vendor/autoload.php';
header('Content-Type: text/plain');

$f = (string)($_GET['f'] ?? '');
$path = __DIR__ . '/uploads/' . basename($f);
if ($f === '' || !is_file($path)) { echo "usage: /safe.php?f=<uploaded name>\n"; return; }

$u = 'phar://' . $path . '/.x';
$r = [
    'file_exists' => @file_exists($u),
    'is_file'     => @is_file($u),
    'filesize'    => @filesize('phar://' . $path),
];
echo "[safe] fs-functions on phar:// ran (no getMetadata): " . json_encode($r) . "\n";
echo "[safe] no unserialize occurred on 8.x -> no injection\n";
