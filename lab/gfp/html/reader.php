<?php
// gfp-lab reader: a legacy shim forces the old `php` handler (the MISMATCH) and
// the app autoloads a real framework (Monolog), so the Monolog file-write POP
// chain is reachable in the reader's scope. session_start() parses the
// php_serialize file as php key|value; the attacker `|` drops the object into a
// value position, unserialize() instantiates it, and the Monolog __destruct
// writes the dropped file. No app bug beyond the (documented, non-default)
// handler mismatch -- same mechanism as the shmismatch/pggc labs.
require __DIR__ . '/vendor/autoload.php';
header('Content-Type: text/plain');
ini_set('session.serialize_handler', 'php');   // <-- the mismatch
session_start();
echo "[gfp-reader] handler=" . ini_get('session.serialize_handler') .
     " vars=" . count($_SESSION) . "\n";
