<?php
// Reader: a legacy shim forces the old `php` handler (the MISMATCH) and the app
// autoloads a real framework (Monolog) -> the phpggc gadget classes are in
// scope. session_start() parses the php_serialize file as php key|value, the
// attacker `|` drops the phpggc object into a value position, unserialize()
// instantiates it, and the Monolog DeduplicationHandler __destruct writes the
// webshell. No app bug beyond the (documented, non-default) handler mismatch.
require __DIR__ . '/vendor/autoload.php';
header('Content-Type: text/plain');
ini_set('session.serialize_handler', 'php');   // <-- the mismatch
session_start();
echo "[reader] handler=" . ini_get('session.serialize_handler') .
     " vars=" . count($_SESSION) . "\n";
