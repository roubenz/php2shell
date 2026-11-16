<?php
// MISMATCH reader: a legacy compatibility shim forces the old `php` handler
// before reading the session. Write side was php_serialize -> this read side is
// php == the serialize_handler mismatch. The gadget class is in scope.
require __DIR__ . "/lib.php";
header("Content-Type: text/plain");
ini_set('session.serialize_handler', 'php');   // <-- the mismatch
session_start();
echo "[legacy] handler=" . ini_get('session.serialize_handler') .
     " vars=" . count($_SESSION) . "\n";
