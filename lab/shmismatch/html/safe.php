<?php
// CONTROL reader: reads with the SAME handler the write side used
// (php_serialize) -- NO mismatch. The gadget class is still in scope, so this
// isolates the gate: with no handler mismatch the poisoned key never reaches a
// value position and no object is instantiated. Used by the verifier as the
// negative control (must NOT yield RCE).
require __DIR__ . "/lib.php";
header("Content-Type: text/plain");
// no ini_set: handler stays php_serialize == the write side
session_start();
echo "[safe] handler=" . ini_get('session.serialize_handler') .
     " vars=" . count($_SESSION) . "\n";
