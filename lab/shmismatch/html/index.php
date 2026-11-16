<?php
// Writer endpoint: starts the session with the ini-level handler
// (php_serialize) -- the "modern recommended" write side.
session_start();
if (!isset($_SESSION['visits'])) $_SESSION['visits'] = 0;
$_SESSION['visits']++;
echo "shmismatch-lab | PHP " . PHP_VERSION . " " . php_sapi_name() .
     " | visits=" . $_SESSION['visits'] .
     " | handler=" . ini_get('session.serialize_handler') . "\n";
