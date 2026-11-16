<?php
// Writer: session_start() with the ini-level php_serialize handler (the modern
// recommended write side). Any multipart POST here fires the upload-progress
// hook that copies our raw key (carrying the phpggc object) into the session file.
session_start();
if (!isset($_SESSION['v'])) $_SESSION['v'] = 0;
$_SESSION['v']++;
echo "pggc-lab | PHP " . PHP_VERSION . " " . php_sapi_name() .
     " | handler=" . ini_get('session.serialize_handler') . "\n";
