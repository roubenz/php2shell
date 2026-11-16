<?php
// gfp-lab writer: session_start() with the ini-level php_serialize handler (the
// modern recommended write side). A multipart POST here fires the
// upload-progress hook that copies the raw key into the session file.
session_start();
if (!isset($_SESSION['v'])) $_SESSION['v'] = 0;
$_SESSION['v']++;
echo "gfp-lab | PHP " . PHP_VERSION . " " . php_sapi_name() .
     " | handler=" . ini_get('session.serialize_handler') . "\n";
