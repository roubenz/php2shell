<?php
// Include-race lab app: one includable GET param + a session_start page, the
// stock shape the 0xdeadbeef include-race chain targets. No app bug beyond the
// (very common) unvalidated include; RCE comes from the upload-progress poison.
$p = $_GET['page'] ?? 'home';
if ($p !== 'home') { include($p); exit; }
session_start();
echo "welcome " . PHP_VERSION . " " . php_sapi_name() . "\n";
