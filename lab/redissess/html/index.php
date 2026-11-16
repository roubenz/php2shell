<?php
// AVENUE #8 redis-session lab app: a page that session_start()s with a POP
// gadget (DeferredWriter) in scope, session.save_handler=redis. No app bug
// beyond the (very common) object-in-scope + session read. The session RECORD
// lives in redis; poisoning it there (via a direct RESP write standing in for
// SSRF, or via the upload-progress hook) and then reading it here object-injects
// -> DeferredWriter::__destruct drops a webshell -> RCE as the fpm worker.
require __DIR__ . '/lib.php';
session_start();
echo "welcome " . PHP_VERSION . " " . php_sapi_name()
   . " handler=" . ini_get('session.save_handler')
   . " serialize=" . ini_get('session.serialize_handler') . "\n";
