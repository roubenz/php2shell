<?php
// Lab fixture for read_leak/uncaught_exception_overread_leak.py: throws an
// uncaught Exception built from a raw POST field so the %S display path
// (html_errors=off) reflects the bytes into the HTTP body byte-exact. Proves
// the response channel is NUL-safe / length-based; not part of any chain.
ini_set('html_errors', '0');
$m = isset($_POST['m']) ? $_POST['m'] : '';
throw new Exception($m);
