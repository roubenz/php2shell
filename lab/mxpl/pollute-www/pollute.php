<?php
// Pollutes the runtime serialize handler, then (optionally) triggers an
// execution-phase memory_limit OOM. fpm is expected to SURVIVE the OOM.
// We log the PID so the caller can confirm the SAME worker served a later req.
@ini_set('session.serialize_handler', 'php_serialize');
@file_put_contents('/tmp/mxpl_pollute_pid.txt', getmypid() . "|" . ini_get('session.serialize_handler') . "\n");
header('Content-Type: text/plain');
echo "POLLUTED pid=" . getmypid() . " handler=" . ini_get('session.serialize_handler') . "\n";
if (isset($_GET['oom'])) {
    // Force a graceful memory_limit bailout during execution (NOT a segfault).
    $a = [];
    while (true) { $a[] = str_repeat('A', 1024 * 1024); }
}
