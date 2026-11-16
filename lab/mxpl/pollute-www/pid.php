<?php
// Reports the serving worker PID and the serialize handler the USER-SCRIPT sees
// at RINIT time (== master/.user.ini value unless THIS script already ini_set).
header('Content-Type: text/plain');
echo "PID=" . getmypid() . "\n";
echo "handler=" . ini_get('session.serialize_handler') . "\n";
echo "php=" . PHP_VERSION . " sapi=" . PHP_SAPI . "\n";
