<?php
header('Content-Type: text/plain');
echo "READ-ENDPOINT pid=" . getmypid() . " handler=" . ini_get('session.serialize_handler') . "\n";
