<?php
header('Content-Type: text/plain');
echo "WRITE-ENDPOINT pid=" . getmypid() . " handler=" . ini_get('session.serialize_handler') . "\n";
