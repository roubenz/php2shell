<?php
header('Content-Type: text/plain');
echo "TARGET pid=" . getmypid() . " handler=" . ini_get('session.serialize_handler') . "\n";
