<?php
/* brleak lab health check. Lab/analysis use only, on systems you own. */
header('Content-Type: text/plain');
echo "brleak-lab ok " . PHP_VERSION . " " . PHP_SAPI . "\n";
