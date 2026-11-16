<?php
// phar-av2-lab landing page. Exposes nothing by itself; composer.lock sits in
// the docroot (served statically by nginx), which is how
// poc/gadget_fingerprint.py auto-detects monolog/monolog and auto-selects the
// Monolog file-write POP chain -- no operator-specified chain.
header('Content-Type: text/plain');
echo "phar-av2-lab | PHP " . PHP_VERSION . " " . php_sapi_name() . "\n";
echo "endpoints: POST /upload.php (field 'img', getimagesize filter),"
   . " GET /inspect.php?f=NAME (getMetadata trigger),"
   . " GET /safe.php?f=NAME (file_exists only, negative control)\n";
