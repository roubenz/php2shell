<?php
/* a7r5 REFLECTIVE (echo) sink -- stands in for an application that
 * unserialize()s request input and echoes serialize() of the result. This is
 * the transport the a7 fire's by-name RESOLUTION reads (R-3..R-6) require (the
 * comparison-sink package calls this a "read endpoint"; see WALL 1 in
 * poc/fpm_fullchain_sinkexfil.py). The a7 fpm driver posts the serialized
 * payload in the `cook` field (a7_fpm_rce._fpm_send_http).
 *
 * Assign to a local first ($r = unserialize(...); echo serialize($r);) so the
 * result-construction allocations -- and thus the a7 reclaim slot the leaked
 * pointer lands in -- match an ordinary app.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
header('Content-Type: text/plain');
$b = $_POST['cook'] ?? $_POST['rows'] ?? $_POST['sess'] ?? '';
$r = @unserialize((string)$b);
echo serialize($r);
