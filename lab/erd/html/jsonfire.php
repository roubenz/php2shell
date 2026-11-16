<?php
/* JSON-API dispatch sink, pre-unserialize groom BYTE-IDENTICAL to remote_app.php
 * (only the final materialise op differs: json_encode instead of echo serialize).
 * Isolates the dispatch question from the heap groom. No pointer echoed. */
require __DIR__ . '/gadget.php';
header('Content-Type: text/plain');
$b = $_POST['cook'] ?? $_POST['rows'] ?? $_POST['sess'] ?? '';
$r = @unserialize((string)$b);
$x = json_encode($r);          // materialise -> get_properties_for(JSON)
echo "ok";
