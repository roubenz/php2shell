<?php
/* Realistic JSON-API DISPATCH sink (NON-ECHO). A plausible API route: decode
 * request input, NORMALISE any decoded objects to arrays (get_object_vars) for
 * the JSON response, and emit only a status object. NO pointer is ever echoed
 * or reflected. The a7 type-confusion FIRES during the get_object_vars
 * normalise -- it dispatches the confused object's get_properties handler
 * (slot 0xC0), the same slot serialize() uses -- so this is a full no-echo RCE
 * target under the offset table. The leak + resolution run on the sort sink
 * (order.php); this endpoint only supplies the dispatch.
 *
 * Pre-unserialize groom is byte-identical to remote_app.php so the a7 reclaim
 * slot matches the proven serialize fire. Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
header('Content-Type: text/plain');
$b = $_POST['cook'] ?? $_POST['rows'] ?? $_POST['sess'] ?? '';
$r = @unserialize((string)$b);
$norm = is_array($r)
    ? array_map(fn($e) => is_object($e) ? get_object_vars($e) : $e, $r)
    : (is_object($r) ? get_object_vars($r) : $r);
echo json_encode(['status' => 'ok', 'n' => is_array($norm) ? count($norm) : 0]);
