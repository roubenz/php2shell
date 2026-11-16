<?php
/* Hazard-1 probe: a JSON API that json_encode()s the decoded TREE directly
 * (objects included, NOT normalised). Pre-unserialize groom byte-identical to
 * remote_app.php so the a7 reclaim slot matches. Lab/analysis use only. */
require __DIR__ . '/gadget.php';
header('Content-Type: application/json');
$b = $_POST['cook'] ?? $_POST['rows'] ?? $_POST['sess'] ?? '';
$r = @unserialize((string)$b);
echo json_encode($r);
