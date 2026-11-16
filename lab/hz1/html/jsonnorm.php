<?php
/* get_object_vars normalise -> json_encode the array (the proven firing shape). */
require __DIR__ . '/gadget.php';
header('Content-Type: application/json');
$b = $_POST['cook'] ?? $_POST['rows'] ?? $_POST['sess'] ?? '';
$r = @unserialize((string)$b);
$norm = is_array($r)
    ? array_map(fn($e) => is_object($e) ? get_object_vars($e) : $e, $r)
    : (is_object($r) ? get_object_vars($r) : $r);
echo json_encode(['status' => 'ok', 'n' => is_array($norm) ? count($norm) : 0]);
