<?php
header('Content-Type: application/json');
echo json_encode([
    'ok' => true,
    'php' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'upload_progress' => ini_get('session.upload_progress.enabled'),
    'max_file_uploads' => ini_get('max_file_uploads'),
]);
