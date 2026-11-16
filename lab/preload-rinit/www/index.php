<?php
// Benign endpoint. It never calls session_start() and never touches $_SESSION.
// On vulnerable PHP the RFC1867 upload-progress handler still initializes and
// deserializes the session record BEFORE this script's RINIT, so the gadget in
// the seeded session file runs regardless of what this script does.
header('Content-Type: application/json');
echo json_encode([
    'ok' => true,
    'php' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'upload_progress' => ini_get('session.upload_progress.enabled'),
    'preload' => ini_get('opcache.preload'),
    'serialize_handler' => ini_get('session.serialize_handler'),
]);
