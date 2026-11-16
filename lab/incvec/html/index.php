<?php
// incvec lab app -- A2 inclusion-vector sink for broadening the include-race.
// Offers three things a realistic LAMP/LEMP app often offers, so the A2 read
// strategies in poc/include_vectors.py can be exercised honestly:
//
//   (1) ONE php://-capable include sink (?page=...). Drives the `direct`,
//       `filter` (php://filter wrapper over the poisoned session file) and
//       `logpoison` (include the PHP error log) strategies. No bespoke LFI
//       beyond the (very common) unvalidated include.
//   (2) A session_start() page that mints a sid -- the upload-progress poison
//       target (reused byte-for-byte from the include-race module).
//   (3) A naive "file manager" upload into the docroot that REJECTS .php/.phar/
//       .phtml (the common hardening) but keeps any other name. This motivates
//       the `.user.ini` auto_prepend route: you cannot drop a .php shell, but
//       you CAN drop a .user.ini (and a non-.php PHP carrier) -> code runs on
//       every request with no include sink at all.
//
// Lab/analysis use only, on systems you own.
error_reporting(E_ALL);

// (3) naive docroot write (rejects executable extensions, keeps the rest).
if (!empty($_FILES['up']['name'])) {
    $name = basename($_FILES['up']['name']);
    if (preg_match('/\.(php|phar|phtml|php[0-9]?)$/i', $name)) {
        http_response_code(403);
        echo "php upload blocked\n";
        exit;
    }
    move_uploaded_file($_FILES['up']['tmp_name'], __DIR__ . '/' . $name);
    echo "stored $name\n";
    exit;
}

// (1) the include sink (accepts stream wrappers; no scheme whitelist).
$p = $_GET['page'] ?? '';
if ($p !== '') {
    include($p);
    exit;
}

// (2) the session page (mints PHPSESSID; also the upload-progress carrier).
session_start();
echo "welcome " . PHP_VERSION . " " . php_sapi_name() . "\n";
