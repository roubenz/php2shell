<?php
// phar-av2-lab upload endpoint. Accepts an image upload under field "img" and
// applies an UPLOAD FILTER: getimagesize() must recognise it as a real image.
// A naive-but-common defence ("it parses as a JPEG, so it is safe"). The
// phar/JPEG polyglot passes because its leading bytes ARE a valid JPEG; the
// phar manifest rides along after the image data, invisible to getimagesize().
header('Content-Type: text/plain');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !isset($_FILES['img'])) {
    echo "POST an image in field 'img'\n";
    return;
}
$f = $_FILES['img'];
if ($f['error'] !== UPLOAD_ERR_OK) { http_response_code(400); echo "upload error\n"; return; }

$info = @getimagesize($f['tmp_name']);           // <-- the upload filter
if ($info === false || strpos((string)($info['mime'] ?? ''), 'image/') !== 0) {
    http_response_code(415);
    echo "rejected: not an image (getimagesize)\n";
    return;
}

// Keep a client-supplied-ish basename but force a .jpg extension (so the stored
// file can never be requested as PHP directly). nginx serves /uploads/ as
// static bytes regardless.
$base = preg_replace('/[^A-Za-z0-9_.-]/', '_', basename($f['name'] ?: 'up'));
$base = preg_replace('/\.(php\d?|phtml|phar)$/i', '', $base);
if (!preg_match('/\.jpe?g$/i', $base)) { $base .= '.jpg'; }
$dest = __DIR__ . '/uploads/' . $base;
if (!move_uploaded_file($f['tmp_name'], $dest)) {
    http_response_code(500); echo "store failed\n"; return;
}
echo "stored: uploads/{$base} (mime={$info['mime']}, {$info[0]}x{$info[1]})\n";
