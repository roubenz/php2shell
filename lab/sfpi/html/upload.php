<?php
// Benign file-upload endpoint -- the ordinary "avatar upload" shape. It stores
// the uploaded file under the docroot at uploads/<basename> and does nothing
// else: it never include()s or executes the upload. The only sin is that the
// file lands under the docroot, where the nginx pathinfo misconfig can reach
// it as /uploads/<name>/x.php and have fpm execute it as PHP.
$dir = __DIR__ . '/uploads';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $name = basename((string)$_FILES['file']['name']);
    if ($name === '' || !move_uploaded_file($_FILES['file']['tmp_name'], $dir . '/' . $name)) {
        http_response_code(500);
        echo "upload-failed\n";
        exit;
    }
    echo "stored:/uploads/" . $name . "\n";
    exit;
}
echo "POST a multipart 'file' field to store an upload under /uploads/\n";
