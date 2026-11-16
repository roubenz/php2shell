<?php
/*
 * Native-parser crash-oracle sink (Hope-B4).
 *
 * Accepts a single uploaded file (multipart field "f") and feeds it to ONE
 * near-universal native parser selected by ?p=:
 *     p=exif  ->  exif_read_data($tmp)        (TIFF/JPEG-APP1 IFD walker)
 *     p=gis   ->  getimagesize($tmp)          (image header prober)
 *     p=zip   ->  ZipArchive::open+statIndex  (central-directory via libzip)
 *
 * The result is DELIBERATELY NOT echoed. The response is a constant, so the
 * only thing an attacker learns is whether THIS request killed the fpm worker
 * (next request 502/reset) or not (200). That is the page-probe crash-oracle
 * channel documented in poc/fpm_intrinsic_reflect.py candidate (1): a worker
 * liveness bit, nothing more. All parser output/exceptions are swallowed.
 */
error_reporting(0);
ini_set('display_errors', '0');

$p = $_GET['p'] ?? 'exif';

if (!isset($_FILES['f']) || !is_uploaded_file($_FILES['f']['tmp_name'] ?? '')) {
    // no file: still a valid liveness target
    header('X-Parser: none');
    echo 'OK';
    return;
}
$tmp = $_FILES['f']['tmp_name'];

// Swallow EVERYTHING the parser emits or throws. The point is that whether the
// parse succeeds, warns, or returns false is INVISIBLE to the client -- only a
// fatal that takes down the worker changes what the client observes.
set_error_handler(function () { return true; });
try {
    switch ($p) {
        case 'gis':
            @getimagesize($tmp);
            break;
        case 'zip':
            $z = new ZipArchive();
            if ($z->open($tmp) === true) {
                $n = $z->numFiles;
                for ($i = 0; $i < $n && $i < 64; $i++) {
                    @$z->statIndex($i);
                    @$z->getNameIndex($i);
                }
                $z->close();
            }
            break;
        case 'exif':
        default:
            @exif_read_data($tmp, 0, true);
            break;
    }
} catch (\Throwable $e) {
    // ignore -- never reflected
}
restore_error_handler();

header('X-Parser: ' . $p);
echo 'OK';
