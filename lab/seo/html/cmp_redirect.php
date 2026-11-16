<?php
/* SIDE-EFFECT ORACLE #2: ordered comparison -> REDIRECT LOCATION (av6).
 *
 * Same comparison as cmp_status, but the observable is the Location header
 * value (/hit vs /miss), i.e. a redirect target that branches on a field of
 * the unserialized result. Still a boolean => 1 bit/request. Models an app
 * that routes the user differently based on an unserialized field without ever
 * printing the field.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
$k = (string)($_POST['k'] ?? 'probe');
$g = (string)($_POST['g'] ?? '');
$r = @unserialize((string)($_POST['cook'] ?? ''));
$probe = seo_field($r, $k);
if ($probe !== null && is_string($probe) && strcmp($probe, $g) < 0) {
    header('Location: /hit');
} else {
    header('Location: /miss');
}
http_response_code(302);
