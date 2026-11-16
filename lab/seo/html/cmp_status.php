<?php
/* SIDE-EFFECT ORACLE #1: ordered comparison -> HTTP STATUS CODE (av6).
 *
 * The app unserializes attacker input, pulls one field out of the result
 * (seo_field), and byte-compares it against an attacker-supplied value `g`
 * (strcmp, exactly what a usort()/ORDER-BY/"is this token <= that one" branch
 * does). The field's bytes are NEVER echoed; the only thing the client learns
 * is the HTTP STATUS: 302 if field < g, else 200. One boolean => 1 bit/request.
 * Binary-searching `g` recovers each byte of the field (the a7 R: leaked
 * memory) in ~8 requests/byte with no serialize echo.
 *
 * Real-world analogues: `if (unserialize($row) < $cutoff) redirect(...)`,
 * version/expiry/token gating, a sorted "first match" branch.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
$k = (string)($_POST['k'] ?? 'probe');
$g = (string)($_POST['g'] ?? '');
$r = @unserialize((string)($_POST['cook'] ?? ''));
$probe = seo_field($r, $k);
/* side-effect: status code only; body is a fixed constant (no reflection). */
if ($probe !== null && is_string($probe) && strcmp($probe, $g) < 0) {
    http_response_code(302);
} else {
    http_response_code(200);
}
header('Content-Type: text/plain');
echo "ok\n";
