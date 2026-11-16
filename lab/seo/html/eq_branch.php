<?php
/* SIDE-EFFECT ORACLE #3: EQUALITY branch -> differential status (av6).
 *
 * The weak oracle: the app only tests EQUALITY of a field against `g`
 * (200 if equal, 404 otherwise). One boolean => 1 bit/request, but it only
 * CONFIRMS a full guess; it cannot binary-search. Useful for low-entropy
 * fields (a byte brute = <=256 req/byte) or to confirm a value already
 * narrowed by an ordered oracle; useless for a from-scratch 48-bit pointer.
 * Included to quantify how much weaker an equality sink is than an ordered one.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
$k = (string)($_POST['k'] ?? 'probe');
$g = (string)($_POST['g'] ?? '');
$n = (int)($_POST['n'] ?? 0);   // optional: compare only first n bytes
$r = @unserialize((string)($_POST['cook'] ?? ''));
$probe = seo_field($r, $k);
$hit = false;
if ($probe !== null && is_string($probe)) {
    $p = $n > 0 ? substr($probe, 0, $n) : $probe;
    $hit = ($p === $g);
}
http_response_code($hit ? 200 : 404);
header('Content-Type: text/plain');
echo "done\n";
