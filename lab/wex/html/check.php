<?php
/* REAL APP SINK #3 (wex): entitlement / prefix check -> differential status.
 *
 * A plausible "does this entitlement token carry this namespace/prefix" route:
 * the client presents a serialized entitlement (`ent`) and a prefix (`want`).
 * The app returns 204 iff the decoded token STARTS WITH the prefix, else 404.
 * This is an EQUALITY-class sink (str_starts_with / ===): one boolean per
 * request, but it only CONFIRMS a guessed prefix -- it cannot binary-search a
 * high-entropy value. It is included to (a) populate the catalog's
 * "differential 204/404 on a decoded flag" entry and (b) serve as an
 * INDEPENDENT non-echo channel that confirms a value an ordered/sort sink
 * already recovered (two side effects agreeing = ground truth with no echo).
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';

$ent  = @unserialize((string)($_POST['ent'] ?? ''));
$want = (string)($_POST['want'] ?? '');
$tok  = wex_field($ent, 'tok');

$ok = is_string($tok) && $want !== '' && str_starts_with($tok, $want);
http_response_code($ok ? 204 : 404);
header('Content-Type: text/plain');
echo "check\n";
