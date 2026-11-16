<?php
/* REAL APP SINK #1 (wex): session/cache ACCESS GATE -> ordered side effect.
 *
 * A plausible standalone route: the client presents a serialized session blob
 * (`sess`) and the clearance marker it wants to use (`need`). The app decodes
 * the session, reads the stored token, and GRANTS (302 -> /area) iff the token
 * sorts below the requested marker, else DENIES (403). This is the everyday
 * "gate on a decoded field" / version / expiry / tier comparison -- an ordered
 * strcmp, exactly what `ORDER BY`, `usort`, or a "is this <= that" branch runs.
 *
 * The token's bytes are NEVER emitted. The only thing the client observes is
 * the HTTP status (302 vs 403) and the redirect Location -- one ordered boolean
 * per request => 1 bit/request, binary-searchable to recover each token byte
 * (here, the a7 R: leaked heap pointer) with no serialize() echo anywhere.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';

$sess = @unserialize((string)($_POST['sess'] ?? ''));
$need = (string)($_POST['need'] ?? '');
$tok  = wex_field($sess, 'tok');

if (is_string($tok) && strcmp($tok, $need) < 0) {
    http_response_code(302);
    header('Location: /area');          // ordered-true route (grant)
} else {
    http_response_code(403);            // ordered-false route (deny)
}
header('Content-Type: text/plain');
echo "gate\n";                          // fixed body -> no field reflection
