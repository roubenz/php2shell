<?php
/* COMPARISON SINK (erd): saved-view SORT / ORDER BY render -> observable
 * permutation. A plausible "saved view" route: the client submits a cached set
 * of rows (`rows`) and some live candidate rows (`cand[]`, an ordinary form
 * array). The app merges them and renders the row LABELS in sorted order (ORDER
 * BY the sort key). The sort KEY values are never emitted -- only the order of
 * the labels. The decoded row's RANK among the attacker candidates reveals the
 * decoded sort key's rank => log2(n+1) bits in ONE request (a byte/request with
 * 256 candidates). This is the EXFIL-ONLY channel of the driver's comparison
 * mode: it recovers the chunk+binbase pointers with NO echo, but (WALL-1) cannot
 * carry the a7 fire's by-name resolution reads.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';

$rows  = @unserialize((string)($_POST['rows'] ?? ''));
$probe = erd_field($rows, 'tok');
if (!is_string($probe)) {
    http_response_code(400);
    echo "no rows\n";
    exit;
}

$items = [['P', $probe]];
$cand = $_POST['cand'] ?? [];
if (is_array($cand)) {
    $i = 0;
    foreach ($cand as $c) {
        $items[] = ['a' . $i, (string)$c];
        $i++;
    }
}

/* stable ORDER BY the sort key; emit only the LABELS, never the key values. */
usort($items, fn($x, $y) => strcmp($x[1], $y[1]));
header('Content-Type: text/plain');
echo implode(' ', array_map(fn($it) => $it[0], $items)) . "\n";
