<?php
/* REAL APP SINK #2 (wex): sort / ORDER BY render -> observable permutation.
 *
 * A plausible "saved view" route: the client submits a cached set of rows
 * (`rows`) and some live candidate rows (`cand[]`, an ordinary form array). The
 * app merges them and renders the row LABELS in sorted order (ORDER BY the sort
 * key). The sort KEY values are never emitted -- only the order of the labels.
 *
 * This is the highest-bandwidth non-echo class. Where the decoded row's label
 * ('P') lands among the attacker-chosen candidate labels reveals the decoded
 * sort key's RANK among the candidates => log2(n+1) bits in ONE request
 * (n candidates), versus 1 bit for a boolean branch. Models a leaderboard that
 * shows positions but not scores, a `usort($rows, strcmp)` listing, or an
 * `ORDER BY col` whose row order (but not the column) is visible.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';

$rows  = @unserialize((string)($_POST['rows'] ?? ''));
$probe = wex_field($rows, 'tok');
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
