<?php
/* SIDE-EFFECT ORACLE #4: SORT / ORDER-BY rank -> observable permutation (av6).
 *
 * The highest-bandwidth non-echo class. The app sorts a set that INCLUDES the
 * unserialized field among attacker-supplied anchor values, and the observable
 * is the resulting ORDER of labels (not the values). Where the probe lands in
 * the sorted sequence reveals its RANK among the anchors, i.e. log2(n+1) bits
 * in ONE request (n = number of anchors), versus 1 bit for a boolean branch.
 *
 * Models: `usort($rows, fn($a,$b)=>strcmp($a->tok,$b->tok)); echo id order` /
 * SQL `ORDER BY col` whose row order (but not the column value) is visible /
 * a leaderboard that shows position but not score. The probe's bytes are never
 * echoed; only the permutation of attacker-chosen labels is.
 *
 * `anchors` = newline-separated anchor strings (attacker-controlled).
 * Output: the label sequence after a stable strcmp sort, e.g. "a2 a0 P a1".
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
$k = (string)($_POST['k'] ?? 'probe');
$r = @unserialize((string)($_POST['cook'] ?? ''));
$probe = seo_field($r, $k);
if (!is_string($probe)) {
    http_response_code(400);
    echo "no probe\n";
    exit;
}
$items = [['P', $probe]];
$anchors = (string)($_POST['anchors'] ?? '');
if ($anchors !== '') {
    $i = 0;
    foreach (explode("\n", $anchors) as $a) {
        $items[] = ['a' . $i, $a];
        $i++;
    }
}
/* stable sort by VALUE; emit only the LABELS (never the values). */
usort($items, function ($x, $y) {
    $c = strcmp($x[1], $y[1]);
    return $c !== 0 ? $c : 0;
});
header('Content-Type: text/plain');
echo implode(' ', array_map(fn($it) => $it[0], $items)) . "\n";
