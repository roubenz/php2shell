<?php
/* UNIFIED side-effect oracle instrument (av6).
 *
 * One endpoint, selectable observable via `mode`, driven with a CONSTANT POST
 * field shape (cook,k,g,mode,n,delay_us,anchors always present) so the
 * pre-unserialize allocation sequence -- and therefore the reclaimed address
 * the a7 var_hash UAF lands the leaked pointer at -- is identical across every
 * mode. That lets the verifier read the TRUE bytes once via mode=echo and then
 * check that the NON-echo modes recover the same value with no serialize echo.
 *
 * Modes (all but `echo` are non-echo observable side-effects):
 *   echo   : echo serialize($result)        [ground-truth channel; verifier only]
 *   cmp    : HTTP 302 if strcmp(field,g)<0 else 200   (ordered -> status bit)
 *   redir  : Location /hit vs /miss                    (ordered -> redirect bit)
 *   eq     : HTTP 200 if substr(field,0,n)===g else 404 (equality confirm bit)
 *   sort   : usort(field + anchors); emit LABEL order   (rank -> log2(n+1) bits)
 *   timing : usleep(delay_us) on the HIT branch         (ordered -> timing bit)
 *
 * The field's bytes are never echoed by any non-echo mode.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';

/* mode is a FIXED-WIDTH 1-char code so every request (echo included) has an
 * identical POST field shape -> the a7 reclaim lands the leaked pointer at the
 * same address in every mode, which is what makes mode=echo an exact ground
 * truth for the non-echo recoveries. Word aliases are accepted for curl. */
$MODE_MAP = ['0' => 'echo', '1' => 'cmp', '2' => 'redir',
             '3' => 'eq', '4' => 'sort', '5' => 'timing'];
$mode = (string)($_POST['mode'] ?? '1');
$mode = $MODE_MAP[$mode] ?? $mode;
$k    = (string)($_POST['k'] ?? 'probe');
$g    = (string)($_POST['g'] ?? '');
$n    = (int)($_POST['n'] ?? 0);
$delay = (int)($_POST['delay_us'] ?? 0);
$anchors = (string)($_POST['anchors'] ?? '');

$r = @unserialize((string)($_POST['cook'] ?? ''));

if ($mode === 'echo') {
    header('Content-Type: text/plain');
    echo serialize($r);
    exit;
}

$probe = seo_field($r, $k);
$probe_s = is_string($probe) ? $probe : null;

switch ($mode) {
    case 'cmp':
        http_response_code(($probe_s !== null && strcmp($probe_s, $g) < 0) ? 302 : 200);
        header('Content-Type: text/plain');
        echo "ok\n";
        break;

    case 'redir':
        header('Location: ' . (($probe_s !== null && strcmp($probe_s, $g) < 0) ? '/hit' : '/miss'));
        http_response_code(302);
        break;

    case 'eq':
        /* compare prefixes so `g` can keep the constant padded length (and thus
         * the constant request shape the oracle relies on). */
        $hit = ($probe_s !== null && substr($probe_s, 0, $n) === substr($g, 0, $n));
        http_response_code($hit ? 200 : 404);
        header('Content-Type: text/plain');
        echo "done\n";
        break;

    case 'sort':
        $items = [['P', (string)$probe_s]];
        if ($anchors !== '') {
            $i = 0;
            foreach (explode("\n", $anchors) as $a) {
                $items[] = ['a' . $i, $a];
                $i++;
            }
        }
        usort($items, fn($x, $y) => strcmp($x[1], $y[1]));
        header('Content-Type: text/plain');
        echo implode(' ', array_map(fn($it) => $it[0], $items)) . "\n";
        break;

    case 'timing':
        if ($probe_s !== null && strcmp($probe_s, $g) < 0) {
            usleep($delay);
        }
        header('Content-Type: text/plain');
        echo "ok\n";
        break;

    default:
        http_response_code(400);
        echo "bad mode\n";
}
