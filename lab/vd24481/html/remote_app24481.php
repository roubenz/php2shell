<?php
/* #24481 remote-delivery sink -- the minimal realistic app shape that reflects
 * php-src #24481's IS_LONG heap-pointer leak in ONE request.
 *
 * The app unserialize()s client input (an object-injection sink, exactly like
 * the a7 echo sink) and then emits a rehydrated cache working-set in its JSON
 * response. The CacheHydrator POP gadget's __destruct (gadget.php) rehydrates
 * that working-set during the unserialize() teardown and publishes it in
 * $GLOBALS['__hydrated'] -- so the single var_push clobber that #24481 performs
 * lands in a value the response carries. items[0] is the leaked heap pointer,
 * reflected as a plain JSON integer (gettype integer, < 2^53 -> exact number).
 *
 * This is STRICTLY heavier than the a7 echo sink (echo serialize(unserialize)):
 * #24481 needs (1) a __destruct (not just Serializable::unserialize) that
 * re-enters unserialize() on attacker bytes, and (2) the rehydrated array
 * reflected in the response. A plain echo serialize() of the decoded value
 * cannot carry it -- the reclaimer is born in teardown and the orphaned gadget
 * object is not part of the decoded result.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';

$b = $_POST['cook'] ?? $_POST['rows'] ?? $_POST['sess'] ?? '';
$GLOBALS['__hydrated'] = null;
$r = @unserialize((string) $b);

header('Content-Type: application/json');
echo json_encode([
    'status' => 'ok',
    'php'    => PHP_VERSION,
    'items'  => $GLOBALS['__hydrated'],
]);
echo "\n";
