<?php
/* Shared var_hash UAF gadget for the side-effect-oracle lab (av6).
 *
 * This is the SAME Serializable gadget the a7 chain needs (iQingshan
 * CachedData): CachedData::unserialize() recursively calls unserialize() and
 * then does one extra property write (->x = 0), the 9th insert that resizes
 * the inner stdClass arData and frees the buffer the OUTER var_hash still
 * indexes -> the CVE-2026-109618/109619 var_hash use-after-free. Every sink in
 * this lab includes it so the a7 R: spray fires; the sinks differ only in the
 * OBSERVABLE they expose after unserialize() (none of them echo serialize()).
 *
 * Lab/analysis use only, on systems you own.
 */

error_reporting(E_ALL & ~E_DEPRECATED);
ini_set('display_errors', '0');

class CachedData implements Serializable
{
    public function serialize(): string
    {
        return '';
    }

    public function unserialize(string $data): void
    {
        unserialize($data)->x = 0;
    }
}

/* Extract one named/indexed field from an unserialized result, for the sinks
 * that branch on "a field of the result". Returns null if absent. */
function seo_field($result, $key)
{
    if (is_array($result) && array_key_exists($key, $result)) {
        return $result[$key];
    }
    if (is_object($result) && isset($result->$key)) {
        return $result->$key;
    }
    return null;
}
