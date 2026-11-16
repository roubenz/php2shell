<?php
/* Shared var_hash UAF gadget for the wex "widened exfil / real app sinks" lab.
 *
 * Identical Serializable gadget the a7 chain needs (iQingshan CachedData):
 * CachedData::unserialize() recursively calls unserialize() then does one extra
 * property write (->x = 0), the 9th insert that resizes the inner stdClass
 * arData and frees the buffer the OUTER var_hash still indexes -> the
 * CVE-2026-109618/109619 var_hash use-after-free. Every app in this lab pulls it
 * in so the a7 R: spray fires on a bare unserialize() of client input; the apps
 * differ only in the ORDINARY comparison/branch they run on the decoded result
 * (an access gate, a sort/ORDER BY render, a prefix entitlement check) -- none
 * of them echo serialize() of the result.
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

/* Read one named field out of a decoded result the way an ordinary app would
 * ($sess['tok'], $row->tok). Returns null if absent. The apps hard-code the
 * field name 'tok'; there is no client-supplied key selector (that was the toy
 * oracle's tell). */
function wex_field($result, $key)
{
    if (is_array($result) && array_key_exists($key, $result)) {
        return $result[$key];
    }
    if (is_object($result) && isset($result->$key)) {
        return $result->$key;
    }
    return null;
}
