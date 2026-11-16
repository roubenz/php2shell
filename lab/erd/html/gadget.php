<?php
/* Shared var_hash UAF gadget for the erd "echo-route driver" lab.
 *
 * Identical Serializable gadget the a7 chain needs (iQingshan CachedData):
 * CachedData::unserialize() recursively calls unserialize() then does one extra
 * property write (->x = 0), the 9th insert that resizes the inner stdClass
 * arData and frees the buffer the OUTER var_hash still indexes -> the
 * CVE-2026-109618/109619 var_hash use-after-free. Every route in this lab pulls
 * it in so the a7 R: spray fires on a bare unserialize() of client input; the
 * routes differ only in what they do with the decoded result -- remote_app.php
 * echoes serialize() (the ECHO sink), order.php/gate.php run an ORDINARY
 * comparison/branch (the no-echo exfil demo).
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
 * ($sess['tok'], $row->tok). Returns null if absent. The comparison sinks
 * hard-code the field name 'tok'; there is no client-supplied key selector. */
function erd_field($result, $key)
{
    if (is_array($result) && array_key_exists($key, $result)) {
        return $result[$key];
    }
    if (is_object($result) && isset($result->$key)) {
        return $result->$key;
    }
    return null;
}
