<?php
// Passive /proc/<worker>/mem observer (lab instrumentation, NOT part of exploit).
// Reads BG(unserialize).{data,level} from the live fpm worker without stopping it.
// Run as root inside the container with CAP_SYS_PTRACE:
//   docker exec fpmsf-fpm php /tmp/observer.php [dump:HEXADDR:LEN]
// basic_globals vaddr (php:8.4.26-fpm): 0x16cc640; unserialize.data @ +0x368, .level @ +0x370.

const BG_VADDR = 0x16cc640;
const UNSER_DATA = 0x368;   // offset of unserialize.data within php_basic_globals
const UNSER_LEVEL = 0x370;  // offset of unserialize.level

function worker_pid(): ?int {
    foreach (glob('/proc/[0-9]*/cmdline') as $f) {
        $c = @file_get_contents($f);
        if ($c !== false && strpos($c, "php-fpm: pool www") !== false) {
            return (int)basename(dirname($f));
        }
    }
    return null;
}

function load_bias(int $pid): ?int {
    $maps = @file('/proc/' . $pid . '/maps', FILE_IGNORE_NEW_LINES);
    if (!$maps) return null;
    $lo = null;
    foreach ($maps as $line) {
        if (strpos($line, 'php-fpm') === false) continue;
        $start = hexdec(explode('-', $line)[0]);
        if ($lo === null || $start < $lo) $lo = $start;
    }
    return $lo;   // first LOAD p_vaddr == 0, so bias == lowest mapping
}

function readmem(int $pid, int $addr, int $len): string|false {
    $f = @fopen('/proc/' . $pid . '/mem', 'rb');
    if (!$f) return false;
    if (@fseek($f, $addr, SEEK_SET) !== 0) { fclose($f); return false; }
    $d = @fread($f, $len);
    fclose($f);
    return $d;
}

$pid = worker_pid();
if ($pid === null) { echo "NO_WORKER\n"; exit(2); }
$bias = load_bias($pid);
if ($bias === null) { echo "NO_BIAS pid=$pid\n"; exit(3); }

function writemem(int $pid, int $addr, string $bytes): bool {
    $f = @fopen('/proc/' . $pid . '/mem', 'r+b');
    if (!$f) return false;
    if (@fseek($f, $addr, SEEK_SET) !== 0) { fclose($f); return false; }
    $n = @fwrite($f, $bytes);
    fclose($f);
    return $n === strlen($bytes);
}

const PS_GLOBALS_VADDR = 0x16cb7a0;
const PS_MOD_DATA = 0x60;  // offset of mod_data in php_ps_globals
const FREE_MAP_OFF = 0x220; // free_map within the 2MB chunk header (8.4.26-fpm, candidate)

if ($argc > 1 && str_starts_with($argv[1], 'freemap:')) {
    // freemap:HEXCHUNK -> print the 512-bit page free_map as free-run segments
    $chunk = (int)hexdec(explode(':', $argv[1])[1]);
    $raw = readmem($pid, $chunk + FREE_MAP_OFF, 64);
    if ($raw === false) { echo "READ_FAIL\n"; exit(4); }
    $bits = '';
    for ($i = 0; $i < 8; $i++) { $w = unpack('P', substr($raw, $i * 8, 8))[1];
        for ($b = 0; $b < 64; $b++) $bits .= (($w >> $b) & 1) ? '1' : '0'; }
    // emit free runs (consecutive 0 bits) >= 2 pages
    echo "chunk=0x" . dechex($chunk) . " free runs (page: len):\n";
    $p = 0;
    while ($p < 512) {
        if ($bits[$p] === '0') { $s = $p; while ($p < 512 && $bits[$p] === '0') $p++;
            $len = $p - $s; if ($len >= 2) printf("  page %d (choff 0x%x): %d pages\n", $s, $s * 0x1000, $len);
        } else $p++;
    }
    exit(0);
}

if ($argc > 1 && str_starts_with($argv[1], 'watchps:')) {
    // watchps:ITERS -> tight loop reading mod_data; print every distinct non-null ps_files
    $iters = (int)explode(':', $argv[1])[1];
    $psg = $bias + PS_GLOBALS_VADDR;
    $f = @fopen('/proc/' . $pid . '/mem', 'rb');
    if (!$f) { echo "NOFILE\n"; exit(4); }
    $seen = [];
    for ($i = 0; $i < $iters; $i++) {
        if (@fseek($f, $psg + PS_MOD_DATA, SEEK_SET) !== 0) continue;
        $d = @fread($f, 8);
        if ($d === false || strlen($d) < 8) continue;
        $v = unpack('P', $d)[1];
        if ($v && !isset($seen[$v])) { $seen[$v] = 1;
            printf("ps_files=0x%x choff=0x%x\n", $v, $v & 0x1fffff); }
    }
    fclose($f);
    if (!$seen) echo "none\n";
    exit(0);
}

if ($argc > 1 && $argv[1] === 'psfiles') {
    $psg = $bias + PS_GLOBALS_VADDR;
    $mdp = readmem($pid, $psg + PS_MOD_DATA, 8);
    if ($mdp === false) { echo "READ_FAIL\n"; exit(4); }
    $psfiles = unpack('P', $mdp)[1];
    $out = sprintf("ps_globals=0x%x ps_files=0x%x chunk=0x%x", $psg, $psfiles, $psfiles & ~0x1fffff);
    if ($psfiles) {
        $lk = readmem($pid, $psfiles + 0, 8);
        $bd = readmem($pid, $psfiles + 8, 8);
        if ($lk !== false && $bd !== false)
            $out .= sprintf(" last_key=0x%x basedir=0x%x", unpack('P', $lk)[1], unpack('P', $bd)[1]);
    }
    echo $out . "\n";
    exit(0);
}

if ($argc > 1 && str_starts_with($argv[1], 'poke:')) {
    // poke:HEXADDR:HEXVAL8  -> write 8 bytes (LE of the 64-bit hex value) at addr
    [, $hex, $valhex] = explode(':', $argv[1]);
    $addr = (int)hexdec($hex);
    $val = (int)hexdec($valhex);
    $ok = writemem($pid, $addr, pack('P', $val));
    echo ($ok ? "POKE_OK" : "POKE_FAIL") . " @0x" . dechex($addr) . " =0x" . dechex($val) . "\n";
    exit($ok ? 0 : 5);
}

if ($argc > 1 && str_starts_with($argv[1], 'dump:')) {
    [, $hex, $len] = explode(':', $argv[1]);
    $addr = (int)hexdec($hex);
    $d = readmem($pid, $addr, (int)$len);
    if ($d === false) { echo "READ_FAIL\n"; exit(4); }
    echo "ADDR=0x" . dechex($addr) . " LEN=" . strlen($d) . "\n" . bin2hex($d) . "\n";
    exit(0);
}

$bg = $bias + BG_VADDR;
$d = readmem($pid, $bg + UNSER_DATA, 8);
$l = readmem($pid, $bg + UNSER_LEVEL, 4);
if ($d === false || $l === false) { echo "READ_FAIL pid=$pid bias=0x" . dechex($bias) . "\n"; exit(4); }
$data = unpack('P', $d)[1];
$level = unpack('V', $l)[1];
printf("pid=%d bias=0x%x BG=0x%x unser.data=0x%x unser.level=%d\n", $pid, $bias, $bg, $data, $level);
