<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/src/auth.php';
audit_require_api();
// Read-only, low-cost metrics endpoint protected by the optional application login.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
function lines(string $p): array { $s = @file_get_contents($p, false, null, 0, 8192); return is_string($s) ? (preg_split('/\r?\n/', $s) ?: []) : []; }
$cpu = null;
foreach (lines('/proc/stat') as $line) {
    if (preg_match('/^cpu\s+((?:\d+\s+){3,}\d+)/', $line, $m)) {
        $v = array_map('intval', preg_split('/\s+/', trim($m[1])) ?: []);
        if (count($v) >= 4) { $cpu = ['total'=>array_sum($v), 'idle'=>$v[3]+($v[4]??0)]; }
        break;
    }
}
$mem = [];
foreach (lines('/proc/meminfo') as $line) if (preg_match('/^(MemTotal|MemAvailable):\s*(\d+)/', $line, $m)) $mem[$m[1]]=(int)$m[2];
$ram = isset($mem['MemTotal'], $mem['MemAvailable']) && $mem['MemTotal']>0 ? round(100 * (1-$mem['MemAvailable']/$mem['MemTotal'])) : null;
$ramUsedMiB = isset($mem['MemTotal'], $mem['MemAvailable']) ? round(($mem['MemTotal']-$mem['MemAvailable'])/1024) : null;
$ramTotalMiB = isset($mem['MemTotal']) ? round($mem['MemTotal']/1024) : null;
$swapTotal = 0; $swapFree = 0;
foreach (lines('/proc/meminfo') as $line) {
    if (preg_match('/^SwapTotal:\s*(\d+)/', $line, $m)) $swapTotal=(int)$m[1];
    if (preg_match('/^SwapFree:\s*(\d+)/', $line, $m)) $swapFree=(int)$m[1];
}
$swapPct = $swapTotal > 0 ? round(100 * (1-$swapFree/$swapTotal)) : null;
$load1 = null; $runningTasks = null;
$loadinfo = @file_get_contents('/proc/loadavg');
if (is_string($loadinfo) && preg_match('/^([0-9.]+)\s+[0-9.]+\s+[0-9.]+\s+(\d+)\/(\d+)/', $loadinfo, $lm)) {
    $load1 = (float)$lm[1]; $runningTasks=(int)$lm[2];
}
// Network counters for the default route's interface only. No shell commands, sockets, or network probes.
$iface = null;
foreach (lines('/proc/net/route') as $r) {
    $parts = preg_split('/\s+/', trim($r)) ?: [];
    if (count($parts) > 3 && $parts[1] === '00000000' && ctype_xdigit($parts[3]) && ((hexdec($parts[3]) & 1) === 1) && preg_match('/^[a-zA-Z0-9_.:-]{1,32}$/', $parts[0])) { $iface = $parts[0]; break; }
}
$net = null;
if ($iface !== null) {
    foreach (lines('/proc/net/dev') as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) !== 2 || trim($parts[0]) !== $iface) continue;
        $v = preg_split('/\s+/', trim($parts[1])) ?: [];
        if (count($v) >= 9 && ctype_digit($v[0]) && ctype_digit($v[8])) $net = ['rx'=>(float)$v[0], 'tx'=>(float)$v[8]];
        break;
    }
}

$temp = null;
$t = @file_get_contents('/sys/class/thermal/thermal_zone0/temp');
if (is_string($t) && is_numeric(trim($t))) { $temp=round(((float)trim($t)/1000)*9/5+32, 1); }
$up = null; $u = @file_get_contents('/proc/uptime');
if (is_string($u) && preg_match('/^([0-9.]+)/', $u, $m)) $up = (int)(float)$m[1];
$disk = @disk_total_space('/'); $free = @disk_free_space('/');
$used = is_numeric($disk) && $disk>0 && is_numeric($free) ? round(100*(1-$free/$disk)) : null;


echo json_encode(['cpu'=>$cpu,'ram_pct'=>$ram,'ram_used_mib'=>$ramUsedMiB,'ram_total_mib'=>$ramTotalMiB,'net'=>$net,'temp_f'=>$temp,'disk_pct'=>$used,'uptime_s'=>$up,'load_1m'=>$load1,'running_tasks'=>$runningTasks,'swap_pct'=>$swapPct], JSON_THROW_ON_ERROR);
