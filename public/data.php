<?php
// A single authenticated, fail-closed reader for sanitized monitor feeds.
declare(strict_types=1);
require_once dirname(__DIR__) . '/src/auth.php';
audit_require_api();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
$allowed = ['security' => 'security-feed.json', 'full' => 'full-audit-feed.json'];
$kind = $_GET['feed'] ?? '';
if (!is_string($kind) || !array_key_exists($kind, $allowed)) {
    http_response_code(400);
    echo json_encode(['state'=>'UNAVAILABLE','message'=>'Invalid feed'], JSON_THROW_ON_ERROR);
    exit;
}
$file = dirname(__DIR__) . '/run/web/' . $allowed[$kind];
clearstatcache(true, $file);
if (is_link($file) || !is_file($file) || !is_readable($file) || filesize($file) > 2097152) {
    http_response_code(503);
    echo json_encode(['state'=>'UNAVAILABLE','message'=>'No verified feed'], JSON_THROW_ON_ERROR);
    exit;
}
$raw = @file_get_contents($file, false, null, 0, 2097153);
if (!is_string($raw) || strlen($raw) > 2097152) {
    http_response_code(503);
    echo json_encode(['state'=>'UNAVAILABLE'], JSON_THROW_ON_ERROR);
    exit;
}
try {
    $data = json_decode($raw, true, 128, JSON_THROW_ON_ERROR);
    if (!is_array($data) || ($data['schema'] ?? null) !== 1
        || ($kind === 'full' && ($data['kind'] ?? null) !== 'full_audit')
        || !isset($data['checked_at_utc'])) throw new RuntimeException('Invalid snapshot');
    echo json_encode($data, JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    http_response_code(503);
    echo json_encode(['state'=>'UNAVAILABLE','message'=>'Invalid feed'], JSON_THROW_ON_ERROR);
}
