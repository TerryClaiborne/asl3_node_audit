<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/auth.php';
audit_require_api();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    echo json_encode(['ok'=>false,'message'=>'POST required'], JSON_THROW_ON_ERROR);
    exit;
}

/*
 * With optional login enabled, only the authenticated administrator may
 * request the privileged audit cycle. When login is disabled, opening the
 * normal dashboard may request it.
 */
$cfg = audit_config();
if ($cfg !== [] && audit_app_identity() === null) {
    http_response_code(403);
    echo json_encode(['ok'=>false,'message'=>'Authentication required'], JSON_THROW_ON_ERROR);
    exit;
}

if (!audit_csrf_valid()) {
    http_response_code(403);
    echo json_encode(['ok'=>false,'message'=>'Invalid request'], JSON_THROW_ON_ERROR);
    exit;
}

$forceRequested = isset($_POST['force']) && $_POST['force'] === '1';
$forceAllowed = $forceRequested && $cfg !== [] && audit_app_identity() !== null
    && !empty($_SESSION['force_audit_once']);

$dir = dirname(__DIR__) . '/run/trigger';
$file = $dir . '/request';
$lockFile = $dir . '/request.lock';

if (is_link($dir) || !is_dir($dir) || !is_writable($dir)) {
    http_response_code(503);
    echo json_encode(['ok'=>false,'message'=>'Audit trigger unavailable'], JSON_THROW_ON_ERROR);
    exit;
}

clearstatcache(true, $file);
clearstatcache(true, $lockFile);
if (is_link($file) || is_link($lockFile)) {
    http_response_code(503);
    echo json_encode(['ok'=>false,'message'=>'Unsafe trigger state'], JSON_THROW_ON_ERROR);
    exit;
}

/*
 * Lock a separate file so a duplicate browser request never opens
 * the systemd-watched request file for writing.  The watched file is touched
 * only when the 300-second gate actually accepts a new full audit request.
 */
$lock = @fopen($lockFile, 'c+');
if ($lock === false) {
    http_response_code(503);
    echo json_encode(['ok'=>false,'message'=>'Could not lock audit request'], JSON_THROW_ON_ERROR);
    exit;
}

try {
    if (!flock($lock, LOCK_EX)) {
        throw new RuntimeException('Could not lock audit request');
    }

    clearstatcache(true, $file);
    if (is_link($file)) {
        throw new RuntimeException('Unsafe trigger state');
    }

    $previous = @file_get_contents($file, false, null, 0, 64);
    $last = is_string($previous) && preg_match('/^[0-9]{1,20}$/', trim($previous))
        ? (int)trim($previous)
        : 0;

    if (!$forceAllowed && $last > 0 && (time() - $last) < 300) {
        flock($lock, LOCK_UN);
        fclose($lock);
        echo json_encode(
            ['ok'=>true,'queued'=>false,'message'=>'Recent audit already requested'],
            JSON_THROW_ON_ERROR
        );
        exit;
    }

    $queuedAt = time();
    $handle = @fopen($file, 'c+');
    if ($handle === false) {
        throw new RuntimeException('Could not request audit');
    }

    try {
        if (!ftruncate($handle, 0) || !rewind($handle)
            || fwrite($handle, (string)$queuedAt . "\n") === false
            || !fflush($handle)) {
            throw new RuntimeException('Could not write audit trigger');
        }
        @chmod($file, 0600);
    } finally {
        fclose($handle);
    }

    if ($forceAllowed) {
        unset($_SESSION['force_audit_once']);
    }
    @chmod($lockFile, 0600);
    flock($lock, LOCK_UN);
} catch (Throwable $e) {
    @flock($lock, LOCK_UN);
    fclose($lock);
    http_response_code(503);
    echo json_encode(['ok'=>false,'message'=>'Could not request audit'], JSON_THROW_ON_ERROR);
    exit;
}

fclose($lock);
echo json_encode(['ok'=>true,'queued'=>true,'queued_at_ms'=>$queuedAt * 1000], JSON_THROW_ON_ERROR);
