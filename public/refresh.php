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

$dir = dirname(__DIR__) . '/run/trigger';
$file = $dir . '/request';

if (is_link($dir) || !is_dir($dir) || !is_writable($dir)) {
    http_response_code(503);
    echo json_encode(['ok'=>false,'message'=>'Audit trigger unavailable'], JSON_THROW_ON_ERROR);
    exit;
}

clearstatcache(true, $file);
if (is_link($file)) {
    http_response_code(503);
    echo json_encode(['ok'=>false,'message'=>'Unsafe trigger state'], JSON_THROW_ON_ERROR);
    exit;
}

$handle = @fopen($file, 'c+');
if ($handle === false) {
    http_response_code(503);
    echo json_encode(['ok'=>false,'message'=>'Could not request audit'], JSON_THROW_ON_ERROR);
    exit;
}

try {
    if (!flock($handle, LOCK_EX)) {
        throw new RuntimeException('Could not lock audit trigger');
    }

    /*
     * Store the last request time in the file itself. An empty newly-created
     * file is never mistaken for an earlier audit request.
     */
    if (!rewind($handle)) {
        throw new RuntimeException('Could not read audit trigger');
    }

    $previous = stream_get_contents($handle, 64);
    $last = is_string($previous) && preg_match('/^[0-9]{1,20}$/', trim($previous))
        ? (int)trim($previous)
        : 0;

    if ($last > 0 && (time() - $last) < 600) {
        flock($handle, LOCK_UN);
        fclose($handle);
        echo json_encode(
            ['ok'=>true,'queued'=>false,'message'=>'Recent audit already requested'],
            JSON_THROW_ON_ERROR
        );
        exit;
    }

    if (!ftruncate($handle, 0) || !rewind($handle)
        || fwrite($handle, (string)time() . "\n") === false
        || !fflush($handle)) {
        throw new RuntimeException('Could not write audit trigger');
    }

    @chmod($file, 0600);
    flock($handle, LOCK_UN);
} catch (Throwable $e) {
    @flock($handle, LOCK_UN);
    fclose($handle);
    http_response_code(503);
    echo json_encode(['ok'=>false,'message'=>'Could not request audit'], JSON_THROW_ON_ERROR);
    exit;
}

fclose($handle);
echo json_encode(['ok'=>true,'queued'=>true], JSON_THROW_ON_ERROR);
