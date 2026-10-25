<?php
/** ASL3 Node Audit session authentication. Never expose this directory via Apache. */
declare(strict_types=1);

function audit_config(): array {
    // Same model as AllStar Connect: the administrator is configured, not entered at login.
    $file=dirname(__DIR__).'/config.ini';
    if (is_link($file) || !is_file($file) || !is_readable($file)) return [];
    $doc=@parse_ini_file($file, false, INI_SCANNER_RAW);
    if (!is_array($doc)) return [];
    if (($doc['ASL3_NODE_AUDIT_AUTH_ENABLED'] ?? '') !== '1') return [];
    $user=$doc['ASL3_NODE_AUDIT_ADMIN_USER'] ?? '';
    $hash=$doc['ASL3_NODE_AUDIT_ADMIN_PASSWORD_HASH'] ?? '';
    if (!is_string($user) || !preg_match('/^[A-Za-z0-9_.-]{1,32}$/D', $user)) return [];
    if (!is_string($hash) || !password_get_info($hash)['algo']) return [];
    return ['enabled'=>'true','username'=>$user,'password_hash'=>$hash];
}

function audit_headers(): void {
    header('Cache-Control: no-store, private, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('X-Frame-Options: DENY');
}

function audit_is_https(): bool {
    $https = strtolower((string)($_SERVER['HTTPS'] ?? ''));
    $proto = strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
    return $https === 'on' || $https === '1' || $proto === 'https';
}

function audit_start_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    session_name('ASL3NODEAUDIT');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/asl3_node_audit/', 'secure' => audit_is_https(),
        'httponly' => true, 'samesite' => 'Strict',
    ]);
    if (!session_start()) { http_response_code(503); exit('Session unavailable'); }
    audit_headers();
}

function audit_csrf(): string {
    audit_start_session();
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function audit_csrf_valid(): bool {
    return isset($_POST['csrf']) && is_string($_POST['csrf'])
        && hash_equals(audit_csrf(), $_POST['csrf']);
}

function audit_app_identity(): ?string {
    audit_start_session();
    $cfg = audit_config();
    if (!$cfg || !isset($_SESSION['user'], $_SESSION['created'], $_SESSION['last'], $_SESSION['v'])) return null;
    $now = time();
    if (!is_string($_SESSION['user']) || !is_int($_SESSION['last']) || !is_int($_SESSION['created'])
        || ($now - $_SESSION['last']) > 1800 || ($now - $_SESSION['created']) > 43200
        || $_SESSION['last'] > $now || $_SESSION['created'] > $now
        || !hash_equals($cfg['username'], $_SESSION['user'])
        || !is_string($_SESSION['v']) || !hash_equals(hash('sha256', $cfg['password_hash']), $_SESSION['v'])) {
        unset($_SESSION['user'], $_SESSION['created'], $_SESSION['last'], $_SESSION['v']);
        return null;
    }
    $_SESSION['last'] = $now;
    return $_SESSION['user'];
}


function audit_identity(): ?string {
    return audit_app_identity();
}

function audit_escape(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function audit_login_page(): never {
    audit_start_session();
    $configured = audit_config() !== [];
    $error = $_SESSION['login_error'] ?? null;
    unset($_SESSION['login_error']);
    $csrf = audit_escape(audit_csrf());
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    $note = $error && is_string($error) ? '<p class="auth-error" role="alert">'.audit_escape($error).'</p>' : '';
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        .'<title>Login | ASL3 Node Audit</title><link rel="stylesheet" href="style.css"></head><body class="auth-page">'
        .'<main class="auth-card"><h1>ASL3 Node Audit</h1><p class="auth-status">Optional web login</p>' . $note;
    if ($configured) {
        echo '<form method="post" action="login.php" autocomplete="on">'
           .'<input type="hidden" name="csrf" value="'.$csrf.'">'
           .'<label for="audit-password">Password</label>'
           .'<input id="audit-password" name="password" type="password" autocomplete="current-password" required autofocus>'
           .'<p><button type="submit" class="outline">Login</button>'
           .'<a class="outline" href="./">Cancel</a></p></form>';
    } else {
        echo '<p>Optional login is not enabled. The dashboard is available without an application password.</p>'
           .'<p><a class="outline" href="./">Cancel</a></p>';
    }
    echo '</main></body></html>';
    exit;
}

/*
 * ASL3 Node Audit is a read-only dashboard. Match the AllStar Connect model:
 * enabling the optional application login does not hide read-only diagnostics.
 * Signed-out users remain in view-only mode; Login/Logout only manages the
 * optional administrator session.
 */
function audit_require_page(): void {
    audit_start_session();
}

function audit_require_api(): void {
    audit_start_session();
}

/** Fail closed if the bounded file-based IP limiter cannot be used. */
function audit_attempt(string $ip, bool $successful = false): bool {
    $dir = dirname(__DIR__) . '/run/auth';
    if (is_link($dir) || !is_dir($dir)) return false;
    $name = $dir.'/'.hash('sha256', $ip).'.json';
    if (is_link($name)) return false;
    $handle = @fopen($name, 'c+');
    if (!$handle) return false;
    try {
        if (!flock($handle, LOCK_EX)) return false;
        @chmod($name, 0600);
        $text = stream_get_contents($handle, 2048);
        $doc = is_string($text) ? json_decode($text, true) : null;
        $now = time();
        $time = is_array($doc) && is_int($doc['time'] ?? null) ? $doc['time'] : $now;
        $count = is_array($doc) && is_int($doc['count'] ?? null) ? $doc['count'] : 0;
        if ($time > $now || ($now - $time) > 900) { $time = $now; $count = 0; }
        $permitted = $successful || $count < 5;
        if ($successful) { $count = 0; $time = $now; }
        elseif ($permitted) { ++$count; }
        rewind($handle);
        if (!ftruncate($handle, 0)) return false;
        $data = json_encode(['time'=>$time, 'count'=>$count], JSON_THROW_ON_ERROR);
        if (fwrite($handle, $data) !== strlen($data) || !fflush($handle)) return false;
        return $permitted;
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}
