<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/src/auth.php';
audit_start_session();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Allow: POST'); http_response_code(405); exit; }
if (!audit_csrf_valid()) { http_response_code(403); exit('Invalid request'); }
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', ['expires'=>time()-3600,'path'=>$params['path'],
        'secure'=>audit_is_https(),'httponly'=>true,'samesite'=>'Strict']);
}
session_destroy();
header('Location: ./', true, 303);
