<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/src/auth.php';
audit_start_session();
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') audit_login_page();
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { header('Allow: GET, POST'); http_response_code(405); exit; }
if (!audit_csrf_valid()) { http_response_code(403); exit('Invalid request'); }
$cfg=audit_config();
$password=$_POST['password'] ?? null;
if (!$cfg || !is_string($password) || strlen($password)>1024) {
    http_response_code(403); exit('Authentication unavailable');
}
$ip=$_SERVER['REMOTE_ADDR'] ?? '';
if (!is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP) || !audit_attempt($ip)) {
    $_SESSION['login_error']='Login temporarily unavailable. Try again later.';
    header('Location: login.php',true,303); exit;
}
if (!password_verify($password,$cfg['password_hash'])) {
    $_SESSION['login_error']='Incorrect password.';
    header('Location: login.php',true,303); exit;
}
if (!session_regenerate_id(true)) { http_response_code(503); exit('Session unavailable'); }
audit_attempt($ip,true);
$_SESSION['user']=$cfg['username'];
$_SESSION['created']=time();
$_SESSION['last']=time();
$_SESSION['v']=hash('sha256',$cfg['password_hash']);
$_SESSION['csrf']=bin2hex(random_bytes(32));
// A successful login must begin with a fresh audit, even if another browser
// requested one within the ordinary five-minute gate.  refresh.php consumes
// this flag exactly once after the trigger is successfully queued.
$_SESSION['force_audit_once']=true;
header('Location: ./',true,303);
