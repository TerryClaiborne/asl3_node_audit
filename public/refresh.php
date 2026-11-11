<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/src/auth.php';
audit_require_api();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {http_response_code(405);header('Allow: POST');echo json_encode(['ok'=>false,'message'=>'POST required'],JSON_THROW_ON_ERROR);exit;}
$cfg=audit_config();
if ($cfg!==[] && audit_app_identity()===null) {http_response_code(403);echo json_encode(['ok'=>false,'message'=>'Authentication required'],JSON_THROW_ON_ERROR);exit;}
if (!audit_csrf_valid()) {http_response_code(403);echo json_encode(['ok'=>false,'message'=>'Invalid request'],JSON_THROW_ON_ERROR);exit;}
$reason=$_POST['reason']??'periodic';
if (!is_string($reason)||!in_array($reason,['open','periodic'],true))$reason='periodic';
$forceRequested=isset($_POST['force'])&&$_POST['force']==='1';
$forceLogin=$forceRequested&&$cfg!==[]&&audit_app_identity()!==null&&!empty($_SESSION['force_audit_once']);
$root=dirname(__DIR__);$dir=$root.'/run/trigger';$file=$dir.'/request';$lockFile=$dir.'/request.lock';$stateFile=$root.'/run/web/audit-state.json';
if (is_link($dir)||!is_dir($dir)||!is_writable($dir)){http_response_code(503);echo json_encode(['ok'=>false,'message'=>'Audit trigger unavailable'],JSON_THROW_ON_ERROR);exit;}
foreach([$file,$lockFile,$stateFile] as $p){clearstatcache(true,$p);if(is_link($p)){http_response_code(503);echo json_encode(['ok'=>false,'message'=>'Unsafe audit state'],JSON_THROW_ON_ERROR);exit;}}
function active_audit_state(string $file): array {
    if(!is_file($file)||!is_readable($file)||filesize($file)>65536)return [];
    $raw=@file_get_contents($file,false,null,0,65537);if(!is_string($raw)||strlen($raw)>65536)return [];
    try{$d=json_decode($raw,true,32,JSON_THROW_ON_ERROR);}catch(Throwable $e){return [];}
    if(!is_array($d)||($d['schema']??null)!==1||($d['kind']??null)!=='audit_state'||($d['state']??null)!=='RUNNING')return [];
    $started=strtotime((string)($d['started_at_utc']??''));if($started===false||time()-$started>960)return [];
    return $d;
}
$lock=@fopen($lockFile,'c+');if($lock===false){http_response_code(503);echo json_encode(['ok'=>false,'message'=>'Could not lock audit request'],JSON_THROW_ON_ERROR);exit;}
try{
 if(!flock($lock,LOCK_EX))throw new RuntimeException('Could not lock audit request');
 $active=active_audit_state($stateFile);
 if($active!==[]){
   flock($lock,LOCK_UN);fclose($lock);
   $started=strtotime((string)$active['started_at_utc']);
   echo json_encode(['ok'=>true,'queued'=>false,'running'=>true,'phase'=>$active['phase']??'full_audit','started_at_ms'=>$started!==false?$started*1000:null],JSON_THROW_ON_ERROR);exit;
 }
 clearstatcache(true,$file);if(is_link($file))throw new RuntimeException('Unsafe trigger state');
 $previous=@file_get_contents($file,false,null,0,64);$last=is_string($previous)&&preg_match('/^[0-9]{1,20}$/',trim($previous))?(int)trim($previous):0;
 $age=$last>0?time()-$last:PHP_INT_MAX;
 // Coalesce simultaneous/repeated opens while systemd is still noticing the trigger.
 if(($reason==='open'||$forceLogin)&&$age<10){flock($lock,LOCK_UN);fclose($lock);echo json_encode(['ok'=>true,'queued'=>true,'queued_at_ms'=>$last*1000,'message'=>'Audit request already queued'],JSON_THROW_ON_ERROR);exit;}
 // Periodic requests retain the global five-minute gate. A genuine page open bypasses it.
 if($reason==='periodic'&&!$forceLogin&&$last>0&&$age<300){flock($lock,LOCK_UN);fclose($lock);echo json_encode(['ok'=>true,'queued'=>false,'message'=>'Recent audit already requested'],JSON_THROW_ON_ERROR);exit;}
 $queuedAt=time();$handle=@fopen($file,'c+');if($handle===false)throw new RuntimeException('Could not request audit');
 try{if(!ftruncate($handle,0)||!rewind($handle)||fwrite($handle,(string)$queuedAt."\n")===false||!fflush($handle))throw new RuntimeException('Could not write audit trigger');@chmod($file,0600);}finally{fclose($handle);}
 if($forceLogin)unset($_SESSION['force_audit_once']);@chmod($lockFile,0600);flock($lock,LOCK_UN);
}catch(Throwable $e){@flock($lock,LOCK_UN);fclose($lock);http_response_code(503);echo json_encode(['ok'=>false,'message'=>'Could not request audit'],JSON_THROW_ON_ERROR);exit;}
fclose($lock);echo json_encode(['ok'=>true,'queued'=>true,'queued_at_ms'=>$queuedAt*1000],JSON_THROW_ON_ERROR);
