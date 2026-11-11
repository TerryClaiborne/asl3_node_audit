(()=>{'use strict';
// Dynamic structured full-audit data plus authoritative browser-trigger state.
const $=s=>document.querySelector(s), all=s=>[...document.querySelectorAll(s)];
const LEVELS=new Set(['PASS','WARN','FAIL','INFO','SKIP','UNKNOWN']);
const canTriggerAudit=Boolean(document.body?.dataset.auditCsrf);
const csrf=document.body?.dataset.auditCsrf||'';
const forceLogin=document.body?.dataset.forceAudit==='1';
const POLL_MS=5000, PERIODIC_MS=5*60*1000, RUN_STALE_MS=16*60*1000;
let lastStamp=null, loading=false, requestInFlight=false, lastPeriodicAttempt=0;
let requestedAt=0, requestAccepted=false, started=false;
const el=(tag,cls,txt)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(txt!==undefined)x.textContent=txt;return x;};
const time=ms=>Number.isFinite(ms)?new Date(ms).toLocaleString():'';
function status(label,health='muted'){
 const target=$('.mast-date');
 if(target){
  target.replaceChildren(el('span','','Full audit: '),el('strong','',label));
  target.classList.toggle('audit-running',health==='running');
  target.classList.toggle('audit-error',health==='bad');
 }
 const footer=$('footer span:first-child');if(footer)footer.textContent='ASL3 Node Audit · Automatically monitored · No automatic repairs';
}
function counters(totals){
 const names=['PASS','WARN','FAIL','INFO','UNKNOWN','SKIP'];
 all('.statcount').forEach((node,i)=>{const v=totals?.[names[i]];node.textContent=Number.isInteger(v)&&v>=0?String(v):'—';});
}
function chip(value){
 const text=String(value??'').trim(), state=text.toLowerCase(), cell=el('span','audit-table-value',text);
 if(['active','running','enabled','yes','ok','healthy','passed','pass'].includes(state))cell.classList.add('audit-positive');
 else if(['failed','error','fail'].includes(state))cell.classList.add('audit-negative');
 else if(['inactive','disabled','static','masked','unknown'].includes(state))cell.classList.add('audit-neutral');
 else if(['warning','warn','pending'].includes(state))cell.classList.add('audit-warning');
 return cell;
}
function groupTable(rows){
 const table=el('table','audit-inventory-table');let cells=rows.map(x=>x.cells);
 const hasHeader=/^(timer unit|dashboard|service|unit|package|name)$/i.test(cells[0][0]||'')||(cells[0].some(x=>/^(startup|active|version|state)$/i.test(x))&&rows.length>1);
 let offset=0;
 if(hasHeader){const head=el('thead'),tr=el('tr');for(const c of cells[0])tr.appendChild(el('th','',c));head.appendChild(tr);table.appendChild(head);offset=1;}
 const body=el('tbody');for(const fields of cells.slice(offset)){const tr=el('tr');for(let col=0;col<fields.length;col++){
  const v=fields[col],td=el('td'),isGit=hasHeader&&/git tracked files/i.test(cells[0][col]||'');
  if(isGit&&v==='Unknown'){const state=chip('Not verified');state.classList.remove('audit-neutral');state.classList.add('audit-warning');state.title='Git status could not be verified (command failed or timed out). This does not mean the application was modified.';td.appendChild(state);}else td.appendChild(chip(v));tr.appendChild(td);
 }body.appendChild(tr);}table.appendChild(body);return table;
}
function fillPanel(section){
 const panel=$(`#detail-${section.number} .detail-rows`);if(!panel)return;const preserve=panel.scrollTop;
 const security=section.number===2?panel.querySelector('.security-details'):null, frag=document.createDocumentFragment();if(security)frag.appendChild(security);
 const rows=Array.isArray(section.rows)?section.rows:[];
 for(let i=0;i<rows.length;){const r=rows[i];
  if(r.kind==='columns'&&Array.isArray(r.cells)&&r.cells.length>=2){const grouped=[r];let j=i+1;while(j<rows.length&&rows[j].kind==='columns'&&rows[j].cells?.length===r.cells.length){grouped.push(rows[j]);j++}const holder=el('div','audit-table-wrap');holder.appendChild(groupTable(grouped));frag.appendChild(holder);i=j;continue;}
  if(r.kind==='result'){const level=LEVELS.has(r.level)?r.level:'INFO',holder=el('div','auditrow');holder.dataset.level=level;holder.appendChild(el('span',`tag ${level.toLowerCase()}`,level));const body=el('div','rowtext');body.appendChild(el('div','',r.text));if(Array.isArray(r.detail)&&r.detail.length){const hints=el('div','detailhint');for(const d of r.detail)hints.appendChild(el('div','',d));body.appendChild(hints)}holder.appendChild(body);frag.appendChild(holder);}
  else{const holder=el('div','auditrow plain');holder.appendChild(el('span','mark','·'));const content=el('div','rowtext',r.text||'');content.classList.add('audit-prose');holder.appendChild(content);frag.appendChild(holder)}i++;
 }
 panel.replaceChildren(frag);panel.scrollTop=preserve;
}
function findings(items){
 const body=$('#findings-body');if(!body)return;all('#findings-body .finding:not([data-audit-security="1"])').forEach(x=>x.remove());
 for(const info of items){if(!Number.isInteger(info.section)||info.section<1||info.section>15)continue;const b=el('button','finding');b.type='button';b.dataset.openSection=info.section;const level=LEVELS.has(info.level)?info.level:'UNKNOWN';const copy=el('span','finding-copy');copy.appendChild(el('span','finding-message',info.message));if(Array.isArray(info.detail)&&info.detail.length)copy.appendChild(el('span','finding-detail',info.detail.slice(0,3).join(' · ')));b.append(el('span',`tag ${level.toLowerCase()}`,level),copy,el('span','arrow','View details ↗'));b.onclick=()=> $(`.tile[data-section="${info.section}"]`)?.click();body.appendChild(b);}
 const message=$('#findings-body p');if(message)message.remove();const counter=$('#toggle-findings strong');if(counter)counter.textContent=String(body.querySelectorAll('.finding').length);
}
function renderAudit(d){
 const stamp=Date.parse(d.checked_at_utc||''),age=Date.now()-stamp;
 if(d.schema!==1||d.kind!=='full_audit'||!Number.isFinite(stamp)||age< -60000||!Array.isArray(d.sections)||d.sections.length!==15||d.status!=='CURRENT')return false;
 counters(d.totals);
 if(lastStamp===d.checked_at_utc)return true;lastStamp=d.checked_at_utc;
 for(const s of d.sections){if(!Number.isInteger(s.number)||s.number<1||s.number>15)continue;const tile=$(`.tile[data-section="${s.number}"]`);if(tile){const sev=s.severity||{},kind=sev.FAIL>0?'fail':sev.WARN>0?'warn':'normal';tile.classList.remove('warn','fail','normal');tile.classList.add(kind);const sub=tile.querySelector('.tile-sub'),badge=tile.querySelector('.tile-badge');if(sub)sub.textContent=sev.FAIL?`${sev.FAIL} failure(s)`:sev.WARN?`${sev.WARN} warning(s)`:sev.PASS?`${sev.PASS} passed`:'Information available';if(badge){badge.className=`tile-badge ${kind}`;badge.textContent=kind==='normal'?'VIEW':kind.toUpperCase();}}fillPanel(s);}
 findings(Array.isArray(d.findings)?d.findings:[]);return true;
}
function stateLabel(state,auditStamp){
 if(!state||state.schema!==1||state.kind!=='audit_state'){
  if(requestAccepted){status('Audit queued…','running');return;}
  if(auditStamp)status(`Checked ${time(auditStamp)}`,'good');else status('Full audit unavailable — no completed snapshot','bad');return;
 }
 const startedMs=Date.parse(state.started_at_utc||''),completedMs=Date.parse(state.completed_at_utc||'');
 if(requestAccepted&&requestedAt){
  const stateIsOlder=(state.state==='COMPLETE'||state.state==='FAILED')&&(!Number.isFinite(completedMs)||completedMs<requestedAt);
  const runningIsOlder=state.state==='RUNNING'&&Number.isFinite(startedMs)&&startedMs<requestedAt-1000;
  if(stateIsOlder||runningIsOlder){status('Audit queued…','running');return;}
 }
 if(state.state==='RUNNING'){
  if(Number.isFinite(startedMs)&&Date.now()-startedMs>RUN_STALE_MS){status('Audit state stale — service completion not confirmed','bad');return;}
  const fullDone=Date.parse(state.full_completed_at_utc||'');
  if(state.phase==='security'&&Number.isFinite(auditStamp)&&Number.isFinite(fullDone)&&auditStamp>=fullDone){status(`Checked ${time(auditStamp)}`,'good');return;}
  status('Running full audit…','running');return;
 }
 if(state.state==='FAILED'){
  requestAccepted=false;requestedAt=0;
  const fullDone=Date.parse(state.full_completed_at_utc||'');
  if(Number.isFinite(auditStamp)&&Number.isFinite(fullDone)&&auditStamp>=fullDone){status(`Checked ${time(auditStamp)}`,'good');return;}
  const msg=typeof state.message==='string'&&state.message?state.message:'Full audit failed; previous completed snapshot retained.';status(msg,'bad');return;
 }
 if(state.state==='COMPLETE'){
  requestAccepted=false;requestedAt=0;
  if(auditStamp)status(`Checked ${time(auditStamp)}`,'good');else if(Number.isFinite(completedMs))status(`Completed ${time(completedMs)} — snapshot unavailable`,'bad');else status('Audit completed — snapshot unavailable','bad');return;
 }
 if(auditStamp)status(`Checked ${time(auditStamp)}`,'good');else status('Audit status unavailable','bad');
}
async function readJson(url){const r=await fetch(url,{cache:'no-store',credentials:'same-origin',headers:{Accept:'application/json'}});if(!r.ok)throw Error('HTTP '+r.status);return r.json();}
async function poll(){
 if(document.hidden||loading)return;loading=true;
 let audit=null,state=null,auditStamp=NaN;
 try{audit=await readJson('data.php?feed=full');if(renderAudit(audit))auditStamp=Date.parse(audit.checked_at_utc||'');}catch(e){}
 try{state=await readJson('data.php?feed=state');}catch(e){}
 if(requestAccepted&&requestedAt&&Number.isFinite(auditStamp)&&auditStamp>=requestedAt){requestAccepted=false;requestedAt=0;}
 stateLabel(state,auditStamp);
 if(!audit&&!state){status('Full audit unavailable — refresh failed','bad');counters(null);}
 loading=false;
}
async function requestAudit(reason){
 if(!canTriggerAudit||requestInFlight)return;
 const now=Date.now();if(reason==='periodic'&&lastPeriodicAttempt&&now-lastPeriodicAttempt<PERIODIC_MS)return;if(reason==='periodic')lastPeriodicAttempt=now;
 requestInFlight=true;
 const body=new URLSearchParams();body.set('csrf',csrf);body.set('reason',reason);if(forceLogin)body.set('force','1');
 try{
  const r=await fetch('refresh.php',{method:'POST',cache:'no-store',credentials:'same-origin',headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body:body.toString()});
  let d={ok:false};try{d=await r.json()}catch(e){}
  if(!r.ok||!d.ok){status('Audit request failed','bad');return;}
  if(d.running){requestAccepted=true;requestedAt=Number(d.started_at_ms)||now;status(d.phase==='security'?'Security check running…':'Running full audit…','running');}
  else if(d.queued){requestAccepted=true;requestedAt=Number(d.queued_at_ms)||now;status('Audit queued…','running');}
  else await poll();
 }catch(e){status('Audit request failed','bad');}
 finally{requestInFlight=false;}
}
function start(){
 if(started)return;started=true;
 if(canTriggerAudit){status('Checking audit state…','running');requestAudit('open');}
 else status('Loading latest completed audit…');
 poll();setInterval(poll,POLL_MS);
 setInterval(()=>{requestAudit('periodic');},PERIODIC_MS);
 document.addEventListener('visibilitychange',()=>{if(!document.hidden){poll();}});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
})();
