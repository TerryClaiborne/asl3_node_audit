(()=>{'use strict';
const $=s=>document.querySelector(s);
const row=(tag,cls,content)=>{const el=document.createElement(tag);if(cls)el.className=cls;if(content!==undefined)el.textContent=content;return el};
let started=false;
function replaceChildren(el,children){if(el)el.replaceChildren(...children)}
function safeProblem(d){
 const p=d&&typeof d.problem==='object'&&d.problem?d.problem:{};
 const text=k=>typeof p[k]==='string'?p[k].slice(0,700):'';
 return {category:text('category'),summary:text('summary'),impact:text('impact'),action:text('action'),verify:text('verify'),repository:text('repository')};
}
function addMeta(contents,label,value,cls='security-meta'){
 if(!value)return;const line=row('div',cls);line.append(row('strong','',label+' '),document.createTextNode(value));contents.push(line);
}
function render(d){
 const date=typeof d.checked_at_utc==='string'?Date.parse(d.checked_at_utc):NaN;
 const fresh=d.state==='CURRENT'&&Number.isFinite(date);
 const checked=fresh&&d.apt_state==='CHECKED'&&Number.isInteger(d.security_count)&&d.security_count>=0;
 const pending=checked?d.security_count:null;
 const problem=safeProblem(d);
 const alarmProblem=d&&typeof d.alarm_problem==='object'&&d.alarm_problem?d.alarm_problem:{};
 const badge=$('.security-inline');
 if(badge){
   let text='Security check unavailable';
   if(checked)text=`Debian security: ${pending} pending`;
   else if(problem.repository&&problem.summary)text=`Security check: ${problem.repository} — ${problem.summary}`;
   else if(problem.summary)text=`Security check: ${problem.summary}`;
   else if(d.state==='STALE')text='Security check: metadata stale';
   badge.textContent=text;
   badge.title=!checked?[problem.summary,problem.impact,problem.action].filter(Boolean).join(' '):'';
   badge.classList.toggle('security-unverified',!checked);
   badge.classList.toggle('security-pending',checked&&pending>0);
   badge.classList.toggle('security-clear',checked&&pending===0);
 }
 const panel=$('#detail-2 .security-details');
 if(panel){
   const contents=[row('strong','', 'Debian security-update verification')];
   if(checked){
     addMeta(contents,'Status:',pending?`${pending} security update(s) pending.`:'Verified; no pending Debian security updates.',pending?'security-meta security-warning':'security-meta security-ok');
     addMeta(contents,'Checked:',new Date(date).toLocaleString());
     addMeta(contents,'Other upgrades:',String(d.other_count??'unknown'));
     if(Array.isArray(d.security_packages)&&pending){
       const table=row('table','security-packages'),head=row('thead'),body=row('tbody'),tr=row('tr');
       for(const title of ['Package','Installed','Available'])tr.append(row('th','',title));head.append(tr);
       for(const p of d.security_packages){const r=row('tr');for(const k of ['package','installed','candidate'])r.append(row('td','',String(p[k]??'')));body.append(r)}
       table.append(head,body);contents.push(table);
     }
   }else{
     addMeta(contents,'Status:','NOT VERIFIED — no clean security-update status is assumed.','security-meta security-error');
     addMeta(contents,'Reason:',problem.summary||'The security collector did not return a verified Debian security-update result.');
     addMeta(contents,'Affected repository:',problem.repository);
     addMeta(contents,'Impact:',problem.impact||'Security-update status cannot be treated as current or clean.');
     addMeta(contents,'Suggested action:',problem.action||'Inspect the Node Audit service log and run the APT verification command.');
     addMeta(contents,'Verify:',problem.verify||'sudo apt-get -o APT::Update::Error-Mode=any update','security-meta security-command');
     if(Number.isFinite(date))addMeta(contents,'Last security collector run:',new Date(date).toLocaleString());
   }
   if(d.alarm==='TRIGGERED'){
     addMeta(contents,'Security alarm:',typeof alarmProblem.summary==='string'?alarmProblem.summary:'A critical-security self-check requires attention.','security-meta security-error');
     addMeta(contents,'Alarm impact:',typeof alarmProblem.impact==='string'?alarmProblem.impact:'');
     addMeta(contents,'Alarm action:',typeof alarmProblem.action==='string'?alarmProblem.action:'');
     addMeta(contents,'Alarm verify:',typeof alarmProblem.verify==='string'?alarmProblem.verify:'','security-meta security-command');
   }
   replaceChildren(panel,contents);
 }
 // Security alarm remains separate from package-update status and audit finding counts.
 let alarm=$('#audit-security-alarm');
 if(!alarm){alarm=row('span','', '');alarm.id='audit-security-alarm';const toggle=$('#toggle-findings .hint');toggle?.after(alarm)}
 if(alarm){alarm.textContent=fresh&&d.alarm==='TRIGGERED'?' SECURITY ALARM': '';alarm.style.color='#ff6b7a';alarm.style.fontWeight='700'}
 if(d.lan_ip&&/^\d{1,3}(?:\.\d{1,3}){3}$/.test(d.lan_ip)){
   let ip=$('#audit-ip-pill');
   if(!ip){ip=row('div','strip-item');ip.id='audit-ip-pill';ip.append(row('span','strip-label','IP'),row('strong','',''));const first=$('#system-strip .strip-item');first?.after(ip)}
   const val=ip.querySelector('strong');if(val)val.textContent=d.lan_ip;
 }
}
async function poll(){
 if(document.hidden)return;
 try{
   const r=await fetch('data.php?feed=security',{cache:'no-store',credentials:'same-origin',headers:{Accept:'application/json'}});
   if(!r.ok)throw Error('HTTP '+r.status);
   const d=await r.json();if(d.schema!==1)throw Error('Bad schema');render(d);
 }catch(e){render({state:'UNAVAILABLE',apt_state:'UNVERIFIED',checked_at_utc:null,alarm:'UNAVAILABLE',problem:{summary:'Security feed could not be read.',impact:'Current Debian security-update status is unavailable.',action:'Refresh the page and inspect the Node Audit service if the problem persists.',verify:'journalctl -u asl3-node-audit.service -n 100 --no-pager'}})}
}
function start(){if(started)return;started=true;
 for(const id of ['live-swap','live-apache'])document.getElementById(id)?.closest('.strip-item')?.remove();
 poll();setInterval(poll,15000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)poll()});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
})();
