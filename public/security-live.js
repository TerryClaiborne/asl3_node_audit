(()=>{'use strict';
const $=s=>document.querySelector(s);
const row=(tag,cls,content)=>{const el=document.createElement(tag);if(cls)el.className=cls;if(content!==undefined)el.textContent=content;return el};
let started=false;
function replaceChildren(el,children){if(el)el.replaceChildren(...children)}
function render(d){
 const viewOnly=document.body?.dataset.viewOnly==='1';
 const date=typeof d.checked_at_utc==='string'?Date.parse(d.checked_at_utc):NaN;
 const fresh=d.state==='CURRENT'&&Number.isFinite(date)&&Math.abs(Date.now()-date)<150000;
 const checked=fresh&&d.apt_state==='CHECKED'&&Number.isInteger(d.security_count);
 const pending=checked?d.security_count:null;
 const stateText=!fresh?'Checking / unavailable':!checked?'Security updates unverified':pending?'Security updates pending':'No pending security upgrades';
 const badge=$('.security-inline');
 if(badge){badge.textContent=checked?`Debian security: ${pending} pending`:stateText;badge.classList.toggle('security-unverified',!checked)}
 const findings=$('#findings-body');
 if(findings){
   let item=[...findings.querySelectorAll('.finding')].find(x=>x.dataset.auditSecurity==='1'||x.textContent.includes('Security results are stale')||x.textContent.includes('Debian security'));
   const needed=!checked||pending>0;
   if(!needed){item?.remove()}else{
     if(!item){item=row('button','finding');item.type='button';findings.prepend(item)}
     item.dataset.auditSecurity='1';item.dataset.openSection='2';
     replaceChildren(item,[row('span',`tag ${checked?'warn':'unknown'}`,checked?'WARN':'CHECKING'),
       row('span','',checked?`${pending} Debian security package updates pending`: 'Security check in progress or unavailable'),
       row('span','arrow',viewOnly?'Login to view details':'View updates ↗')]);
     item.disabled=viewOnly;
     item.onclick=viewOnly?null:()=>$('#tilegrid .tile[data-section="2"]')?.click();
   }
   const counter=$('#toggle-findings strong');
   if(counter)counter.textContent=String(findings.querySelectorAll('.finding').length);
 }
 const panel=$('#detail-2 .security-details');
 if(panel){
   const contents=[row('strong','', 'Current Debian security updates'),row('div','security-meta',
     fresh?`Security checked: ${new Date(date).toLocaleString()} · Partial audit coverage`:'A current security check is not available yet')];
   if(checked){
     contents.push(row('div','security-meta',`${pending} security updates; ${d.other_count??'?'} other upgrades`));
     if(Array.isArray(d.security_packages)&&pending){
       const table=row('table','security-packages'),head=row('thead'),body=row('tbody'),tr=row('tr');
       for(const title of ['Package','Installed','Available'])tr.append(row('th','',title));head.append(tr);
       for(const p of d.security_packages){const r=row('tr');for(const k of ['package','installed','candidate'])r.append(row('td','',String(p[k]??'')));body.append(r)}
       table.append(head,body);contents.push(table);
     }
   }else contents.push(row('div','security-meta','Automatic monitoring will retry. No clean status is assumed.'));
   replaceChildren(panel,contents);
 }
 // Keep security alarm separate from ordinary pending package updates.
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
   const d=await r.json();if(d.schema!==1)throw Error('Bad schema');
   render(d);
 }catch(e){render({state:'UNAVAILABLE',apt_state:'UNVERIFIED',checked_at_utc:null,alarm:'UNAVAILABLE'})}
}
function start(){if(started)return;started=true;
  // No SWAP or APACHE2 pills in the final ribbon.
  for(const id of ['live-swap','live-apache'])document.getElementById(id)?.closest('.strip-item')?.remove();
  // Full-audit status and timestamp are maintained by the full audit.
  poll();setInterval(poll,15000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)poll()});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
})();
