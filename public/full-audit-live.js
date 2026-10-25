(()=>{'use strict';
// Dynamic structured full-audit data. Keeps the accepted 15-card dashboard layout.
const $=s=>document.querySelector(s), all=s=>[...document.querySelectorAll(s)];
const LEVELS=new Set(['PASS','WARN','FAIL','INFO','SKIP','UNKNOWN']);
const MAX_AGE=15*60*1000;
let lastStamp=null, loading=false;
const el=(tag,cls,txt)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(txt!==undefined)x.textContent=txt;return x;};
const time=ms=>Number.isFinite(ms)?new Date(ms).toLocaleString():'';
function status(label,health='muted'){
 const target=$('.mast-date');if(target)target.replaceChildren(el('span','','Full audit: '),el('strong','',label));
 const footer=$('footer span:first-child');if(footer)footer.textContent='ASL3 Node Audit · Automatically monitored · No automatic repairs';
}
function counters(totals){
 const names=['PASS','WARN','FAIL','INFO','UNKNOWN','SKIP'];
 all('.statcount').forEach((node,i)=>{const v=totals?.[names[i]];node.textContent=Number.isInteger(v)&&v>=0?String(v):'—';});
}
function chip(value){
 const text=String(value??'').trim();const state=text.toLowerCase();
 const cell=el('span','audit-table-value',text);
 if(['active','running','enabled','yes','ok','healthy','passed','pass'].includes(state))cell.classList.add('audit-positive');
 else if(['failed','error','fail'].includes(state))cell.classList.add('audit-negative');
 else if(['inactive','disabled','static','masked','unknown'].includes(state))cell.classList.add('audit-neutral');
 else if(['warning','warn','pending'].includes(state))cell.classList.add('audit-warning');
 return cell;
}
function groupTable(rows){
 const table=el('table','audit-inventory-table');
 let cells=rows.map(x=>x.cells);const hasHeader=/^(timer unit|dashboard|service|unit|package|name)$/i.test(cells[0][0]||'')
    || (cells[0].some(x=>/^(startup|active|version|state)$/i.test(x)) && rows.length>1);
 let offset=0;
 if(hasHeader){const head=el('thead');const tr=el('tr');for(const c of cells[0])tr.appendChild(el('th','',c));head.appendChild(tr);table.appendChild(head);offset=1;}
 const body=el('tbody');for(const fields of cells.slice(offset)){
  const tr=el('tr');for(let col=0;col<fields.length;col++){
  const v=fields[col],td=el('td');
  const isGit=hasHeader&&/git tracked files/i.test(cells[0][col]||'');
  if(isGit&&v==='Unknown'){
    const state=chip('Not verified');state.classList.remove('audit-neutral');state.classList.add('audit-warning');
    state.title='Git status could not be verified (command failed or timed out). This does not mean the application was modified.';
    td.appendChild(state);
  }else{td.appendChild(chip(v));}tr.appendChild(td);
 }body.appendChild(tr);
 }table.appendChild(body);return table;
}
function fillPanel(section){
 const panel=$(`#detail-${section.number} .detail-rows`);if(!panel)return;
 const preserve=panel.scrollTop;
 // Preserve any separate live security table in Section 2.
 const security=section.number===2?panel.querySelector('.security-details'):null;
 const frag=document.createDocumentFragment();if(security)frag.appendChild(security);
 const rows=Array.isArray(section.rows)?section.rows:[];
 for(let i=0;i<rows.length;){const r=rows[i];
  if(r.kind==='columns'&&Array.isArray(r.cells)&&r.cells.length>=2){
    const grouped=[r];let j=i+1;
    while(j<rows.length&&rows[j].kind==='columns'&&rows[j].cells?.length===r.cells.length){grouped.push(rows[j]);j++}
    const holder=el('div','audit-table-wrap');holder.appendChild(groupTable(grouped));frag.appendChild(holder);i=j;continue;
  }
  if(r.kind==='result'){
    const level=LEVELS.has(r.level)?r.level:'INFO';const holder=el('div','auditrow');holder.dataset.level=level;
    holder.appendChild(el('span',`tag ${level.toLowerCase()}`,level));
    const body=el('div','rowtext');body.appendChild(el('div','',r.text));
    if(Array.isArray(r.detail)&&r.detail.length){const hints=el('div','detailhint');for(const d of r.detail)hints.appendChild(el('div','',d));body.appendChild(hints)}
    holder.appendChild(body);frag.appendChild(holder);
  }else{const holder=el('div','auditrow plain');holder.appendChild(el('span','mark','·'));const content=el('div','rowtext',r.text||'');content.classList.add('audit-prose');holder.appendChild(content);frag.appendChild(holder)}
  i++;
 }
 panel.replaceChildren(frag);panel.scrollTop=preserve;
}
function findings(items){
 const body=$('#findings-body');if(!body)return;
 // Leave the live security finding alone; that script updates it separately.
 all('#findings-body .finding:not([data-audit-security="1"])').forEach(x=>x.remove());
 for(const info of items){if(![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15].includes(info.section))continue;
   const b=el('button','finding');b.type='button';b.dataset.openSection=info.section;
   const level=LEVELS.has(info.level)?info.level:'UNKNOWN';
   b.append(el('span',`tag ${level.toLowerCase()}`,level),el('span','',info.message),el('span','arrow','View details ↗'));
   b.onclick=()=> $(`.tile[data-section="${info.section}"]`)?.click();
   body.appendChild(b);
 }
 const message=$('#findings-body p');if(message)message.remove();
 const counter=$('#toggle-findings strong');if(counter)counter.textContent=String(body.querySelectorAll('.finding').length);
}
function render(d){
 const stamp=Date.parse(d.checked_at_utc||'');const age=Date.now()-stamp;
 if(d.schema!==1||d.kind!=='full_audit'||!Number.isFinite(stamp)||age< -60000||age>MAX_AGE
    || !Array.isArray(d.sections)||d.sections.length!==15||d.status!=='CURRENT'){
   status('Overdue — new check required','bad');counters(null);return;
 }
 status(`Checked ${time(stamp)}`, 'good');
 counters(d.totals);
 if(lastStamp===d.checked_at_utc)return;
 lastStamp=d.checked_at_utc;
 for(const s of d.sections){if(!Number.isInteger(s.number)||s.number<1||s.number>15)continue;
   const tile=$(`.tile[data-section="${s.number}"]`);
   if(tile){const sev=s.severity||{};const kind=sev.FAIL>0?'fail':sev.WARN>0?'warn':'normal';
     tile.classList.remove('warn','fail','normal');tile.classList.add(kind);
     const sub=tile.querySelector('.tile-sub'),badge=tile.querySelector('.tile-badge');
     if(sub)sub.textContent=sev.FAIL?`${sev.FAIL} failure(s)`:sev.WARN?`${sev.WARN} warning(s)`:sev.PASS?`${sev.PASS} passed`:'Information available';
     if(badge){badge.className=`tile-badge ${kind}`;badge.textContent=kind==='normal'?'VIEW':kind.toUpperCase();}
   }fillPanel(s);
 }
 findings(Array.isArray(d.findings)?d.findings:[]);
}
async function poll(){if(document.hidden||loading)return;loading=true;
 try{const res=await fetch('data.php?feed=full',{cache:'no-store',credentials:'same-origin',headers:{Accept:'application/json'}});
   if(!res.ok)throw Error('Audit HTTP '+res.status);render(await res.json());
 }catch{status('Checking / temporarily unavailable','bad');counters(null)}finally{loading=false;}
}
function start(){
 // Avoid presenting the old report's counts/timestamp before the first updated feed.
 status('Checking…');counters(null);findings([]);
 all('.tile-sub').forEach(x=>x.textContent='Checking…');
 all('.tile-badge').forEach(x=>x.textContent='…');
 poll();setInterval(poll,30000);
 document.addEventListener('visibilitychange',()=>{if(!document.hidden)poll();});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
})();
