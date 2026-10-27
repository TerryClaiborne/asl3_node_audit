(()=>{'use strict';
const q=s=>document.querySelector(s),qa=s=>[...document.querySelectorAll(s)];
const tiles=qa('.tile'),panels=qa('.detailpanel'),modal=q('#detail-area'),backdrop=q('#detail-backdrop');
const viewOnly=document.body?.dataset.viewOnly==='1';
let lastFocus=null;
if(viewOnly){
 tiles.forEach(t=>{t.disabled=true;t.setAttribute('aria-expanded','false')});
 qa('.finding').forEach(b=>b.disabled=true);
 const findingsToggle=q('#toggle-findings');if(findingsToggle)findingsToggle.disabled=true;
 const search=q('#search');if(search){search.disabled=true;search.setAttribute('aria-disabled','true')}
}
function close(){tiles.forEach(t=>t.setAttribute('aria-expanded','false'));panels.forEach(p=>p.hidden=true);if(modal)modal.hidden=true;if(backdrop)backdrop.hidden=true;document.body.classList.remove('modal-open');if(lastFocus?.isConnected)lastFocus.focus();lastFocus=null}
function open(n){if(viewOnly)return;const tile=tiles.find(t=>t.dataset.section===String(n)),panel=q('#detail-'+n);if(!tile||!panel)return;lastFocus=document.activeElement;tiles.forEach(t=>t.setAttribute('aria-expanded',String(t===tile)));panels.forEach(p=>p.hidden=p!==panel);modal.hidden=false;backdrop.hidden=false;document.body.classList.add('modal-open');const content=panel.querySelector('.detail-rows');if(content)content.scrollTop=0;panel.querySelector('.detail-close')?.focus()}
if(!viewOnly)tiles.forEach(t=>t.addEventListener('click',()=>open(t.dataset.section)));
if(!viewOnly)qa('.finding').forEach(b=>b.addEventListener('click',()=>open(b.dataset.openSection)));
qa('.detail-close').forEach(b=>b.addEventListener('click',close));backdrop?.addEventListener('click',close);
document.addEventListener('keydown',e=>{if(modal?.hidden)return;if(e.key==='Escape'){e.preventDefault();close()}if(e.key==='Tab'){const focusables=qa('.detailpanel:not([hidden]) button:not([disabled]), .detailpanel:not([hidden]) a[href]');if(!focusables.length)return;const first=focusables[0],last=focusables[focusables.length-1];if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus()}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}}});
if(!viewOnly)q('#toggle-findings')?.addEventListener('click',e=>{const body=q('#findings-body'),button=e.currentTarget;body.hidden=!body.hidden;button.setAttribute('aria-expanded',String(!body.hidden))});
if(!viewOnly)q('#search')?.addEventListener('input',e=>{const term=e.target.value.toLowerCase().trim();tiles.forEach(t=>{const panel=q('#detail-'+t.dataset.section);t.hidden=!!term&&!((t.textContent+' '+(panel?.textContent||'')).toLowerCase().includes(term))});if(!modal?.hidden){const active=tiles.find(t=>t.getAttribute('aria-expanded')==='true');if(active?.hidden)close()}});
q('#theme')?.addEventListener('click',()=>document.documentElement.classList.toggle('light'));
})();

// Live system metrics: no root commands; five-second steady polling.
// Successful live polling uses the existing Apache 200-only log filter.
// Unsuccessful HTTP responses remain recorded by the server.
(()=>{
const $=id=>document.getElementById(id);
if(!$('system-strip'))return;
const put=(id,v)=>{const e=$(id);if(e)e.textContent=v};
const stamp=()=>put('live-time',new Intl.DateTimeFormat(undefined,{hour:'numeric',minute:'2-digit',second:'2-digit'}).format(new Date()));
let prev=null,prevNet=null,failures=0,inFlight=false;
const speed=bps=>{if(!Number.isFinite(bps)||bps<0)return '—';if(bps>=1048576)return (bps/1048576).toFixed(2)+' MB/s';if(bps>=1024)return (bps/1024).toFixed(1)+' KB/s';return Math.round(bps)+' B/s'};
const fetchMetrics=async()=>{
 if(document.hidden||inFlight)return;
 inFlight=true;
 try{
  const res=await fetch('live.php',{cache:'no-store',credentials:'same-origin',headers:{Accept:'application/json'}});
  if(!res.ok)throw Error('HTTP '+res.status);
  const j=await res.json();
  if(j.cpu && prev){const total=j.cpu.total-prev.total,idle=j.cpu.idle-prev.idle;if(total>0&&idle>=0)put('live-cpu',Math.max(0,Math.min(100,Math.round(100*(1-idle/total))))+'%');}
  if(j.cpu)prev=j.cpu;
  put('live-ram',Number.isFinite(j.ram_pct)?j.ram_pct+'%':'—');
  put('live-ram-detail',Number.isFinite(j.ram_used_mib)&&Number.isFinite(j.ram_total_mib)?j.ram_used_mib+' / '+j.ram_total_mib+' MB':'');
  if(j.net && prevNet){const d=(performance.now()-prevNet.at)/1000;if(d>0){put('live-net-up',speed((j.net.tx-prevNet.tx)/d));put('live-net-down',speed((j.net.rx-prevNet.rx)/d));}}
  prevNet=j.net?{...j.net,at:performance.now()}:null;
  put('live-temp',Number.isFinite(j.temp_f)?j.temp_f.toFixed(1)+'°F':'—');
  put('live-disk',Number.isFinite(j.disk_pct)?j.disk_pct+'%':'—');
  put('live-load',Number.isFinite(j.load_1m)?j.load_1m.toFixed(2):'—');
  if(Number.isFinite(j.uptime_s)){const m=Math.floor(j.uptime_s/60);put('live-uptime',(Math.floor(m/1440)?Math.floor(m/1440)+'d ':'')+Math.floor(m%1440/60)+'h '+m%60+'m');}
  failures=0;
 }catch(err){failures++;if($('live-status'))$('live-status').textContent='Live readings unavailable';}finally{inFlight=false;}
};
stamp();setInterval(stamp,1000);fetchMetrics();setTimeout(fetchMetrics,1000);setInterval(fetchMetrics,5000);
})();

// GitHub release check. Failure is silent and never affects dashboard operation.
(()=>{'use strict';
function parseVersion(value){const m=String(value||'').trim().match(/^v?(\d+)\.(\d+)\.(\d+)/i);return m?[Number(m[1]),Number(m[2]),Number(m[3])]:null}
function newer(remote,local){const a=parseVersion(remote),b=parseVersion(local);if(!a||!b)return false;for(let i=0;i<3;i++){if(a[i]!==b[i])return a[i]>b[i]}return false}
async function check(){const brand=document.getElementById('branding-title');if(!brand)return;const local=String(brand.dataset.localVersion||'').trim(),url=String(brand.dataset.versionUrl||'').trim();if(local)brand.title=`ASL3 Node Audit v${local}`;if(!local||!url)return;try{const r=await fetch(url,{method:'GET',cache:'no-store'});if(!r.ok)return;const remote=String(await r.text()).trim();if(newer(remote,local)){brand.classList.add('has-update');brand.title=`ASL3 Node Audit v${local} → v${remote} update available`;brand.setAttribute('aria-label',`Open the ASL3 Node Audit repository. Update available from version ${local} to ${remote}.`)}else{brand.classList.remove('has-update');brand.title=`ASL3 Node Audit v${local}`;brand.setAttribute('aria-label','Open the ASL3 Node Audit repository')}}catch(e){}}
check();
})();

// Request a full audit immediately when the dashboard opens, then every
// five minutes while the page remains open, including while it is hidden.
// refresh.php enforces the same five-minute gate globally across browser windows.
(()=>{
'use strict';
const token=document.body?.dataset.auditCsrf;
if(!token)return;

let forceFirst=document.body?.dataset.forceAudit==='1';
const ATTEMPT_INTERVAL=5*60*1000;
let lastAttempt=0;
let inFlight=false;

function requestAudit(force=false){
 const now=Date.now();
 if(inFlight)return;
 if(!force&&lastAttempt&&now-lastAttempt<ATTEMPT_INTERVAL)return;
 lastAttempt=now;
 inFlight=true;

 const body=new URLSearchParams();
 body.set('csrf',token);
 if(forceFirst){body.set('force','1');forceFirst=false;}

 fetch('refresh.php',{
  method:'POST',
  cache:'no-store',
  credentials:'same-origin',
  headers:{
   'Accept':'application/json',
   'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'
  },
  body:body.toString()
 }).then(async res=>{
  let data={ok:false,queued:false};
  try{data=await res.json()}catch(e){}
  window.dispatchEvent(new CustomEvent('asl3-audit-request',{detail:data}));
 }).catch(()=>{
  window.dispatchEvent(new CustomEvent('asl3-audit-request',{detail:{ok:false,queued:false}}));
 }).finally(()=>{inFlight=false});
}

requestAudit(true);
setInterval(requestAudit,ATTEMPT_INTERVAL);
document.addEventListener('visibilitychange',()=>{
 if(!document.hidden)requestAudit();
});
})();
