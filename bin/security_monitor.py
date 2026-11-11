#!/usr/bin/env python3
"""Critical security monitor, with bounded APT checks and sanitized private feeds.

Runs the critical collector; refreshes APT metadata only when overdue.
Never installs upgrades or modifies Apache configuration.
"""
from __future__ import annotations
import datetime as dt
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

APP = Path(__file__).resolve().parent.parent
RUN = APP / 'run'
FEED = RUN / 'web' / 'security-feed.json'
REFRESH_SECONDS = 6*3600
RETRY_SECONDS = 3600


def now():
    return dt.datetime.now(dt.timezone.utc)


def command(args, timeout):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C',
                               'PYTHONDONTWRITEBYTECODE':'1'})


def stamp_age(path):
    try:
        doc = json.loads(path.read_text())
        stamp = dt.datetime.fromisoformat(doc['apt_refreshed_at_utc'])
        if stamp.utcoffset() != dt.timedelta(0): return None
        age = (now()-stamp).total_seconds()
        return age if age >= 0 else None
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def need_apt_refresh():
    age = stamp_age(RUN/'apt-refresh.json')
    if age is not None and age < REFRESH_SECONDS: return False
    attempt = RUN/'.apt-attempt.json'
    try:
        d = json.loads(attempt.read_text())
        last = dt.datetime.fromisoformat(d['apt_refreshed_at_utc'])
        if (now()-last).total_seconds() < RETRY_SECONDS: return False
    except (OSError, KeyError, TypeError, ValueError):
        pass
    return True


def atomic_json(path, obj, mode):
    fd, tmp = tempfile.mkstemp(prefix='.security-', dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf8') as f:
            json.dump(obj,f,ensure_ascii=True,sort_keys=True,indent=2)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,mode)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def lan_ip():
    try:
        routes=(Path('/proc/net/route').read_text().splitlines())[1:]
        iface=None
        for line in routes:
            cols=line.split()
            if len(cols)>3 and cols[1]=='00000000' and int(cols[3],16)&1:
                if re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',cols[0]):
                    iface=cols[0]; break
        if not iface: return None
        res=command(['ip','-4','-o','address','show','dev',iface],8)
        if res.returncode: return None
        for s in res.stdout.splitlines():
            m=re.search(r'\binet\s+([0-9.]+)/\d+',s)
            if m:
                address=ipaddress.IPv4Address(m.group(1))
                if not (address.is_loopback or address.is_link_local or address.is_unspecified):
                    return str(address)
    except (OSError, ValueError, subprocess.TimeoutExpired): pass
    return None


def _curl_code(url):
    args=['curl','-sS','--noproxy','*','--connect-timeout','3','--max-time','8',
          '-A','ASL3-Node-Audit-SelfCheck/1',
          '-o','/dev/null','-w','%{http_code}']
    if url.startswith('https://'):
        args.append('-k')
    args.append(url)
    try:
        res=command(args,12)
        return res.stdout.strip() if res.returncode==0 else None
    except subprocess.TimeoutExpired:
        return None


def authorized():
    """Verify public-route behavior and that private application paths are not served."""
    try:
        cfg=APP/'config.ini'
        if cfg.is_symlink() or not cfg.is_file(): return False
        enabled=[m.group(1) for line in cfg.read_text(encoding='utf8').splitlines()
                 if (m:=re.fullmatch(r'\s*ASL3_NODE_AUDIT_AUTH_ENABLED\s*=\s*"?([01])"?\s*',line))]
        if len(enabled)!=1: return False
        # The signed-out dashboard remains view-only when application login is enabled,
        # so its read-only live/feed routes intentionally remain HTTP 200. Login protects
        # interactive detail access in the browser; private source/config/runtime paths
        # must still never be served directly.
        api_expected='200'

        # Prefer loopback HTTP because the Alias is global; fall back to local HTTPS.
        for base in ('http://127.0.0.1','https://127.0.0.1'):
            root=_curl_code(base+'/asl3_node_audit/')
            live=_curl_code(base+'/asl3_node_audit/live.php')
            if root!='200' or live!=api_expected:
                continue
            private_ok=True
            for suffix in ('config.ini','src/auth.php','run/web/security-feed.json'):
                code=_curl_code(base+'/asl3_node_audit/'+suffix)
                if code not in ('403','404'):
                    private_ok=False
                    break
            if private_ok:
                return True
        return False
    except (OSError,ValueError):
        return False


def snapshot_to_feed():
    from importlib.util import spec_from_file_location, module_from_spec
    # Reuse the validated critical snapshot reader, do not trust arbitrary JSON.
    runner = APP/'bin/monitor_runner.py'
    spec=spec_from_file_location('audit_runner',runner)
    if spec is None or spec.loader is None: raise RuntimeError('Runner validation unavailable')
    mod=module_from_spec(spec); spec.loader.exec_module(mod)
    state=mod.classify_snapshot(RUN/'latest-critical.json',max_age=150)
    if state['state'] not in ('CURRENT','STALE'):
        return {'schema':1,'state':'UNAVAILABLE','checked_at_utc':None,'apt_state':'UNVERIFIED',
                'security_count':None,'other_count':None,'security_packages':[],
                'alarm':'UNAVAILABLE','coverage':'PARTIAL','lan_ip':lan_ip(),
                'problem':{
                    'category':'SECURITY_COLLECTOR_UNAVAILABLE',
                    'summary':'The security collector did not produce a usable current snapshot.',
                    'impact':'Security-update status and critical-security checks cannot be treated as verified.',
                    'action':'Inspect the Node Audit service log and retry the monitor cycle.',
                    'verify':'sudo systemctl start asl3-node-audit.service && journalctl -u asl3-node-audit.service -n 100 --no-pager'
                },
                'message':'Security collector unavailable'}
    snap=json.loads((RUN/'latest-critical.json').read_text(encoding='utf8'))
    apt=snap.get('package_security_updates',{})
    apt_ok=(state.get('apt_security_state')=='CHECKED' and
            isinstance(apt.get('security_count'),int) and
            0<=apt['security_count']<=2000 and
            isinstance(apt.get('security_packages'),list) and
            len(apt['security_packages'])==apt['security_count'])
    packs=[]
    if apt_ok:
        for p in apt['security_packages']:
            if not all(isinstance(p.get(k),str) and len(p[k])<=128 for k in ('package','installed','candidate')):
                apt_ok=False; break
            packs.append({k:p[k] for k in ('package','installed','candidate')})
    problem=None
    if not apt_ok:
        raw_problem=apt.get('refresh_problem') if isinstance(apt.get('refresh_problem'),dict) else None
        if raw_problem:
            allowed=('category','summary','impact','action','verify','repository','checked_at_utc')
            problem={k:raw_problem[k] for k in allowed if isinstance(raw_problem.get(k),str)}
        else:
            problem={
                'category':'APT_SECURITY_UNVERIFIED',
                'summary':str(apt.get('reason') or 'Debian security-update status could not be verified.')[:700],
                'impact':'Security-update status cannot be treated as clean.',
                'action':'Run the APT verification command and correct any reported repository, network or package-metadata error.',
                'verify':'sudo apt-get -o APT::Update::Error-Mode=any update'
            }
    return {'schema':1,'state':state['state'],
            'checked_at_utc':snap['checked_at_utc'],
            'apt_state':'CHECKED' if apt_ok else 'UNVERIFIED',
            'security_count':apt['security_count'] if apt_ok else None,
            'other_count':apt.get('other_count') if apt_ok else None,
            'security_packages':packs if apt_ok else [],
            'apt_refreshed_at_utc':apt.get('apt_refreshed_at_utc') if apt_ok else None,
            'problem':problem,
            'alarm':state['alarm'],'coverage':'PARTIAL','lan_ip':lan_ip(),
            'message':'Critical-security monitoring only; full diagnostics run separately'}


def once():
    if os.geteuid()!=0: raise RuntimeError('Root required')
    if not APP.is_dir() or APP.is_symlink() or not RUN.is_dir():
        raise RuntimeError('Protected application state missing')
    if FEED.parent.is_symlink() or not FEED.parent.is_dir():
        raise RuntimeError('Protected feed directory missing')
    lock=RUN/'.security-cycle.lock'
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            print('SKIP: Another monitoring cycle is running');return 0
        if need_apt_refresh():
            atomic_json(RUN/'.apt-attempt.json',
                        {'apt_refreshed_at_utc':now().isoformat()},0o600)
            refresh=command(['python3',str(APP/'src/apt_security.py'),'--refresh'],330)
            if refresh.returncode:
                # apt_security.py emits only sanitized diagnostics; preserve them in the journal
                # so an operator sees the real cause without rerunning a separate command.
                detail=(refresh.stderr or refresh.stdout).strip()
                print('WARNING: APT refresh incomplete; Debian security-update status is not verified.',file=sys.stderr)
                if detail:
                    print(detail,file=sys.stderr)
        result=command(['python3',str(APP/'bin/monitor_runner.py'),'--once'],120)
        if result.returncode: print('WARNING: Security collector did not complete',file=sys.stderr)
        data=snapshot_to_feed()
        if not authorized():
            data['alarm']='TRIGGERED'
            data['alarm_problem']={
                'summary':'Node Audit dashboard/private-path self-check failed.',
                'impact':'The audit could not verify both the public dashboard route and protection of private application paths.',
                'action':'Inspect Apache configuration and the Node Audit Alias/access rules before exposing the dashboard beyond a trusted network.',
                'verify':'sudo apache2ctl configtest && curl -I http://127.0.0.1/asl3_node_audit/'
            }
            data['message']='Dashboard route/private-path verification needs attention'
            print('WARNING: Dashboard route/private-path verification failed',file=sys.stderr)
        if FEED.is_symlink(): raise RuntimeError('Unsafe private feed path')
        atomic_json(FEED,data,0o640)
        if data.get('apt_state')=='CHECKED':
            print('PASS: Security feed published securely:',data['state'],
                  data['apt_state'],data['security_count'])
        else:
            problem=data.get('problem') if isinstance(data.get('problem'),dict) else {}
            print('ATTENTION: Security feed published, but Debian security-update verification is incomplete.',file=sys.stderr)
            if problem.get('summary'):
                print('Reason:',problem['summary'],file=sys.stderr)
            if problem.get('repository'):
                print('Affected repository:',problem['repository'],file=sys.stderr)
            if problem.get('action'):
                print('Next:',problem['action'],file=sys.stderr)
            if problem.get('verify'):
                print('Verify:',problem['verify'],file=sys.stderr)
        return 0 if result.returncode==0 else 3
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


if __name__=='__main__':
    try: raise SystemExit(once())
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as e:
        print('STOP:',e,file=sys.stderr);raise SystemExit(2)
