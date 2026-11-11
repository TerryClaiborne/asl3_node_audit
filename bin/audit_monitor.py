#!/usr/bin/env python3
"""On-demand service entrypoint for full audit and Debian security monitoring.

Writes a sanitized root-owned state feed so the browser reports actual service
state instead of inferring RUNNING from a request alone.
"""
from __future__ import annotations
from pathlib import Path
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile

APP=Path(__file__).resolve().parent.parent
STATE=APP/'run/web/audit-state.json'


def utc(): return dt.datetime.now(dt.timezone.utc)


def write_state(state:str, phase:str, started:dt.datetime, *, full_done:dt.datetime|None=None,
                completed:dt.datetime|None=None, message:str='') -> None:
    data={'schema':1,'kind':'audit_state','state':state,'phase':phase,
          'started_at_utc':started.isoformat(),'checked_at_utc':utc().isoformat()}
    if full_done is not None:data['full_completed_at_utc']=full_done.isoformat()
    if completed is not None:data['completed_at_utc']=completed.isoformat()
    if message:data['message']=message[:300]
    payload=(json.dumps(data,separators=(',',':'),ensure_ascii=True)+'\n').encode()
    STATE.parent.mkdir(parents=True,exist_ok=True)
    if STATE.is_symlink():raise RuntimeError('Unsafe audit-state symlink')
    fd,tmp=tempfile.mkstemp(prefix='.audit-state-',dir=STATE.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(payload);f.flush();os.fsync(f.fileno())
        os.chmod(tmp,0o640);os.replace(tmp,STATE)
        os.chown(STATE,0,-1)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def once():
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
    started=utc();full_done=None
    write_state('RUNNING','full_audit',started)
    try:
        full=subprocess.run(['/usr/bin/python3',str(APP/'bin/full_audit.py'),'--once','--force'],env=env,timeout=260)
        full_done=utc()
        if full.returncode:
            print('WARNING: Full audit refresh failed; previous result remains explicitly timestamped',file=sys.stderr)
        write_state('RUNNING','security',started,full_done=full_done,
                    message='Full audit failed; previous completed snapshot retained.' if full.returncode else '')
        sec=subprocess.run(['/usr/bin/python3',str(APP/'bin/security_monitor.py')],env=env,timeout=600)
        if sec.returncode:
            print('WARNING: Critical security refresh failed; previous security result remains explicitly timestamped',file=sys.stderr)
        completed=utc()
        if full.returncode==0 and sec.returncode==0:
            write_state('COMPLETE','done',started,full_done=full_done,completed=completed)
            return 0
        problems=[]
        if full.returncode:problems.append('Full audit refresh failed')
        if sec.returncode:problems.append('Security refresh failed')
        write_state('FAILED','done',started,full_done=full_done,completed=completed,message='; '.join(problems)+'. Previous completed feeds retained.')
        return 3
    except subprocess.TimeoutExpired as e:
        completed=utc();phase='full_audit' if full_done is None else 'security'
        msg=f'{phase.replace("_"," ").title()} exceeded its time limit; previous completed feed retained.'
        write_state('FAILED',phase,started,full_done=full_done,completed=completed,message=msg)
        print('STOP: Monitor cycle timed out during',phase,file=sys.stderr)
        return 2
    except Exception as e:
        try:write_state('FAILED','internal',started,full_done=full_done,completed=utc(),message='Audit monitor internal failure; previous completed feeds retained.')
        except Exception:pass
        print('STOP: Audit monitor internal failure:',type(e).__name__,file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(once())
