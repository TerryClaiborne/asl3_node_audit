#!/usr/bin/env python3
"""On-demand service entrypoint for security monitoring and the full audit.

Security and full-audit failures are reported independently.
"""
from pathlib import Path
import subprocess,sys
APP=Path(__file__).resolve().parent.parent

def once():
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
    full=subprocess.run(['/usr/bin/python3',str(APP/'bin/full_audit.py'),'--once','--force'],env=env,timeout=260)
    if full.returncode:
        print('WARNING: Full audit refresh failed; previous result remains explicitly timestamped',file=sys.stderr)
    sec=subprocess.run(['/usr/bin/python3',str(APP/'bin/security_monitor.py')],env=env,timeout=600)
    if sec.returncode:
        print('WARNING: Critical security refresh failed; previous security result remains explicitly timestamped',file=sys.stderr)
    return 0 if full.returncode==0 and sec.returncode==0 else 3

if __name__=='__main__':
    try:raise SystemExit(once())
    except subprocess.TimeoutExpired:
        print('STOP: Monitor cycle timed out',file=sys.stderr);raise SystemExit(2)
