#!/usr/bin/env python3
"""ASL3 Node Audit Debian APT security-update monitor (no package installs).

--refresh explicitly runs apt-get update, updating APT *metadata only*.
--check uses the last successful update by this component; errors/stale never mean zero.
"""
from __future__ import annotations
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

BASE = Path(__file__).resolve().parent.parent
RUN = BASE / 'run'
STAMP = RUN / 'apt-refresh.json'
RESULT = RUN / 'latest-apt-security.json'
MAX_AGE_SECONDS = 6 * 3600
MAX_LIST = 2000
PKG_NAME = re.compile(r'^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?$')
LINE = re.compile(r'^([^/\s]+)/([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[upgradable from: ([^\]]+)\]$')


def debian_codename() -> str | None:
    try:
        values = {}
        for line in Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            values[key] = value.strip().strip('\"')
        if values.get('ID') != 'debian':
            return None
        codename = values.get('VERSION_CODENAME', '')
        return codename if re.fullmatch(r'[a-z0-9][a-z0-9-]{1,31}', codename) else None
    except OSError:
        return None

def security_release_pattern(codename: str) -> re.Pattern[str]:
    suite = re.escape(codename + '-security')
    return re.compile(r'\brelease\s+[^\n]*\bo=Debian\b[^\n]*\bn=' + suite + r'\b[^\n]*\bl=Debian-Security\b')

def utcnow():
    return dt.datetime.now(dt.timezone.utc)

def command(argv, timeout=50):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, 'LC_ALL':'C', 'DEBIAN_FRONTEND':'noninteractive'})
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired):
        return 127, '', 'Could not execute command or timed out'

def atomic_json(path: Path, obj: dict):
    RUN.mkdir(mode=0o700, exist_ok=True)
    if RUN.is_symlink(): raise RuntimeError('Unsafe run directory')
    fd, tmp = tempfile.mkstemp(prefix='.apt-security-', dir=RUN)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(obj, f, indent=2, sort_keys=True)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,0o600)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def load_stamp():
    try:
        if STAMP.is_symlink() or STAMP.stat().st_size > 4096: return None
        doc = json.loads(STAMP.read_text(encoding='utf-8'))
        if doc.get('schema') != 1: return None
        val = dt.datetime.fromisoformat(doc['apt_refreshed_at_utc'])
        if val.tzinfo is None or val.utcoffset() != dt.timedelta(0): return None
        return val
    except (OSError, ValueError, KeyError, TypeError):
        return None

def parse_upgradable(output: str) -> dict:
    packages = {}
    for s in output.splitlines():
        s = s.strip()
        if not s or s.startswith('Listing') or s.startswith('WARNING:'): continue
        m = LINE.fullmatch(s)
        if not m or not PKG_NAME.fullmatch(m[1]):
            raise ValueError('Unrecognized APT upgradable entry: ' + s[:100])
        if m[1] in packages: raise ValueError('Duplicate APT package entry')
        packages[m[1]] = {'package': m[1], 'candidate': m[3], 'installed': m[5], 'sources': m[2]}
        if len(packages) > MAX_LIST: raise ValueError('Too many APT upgrade entries')
    return packages

def source_configured(policy: str, codename: str) -> bool:
    return security_release_pattern(codename).search(policy) is not None

def collect(now=None, cmd=command, stamp_time=None) -> dict:
    now = now or utcnow()
    stamp_time = stamp_time if stamp_time is not None else load_stamp()
    result = {'schema':1, 'checked_at_utc':now.isoformat(timespec='seconds'),
              'apt_refreshed_at_utc':stamp_time.isoformat(timespec='seconds') if stamp_time else None,
              'refresh_age_s':None, 'status':'UNKNOWN', 'reason':'',
              'security_count':None, 'security_packages':[], 'other_count':None, 'other_packages':[],
              'classification':'APT ?security for upgrade candidates; Debian-Security origin verified',
              'coverage':'Debian/APT repositories only; third-party advisories not independently verified'}
    if stamp_time:
        age = (now - stamp_time).total_seconds()
        if age >= 0: result['refresh_age_s'] = round(age)
    # An absent/stale stamp must NEVER imply a clean system.
    if stamp_time is None or result['refresh_age_s'] is None or result['refresh_age_s'] > MAX_AGE_SECONDS:
        result.update(status='STALE', reason='APT metadata was not successfully refreshed by Node Audit within six hours.')
        return result
    codename = debian_codename()
    result['debian_codename'] = codename
    if codename is None:
        result.update(reason='Debian VERSION_CODENAME could not be verified')
        return result
    rc, policy, err = cmd(['apt-cache','policy'],timeout=20)
    if rc != 0:
        result.update(reason='Unable to read APT repository policy')
        return result
    if not source_configured(policy, codename):
        result.update(reason=f'{codename}-security (Debian-Security) repository not verified in APT policy')
        return result
    rc, all_out, err = cmd(['apt','list','--upgradable'],timeout=65)
    if rc != 0:
        result.update(reason='APT could not list available upgrades')
        return result
    rc, sec_out, err = cmd(['apt','list','?upgradable ?security'],timeout=65)
    if rc != 0:
        result.update(reason='APT ?security query unsupported or failed')
        return result
    try:
        all_p = parse_upgradable(all_out)
        sec_p = parse_upgradable(sec_out)
    except ValueError:
        result.update(reason='APT output was not in the expected format; refusing to report zero')
        return result
    if not sec_p.keys() <= all_p.keys():
        result.update(reason='Security upgrade query inconsistent with all upgrades')
        return result
    result.update(status='CHECKED', reason='Verified against refreshed APT metadata',
                  security_count=len(sec_p), other_count=len(all_p)-len(sec_p),
                  security_packages=[sec_p[n] for n in sorted(sec_p)],
                  other_packages=[all_p[n] for n in sorted(all_p) if n not in sec_p])
    return result

def refresh(cmd=command) -> bool:
    if os.geteuid() != 0:
        print('STOP: --refresh requires root; no APT lists updated.', file=sys.stderr); return False
    RUN.mkdir(mode=0o700,exist_ok=True)
    lock = RUN / '.apt-refresh.lock'
    fd = os.open(lock, os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            print('STOP: Node Audit APT metadata refresh already running',file=sys.stderr);return False
        print('Refreshing APT package metadata only; no packages will be installed.')
        rc, stdout, stderr = cmd(['apt-get','-o','APT::Update::Error-Mode=any','update'],timeout=300)
        combined = stdout + '\n' + stderr
        if rc != 0 or re.search(r'^\s*(Err:|W: Failed to fetch|W: Some index files failed)', combined, re.M):
            print('UNKNOWN: APT metadata refresh incomplete/failed; last successful timestamp unchanged.',file=sys.stderr)
            print('Inspect manually: sudo apt-get update',file=sys.stderr)
            return False
        atomic_json(STAMP,{'schema':1,'apt_refreshed_at_utc':utcnow().isoformat(timespec='seconds')})
        print('PASS: Fresh APT metadata downloaded (no packages installed).')
        return True
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def main():
    p = argparse.ArgumentParser(description='Debian security update monitor: metadata refresh only, no upgrades')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--refresh', action='store_true', help='Explicitly refresh APT metadata only; requires root')
    mode.add_argument('--check', action='store_true', help='Classify cached upgrades with freshness policy')
    a = p.parse_args()
    if a.refresh and not refresh(): return 2
    result = collect()
    atomic_json(RESULT, result)
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result['status']=='CHECKED' else 3

if __name__ == '__main__':
    raise SystemExit(main())
