#!/usr/bin/env python3
"""ASL3 Node Audit Debian APT security-update monitor (no package installs).

The collector never treats stale or failed APT metadata as a clean result.  When
an APT refresh fails, it records a sanitized diagnostic with the failure class,
affected repository host when identifiable, impact, next action and a command
the operator can use to verify the repair.
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
from urllib.parse import urlsplit

BASE = Path(__file__).resolve().parent.parent
RUN = BASE / 'run'
STAMP = RUN / 'apt-refresh.json'
PROBLEM = RUN / 'apt-refresh-problem.json'
RESULT = RUN / 'latest-apt-security.json'
MAX_AGE_SECONDS = 6 * 3600
MAX_LIST = 2000
PKG_NAME = re.compile(r'^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?$')
LINE = re.compile(r'^([^/\s]+)/([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[upgradable from: ([^\]]+)\]$')
URL = re.compile(r'https?://[^\s\]\)>,;]+', re.I)


def debian_codename() -> str | None:
    try:
        values = {}
        for line in Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            values[key] = value.strip().strip('"')
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
    except subprocess.TimeoutExpired:
        return 124, '', 'Command timed out'
    except OSError as exc:
        return 127, '', f'Could not execute command: {exc.__class__.__name__}'


def atomic_json(path: Path, obj: dict):
    RUN.mkdir(mode=0o700, exist_ok=True)
    if RUN.is_symlink():
        raise RuntimeError('Unsafe run directory')
    fd, tmp = tempfile.mkstemp(prefix='.apt-security-', dir=RUN)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(obj, f, indent=2, sort_keys=True)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,0o600)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_stamp():
    try:
        if STAMP.is_symlink() or STAMP.stat().st_size > 4096:
            return None
        doc = json.loads(STAMP.read_text(encoding='utf-8'))
        if doc.get('schema') != 1:
            return None
        val = dt.datetime.fromisoformat(doc['apt_refreshed_at_utc'])
        if val.tzinfo is None or val.utcoffset() != dt.timedelta(0):
            return None
        return val
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def load_problem() -> dict | None:
    try:
        if PROBLEM.is_symlink() or not PROBLEM.is_file() or PROBLEM.stat().st_size > 16384:
            return None
        d = json.loads(PROBLEM.read_text(encoding='utf-8'))
        required = ('category','summary','impact','action','verify')
        if d.get('schema') != 1 or any(not isinstance(d.get(k), str) for k in required):
            return None
        out = {k: d[k][:700] for k in required}
        repo = d.get('repository')
        if isinstance(repo, str) and re.fullmatch(r'[A-Za-z0-9.-]{1,253}', repo):
            out['repository'] = repo
        checked = d.get('checked_at_utc')
        if isinstance(checked, str):
            out['checked_at_utc'] = checked[:64]
        return out
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def parse_upgradable(output: str) -> dict:
    packages = {}
    for s in output.splitlines():
        s = s.strip()
        if not s or s.startswith('Listing') or s.startswith('WARNING:'):
            continue
        m = LINE.fullmatch(s)
        if not m or not PKG_NAME.fullmatch(m[1]):
            raise ValueError('Unrecognized APT upgradable entry: ' + s[:100])
        if m[1] in packages:
            raise ValueError('Duplicate APT package entry')
        packages[m[1]] = {'package': m[1], 'candidate': m[3], 'installed': m[5], 'sources': m[2]}
        if len(packages) > MAX_LIST:
            raise ValueError('Too many APT upgrade entries')
    return packages


def source_configured(policy: str, codename: str) -> bool:
    return security_release_pattern(codename).search(policy) is not None


def _repository_host(text: str) -> str | None:
    # Prefer URLs occurring on error/failure lines, then fall back to any URL.
    lines = [line for line in text.splitlines() if re.search(r'(^\s*Err:|Failed to fetch|signature|OpenPGP|Release file|404)', line, re.I)]
    for blob in ('\n'.join(lines), text):
        for raw in URL.findall(blob):
            try:
                host = urlsplit(raw.rstrip('.')).hostname
                if host and re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host):
                    return host.lower()
            except ValueError:
                pass
    return None


def classify_refresh_problem(output: str, rc: int) -> dict:
    """Turn noisy apt output into a safe, actionable diagnostic."""
    low = output.lower()
    repo = _repository_host(output)
    category = 'APT_REFRESH_FAILED'
    summary = 'APT package metadata refresh failed.'
    impact = 'Debian security-update status cannot be verified from current metadata.'
    action = 'Run the verification command below and correct the reported APT repository or network problem; do not disable signature verification.'

    if rc == 124 or 'command timed out' in low:
        category = 'APT_TIMEOUT'
        summary = 'APT package metadata refresh timed out.'
        action = 'Check network/repository responsiveness, then retry the APT metadata refresh.'
    elif re.search(r'could not get lock|unable to acquire.*lock|is another process using it', low):
        category = 'APT_LOCKED'
        summary = 'APT metadata refresh could not start because another package operation holds an APT/dpkg lock.'
        action = 'Let the existing package operation finish, then retry. Do not delete lock files while a package process is running.'
    elif re.search(r'signature verification|openpgp|\bsqv\b|no_pubkey|expkeysig|badsig|not bound|sha1 is not considered secure', low):
        category = 'REPOSITORY_SIGNATURE'
        if 'sha1 is not considered secure' in low or ('not bound' in low and 'sha1' in low):
            summary = 'APT repository signing key/certification was rejected because SHA-1 is no longer accepted by the current cryptographic policy.'
        elif 'no_pubkey' in low:
            summary = 'APT cannot verify a repository because its signing public key is not available.'
        elif 'expkeysig' in low or 'expired' in low:
            summary = 'APT repository signature verification failed because the signing key/signature is expired.'
        else:
            summary = 'APT repository signature verification failed.'
        action = 'Update or replace the affected repository signing key/keyring from the repository maintainer, then retry. Do not bypass APT signature checks.'
    elif re.search(r'temporary failure resolving|could not resolve|name or service not known|nodename nor servname', low):
        category = 'DNS_FAILURE'
        summary = 'APT could not resolve a repository hostname.'
        action = 'Check DNS and network connectivity, then retry the metadata refresh.'
    elif re.search(r'certificate verification failed|certificate.*not trusted|tls|ssl.*error', low):
        category = 'TLS_FAILURE'
        summary = 'APT could not verify or establish a TLS connection to a repository.'
        action = 'Check system time, CA certificates, HTTPS interception/proxy settings and the affected repository, then retry.'
    elif re.search(r'network is unreachable|connection timed out|could not connect|connection failed|connection refused', low):
        category = 'NETWORK_FAILURE'
        summary = 'APT could not reach a configured repository.'
        action = 'Check network connectivity and repository availability, then retry the metadata refresh.'
    elif re.search(r'does not have a release file|404 not found|repository .* is no longer signed|release file.*expired', low):
        category = 'REPOSITORY_CONFIGURATION'
        summary = 'A configured APT repository is unavailable or no longer valid for this system.'
        action = 'Review the affected repository configuration and distribution/suite with its maintainer documentation, then retry.'
    elif rc == 127:
        category = 'APT_EXECUTION'
        summary = 'The APT metadata refresh command could not be executed.'
        action = 'Verify apt-get is installed and executable, then retry.'

    problem = {
        'schema': 1,
        'checked_at_utc': utcnow().isoformat(timespec='seconds'),
        'category': category,
        'summary': summary,
        'impact': impact,
        'action': action,
        'verify': 'sudo apt-get -o APT::Update::Error-Mode=any update',
    }
    if repo:
        problem['repository'] = repo
    return problem


def collect(now=None, cmd=command, stamp_time=None) -> dict:
    now = now or utcnow()
    stamp_time = stamp_time if stamp_time is not None else load_stamp()
    result = {'schema':1, 'checked_at_utc':now.isoformat(timespec='seconds'),
              'apt_refreshed_at_utc':stamp_time.isoformat(timespec='seconds') if stamp_time else None,
              'refresh_age_s':None, 'status':'UNKNOWN', 'reason':'',
              'security_count':None, 'security_packages':[], 'other_count':None, 'other_packages':[],
              'classification':'APT ?security for upgrade candidates; Debian-Security origin verified',
              'coverage':'Debian/APT repositories only; third-party advisories not independently verified',
              'refresh_problem':None}
    if stamp_time:
        age = (now - stamp_time).total_seconds()
        if age >= 0:
            result['refresh_age_s'] = round(age)
    # An absent/stale stamp must NEVER imply a clean system.
    if stamp_time is None or result['refresh_age_s'] is None or result['refresh_age_s'] > MAX_AGE_SECONDS:
        problem = load_problem()
        result['refresh_problem'] = problem
        if problem:
            where = f" Affected repository: {problem['repository']}." if problem.get('repository') else ''
            result.update(status='STALE', reason=problem['summary'] + where)
        else:
            result.update(status='STALE', reason='APT metadata was not successfully refreshed by Node Audit within six hours.')
        return result
    codename = debian_codename()
    result['debian_codename'] = codename
    if codename is None:
        result.update(reason='Debian VERSION_CODENAME could not be verified')
        return result
    rc, policy, _ = cmd(['apt-cache','policy'],timeout=20)
    if rc != 0:
        result.update(reason='Unable to read APT repository policy')
        return result
    if not source_configured(policy, codename):
        result.update(reason=f'{codename}-security (Debian-Security) repository not verified in APT policy')
        return result
    rc, all_out, _ = cmd(['apt','list','--upgradable'],timeout=65)
    if rc != 0:
        result.update(reason='APT could not list available upgrades')
        return result
    rc, sec_out, _ = cmd(['apt','list','?upgradable ?security'],timeout=65)
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
        print('STOP: --refresh requires root; no APT lists updated.', file=sys.stderr)
        return False
    RUN.mkdir(mode=0o700,exist_ok=True)
    lock = RUN / '.apt-refresh.lock'
    fd = os.open(lock, os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            problem = {
                'schema':1,'checked_at_utc':utcnow().isoformat(timespec='seconds'),
                'category':'APT_LOCKED','summary':'APT metadata refresh is already running.',
                'impact':'Security-update status is not refreshed by this attempt.',
                'action':'Let the existing Node Audit/APT operation finish, then retry.',
                'verify':'sudo apt-get -o APT::Update::Error-Mode=any update'
            }
            atomic_json(PROBLEM, problem)
            print('UNKNOWN:', problem['summary'], file=sys.stderr)
            print('Next:', problem['action'], file=sys.stderr)
            return False
        print('Refreshing APT package metadata only; no packages will be installed.')
        rc, stdout, stderr = cmd(['apt-get','-o','APT::Update::Error-Mode=any','update'],timeout=300)
        combined = stdout + '\n' + stderr
        if rc != 0 or re.search(r'^\s*(Err:|W: Failed to fetch|W: Some index files failed)', combined, re.M):
            problem = classify_refresh_problem(combined, rc)
            atomic_json(PROBLEM, problem)
            print('UNKNOWN:', problem['summary'], file=sys.stderr)
            if problem.get('repository'):
                print('Affected repository:', problem['repository'], file=sys.stderr)
            print('Impact:', problem['impact'], file=sys.stderr)
            print('Next:', problem['action'], file=sys.stderr)
            print('Verify:', problem['verify'], file=sys.stderr)
            return False
        atomic_json(STAMP,{'schema':1,'apt_refreshed_at_utc':utcnow().isoformat(timespec='seconds')})
        try:
            PROBLEM.unlink(missing_ok=True)
        except OSError:
            pass
        print('PASS: Fresh APT metadata downloaded (no packages installed).')
        return True
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)


def print_summary(result: dict) -> int:
    if result.get('status') == 'CHECKED':
        print(f"CHECKED: {result['security_count']} Debian security update(s) pending; {result['other_count']} other upgrade(s).")
        print('Reason:', result.get('reason','Verified against refreshed APT metadata'))
        return 0
    print('UNVERIFIED:', result.get('reason') or 'Security-update status could not be verified.')
    problem = result.get('refresh_problem')
    if isinstance(problem, dict):
        if problem.get('repository'):
            print('Affected repository:', problem['repository'])
        print('Impact:', problem.get('impact','Security-update status cannot be trusted.'))
        print('Next:', problem.get('action','Inspect APT and retry.'))
        print('Verify:', problem.get('verify','sudo apt-get update'))
    else:
        print('Impact: Security-update status cannot be treated as clean.')
        print('Next: Run sudo apt-get update and correct any reported APT error.')
        print('Verify: sudo apt-get -o APT::Update::Error-Mode=any update')
    return 3


def self_test() -> None:
    cases = [
        ('OpenPGP signature verification failed: https://repo.example.invalid/dists/testing/InRelease sqv SHA1 is not considered secure', 100, 'REPOSITORY_SIGNATURE', 'repo.example.invalid'),
        ('Err:1 https://mirror.example.invalid stable InRelease Temporary failure resolving mirror.example.invalid', 100, 'DNS_FAILURE', 'mirror.example.invalid'),
        ('Failed to fetch https://secure.example.invalid/InRelease Certificate verification failed', 100, 'TLS_FAILURE', 'secure.example.invalid'),
        ('Failed to fetch http://down.example.invalid/InRelease Connection timed out', 100, 'NETWORK_FAILURE', 'down.example.invalid'),
        ('E: The repository http://old.example.invalid testing Release does not have a Release file.', 100, 'REPOSITORY_CONFIGURATION', 'old.example.invalid'),
    ]
    for text, rc, category, repo in cases:
        got = classify_refresh_problem(text, rc)
        assert got['category'] == category, (got, category)
        assert got.get('repository') == repo, (got, repo)
        assert 'verify' in got and 'action' in got and 'impact' in got
    print('PASS: APT refresh failure classification covers signature, DNS, TLS, network and repository configuration errors.')


def main():
    p = argparse.ArgumentParser(description='Debian security update monitor: metadata refresh only, no upgrades')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--refresh', action='store_true', help='Explicitly refresh APT metadata only; requires root')
    mode.add_argument('--check', action='store_true', help='Classify cached upgrades with freshness policy')
    mode.add_argument('--summary', action='store_true', help='Print the current security-update classification and actionable reason')
    mode.add_argument('--self-test', action='store_true', help='Run isolated failure-classification tests')
    a = p.parse_args()
    if a.self_test:
        self_test(); return 0
    if a.refresh and not refresh():
        return 2
    result = collect()
    if a.summary:
        return print_summary(result)
    if a.check:
        print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result['status']=='CHECKED' else 3


if __name__ == '__main__':
    raise SystemExit(main())
