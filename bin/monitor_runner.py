#!/usr/bin/env python3
"""ASL3 Node Audit single-flight structured critical-security runner."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / 'run'
ENGINE = ROOT / 'src' / 'monitor_engine.py'
SNAPSHOT = STATE / 'latest-critical.json'
MAX_FILE_BYTES = 524288
ALLOWED = frozenset(('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP', 'UNKNOWN'))


def classify_snapshot(path: Path, max_age: int, now: dt.datetime | None = None) -> dict:
    """Classify snapshot without ever turning missing, stale or partial into ALL CLEAR."""
    out = {'state': 'UNAVAILABLE', 'coverage': 'UNKNOWN', 'health': 'UNKNOWN',
           'alarm': 'UNAVAILABLE', 'age_s': None, 'reason': 'No verified snapshot'}
    if max_age < 1 or max_age > 86400:
        out['reason'] = 'Invalid freshness policy'
        return out
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError('Missing, symlinked, or oversized snapshot')
        with path.open('r', encoding='utf8') as stream:
            snap = json.load(stream)
        if snap.get('schema') != 1 or snap.get('profile') != 'critical_security':
            raise ValueError('Unexpected schema/profile')
        checks = snap.get('checks')
        if not isinstance(checks, list) or not 1 <= len(checks) <= 256:
            raise ValueError('Invalid checks')
        counts = {key: 0 for key in ALLOWED}
        alarms = False
        for item in checks:
            if not isinstance(item, dict) or item.get('status') not in ALLOWED:
                raise ValueError('Invalid item status')
            if not isinstance(item.get('security_alarm'), bool):
                raise ValueError('Invalid alarm field')
            counts[item['status']] += 1
            alarms |= item['status'] == 'FAIL' and item['security_alarm']
        if not isinstance(snap.get('counts'), dict):
            raise ValueError('Missing count totals')
        for key, n in counts.items():
            if snap['counts'].get(key, 0) != n:
                raise ValueError('Count mismatch')
        if snap.get('security_alarm') is not alarms:
            raise ValueError('Alarm mismatch')
        stamp = dt.datetime.fromisoformat(snap['checked_at_utc'])
        if stamp.tzinfo is None or stamp.utcoffset() != dt.timedelta(0):
            raise ValueError('Timestamp not UTC')
        now = now or dt.datetime.now(dt.timezone.utc)
        age = (now - stamp).total_seconds()
        if age < -30:
            raise ValueError('Snapshot timestamp is in future')
        aptdata = snap.get('package_security_updates', {})
        apt = aptdata.get('status', 'NOT_CHECKED')
        if apt == 'CHECKED' and (not isinstance(aptdata.get('security_count'), int)
                                 or aptdata.get('security_count') < 0):
            raise ValueError('Invalid APT security update count')
        # Require a Debian security check entry when reporting complete APT checking.
        if apt == 'CHECKED' and not any(item.get('id') == 'debian.security-updates' for item in checks):
            raise ValueError('APT checked without corresponding security finding')
        out.update(state='CURRENT' if age <= max_age else 'STALE',
                   coverage='PARTIAL',  # Critical-security subset; the 15-section audit runs separately.
                   apt_security_state=apt,
                   apt_security_pending=aptdata.get('security_count') if apt == 'CHECKED' else None,
                   health='FAIL' if counts['FAIL'] else ('WARN' if counts['WARN'] else ('UNKNOWN' if counts['UNKNOWN'] else 'PASS')),
                   alarm='TRIGGERED' if alarms else 'CLEAR_FOR_CHECKED_SCOPE',
                   age_s=max(0, round(age)),
                   reason=('Critical-security subset; Debian APT ' + apt.lower() + '; full audit runs separately'))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        out['reason'] = str(exc)
    return out


def run_once(timeout: int) -> int:
    if os.geteuid() != 0:
        print('STOP: Must run as root for complete checks', file=sys.stderr)
        return 2
    if not ENGINE.is_file() or ENGINE.is_symlink():
        print('STOP: Security collector missing', file=sys.stderr)
        return 2
    if not STATE.is_dir() or STATE.is_symlink():
        print('STOP: State directory missing or unsafe', file=sys.stderr)
        return 2
    lock_path = STATE / '.critical.lock'
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        print(f'STOP: Cannot acquire lock file: {exc}', file=sys.stderr)
        return 2
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('SKIP: A critical-security collection is already running')
            return 0
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
        try:
            child = subprocess.run([sys.executable, str(ENGINE)], cwd=str(ROOT),
                                   env=env, timeout=timeout, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            print('UNKNOWN: Critical-security collector timed out', file=sys.stderr)
            return 2
        if child.returncode:
            print('UNKNOWN: Collector failed without updating a verified snapshot', file=sys.stderr)
            return 2
        status = classify_snapshot(SNAPSHOT, max_age=120)
        if status['state'] != 'CURRENT':
            print('UNKNOWN: Collector returned but no current verified snapshot exists', file=sys.stderr)
            return 2
        print('PASS: Security collector completed; JSON schema and freshness verified')
        print('STATUS:', json.dumps(status, sort_keys=True))
        return 0
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description='Structured critical-security runner; no package installation or service changes')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--once', action='store_true', help='Run one bounded critical-security collection')
    group.add_argument('--status', action='store_true', help='Read and classify the current security snapshot')
    group.add_argument('--self-test', action='store_true', help='Run isolated JSON classification tests')
    parser.add_argument('--max-age', type=int, default=120)
    args = parser.parse_args()
    if args.once:
        return run_once(timeout=90)
    if args.status:
        print(json.dumps(classify_snapshot(SNAPSHOT, args.max_age), indent=2, sort_keys=True))
        return 0
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix='asl3-monitor-test-') as tmp:
        p = Path(tmp) / 'snapshot.json'
        now = dt.datetime(2026, 10, 24, 16, 0, tzinfo=dt.timezone.utc)
        data = {'schema': 1, 'profile': 'critical_security', 'checked_at_utc': now.isoformat(),
                'counts': {'PASS': 1, 'WARN': 0, 'FAIL': 0, 'INFO': 0, 'UNKNOWN': 0},
                'checks': [{'status': 'PASS', 'security_alarm': False}],
                'security_alarm': False, 'package_security_updates': {'status': 'NOT_CHECKED'}}
        assert classify_snapshot(p, 120, now)['state'] == 'UNAVAILABLE'
        p.write_text(json.dumps(data), encoding='utf8')
        assert classify_snapshot(p, 120, now)['state'] == 'CURRENT'
        assert classify_snapshot(p, 120, now)['coverage'] == 'PARTIAL'
        assert classify_snapshot(p, 120, now + dt.timedelta(seconds=121))['state'] == 'STALE'
        data['security_alarm'] = True
        p.write_text(json.dumps(data), encoding='utf8')
        assert classify_snapshot(p, 120, now)['state'] == 'UNAVAILABLE'
        p.write_text('{invalid', encoding='utf8')
        assert classify_snapshot(p, 120, now)['state'] == 'UNAVAILABLE'
        print('PASS: Missing, current, partial, stale, mismatched-alarm, and malformed JSON classified safely')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
