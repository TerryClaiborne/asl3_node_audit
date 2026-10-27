#!/usr/bin/env python3
"""Bounded critical-security collector for ASL3 Node Audit."""
import datetime as dt
import json
import os
from pathlib import Path
from apt_security import collect as collect_apt
import shutil
import stat
import subprocess
import tempfile

BASE = Path(__file__).resolve().parent.parent
OUTDIR = BASE / 'run'
checks = []

def run(*args, timeout=6):
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout,
                           env={**os.environ, 'LC_ALL': 'C'})
        return p.returncode, (p.stdout + '\n' + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return 127, ''

def add(key, name, status, detail, *, alarm=False):
    checks.append(dict(id=key, name=name, status=status, detail=detail,
                       security_alarm=bool(alarm and status == 'FAIL')))

def service(unit, title, security=False):
    code, loaded = run('systemctl', 'show', '--property=LoadState', '--value', unit)
    if code != 0 or loaded != 'loaded':
        add(unit, title, 'UNKNOWN', 'Service not installed or status could not be established.')
        return
    _, active = run('systemctl', 'is-active', unit)
    _, enabled = run('systemctl', 'is-enabled', unit)
    active = active.splitlines()[0] if active else 'unknown'
    enabled = enabled.splitlines()[0] if enabled else 'unknown'
    if active == 'active':
        add(unit, title, 'PASS', 'Active (startup: %s).' % enabled)
    elif enabled == 'enabled' and security:
        add(unit, title, 'FAIL', 'Enabled protection service is %s.' % active, alarm=True)
    elif enabled == 'enabled':
        add(unit, title, 'WARN', 'Enabled service is %s.' % active)
    else:
        add(unit, title, 'INFO', 'Not active (startup: %s); may be intentional.' % enabled)

if os.geteuid() != 0:
    raise SystemExit('STOP: Security collector requires root for reliable checks.')

service('fail2ban.service', 'Fail2Ban protection', security=True)
service('firewalld.service', 'Firewalld protection', security=True)
service('apache2.service', 'Apache web service')
service('asterisk.service', 'Asterisk service')

manager = Path('/etc/asterisk/manager.conf')
try:
    mode = stat.S_IMODE(manager.stat().st_mode)
    rc, sockets = run('ss', '-H', '-l', '-t', '-n')
    ami_listening = False
    ami_wildcard = False
    if rc == 0:
        for line in sockets.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[3]
            if local.endswith(':5038'):
                ami_listening = True
                if local.startswith('0.0.0.0:') or local.startswith('*:') or local.startswith('[::]:'):
                    ami_wildcard = True
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        add('asterisk.manager.perms', 'Asterisk manager.conf permissions', 'WARN',
            f'Mode {mode:04o} permits group/other write access; review ownership and write permissions carefully.')
    elif mode & stat.S_IROTH:
        if ami_wildcard:
            add('asterisk.manager.perms', 'Asterisk manager.conf permissions', 'WARN',
                f'Mode {mode:04o} permits local-user read access and AMI is wildcard-bound. File readability is local filesystem exposure; assess AMI network exposure separately.')
        elif rc == 0:
            detail = (f'Mode {mode:04o} permits local-user read access. ' +
                      ('AMI is listening but not wildcard-bound.' if ami_listening else 'No AMI TCP/5038 listener was observed.') +
                      ' This is not direct LAN/Internet exposure by itself.')
            add('asterisk.manager.perms', 'Asterisk manager.conf permissions', 'INFO', detail)
        else:
            add('asterisk.manager.perms', 'Asterisk manager.conf permissions', 'INFO',
                f'Mode {mode:04o} permits local-user read access; AMI network exposure could not be checked.')
    else:
        add('asterisk.manager.perms', 'Asterisk manager.conf permissions', 'PASS',
            f'Mode {mode:04o} does not permit other-user read access.')
except OSError:
    add('asterisk.manager.perms', 'Asterisk manager.conf permissions', 'UNKNOWN',
        'Could not inspect file permissions.')

sshd = shutil.which('sshd') or '/usr/sbin/sshd'
if Path(sshd).is_file():
    rc, result = run(sshd, '-T')
    if rc == 0:
        settings = {}
        for line in result.splitlines():
            words = line.split(None, 1)
            if len(words) == 2:
                settings[words[0].lower()] = words[1].lower()
        empty = settings.get('permitemptypasswords')
        root = settings.get('permitrootlogin')
        if empty == 'yes':
            add('ssh.empty', 'SSH empty passwords', 'FAIL', 'Effective SSH configuration permits empty passwords.', alarm=True)
        elif empty == 'no':
            add('ssh.empty', 'SSH empty passwords', 'PASS', 'Empty passwords are not permitted.')
        else:
            add('ssh.empty', 'SSH empty passwords', 'UNKNOWN', 'Effective value not available.')
        if root == 'yes':
            add('ssh.root', 'SSH root login', 'WARN', 'Effective configuration permits root login; check authentication methods.')
        elif root:
            add('ssh.root', 'SSH root login', 'INFO', 'Effective PermitRootLogin setting: ' + root)
        else:
            add('ssh.root', 'SSH root login', 'UNKNOWN', 'Effective setting not available.')
    else:
        add('ssh.settings', 'SSH security settings', 'UNKNOWN', 'Unable to obtain effective sshd configuration.')
else:
    add('ssh.settings', 'SSH security settings', 'UNKNOWN', 'sshd executable not found.')

if shutil.which('apache2ctl'):
    rc, _ = run('apache2ctl', 'configtest', timeout=10)
    add('apache.syntax', 'Apache configuration syntax', 'PASS' if rc == 0 else 'WARN',
        'Syntax OK.' if rc == 0 else 'Configuration validation failed or timed out; run sudo apache2ctl configtest.')

# Debian security updates: read-only classification. APT metadata refresh is a
# separate, explicit, root-run operation; unknown/stale is never reported as clean.
apt_security = collect_apt()
if apt_security['status'] == 'CHECKED':
    count = apt_security['security_count']
    add('debian.security-updates', 'Debian security updates',
        'WARN' if count else 'PASS',
        f'{count} pending Debian security-related upgrade(s); {apt_security["other_count"]} other upgrade(s). '
        'No packages installed by this audit.')
else:
    add('debian.security-updates', 'Debian security updates', 'UNKNOWN',
        apt_security['reason'] + ' Do not interpret as zero security updates.')

now = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
counts = {level: sum(item['status'] == level for item in checks)
          for level in ('PASS', 'WARN', 'FAIL', 'INFO', 'UNKNOWN')}
snapshot = {
    'schema': 1,
    'profile': 'critical_security',
    'checked_at_utc': now,
    'checks': checks,
    'counts': counts,
    'security_alarm': any(c['security_alarm'] for c in checks),
    'package_security_updates': apt_security,
    'note': 'Critical-security subset; the full 15-section audit runs separately.'
}
OUTDIR.mkdir(mode=0o700, exist_ok=True)
# Keep installer-managed directory ownership/mode; sensitive snapshots remain 0600.
fd, staging = tempfile.mkstemp(prefix='.critical-', dir=OUTDIR)
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(snapshot, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.chmod(staging, 0o600)
    os.replace(staging, OUTDIR / 'latest-critical.json')
finally:
    if os.path.exists(staging):
        os.unlink(staging)
print('PASS: Structured security snapshot saved.')
print('Check totals:', ', '.join(f'{k}={v}' for k, v in counts.items()))
print('Security alarm:', 'YES' if snapshot['security_alarm'] else 'NO')
print('APT security updates:', apt_security['status'], apt_security['security_count'])
