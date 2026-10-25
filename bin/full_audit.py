#!/usr/bin/env python3
"""Full-audit bridge with validated structured output for the web dashboard."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import sys

APP=Path(__file__).resolve().parent.parent
RUN=APP/'run'
WEB=RUN/'web'
FEED=WEB/'full-audit-feed.json'
CLI=APP/'bin/asl3-node-audit.sh'
INTERVAL=300
MAX_AGE=900
MAX_BYTES=1024*1024
SEV=('PASS','WARN','FAIL','INFO','SKIP','UNKNOWN')
HEADER=re.compile(r'^===\s*(\d+)\.\s*(.*?)\s*===\s*$')
RESULT=re.compile(r'^\s*\[(PASS|WARN|FAIL|INFO|SKIP|UNKNOWN)\s*\]\s*(.*)$')
TOTAL=re.compile(r'^TOTAL:\s*(\d+) PASS \| (\d+) WARN \| (\d+) FAIL \| (\d+) INFO \| (\d+) SKIP \| (\d+) UNKNOWN')


def utc(): return dt.datetime.now(dt.timezone.utc)


def parse_report(report: str) -> dict:
    if len(report.encode('utf8'))>MAX_BYTES: raise ValueError('Report exceeds size limit')
    section=None; sections=[]; totals=None; findings=[]
    audit_version=None
    for line in report.splitlines():
        if '\x1b' in line: raise ValueError('ANSI codes rejected')
        if line.startswith('ASL3 NODE AUDIT v'):
            audit_version=line.split(' | ',1)[0].split(' v',1)[-1][:20]
        match=HEADER.fullmatch(line)
        if match:
            section={'number':int(match.group(1)),'title':match.group(2),'rows':[],
                     'severity':{k:0 for k in SEV}}
            sections.append(section);continue
        match=TOTAL.match(line)
        if match:
            totals=dict(zip(SEV,(int(v) for v in match.groups())))
            continue
        if section is None:continue
        match=RESULT.match(line)
        if match:
            level,text=match.group(1),match.group(2).strip()
            section['rows'].append({'kind':'result','level':level,'text':text,'detail':[]})
            section['severity'][level]+=1
            if level in ('WARN','FAIL','UNKNOWN') and section['number'] not in (16,17):
                findings.append({'level':level,'message':text,'section':section['number']})
        elif line.strip():
            if (section['rows'] and section['rows'][-1]['kind']=='result'
                    and len(line)-len(line.lstrip())>=10):
                section['rows'][-1]['detail'].append(line.strip()[:500])
            else:
                raw=line.strip()[:500]
                cells=[v.strip() for v in re.split(r'\s{2,}',raw) if v.strip()]
                section['rows'].append({'kind':'columns' if len(cells)>=2 else 'plain',
                                        'text':raw,'cells':cells})
    sections=[s for s in sections if 1<=s['number']<=15]
    if len(sections)!=15 or [s['number'] for s in sections]!=list(range(1,16)):
        raise ValueError('Expected all 15 diagnostic sections')
    if totals is None or audit_version is None:raise ValueError('Incomplete CLI report')
    expected={k:sum(s['severity'][k] for s in sections) for k in SEV}
    # Original CLI includes two additional INFO entries in sections 17 and may
    # include non-section summary rows. Do not infer equality from this alone.
    if any(totals[k]<expected[k] for k in SEV):
        raise ValueError('Counter inconsistency')
    return {'schema':1,'kind':'full_audit','coverage':'FULL','engine':'cli-adapter',
            'version':audit_version,'checked_at_utc':utc().isoformat(),
            'status':'CURRENT','totals':totals,'sections':sections,'findings':findings}


def safe_write(path:Path,data:dict,mode:int):
    if path.is_symlink():raise ValueError('Unsafe feed symlink')
    payload=json.dumps(data,ensure_ascii=True,separators=(',',':')).encode('utf8')+b'\n'
    if len(payload)>MAX_BYTES*2:raise ValueError('Feed too large')
    fd,tmp=tempfile.mkstemp(prefix='.full-audit-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as fp:
            fp.write(payload);fp.flush();os.fsync(fp.fileno())
        os.chmod(tmp,mode);os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def is_due():
    try:
        d=json.loads(FEED.read_text()); stamp=dt.datetime.fromisoformat(d['checked_at_utc'])
        return (utc()-stamp).total_seconds()>=INTERVAL
    except (OSError,ValueError,KeyError,TypeError):return True


def collect(force=False):
    if os.geteuid()!=0:raise ValueError('Root required')
    if not APP.is_dir() or APP.is_symlink() or not WEB.is_dir() or WEB.is_symlink():
        raise ValueError('Application/private feed directory missing')
    if not CLI.is_file() or CLI.is_symlink():raise ValueError('CLI bridge source missing')
    if not force and not is_due():
        print('SKIP: Full audit not due');return 0
    try:
        p=subprocess.run(['/bin/bash',str(CLI),'--no-color'],capture_output=True,text=True,
                         timeout=240,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    except subprocess.TimeoutExpired:
        print('WARNING: Full audit exceeded time limit; previous snapshot remains timestamped',file=sys.stderr)
        return 3
    # Exit 3 means WARN/UNKNOWN, exit 1 means audited FAIL; both may be valid.
    if p.returncode not in (0,1,3):
        print(f'WARNING: CLI exited unexpectedly ({p.returncode})',file=sys.stderr);return 3
    try:
        result=parse_report(p.stdout)
        if result['totals']['FAIL']==0 and p.returncode==1:
            raise ValueError('CLI exit code/report mismatch')
        safe_write(FEED,result,0o640)
    except (ValueError,OSError) as e:
        print('WARNING: Full audit validation failed:',e,file=sys.stderr);return 3
    print('PASS: Full audit snapshot published:',result['checked_at_utc'], result['totals']);return 0


def self_test():
    sample='ASL3 NODE AUDIT v1.0.0 | DATE\n'
    for i in range(1,16):
        sample+=f'\n=== {i}. Section {i} ===\n  [PASS   ] healthy\n'
        if i==13:sample+='    Timer unit                                Startup      Active\n      apt-daily.timer                          enabled      active\n'
    sample+='\n=== 16. Priority findings ===\n=== 17. Report limitations ===\nTOTAL: 15 PASS | 0 WARN | 0 FAIL | 0 INFO | 0 SKIP | 0 UNKNOWN\n'
    got=parse_report(sample)
    assert len(got['sections'])==15 and got['totals']['PASS']==15
    assert any(r['kind']=='columns' and len(r['cells'])==3 for r in got['sections'][12]['rows'])
    for bad in ('TOTAL: 0 PASS',sample.replace('=== 15. Section 15 ===',''),sample+'\x1b[31m'):
        try:parse_report(bad)
        except ValueError:pass
        else:raise AssertionError('Invalid input accepted')
    print('PASS: Full audit parser, 15 sections, table columns and invalid-output guards')


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--once',action='store_true');ap.add_argument('--force',action='store_true');ap.add_argument('--self-test',action='store_true');args=ap.parse_args()
    if args.self_test:self_test()
    elif args.once:raise SystemExit(collect(args.force))
    else:ap.error('Choose --once or --self-test')

if __name__=='__main__':
    try:main()
    except (OSError,ValueError) as e:
        print('STOP:',e,file=sys.stderr);raise SystemExit(2)
