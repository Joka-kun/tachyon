#!/usr/bin/env python3
"""Scan fork-only history and candidate metadata without printing matched values."""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = '8.30.1'
ASSETS = {
    'x86_64': ('x64', 8230402, '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
    'aarch64': ('arm64', 7601421, 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080'),
}
# Only own additions are scanned. Upstream documentation contains intentional examples.
RULES = {
    'private-ipv4': rb'\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b',
    'private-key': rb'-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----',
    'vpn-profile': rb'(?i)\b(?:vless|vmess|trojan|ss|wg|awg|hysteria2|tuic|amnezia)://[^\s"\x00<>]{10,}',
    'base64-key': rb'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])',
    'private-host-path': rb'/(?:home|Users)/(?!runner/)[A-Za-z0-9_.-]+/',
    'wifi-config': rb'(?im)^\s*(?:option\s+ssid\s+|ssid\s*[:=]\s*)["\']?[^\s"\']{2,}',
    'local-domain': rb'(?i)\b[a-z0-9.-]+\.(?:duckdns\.org|ddns\.net|no-ip\.org|lan|local)\b',
    'credential-assignment': rb'(?i)\b(?:password|passwd|secret|private_key|preshared_key|pre_shared_key|api_key|token)\b["\']?\s*[:=]\s*["\'][^"\'\n]{8,}["\']',
    'mac-address': rb'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',
}

class Hold(RuntimeError): pass

def require(ok, message):
    if not ok: raise Hold(message)

def git(*args):
    return subprocess.check_output(['git', *args], stderr=subprocess.DEVNULL)

def pattern_check(data):
    return [name for name, pattern in RULES.items() if re.search(pattern, data)]

def scan_bytes(data):
    require(len(data) <= 4 * 1024 * 1024, 'own text file too large')
    require(b'\x00' not in data, 'binary file in own source changes')
    data.decode('utf-8', errors='strict')
    matches = pattern_check(data)
    require(not matches, 'privacy pattern match: ' + ','.join(matches))

def gitleaks_scan(directory, work):
    arch, size, digest = ASSETS[platform.machine()]
    url = f'https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_linux_{arch}.tar.gz'
    with urllib.request.urlopen(url, timeout=30) as resp:
        require(resp.geturl().startswith('https://'), 'scanner redirect not HTTPS')
        blob = resp.read(size + 1)
    require(len(blob) == size and hashlib.sha256(blob).hexdigest() == digest, 'scanner archive pin mismatch')
    archive = work / 'scanner.tar.gz'
    archive.write_bytes(blob)
    with tarfile.open(archive, 'r:gz') as tar:
        members = [x for x in tar.getmembers() if PurePosixPath(x.name).name == 'gitleaks']
        require(len(members) == 1 and members[0].isfile() and 0 < members[0].size < 64*1024*1024, 'scanner member invalid')
        executable = work / 'gitleaks'
        executable.write_bytes(tar.extractfile(members[0]).read())
    executable.chmod(0o700)
    result = subprocess.run([str(executable), 'dir', '--redact=100', '--no-banner', '--log-level', 'error', '--exit-code', '1', str(directory)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
    require(result.returncode == 0, 'Gitleaks rejected input or failed; no matched values printed')

def check_identity(commit):
    fields = git('show', '-s', '--format=%an%x00%ae%x00%cn%x00%ce', commit).decode().rstrip('\n').split('\0')
    require(len(fields) == 4, 'author metadata malformed')
    for name, email in ((fields[0], fields[1]), (fields[2], fields[3])):
        require(bool(re.fullmatch(r'[A-Za-z0-9_-]+', name)), 'author name must be a public pseudonym')
        require(bool(re.fullmatch(r'[0-9]+\+[A-Za-z0-9_-]+@users\.noreply\.github\.com', email, re.I)), 'author email not GitHub noreply')

def history(base, head, directory):
    require(subprocess.run(['git', 'merge-base', '--is-ancestor', base, head], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0, 'baseline is not ancestor')
    commits = git('rev-list', '--reverse', f'{base}..{head}').decode().splitlines()
    require(0 < len(commits) <= 500, 'own history scope invalid')
    files = 0
    for commit in commits:
        check_identity(commit)
        parents = git('show', '-s', '--format=%P', commit).decode().split()
        require(len(parents) == 1, 'merge in own history requires explicit review')
        changed = git('diff', '--name-only', '--diff-filter=ACMRT', '-z', parents[0], commit).split(b'\0')
        for raw in filter(None, changed):
            name = raw.decode('utf-8')
            p = PurePosixPath(name)
            require(not p.is_absolute() and '..' not in p.parts, 'unsafe filename')
            require(not re.search(r'(?i)(?:^|/)(?:\.env(?:\.|$)|id_(?:rsa|ed25519)|secrets?\.|credentials?\.)|\.(?:pem|p12|pfx|key|ovpn|zip|tgz|gz|apk|ipk)$', name), 'sensitive or archive filename in own history')
            entry = git('ls-tree', commit, '--', name).split(b'\t', 1)[0].split()
            require(len(entry) == 3 and entry[0] in (b'100644', b'100755') and entry[1] == b'blob', 'nonregular own file')
            data = git('show', f'{commit}:{name}')
            scan_bytes(data)
            dest = directory / commit / Path(*p.parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            files += 1
    return len(commits), files

def artifact(path, directory):
    expected = {'LICENSE','admission.patch','SHA256SUMS','build-info.txt','elf.txt','provider_admission.rs','program-headers.txt','tachyon','test.log','toolchain.txt','upstream-source.tar.gz','version.txt'}
    if path.is_file():
        require(path.name == 'candidate-pair.json' and not path.is_symlink(), 'unexpected metadata artifact')
        entries = [path]
    else:
        require(path.is_dir() and not path.is_symlink(), 'artifact directory missing')
        entries = list(path.iterdir())
        require({x.name for x in entries} == expected, 'candidate artifact inventory mismatch')
    for f in entries:
        require(f.is_file() and not f.is_symlink(), 'nonregular candidate file')
        if f.name in {'tachyon','upstream-source.tar.gz'}:
            # Exact upstream archive and derived executable checked by the build's provenance gates.
            # Generic patterns in upstream fixtures are outside the fork-only scan.
            continue
        data = f.read_bytes()
        scan_bytes(data)
        (directory / f.name).write_bytes(data)
    return len(entries)

def selftest():
    tests = [
        (b'let name = "test-group";', False),
        (b'address = "' + b'192.' + b'168.1.1"', True),
        (b'-----BEGIN ' + b'PRIVATE KEY-----', True),
        (b'awg' + b'://0123456789abcdef', True),
        (b'A'*43+b'=', True),
        (b'/home'+b'/fixture/file', True),
    ]
    for data, expected in tests: require(bool(pattern_check(data)) == expected, 'privacy self-test failed')
    print('PRIVACY_PATTERN_SELFTEST_PASS', len(tests))

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='mode', required=True)
    h = sub.add_parser('history'); h.add_argument('base'); h.add_argument('head')
    a = sub.add_parser('artifact'); a.add_argument('path', type=Path)
    sub.add_parser('selftest')
    args = p.parse_args()
    if args.mode == 'selftest': selftest(); return
    with tempfile.TemporaryDirectory(prefix='privacy-scan-') as name:
        work = Path(name); scan = work / 'scan'; scan.mkdir(mode=0o700)
        count = history(args.base, args.head, scan) if args.mode == 'history' else artifact(args.path, scan)
        gitleaks_scan(scan, work)
        print('PRIVACY_GATE_PASS', args.mode, count)

if __name__ == '__main__':
    try: main()
    except (Hold, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        # Never output exception details from external programs or raw bytes.
        print('PRIVACY_GATE_HOLD:', str(e) if isinstance(e, Hold) else type(e).__name__)
        raise SystemExit(78)
