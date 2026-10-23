"""Defense-in-depth checks, not a proof that arbitrary content is public-safe."""
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = [re.compile(r'gh[pousr]_[A-Za-z0-9]{20,}'),
            re.compile(r'github_pat_[A-Za-z0-9_]{30,}'),
            re.compile(r'AKIA[A-Z0-9]{16}'),
            re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')]
SAFE_NETS = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '127.0.0.0/8')]


def violations(name, content):
    errors = []
    lowered = name.lower()
    if any(part in lowered.split('/') for part in ('secrets', 'raw-data', 'participant-data', 'runtime', 'private', 'inventory')):
        errors.append('forbidden directory')
    if lowered.endswith(('.pcap', '.pcapng', '.pem', '.key', '.p12', '.pfx', '.log')) or Path(name).name.startswith('.env'):
        errors.append('forbidden file type')
    if any(p.search(content) for p in PATTERNS):
        errors.append('possible credential')
    for token in re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', content):
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            continue
        if not any(address in n for n in SAFE_NETS):
            errors.append('non-documentation IPv4 address')
    if name.startswith('.github/workflows/'):
        if any(word in content for word in ('pull_request_target', 'workflow_run', 'self-hosted', 'secrets.')):
            errors.append('privileged workflow feature')
        for use in re.findall(r'uses:\s*([^\s#]+)', content):
            if not re.fullmatch(r'actions/(checkout|setup-python)@[0-9a-f]{40}', use):
                errors.append('unapproved or unpinned action')
    return errors


def main():
    allowed = set(json.loads((ROOT / 'publication-allowlist.json').read_text())['paths'])
    proc = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z'], capture_output=True, check=True)
    tracked = set(proc.stdout.decode().strip('\0').split('\0')) - {''}
    errors = []
    for name in sorted(tracked - allowed):
        errors.append(name + ': not on publication allowlist')
    for name in sorted(allowed - tracked):
        errors.append(name + ': allowlisted but not tracked')
    for name in sorted(tracked):
        data = (ROOT / name).read_bytes()
        if len(data) > 2_000_000:
            errors.append(name + ': oversized public artifact')
            continue
        try:
            content = data.decode('utf-8')
        except UnicodeDecodeError:
            errors.append(name + ': binary file requires explicit process')
            continue
        errors.extend(name + ': ' + error for error in violations(name, content))
    if errors:
        print('\n'.join(errors))
        return 1
    print('Publication composition checks passed; human content review remains required.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
