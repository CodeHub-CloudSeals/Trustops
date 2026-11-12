"""Run passive REA on one explicit origin and export minimal TrustOps capture metadata.

Client-side only. No registration/setup, source capture, cookies, payloads, LLM calls or remote API writes.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'apps' / 'assessment-api'))
from app.application_evidence import Capture, safe_url


def normalize(raw, version, expected_origin):
    if raw.get('ok') is not True:
        raise ValueError('REA did not return a successful observation')
    ev = raw['data']
    if ev['operation'] != 'inspect_web_page' or ev['provider']['id'] != 'rea-cdp-browser':
        raise ValueError('Expected REA passive CDP page observation')
    data = ev['normalized_result']
    if data['target']['origin'] != expected_origin:
        raise ValueError('The observation target differs from the explicitly selected origin')
    raw_bytes = json.dumps(raw, sort_keys=True, ensure_ascii=False).encode()
    scripts = [{'url': safe_url(s['url']), 'reported_hash': s.get('cdp_hash')}
               for s in data['scripts']['items'][:200] if s.get('url', '').startswith(('http://', 'https://'))]
    requests = [{'url': safe_url(r['url']), 'method': r['method'], 'status': r.get('status')}
                for r in data['network']['requests'][:300] if r.get('url', '').startswith(('http://', 'https://'))]
    limits = list(dict.fromkeys(ev['limitations'] + data.get('limitations', [])))[:55]
    limits.append('The connector retains at most 200 script records and 300 request records; other capture fields are excluded.')
    # Non-HTTP scripts, completeness exclusions and prior activity never become negative findings.
    limits.append('Non-HTTP scripts and any REA completeness exclusions are outside the retained metadata view.')
    return Capture.model_validate({'schema_version': 'trustops.rea.capture.v1', 'producer': 'rea-agents',
        'producer_version': version, 'rea_evidence_id': ev['evidence_id'], 'source_sha256': hashlib.sha256(raw_bytes).hexdigest(),
        'target_url': safe_url(data['target']['url']), **data['capture_window'], 'dom_nodes': data['dom']['total_nodes'],
        'scripts': scripts, 'requests': requests, 'limitations': [s[:1000] for s in limits]}).model_dump(mode='json')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--node', required=True, help='Absolute Node.js executable')
    p.add_argument('--rea-cli', required=True, help='Installed rea-agents/scripts/rea.mjs entry point')
    p.add_argument('--endpoint', default='http://127.0.0.1:9227')
    p.add_argument('--origin', required=True, help='One exact approved test/customer origin')
    p.add_argument('--output', required=True)
    p.add_argument('--raw-output')
    p.add_argument('--observation-ms', type=int, default=5000)
    args = p.parse_args()
    origin = urlsplit(args.origin)
    if origin.scheme not in ('http', 'https') or not origin.hostname or origin.path or origin.query or origin.fragment or origin.username:
        p.error('Use an exact HTTP(S) origin, without path, credentials, query or fragment')
    if not 500 <= args.observation_ms <= 30_000:
        p.error('Observation duration must be between 500 and 30000 ms')
    command = [args.node, args.rea_cli]

    def rea(*parts):
        r = subprocess.run([*command, *parts, '--format', 'json', '--full-output'], capture_output=True, text=True, timeout=60)
        if r.returncode:
            raise RuntimeError('REA process failed; verify Node and the CLI entry point')
        b = json.loads(r.stdout)
        if r.returncode or not b.get('ok'):
            raise RuntimeError('REA capture unavailable; check the dedicated browser, debugging endpoint and origin')
        return b

    targets = rea('list-browser-targets', args.endpoint, '--allowed-origins', args.origin)['data']['normalized_result']['targets']
    if len(targets) != 1:
        p.error('Open exactly one matching page in the dedicated test browser')
    raw = rea('inspect-web-page', args.endpoint, targets[0]['target_id'], '--allowed-origins', args.origin,
              '--observation-ms', str(args.observation_ms))
    # Version comes from the installed package, rather than a caller-supplied capture claim.
    package = Path(args.rea_cli).resolve().parent.parent / 'package.json'
    capture = normalize(raw, json.loads(package.read_text())['version'], args.origin)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(capture, indent=2, ensure_ascii=False) + '\n')
    output.chmod(0o600)
    if args.raw_output:
        raw_path = Path(args.raw_output)
        raw_path.write_text(json.dumps(raw, sort_keys=True, ensure_ascii=False))
        raw_path.chmod(0o600)
    print(json.dumps({'output': str(output), 'rea_evidence_id': capture['rea_evidence_id'],
                      'dom_nodes': capture['dom_nodes'], 'scripts': len(capture['scripts']), 'requests': len(capture['requests'])}))


if __name__ == '__main__':
    main()
