"""Deploy the built self-host images as a no-traffic Cloud Run revision, preserving auth/storage/scanner configuration."""
import argparse
import json
import re
import subprocess
from pathlib import Path


def run(args):
    # Global flags must precede multi-container flag groups.
    result = subprocess.run(['gcloud', '--format=json', '--quiet', *args], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-id', required=True)
    parser.add_argument('--model-build-id', help='Reuse a completed model build when only the application changed')
    parser.add_argument('--project', default='trustops-uat')
    parser.add_argument('--region', default='europe-west1')
    parser.add_argument('--service', default='trustops-ui')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-f0-9-]{36}', args.build_id):
        parser.error('Use the completed Cloud Build UUID')
    build = run(['builds', 'describe', args.build_id, '--project', args.project])
    if build.get('status') != 'SUCCESS':
        parser.error('Build must have completed successfully')
    model_build_id = args.model_build_id or args.build_id
    if not re.fullmatch(r'[a-f0-9-]{36}', model_build_id):
        parser.error('Use the completed model Cloud Build UUID')
    model_build = run(['builds', 'describe', model_build_id, '--project', args.project]) if model_build_id != args.build_id else build
    if model_build.get('status') != 'SUCCESS':
        parser.error('Model build must have completed successfully')
    service = run(['run', 'services', 'describe', args.service, '--region', args.region, '--project', args.project])
    live = [t['revisionName'] for t in service['status']['traffic'] if t.get('percent') == 100]
    if len(live) != 1:
        parser.error('This single-writer service must have one explicit revision receiving 100% of traffic')
    template = service['spec']['template']
    containers = {c['name']: c for c in template['spec']['containers']}
    env = {e['name']: e.get('value') for e in containers['app']['env']}
    if env.get('TAAD_AUTH_MODE') != 'oidc':
        parser.error('Refusing to deploy this online service without existing OIDC authentication')
    annotations = template.get('metadata', {}).get('annotations', {})
    deps = json.loads(annotations.get('run.googleapis.com/container-dependencies', '{}')).get('app', [])
    deps = list(dict.fromkeys([*deps, 'ollama']))
    image_root = f'{args.region}-docker.pkg.dev/{args.project}/taad'
    images = {i['name']: i.get('digest') for b in (build, model_build) for i in b['results']['images']}
    api = f'{image_root}/api:{args.build_id}'
    model = f'{image_root}/ollama:{model_build_id}'
    for image in (api, model):
        if not images.get(image):
            parser.error('Build output is missing an image digest')
    # Use digests, never moving tags, for the deployable revision.
    api_ref = f'{image_root}/api@{images[api]}'
    model_ref = f'{image_root}/ollama@{images[model]}'
    plan = {'project': args.project, 'region': args.region, 'service': args.service, 'build_id': args.build_id,
            'model_build_id': model_build_id, 'previous_revision': live[0], 'tag': 'selfhost-check',
            'api_image': api_ref, 'model_image': model_ref, 'model': 'qwen3:4b',
            'new_revision_min_instances': 0, 'new_revision_max_instances': 1, 'client_traffic_percent': 0,
            'model_cpu': 4, 'model_memory': '12Gi', 'existing_auth_and_storage': 'preserved'}
    Path(args.output).write_text(json.dumps(plan, indent=2)+'\n')
    update = ['run', 'services', 'update', args.service, '--region', args.region, '--project', args.project,
              '--no-traffic', '--tag=selfhost-check', '--min-instances=0', '--max-instances=1', '--concurrency=1', '--timeout=900', '--async',
              '--container=app', f'--image={api_ref}', '--depends-on='+','.join(deps),
              '--update-env-vars=^|^TAAD_LLM_PROVIDER=ollama|TAAD_OLLAMA_URL=http://127.0.0.1:11434|TAAD_OLLAMA_MODEL=qwen3:4b|'
              'TAAD_OLLAMA_TIMEOUT=240|TAAD_MODEL_STARTUP_CHECK=1|TAAD_MODEL_DOCUMENT_CHECK=1',
              '--container=ollama', f'--image={model_ref}', '--cpu=4', '--memory=12Gi',
              '--startup-probe=tcpSocket.port=11434,periodSeconds=5,timeoutSeconds=1,failureThreshold=48']
    run(update)
    print(json.dumps(plan, indent=2))


if __name__ == '__main__':
    main()
