"""Exact token counts for captured synthetic-fixture outputs, using cl100k_base."""
import argparse
import json
import subprocess
import tiktoken

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('cli')
parser.add_argument('--instance', help='Explicit synthetic-corpus instance when several are live')
args = parser.parse_args()
cli = args.cli
encoder = tiktoken.get_encoding('cl100k_base')
status_args = [cli] + (['--instance', args.instance] if args.instance else [])
status = json.loads(subprocess.check_output(status_args + ['status', '--format', 'json']))
instance = status['result']['instance_id']
project = status['result']['project_id']
base = [cli, '--instance', instance]
filters = ['--host', '127.0.0.1', '--path-contains', '/fixture/']
selection = json.loads(subprocess.check_output(base + ['history', 'list', '--limit', '100', '--fields', 'id,path', '--format', 'json'] + filters))
if selection['meta']['provenance'] != {'instance_id': instance, 'project_id': project}:
    raise SystemExit('Fixture context changed; obtain a fresh reference')
matches = [row for row in selection['result']['items'] if row['path'] == '/fixture/0']
if len(matches) != 1:
    raise SystemExit('Expected exactly one /fixture/0 row; cannot identify the synthetic body')
fixture_id = str(matches[0]['id'])
commands = {
    'status_compact': ['status'],
    'history_default_compact': ['history', 'list', '--limit', '10'] + filters,
    'history_projected_json': ['history', 'list', '--limit', '10', '--fields', 'id,status', '--format', 'json'] + filters,
    'small_base64_json': ['history', 'get', fixture_id, '--project-id', project, '--part', 'response.body', '--base64', '--format', 'json'],
}
for name, arguments in commands.items():
    output = subprocess.check_output(base + arguments)
    record = {'workflow': name, 'bytes': len(output), 'tokens': len(encoder.encode(output.decode('utf-8'))), 'encoding': 'cl100k_base'}
    if name == 'history_projected_json':
        rows = json.dumps(json.loads(output)['result']['items'], separators=(',', ':'))
        record['result_row_tokens'] = len(encoder.encode(rows))
    print(json.dumps(record))
