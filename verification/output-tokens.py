"""Exact token counts for captured synthetic-fixture outputs, using cl100k_base."""
import json
import subprocess
import sys
import tiktoken

cli = sys.argv[1]
encoder = tiktoken.get_encoding('cl100k_base')
status = json.loads(subprocess.check_output([cli, 'status', '--format', 'json']))
instance = status['result']['instance_id']
project = status['result']['project_id']
base = [cli, '--instance', instance]
commands = {
    'status_compact': ['status'],
    'history_default_compact': ['history', 'list', '--limit', '10'],
    'history_projected_json': ['history', 'list', '--limit', '10', '--fields', 'id,status', '--format', 'json'],
    'small_base64_json': ['history', 'get', '1', '--project-id', project, '--part', 'response.body', '--base64', '--format', 'json'],
}
for name, arguments in commands.items():
    output = subprocess.check_output(base + arguments)
    record = {'workflow': name, 'bytes': len(output), 'tokens': len(encoder.encode(output.decode('utf-8'))), 'encoding': 'cl100k_base'}
    if name == 'history_projected_json':
        rows = json.dumps(json.loads(output)['result']['items'], separators=(',', ':'))
        record['result_row_tokens'] = len(encoder.encode(rows))
    print(json.dumps(record))
