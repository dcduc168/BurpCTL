"""Run production-server fixtures and native CLI byte checks without target traffic."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cli', type=Path, required=True)
parser.add_argument('--screenshot', action='store_true', help='Also open a synthetic Swing window')
args = parser.parse_args()
cli = args.cli.resolve()
gradle = Path(os.environ.get('GRADLE_USER_HOME', Path.home() / '.gradle'))
montoya = list((gradle / 'caches/modules-2/files-2.1/net.portswigger.burp.extensions/montoya-api/2026.7').rglob('montoya-api-2026.7.jar'))
assert len(montoya) == 1, 'Expected the locked Montoya API JAR'


def call(*arguments, expected=0):
    result = subprocess.run([str(cli), *map(str, arguments)], capture_output=True, text=True, timeout=40)
    assert result.returncode == expected, f'CLI exit {result.returncode}, expected {expected}: {result.stderr}'
    return json.loads(result.stdout) if result.stdout.strip() else None


def instances():
    return call('instance', 'list', '--format', 'json')['result']['items']


def line(process):
    received = queue.Queue()
    threading.Thread(target=lambda: received.put(process.stdout.readline()), daemon=True).start()
    return received.get(timeout=10).strip()


@contextmanager
def fixture(name, classpath, *arguments):
    before = {item['instance_id'] for item in instances()}
    process = subprocess.Popen(['java', '-Djava.awt.headless=true', '-cp', classpath, name, *arguments],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert line(process) == 'ready', f'{name} startup failed'
        added = [item for item in instances() if item['instance_id'] not in before]
        assert len(added) == 1 and added[0]['project_id'] == 'fixture-project', 'Fixture discovery failed'
        yield process, added[0]
    finally:
        if process.poll() is None:
            try:
                process.stdin.write('stop\n')
                process.stdin.flush()
                process.wait(timeout=5)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=5)
        process.stdin.close()
        process.stdout.close()
    assert process.returncode == 0, f'{name} shutdown failed'
    assert not any(item['instance_id'] == added[0]['instance_id'] for item in instances()), 'Fixture retained'


with tempfile.TemporaryDirectory(prefix='bctl-check-') as directory:
    directory = Path(directory)
    classes = directory / 'classes'
    classes.mkdir()
    classpath = os.pathsep.join(map(str, [classes, root / 'extension/build/libs/burpctl-extension.jar', montoya[0]]))
    sources = ['StatusSmoke', 'TrafficFixture', 'HistorySmoke', 'HistoryServer', 'PartialSmokeServer',
               'SettingsSmoke', 'LifecycleSmoke', 'ScreenshotSmoke', 'ReadToolsSmoke']
    subprocess.run(['javac', '--release', '21', '-cp', classpath, '-d', str(classes),
                    *[str(root / f'verification/{name}.java') for name in sources]], check=True, timeout=60)
    for name in ['StatusSmoke', 'HistorySmoke', 'SettingsSmoke', 'LifecycleSmoke', 'ReadToolsSmoke']:
        subprocess.run(['java', '-Djava.awt.headless=true', '-cp', classpath, name], check=True, timeout=90)
    if args.screenshot:
        subprocess.run(['java', '-cp', classpath, 'ScreenshotSmoke'], check=True, timeout=40)
    expected = json.loads(subprocess.run(['java', '-cp', classpath, 'TrafficFixture', 'hashes'],
                                        check=True, capture_output=True, text=True, timeout=15).stdout)
    assert len(expected) == 100
    with fixture('HistoryServer', classpath) as (_, instance):
        common = ['--instance', instance['instance_id'], '--format', 'json']
        status = call(*common, 'status')['result']
        assert status['permissions']['history_raw']
        assert call(*common, 'scope', 'check', 'http://127.0.0.1:18123/fixture/0')['ok']
        rows = call(*common, 'history', 'list', '--limit', 100, '--host', '127.0.0.1',
                    '--path-contains', '/fixture/', '--fields', 'id,path,status')['result']['items']
        assert len(rows) == 100 and len({row['id'] for row in rows}) == 100
        assert {row['path'] for row in rows} == {f'/fixture/{index}' for index in range(100)}
        assert all(set(row) == {'id', 'path', 'status'} for row in rows), 'Projection mismatch'
        output = directory / 'body.bin'
        for row in rows:
            index = int(row['path'].removeprefix('/fixture/'))
            reference = [*common, 'history', 'get', row['id'], '--project-id', instance['project_id']]
            for part in ['request.body', 'response.body']:
                call(*reference, '--part', part, '--raw', '--output', output)
                data = output.read_bytes()
                assert len(data) == expected[index]['size'] and hashlib.sha256(data).hexdigest() == expected[index]['sha256']
                output.unlink()
            preview = call(*reference, '--part', 'response.body', '--base64')['result']['item']
            assert hashlib.sha256(base64.b64decode(preview['data'], validate=True)).hexdigest() == expected[index]['prefix_sha256']
        output.write_bytes(b'sentinel')
        reference = [*common, 'history', 'get', 0, '--project-id', instance['project_id'], '--part', 'request.body', '--raw', '--output', output]
        call(*reference, expected=2)
        assert output.read_bytes() == b'sentinel', 'Existing destination replaced without force'
        call(*reference, '--force')
        assert hashlib.sha256(output.read_bytes()).hexdigest() == expected[0]['sha256']
        output.unlink()
        with fixture('HistoryServer', classpath):
            call('status', expected=3)
            assert call(*common, 'status')['result']['instance_id'] == instance['instance_id']
        assert not list(directory.glob('*.part')), 'Partial exports retained'
    with fixture('ReadToolsSmoke', classpath, 'serve') as (_, instance):
        common = ['--instance', instance['instance_id'], '--format', 'json']
        reference = ['--project-id', instance['project_id']]
        status = call(*common, 'status')['result']
        assert {'history.stats', 'history.endpoints', 'history.match', 'sitemap.issues.list', 'sitemap.issues.get', 'repeater.open'} <= set(status['methods'])
        stats = call(*common, 'history', 'stats', '--by', 'method')['result']
        assert stats['matched'] == 100 and stats['buckets'] == {'POST': 100}
        endpoints = call(*common, 'history', 'endpoints', '--limit', 10, '--fields', 'path,count,sample_id')
        assert endpoints['meta']['inventory_complete'] and len(endpoints['result']['items']) == 10
        assert all(item['count'] == 10 for item in endpoints['result']['items'])
        assert call(*common, 'history', 'endpoints', '--limit', 3)['meta']['truncated']
        prefix = base64.b64encode(bytes([0])).decode()
        match = call(*common, 'history', 'match', 0, *reference, '--part', 'request.body', '--base64', prefix)['result']
        assert isinstance(match['matched'], bool) and 'search_complete' in match
        call(*common, 'history', 'match', 0, *reference, '--part', 'request.body', '--text', '', expected=2)
        call(*common, 'history', 'stats', '--by', 'path', expected=2)
        call(*common, 'history', 'match', 0, '--project-id', 'wrong', '--part', 'request.body', '--text', 'x', expected=3)
        call('history', 'match', 0, *reference, '--part', 'request.body', '--text', 'x', expected=2)
        issue_list = call(*common, 'sitemap', 'issues', 'list', '--host', '127.0.0.1', '--severity', 'high')['result']['items']
        assert len(issue_list) == 2 and all('detail' not in item for item in issue_list)
        issue = call(*common, 'sitemap', 'issues', 'get', issue_list[0]['id'], *reference, '--fields', 'detail,remediation')['result']['item']
        assert issue == {'detail': '<p>fixture detail</p>', 'remediation': None}
        call(*common, 'sitemap', 'issues', 'get', issue_list[0]['id'], '--project-id', 'wrong', expected=3)
        opened = call(*common, 'repeater', 'open', 0, *reference, '--name', 'fixture')
        assert opened['result']['opened'] and opened['meta']['network_sent'] is False
        call(*common, 'repeater', 'open', 0, *reference, '--name', 'bad\nname', expected=2)
    print('PASS: native stats/endpoints/match/issues/UI-open commands and source-context/schema checks')
    print('PASS: native discovery/ambiguity, scope/projection, 200 raw hashes, 100 Base64 prefixes, no-clobber/force')
    with fixture('PartialSmokeServer', classpath) as (process, instance):
        output = directory / 'incomplete.bin'
        result = subprocess.run([str(cli), '--instance', instance['instance_id'], 'history', 'get', '102',
                                 '--project-id', instance['project_id'], '--part', 'request.body', '--raw', '--output', str(output)],
                                capture_output=True, text=True, timeout=40)
        assert result.returncode == 7 and result.stderr.startswith('PARTIAL_TRANSFER:')
        assert line(process) == 'first chunk sent', 'Failure happened before streaming'
        assert not output.exists() and not list(directory.glob('*.part'))
    print('PASS: interrupted native stream, export cleanup and fixture unload')
