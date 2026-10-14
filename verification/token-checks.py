"""Assert token workflows select the synthetic row instead of a fixed history ID."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import types
from unittest.mock import patch

script = Path(__file__).with_name('output-tokens.py')
for paths, changed in [(['/fixture/0'], False), ([], False), (['/fixture/0', '/fixture/0'], False), (['/fixture/0'], True)]:
    calls = []

    def output(arguments):
        calls.append(arguments)
        assert '--instance' in arguments and arguments[arguments.index('--instance') + 1] == 'fixture'
        if 'status' in arguments:
            return json.dumps({'result': {'instance_id': 'fixture', 'project_id': 'project'}}).encode()
        if 'list' in arguments:
            assert '--host' in arguments and '--path-contains' in arguments
            return json.dumps({'result': {'items': [{'id': 987 + index, 'path': path} for index, path in enumerate(paths)]},
                               'meta': {'provenance': {'instance_id': 'other' if changed else 'fixture', 'project_id': 'project'}}}).encode()
        assert arguments[arguments.index('get') + 1] == '987'
        assert arguments[arguments.index('--project-id') + 1] == 'project'
        return b'{"result":{"item":{"data":"synthetic"}}}'

    # No token counts from this stub are treated as measured benchmark results.
    tokenizer = types.SimpleNamespace(get_encoding=lambda _: types.SimpleNamespace(encode=lambda value: list(value)))
    rejected = False
    with patch.object(subprocess, 'check_output', output), patch.object(sys, 'argv', [str(script), 'fixture-cli', '--instance', 'fixture']), \
            patch.dict(sys.modules, {'tiktoken': tokenizer}), contextlib.redirect_stdout(io.StringIO()):
        try:
            runpy.run_path(str(script), run_name='__main__')
        except SystemExit:
            rejected = True
    valid = len(paths) == 1 and not changed
    assert rejected != valid
    assert any('get' in command for command in calls) == valid
print('PASS: dynamic fixture ID, scoped filters/context, missing/duplicate/stale fixture rejected before body access')
