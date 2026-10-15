"""Focused checks for golden frames and matching release artifacts."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import zipfile

root = Path(__file__).resolve().parents[1]
wrapper = (root / 'extension/gradle/wrapper/gradle-wrapper.properties').read_text()
checksum = next(line.split('=', 1)[1] for line in wrapper.splitlines() if line.startswith('distributionSha256Sum='))
assert len(checksum) == 64 and all(character in '0123456789abcdef' for character in checksum), 'Invalid Gradle distribution SHA-256'
spec = importlib.util.spec_from_file_location('release', root / 'scripts/check-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--target', choices=release.TARGETS, default=release.native_target())
args = parser.parse_args()
target = args.target

for name in ['status-request', 'history-list-response']:
    payload = (root / f'protocol/examples/{name}.json').read_bytes().rstrip(b'\n')
    frame = bytes.fromhex((root / f'protocol/examples/{name}.frame.hex').read_text())
    assert struct.unpack('>I', frame[:4])[0] == len(frame) - 4
    assert frame[4] == 1 and frame[5:] == payload
frames = [bytes.fromhex(line) for line in (root / 'protocol/examples/raw-stream.frame.hex').read_text().splitlines()]
controls = (root / 'protocol/examples/raw-stream.jsonl').read_bytes().splitlines()
for frame in frames:
    assert struct.unpack('>I', frame[:4])[0] == len(frame) - 4
assert frames[0][4] == frames[-1][4] == 1
assert frames[0][5:] == controls[0] and frames[-1][5:] == controls[1]
opening, ending = (json.loads(control) for control in controls)
body = frames[1][5:]
assert frames[1][4] == 2 and opening['stream']['size_bytes'] == len(body)
assert ending['stream_end']['bytes_sent'] == len(body)
assert ending['stream_end']['sha256'] == hashlib.sha256(body).hexdigest()

with tempfile.TemporaryDirectory(prefix='burpctl-release-check-') as directory:
    release.root = Path(directory)
    inputs = ['cli/Cargo.toml', 'extension/build.gradle.kts',
              release.cli_path(target), 'extension/build/libs/burpctl-extension.jar']
    for relative in inputs:
        destination = release.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, destination)
    release.check_release(target)
    cli = release.root / release.cli_path(target)
    missing = cli.with_suffix('.missing')
    cli.rename(missing)
    try:
        release.check_release(target)
        raise AssertionError('Missing CLI accepted')
    except FileNotFoundError:
        pass
    finally:
        missing.rename(cli)
    # The source config claims a different release; artifacts must not be relabeled.
    version = release.tomllib.loads((release.root / 'cli/Cargo.toml').read_text())['package']['version']
    for relative in ['cli/Cargo.toml', 'extension/build.gradle.kts']:
        path = release.root / relative
        path.write_text(path.read_text().replace(f'version = "{version}"', 'version = "99.0.0"'))
    try:
        release.check_release(target)
        raise AssertionError('Stale extension accepted')
    except ValueError as error:
        assert 'Extension artifact version' in str(error)
    jar = release.root / 'extension/build/libs/burpctl-extension.jar'
    with zipfile.ZipFile(jar) as package:
        entries = {name: package.read(name) for name in package.namelist()}
    entries['META-INF/MANIFEST.MF'] = entries['META-INF/MANIFEST.MF'].replace(
        f'Implementation-Version: {version}'.encode(), b'Implementation-Version: 99.0.0')
    with zipfile.ZipFile(jar, 'w') as package:
        for name, data in entries.items():
            package.writestr(name, data)
    try:
        release.check_release(target)
        raise AssertionError('Stale CLI accepted')
    except ValueError as error:
        assert 'CLI artifact version' in str(error)
print('PASS: golden bytes/hash, matching artifact versions, missing/stale CLI/JAR denial')
