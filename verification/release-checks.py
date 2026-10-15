"""Focused checks for golden frames, stale artifacts and failed release cleanup."""
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
spec = importlib.util.spec_from_file_location('release', root / 'scripts/package-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

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
    inputs = ['cli/Cargo.toml', 'extension/build.gradle.kts', 'README.md', 'protocol/SPEC.md', 'skills/burpctl/SKILL.md', 'verification/README.md',
              'cli/target/x86_64-pc-windows-msvc/release/burpctl.exe', 'extension/build/libs/burpctl-extension.jar']
    for relative in inputs:
        destination = release.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, destination)
    output = release.root / 'release.zip'
    release.package_release(output)
    with zipfile.ZipFile(output) as package:
        assert package.testzip() is None
        assert set(package.namelist()) == {'burpctl.exe', 'burpctl-extension.jar', 'SHA256SUMS', 'README.md', 'protocol/SPEC.md', 'skills/burpctl/SKILL.md', 'verification/README.md'}
        for line in package.read('SHA256SUMS').decode().splitlines():
            digest, name = line.split('  ', 1)
            assert hashlib.sha256(package.read(name)).hexdigest() == digest
    original = output.read_bytes()
    try:
        release.package_release(output)
        raise AssertionError('Existing output overwritten')
    except FileExistsError:
        assert output.read_bytes() == original
    output.unlink()
    skill = release.root / 'skills/burpctl/SKILL.md'
    skill.unlink()
    try:
        release.package_release(output)
        raise AssertionError('Missing input accepted')
    except FileNotFoundError:
        assert not output.exists()
    shutil.copy2(root / 'skills/burpctl/SKILL.md', skill)
    original_zip = zipfile.ZipFile

    class FailingZip(original_zip):
        def writestr(self, name, data, *args, **kwargs):
            if name == 'skills/burpctl/SKILL.md':
                raise OSError('Injected archive write failure')
            return super().writestr(name, data, *args, **kwargs)

    try:
        release.zipfile.ZipFile = FailingZip
        try:
            release.package_release(output)
            raise AssertionError('Write failure ignored')
        except OSError:
            assert not output.exists()
    finally:
        release.zipfile.ZipFile = original_zip
    # The source config claims a different release; artifacts must not be relabeled.
    version = release.tomllib.loads((release.root / 'cli/Cargo.toml').read_text())['package']['version']
    for relative in ['cli/Cargo.toml', 'extension/build.gradle.kts']:
        path = release.root / relative
        path.write_text(path.read_text().replace(f'version = "{version}"', 'version = "99.0.0"'))
    try:
        release.package_release(output)
        raise AssertionError('Stale extension accepted')
    except ValueError as error:
        assert 'Extension artifact version' in str(error) and not output.exists()
    jar = release.root / 'extension/build/libs/burpctl-extension.jar'
    with original_zip(jar) as package:
        entries = {name: package.read(name) for name in package.namelist()}
    entries['META-INF/MANIFEST.MF'] = entries['META-INF/MANIFEST.MF'].replace(
        f'Implementation-Version: {version}'.encode(), b'Implementation-Version: 99.0.0')
    with original_zip(jar, 'w') as package:
        for name, data in entries.items():
            package.writestr(name, data)
    try:
        release.package_release(output)
        raise AssertionError('Stale CLI accepted')
    except ValueError as error:
        assert 'CLI artifact version' in str(error) and not output.exists()
print('PASS: golden bytes/hash, matching artifact versions, stale CLI/JAR denial, missing/write-failure cleanup and no-clobber')
