"""Package already-built matching CLI/extension artifacts; never uploads a release."""
import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import tomllib
import zipfile

root = Path(__file__).resolve().parents[1]


def package_release(output: Path) -> str:
    version = tomllib.loads((root / 'cli/Cargo.toml').read_text())['package']['version']
    cli = root / 'cli/target/x86_64-pc-windows-msvc/release/burpctl.exe'
    extension = root / 'extension/build/libs/burpctl-extension.jar'
    if f'version = "{version}"' not in (root / 'extension/build.gradle.kts').read_text():
        raise ValueError('CLI and extension build versions do not match')
    with zipfile.ZipFile(extension) as jar:
        if any(name.startswith('burp/api/') for name in jar.namelist()):
            raise ValueError('Montoya classes must not be bundled')
        major = struct.unpack('>H', jar.read('dev/burpctl/BurpCtlExtension.class')[6:8])[0]
        if major != 65:
            raise ValueError('Extension entrypoint must target Java 21 bytecode')
        manifest = dict(line.split(': ', 1) for line in jar.read('META-INF/MANIFEST.MF').decode().splitlines() if ': ' in line)
        if manifest.get('Implementation-Version') != version:
            raise ValueError('Extension artifact version does not match the release')
    cli_bytes = cli.read_bytes()
    if not cli_bytes.startswith(b'MZ'):
        raise ValueError('CLI is not a native Windows executable')
    actual = subprocess.run([str(cli), '--version'], check=True, capture_output=True, text=True, timeout=15)
    if actual.stdout.strip() != f'burpctl {version}':
        raise ValueError('CLI artifact version does not match the release')
    artifacts = {cli.name: cli_bytes, extension.name: extension.read_bytes()}
    checksums = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n' for name, data in artifacts.items())
    artifacts['SHA256SUMS'] = checksums.encode()
    for relative in ['README.md', 'protocol/SPEC.md', 'skills/burpctl/SKILL.md']:
        artifacts[relative] = (root / relative).read_bytes()
    # Only a file created by this invocation is removed on failure.
    handle = output.open('xb')
    try:
        with handle, zipfile.ZipFile(handle, 'w', compression=zipfile.ZIP_DEFLATED) as package:
            for name, data in artifacts.items():
                package.writestr(name, data)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return version


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        version = package_release(args.output)
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        parser.exit(1, f'Packaging failed: {error}\n')
    print(f'Packaged BurpCTL {version} protocol 1.0: {args.output}')
