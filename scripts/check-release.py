"""Validate matching Windows CLI and Java extension release artifacts."""
import argparse
from pathlib import Path
import struct
import subprocess
import tomllib
import zipfile

root = Path(__file__).resolve().parents[1]


def check_release() -> str:
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
        if manifest.get('Implementation-Title') != 'BurpCTL':
            raise ValueError('Extension artifact title must be BurpCTL')
        if manifest.get('Implementation-Version') != version:
            raise ValueError('Extension artifact version does not match the release')
    with cli.open('rb') as source:
        if source.read(2) != b'MZ':
            raise ValueError('CLI is not a native Windows executable')
    actual = subprocess.run([str(cli), '--version'], check=True, capture_output=True, text=True, timeout=15)
    if actual.stdout.strip() != f'burpctl {version}':
        raise ValueError('CLI artifact version does not match the release')
    return version


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        version = check_release()
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        parser.exit(1, f'Release check failed: {error}\n')
    print(f'PASS: BurpCTL {version} release artifacts')
