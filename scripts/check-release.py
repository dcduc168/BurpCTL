"""Validate matching native CLI and Java extension release artifacts."""
import argparse
import platform
from pathlib import Path
import struct
import subprocess
import tomllib
import zipfile

root = Path(__file__).resolve().parents[1]


TARGETS = {
    'x86_64-pc-windows-msvc': b'MZ',
    'x86_64-unknown-linux-gnu': b'\x7fELF',
    'aarch64-unknown-linux-gnu': b'\x7fELF',
    'x86_64-apple-darwin': b'\xcf\xfa\xed\xfe',
    'aarch64-apple-darwin': b'\xcf\xfa\xed\xfe',
}


def native_target() -> str:
    architecture = {'AMD64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    system = {'Windows': 'pc-windows-msvc', 'Linux': 'unknown-linux-gnu', 'Darwin': 'apple-darwin'}[platform.system()]
    return f'{architecture}-{system}'


def cli_path(target: str) -> Path:
    return Path('cli/target') / target / 'release' / ('burpctl.exe' if 'windows' in target else 'burpctl')


def check_release(target: str | None = None) -> str:
    target = target or native_target()
    version = tomllib.loads((root / 'cli/Cargo.toml').read_text())['package']['version']
    cli = root / cli_path(target)
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
        if not source.read(4).startswith(TARGETS[target]):
            raise ValueError('CLI format does not match the release target')
    actual = subprocess.run([str(cli), '--version'], check=True, capture_output=True, text=True, timeout=15)
    if actual.stdout.strip() != f'burpctl {version}':
        raise ValueError('CLI artifact version does not match the release')
    return version


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=TARGETS, default=native_target())
    args = parser.parse_args()
    try:
        version = check_release(args.target)
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        parser.exit(1, f'Release check failed: {error}\n')
    print(f'PASS: BurpCTL {version} release artifacts')
