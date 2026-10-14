"""Package already-built matching CLI/extension artifacts; never uploads a release."""
import argparse
import hashlib
from pathlib import Path
import struct
import tomllib
import zipfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
version = tomllib.loads((root / 'cli/Cargo.toml').read_text())['package']['version']
cli = root / 'cli/target/x86_64-pc-windows-msvc/release/burpctl.exe'
extension = root / 'extension/build/libs/burpctl-extension.jar'
if f'version = "{version}"' not in (root / 'extension/build.gradle.kts').read_text():
    raise SystemExit('CLI and extension versions do not match')
with zipfile.ZipFile(extension) as jar:
    if any(name.startswith('burp/api/') for name in jar.namelist()):
        raise SystemExit('Montoya classes must not be bundled')
    major = struct.unpack('>H', jar.read('dev/burpctl/BurpCtlExtension.class')[6:8])[0]
    if major != 65:
        raise SystemExit('Extension entrypoint must target Java 21 bytecode')
artifacts = {cli.name: cli.read_bytes(), extension.name: extension.read_bytes()}
if not artifacts[cli.name].startswith(b'MZ'):
    raise SystemExit('CLI is not a native Windows executable')
checksums = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n' for name, data in artifacts.items())
with args.output.open('xb') as output:
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as package:
        for name, data in artifacts.items():
            package.writestr(name, data)
        package.writestr('SHA256SUMS', checksums)
        for relative in ['README.md', 'protocol/SPEC.md', 'skills/burpctl/SKILL.md']:
            package.write(root / relative, relative)
print(f'Packaged BurpCTL {version} protocol 1.0: {args.output}')
