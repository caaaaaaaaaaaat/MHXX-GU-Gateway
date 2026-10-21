"""Create the portable archive and matching source archive; exclude local data."""
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import json

here = Path(__file__).resolve().parent
root = here.parents[1]
out = here / '.build-desktop'
package = out / 'XXGU-Gateway'
source_files = set()
for name in ['gateway-gui', 'citra-gateway', 'citra-control', 'citra-room', 'room-client', 'room-transport']:
    base = root / 'crossplay' / name
    for file in base.rglob('*'):
        if not file.is_file():
            continue
        relative = file.relative_to(base)
        if any(part.startswith('.') or part == '__pycache__' for part in relative.parts):
            continue
        if file.suffix.lower() in {'.exe', '.dll', '.o', '.a', '.pyc', '.jsonl', '.zip'}:
            continue
        source_files.add(file)
# Original upstream sources used by integration/regression tests. These are
# explicitly selected; no emulator user data, binaries or game files are copied.
upstream = root / '01052024-yuzu-mirror-master'
source_files.add(upstream / 'LICENSE.txt')
for rel in ['network/room.h', 'network/room.cpp', 'network/packet.h', 'network/packet.cpp',
            'network/verify_user.h', 'network/verify_user.cpp', 'common/common_types.h',
            'common/socket_types.h', 'common/announce_multiplayer_room.h',
            'common/logging/log.h', 'common/string_util.h']:
    source_files.add(upstream / 'src' / rel)
with ZipFile(package / 'SOURCE-CODE.zip', 'w', ZIP_DEFLATED) as archive:
    for file in sorted(source_files):
        archive.write(file, file.relative_to(root).as_posix())
manifest = {
    'version': 'V334',
    'executable_sha256': sha256((package / 'XXGU-Gateway.exe').read_bytes()).hexdigest(),
    'sources': {file.relative_to(root).as_posix(): sha256(file.read_bytes()).hexdigest()
                for file in sorted(source_files)},
}
(package / 'BUILD-MANIFEST.json').write_bytes((json.dumps(manifest, indent=2) + '\n').encode())
target = out / 'XXGU-Gateway-V334-win64.zip'
with ZipFile(target, 'w', ZIP_DEFLATED) as archive:
    for file in sorted(package.iterdir()):
        if file.is_file() and file.suffix.lower() != '.log':
            archive.write(file, 'XXGU-Gateway/' + file.name)
print(f'Portable package: {target.name}; matching source files: {len(source_files)}')
