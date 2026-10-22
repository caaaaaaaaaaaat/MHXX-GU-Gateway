"""Build the V335 release layout: EXE + guide ZIP, separate source ZIP and notes."""
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import json
import re
import shutil

here = Path(__file__).resolve().parent
root = here.parents[1]
out = here / '.build-desktop'
package = out / 'XXGU-Gateway'
version = re.search(r'AppVersion\[\] = L"(V\d+)"', (here / 'src/main.cpp').read_text(encoding='utf-8')).group(1)
notes = (here / 'releases' / f'{version}.md').read_text(encoding='utf-8')
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
    'version': version,
    'executable_sha256': sha256((package / 'XXGU-Gateway.exe').read_bytes()).hexdigest(),
    'sources': {file.relative_to(root).as_posix(): sha256(file.read_bytes()).hexdigest()
                for file in sorted(source_files)},
}
(package / 'BUILD-MANIFEST.json').write_bytes((json.dumps(manifest, indent=2) + '\n').encode())
release = out / f'release-{version}'
release.mkdir(exist_ok=True)
shutil.copyfile(package / 'XXGU-Gateway.exe', release / 'XXGU-Gateway.exe')
guide = (here / 'USER-GUIDE.md').read_text(encoding='utf-8-sig')
guide = guide.replace('对应源码和构建脚本见随包 `SOURCE-CODE.zip`；许可证及第三方说明随包附带。',
    f'项目源码与构建说明：https://github.com/caaaaaaaaaaaat/MHXX-GU-Gateway 。完整对应源码归档 `XXGU-Gateway-{version}-source.zip` 作为同一 Release 的独立附件提供。')
guide += '\n\n## 开源许可\n\n'
for name in ['LICENSE-GPL3.txt', 'LICENSE-ENet.txt', 'LICENSE-fmt.txt', 'LICENSE-zstd.txt']:
    guide += f'<details>\n<summary>{name}</summary>\n\n```text\n'
    guide += (package / name).read_text(encoding='utf-8-sig')
    guide += '\n```\n\n</details>\n\n'
(release / '使用说明.md').write_text(guide, encoding='utf-8')
(release / '发布说明.md').write_text(notes, encoding='utf-8')
target = out / f'XXGU-Gateway-{version}-release-win64.zip'
with ZipFile(target, 'w', ZIP_DEFLATED) as archive:
    for name in ['XXGU-Gateway.exe', '使用说明.md']:
        archive.write(release / name, name)
source_target = out / f'XXGU-Gateway-{version}-source.zip'
shutil.copyfile(package / 'SOURCE-CODE.zip', source_target)
print(f'Release: {target.name}; Source: {source_target.name}; notes: {release / "发布说明.md"}')
