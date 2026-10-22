"""Verify the archive, its executable and all corresponding source hashes."""
from pathlib import Path
from hashlib import sha256
from zipfile import ZipFile
import json

here = Path(__file__).resolve().parents[1]
out = here / '.build-desktop'
package = out / 'XXGU-Gateway'
manifest = json.loads((package / 'BUILD-MANIFEST.json').read_text())
artifacts = json.loads((out / 'artifacts.json').read_text(encoding='utf-8-sig'))
assert artifacts['version'] == manifest['version']
assert artifacts['executable_sha256'] == manifest['executable_sha256']
for entry in artifacts['inputs']:
    assert sha256((here / entry['path']).read_bytes()).hexdigest() == entry['sha256'], entry['path']
with ZipFile(out / f"XXGU-Gateway-{manifest['version']}-release-win64.zip") as archive:
    assert archive.testzip() is None
    assert archive.namelist() == ['XXGU-Gateway.exe', '使用说明.md']
    exe = archive.read('XXGU-Gateway.exe')
    assert sha256(exe).hexdigest() == manifest['executable_sha256']
    assert exe == (package / 'XXGU-Gateway.exe').read_bytes()
    guide = archive.read('使用说明.md').decode('utf-8').replace('\r\n', '\n')
    assert f"XXGU-Gateway-{manifest['version']}-source.zip" in guide
    assert '随包 `SOURCE-CODE.zip`' not in guide
    for name in ['LICENSE-GPL3.txt', 'LICENSE-ENet.txt', 'LICENSE-fmt.txt', 'LICENSE-zstd.txt']:
        assert (package / name).read_text(encoding='utf-8-sig') in guide
source_zip = out / f"XXGU-Gateway-{manifest['version']}-source.zip"
assert source_zip.read_bytes() == (package / 'SOURCE-CODE.zip').read_bytes()
with ZipFile(source_zip) as archive:
    assert archive.testzip() is None
    assert set(archive.namelist()) == set(manifest['sources'])
    for name, expected in manifest['sources'].items():
        assert sha256(archive.read(name)).hexdigest() == expected, name
        assert sha256((here.parents[1] / name).read_bytes()).hexdigest() == expected, name
    assert all('.private-runtime' not in name and '.build-' not in name for name in archive.namelist())
notes = out / f"release-{manifest['version']}" / '发布说明.md'
assert notes.read_text(encoding='utf-8') == (here / 'releases' / f"{manifest['version']}.md").read_text(encoding='utf-8')
print('PASS: V335 layout (EXE + guide only), embedded licenses, separate source ZIP, current source hashes and release notes.')
