"""Verify the archive, its executable and all corresponding source hashes."""
from pathlib import Path
from hashlib import sha256
from zipfile import ZipFile
import json

here = Path(__file__).resolve().parents[1]
out = here / '.build-desktop'
package = out / 'XXGU-Gateway'
manifest = json.loads((package / 'BUILD-MANIFEST.json').read_text())
with ZipFile(out / f"XXGU-Gateway-{manifest['version']}-win64.zip") as archive:
    assert archive.testzip() is None
    exe = archive.read('XXGU-Gateway/XXGU-Gateway.exe')
    assert sha256(exe).hexdigest() == manifest['executable_sha256']
    assert exe == (package / 'XXGU-Gateway.exe').read_bytes()
with ZipFile(package / 'SOURCE-CODE.zip') as archive:
    assert archive.testzip() is None
    assert set(archive.namelist()) == set(manifest['sources'])
    for name, expected in manifest['sources'].items():
        assert sha256(archive.read(name)).hexdigest() == expected, name
    assert all('.private-runtime' not in name and '.build-' not in name for name in archive.namelist())
print('PASS: portable archive, executable, source archive and all source hashes match; no private runtime/build files.')
