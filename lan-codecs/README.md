# lan-codecs

Offline C++20 UDS, LDN and Zstd codecs. This module handles bounded wire representations, not MHXX/MHGU gameplay translation or network transport. See the [gateway](../citra-gateway/README.md) for the runnable bridge.

## Build and test

From this repository root, with Windows PowerShell 5.1 or PowerShell 7:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./lan-codecs/build.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File ./lan-codecs/test.ps1
./lan-codecs/build/lan-codecs.exe --help
```

The default toolchain is `G:/msys64/mingw64`; override build parameter `-ToolchainRoot` if needed. Requires installed zstd headers and static library. Outputs and verification logs are under `lan-codecs/build/`.

## API and limits

[lan_codecs.h](include/lan_codecs.h) defines explicit byte serialization: a 22-byte UDS header, opaque application body capped at 0x5C6 bytes, 0x40-byte NodeInfo, 0x480-byte NetworkInfo, six LDN body types and bounded Zstd encode/decode. No native structure reinterpretation or socket is required. Invalid lengths, enums, trailing data and invalid/unknown-size compressed frames are rejected under the relevant codec rules.

The CLI supports `uds-decode`, `uds-encode`, `node-decode`, `network-decode`, `ldn-decode`, `zstd-decode` and `zstd-encode`. Hex input may be literal or `@path` to an offline fixture. Numeric arguments are unsigned decimal. See [fixtures](fixtures) and [tests](tests) for synthetic examples and checks.

Updated 2026-10-22. GPL-3.0-or-later; see [LICENSE.txt](LICENSE.txt) and [zstd notice](THIRD-PARTY-zstd-LICENSE.txt).
