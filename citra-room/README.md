# crossplay/citra-room — offline Citra room codec foundation

An offline, standard-library-only C++20 library and synthetic harness for the
**Citra room protocol, `network_version` 4**
(`citra-master/src/network/room.h:16`).

**OFFLINE ONLY.** This tree opens no sockets, contains no ENet transport, no
threads, no timers and no emulator code. It never reads a game, ROM, key, token
or save. It does not touch the Yuzu side of this project. It is a codec and
state-machine foundation and is **not** evidence of game interoperability.

## Layout

| Path | Contents |
| --- | --- |
| `include/citra_room/protocol.hpp` | Packet primitives, message structs, `encode`/`decode`, `parse_hex`/`to_hex` |
| `include/citra_room/session.hpp` | Synchronous client session state machine |
| `src/protocol.cpp` | Codec implementation (bounded, fail-closed) |
| `src/session.cpp` | Session implementation |
| `src/main.cpp` | Offline replay / decode CLI |
| `tests/golden.hpp` | Hand-computed hex goldens derived from the Citra sources |
| `tests/test_protocol.cpp` | Codec tests (prefix truncation, length, enum, direction, limits) |
| `tests/test_session.cpp` | Session tests (state invariants on every rejection) |
| `fixtures/*.hex` | Replay fixtures for the CLI |
| `build.ps1` | Build, test, smoke and PE-evidence driver |

The full wire specification, decisions, test inventory, evidence and the
explicit untested list are in
[`docs/citra-room-report.md`](../../docs/citra-room-report.md).

## Build and test (Windows, MinGW GCC)

```powershell
# from G:\抛瓦饮料\跨平台联机\crossplay\citra-room
.\build.ps1
```

The driver defaults to `G:\msys64\mingw64\bin\g++.exe` and
`G:\msys64\mingw64\bin\objdump.exe`; override with `-Compiler` / `-Objdump`.
It exits 0 only when both test binaries pass and all CLI smokes behave.

The workspace path contains non-ASCII characters, and GCC on this machine fails
to create its assembler temporary file when it absolutizes an object path into
it. Every translation unit is therefore compiled from the project directory with
**relative** source and object paths plus `-pipe`, and the objects are linked
explicitly. No global `TMP`/`TEMP`/`PATH` setting or registry change is made.

## CLI

```text
citra-room emit-join NICKNAME              # hex of an IdJoinRequest (no_preferred_mac)
citra-room decode c2s|s2c HEX              # name the frame, or fail with a code
citra-room replay NICKNAME [HEX-FILE]      # one frame per line, 1 synthetic ms per line
```

`#` starts a comment; blank lines are ignored. `replay` exits 0 only if the
replay reaches membership, 1 for a replay that does not (or a protocol error),
and 2 for usage errors. The CLI prints `OFFLINE ONLY: no ENet, socket, UDS
conversion, or room connection.` on bad usage.

## Licence

GPL-2.0-or-later. See [`NOTICE.md`](NOTICE.md).

SPDX-License-Identifier: GPL-2.0-or-later
