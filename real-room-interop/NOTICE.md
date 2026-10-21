# Provenance and licensing — crossplay/real-room-interop

SPDX-License-Identifier: GPL-2.0-or-later

This directory is a test harness for **real room-server interoperability**. It links
the frozen M2 client transport/codec of `crossplay/room-transport` and
`crossplay/room-client` (both GPL-2.0-or-later), and — in Self mode only — it links
the **unmodified** original room sources of the workspace mirror
`01052024-yuzu-mirror-master`. Those upstream files are never copied into this
tree: they are compiled in place by `build.ps1` and their SHA256 is checked before
and after every build.

## Upstream sources read or linked

| Package | Upstream paths | Notice |
| --- | --- | --- |
| yuzu / 01052024 mirror | `01052024-yuzu-mirror-master/src/network/room.cpp` / `room.h` | `// Copyright 2023 yuzu Emulator Project` / `// Licensed under GPLv2 or any later version` / `// Refer to the license.txt file included.` |
| yuzu / 01052024 mirror | `.../src/network/packet.cpp` / `packet.h` | same notice |
| yuzu / 01052024 mirror | `.../src/network/verify_user.cpp` / `verify_user.h` | same notice |
| yuzu / 01052024 mirror | `.../src/common/{common_types.h,socket_types.h,announce_multiplayer_room.h}`, `.../src/web_service/web_result.h` | same notice (headers only) |
| Citra Emulator Project | `citra-master/src/network/room*.{h,cpp}`, `packet.*` | `// Copyright 2017 Citra Emulator Project` / `// Licensed under GPLv2 or any later version` / `// Refer to the license.txt file included.` |
| ENet 1.3.18 (vendored by room-transport) | `crossplay/room-transport/vendor/enet-2662c0de...` | MIT licence, vendored file lists its own notice |
| fmt 10.2.1 (vendored by room-transport) | `crossplay/room-transport/vendor/fmt-e69e5f97...` | MIT licence, header-only, notice kept in the vendored copy |
| zstd | `G:/msys64/mingw64/{include,lib}` (system) | BSD-3-Clause, not redistributed here |

The complete GPLv2 text is at `01052024-yuzu-mirror-master/license.txt` and
`citra-master/license.txt`; it is not duplicated here.

## Licence of this tree

The harness sources in `src/`, the scripts in `tools/` and `build.ps1` are a
derivative work of the GPL-2.0-or-later sources above (the wire layouts, the
message numbering and the room state machine follow them exactly), so this tree is
distributed under **GPL-2.0-or-later**. Every source, header and script file in
this tree carries `SPDX-License-Identifier: GPL-2.0-or-later`.

## What is *not* included or shipped

* No emulator, room binary, game, ROM, save file, key, or firmware is copied into
  this tree. Real-mode evidence contains only hashes, byte counts, endpoint
  listings, command lines, counter lines and the **harness's own synthetic wire
  frames** (hex dumps of packets produced by this project's test clients).
* No byte from a real server's own output is redistributed beyond the bounded
  stdout/stderr capture files that the harness writes while it supervises that
  server; those files stay under `evidence/<mode>/<tag>/server/` inside this tree.
* Nothing in this tree contacts a public or official service. The only network
  activity is loopback (127.0.0.1) ENet traffic between this harness and a room
  server it started itself.
* Real-mode execution is refused unless the operator passes `-AllowRun`; the
  candidate executable must match the authorisation identity table
  (path + byte count + SHA256) recorded in `docs/AUTHORIZATIONS.md`, otherwise the
  run is refused and no evidence is produced.
