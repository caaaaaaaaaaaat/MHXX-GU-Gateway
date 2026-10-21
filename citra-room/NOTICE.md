# Provenance and licensing — crossplay/citra-room

SPDX-License-Identifier: GPL-2.0-or-later

This directory is an independent, offline re-implementation of the **Citra room
wire format** (`network_version` 4). It was written for this cross-emulator
project by reading the upstream sources listed below. Their notices are
reproduced here.

## Upstream sources read

| Package | Upstream paths | Notice |
| --- | --- | --- |
| Citra Emulator Project | `citra-master/src/network/packet.h`, `packet.cpp` | `// Copyright 2017 Citra Emulator Project` / `// Licensed under GPLv2 or any later version` / `// Refer to the license.txt file included.` (packet.h:1-3) |
| Citra Emulator Project | `citra-master/src/network/room.h`, `room.cpp` | same notice (room.h:1-3) |
| Citra Emulator Project | `citra-master/src/network/room_member.h`, `room_member.cpp` | same notice (room_member.h:1-3) |

The complete GPLv2 text is at `citra-master/license.txt`; it is not duplicated
here.

## Licence of this tree

No upstream file is copied verbatim into this tree. However, the wire
definitions here — the message-id numbering, the enum value sets, the struct
field orders and the byte-level layouts — are **derived** from the
GPL-2.0-or-later sources above, so this tree is a derivative work and is itself
distributed under **GPL-2.0-or-later**. Every source, header, test and script
file in this tree carries `SPDX-License-Identifier: GPL-2.0-or-later`.

## What is *not* included

Nothing from `01052024-yuzu-mirror-master/`, `Luma3DS-plugin/`, the other
`crossplay/` trees, or any game/ROM/save/key data is included or referenced by
this code. The hex goldens in `tests/golden.hpp` are hand-computed from the
layout of the upstream senders (see the source references in that file and in
`docs/citra-room-report.md`); they were not produced by this codec.
