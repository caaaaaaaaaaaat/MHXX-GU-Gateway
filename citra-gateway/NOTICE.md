# NOTICE

crossplay/citra-gateway is part of the crossplay work in this repository.

## License

GPL-2.0-or-later.  Every source file in this tree carries an
`SPDX-License-Identifier: GPL-2.0-or-later` header.

## Derivation

This tree is written for this project.  It links against and derives its wire
model from two sibling trees, both of which are GPL-2.0-or-later:

* crossplay/room-transport - the frozen M2 Yuzu v1 client transport
  (room_transport::Runtime / Transport / Options / Snapshot).  This tree
  compiles that unmodified source and calls only its public header.
* crossplay/citra-room - the frozen Citra v4 offline codec
  (citra_room::encode / decode / Limits / message ids).  This tree compiles
  that unmodified source and calls only its public header.
* crossplay/room-client - the frozen Yuzu v1 codec used by room-transport.
* crossplay/citra-control - the G-b' control-plane library
  (citra_control::ControlPlane, LDN and UDS frame codecs, field mapping).  This
  tree compiles that unmodified source and calls only its public headers; it
  never hand writes an LDN or UDS byte.

No upstream file is copied verbatim into this tree.  The wire definitions
(message ids, field order, error semantics) are derived from

* citra-master/src/network/room.h and room.cpp (Citra GPL-2.0-or-later), and
* 01052024-yuzu-mirror-master/src/network/room.h and room.cpp (GPL-2.0-or-later),

and are recorded in docs/M4-ADAPTER-SPEC.md.

## No game data

This tree contains no ROM, no key, no save file and no packet capture.  Every
fixture in tests/test_gateway.cpp is generated in code from a deterministic
synthetic byte pattern (see synthetic_payload) and every Zstd frame used in a
test is compressed at run time from those bytes.

## Scope statement

This tree implements the structural bridge of acceptance item M4-gateway
(G-b) plus the G-b' control-plane bridge of docs/M4-CONTROL-PLANE.md section 7
(the bridge is off by default).  A passing run says that synthetic Citra v4
clients, this gateway and the unmodified Yuzu v1 room sources agree on the
loopback protocol.  It does not say that a real Yuzu client receives data
(tier B, needs G2) and it does not say that a game is playable (tier C, needs
M5).  See README.md and docs/citra-gateway-report.md section 13.
