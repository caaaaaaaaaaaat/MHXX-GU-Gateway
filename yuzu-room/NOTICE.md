# Provenance and licensing — crossplay/yuzu-room

SPDX-License-Identifier: GPL-2.0-or-later

This directory is an independent offline re-implementation of the Yuzu /
Nintendo-LDN room protocol version 1. It reproduces the wire format from the
read-only reference source and the captured evidence, but contains no yuzu code,
no ENet code, no emulator code and no game data.

## Upstream sources read

| Upstream | Path (read-only) | Notice |
| --- | --- | --- |
| yuzu | crossplay/reference/yuzu-src-20220923/yuzu-windows-msvc-source-20220923-7edc31be2/src/network/room.{h,cpp} | Copyright (C) 2017 yuzu Emulator Project; GPL-2.0-or-later |
| yuzu | .../src/network/room_member.{h,cpp} | as above |
| yuzu | .../src/network/packet.{h,cpp} | as above |
| yuzu | .../src/common/socket_types.h | as above |
| yuzu | .../src/dedicated_room/yuzu_room.cpp | as above |
| evidence | crossplay/real-room-interop/evidence/real/yuzu-ea-2024/ | captured from a real yuzu-room.exe by this repository |

## Licence of this tree

The wire definitions are derived from GPL-2.0-or-later sources, so this tree is
distributed under GPL-2.0-or-later and every source file carries an SPDX header.

## What is not included

* Nothing copied from yuzu, from Citra, or from any other crossplay project.
* No game data, no save data, no screenshots, no raw capture beyond the evidence
  already committed under crossplay/real-room-interop/.
* No ENet, no socket code, no threads, no third-party libraries.
* The test goldens are hand-computed from the reference senders or copied from
  the existing captured evidence; none was produced by the codec under test.
