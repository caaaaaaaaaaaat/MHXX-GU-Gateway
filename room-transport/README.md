# M2a native ENet / original Room source interoperability

**Not a MHXX↔MHGU gameplay bridge. M2b (the user's complete unmodified Yuzu / room distribution binary) is untested. M4–M6 are not completed.**

This standalone GPL-2.0-or-later project adds a native ENet transport over the sibling M1 bounded codec/session. Its harness compiles the **unchanged** original [Room implementation](../../01052024-yuzu-mirror-master/src/network/room.cpp), [Packet implementation](../../01052024-yuzu-mirror-master/src/network/packet.cpp), and [verification implementation](../../01052024-yuzu-mirror-master/src/network/verify_user.cpp). It calls the original Room::Create with the original VerifyUser::NullBackend: a source-provided self-hosted mode without web validation, not a bypass of any real service or paid authentication. No emulator, plugin, or M1 source is edited. No public/official room is contacted.

## Offline rebuild / bounded test

In Windows PowerShell 5.1, from this directory:

~~~powershell
./build.ps1 -RunTests
~~~

Uses absolute G:/msys64/mingw64/bin/gcc.exe, g++.exe and objdump.exe. GCC compilation is direct, -pipe, each source to an ASCII-relative object path, then a separate static link. This avoids the local GCC/non-ASCII TEMP path problem without global installation, PATH/TEMP modification, CMake or Ninja. The existing G:/msys64/mingw64/include/zstd.h and lib/libzstd.a are required. ENet and fmt are fully local; vendor hashes are checked first. The original source collection and sibling M1 source must remain in their current relative locations. No emulator executable is downloaded or used.

Outputs under build-mingw: commands.txt, toolchain.txt, test.stdout.log, test.stderr.log, test-exit.txt, artifacts-sha256.json, pe-dependencies.txt, and room_transport_loopback.exe. The build script watchdog kills a test process exceeding 45 seconds; each network wait is individually bounded. The executable listens only on 127.0.0.1:39472; a conflicting local port is a reported failure, never a fallback to an external service. Stop other copies before running it. All clients and server belong to the harness. No real Yuzu client receives test traffic.

## Transport contract

[Public API](include/room_transport/transport.hpp) and [implementation](src/transport.cpp):

- No worker thread. The application regularly calls poll(wait_ms), with wait 0..5ms and at most one ENet event per call. Application starvation can delay deadline detection until the next poll. No reconnect loop.
- Every public operation locks the same mutex. Concurrent snapshot/poll/send/leave is serialized. Object destruction still requires the owner to ensure no other call is in flight; this is not a DLL unload protocol.
- States: Idle → Connecting → Joining → Joined → Leaving → Idle; failures → Failed, explicit stop before restarting. Session uses steady_clock milliseconds. Defaults: connect/join 1500ms, leave 500ms. The native host is force-released on deadlines.
- Channel 0, ENET_PACKET_FLAG_RELIABLE only. M1 Session validates direction, membership, RoomInformation-before-success, assigned local identity, enum/bool/size bounds. Pre-membership application sends are refused.
- Default packet cap 65536, data 60000, string 4096, members 254; receive queue 128 messages / 262144 bytes; ENet maximumWaitingData 262144; outstanding outgoing 64 packets / 262144 bytes. Each configurable queue has a hard maximum 1024 packets / 4194304 bytes.
- Outgoing budget covers native ENet packets **until ACK or reset**, not merely until host_flush. Packet freeCallback releases the ticket; the ticket shares its budget lifetime safely. Backpressure returns false rather than growing memory indefinitely. Inbound overflow fails closed and clears identity/data.
- Snapshot contains core identity/room, last server error and native resource counters. Failure clears data queues/identity, destroys host, and retains error diagnostics. stop is idempotent and services graceful disconnect until its bounded deadline, then destroys ENet resources. Root Runtime initializes/deinitializes ENet with a serialized reference count. Each Transport owns a Runtime.
- This milestone intentionally rejects any address other than numeric 127.0.0.1. It is a test/library foundation, not a general public-room client CLI.

## Original-source support boundary

[Logging support](support/include/common/logging/log.h) is the only shadow header: it maps LOG_INFO / LOG_ERROR to stderr through vendored real fmt, and supplies the fmt/format.h declaration used by unchanged Room code. It does not shadow network/room.h, network/packet.h, member validation, routing, verification, common types, socket enums, announce definitions, or web_result. Original common/common_types.h, common/socket_types.h, common/announce_multiplayer_room.h and web_service/web_result.h are compiled directly. The Room/Packet/verify sources remain in the original tree; build integrity records SHA256 before and after.

This is **original Room source implementation + logging support**, not the complete release room binary: the emulator-wide asynchronous logging service, room CLI/configuration, web announcement/token backends, release build system and the user's distribution dependencies are not exercised. The test does not prove release ABI or specific client build compatibility. Source license text is retained in LICENSE.txt; upstream file copyright/SPDX remain untouched.

## Test meaning / limitations

The harness covers automatic FFFFFFFF and specified IPv4, strict RoomInfo→success ordering, independent client membership and join/leave updates, high-bit u64 game ID/version, password/name/IP/version/full-room failures, original Room close, deadlines/resource release, bounded queues/backpressure, concurrent serialized calls, repeat lifecycle and process thread-count return. Three clients check exact recipient sets for LDN Scan empty-payload and Proxy envelopes: unicast, broadcast except sender, unknown destination with no receiver. Proxy uses a real Zstd frame and decompresses it back to exact synthetic bytes.

Version-2 rejection has a narrowly scoped **test-only raw ENet client** using M1 encode/decode, because the normal Session intentionally requires version 1. It sends a fully framed JoinRequest, not malformed packets. No fake server, server fuzzing, arbitrary/unknown LDN payload or game traffic is used.

Room membership and transport routing do not establish Citra UDS↔LDN control translation, socket/UDS application compatibility, hub visibility, quests, four-player or long-duration reliability. The original Room is not hardened by this harness; never expose it to untrusted peers based on this result.

## Dependency provenance

See [vendor provenance](vendor/PROVENANCE.md) and [file integrity manifest](vendor/manifest.json). Only open-source code was downloaded, under this project's vendor directory; no global packages were installed. Test result/evidence is recorded in [M2 report](../../docs/room-transport-m2-report.md).
