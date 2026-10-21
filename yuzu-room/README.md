# crossplay/yuzu-room — offline Yuzu room codec foundation

An offline (no ENet, no sockets, no threads) C++20 codec and synchronous client
session for the Yuzu / Nintendo-LDN room protocol, network_version 1, as
implemented by the official read-only reference tree:

    Y = crossplay/reference/yuzu-src-20220923/
          yuzu-windows-msvc-source-20220923-7edc31be2/src

Every wire fact below is cited into that tree as Y/path:line. The bytes are
cross-checked against the captured evidence under
crossplay/real-room-interop/evidence/real/yuzu-ea-2024/ (a real
yuzu-room.exe, protocol v1). This project exists so that G1/G2 Yuzu MHGU local
play can later be reproduced through our own room server; this tree is the
offline protocol + session foundation only.

OFFLINE ONLY. No sockets, no ENet, no threads, no timers, no emulator, no game
data, no network access at runtime. The CLI only reads hex files.

## Layout

| Path | Purpose |
| --- | --- |
| include/yuzu_room/protocol.hpp | constants, enums, message structs, codec API, limits |
| src/protocol.cpp | bounded fail-closed encode/decode, primitives, hex |
| include/yuzu_room/session.hpp | Session, SessionState, SessionOptions |
| src/session.cpp | synchronous client state machine, rejection invariants |
| src/main.cpp | offline emit-join / decode / replay CLI |
| tests/golden.hpp | hand-computed and captured wire goldens with derivation comments |
| tests/test_protocol.cpp | primitives, hex, goldens, ids, declared lengths, limits, names |
| tests/test_session.cpp | state machine, sends, timeouts, termination, fail-closed invariants |
| fixtures/ | replay fixtures (synthetic + captured evidence bytes) |
| build.ps1 | build + test + smoke + PE-evidence driver, prints a machine-readable summary |

## Transport contract

Source of record: Y/network/room.h, Y/network/room.cpp,
Y/network/room_member.{h,cpp}, Y/network/packet.{h,cpp},
Y/common/socket_types.h.

* Transport is ENet over UDP with exactly one channel: NumChannels = 1,
  Y/network/room.h:30. A session only accepts frames on channel 0.
* Every frame starts with a one-byte message id, Y/network/room.h:37-64.
* Integers are big-endian; strings and blobs are u32 length prefixed,
  Y/network/packet.cpp (EncodeString / DecodeString).
* MaxMessageSize = 500, Y/network/room.h:25, is applied by the room to the
  chat message only (Y/network/room.cpp:944-945). The captured 1215-byte LDN
  frame proves the data plane is not capped at 500 bytes.
* Default port DefaultRoomPort = 24872, Y/network/room.h:23; the room admits up
  to MaxConcurrentConnections = 254 members, Y/network/room.h:28.
* The room always sends RoomInformation (id 3) before JoinSuccess (id 2);
  captured evidence confirms room_information_at=0, join_success_at=1 for every
  client.
* ProxyPacket (id 5) and LdnPacket (id 6) are symmetric: the room relays the
  whole original frame byte-for-byte to the destination member and never
  re-encodes it, Y/network/room.cpp:815-925.

## Message ids

Y/network/room.h:37-64. unsupported means the id is defined by the source but
deliberately refused by this codec (moderation needs moderator rights).

| id | name | direction | fields | status in this codec |
| --- | --- | --- | --- | --- |
| 1 | JoinRequest | client -> server | nickname, preferred_fake_ip(4B), version u32, password, token | supported |
| 2 | JoinSuccess | server -> client | assigned fake ip (4B) | supported |
| 3 | RoomInformation | server -> client | name, description, slots u32, port u16, preferred game name, host username, member count u32, members | supported |
| 4 | SetGameInfo | client -> server | name, game id u64, version | supported |
| 5 | ProxyPacket | both (relayed) | family u8, local ip(4B), local port u16, family u8, remote ip(4B), remote port u16, protocol u8, broadcast bool, data | supported |
| 6 | LdnPacket | both (relayed) | type u8, local ip(4B), remote ip(4B), broadcast bool, data | supported |
| 7 | ChatMessage | client -> server: message; server -> client: nickname, username, message | | supported |
| 8 | NameCollision | server -> client | none | server error |
| 9 | IpCollision | server -> client | none | server error |
| 10 | VersionMismatch | server -> client | server network_version u32 | server error |
| 11 | WrongPassword | server -> client | none | server error |
| 12 | CloseRoom | server -> client | none | server error (source only; not in the captured set) |
| 13 | RoomIsFull | server -> client | none | server error |
| 14 | StatusMessage | server -> client | type u8 (1..5), nickname, username | supported |
| 15 | HostKicked | server -> client | none | server error |
| 16 | HostBanned | server -> client | none | server error |
| 17..23 | ModKick, ModBan, ModUnban, ModGetBanList, ModBanListResponse, ModPermissionDenied, ModNoSuchUser | moderator only | not modelled | unsupported (fail closed) |
| 24 | JoinSuccessAsMod | server -> client | assigned fake ip (4B) | supported |

Message names come from Y/network/room.h:38-61.

### Field order and citations

* JoinRequest: Y/network/room_member.cpp:284-296 (sender) and
  Y/network/room.cpp:304-318 (reader): id, nickname, preferred_fake_ip,
  version, password, token.
* JoinSuccess / JoinSuccessAsMod: Y/network/room.cpp:641-659.
* RoomInformation: Y/network/room.cpp:772-801 (BroadcastRoomInformation): id,
  name, description, member_slots u32, port u16, preferred_game.name,
  host_username, members.size() u32, then per member: nickname, fake_ip(4B),
  game_info.name, game_info.id u64, game_info.version, user_data.username,
  display_name, avatar_url.
* SetGameInfo: Y/network/room_member.cpp:668-679; the room reads it at
  Y/network/room.cpp:977-985.
* ProxyPacket: Y/network/room_member.cpp:627-644 (sender) and :354-383
  (reader); the room reads and relays it at Y/network/room.cpp:815-871.
* LdnPacket: Y/network/room_member.cpp:646-659 and :385-404; the room reads and
  relays it at Y/network/room.cpp:873-925.
* Chat: sender Y/network/room_member.cpp:661-666; the room truncates to
  MaxMessageSize and does not echo to the sender, Y/network/room.cpp:927-975
  (nickname, username, message).
* StatusMessage: Y/network/room.cpp:733-748; types at Y/network/room.h:67-73
  (1 MemberJoin, 2 MemberLeave, 3 MemberKicked, 4 MemberBanned,
  5 AddressUnbanned).
* Server errors: Y/network/room.cpp:590-699. Only VersionMismatch carries a
  payload, Y/network/room.cpp:630-639.
* LdnPacketType: Y/network/room_member.h:20-27 (0 Scan, 1 ScanResp, 2 Connect,
  3 SyncNetwork, 4 Disconnect, 5 DestroyNetwork).
* SockAddrIn: Y/common/socket_types.h:41-45; Domain/Protocol names at :11-13 and
  :24-28.

### Join acceptance order (observed by the session and the evidence)

Y/network/room.cpp:295-398: room-full check, then password, then nickname regex,
then IP collision, then version mismatch, then ban. The captured error_order file
agrees (password before version, nickname before version, IP before version).
IsValidNickname is ^[ a-zA-Z0-9._-]{4,20}$, Y/network/room.cpp:550-560;
is_valid_nickname implements exactly that.

## Bounds and fail-closed rules

Hard ceilings (Limits): whole frame 65536 bytes, any single string 4096 bytes,
members 254 (Y/network/room.h:28), data blob 60000 bytes, chat 500 bytes
(Y/network/room.h:25). A caller may only tighten them.

* A u32 declared length is range-checked against the ceiling and against the
  remaining frame before any allocation, so a hostile length cannot allocate.
* Every reader is bounds-checked; a short frame reports Truncated.
* Unknown ids -> UnknownMessage; ids 17..23 -> UnsupportedMessage; an unexpected
  enum byte -> InvalidEnum; a bool other than 0/1 -> InvalidBoolean (the
  reference reader is more lenient, Y/network/packet.cpp, and accepts any
  nonzero; this codec refuses).
* Extra bytes after the last field -> TrailingBytes.
* A message sent the wrong way -> WrongDirection.
* ServerError whose id is not one of the eight, or which carries a payload when
  the id does not define one -> InvalidEnum / InvalidArgument.
* A rejected packet never changes observable session state; the only exception
  is the documented timeout transition (a receive at the deadline moves the
  session to Failed with Timeout).

## Build and test (Windows, MinGW GCC)

    powershell -ExecutionPolicy Bypass -File build.ps1

Default toolchain: G:\msys64\mingw64\bin\g++.exe and ...\objdump.exe (override
with -Compiler / -Objdump; if the compiler path is absent, g++ from PATH is
used). Exit code 0 means: every translation unit compiled warning-free under
-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion, all tests passed, all
9 CLI smoke cases behaved, sha256 of every artifact was printed, and objdump
-f/-p proved the PE x86-64 architecture and imports.

Because the workspace path contains non-ASCII characters, the driver compiles
from the project directory with relative source/object paths plus -pipe and links
the objects explicitly; it does not change global TMP, PATH or the registry (the
PATH edit is restored on exit).

## CLI

    yuzu-room.exe emit-join Test pw1        # -> hex JoinRequest
    yuzu-room.exe decode c2s <hex>          # structured fields of one frame
    yuzu-room.exe decode s2c <hex>          # same for a server frame
    yuzu-room.exe replay rri-a1 fixtures/real-join.s2c.hex

replay feeds one hex frame per line into a Session (line number is the synthetic
millisecond), ignores blank lines and '#' comments, and exits 0 only if the
session reached Joined. Exit codes: 0 success, 1 protocol/state failure, 2 usage
error. Every run prints "OFFLINE ONLY: no ENet, socket, LAN proxy, or room
connection." on usage.

## Fixtures and evidence

| Fixture | Source |
| --- | --- |
| fixtures/join-replay.hex | hand goldens: StatusMessage, RoomInformation, JoinSuccess |
| fixtures/nojoin.hex | the same greeting without JoinSuccess |
| fixtures/real-join.s2c.hex | captured cases/join.s2c.hex (client A), byte-for-byte |
| fixtures/real-proxy.s2c.hex | captured cases/proxy_route.s2c.hex (client A), byte-for-byte |
| fixtures/error-version-mismatch.hex | captured cases/version_mismatch.s2c.hex |

All captured bytes come from
crossplay/real-room-interop/evidence/real/yuzu-ea-2024/cases/; no new raw capture
was added to the repository.

## Provenance and dependencies

* Depends on nothing but the C++ standard library (array, cstdint, optional,
  string, variant, vector, ...). No ENet, no third-party code, no network.
* The wire definitions are derived from the GPL-2.0-or-later yuzu source; this
  tree is therefore GPL-2.0-or-later. See NOTICE.md. Every file carries an SPDX
  header.
* Goldens in tests/golden.hpp are hand-computed from the reference senders or
  copied from the captured evidence (commented per constant); they are not
  produced by the codec under test.

## Facts derived from the reference source (file:line)

| Fact | Citation |
| --- | --- |
| network_version = 1 | Y/network/room.h:21 |
| DefaultRoomPort = 24872 | Y/network/room.h:23 |
| MaxMessageSize = 500 | Y/network/room.h:25 |
| MaxConcurrentConnections = 254 | Y/network/room.h:28 |
| NumChannels = 1 | Y/network/room.h:30 |
| NoPreferredIP = {FF,FF,FF,FF} | Y/network/room.h:34 |
| message ids 1..24 | Y/network/room.h:37-64 |
| status types 1..5 | Y/network/room.h:67-73 |
| join read order + rejection order | Y/network/room.cpp:295-398 |
| nickname regex ^[ a-zA-Z0-9._-]{4,20}$ | Y/network/room.cpp:550-560 |
| VersionMismatch carries u32 | Y/network/room.cpp:630-639 |
| JoinSuccess / JoinSuccessAsMod layout | Y/network/room.cpp:641-659 |
| BroadcastRoomInformation field order | Y/network/room.cpp:772-801 |
| ProxyPacket relay + no sender validation | Y/network/room.cpp:815-871 |
| LdnPacket relay | Y/network/room.cpp:873-925 |
| chat truncation to 500, no echo to sender | Y/network/room.cpp:927-975 |
| SetGameInfo read order | Y/network/room.cpp:977-985 |
| client ConnectionTimeoutMs = 5000 | Y/network/room_member.cpp:17 |
| SendJoinRequest layout | Y/network/room_member.cpp:284-296 |
| SendProxyPacket layout | Y/network/room_member.cpp:627-644 |
| SendLdnPacket layout | Y/network/room_member.cpp:646-659 |
| SendChatMessage layout | Y/network/room_member.cpp:661-666 |
| SendGameInfo layout | Y/network/room_member.cpp:668-679 |
| LDNPacketType 0..5 | Y/network/room_member.h:20-27 |
| Domain::INET = 0 | Y/common/socket_types.h:11-13 |
| Protocol::ICMP/TCP/UDP = 0/1/2 | Y/common/socket_types.h:24-28 |
| IPv4Address = array<u8,4> | Y/common/socket_types.h:38 |
| SockAddrIn { family, ip, portno } | Y/common/socket_types.h:41-45 |
| big-endian, u32 length prefixes | Y/network/packet.cpp |

## What is proven, and what is NOT proven

Proven here (offline, deterministic):

* The encoder reproduces the captured and hand-computed frames byte-for-byte;
  the decoder accepts them and rejects every proper prefix, trailing bytes,
  unknown/unsupported ids, wrong directions and malformed fields.
* Declared lengths are bounded before allocation; all ceilings are enforced.
* The session reaches Joined on RoomInformation + JoinSuccess, refuses
  invariant-breaking rooms, gates client sends, and leaves observable state
  untouched on every rejected packet (asserted by snapshot comparison).

NOT proven — this is an offline codec:

* Nothing about a real room, ENet, latency, ordering, retransmission, NAT or the
  LAN proxy.
* Nothing about Yuzu emulated LDN behaviour, MHGU, or any game content.
* Nothing about ProxyPacket/LdnPacket payload meaning: the codec never
  interprets game payload bytes, and the room itself relays them verbatim.
* No captured SetGameInfo, chat request or moderation flow was exercised against
  a real server here; those layouts are derived from the source only.
* The moderation ids 17..23 are not implemented, so an exchange with them is out
  of scope by construction.

## Open questions, uncertainty and disagreements

1. Disagreement: ProxyPacket family/protocol bytes. The 2022 source defines
   Domain::INET == 0 (Y/common/socket_types.h:11-13) and Protocol::UDP == 2
   (:24-28), but every captured ProxyPacket carries family = 0x01 and
   protocol = 0x03 (for example cases/proxy_route.s2c.hex:
   05 01 c0a82921 1388 01 c0a8200d 1389 03 00 ...). The room never reads either
   byte (Y/network/room.cpp:815-871 relays the frame verbatim), so this codec
   preserves both as opaque u8 and deliberately does not range-check them.
   domain_name/protocol_name return Unknown for the captured values; a test pins
   that.
2. Source vs evidence on sender validation. The captured unjoined_source case
   shows a peer that never joined having its ProxyPacket forwarded, and a local_ip
   that does not need to equal the sender fake IP. The source performs no such
   check either (Y/network/room.cpp:815-871). The server therefore cannot be
   relied on to enforce identity; Session::send enforces the client-side gate
   instead (local endpoint must be the assigned fake IP, remote must be a
   registered member unless broadcast). This is a deliberate, documented
   asymmetry.
3. Chat payload size. The captured chat_limit case shows the server truncating a
   2000-byte client message to 500 bytes on the server->client copy. A
   client-to-server ChatRequest longer than the room limit is accepted by this
   codec up to chat_bytes and cannot be predicted to succeed against a real room.
4. CloseRoom (12) is source-only. No captured CloseRoom frame exists, so its byte
   shape (bare id) is derived from the source alone.
5. Uncatalogued error ids. The eight server-error ids are the only ones the
   reference source defines; IpCollision (9) and NameCollision (8) are
   distinguished from Citra, and Yuzu has no console-id-collision error.
6. Moderation. Ids 17..23 are refused as UnsupportedMessage; behaviour around
   them is not audited.
7. Chat id 7 is direction-overloaded. Client-to-server the payload is a single
   length-prefixed string (Y/network/room_member.cpp:661-666); server-to-client
   it is nickname + username + message (Y/network/room.cpp:927-975). Because the
   wire carries no discriminator, decoding a client frame as a server frame
   fails structurally -- Truncated, because the message text is read as the
   nickname and the username read then runs out of bytes -- and decoding a server
   frame as a client frame fails with TrailingBytes. Only encode() can attribute
   the overflow, so encode(ChatRequest, s2c) and encode(ChatMessage, c2s) are the
   WrongDirection cases and both are asserted. Relatedly, a session refuses to
   leave from Joining: begin_leave requires Joined, so a join still in flight
   cannot be abandoned as a leave (use disconnected() or reset()).

## Licence

GPL-2.0-or-later, matching the yuzu sources the wire format was derived from. See
NOTICE.md for the provenance table and what is not included.

SPDX-License-Identifier: GPL-2.0-or-later
