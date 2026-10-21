## Per-session dual host mode

`--ldn-dual-host` enables Citra-host and GU-host discovery/admission in the same gateway. It requires `--control-plane`, a full UDS profile (for example `--uds-profile mhxx`), `--ldn-comm-id` and `--ldn-proxy-port`. Static identity pairs are unnecessary: each actual Citra host beacon supplies its seed and the gateway uses that session's assigned native-room IP.

Roles and hall membership are per Citra session. Multiple Citra halls can coexist with GU halls; hosting or closing one hall does not change other sessions' roles. Native local Citra associations are forwarded only within their chosen hall. Legacy single-direction flags retain their previous validation unless dual mode is explicitly enabled. Live dual-direction hall acceptance is pending; quest tests are paused.

# citra-gateway (G-b / G-b' / G-c)

A loopback structural gateway between the Citra v4 room protocol and the Yuzu
v1 room protocol, built for acceptance item M4-gateway (G-b) of this
repository.  Since M4 section 7 it also carries the G-b' control-plane bridge
(Yuzu LDN bodies <-> Citra 802.11/EAPoL frames); the bridge is off by default so
that the G-b evidence stays byte identical, and --control-plane enables it.
Since V-027 the Citra side is served over ENet/UDP, the transport a real Citra
room member speaks.

V-274 adds the opt-in `--ldn-game-return` path for MH control replies from an
admitted Yuzu station whose Citra guest injection completed. It learns both
channels from Citra and wraps replies in LLC/SecureData. This requires
`--control-plane --ldn-announce-forward --ldn-guest-inject --ldn-proxy-port 12345`
and the current session's explicit identity pair. It does not yet establish
game interoperability; scope and validation are in
[V274-GAME-RETURN](../../docs/V274-GAME-RETURN.md).

    real Citra v4 clients (Citra room member: ENet/UDP, one channel,
                           one bare v4 message per reliable packet)
            |
            v
    citra-gateway (this tree)
            |
            v
    original Yuzu v1 room sources (unmodified, in process or as a server)

One Citra client is one Yuzu room peer (ADR-009).  The gateway keeps a session
scoped bidirectional permutation between the Citra 6 byte MAC and the Yuzu
4 byte fake IPv4, and never lets either side see the other side's version
number: the Citra side only ever sees v4, the room only ever sees v1.

## Evidence tiers (do not upgrade these)

* Tier A - structural: what this tree proves.  Synthetic clients, the gateway
  and the unmodified room sources agree on the loopback protocol.
* Tier B - a real Yuzu client receiving data: NOT shown here, needs G2 (the
  socket_proxy.cpp:30-46 local port rule is still an unproven assumption).
* Tier C - a game is playable: NOT shown here, needs M5.

Nothing in this tree, its tests or its comments claims tier B or tier C.

The CLI script parser has a separate regression suite (V-135), run from the
workspace root after building:

```powershell
python crossplay/citra-gateway/tests/test_cli.py
```

It invokes the built CLI with `--game-script ... --help` and exits before
network initialization. This covers directive parsing in `main.cpp`, which the
Options-based gateway harness does not exercise. Set `CITRA_GATEWAY_TEST_EXE`
to test a different executable. The suite is not yet invoked by `build.ps1`.

## Layout

    include/citra_gateway/identity.hpp   MAC <-> fake IPv4 session map (ADR-009)
    include/citra_gateway/control.hpp    G-b' ControlBridge, one per Citra session
    include/citra_gateway/gateway.hpp    gateway API, counters, snapshots, JSON
    src/identity.cpp                     identity table
    src/control.cpp                      G-b' event table -> citra_control calls
    src/gateway.cpp                      single threaded non blocking gateway
    src/main.cpp                         CLI (--self-check, --dump, ...)
    tests/test_identity.cpp              identity unit checks
    tests/test_gateway.cpp               acceptance groups A1..A10 plus B1/B2/B3/B4
    build.ps1                            per source -pipe -c, then explicit link
    README.md, NOTICE.md

## Offline verification (V-231)

See [boundary and zero-FCS regression](../../docs/MH-GATEWAY-OFFLINE-BOUNDARY.md). From the workspace root:

    powershell -NoProfile -File crossplay/citra-gateway/build.ps1 -OfflineVerify -OfflineOutput .build-offline-new-label -SkipRepro

Use a fresh ASCII leaf; existing output is refused and old .build-direct is preserved. OfflineVerify and RunTests are mutually exclusive. This still builds all three original targets plus the offline test, but runs only identity and codec/capability tests, including denied Gateway::open calls behind an invalid-IP safety fence: no successful open, CLI, Runtime, ENet init or sockets. Without SkipRepro it rebuilds twice. Default build/RunTests behavior remains separate; RunTests opens loopback sockets.

V-232 adds explicit startup capability requests (not application conversion): `--application-mode legacy-transport|mhxx-mhgu`, `--proxy-profile yuzu-mirror-01052024|yuzu-2022-7edc31be2`. Only legacy+mirror is supported; other/unknown enum values are denied before trace/listener startup in both CLI and API. `--capabilities` is globally reserved and must be the sole argument, including when otherwise used as an old string value; it emits honest offline JSON with conversion/installed-binary verification/production flags false. Legacy still includes existing experimental replay/patch behavior, not a ban on MH bytes. See [capability contract](../../docs/MH-GATEWAY-CAPABILITY-CONTRACT.md) for controlled, separately invoked [CLI probes](tests/test_capabilities.ps1), their synthetic files and no-successful-open boundary.

## Build

PowerShell 5.1.  The only compiler used is G:/msys64/mingw64/bin/g++.exe
(GCC 16.1.0, x86_64-w64-mingw32) with the system zstd.

    cd crossplay/citra-gateway
    powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1

The script compiles every translation unit on its own with a relative ASCII
source and object path (MinGW cannot create assembler temporaries under the
non ASCII workspace path) and then links explicitly.  It builds twice, hashes
the three executables after each build, and fails if the hashes differ.  It
writes .build-direct/artifacts-sha256.json with the hashes of every input and
output.  TMP, TEMP and PATH are never modified.

Add -SkipRepro for a single build.

## Test

    powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -RunTests

This builds, then runs (each under the process watchdog):

    citra-gateway-identity-tests.exe
    citra-gateway.exe --help            (exit 0)
    citra-gateway.exe --self-check      (exit 0)
    citra-gateway.exe --unknown-option  (exit 2)
    citra-gateway.exe --listen 8.8.8.8  (exit 3)
    citra-gateway.exe --listen-port 39999 --room-port 39998 --seconds 1 --quiet --dump .build-direct/cli-dump
    citra-gateway-tests.exe .build-direct/evidence

citra-gateway-tests.exe runs the acceptance groups A1..A10 plus the G-b'
control-plane groups B1_control and B2_control_loopback, the G-c transport group
B3_citra_enet and the V-028 group B4_session_ledger against the unmodified Yuzu
room sources compiled into the
same process, prints one PASS
or FAIL line per assertion, dumps seven JSON documents per group into
.build-direct/evidence, and finishes with

    RESULT cases=N failed=0 groups=G exit=0

build.ps1 then re-checks a subset of those JSON documents with
ConvertFrom-Json and prints ASSERT-OK / ASSERT-FAIL lines plus a
.build-direct/build-summary.txt.

## Acceptance groups

    A1  gateway appears in the room member table (nickname, game name,
        fake IPv4, member_slots, table update after disconnect)
    A2  RoomInformation before JoinSuccess; neither side sees the other version
    A3  one independent hand written hex golden per error mapping
    A3b the same mappings read from the room's own wire bytes
    A4  declared payload category byte identical end to end (hex compared,
        no decode/encode round trip); undeclared categories refused + counted
    A5  fail closed boundaries (LDN exact body size, single frame Zstd with
        known content size and both caps, source member, no self echo,
        destination self or broadcast)
    A6  negative tests: every prefix truncation, trailing bytes, unknown ids,
        unsupported ids, unknown enums, wrong direction, sentinel MAC - all
        refused without changing state and without exiting; plus the V-023 large
        frame cases (501 and 1200 byte data frames relayed byte for byte against
        a hand written golden) and the frozen codec limits (data >60000, chat
        >500) refused
    A7  release regression: after a rejected client, a fresh client joins in
        well under 1000 ms (measured and printed)
    A8  isolation between clients; bounded inbound/outbound queues
    A10 loopback only, explicit port conflict, no background worker threads,
        no leaked ENet hosts
    B1  G-b' control plane, deterministic injection: every event of M4 section
        7.2 is injected as wire bytes and the emitted bytes are compared with
        hand written goldens (beacon fixture, Auth SEQ2, 16 byte
        AssociationResponse, NodeMap, EAPoL-Logoff field window, ScanResponse
        and SyncNetwork field window); every refusal is counted
    B2  G-b' control plane over a real loopback: a raw ENet room member sends
        LDN Scan and Connect and the gateway answers ScanResponse and
        SyncNetwork through the room; the elapsed times are measured and
        printed
     B3  G-c transport: a real ENet/UDP peer (one channel, bare v4 messages)
         joins the gateway, RoomInformation still precedes JoinSuccess, the hand
         written A2/A3 goldens (09 00000004, 07, 0a) survive the wire unchanged,
         a TCP length prefixed join is rejected, and the harness-only TCP
         listener is labelled tcp-test
     B4  V-028 feedback: a v4 SetGameInfo reaches only its own room peer, and
         after the client leaves, clients.json / identities.json still carry its
         nickname, fake IPv4 and Departed phase while counters.json keeps the
         cumulative control counters (control_scope "cumulative")

## Transports

The Citra side is a single channel ENet/UDP server bound to
--listen/--listen-port, exactly like the original room server
(citra-master/src/network/room.cpp:1026 enet_host_create); every packet carries
exactly one bare citra_room v4 message (data[0] is the message id) and there is
no length prefix.  This is the deliverable transport: it is what a real Citra
room member connects to (citra-master/src/network/room_member.cpp:553-563) and
what the B3_citra_enet group exercises with a real ENet peer.  ENet port
conflicts fail loudly at open() (port_conflicts + exit code 3), never silently.

The Yuzu side is unchanged: a v1 ENet room client owned by
room_transport::Transport (one channel, raw room_client v1 messages), plus the
G-b' control-plane bridge on top.

The TCP listener with a 4 byte big endian length prefix is HARNESS ONLY.  It
exists so that the A1..A10, B1 and B2 groups can drive the state machine and the
control plane deterministically with synthetic clients whose framing does not
depend on UDP timing; it is reachable only through the process local option
citra_gateway::Options::citra_tcp_test_transport, which no CLI flag and no
environment variable can set.  It is not the delivery path and it is reported as
"tcp-test" in the transport fields and counters below.

## CLI

    citra-gateway [--listen 127.0.0.1] [--listen-port 24873]
                  [--room 127.0.0.1] [--room-port 24872]
                  [--password text] [--room-capacity n]
                  [--max-inbound-citra 65536]
                  [--control-plane] [--citra-peer-relay] [--emitted-limit 256]
                  [--seconds 5] [--max-clients 254]
                  [--dump dir] [--quiet] [--self-check] [--help]

--password is the room password.  It is enforced locally first (so that a wrong
password is rejected before any nickname/MAC/console-id/version check, exactly
as the Citra server does) and is still forwarded unchanged in the v1 join.
--room-capacity n gives the known member_slots so that the room-full check can
also be made locally; 0 means unknown and disables only that local check (see
the ordering note below).
--max-inbound-citra n is the pre-decode cap for one Citra client frame.  It is
NOT Network::MaxMessageSize: the upstream 500 byte constant only truncates chat
bodies (citra-master/src/network/room.cpp:913-914).  The frozen codec's own data
plane limit is Limits::data_bytes = 60000 and its whole frame limit is
Limits::packet_bytes = 65536, so this guard defaults to 65536 and never silently
drops a legal data frame (V-023).

--control-plane enables the G-b' control-plane bridge for every joined Citra
session (one citra_control::ControlPlane per session): Yuzu LDN Scan / Connect
/ Disconnect / DestroyNetwork bodies are answered with synthesised
ScanResponse / SyncNetwork bodies, and Citra Authentication (SEQ1), EAPoL-Start,
EAPoL-Logoff and Deauthentication frames are answered with Auth SEQ2 plus
AssociationResponse or NodeMap plus EAPoL-Logoff.  Data frames whose LLC type is
Eapol or SecureData join the control path; everything else stays opaque.  Without
the switch the gateway keeps the frozen G-b behaviour (every LDN body refused and
counted).
--citra-peer-relay selects the V-047/V-048 transport-only passthrough for
Citra<->Citra sessions.  Without it only FrameType::Data is forwarded and every
other type (Beacon, Authentication, AssociationResponse, Deauthentication,
NodeMap) is dropped with payload_rejected_unknown_category, so a Citra client
can never discover a room.  With it every WifiPacket type travels the same path
as Data, exactly like the dumb citra-room.exe relay.  The Yuzu ProxyPacket
cannot express the frame type or channel, so the gateway prepends a 7 byte
wrapper -- magic "CRLY" (0x43 0x52 0x4C 0x59), version 0x01, type, channel --
to the plain payload before Zstd and restores both fields on the way back.  A
receiver that does not find the magic (a non-relay peer, or a plain Data frame)
keeps the frozen Data type and placeholder channel.  It is mutually exclusive
with --control-plane (exit 2), because the two describe different topologies.
Counting: peer_relay_frames_emitted / peer_relay_frames_consumed count wrapper
round trips, peer_relay_bad_wrapper counts a CRLY header with an unknown version
or an out-of-range frame type (> 5); all three are 0 while the switch is off.
channel_normalized keeps its meaning ("a placeholder channel was substituted")
and therefore does not increment for a wrapped frame, which carries the original
channel, nor for a Data frame on the relay path.
--emitted-limit n bounds the exported emitted-frame log (default 256).  Every
control-plane frame handed to either side is recorded with its kind, size and
hex bytes and exported as <evidence>.emitted.json / --dump dir/emitted.json.

Exit codes: 0 ok, 2 usage error, 3 open failure (port conflict or a non
loopback listen address; the gateway never silently falls back to another
port).

## Declared protocol decisions

* Identity: Citra 6 byte MAC <-> Yuzu 4 byte fake IPv4, session scoped.
  Citra NoPreferredMac / BroadcastMac (FF:FF:FF:FF:FF:FF) and the Yuzu
  NoPreferredIP sentinel are never stored.  console_id_hash is kept locally,
  never forwarded and never logged.
* Declared payload category: Citra IdWifiPacket with type Data (1) only.  The
  gateway compresses the opaque Citra payload into exactly one standard Zstd
  frame and sends it as a Yuzu IdProxyPacket, and it decompresses an inbound
  IdProxyPacket back into a Citra IdWifiPacket.  The opaque bytes are relayed
  unchanged.
* Declared lossy fields: the Citra channel byte has no Yuzu counterpart (a
  constant 0 is used) and the Yuzu endpoint port has no Citra counterpart (a
  constant 0 is used).  Both are counted.
* Citra SetGameInfo (4): accepted since V-028 and translated under ADR-009 to
  exactly one room_client GameInfo for that client's own v1 room peer (never for
  another session's peer), which is what the original room turns into its
  HandleGameInfoPacket member game info (citra-master/src/network/room.cpp:977).
  While the upstream join is pending, the latest valid metadata is retained in
  one bounded slot and sent only after JoinSuccess; replacement/discard counts
  are explicit. This matches native Citra's immediate post-JoinRequest update.
  An empty name is accepted to clear stopped-game state. A name longer than
  4096 bytes or containing a control byte, a
  session that has not requested to join, or a failed/backpressured room send is refused as
  set_game_info_rejected with an event and never becomes an unknown category.
  The v1 GameInfo has a version field the v4 message does not carry, so the
  declared peer version is used and every such field is counted as
  set_game_info_version_placeholder.
* V317 room UI: every upstream RoomInformation update is projected while joining
  or joined, including native players, current game name/id and departures.
  Native-only players use deterministic locally administered display MACs; these
  are never inserted in the identity table that authorizes game packet routing.
* Joined Citra ChatRequest messages go through that session's native room peer.
  Native ChatMessage replies retain the server-authored nickname, username and
  text. The native room excludes the sender, so no extra echo is synthesized.
  Codec chat limits and outgoing queue budgets remain enforced. Chat before join
  is refused. Other unsupported categories and malformed frames remain refused.
* Citra IdConsoleIdCollision (13) has no Yuzu counterpart.  It is only ever
  produced by this side's own console_id_hash uniqueness check and is counted
  as no_correspondence_rejections; it is never synthesised from a room error.
* Citra's ASSERT is fatal (no NDEBUG), so the gateway only ever emits WifiPacket
  frames of type Data and synthesises no LLC/SecureData at all.  A host's
  transmitter MAC is stable for the whole session.
* Join validation order, matched to citra-master/src/network/room.cpp:302-360:
  closing -> room full -> wrong password -> nickname (regex
  ^[ a-zA-Z0-9._-]{4,20}$ then uniqueness) -> MAC uniqueness -> console_id_hash
  uniqueness -> version != 4.  The first six are decided locally, the version is
  decided last; the unmodified v1 room still re-runs its own checks and its
  errors are mapped back through room_errors_mapped.  With --room-capacity 0
  the room-full check cannot run locally, so multi-fault joins are not
  guaranteed to return the same code as a real Citra server; the default
  in-process host reads member_slots from the room and keeps the full order.

## Control-plane bridge (G-b')

Mapping of docs/M4-CONTROL-PLANE.md section 7.2, one line per event:

    Yuzu Scan (body 0)          -> yuzu_scan          -> unicast ScanResponse (0x480)
    Yuzu ScanResponse           -> none               -> refused, direction counted
    Yuzu Connect (0x40)         -> yuzu_connect       -> SyncNetwork (0x480) per client
    Yuzu SyncNetwork            -> none               -> refused, direction counted
    Yuzu Disconnect (0x40)      -> yuzu_disconnect    -> SyncNetwork per remaining client
    Yuzu DestroyNetwork (0)     -> yuzu_destroy_network -> nothing
    Citra Auth (SEQ1, 6 B)      -> citra_auth_seq1    -> Auth SEQ2 then AssociationResponse
    Citra EAPoL-Start (0x30)    -> citra_eapol_start  -> NodeMap then EAPoL-Logoff
    Citra EAPoL-Logoff / Deauth -> citra_eapol_logoff / citra_deauth -> nothing
    Citra SecureData data frame -> citra_data_in      -> forwarded only when connected
    gateway AP lifecycle        -> ap_created / citra_beacon_sent -> periodic Beacon

Every body length is checked against the frozen citra_control::ldn_body_size
{0, 0x480, 0x40, 0x480, 0x40, 0} before anything else; anything not in the
table is refused and counted (fail closed).  All LDN and UDS bytes come from the
citra-control encoders; this tree never hand writes a control-plane frame.

Declared constants (no capture exists for any of them):

* channel 6, link level Excellent (3), network type Ldn (2), security mode All,
  accept policy AcceptAll, node_count_max 8, node_count = Yuzu clients + 1.
* beacon interval 200 ms; a Beacon is only sent while the plane accepts one
  (otherwise beacon_skipped is counted).
* bssid = 02:00:HH:HH:HH:HH derived from
  FNV-1a("citra-gateway-bssid:" + room_name + ":" + seed) with
  seed = FNV-1a(room_name + ":" + room_port): stable per room, never random and
  never per frame.
* ssid = the room name (deterministic; the fallback "CITRAGWB" is counted as
  ssid_fallback); wlan_comm_id = mix32(seed ^ 0x4E574D00) and network_id =
  mix32(seed ^ 0x55445331) from citra-control; local_communication_id, scene_id,
  session_id, node user names and friend codes stay 0.
* node ids use the first free slot in 1..7; NetworkInfo keeps each station in
  nodes[node_id] through other stations' departure and rejoin. A Connect that
  would exceed 7 stations is refused (ldn_capacity_rejected).
* Connect and Disconnect validate the complete NodeInfo before changing
  membership. Invalid connected enums or unterminated names increment
  ldn_bad_body and emit nothing. A mapped MAC may fill an unusable MAC only in
  an otherwise valid Connect; it cannot rescue a malformed NodeInfo.
* One owner: the joined session with the smallest client id handles inbound LDN.
  Other sessions count ldn_non_owner_ignored.  After an accepted event the other
  joined sessions mirror the plane state without emitting frames (mirror_applied
  / mirror_suppressed); only the owner's bytes reach the wire.

## Declared limitations

* The synthetic Citra client in tests/test_gateway.cpp speaks a bounded
  4 byte big endian length prefixed TCP stream.  The real Citra client speaks
  ENet.  This framing is a harness transport substitute for the offline G-b
  topology only; the real client path is G-c.
* Loopback only.  No emulator, no game, no ROM, no key, no save, no capture and
  no network beyond 127.0.0.1 are involved anywhere in this tree.
* Citra side frame size follows the frozen codec, not the 500 byte
  Network::MaxMessageSize (V-023): Limits::data_bytes = 60000 bounds the data
  body, Limits::packet_bytes = 65536 bounds the whole frame, and the pre-decode
  guard --max-inbound-citra defaults to 65536.  A real Citra client was not run
  (G-c), so the actual client behaviour for large frames is untested; the codec
  is the oracle.

* The control-plane constants above were chosen by this tree; no real
  UDS/LDN exchange was captured, and --control-plane is off by default.
* Citra does not broadcast member changes to already connected clients upstream
  (citra-master/src/core/hle/service/nwm/nwm_uds.cpp:500 TODO), so the gateway
  only answers a Scan with a fresh NetworkInfo and never pushes a member update
  to a connected Citra client.
* Real Citra clients and real 3DS peers are not tested here (G-c); section 13 of
  docs/citra-gateway-report.md lists what the G-b' bridge does not show.

## Machine readable evidence

Every group dumps

    .build-direct/evidence/<group>.counters.json
    .build-direct/evidence/<group>.clients.json
    .build-direct/evidence/<group>.identities.json
    .build-direct/evidence/<group>.captures.json
    .build-direct/evidence/<group>.events.json
    .build-direct/evidence/<group>.snapshot.json
    .build-direct/evidence/<group>.emitted.json

counters.json carries every counter listed in
include/citra_gateway/gateway.hpp, including the per error code
error_map_hits object, the decode_error_codes object and the merged control
plane counter block ("control"), whose keys are the
citra_gateway::control_counter_keys() set.  emitted.json carries the emitted
control-plane frame log (seq, time_ms, client_id, direction, kind, bytes, hex).

Since V-028 the dumps are not a live-only view: clients.json and identities.json
append a departed-session ledger entry (nickname, fake IPv4 under the field names
fake_ip / assigned_fake_ip / ipv4_address, joined_room, accepted_at_ms,
joined_at_ms, departed_at_ms, the per-session control counters, plus
"departed":true, "live":false and "phase":"Departed"), so a client that left
before the dump still shows who it was and which fake IPv4 it held.  counters.json
adds control_scope ("cumulative"), control_sessions_live and
control_sessions_departed; the control block is the cumulative total across live
and departed sessions and is never zeroed by a session ending.

## License

GPL-2.0-or-later.  See NOTICE.md.

GU-host member translation (V320/V321): independent guest sessions share only authenticated identities from the same native host/session. Initial game rosters support2..4 members and periodic332-byte rosters restore each proven complete70-byte descriptor. Unknown, duplicate or mismatched members are rejected. Counts2..4 have synthetic regression coverage; simultaneous multi-guest gameplay still requires live validation.

V322 also relays native XX secure frames directly between connected Citra guests in the same GU-host hall. MAC/IP/name and current source/destination node IDs must match authenticated session membership; channel243 is preserved, broadcasts exclude the sender, and frames do not pass through GU application conversion. An integrated four-node fixture covers all six directed Citra guest links. Live simultaneous entry/gameplay remains pending.
