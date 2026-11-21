# citra-gateway: MHXX / MHGU protocol gateway

Standalone C++ gateway between Citra room protocol v4 and Yuzu room protocol v1, with UDS/LDN control-plane and MH/Pia application translation. Neither emulator needs modification. Players should start with the [Windows GUI](../gateway-gui/README.md); this module provides the CLI, core API and regression harness.

## Current status (2026-11-22)

**双向接纳已实测通过：Citra（MHXX）房主接纳 Yuzu（MHGU）客人，以及 Yuzu（MHGU）房主接纳 Citra（MHXX）客人均通过；两台 Yuzu + 两台 Citra 混合联机也已通过。双向接纳不再处于暂停或待验收状态。**

The gateway core is V338; the desktop application is V338, with a persistent listener IPv4 configuration page (loopback by default, optional wildcard/interface binding). The CLI retains its loopback restriction. On 2026-10-21 the user confirmed three-player entry with each host type (Citra host and Yuzu host), then confirmed normal operation with two Yuzu and two Citra clients. The project has entered desktop packaging. The four-player report did not specify host, join order, duration or quest stages. Extended retention, reconnects, quest loading/area transitions/results, every join order and independent simultaneous halls do not have complete acceptance coverage.

V338 continues the disconnect work started in V337 and removes three paths that dropped a player who had no fault of their own. (1) A full per-client queue used to close the Citra session outright (`outbound queue limit` / `inbound queue limit`); a 3-4 player hall's room broadcast volume scales with the member count, so a burst could evict an unrelated player. The default is now `Options::QueueOverflowPolicy::Drop`: the offending frame is shed, the session survives, and the new `outbox_dropped`/`inbox_dropped` counters distinguish a shed frame from a disconnect. `--queue-policy close` restores the old fail-closed behaviour. (2) The Citra-facing ENet host reused the 256 KiB application inbox as its reassembly budget, 128x below the 32 MiB vendor default; `enet_protocol_dispatch_incoming_commands` takes `notifyError`, which resets that peer (vendor `peer.c:956`), so the library itself forced the disconnect. That budget is now its own `Options::citra_enet_waiting_data_bytes` (default 4 MiB, validated to at least one maximal frame). (3) The joined upstream timeout profile from V337 is reachable as `Options::room_joined_timeout_minimum_ms`/`room_joined_timeout_limit_ms` and via `--joined-timeout-min`/`--joined-timeout-max` (1..60000 ms, minimum <= limit, refused at construction when nonsense), so a lossy link can be widened in the field without patching code. Connecting keeps its fast-fail profile.

V337 was the first stability revision after user reports of frequent disconnects in three/four-player halls. The upstream room peer now retransmits under the ENet default timeout profile (`room_transport::Options::joined_timeout_*`, defaults 5000/30000 ms) from the ENet connect event onward; the pre-V337 compact profile (≈1.5 s hard disconnect) covered Connecting only, so it no longer tears down a live session on a transient upstream loss burst. The dual-host beacon watchdog is `Options::dual_host_beacon_timeout_ms` (default 3000 ms, was the 1500 ms `kCitraAppdataMaxAgeMs`), so a paused real-host beacon cadence during quest loading no longer demotes the Citra-host role immediately. Trade-off: a truly dead upstream room connection is detected in ~30 s while joined (previously ~1.5 s), matching the native room clients. The GUI additionally requests a 1 ms Windows timer resolution for its `Sleep(1)`-driven gateway loop.

Earlier V274/V320/V322 statements that live interoperability was pending are superseded by this feedback. The recorded V338 automated baseline is 1873 checks / 48 groups / zero failures plus 155 PowerShell evidence assertions (the historical V333 baseline was 1845 checks / 46 groups). These are historical results, not tests rerun for this documentation update. Automated protocol tests and live game acceptance remain distinct evidence.

## Architecture and behavior

```text
Citra / MHXX -- ENet/UDP v4 --> gateway -- ENet/UDP v1 --> self-hosted Yuzu room
                                                               ^
                                                               |
                                                          Yuzu / MHGU
```

One actual Citra client owns one upstream Yuzu room peer; the gateway adds no observer member. Each session maps its Citra MAC to its assigned upstream fake IPv4. Citra sees only v4; the upstream room sees only v1.

- Control translation covers UDS beacons, association/EAPoL and LDN Scan, Connect, SyncNetwork and departure.
- Dual-host mode chooses the Citra-host or GU-host role per session, using live hall advertisements, learned identities, guest injection and game return traffic.
- Application translation handles identity words, member descriptors, admission, heartbeat and GU/XX stream differences, with length, source, identity, route and capacity checks.
- V333 includes actual local Citra guests in native LDN membership, preserves node slots, and withdraws them on departure or role change. Same-hall Citra secure frames are relayed under authenticated membership checks.
- V337 relaxes two disconnect paths: the upstream room peer retransmits under ENet default timeouts once the link is up (the compact profile now covers Connecting only), and the dual-host beacon watchdog is configurable through `Options::dual_host_beacon_timeout_ms` (default 3000 ms, previously the fixed 1500 ms appdata age).
- V338 removes the remaining involuntary-disconnect paths: a full queue sheds the frame instead of closing the session (`Options::queue_overflow_policy`, default Drop), the Citra-facing ENet reassembly budget is its own 4 MiB option instead of the 256 KiB inbox, and the joined upstream timeout profile is a validated gateway/CLI option.
- The core projects upstream room/game metadata and chat, retains departed-session ledgers and cumulative counters. The GUI displays connection state and attached count only.

## Build and test

Run from this source repository root (the directory containing `citra-gateway/`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./citra-gateway/build.ps1 -RunTests
python ./citra-gateway/tests/test_cli.py
```

Requires Windows PowerShell 5.1, the GCC toolchain at `G:/msys64/mingw64`, installed static zstd, and the vendored ENet/fmt sources. Original Room/Packet/VerifyUser sources and headers must also be available at `../01052024-yuzu-mirror-master/src`, outside this Git repository. In the full engineering workspace this repository is named `crossplay`, beside that upstream tree. The upstream snapshot is not distributed here.

The driver compiles each source separately and links explicitly. It builds twice and compares hashes by default; `-SkipRepro` builds once. Outputs are under `citra-gateway/.build-direct/`, including `citra-gateway.exe`. `-RunTests` opens loopback sockets: do not run competing tests on the same ports. The Python CLI parser regression is separate; set `CITRA_GATEWAY_TEST_EXE` to select another executable.

For offline checks, choose a fresh ASCII output leaf:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./citra-gateway/build.ps1 -OfflineVerify -OfflineOutput .build-offline-readme -SkipRepro
```

`-OfflineVerify` and `-RunTests` are mutually exclusive. Offline mode still compiles dependencies but runs only identity/codec/capability checks, without successful gateway open, ENet initialization or sockets.

## CLI

```powershell
./citra-gateway/.build-direct/citra-gateway.exe --help
./citra-gateway/.build-direct/citra-gateway.exe --capabilities
```

`--help` is the complete current parameter reference. Defaults are listener `127.0.0.1:24873`, room `127.0.0.1:24872`, and a five-second lifetime. The CLI keeps loopback defaults and restrictions. The GUI explicitly enables remote IPv4 and supplies its own worker loop without a fixed session lifetime.

With a self-hosted loopback room already running, enable dual-host translation for ten minutes (use the example password on Citra and the room):

```powershell
./citra-gateway/.build-direct/citra-gateway.exe --listen-port 24873 --room-port 24872 --password example --seconds 600 --control-plane --ldn-dual-host --uds-profile mhxx --ldn-comm-id 0100770008dd8000 --ldn-proxy-port 12345
```

`--ldn-dual-host` requires the control plane, full UDS identity profile, communication ID and proxy port. It also enables GU-host discovery/admission, live-hall gating, announcement forwarding, guest injection and game return. Session beacons and assigned native-room IPs supply dynamic identities; static `--ldn-identity-pair` options are unnecessary. Legacy single-direction flags retain their validation requirements.

`--citra-peer-relay` selects the separate Citra-to-Citra CRLY transport topology and is mutually exclusive with `--control-plane`. Basic mode without these switches retains its declared transport-only behavior.

The earlier capability interface accepts only `--application-mode legacy-transport` with `--proxy-profile yuzu-mirror-01052024`. Its conservative JSON flags are not a summary of subsequent dual-host live acceptance.

Exit codes: 0 success, 2 usage error, 3 open failure (including address restrictions or port conflicts). `--stop-file <path>` requests graceful shutdown; `--dump <dir>` exports diagnostics.

## Source and diagnostics

| Path | Purpose |
| --- | --- |
| [gateway.hpp](include/citra_gateway/gateway.hpp) | Options, core API, snapshots and counters |
| [identity.cpp](src/identity.cpp) | MAC / fake IPv4 mapping |
| [control.cpp](src/control.cpp) | Control-plane and application translation |
| [gateway.cpp](src/gateway.cpp) | ENet loop, sessions and routing |
| [main.cpp](src/main.cpp) | CLI parsing and lifecycle |
| [tests](tests) | Identity, integration, offline and CLI regression |

Dumps include counters, clients, identities, captures, events, snapshot and emitted JSON. Departed sessions remain in the ledger; control counters are cumulative. Raw tracing requires an explicit opt-in. Runtime diagnostics are not part of the public source distribution.

The delivery path is single-channel ENet/UDP with one bare v4 message per reliable packet. The four-byte big-endian length-prefixed TCP path is available only through an in-process harness option, not a CLI flag. Default whole-frame and data-body caps are 65536 and 60000 bytes. The upstream 500-byte constant limits chat, not game frames.

Historical specifications and raw acceptance evidence live in the full engineering workspace's `docs/`, verification and private runtime directories, outside this source repository. The implementation and regression entry points above are distributed here. See [NOTICE.md](NOTICE.md) for licensing.
