# citra-gateway: MHXX / MHGU protocol gateway

Standalone C++ gateway between Citra room protocol v4 and Yuzu room protocol v1, with UDS/LDN control-plane and MH/Pia application translation. Neither emulator needs modification. Players should start with the [Windows GUI](../gateway-gui/README.md); this module provides the CLI, core API and regression harness.

## Current status (2026-10-22)

The gateway core is V333; the desktop application is V335. On 2026-10-21 the user confirmed three-player entry with each host type (Citra host and Yuzu host), then confirmed normal operation with two Yuzu and two Citra clients. The project has entered desktop packaging. The four-player report did not specify host, join order, duration or quest stages. Extended retention, reconnects, quest loading/area transitions/results, every join order and independent simultaneous halls do not have complete acceptance coverage.

Earlier V274/V320/V322 statements that live interoperability was pending are superseded by this feedback. The recorded V333 automated baseline was 1845 checks / 46 groups / zero failures and CLI 25/25. These are historical results, not tests rerun for this documentation update. Automated protocol tests and live game acceptance remain distinct evidence.

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
