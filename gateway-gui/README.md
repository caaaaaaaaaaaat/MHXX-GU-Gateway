# XXGU-Gateway Windows GUI (V339)

Native Win32 desktop application around the V339 gateway core. Start with the [user guide](USER-GUIDE.md): enter a Yuzu room server IPv4 address or hostname, UDP port, local Citra port and password. Connect same-machine Citra clients to the displayed endpoint; Yuzu connects directly to the original room server.

## Current features (2026-11-22)

- DNS and network work run on a worker thread. The window reports attached Citra count and actual upstream join progress separately. Closing/closed sessions are excluded; listening alone never counts as a successful server connection.
- MHXX/MHGU control-plane and dual-host discovery/admission are configured automatically. Each Citra uses one upstream member; an idle gateway adds no room member or observer connection.
- V339 keeps the focus on connection stability. The local room-full answer now uses the member slots the room itself declares in its `RoomInformation` instead of treating the count as unknown and deferring every rejection to the remote server, so a player is no longer refused locally while the room still has room (or admitted into a full one). The multi-fault answer order (full before password/nickname/MAC/console-id/version) is unchanged, and a room that never declares keeps the check disabled exactly as before. The session-level fixes from V338 remain in effect: a full per-client queue sheds the frame instead of closing the session, the Citra-facing ENet reassembly budget is a dedicated 4 MiB, and the joined upstream timeout profile is configurable.
- V338 continues the disconnect work: a full per-client queue now sheds the frame instead of closing the session (a 3-4 player hall's broadcast volume could otherwise evict a player who had no fault), the Citra-facing ENet reassembly cap is a dedicated 4 MiB budget instead of the 256 KiB application inbox (ENet resets a peer that exceeds it, vendor default 32 MiB), and the joined upstream timeout profile is explicit and configurable. `outbox_dropped`/`inbox_dropped` now distinguish a shed frame from a disconnect.
- V337 fixed the upstream room link (ENet default timeouts after connect, compact profile covers Connecting only), widened the dual-host beacon watchdog to 3000 ms, and requested a 1 ms Windows timer resolution so `Sleep(1)` ticks do not inherit the ~15.6 ms default jitter.
- First-run server and remote port are blank; the local port defaults to 8888. Normal window close saves all four fields, including explicitly cleared values, and the next launch restores them.
- Settings live at `%LOCALAPPDATA%/XXGU-Gateway/settings.ini`; Windows current-user DPAPI encrypts the password. Smoke mode does not read or write user settings.
- The Configuration menu precedes About and saves the listener IPv4 address for future sessions. About shows V339, author/contact information, copyable QQ/group entries and a GitHub link. The application uses the MHXX icon and displays the hunting-dog image at the bottom right.
- Stop/close waits asynchronously for gateway cleanup. There is no fixed session lifetime and no raw packet trace is enabled.

The listener defaults to `127.0.0.1`. Configuration accepts `0.0.0.0` for all interfaces or a local interface IPv4 address; other computers connect to the gateway computer's actual IP and UDP port, subject to firewall/network reachability. Saved changes apply on the next gateway start and persist across application restarts, including migration from older settings. The CLI has no loopback guard either: `--listen` accepts any IPv4 binding and `--room` accepts a hostname or a remote address, because a server-side console has to expose a gateway to players on other machines. Remote rooms must offer reachable IPv4; hostnames resolve in the worker. IPv6, public-lobby account authentication and automatic reconnect are not supported; rejoin in Citra after disconnecting.

## Build and verification

From this source repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./gateway-gui/build.ps1 -RunTests
```

Requires Windows PowerShell 5.1, GCC/G++/windres under `G:/msys64/mingw64`, installed static zstd, and Python 3 for packaging. ENet/fmt come from [room-transport/vendor](../room-transport/vendor/manifest.json).

The driver also needs original upstream sources at `../01052024-yuzu-mirror-master/src` and the upstream license. This snapshot is outside the GitHub source repository. In the full workspace this repository is named `crossplay`, beside the upstream tree. The driver rebuilds production sources, runs selected checks and packages the result without operating emulators.

Outputs are under `gateway-gui/.build-desktop/`: `XXGU-Gateway-V339-release-win64.zip` (exactly EXE + `使用说明.md`, licenses embedded), `XXGU-Gateway-V339-source.zip` (matching sources), and `release-V339/发布说明.md` (Release body). Version comes from `AppVersion`; the build packages and verifies both ZIPs and runs hidden-window smoke checks. Follow [RELEASE-WORKFLOW.md](RELEASE-WORKFLOW.md) for all future builds and releases; [releases/V338.md](releases/V338.md) contains the previous version's release notes. `artifacts.json` and `XXGU-Gateway/` are internal build artifacts. Backend regression uses an isolated original room and synthetic Citra ENet clients.

## Acceptance scope

On 2026-10-21 the user confirmed V333 three-player hall entry with both host types, followed by normal operation with two Yuzu and two Citra clients. GUI automated checks cover counts, member slots, failures, stop/restart and hidden-window lifecycle. Core live acceptance and desktop automation are separate results. Extended stability, quest loading/area transitions/results, every join order and independent simultaneous halls do not have complete acceptance coverage.

See [citra-gateway](../citra-gateway/README.md) for the core and CLI. GPL and third-party notices accompany the packaged application.
