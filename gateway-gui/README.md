# XXGU-Gateway Windows GUI (V336)

Native Win32 desktop application around the V333 gateway core. Start with the [user guide](USER-GUIDE.md): enter a Yuzu room server IPv4 address or hostname, UDP port, local Citra port and password. Connect same-machine Citra clients to the displayed endpoint; Yuzu connects directly to the original room server.

## Current features (2026-10-22)

- DNS and network work run on a worker thread. The window reports attached Citra count and actual upstream join progress separately. Closing/closed sessions are excluded; listening alone never counts as a successful server connection.
- MHXX/MHGU control-plane and dual-host discovery/admission are configured automatically. Each Citra uses one upstream member; an idle gateway adds no room member or observer connection.
- First-run server and remote port are blank; the local port defaults to 8888. Normal window close saves all four fields, including explicitly cleared values, and the next launch restores them.
- Settings live at `%LOCALAPPDATA%/XXGU-Gateway/settings.ini`; Windows current-user DPAPI encrypts the password. Smoke mode does not read or write user settings.
- The Configuration menu precedes About and saves the listener IPv4 address for future sessions. About shows V336, author/contact information, copyable QQ/group entries and a GitHub link. The application uses the MHXX icon and displays the hunting-dog image at the bottom right.
- Stop/close waits asynchronously for gateway cleanup. There is no fixed session lifetime and no raw packet trace is enabled.

The listener defaults to `127.0.0.1`. Configuration accepts `0.0.0.0` for all interfaces or a local interface IPv4 address; other computers connect to the gateway computer's actual IP and UDP port, subject to firewall/network reachability. Saved changes apply on the next gateway start and persist across application restarts, including migration from older settings. The CLI retains its loopback guard. Remote rooms must offer reachable IPv4; hostnames resolve in the worker. IPv6, public-lobby account authentication and automatic reconnect are not supported; rejoin in Citra after disconnecting.

## Build and verification

From this source repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./gateway-gui/build.ps1 -RunTests
```

Requires Windows PowerShell 5.1, GCC/G++/windres under `G:/msys64/mingw64`, installed static zstd, and Python 3 for packaging. ENet/fmt come from [room-transport/vendor](../room-transport/vendor/manifest.json).

The driver also needs original upstream sources at `../01052024-yuzu-mirror-master/src` and the upstream license. This snapshot is outside the GitHub source repository. In the full workspace this repository is named `crossplay`, beside the upstream tree. The driver rebuilds production sources, runs selected checks and packages the result without operating emulators.

Outputs are under `gateway-gui/.build-desktop/`: `XXGU-Gateway/XXGU-Gateway.exe`, portable ZIP, matching source archive and `artifacts.json`. See [package.py](package.py) for archive names. `--smoke-test` creates the real window hidden, services its timer and closes without network connections. Backend regression uses an isolated original room and synthetic Citra ENet clients.

## Acceptance scope

On 2026-10-21 the user confirmed V333 three-player hall entry with both host types, followed by normal operation with two Yuzu and two Citra clients. GUI automated checks cover counts, member slots, failures, stop/restart and hidden-window lifecycle. Core live acceptance and desktop automation are separate results. Extended stability, quest loading/area transitions/results, every join order and independent simultaneous halls do not have complete acceptance coverage.

See [citra-gateway](../citra-gateway/README.md) for the core and CLI. GPL and third-party notices accompany the packaged application.
