# Gateway Desktop

Windows native Win32 GUI around the verified V333 gateway core. No web server, shell subprocesses, observer member, room-browser connection or runtime GUI dependency. All network and DNS work runs on a worker thread. UI polls a mutex-protected status snapshot. Stop/close waits asynchronously for graceful gateway cleanup. The worker has no fixed session lifetime.

Build from the workspace root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/gateway-gui/build.ps1 -RunTests
```

Output: `.build-desktop/XXGU-Gateway/XXGU-Gateway.exe` and accompanying user guide/licenses. Build compiles production sources afresh and leaves previous V333 artifacts and live services untouched. Toolchain matches the existing MinGW gateway build. The remote transport is an explicit opt-in; legacy CLI and tests remain loopback-only by default. The application resolves IPv4/DNS in its worker and passes numeric IPv4 to the existing transport. The Citra listener remains loopback-only.

Settings and passwords are not persisted. No raw packet trace is enabled. Attached count excludes closing/closed Citra sessions; upstream joined count is reported separately. No speculative successful connection is shown without an actual Citra-to-room join.

`--smoke-test` creates the real window hidden, services its timer and closes it without starting network connections. Backend tests use an isolated original Yuzu room and synthetic ENet Citra clients; they do not operate emulators. Additional gateway regression is logged under `.build-desktop`.
