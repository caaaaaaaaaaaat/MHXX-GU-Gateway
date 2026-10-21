# real-room-interop — real room-server interoperability harness

**This is a room-layer test harness, not a gameplay bridge.** Self mode proves that the
harness (M2 client + this project's raw capture clients) works against the *unmodified
original room source*; it is **not** real-distribution interoperability. Real mode drives a
real `yuzu-room.exe` / `citra-room.exe` and proves room join, the four error faces and
byte-exact wire frames. Nothing here proves game compatibility: entering a room is not
packet relay, not seeing each other in a lobby, and not completing a hunt.

SPDX-License-Identifier: GPL-2.0-or-later

## Modes

| Sub-command | What it does | Needs authorisation |
| --- | --- | --- |
| `self` (default) | Builds a room server from the **unmodified** `01052024-yuzu-mirror-master/src/network/{room,packet,verify_user}.cpp` (`real_room_self_server.exe`) and runs the v1 cases against it over 127.0.0.1. | no |
| `real` | Starts a real `yuzu-room.exe` / `citra-room.exe` as a child process and runs the same cases against it. Refused without `-AllowRun`. | yes |
| `dryrun` | Prints the exact command lines that real mode *would* run for every candidate executable. Never starts anything; every line is marked `NOT EXECUTED / 尚未执行`. | no |
| `probe` | Runs `<exe> --help` and `<exe> --version` to confirm a candidate's option set. Refused without `-AllowRun`. | yes |
| `observe` | Joins a room as an ordinary **v1 member**, decodes every server frame and writes them — including the full member table of each `RoomInformation` — to a JSON file. Loopback only. | no |
| `attach` | Runs the same cases against a room server that is **already running elsewhere**. Starts nothing, skips the V-017 identity gate (the target is not in the authorisation table) and is therefore **never distribution evidence**; `-AttachAddr` must be loopback. | no |

## Safety rules enforced by the code

* **Authorization gate** — `real` and `probe` exit 3 with `未获用户授权` unless `-AllowRun`
  is passed. The gate lives in `src/main.cpp`, not in a wrapper script.
* **Identity gate** — before launching, the harness reads the actual executable, prints
  `SERVER IDENTITY: path=… bytes=… sha256=…`, and compares the SHA256 with the
  authorisation table in `docs/AUTHORIZATIONS.md` (V-017). A file that is not in the table
  is refused (exit 4) and produces no evidence. A protocol that does not match the
  candidate is refused too.
* **Bind gate** — a server is only started when it can be shown to be loopback-only, or when
  the operator explicitly passes `-AllowWildcardBind`:
  * command line already binds `127.0.0.1` → allowed, `loopback_only=true`;
  * command line binds another address → refused;
  * command line has no bind option but the binary supports `--bind-address` →
    `--bind-address 127.0.0.1` is injected, `loopback_only=true`;
  * no bind option and no support → only allowed with `-AllowWildcardBind`
    (`loopback_only=false`; the socket is then `0.0.0.0`, so the run must be recorded as
    wildcard-authorised). Refused otherwise (exit 5).
* **Loopback clients** — every test client binds its own socket to 127.0.0.1 and never
  sends anywhere else. No packet is sent to a public or official service.
* **Bounded runs** — each server has a readiness timeout and a stop/terminate watchdog;
  every case has its own port and work directory; the executable's stdout/stderr are
  captured to files. The full real suite is asserted to finish under 60 s
  (`run_elapsed_under_60s`) and the port must be gone after the process exits.
* **No third-party peers** — the harness compares the room's own `has joined` log lines
  with the number of `JoinSuccess` frames it captured; an extra member is a failure.
* **Original sources are never modified** — `build.ps1` records the SHA256 of the linked
  original files before the build and checks them again afterwards.
* **No emulator, no game** — only `*-room.exe` room servers are ever started, and only
  after `-AllowRun`. No ROM, save, key or GUI process is involved.

## Build (PowerShell 5.1)

```powershell
cd crossplay/real-room-interop
./build.ps1                 # compile both executables
./build.ps1 -RunSelf        # compile, then run the self suite
./build.ps1 -RunInventory   # refresh the static inventory JSON
./build.ps1 -RunDryRun      # refresh the dry-run command list
./build.ps1 -RunReal -AllowRun -Protocol v1 -RoomExe <path>   # real suite (needs authorisation)
./build.ps1 -Clean -Out build-verify                          # same sources, other output dir
```

`-Out` exists so the byte-for-byte reproducibility check (two consecutive clean builds)
can be run even while another process is still holding a running image in `build-mingw`
on Windows: a running `.exe` cannot be overwritten.

Only `G:/msys64/mingw64/bin/g++.exe` (GCC 16.1.0) is used. Each translation unit is
compiled separately as `g++ -pipe -c <ASCII relative source> -o <ASCII relative object>`
and the objects are linked explicitly, because MinGW 16.1 cannot generate its temporary
assembly file when a non-ASCII path reaches the compiler. `TMP`/`TEMP`/`PATH` are not
touched; there is no CMake, Ninja, Make, MSVC or clang.

Products (delivery directory `build-mingw`; three full builds of this revision — `build-attach`,
`build-mingw` and a `-Clean -Out build-verify` re-run — produce byte-identical hashes, because
`Compile-Set` recompiles every translation unit unconditionally; see
`docs/real-room-interop-report.md` §1):

| Product | Bytes | SHA256 |
| --- | --- | --- |
| `build-mingw/real_room_interop.exe` | 20169061 | `c7cb8883a615ccebd79afdd802edce51768bfe97492f991ecc1b3c992c9a86a4` |
| `build-mingw/real_room_self_server.exe` | 7949058 | `414d7187607e77176dcc263c55a022aa345a8d826905fe728c8df56211a3172c` |

## Self mode

```powershell
./build-mingw/real_room_interop.exe self -Evidence evidence -Work work -Cases all
```

`Cases=all` runs 18 v1 cases (17 protocol cases + `fixture_bytes`); `Cases=core` runs the
subset needed for a quick check. The suite covers: join + RoomInformation-before-JoinSuccess
+ member list, version mismatch, wrong password, name collision, IP collision, room full,
capacity release after a rejection, M2 `room_transport::Transport` parity, port conflict
(second server must fail to start), cross-family version isolation, Proxy routing and
broadcast, 1200-byte data-plane payload pass-through, 500-byte chat truncation, unjoined
source (record-only: the room does not validate senders), validation order, and byte-exact
comparison against the M2 fixture.

`fixture_bytes` reads `crossplay/room-client/fixtures/join-success.hex` (produced by the
frozen codec's own fixture CLI, not by this harness), requests the fixture's fake IP as the
preferred IP, and compares the **on-the-wire** JoinSuccess frame with the fixture's golden
line byte for byte — no decode → encode round trip. The RoomInformation frame is compared
field by field and its first differing byte offset is recorded with an explanation, because a
real join broadcasts RoomInformation before JoinSuccess and before any SetGameInfo, so the
fixture's synthetic single-member room state cannot be reproduced by a real handshake.

Observed result: `RESULT mode=self protocol=v1 server=self-original-source cases=18 failed=0
elapsed_ms=8307` (exit 0).

**Self mode proves only that the harness can drive a room built from the unmodified room
source. It says nothing about a real released binary.**

## Real mode

```powershell
# (b) strict loopback baseline: EA binary, --bind-address injected automatically
./build-mingw/real_room_interop.exe real -AllowRun -Protocol v1 `
  -RoomExe 'C:\Users\马光述\AppData\Local\yuzu\yuzu-windows-msvc-early-access\yuzu-room.exe' `
  -RoomArgsFile config/yuzu-room.args -Evidence evidence -Work work -Cases all

# (a) 2022 main binary: no --bind-address exists, so a wildcard bind needs the explicit switch
./build-mingw/real_room_interop.exe real -AllowRun -AllowWildcardBind -Protocol v1 `
  -RoomExe 'C:\Users\马光述\AppData\Local\yuzu\yuzu-windows-msvc\yuzu-room.exe' `
  -RoomArgsFile config/yuzu-room.args -Evidence evidence -Work work -Cases all

# v4 (citra-room): same wildcard situation, v4 codec and cases
./build-mingw/real_room_interop.exe real -AllowRun -AllowWildcardBind -Protocol v4 `
  -RoomExe 'F:\citra mul\citra-windows-msys2-20240927-608383e\citra-room.exe' `
  -RoomArgsFile config/citra-room.args -Evidence evidence -Work work -Cases all
```

`-RoomArgsFile` uses `key = arg arg …` lines, `#` comments and `*` as the default
scenario. Placeholders `{port}`, `{work}`, `{slots}`, `{room}`, `{tag}`, `{password}` are
substituted per scenario; a scenario's own line replaces the default line entirely. Neither
yuzu-room nor citra-room is ever given `--token`/`--web-api-url`, so the server logs
`Hosting a private room` and never contacts an announce service; the harness asserts that
line and no custom server is contacted.

Evidence is written to `evidence/real/<tag>/`:

* `summary.json` — machine-readable result of the whole run (cases, checks, notes, frames);
* `server-identity.json` — path, bytes, SHA256, build id, protocol, `loopback_only`,
  whether `--bind-address` was injected, case counts, elapsed time and the **observed UDP
  endpoints per pid**;
* `commands.txt` — the exact command line used for every scenario;
* `cases/<id>.wire.txt` and `cases/<id>.s2c.hex` — the real on-the-wire bytes;
* `cases/<id>.checks.txt` — every check with its verdict and detail;
* `server/<id>.out.txt`, `server/<id>.err.txt` — the server's own output.

## Attach mode (external already-running room server)

```powershell
# the room server is started by the operator, not by the harness
./build-mingw/real_room_self_server.exe --name rri-attach-selftest --port 39811 --password pw1 --slots 8
./build-mingw/real_room_interop.exe attach -AttachAddr 127.0.0.1:39811 -Protocol v1 `
  -RoomName rri-attach-selftest -Slots 8 -AttachTag attach-selftest-v1 -Evidence evidence -Work work -Cases all
```

`attach` never starts a process, never authorises a binary and skips the V-017 identity gate on
purpose: the target is a room this harness does not own, so the run is **not distribution
evidence** (`not_distribution_evidence=true`, bilingual warning printed, and recorded in
`summary.json` together with `server_started_by_this_run=false`,
`server_inventory_check=skipped on purpose: docs/VERIFICATION-LOG.md V-017 does not cover this target`,
`attach_addr/attach_host/attach_port`, `attach_is_loopback`, `attach_observed_wildcard_bind`,
`observed_udp_endpoints_before/after` and `skipped[{id,reason}]`). `-AttachAddr` must be
`127.0.0.1`/`localhost`; a non-loopback target is refused (exit 2) because every client case
connects to loopback.

* Exit codes: `0` all cases passed; `1` a case failed; `2` usage (missing `-AttachAddr`,
  `-Protocol` other than `v1|v4`, unparseable or non-loopback address); `6` nothing is
  listening on that UDP port (`ATTACH REFUSED: nothing is listening on UDP port …; start the
  external room server first (attach mode never starts one)`).
* `-AttachTag` defaults to `foreign-<ip>-<port>`, `-Password` to `pw1`. Omitting `-RoomName` or
  `-Slots` records the corresponding check as skipped with its reason instead of failing it;
  `-Skip <id,id>` records the operator's declaration that a case is not applicable to this room.
* Always skipped, because they need a server this run owns: v4 `room_full_v4`; v1 `room_full`,
  `release`, `m2_parity`, `port_conflict`, `fixture_bytes`, `bind_gate`.
* Observed self-checks: v1 core `cases_executed=5 failed=0 skipped=6` (1663 ms) and `-Cases all`
  13/0/6 (3419 ms) against `build-mingw/real_room_self_server.exe`; `-Cases all` 10/0/1 (2625 ms)
  against a real `citra-room.exe` actually bound to `0.0.0.0:39812` (truthfully recorded as
  `attach_observed_wildcard_bind=true`). Evidence: `evidence/attach/<tag>/{summary.json,target.txt,cases/}`.
* **Attach mode says nothing about distribution interoperability**: it proves only that the
  harness can drive a room that somebody else started.

## Observe mode (member observer / independent oracle)

```powershell
./build-mingw/real_room_interop.exe observe --room 127.0.0.1 --room-port 24930 `
  --password pw1 --nickname rri-obs-a --seconds 10 `
  --out evidence/observe-real/yuzu-ea-2024/observer-a.json
```

The observer sends exactly one `JoinRequest` and then only decodes what the server sends.
The original room broadcasts `IdRoomInformation` to *every* member whenever the membership
changes (`01052024-yuzu-mirror-master/src/network/room.cpp:772-799`), so an observer that is
independent of the gateway is an independent oracle for "who is in the room": it reports the
member table that the original server broadcast, not the member table a gateway claims.

* `--out` receives the JSON only; progress and the full member tables go to stdout, so a
  parent process can watch them live.
* Exit codes: `0` observation finished, `2` usage (bad nickname, missing `--out`, bad port),
  `3` `--room` is not loopback and `--allow-non-loopback` was not given, `4` no join within
  the window, `5` the server refused the join (recorded as an `error` event).
* `--via raw` (default) uses this project's own ENet connection plus the frozen
  `room_client::Session`; `--via transport` uses the frozen `room_transport::Transport`.
  The default is `raw` because `Transport` only hands out decoded `Message` values and keeps
  no per-frame raw bytes, while this mode must keep the raw bytes (and their SHA256) of every
  frame it fails to decode. The two paths are deliberately independent readings.
* JSON: `tool/mode/run_id/start_utc/end_utc`, `exe{path,bytes,sha256}`, `command_line`,
  `protocol`, `via`, `room{address,port,nickname,password_set,loopback_only,local_socket}`,
  `decode_failures`, `events[]` and a final `summary`. Event kinds: `join_success`,
  `room_information` (full member list), `error`, `status`, `chat`, `proxy`, `ldn`,
  `other`, `unknown{raw_bytes,raw_sha256,reason}`. `summary` counts them and adds
  `joined`, `saw_self`, `self_fake_ip`, `max_member_count`, `members_seen`.
* **Fail-closed**: every `room_client`/`ProtocolError`/standard exception is caught, written
  into the JSON as an `unknown` event with `decode_failures` bumped, and ends the run with a
  non-zero exit code. The mode never calls `std::terminate`/abort. `--seconds` bounds the
  observation loop only; it is never pushed into the frozen codec's timeout fields (those are
  validated to 1..60000 ms by `crossplay/room-client/src/session.cpp:21-23`).

Two self-check scripts, both writing their own evidence directory:

```powershell
./tools/observe-selftest.ps1                                   # self room: 22 checks, no authorisation
./tools/observe-real.ps1 -AllowRun -RoomTag yuzu-ea-2024 -Port 24930 -Seconds 10   # real room, needs -AllowRun
```

The self-check starts the original-source room and two observers (A joins first, B 1.5 s later
and leaves); the real check verifies the authorised identity table, refuses an occupied port,
starts the real EA `yuzu-room.exe` on loopback, and runs observers A+B together plus a lone
observer C. **Observe mode says nothing about G-c**: it never joins the gateway's data plane,
never uses Citra, a game or a ROM, and its output is evidence about member-list visibility only.

## Static inventory (read-only, never executes the binaries)

```powershell
./tools/static-inventory.ps1
```

Parses the PE headers/import tables in-process, reads strings with
`G:/msys64/mingw64/bin/strings.exe` and writes `evidence/static-inventory.json` +
`.txt`: SHA256, byte count, PE machine/subsystem, linker version, import DLLs, the option
strings, the `getopt` string, room symbols/markers and, per target, whether
`--bind-address` exists. The candidate list lives in
`config/static-inventory-targets.json` (a UTF-8 data file) so the script itself stays pure
ASCII.

## Dry run

```powershell
./tools/dry-run.ps1
```

Writes `evidence/dry-run.json` and `evidence/dry-run.txt`: for every known candidate and
every scenario, the exact command line real mode would use, with the bind decision
explicitly marked `executed=false` / `NOT EXECUTED / 尚未执行`.

## Not tested (deliberately out of scope here)

* Real binaries were run only as room servers on loopback, with synthetic room clients — no
  emulator front-end, no game, no ROM, no save, no GUI.
* No 4-real-player room, no long soak, no cross-machine run, no CI, no sanitiser, no CMake
  build.
* Self mode has no v4 server (the citra room server has too many upstream dependencies), so
  v4 cases exist only in real mode.
* A real client has not yet been run against a real server; only this project's synthetic
  clients were.
* Observe mode was run against the original-source room and against the authorised EA
  `yuzu-room.exe` on loopback with at most two simultaneous observers; no 4-observer, no
  soak and no cross-machine observation, and no v4 room observation (an observer is a v1
  member).
* Attach mode was pointed only at loopback targets (the entry point refuses anything else), and only at a self-built original-source room (v1) and a real `citra-room` (v4); no attach against a real `yuzu-room`, no attach against a gateway, and no cross-machine or public-address attach.
* Nothing about gameplay: room entry ≠ packet relay ≠ lobby visibility ≠ a completed hunt.
