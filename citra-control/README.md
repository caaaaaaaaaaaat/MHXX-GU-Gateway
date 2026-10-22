# citra-control

## Current role and entry point (2026-10-22)

Offline UDS/LDN parsing, generation, mapping and state-machine library used by the production gateway. This library itself opens no sockets; live acceptance belongs to the gateway, not its synthetic fixtures.

Run from this source repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./citra-control/build.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File ./citra-control/test.ps1
```

See the [gateway status](../citra-gateway/README.md) and [desktop user guide](../gateway-gui/USER-GUIDE.md) for current player-facing behavior. The detailed reference below retains original milestone names and historical test counts. Commands containing `crossplay/` assume the parent engineering workspace; in a standalone checkout, omit that prefix. References to `../../docs/`, upstream source snapshots and private evidence refer to that larger workspace and are not distributed in this Git repository. Build scripts are the source of truth for required upstream paths and toolchains.

## Detailed module reference

SPDX-License-Identifier: GPL-3.0-or-later

Citra《怪物猎人XX》(3DS, UDS/802.11 管理面) 与 Yuzu《怪物猎人GU》(NS, LDN) 之间的
**控制面离线映射库**。它只做字节级解析 / 生成 / 映射 / 状态机，不发起任何网络连接，
不读注册表 / 环境变量，不写库目录以外的任何文件，不依赖除 C++ 标准库以外的任何库。

权威规格：docs/M4-CONTROL-PLANE.md（§3 映射表、§4/§4.1 状态机、§5 fail-closed）、
docs/M4-ADAPTER-SPEC.md §9、docs/ACCEPTANCE.md「安全红线」、docs/VERIFICATION-LOG.md
的 V-016b / V-016d / V-016k / V-016n / V-019。详细报告见 docs/citra-control-report.md。

## 目录

    include/citra_control/bytes.hpp     定点字节读写、Reader/Writer、错误码、计数器、事件日志
    include/citra_control/crypto.hpp    MD5 / SHA-1 / AES-128 / AES-128-CTR
    include/citra_control/mirrors.hpp   Citra / Yuzu 结构体的 POD 镜像（static_assert 锁布局）
    include/citra_control/uds_frames.hpp Citra 侧帧（Beacon / Auth / AssocResp / EAPoL / SecureData / NodeMap / Deauth）
    include/citra_control/ldn_ctrl.hpp  Yuzu 侧 LDN 六类体（尺寸门）
    include/citra_control/map.hpp       身份/网络标识/SSID/用户名/容量的映射与会话映射表
    include/citra_control/state.hpp     控制面状态机（AP 门、折叠关联、有序发射义务）
    src/*.cpp                           同一批实现
    tests/*.cpp                         用例（goldens、全前缀截断、独立 oracle、布局打印）
    tests/layout_report.cpp             单独链接成 layout.exe，打印全部 sizeof/offsetof
    fixtures/*.hex                      手写合成十六进制 + 独立 oracle 输出（无真实抓包）
    fixtures/beacon_oracle.py           独立 oracle 生成器（Python hashlib + cryptography）
    build.ps1 / test.ps1                构建 / 测试脚本（Windows PowerShell 5.1）

## 构建与测试

    powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/citra-control/build.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/citra-control/build.ps1 -Clean
    powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/citra-control/test.ps1
    crossplay/citra-control/.build-direct/test.exe
    crossplay/citra-control/.build-direct/layout.exe

编译器固定为 G:/msys64/mingw64/bin/g++.exe（GCC 16.1.0），编译选项
-std=c++17 -Wall -Wextra -Wpedantic -Werror -O2，链接加 -Wl,--no-insert-timestamp
以保证两次干净构建逐字节相同。因为工作区路径含中文，MinGW 无法在其中创建汇编临时文件，
所以每个 .cpp 单独编译到 ASCII 目录 crossplay/citra-control/.build-direct/ 后再显式链接；
脚本不修改 TMP/TEMP/PATH。

test.exe 每个用例组打印一行 GROUP <name> cases=N checks=M failed=K，最后打印
RESULT cases=N checks=M failed=K；全部通过时 exit 0。

## 独立 oracle

fixtures/beacon_n2.hex 由 fixtures/beacon_oracle.py 生成，其 MD5/SHA-1 来自 Python
hashlib、AES-128-CTR 来自 cryptography 包，与本库的 C++ 实现完全独立；MD5/AES/SHA-1
的单元测试另有 RFC 1321 / FIPS 197 / FIPS 180-4 / NIST SP 800-38A 公开测试向量。
fixtures/beacon_n1.hex 是冻结的旧模型（0x12+0x1E*n，n=1）反例，只用于必须被拒的用例。

## 计数器

每个拒绝都会累加到 include/citra_control/bytes.hpp 的 Counters（机器可读的名字），
并写入 EventLog（REJECT <where> reason=<Err>）。Diag::counters_text() 只输出非零项。
库本身不引入任何全局可变状态：映射表、计数器、事件日志全部由调用方传入。

## 许可证

GPL-3.0-or-later（整树）。本库派生自 Citra（GPLv2-or-later）与 yuzu（GPL-3.0-or-later）
的公开数据结构与常量，详见 NOTICE。

## 2026-10-15 信标布局修复

NetworkInfo IE 的 31 字节网络信息已包含 OUI/type，不额外重复写入。
length 为 52+appdata_size（含头总长 54+appdata_size），与 Citra GenerateNintendoNetworkInfoTag 一致。
生成器、解析器与 Python oracle 共享的旧错误已修复，并增加独立 IE 边界与旧格式拒绝检查。
离线结果：77 cases / 726 checks / 0 failed。详见 docs/VERIFICATION-LOG.md V-050。

## 2026-10-16 G4 翻译层骨架

新增 LDN ↔ UDS 跨侧字段映射与 fail-closed 门的纯离线骨架（规格
docs/G4-TRANSLATE-SPEC.md，事实来源 docs/G4-PRE-ANALYSIS.md / docs/M4-CONTROL-PLANE.md /
docs/M4-ADAPTER-SPEC.md §9.1），不新增任何计数器字段：

    include/citra_control/translate.hpp  接口（kUdsDataPrefixSize=22、CRLY 魔数、MatchKey、CrossSideKind）
    src/translate.cpp                    映射与门的实现
    tests/test_translate.cpp             四个用例组 translate_net / translate_nodes / translate_guards / translate_data

映射与门的四组职责：

    A 网络信息   uds_network_to_ldn / ldn_network_to_uds：network_id 直取 in.ids（绝不由 wlan_comm_id 反推），
                 信道/链路等级/节点容量逐字段校验，appdata 超过 0xC8 一律拒绝（绝不截断）。
    B 节点       uds/eapol/beacon_node_to_ldn 与 ldn_node_to_uds_guest/eapol/beacon：
                 用户名一律走 username_from_bytes / username_to_bytes，不可精确表示即 Err::Encoding 并计数。
    C 门         G1 guard_association_response、G2 guard_advertise_capacity、G3 guard_node_capacity、
                 G4 guard_no_crly、G5 guard_match_key、G6 guard_cross_side、G7 guard_beacon_layout。
                 G7 只做布局检查，SHA-1/MD5/AES-CTR 全部委托既有 parse_beacon_frame，不重复计数。
    D 数据前缀   strip_uds_data_prefix / wrap_ldn_payload_as_uds_data：CITRA LLC 8 字节 + SecureData 头 14 字节，
                 共 22 字节；sequence_number 与 is_management 一律置 0。

每个拒绝路径都落在既有 Counters（unsafe_assoc_blocked / oversize_rejected / invented_fields /
undefined_fields / node_id_out_of_range / username_rejected / channel_rejected / sha1_verify_fail /
md5_verify_fail / cross_side_leak_blocked / err[]）与 EventLog 上。
离线结果：新增 35 cases / 167 checks，全量 112 cases / 893 checks / 0 failed。## 2026-10-16 G4 信标加密载荷长度修复（D1）

契约 docs/G4-BEACON-LENGTH-FIX-SPEC.md。`guard_beacon_layout` 与 `build/parse_beacon_frame`
原先按 `0x12 + 0x1E*n`（合法内容长度）校验加密载荷，而 Citra 收发实际传的密文长度是
`0x28 * n`（n = NetworkInfo nib[17] = max_nodes，`sizeof(nwm::NodeInfo)`=40；见
citra-master/src/core/hle/service/nwm/uds_beacon.cpp:239-294 与 nwm_uds.cpp:1395-1419）。
合法内容只覆盖前 `0x12 + 0x1E*n` 字节，`[content, 0x28n)` 是不校验的尾巴。
两者不符导致三个真实 MHXX/Citra 信标（max_nodes=4/2）全部被误拒（Err::BadLength）。

改动：

    uds_frames.hpp   新增 kBeaconNodeStride=0x28、kBeaconContentHeaderSize=0x12（只加常量，未改旧值、未改签名）
    uds_frames.cpp   build/parse：明文缓冲区 = 0x28*n（尾巴补 0）；MD5 只覆盖 [0x10, 0x12+0x1E*n)；
                     长度门 = 0x28*n；标签切分按 min(0xFA, 0x28n) + 余量（R4）
    translate.cpp    guard_beacon_layout：期望密文 = 0x28 * rep.node_count（R1）
    R7               n < 2 时生成与校验一律 Err::BadLength + 事件 beacon_max_nodes_too_small
                     （Citra 自身在该边界生成截断、接收越读 8 字节，故 fail-closed）
    R6               caller 传入的 network_info.max_nodes 非 0 且 ≠ 记录数时 Err::BadLength

fixtures/beacon_oracle.py 已按 R1–R5 更新并生成 fixtures/beacon_n2.hex（max_nodes=2，密文
0x28*2=80，内容 0x12+0x1E*2=78，总帧 171 字节）。fixtures/beacon_n1.hex 保持逐字节不变
（网关用例读它的 frame 前 31 字节），仅作为「必须被拒」的反例。

已知契约自相矛盾（未自行修改契约，原始证据见回报）：docs/G4-BEACON-LENGTH-FIX-SPEC.md §4
同时要求 .verify-r26/g4/mut/m4_bad_md5.hex 仍为 Err::BadDigest、good_fixture.hex 仍被接受，
但两者 max_nodes=1；而 §3 R7 要求 n<2 一律 Err::BadLength，二者不能同时成立。
