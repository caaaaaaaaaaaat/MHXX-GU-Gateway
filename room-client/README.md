# room-client M1：离线 room 协议核心

## Current role and entry point (2026-10-22)

Offline Yuzu v1 codec and bounded session foundation. Networking is implemented by the sibling room-transport module, now used by the gateway. A fixture reaching Joined is an offline result.

Run from this source repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./room-client/build.ps1
```

See the [gateway status](../citra-gateway/README.md) and [desktop user guide](../gateway-gui/USER-GUIDE.md) for current player-facing behavior. The detailed reference below retains original milestone names and historical test counts. Commands containing `crossplay/` assume the parent engineering workspace; in a standalone checkout, omit that prefix. References to `../../docs/`, upstream source snapshots and private evidence refer to that larger workspace and are not distributed in this Git repository. Build scripts are the source of truth for required upstream paths and toolchains.

## Detailed module reference

**目前不能连接任何房间。** 此目录仅为 M1 基础设施：标准 C++20 codec、同步有界状态机及离线 fixture CLI。
不含 ENet、socket、假 ENet/server、模拟器 Hook、UDS→LDN 转换、游戏 payload translator 或 ZSTD 解压器。
真实 ENet 客户端与原版 room 互操作留给独立 M2；本工具打印 Joined 只是离线 fixture 的状态，不是联网成功。

## 文件与冻结 API

- [protocol.hpp](<include/room_client/protocol.hpp>)：消息值类型、原始 IPv4、Limits、encode/decode、hex 工具及 ProtocolError。
- [session.hpp](<include/room_client/session.hpp>)：Session / SessionOptions / SessionState。
- [protocol.cpp](<src/protocol.cpp>)、[session.cpp](<src/session.cpp>)：标准库实现，不 include/link 模拟器。
- [main.cpp](<src/main.cpp>)：room-fixture 离线 CLI。
- [golden.hpp](<tests/golden.hpp>)、[test_protocol.cpp](<tests/test_protocol.cpp>)：人工从源码推导的独立固定 hex 与异常/状态测试。
- [CMakeLists.txt](<CMakeLists.txt>)：独立入口；[build.ps1](<build.ps1>)：本机已实测的直接 MinGW 构建/测试替代入口。
- M1 实测报告 (`../../docs/room-client-m1-report.md`; full workspace)、协议审计 (`../../docs/yuzu-protocol-audit.md`; full workspace)、验收矩阵 (`../../docs/ACCEPTANCE.md`; full workspace)。

公开 API 已冻结。M2 不应修改此目录。Session 无 transport、线程或队列；宿主须串行调用，并提供不倒退的单调毫秒时间。
M2 收到真实 ENet CONNECT 后调用 begin_join 并发送返回 bytes；每个真实 channel0 RECEIVE 调用 receive；周期调用 advance；实际断线调用 disconnected。
协议要求可靠 ENet channel0；本库只审计 channel 值，不实现或验证传输可靠性。

## 离线构建

仅需 C++20 编译器与标准库；没有 FetchContent、下载、联网配置或新增网络依赖。

### 本机已执行的 MinGW 路径

从此目录执行（PowerShell 5.1 可用）：

~~~powershell
& './build.ps1'
# 非默认编译器路径时：
& './build.ps1' -Compiler 'G:/msys64/mingw64/bin/g++.exe'
~~~

脚本每次重编四个对象、链接两个程序、执行核心测试与四项 CLI smoke。
为规避 MinGW 不能处理本机中文工作区/TEMP 路径，使用 -pipe -c + 明确 ASCII 相对对象路径，再单独链接；不更改 TMP/TEMP。
只临时增加编译器目录到进程 PATH，finally 恢复；不改全局环境。不扫描/运行其它代理的构建。
MinGW 链接使用 --no-insert-timestamp；最终两个 EXE 已重复构建并验证 SHA256 相同。

### CMake 路径（入口已提供，本机缺 CMake/Ninja，未实测）

从 workspace 根执行；选择自己已有的 generator/compiler，以下适用于已存在 Ninja + GCC 的环境：

~~~powershell
cmake -S crossplay/room-client -B crossplay/room-client/build -G Ninja -DBUILD_TESTING=ON
cmake --build crossplay/room-client/build
ctest --test-dir crossplay/room-client/build --output-on-failure
# 重复构建：
cmake --build crossplay/room-client/build
ctest --test-dir crossplay/room-client/build --output-on-failure
~~~

需 CMake>=3.20。核心、CLI、tests 均由同一独立入口编译；CTest 声明 5 项测试，最后一项用 WILL_FAIL 验证截断退出非零。
**以上 CMake/CTest 命令尚未实际运行，不能把直接 GCC 测试说成 CTest 已通过。**

## 离线 CLI

从此目录执行；运行库目录须在 PATH（构建脚本执行期间已设置）：

~~~powershell
& './.build-direct/room-fixture.exe' emit-join Test
& './.build-direct/room-fixture.exe' decode s2c 02c0a80102
& './.build-direct/room-fixture.exe' replay Test fixtures/join-success.hex
& './.build-direct/room-fixture.exe' decode s2c 02c0a8  # 预期退出1，不是成功消息
~~~

emit-join 使用 version1、自动 IP、空密码/token；decode 只报告名称/包字节数，不打印凭据或数据内容。
replay 读取 [join-success.hex](<fixtures/join-success.hex>)（每行一条 S→C payload）或 stdin，每条非空行推进 1 个合成毫秒。
exit0=fixture 操作成功，exit1=协议/状态/文件错误或未完成加入，exit2=用法错误。

## 审计 wire 与子集

整数 u16/u32/u64 为 BE；IPv4 是四个原始 octet，**不是 u32，不进行端序反转**。
字符串/数据为 u32BE **字节数** + 原始字节，保留内嵌 NUL，不做 Unicode 转码。
证据：packet.cpp (`../../01052024-yuzu-mirror-master/src/network/packet.cpp#L172-L259`; full workspace)、packet.h (`../../01052024-yuzu-mirror-master/src/network/packet.h#L146-L162`; full workspace)。

| payload ID | 支持内容 | 证据 |
|---|---|---|
| 1 | nickname, IP4, version, password, token；Test 空凭据为25bytes | room_member.cpp:284–295 (`../../01052024-yuzu-mirror-master/src/network/room_member.cpp#L284-L295`; full workspace) |
| 2 / 24 | 成功/Moderator + IP4；恰好5bytes | room.cpp:641–658 (`../../01052024-yuzu-mirror-master/src/network/room.cpp#L641-L658`; full workspace) |
| 3 | 完整 RoomInformation；成员含 nickname/IP/game name/u64 id/version/username/display/avatar | room.cpp:772–794 (`../../01052024-yuzu-mirror-master/src/network/room.cpp#L772-L794`; full workspace) |
| 4 / 7 / 14 | SetGameInfo、双向不同布局 chat、status | room_member.cpp:668–699 (`../../01052024-yuzu-mirror-master/src/network/room_member.cpp#L668-L699`; full workspace) |
| 5 | 两端 family/IP/port、socket protocol、bool、opaque data | room_member.cpp:627–640 (`../../01052024-yuzu-mirror-master/src/network/room_member.cpp#L627-L640`; full workspace) |
| 6 | LDN type、local/remote IP、bool、opaque data | room_member.cpp:643–658 (`../../01052024-yuzu-mirror-master/src/network/room_member.cpp#L643-L658`; full workspace) |
| 8–13 / 15–16 / 22–23 | 已审计 server error；仅10另含u32BE服务器版本 | room.cpp:590–748 (`../../01052024-yuzu-mirror-master/src/network/room.cpp#L590-L748`; full workspace) |

IDs17–21（moderation 请求/banlist）明确 UnsupportedMessage；其余未知 ID 拒绝。M1 不是全协议/full room 客户端。
LDN type 0…5 是控制面；Proxy ID5 是独立 socket 数据面，data 在源客户端经 ZSTD。
这里只保存 outer envelope 原始字节，不解析 native NodeInfo/NetworkInfo，不解压/验证 ZSTD frame，不把 UDS payload 直接当 LDN data。
固定 Proxy 示例的9个 ZSTD frame bytes 仅验证 opaque 保留，不证明压缩/游戏互通。

## 限额与安全子集

| 字段 | 默认及硬上限 |
|---|---:|
| 单条二进制 payload | 65,536 bytes |
| 每个普通 string（含凭据） | 4,096 bytes |
| room slots / member count | 254（slots 至少1，count<=slots） |
| LDN/Proxy opaque data | 60,000 bytes |
| chat message | 500 bytes |
| hex text / CLI 每行 | 196,608 chars（hex 上限还随较小 packet cap 缩减） |
| application join / leave timeout | 默认5,000ms，各可配1…60,000ms |

Limits 仅可在正值至硬上限内缩小。上述资源上限是独立端保守政策，不是 ENet MTU 或全部 Yuzu 官方 wire 上限。
length 先验 cap/remaining 再分配；members 先验 count/slots/剩余最小布局再 reserve；完整消息必须精确消费，无尾随垃圾。
拒绝非法 bool/枚举/方向/截断。**原 Packet reader 把任意非0 bool当 true；这里仅接受0/1，是更严格的安全子集。**
底层 Join codec 支持有界任意 bytes/版本以做负面 fixture；Session 只接受源合法 ASCII 昵称4…20 bytes与 version1。

Session：Idle→Joining；允许 RoomInformation→JoinSuccess 顺序，成功还必须缓存自己的 nickname/IP对应成员；之后为 Joined/Moderator。
重复/乱序成功、重复成员 nickname/IP、已加入后丢失自身成员，均拒绝。
仅 Joined/Moderator 可 send game/chat/LDN/Proxy；LDN.local_ip 和 Proxy.local.ip 必须等于 assigned_ip。
stock 可在 Joining 发 SetGameInfo，本库刻意只在加入成功后允许应用发送；M2 应随后同步 metadata。
失败/leave/断线清理缓存与身份；join失败后必须显式 reset，不自动重试；begin_leave 不制造未定义的离房 wire 消息。
receive 错误不会修改成员身份/room/membership，但单调时钟可以推进；达到独立 deadline 时会明确转 timeout/清理，不保证时间停滞。

## 已实测 / 未完成

最终直接 GCC 构建：6/6 groups，1,432 checks，24 固定 golden，431 全部 codec 截断前缀，106 异常长度案例；CLI 4/4。
详细命令、最终哈希及失败尝试见 M1 报告 (`../../docs/room-client-m1-report.md`; full workspace)。
CMake/CTest 因工具缺失未执行；额外 UBSan 因缺 -lubsan 链接失败，未提供 sanitizer 通过证据。
未连接真实 room、未构建/运行模拟器、未执行 M2–M6 游戏/传输验收。SPDX 标识 GPL-2.0-or-later。
