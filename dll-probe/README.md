# M3 第一阶段：独立 Windows x64 DLL 生命周期探针

## Current role and entry point (2026-10-22)

Retained early DLL lifecycle experiment using its own loader host. The current production architecture is a standalone gateway with unmodified emulators; this probe is not required to run it.

Run from this source repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./dll-probe/build.ps1
```

See the [gateway status](../citra-gateway/README.md) and [desktop user guide](../gateway-gui/USER-GUIDE.md) for current player-facing behavior. The detailed reference below retains original milestone names and historical test counts. Commands containing `crossplay/` assume the parent engineering workspace; in a standalone checkout, omit that prefix. References to `../../docs/`, upstream source snapshots and private evidence refer to that larger workspace and are not distributed in this Git repository. Build scripts are the source of truth for required upstream paths and toolchains.

## Detailed module reference

> **没有 Citra Hook、没有实际 Citra 注入、没有游戏联机。** 本目录只在自有测试 EXE 中显式加载独立 DLL，复制、校验并计数合成 UDS-like fixture。没有 detour、远程进程注入、符号/地址扫描、guest memory、socket/ENet 或宿主私有接口。合成字段与 256-byte 上限不是 Citra UDS wire format，也不是游戏兼容证据。

## 快速复现（已实测）

在工作区根目录运行 Windows PowerShell：

~~~powershell
& './crossplay/dll-probe/build.ps1'
# 显式指定另一个已有工具链时，必须使用绝对路径；gcc/objdump 须在同目录。
# & './crossplay/dll-probe/build.ps1' -Compiler 'G:\msys64\mingw64\bin\g++.exe'
~~~

[build.ps1](build.ps1) 不安装工具、不改 PATH/TEMP/TMP、不修改模拟器。默认绝对编译器是 g++.exe (`G:/msys64/mingw64/bin/g++.exe`)；同目录调用 gcc.exe (`G:/msys64/mingw64/bin/gcc.exe`)、objdump.exe (`G:/msys64/mingw64/bin/objdump.exe`)。源码 C++17/C11，启用 -Wall -Wextra -Werror。脚本先切到自己的目录，用 -pipe 和相对路径显式编译 .o，再单独链接，避免本机非 ASCII 用户临时目录使 assembler 失败。结束恢复调用者目录。

产物与源码隔离：[DLL](build-mingw/dll_probe.dll)、[自有宿主 EXE](build-mingw/loader_host.exe)、[构建日志](build-mingw/build.log)、[测试日志](build-mingw/tests.log)、[SHA-256](build-mingw/sha256.txt)。默认每次重建并运行测试；-SkipTests 只跳过运行，不能据此声称测试通过。

已实测 g++.exe (`G:/msys64/mingw64/bin/g++.exe`) (Rev5, Built by MSYS2 project) 16.1.0，target x86_64-w64-mingw32，Windows 10.0.22631.0，Windows PowerShell 5.1。CMake/Ninja 未运行；[CMakeLists.txt](CMakeLists.txt) 仅供以后具备工具时验证，不承诺其他编译器/平台。

### 单独运行与核验

~~~powershell
$dll = (Resolve-Path -LiteralPath './crossplay/dll-probe/build-mingw/dll_probe.dll').Path
& './crossplay/dll-probe/build-mingw/loader_host.exe' $dll
$LASTEXITCODE # 预期 0
& 'G:\msys64\mingw64\bin\objdump.exe' -f $dll
& 'G:\msys64\mingw64\bin\objdump.exe' -p $dll
~~~

脚本已经实际对两份二进制运行 objdump：均为 pei-x86-64。DLL 导出地址表只有六项，名称逐项匹配下文。两者导入 **仅 KERNEL32.dll 与 msvcrt.dll**。链接使用 -static -static-libgcc -static-libstdc++，本次产物无需部署 msys-2.0.dll、libgcc、libstdc++、libwinpthread DLL；并非无系统运行库，也未证明所有 MinGW 版本产生相同依赖。静态运行库不应跨 DLL 分配/释放；本 API 没有这种行为。

## ABI 与限额

规范见 [dll_probe.h](include/dll_probe.h)；[C11 编译测试](tests/header_c_smoke.c) 对大小/偏移做静态断言。Windows x64 默认 packing、固定宽度整数、__cdecl、C 链接；ABI_VERSION=1，所有结构（含输出）调用前置零，并填 struct_size=sizeof(T)、abi_version=1。大小必须精确一致，较小/较大均拒绝，不声称可追加字段兼容。不要使用自定义 pack。无 STL、C++ 对象、动态内存所有权或异常跨 ABI。

| 精确导出名称 | 用途 |
|---|---|
| dp_get_abi_version | 返回 ABI 版本；允许 start 前查询 |
| dp_get_limits | 返回固定上限；输入输出结构 32 bytes |
| dp_start | 配置 32 bytes；显式创建一条 worker 和唤醒 event |
| dp_submit | 记录 288 bytes；同步完整复制到 DLL 的有界环形队列 |
| dp_snapshot_read | 快照 72 bytes；状态、排队/在途数量、计数及最后处理序号/校验和 |
| dp_stop | 请求排空、等待实际线程句柄退出（join），成功后关闭句柄 |

- 队列容量 1..64，最多另有 **1 条在途记录**；静态队列储存固定 64 条，无无界增长。payload_size 1..256；只对 payload_size 范围计算 FNV-1a 32。
- 合成 source_node 1..16；destination_node 1..16 或 65535（广播）；channel 0..31；reserved 必须零。没有真实节点/MAC/IP 映射或协议语义。
- worker_delay_ms 0..500，专为合成处理/背压测试使用。正常可配置为零；没有回调、外部 I/O 或宿主写操作。
- 每次 stop 的 timeout_ms 0..5000；0 是非阻塞探测，不保证当次返回成功。最多 65 条 × 500 ms 的排空工作量可超过单次 5 s；宿主须保留模块并重试。OS 调度不是硬实时，不承诺墙钟绝对完成上限。
- snapshot 累积 submitted/completed/payload_bytes/rejected_full，记录最后完成的序号/长度/校验和；一次成功 start 重置统计。序号仅原样记录，不校验连续性。计数为 uint64_t，未做永不溢出的无限期运行承诺。
- 无效参数按 NULL→struct_size→abi_version→字段范围先检查，再检查生命周期；队列满只增加 rejected_full，不接受/覆盖记录。

## 必须遵守的生命周期 / 卸载契约

**宿主必须跨所有调用线程，外部串行化全部导出调用，包括 submit、snapshot、start、stop；并发/重入调用不属于支持契约。内部锁只协调宿主串行调用与 DLL 自己的 worker。** 不得从 DllMain/loader-lock、任何回调或 worker 上调用初始化、停止、卸载。不要把 API 函数指针交给卸载后仍可能运行的任务。

| 状态 | 行为 |
|---|---|
| FRESH | 查询可用、计数为零；submit=NOT_RUNNING，stop=NOT_STARTED；可 start |
| RUNNING | 可提交/读快照；重复有效 start=ALREADY_RUNNING |
| STOPPING | 拒绝 submit，start=BUSY；worker 排空已接受的记录；可重试 stop |
| STOPPED | worker 已 join、两个句柄已关闭；重复 stop=OK；可重新 start 并清零统计 |

安全顺序：停止产生提交 → 收拢全部调用者（全部 API 已返回）→ 串行 stop → 仅在返回 DP_OK 后清除函数指针并 FreeLibrary。自有宿主还检查 STOPPED、queued=0、in_flight=0，再卸载并检查模块确实不存在。**stop=TIMEOUT 绝不表示可卸载**：保持 DLL/函数指针有效，拒绝新提交并重试 stop；线程真正退出前不关闭句柄、不 TerminateThread、不 FreeLibrary。

本实现没有自定义 DllMain，没有用户全局构造/析构器；系统/编译器 CRT 入口仍存在。线程只在显式 start 创建。空闲 worker 等待 event，stop 会唤醒；完成所有已接受记录后才退出。无用户回调 API，因而不可能等待用户回调返回，也不支持回调内自卸载。

每个导出与线程入口均以 catch(...) 拦截 C++ 异常并返回/记录 INTERNAL；当前实现不主动抛异常。**这不是对野指针、访问冲突、SEH、损坏堆的恢复保证**：非空指针须是本次调用期间有效、可访问、正确对齐的完整对象；调用期间不得被其他线程改写。submit 返回后宿主可以改写/释放自己的记录，worker 只读私有副本。输出版本/限额/快照由调用者显式提供，除此不修改宿主数据。

对 OS/INTERNAL 故障不要无条件卸载或自动重启循环；保留模块检查状态/完整性，只有后续 stop 明确成功、已无调用者后再卸载。本阶段未强制注入 OS 句柄/线程创建失败。测试断言若失败会终止**自有测试 EXE**而非危险卸载；这不是任何真实宿主的故障处置方案。

## 已执行测试与边界

[loader_host.cpp](tests/loader_host.cpp) 每次 LoadLibraryW 后完整解析六个导出，在成功 stop 后才 FreeLibrary。一次完整运行输出：

~~~text
PASS suite=loader-version-fresh checks=13
PASS suite=invalid-null-size-limits checks=36
PASS suite=copy-drain-restart checks=14
PASS suite=queue-full-timeout-recovery checks=13
PASS suite=idle-no-callback-stop checks=5
EVIDENCE cycles=32 handles_before=61 handles_after=61
PASS suite=32-load-stop-unload-cycles checks=579
SUMMARY suites=6 checks=673 failed=0 loads=33 unloads=33
~~~

673 是运行期断言数（含测试套件外的加载/卸载检查），不是 673 个独立测试用例；C11 静态断言不计入其中。32 是额外重复循环，另有 1 次综合加载，所以共 33 次加载/卸载。覆盖：加载失败/未知符号后恢复，null/精确大小/版本/保留字段/限额，未初始化读取与提交、重复 start/stop、重新 start 统计清零，复制后修改源 fixture、固定黄金校验和，排队满不覆盖，stop(0) 超时→STOPPING 拒绝提交/启动→重试排空 join，空闲无回调退出，反复模块移除与句柄无净增长。

同一产物另外独立运行五次，均为 673 checks/33 loads/33 unloads/exit=0，记录在 [五次回放日志](build-mingw/replay-tests.log)。包括默认构建测试共六次宿主执行、4038 次断言、198 对加载/卸载，不意味着新增测试种类或长时稳定性证明。

未覆盖：强制资源分配/Win32 API 失败、实际 C++ 抛出异常、非法非空指针、恶意内存破坏、并发 public API/并发 stop/unload（明确不支持）、任意时刻安全卸载、32-bit/ARM/Linux/MSVC/CMake、多日压力与真实 Citra/游戏。时间窗口测试依赖本机能在 500 ms 合成延时内执行几条宿主调用，不是任意系统负载下的硬实时测试。完整实施证据见 M3 报告 (`G:/抛瓦饮料/跨平台联机/docs/dll-probe-m3-report.md`)。

## 来源与许可证

本目录头文件、DLL、宿主、C smoke、构建描述均为本任务原创，没有复制 Citra/Yuzu/Luma 代码；仅依据项目安全验收需求设计。源码均含 SPDX-License-Identifier: GPL-2.0-or-later，许可说明见 [LICENSE.md](LICENSE.md)。Win32 API 来自系统头/库，GCC 链接产物包含其工具链运行库；发布时应保留对应许可证/例外与可对应的源码，不把这里的运行验证当作第三方许可证审计或可直接分发的发布包。
