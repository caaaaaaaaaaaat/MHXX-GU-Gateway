# Yuzu v1 回环采集前端

独立 ENet 观察前端：每个下游 peer 对应一条独立上游连接，连接原版自建房间。
保留房间帧字节，不做 MHXX/MHGU 转换，不修改模拟器。只绑定与连接 127.0.0.1。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/yuzu-capture/build.ps1 -RunTests
crossplay/yuzu-capture/.build-direct/yuzu-capture.exe --help
```

构建使用当前 MinGW 工具链、已有 vendored ENet/fmt、系统静态 zstd，直接链接既有
`yuzu-room` 离线 codec 和 `citra-gateway/src/trace.cpp`，不复制其实现。
测试链接未修改的原版 Room/Packet/VerifyUser 源码，以合成客户端验证保真与生命周期。

正常采集示例（先单独启动严格回环的自建房间）：

```powershell
crossplay/yuzu-capture/.build-direct/yuzu-capture.exe --listen-port 24940 --room-port 24930 --seconds 600 --trace-out G:/mh-evidence/g2-trace/g2b.jsonl --manifest <基线ID> --build <Yuzu构建ID>
```

两个 Yuzu 客户端均加入 `127.0.0.1:24940`。房间密码、昵称等由原客户端发送，
前端不生成或改写加入请求；版本错误回复后仍允许客户端在同一连接重试。
CLI 默认限时 60 秒；`--stage-file` 可读阶段标签；只有显式 `--trace-raw` 才保存原文。
用户已指定在当前G盘项目工作：真实原文保存在专用 `.private-runtime/evidence/<新运行名>/`；工程外私密目录仍可使用。合成测试原文留在 `.build-direct/evidence/`。

隔离程序准备：`powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/yuzu-capture/prepare-instances.ps1`。
默认在系统临时目录建立全新 A/B 副本，固定 2022 main 哈希，逐文件核对程序和资源，建立独立便携 user 与关闭遥测的回环配置。不复制原 user、密钥、NAND、存档或游戏，也不启动 GUI。当前用户授权的实例位于项目 `.private-runtime/mhgu-20261015/`，已单独复制私密运行数据；不得覆盖。准备器只允许专用私密子树或隔离的工程外目录，目标必须与原安装分离且不存在。输出 preparation.json 的 game_ready/game_verified 均为 false。

NetworkInfo的节点数组固定8槽；node_count表示连接总数，并非连续有效前缀。观察器输出node_slots=8及全部槽位元数据，以保留退出后留下的空槽和后部在线玩家。旧采集只记录前node_count槽，无法从其结构元数据证明后部无人；若保留原文仍可重新分析。用户名不进入结构元数据。

原生测试故意发送一个非法LDN长度包。严格trace审计应报告恰好1个错误，构建脚本验证该指定错误并要求其余审计通过；这份负例trace的passed=false是预期结果，不用于证明游戏流量有效。

输出 trace 的 `channel=B`，`role=observer` 表示共享采集前端，而非某个玩家。
每条网络记录有 `peer_id`，可据 JoinSuccess 的 assigned_ip 和原始加入请求把玩家与会话归因；
要给出 host/client 游戏角色结论，仍需运行 manifest 的人工/编排角色表，不能按接入先后猜测。
原文是完整 v1 房间帧，Proxy 的压缩载荷位于其内部，区别于旧网关只记录压缩数据的 trace。
未保存原文时只留包长、哈希、端口等结构字段，不保存昵称、聊天、密码或 token 字符串。

观察器对可解码消息记录 Proxy endpoint、压缩长度、可验证的解压长度/哈希；
Zstd 仅验证单帧、已知长度且解压上限 60000 B。LDN 按冻结尺寸表检查。
不合该尺寸的 LDN、无法验证的 Zstd、损坏的 LDN/Proxy 封套会标记 undecoded，
记录 forwarding_allowed=false 并拒绝转发，两个方向均生效，未启用 trace 时同样检查。
其余房间管理消息保持原字节；合法网络帧逐字节保真，不做跨协议转换。

限额：默认 4 peer（最大 16）、每帧 65536 B、每 session 待发和待 ACK 总计最多
64 packet/262144 B；超限关闭该会话。连接/加入/退出有 deadline，每 tick 有事件预算。
trace 打开失败在绑定前报错；写入失败使本次运行返回非零，不宣称采集完整。

CLI 退出码：0=正常到时关闭（不代表产生流量），2=参数错误，3=启动/运行异常，4=trace 失败。
空运行也有 run.begin/run.end。真实运行是否捕获完整须检查事件和计数。

当前状态与缺口以 docs/VERIFICATION-LOG.md 和 docs/HANDOFF.md 为准。

真实专用房间互操作（只启动已核对哈希的 EA 专用房间与合成客户端，不加载游戏）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/yuzu-capture/real-interop.ps1
```

脚本核查 UDP 实际绑定地址与 PID，设置测试看门狗，结束时关闭自己的房间进程并核查端口释放。
2026-10-15 已通过，报告位于 `.build-direct/real/20261015T041427148Z/report.json`。

完整采集编排（启动专用房间和观察前端，不启动或结束用户的游戏 GUI）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/yuzu-capture/capture-run.ps1 -InstanceA G:/private/yuzu-a -InstanceB G:/private/yuzu-b -EvidenceDir G:/private/evidence/run-001 -ManifestId baseline-001 -Seconds 600 -TraceRaw
```

真实运行前会调用双实例预检；证据目录必须为空，位置在工程外或用户指定的项目 `.private-runtime/` 专用子目录内，阶段标签写入输出目录的 stage.txt。脚本核对两端口的实际绑定/PID，设置看门狗，独立审计 trace，在 finally 中只结束自己启动的专用房间和观察前端并确认端口释放。report.json 的 passed 表示编排、采集记录检查与清理通过；game_verified 始终 false，不将空跑或成员表计为游戏成功。

不加载游戏的编排冒烟：`capture-run.ps1 -SyntheticOnly -Seconds 3`。此开关只用于无真实游戏的合成测试，允许证据留在构建目录。独立回归命令为 `powershell -NoProfile -ExecutionPolicy Bypass -File crossplay/yuzu-capture/tests/test-runner.ps1`，覆盖含空格路径、默认无原文、重复证据保护、缺少前置、非法参数、端口冲突和收尾；10 项检查通过。
