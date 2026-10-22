# crossplay — 《怪物猎人XX/GU》跨模拟器联机网关

让 3DS《怪物猎人XX》(Citra 系模拟器) 与 NS《怪物猎人GU》(Yuzu 系模拟器) 进入**同一个集会所**联机狩猎的协议网关。两端模拟器均**不做任何修改**,翻译工作全部由一个独立网关进程完成,并配套了面向普通用户的 Windows 图形界面。

> 本项目仅供网络协议学习与技术研究。仓库不包含任何游戏 ROM、密钥、存档;联机请使用自建房间服务器,请遵守相关法律法规与用户协议。

## 当前版本（2026-10-22）

联机核心为 V333，Windows GUI 为 V336。GUI 首次启动时服务器地址与端口留空，Citra 接入端口默认 `8888`；正常关闭时记住输入，密码通过当前 Windows 用户 DPAPI 加密。“关于”前的“配置”页支持保存监听 IPv4 地址，默认 `127.0.0.1` 仅限本机，可改为 `0.0.0.0` 接受其他电脑连接；保存后下次启动网关生效，下次打开程序自动恢复。

现场确认覆盖两种房主的三人入厅及“两台 Yuzu + 两台 Citra 正常联机”。长时间稳定性、断线重连、任务加载/换区/结算、全部加入顺序与独立多厅尚无完整验收结论。

本仓库根目录直接包含各模块，下文构建命令从此目录执行。各模块历史参考中带 `crossplay/` 前缀的命令以完整工程工作区为起点。完整工程中的 `docs/`、上游源码镜像和私密证据未随此源码仓库分发。

## 功能介绍

- **跨模拟器联机**:Citra 上的 MHXX 与 Yuzu 上的 MHGU 加入同一场集会所,混合组队狩猎。2026-10 已完成"两台 Yuzu + 两台 Citra"四人混编与两种房主(XX 房主 / GU 房主)配置的现场验收。
- **模拟器零修改**:Citra 与 Yuzu 都以为自己在和"正常的同类客户端"联机——Citra 把网关当成一个普通房间服务端,Yuzu 把网关当成房间里的一个普通玩家。现有稳定版模拟器无需换版本、无需打补丁。
- **Windows 图形界面**([gateway-gui](gateway-gui/README.md)):填写服务器地址、UDP 端口、本机 Citra 接入端口与密码即可启动网关,实时显示服务器连接状态与"已接入 X 台 Citra"。不创建多余房间成员、不内嵌网页服务。使用方法见[用户指南](gateway-gui/USER-GUIDE.md)。
- **命令行网关**([citra-gateway](citra-gateway/README.md)):面向研究者的完整参数入口,支持逐层开关(控制面桥、数据面转发、反向注入、双房主模式等)与运行计数器,便于分层定位问题。
- **离线协议库与测试基础**:房间协议 codec、控制面映射库、真实房间服务器互操作测试框架,全部自带测试,可独立复现。

**诚实边界**:以上联机结论来自真机混合四人验收;更早的验收记录、测试边界与逐轮证据保存在工程仓库历史中。本仓库不声称支持一切模拟器版本组合,具体适配范围见各模块 README 与提交记录。

## 仓库结构

| 模块 | 说明 |
|---|---|
| [citra-gateway](citra-gateway/README.md) | **核心网关**:Citra v4 房间协议 ⇄ Yuzu v1 房间协议的双向翻译进程,含控制面桥与数据面翻译 |
| [gateway-gui](gateway-gui/README.md) | Windows 原生图形界面,封装网关核心 |
| [citra-control](citra-control/README.md) | 控制面离线映射库:UDS(802.11/EAPoL)⇄ LDN 字节级解析/生成/状态机 |
| [room-client](room-client/README.md) | M1 离线房间协议核心(C++20 codec + 有界状态机) |
| [room-transport](room-transport/README.md) | M2 原生 ENet 传输,与未修改的原版 Room 源码互操作 |
| [real-room-interop](real-room-interop/README.md) | 真实 yuzu-room / citra-room 互操作测试框架 |
| [yuzu-room](yuzu-room/README.md) / [citra-room](citra-room/README.md) | Yuzu(LDN v1)/ Citra(v4) 房间协议离线 codec 基础库 |
| [lan-codecs](lan-codecs/README.md) | 局域网帧格式 codec(UDS 帧、NetworkInfo/NodeInfo、zstd) |
| [yuzu-capture](yuzu-capture/README.md) | 回环录制中继:录制真实 Yuzu 客户端与房间服务器之间的全部帧,用于协议逆向 |
| [dll-probe](dll-probe/README.md) | DLL 生命周期探针(早期注入路线的可行性验证,当前主路线不注入) |
| [tools](tools/README.md) | Node.js 追踪审计、数据流预览等研究工具 |
| [env-manifest](env-manifest/README.md) / [review-tools](review-tools/README.md) | 环境清单与代码评审工具 |
| `reference/`(不入库) | 上游 Yuzu/Citra 源码只读快照,协议事实的引用出处,见下文"构建依赖" |

## 原理

### 总体架构:独立翻译网关,而不是修改模拟器

早期方案设想在 Citra 端注入 DLL 做协议翻译。实施中改为**独立网关进程**:任何一侧模拟器都不用改,反而更稳、更易分发。

```
Citra (MHXX, 未修改)                Yuzu (MHGU, 未修改)
  │ 以普通房间客户端身份                │ 以普通房间客户端身份
  │ 经 ENet/UDP (v4 线格式)            │ 经 ENet (v1 线格式)
  ▼                                   ▼
┌────────────────── crossplay 网关 ──────────────────┐
│ 对 Citra 扮演:房间服务端 + UDS 主机                │
│   (信标/关联/EAPoL 认证/数据帧)                    │
│ 对 Yuzu 扮演:房间里的一名普通成员                  │
│   ── ENet ──▶ yuzu-room(未修改的自建房间服务器)    │
│                                                    │
│  身份映射:每会话维护 Citra 6字节MAC ⇄ Yuzu 伪IPv4  │
│  控制面翻译:UDS ⇄ LDN(发现/接入/网络同步)          │
│  数据面翻译:MH/Pia 游戏包(身份词/成员表/批量流)     │
└────────────────────────────────────────────────────┘
```

关键设计(ADR-009):**一台 Citra 客户端 = 房间里的一个 v1 成员**;网关自身不占成员位。两侧永远看不到对方的协议版本号——Citra 侧只见 v4,房间侧只见 v1。

### 控制面:发现与接入的翻译

- **发现层**:MHGU 的集会所搜索基于 LDN `Scan/ScanResp`,回应体是 1152 字节的 `NetworkInfo`;MHXX 基于 3DS UDS 信标扫描。网关把 Citra 的实时信标 `application_data` 动态注入 LDN 广告(200 字节,含 UTF-16LE 厅名、comm id 覆写,并处理两款游戏广告布局差 8 字节的密码槽错位),于是 **MHGU 的搜索列表里能直接列出 MHXX 玩家建的厅,显示真实厅名**。
- **接入层**:MHGU 发 LDN `Connect`,网关翻译为 UDS 侧的关联 + EAPoL 认证流程;反向还有**客人注入**——网关冒充新客机向 Citra 完成 Authentication/EAPoL 握手,让 MHXX 的节点表里真的多出一个成员,从而驱动 MHXX 侧产生游戏层流量。
- 网络成员视图双向同步(`SyncNetwork` ⇄ 节点表),MAC、昵称、节点号按会话一一映射。

### 数据面:游戏层包的翻译

真正让两款游戏"看见彼此"的是 MH/Pia 游戏层流量。Citra 侧它们装在 UDS Data 帧(LLC EtherType `0x876D` 的 SecureData)里;Yuzu 侧它们以 zstd 压缩的 ProxyPacket 在房间内中转。网关在中间做逐类翻译:

- **厅通告(kind0)**:剥离 41 字节封装头后做 4 字节**身份词替换**。XX 侧身份词是 `CRC-32/ISO-HDLC(NodeInfo.friend_code_seed)`,须映射为 GU 侧认识的端点词,消息头 sender 原样保留。
- **成员表(`0x0111`)与控制帧**:成员表槽数、host 标识、各槽 endpoint/端口按两侧格式重排;心跳与控制帧两侧逐字段同构,差异只有身份词与本地时间戳。
- **会话状态机**:按实测的 station/session-node 状态条件驱动准入与授权(如 family-02 状态授予),心跳节拍按两侧节奏重缩放。
- **GU→XX blob 转换**:把 GU 侧主数据流转成 XX 侧可接受的形态,解锁批量数据通道。
- 加密/压缩形态的会话数据不做字段级伪造,而是靠上面各层让**两侧游戏各自相信对端存在**,由游戏自身的会话机制完成后续握手。

### 部署拓扑

```
[自建 yuzu-room 房间服务器] ◀── Yuzu 玩家(JOIN 网关通告的厅)
        ▲
        └── crossplay 网关 ◀── Citra 玩家(连本机网关端口)
```

房间必须先由 yuzu-room 提供(网关以普通客户端身份加入),因此 **Yuzu 侧要"加入"网关通告的厅,而不是自行创建房间**。Citra 玩家则像连普通房间一样连本机网关。

## 构建

工具链:Windows + PowerShell 5.1,MinGW-w64 GCC(如 `G:\msys64\mingw64`),系统 zstd;追踪/预检工具需 Node.js 22+。各模块自带 `build.ps1`,例如:

```powershell
# 网关
powershell -NoProfile -ExecutionPolicy Bypass -File .\citra-gateway\build.ps1 -RunTests
# 图形界面(产物在 .build-desktop/XXGU-Gateway/)
powershell -NoProfile -ExecutionPolicy Bypass -File .\gateway-gui\build.ps1 -RunTests
# 数据流研究工具
node --test tools/
```

**构建依赖说明**:部分模块的互操作 harness 会编译**未修改的上游源码**(Yuzu 的 `room.cpp`/`packet.cpp` 等),这些上游快照(`reference/`、工程工作区里的 Citra/Yuzu 源码镜像)不含在本仓库中,需要自行获取对应版本并按各模块 README 的路径放置。协议相关的字节级事实均在模块文档中标注了上游源码出处。

## 使用

普通用户:启动 [XXGU-Gateway](gateway-gui/USER-GUIDE.md) 图形界面 → 填写自建服务器地址/端口与 Citra 接入密码 → 启动网关 → Citra 玩家连接界面上显示的本机端口,Yuzu 玩家在游戏内搜索并加入对应厅。

研究者:直接使用 [citra-gateway CLI](citra-gateway/README.md),按需开启 `--control-plane`、数据面转发、客人注入、双房主模式等开关,并观察运行计数器定位问题层级(网关计数器 → 房间日志 → 游戏画面)。

## 许可证

各模块带有各自的许可证声明(GPL-2.0-or-later / GPL-3.0-or-later 等),见各模块目录内的 `README.md`、`NOTICE.md` 或 `LICENSE*` 文件。与上游 GPL 源码链接构建的部分遵循相应上游许可证。

## 免责声明

本项目输出物为协议研究与教育用途,不包含、不分发游戏 ROM、密钥、存档;不绕过任何付费验证;请勿连接官方服务器。使用本项目的联机功能请使用自建房间服务器,并对自己的行为遵守当地法律法规与相关用户协议负责。
