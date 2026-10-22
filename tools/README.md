# Trace audit

## Current role and entry point (2026-10-22)

Offline protocol analysis, trace auditing, conversion previews and optional diagnostic scripts. The V236 and earlier test totals below are historical milestones, not current full-repository acceptance totals. Conservative flags in preview tools describe those tools only; current production translation and live acceptance are documented in citra-gateway.

Run from this source repository root:

```powershell
node --test ./tools/*.test.mjs
```

See the [gateway status](../citra-gateway/README.md) and [desktop user guide](../gateway-gui/USER-GUIDE.md) for current player-facing behavior. The detailed reference below retains original milestone names and historical test counts. Commands containing `crossplay/` assume the parent engineering workspace; in a standalone checkout, omit that prefix. References to `../../docs/`, upstream source snapshots and private evidence refer to that larger workspace and are not distributed in this Git repository. Build scripts are the source of truth for required upstream paths and toolchains.

## Detailed module reference

V-236当前统一工具回归为250项，33个测试文件直接执行node --test通过；PowerShell统一26批入口亦exit0。新增[同侧连续terminal body序列预览](mh-stream-receive-sequence.mjs)：同一观测集上以显式bodyLimit逐body预览，分桶预检不添加信任，每轮子集原样交既有receive preview完整重算，第k+1轮start=上一body terminal+1；全部供给须在首start的64槽内，超窗拒绝而非截断，stoppedReason四值与complete独立。不consume/ACK/推进base，能力标志仍false。见契约 (`../../docs/MH-STREAM-RECEIVE-SEQUENCE-CONTRACT.md`; full workspace)。

V-235统一工具回归为241项，32个测试文件直接执行node --test通过；PowerShell统一25批入口亦exit0。新增[首typed body到显式目标候选关联](mh-base-peer-list-transfer-preview.mjs)：每次从原始snapshot/messages重算receive preview，target为closed独立声明加1..64行显式outer/stream/payloadLength计划，source未齐时candidate=null但坏声明仍逐行拒绝；候选来自既有checked mapper，不消费/入队/ACK，deliveryStatus恒unverified。见契约 (`../../docs/MH-BASE-PEER-LIST-TRANSFER-PREVIEW-CONTRACT.md`; full workspace)。本轮在前一代理中断后由接手代理独立复跑补齐验收。

V-234历史统一工具回归为233项，31个测试文件直接执行node --test通过；PowerShell统一24批入口亦exit0。新增[同侧DATA快照预览](mh-stream-receive-preview.mjs)：closed上下文/显式start下完整验证pending+incoming，允许gap，首个连续terminal body仅作预览，保留全部消息、不consume/推进base/ACK/交付。抽取共享outer/context检查复用于旧ACK，能力标志仍false。见契约 (`../../docs/MH-STREAM-RECEIVE-PREVIEW-CONTRACT.md`; full workspace)。未改生产/Yuzu、未重建C++或运行原生网关；真实互通仍待用户测试证据。

V-233历史统一工具回归为223项，30个测试文件直接执行node --test通过；PowerShell统一23批入口亦exit0。新增[同侧发送窗口批次重放](mh-stream-send-replay.mjs)：closed观察项顺序应用原ACK上下文guard与schedule比较，返回独立历史，不发送、不enqueue、不生成ACK/序号或持久提交；MAX equality仅比较通过，能力标志仍false。见契约 (`../../docs/MH-STREAM-SEND-REPLAY-CONTRACT.md`; full workspace)。本轮未重建C++或运行网关。

V-231历史统一工具回归为215项，29个测试文件直接执行node --test通过；PowerShell统一入口亦exit0，未修改系统执行策略。新增零FCS四fixture（合法空/正确checksum、非空raw/错误checksum）在两个显式Room profile下回归。另见现有C++网关隔离构建与零FCS生产helper修复 (`../../docs/MH-GATEWAY-OFFLINE-BOUNDARY.md`; full workspace)：原三EXE+新codec EXE完整重建，仅执行identity34+codec41内存检查，不开harness网络，不接MH局部转换；旧产物未覆盖。

[同侧ACK上下文守卫](mh-stream-context-ack.mjs)提供applyMhStreamAckForContext(window,message,observedContext)：closed profile/sessionId/epoch/windowId/routeKey/senderIdentity相等并匹配wire route/sender后，应用原ACK阶段，返回新snapshot；不生成ACK/序号/发送、不跨侧映射。contextMatched仅为声明相等，其余能力标志全false，不认证、不抗重放。详见契约 (`../../docs/MH-STREAM-CONTEXT-ACK-CONTRACT.md`; full workspace)。

[列表流原sender对应守卫](mh-base-peer-list-stream.mjs)另提供translateMhBasePeerListStreamCheckedSender(messages,{sourceSenderIdentity,...options})，去重前核对所有source原sender，并检查显式目标sender与map/session方向映射一致；不自动填/改头，不提前用GU单块限制拒绝可重新分段的XX source。senderCorrespondenceValidated仅表示字节关系，非认证/生产放行。详见契约 (`../../docs/MH-BASE-PEER-LIST-SENDER-CONTRACT.md`; full workspace)。

[完整列表流条件endpoint组合](mh-base-peer-list-stream.mjs)提供translateMhBasePeerListStream(messages,options)：先恢复完整列表/单份variant2，再按显式base分支断言只映射首endpoint地址，使用独立目标route/startSequence/头与精确payloadLength计划重分段并复验typed body。只返回局部转换，三项能力标志false，不自动映射outer sender或生成可靠流状态。详见契约 (`../../docs/MH-BASE-PEER-LIST-STREAM-CONTRACT.md`; full workspace)。

[GU封套/XX原始包局部身份组合](mh-gu-proxy-identity.mjs)提供translateMhguProxyToMhxx与translateMhxxToMhguProxy。仅GU侧使用Room/Zstd；显式Proxy profile、独立目标MH头/Proxy头、route/session/map/两端key，只映射消息头原身份。XX传输由调用者提取，不生成ACK/序号或绑定IP。仅compressionValidated=true，其余三个能力标志false。详见分层契约 (`../../docs/MH-GU-PROXY-IDENTITY-CONTRACT.md`; full workspace)，不接生产。

[有界压缩载荷组合](yuzu-udp-datagram.mjs)提供decodeYuzuUdpProxyDatagram(packet,profile)/encodeYuzuUdpProxyDatagram(header,datagram,profile)，显式目标头/profile，单个已知大小Zstd帧，无字典、压缩<=65536/输出<=60000/窗口<=131072。仅compressionValidated=true，三个既有能力标志仍false；不解释MH语义、不认证、不发包。分析器提取共享[zstd-frame原语](zstd-frame.mjs)并收紧同样输入策略；详见契约 (`../../docs/YUZU-UDP-DATAGRAM-CONTRACT.md`; full workspace)。

[UDP Proxy封套编解码与参考profile局部转换](yuzu-udp-proxy.mjs)提供decodeYuzuUdpProxyPacket(packet,profile)与encodeYuzuUdpProxyPacket(header,data,profile)：严格拆分为独立header/data，或按独立21字节目标头重建BE32长度；校验但不改目标枚举、不自动压缩、不验证data语义。另提供translateYuzuUdpProxyProfile(packet, sourceProfile, targetProfile)：显式2022与01052024镜像profile，仅改两处IPv4 family和一处UDP枚举。严格完整21字节头/长度，opaque data最多65536字节（工具限制），其他字节不变。无EA猜测，不解压、不验证payload/应用/源身份，不接生产；三项安全边界标志始终false。见契约 (`../../docs/YUZU-UDP-PROXY-PROFILE-CONTRACT.md`; full workspace)。

[原始调用观察校验器](mh-init-raw-observations.mjs)提供checkMhInitRawObservations(events, profile)，仅显式GU v262144。独立配对两次入口/返回，保留漏采、未知原始状态和未完成记录；始终列出来源/规范化/资源/生命周期证据未知，不输出V-220规范化事件。metadataConsistent或gaps为空不代表初始化成功。详见原始观察契约 (`../../docs/MH-INIT-RAW-OBSERVATIONS-CONTRACT.md`; full workspace)，未安装观察器，不接生产。

[生命周期声明校验器](mh-collection-evidence.mjs)提供checkMhCollectionEvidence(events)：纯离线闭合JSON元数据检查，区分session/epoch/generation和两次独立初始化结果；新attempt撤销旧成功关联。localContractSatisfied仅历史声明内部一致，不是真实观察、存活或认证，productionReady始终false。status0是记录器声明的规范化成功，未证明所有真实callee结果语义。详见证据契约 (`../../docs/MH-COLLECTION-EVIDENCE-CONTRACT.md`; full workspace)，不接转换器或生产。

[基类列表端点局部转换](mh-base-peer-list-endpoints.mjs)提供translateMhBasePeerDescriptorEndpoint与translateMhBasePeerListEndpoints。options必须显式给出profile、endpointBranch='base-first-endpoint-a'、identityMap及sessionId；分支标签是调用者断言，不检测真实工厂。只改首endpointA，wire18/53和其他端点逐字保留；支持完整列表与独立两片之一，空列表仍验会话，任一项失败无部分返回。applicationConverted=false，不自动转换消息头、可靠状态或未知描述字段，不接生产。

[包级身份组合](mh-packet-identity.mjs)提供translateMhPacketStreamIdentities(packet,{profile,targetHeader,expectedRouteKey,identityMap,sessionId,sourceKey,targetKey})。显式目标包头、独立两端key；空包也校验会话及route参数。仅映射消息头原身份，保留opaque尾部，任一消息失败整包拒绝。调用者须预先确认同一stream路由，返回applicationConverted=false，不认证会话或key，不转换嵌入描述，不生成序号/ACK，不接生产。详见入口契约 (`../../docs/MH-CONVERSION-ENTRY-CONTRACT.md`; full workspace)。

`mh-packet.mjs`提供decodeMhPacket/encodeMhPacket：固定双profile、12字节包头、mode1直接分帧、mode2显式key变换后分帧；保留未知包头、消息对齐字节及FF起始的opaque尾部，返回独立Buffer。mode1 body<=1460，mode2块对齐body<=1456。不解释包头序号/时间字段、不验证会话或body语义，不接生产网络。成功分帧不表示转换成功。

`mh-packet-transform.mjs`共享固定mhxx-1.4/mhgu-v262144的显式key包body变换。V-204独立核验XX的FF填充、逐16字节块流程及完整AES表；共享接口不处理包头、不去FF、不自动映射body字段，也不获取真实会话key。原GU专用接口保持仅接受GU profile。两端真实密钥来源与运行模式仍待绑定。

`mhgu-packet-transform.mjs`提供GU v262144包body的AES-128独立块加解密，必须显式提供16字节key；发送仅以FF补齐16字节，接收不去除FF，最多1456字节。只处理12字节外包头之后的body，不读取或推导游戏密钥，不自动设置packet mode，不提供认证，也未接生产网关。

`recoverMhPeerListFromMessages`新增20字节头完整消息入口，严格检查对齐长度及显式route key，再提取流块恢复列表；保留外头和原身份字段，调用者负责先拆包及同peer/session归属。见转换入口契约 (`../../docs/MH-CONVERSION-ENTRY-CONTRACT.md`; full workspace)。

`mh-stream-ack.mjs`提供离线ACK阶段纯函数：累计确认释放前缀，位图置位把对应调度设为UINT64_MAX，旧ACK不推进。窗口必须由调用者提供，限制64槽且不回绕；不模拟后续数据插入、定时器、通道检测或在线重传。调度比较使用uint64 BigInt并保留最大值相等时放行的边界。

`mh-system-stream.mjs`把已知同peer/session的流块恢复为完整系统body，再严格检查类型0x20并解析完整列表或variant2独立分片。要求固定profile和显式起始序号，返回原body及流头副本；不自动跨列表分片合并，不转换未知消息，不接生产网络。

V-195增加encodeMhStreamMessage({outerHeader, streamHeader, payload}, profile, expectedRouteKey)，重建单条按4字节对齐的消息。调用者提供20字节外头、24字节子头与已关联的route；仅更新两层长度，尾部补零，保留身份、序号及ACK。GU沿用1416字节payload上限，MHXX同时受外头BE16长度限制。此接口不生成可靠流状态或数据报。

V-201增加translateMhStreamMessageIdentity(message, profile, expectedRouteKey, identityMap, sessionId)，只映射20字节外头+8的原始发送者身份。验证精确消息边界、route及源/目标profile流块限制，要求MhIdentityMap和匹配会话；返回{profile, bytes}独立消息，仅+8..11可能改变，其他字节含填充保持不变。目标profile表示本原语校验的目标布局，不代表body已完成协议转换；不会重写嵌入描述或创建可靠性状态。

`mh-stream-chunk.mjs`提供mhxx-1.4/mhgu-v262144共享的24字节子头编解码与离线恢复入口；GU单块payload限制1416字节。编码保留flags、sequence和未知头，仅按payload重写长度。沿用显式起始序号、同会话归属及保守批量限制；不自动识别通道、不实现在线可靠性，也不接生产。

`mhxx-stream-chunk.mjs`解析MHXX固定profile的24字节子头（输入位于20字节内层头之后），按显式起始序号离线恢复连续数据块，保留未知头字段。乱序排序、相同重复幂等，拒绝缺口、结束边界错误、冲突重复及ack-only块。64块、1MiB和不跨序号回绕是工具保守限制，不是游戏容量结论；调用者负责同一peer/session归属，不实现在线确认/重传，不适用于列表variant2或未核对的GU构建。

`mh-base-peer-endpoint.mjs`提供已证实基类分支的第一endpointA选择，以及显式会话身份表驱动的双向端点转换。调用者必须已确认采用基类工厂；支持两种固定游戏profile，转换要求非零已绑定身份及端口12345，仅返回独立六字节端点和目标profile，不重写完整描述、不接网络。未知身份、过期会话和不支持端口均拒绝。

`mhxx-working-descriptor.mjs`提供限定MHXX派生状态的排序与零字段回填阶段模型；仅mhxx-1.4，输出独立70字节Buffer，不模拟后续端点选择或完整初始化。

`mh-peer-list-assembly.mjs`提供离线两片合并校验，拒绝重复片号、头冲突、重叠与缺口，保留两片原始头；调用者负责同一peer/session归属，不维护在线状态。

`mh-peer-list-fragment.mjs`提供双profile独立分片codec：精确本片长度、两片范围及条目范围检查，保留未知字段；不负责跨片覆盖、会话校验或重组。

`mh-peer-list.mjs`新增显式profile的MHXX/GU离线完整列表接口，仅mhxx-1.4与mhgu-v262144；保留严格长度和未知字段，不承担网络分类、分片或地址转换。

`mhgu-peer-list.mjs`离线编解码已明确交给GU列表解析器的完整body（variant1）：12字节头、72字节项，每项70字节描述、编号与未解释末尾字节。严格长度，拒绝分片variant2；不自动识别消息、不发包、不转换地址。见契约 (`../../docs/MHGU-PEER-LIST-SPEC.md`; full workspace)。

`mh-peer-descriptor.mjs`新增显式mhxx-1.4/mhgu-v262144 profile的共享编解码入口，两侧固定基线的结构已独立核对。仅共享布局，不自动转换字段或推断payload边界，原GU接口保留。

`mhgu-peer-descriptor.mjs`离线编解码固定GU解析器的70字节节点描述：两个35字节子记录，共四个六字节BE端点，未知23字节字段逐项保留。严格长度、独立Buffer；MHXX固定基线共享布局已由后续证据核对，不接生产转换。见契约 (`../../docs/MHGU-PEER-DESCRIPTOR-SPEC.md`; full workspace)。

`mhguLdnIdentityFromFakeIp(bytes, 'yuzu-2022-7edc31be2')`将正常顺序RoomMember fake IP转换为GU wire身份副本。仅支持此静态核对构建，拒绝未知profile；不要传入逆序NodeInfo/IPC字节。此接口离线使用，尚未接生产网关。

`mh-identity.mjs`新增离线`MhIdentityMap`，按会话对MHXX种子CRC32与显式提供的GU四字节wire身份建立双向映射。支持节点退出、整会话重建、零值保留，拒绝未知值/CRC碰撞/重复地址/超出四玩家容量；按原消息身份查表，不按外层转发者改写。输入须来自已确认的字段域，不能猜IP字节序或搜索替换payload；尚未接入网关。接口与限制见映射契约 (`../../docs/MH-IDENTITY-MAPPING-SPEC.md`; full workspace)。下文旧测试数量为历史记录。

Node.js 22+，只读 JSONL，不连接网络，不输出原始载荷。

```powershell
node crossplay/tools/trace-audit.mjs <工作区外的 trace.jsonl>
node --test crossplay/tools/trace-audit.test.mjs
```

退出码：0=检查通过，1=记录不满足检查，2=调用或读取失败。
逐行核对 schema、稳定运行身份、单调时间、run.begin、可用原文的 SHA256/长度，
另独立核对 WifiPacket 长度、SecureData 通道，以及 Yuzu Proxy 完整封套、endpoint 元数据、已验证 Zstd 明文哈希和 LDN 类型长度。报告分事件、阶段、帧类型、数据通道及 peer 汇总，
不解释未知应用字段，不判断游戏兼容。没有 raw_hex 的记录无法复核原始字节，
因此 raw_verified 单独计数，不能把 schema 通过视为原文完整性已验证。

旧版 Beacon trace 重复使用 channel 键记录 Wi-Fi 信道（V-051），本工具会报告身份
不稳定及 invalid channel；不自动改写历史记录。新记录使用 wifi_channel。

Yuzu 双实例只读预检：

```powershell
node crossplay/tools/yuzu-preflight.mjs G:/private/yuzu-a G:/private/yuzu-b
```

检查固定 2022 main exe 哈希、独立便携 user、非共享存储、目录链接、有效配置的遥测关闭与回环地址/24940 端口、不同昵称及私密 prod.keys 文件存在。密钥内容不读取，配置值和昵称不输出。支持 Qt 自动回写的 Windows 双反斜杠、Unicode hex 和 octal 路径转义，解码后检查实际存储路径；不解释 QVariant 或列表路径，不猜测格式。遥测的 `enable_telemetry\default=true` 会恢复默认 true，即使显示值写着 false 也不通过。

输出 passed 只表示这些隔离检查通过，game_verified 始终 false；启用更新、存档可加载、不同玩家身份和狩猎结果仍需真实运行证据。退出码 0/1/2 分别为检查通过/未通过/调用错误。工具测试由 `test.ps1` 统一运行，当前共 29 项 Node 测试。LDN原文的类型、六类body精确长度和广播布尔值独立检查，即使元数据自洽地标为未验证也不能使非法帧通过审计。

`uds-advertisement.mjs` 导出 `udsAdvertisement(record)`，供离线研究导入，检查完整Citra记录后提取Beacon公共NetworkInfo IE元数据（通信/网络ID、人数/容量、广告长度/SHA256），独立验证IE公共SHA-1，不输出广告字节。返回encrypted_nodes_verified=false与game_verified=false；没有解密或验证后续加密节点内容，不能把公共IE检验作为完整Beacon或身份认证结论。实际历史样本结果及限制见协议转换计划V062。

应用协议对照：`node crossplay/tools/app-profile.mjs --citra <trace-A> --yuzu <trace-B>`；也可只提供一侧。独立检查 UDS 的 LLC/SecureData 长度及 Proxy/Zstd 单帧，输出应用长度、路由和分阶段字节变化偏移，不输出载荷。默认最多256组、每组前1024字节的变化统计、20000个不同 payload 指纹；截取宽度明确标注，超过容量失败。CRLY/旧UDS隧道不计作GU样本，无法凭哈希相同判定互通。完整操作与证据边界见 协议转换下一步 (`../../docs/PROTOCOL-CONVERSION-NEXT.md`; full workspace)。

`mhxx-endpoint.mjs`导出`decodeMhxxEndpoint(Buffer)`和`encodeMhxxEndpoint({address, port})`，用于已定位的六字节地址表示：BE32 IPv4 + BE16端口。只接受完整六字节，编码要求规范点分十进制地址、整数端口0..65535，不截断或隐式转换；零地址和零端口是可表示值，路由是否允许由调用方判断。示例hex `c0a801021234`对应`192.168.1.2:4660`。源码依据与适用限制见端点证据 (`../../docs/mhxx-endpoint-codec-evidence.json`; full workspace)。它是离线表示编解码器，尚未接入生产网关；不证明所有游戏消息都含此结构、也不证明传输一定为UDP。V-119工具测试入口现覆盖39项Node测试。

V-120应用分析报告新增`mhxx_messages.header_u32_ranges`：分别统计内层头偏移4/8/12/16的BE32计数、最小/最大、零值和全1计数。全局与各阶段/路由组分别汇总，存储每组固定四项，不缓存任意字段值集合。只有完整分帧成功的mode=1消息进入统计，短尾、mode=2和sentinel后的内容不计；字段仍用偏移命名，不能把数值自动解释成玩家号、地址或校验。统一工具测试现为41项。

路径转义依据 [Qt 5.15 QSettings 源码](https://github.com/qt/qtbase/blob/5.15/src/corelib/io/qsettings.cpp)，并对实际便携实例回写配置复核。
# MHXX本地合成端点推导（V-124）

`mhxx-endpoint.mjs`新增`deriveMhxxUdsEndpoint(seedBytes)`：输入NodeInfo中原始8字节LE64种子内存，输出CRC-32/ISO-HDLC合成地址与端口12345；EAPoL BE64种子须先恢复内存顺序。仅供离线研究，不生成真实MHGU socket路由，也不自动改写应用包。四组独立zlib golden及严格输入检查已纳入统一测试入口，当前工具43项通过。真实旧采集有byte1=253/字段零例外，不能对所有消息使用此推导。

