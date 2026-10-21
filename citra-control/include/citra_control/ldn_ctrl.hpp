// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - Yuzu side LDN bodies (01052024-yuzu-mirror-master
// src/core/hle/service/ldn/ldn_types.h).
//
// The six LDNPacketType values each map to exactly one body length:
//   Scan 0, ScanResp 0x480, Connect 0x40, SyncNetwork 0x480,
//   Disconnect 0x40, DestroyNetwork 0.
// A body whose length differs from the expected one is rejected and counted
// (ldn_size_reject); it is never truncated or padded, because a real Yuzu
// client memcpy's the body into a fixed struct with no length check
// (lan_discovery.cpp:492-493/501-502/525-526/546-547).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "citra_control/bytes.hpp"

namespace citra_control {

inline constexpr std::size_t kLdnNodeInfoSize = 0x40;
inline constexpr std::size_t kLdnSsidSize = 0x22;
inline constexpr std::size_t kLdnCommonNetworkInfoSize = 0x30;
inline constexpr std::size_t kLdnLdnNetworkInfoSize = 0x430;
inline constexpr std::size_t kLdnNetworkInfoSize = 0x480;

inline constexpr std::size_t kLdnSsidLengthMax = 32;
inline constexpr std::size_t kLdnUserNameBytesMax = 32;
inline constexpr std::size_t kLdnNodeCountMax = 8;
inline constexpr std::size_t kLdnStationCountMax = 7;
inline constexpr std::size_t kLdnAdvertiseDataSizeMax = 0x180;
inline constexpr std::size_t kLdnPassphraseLengthMax = 64;

// Offsets inside LdnNetworkInfo / NetworkInfo (compile-time checked below).
inline constexpr std::size_t kLdnLdnOffset = 0x50;
inline constexpr std::size_t kLdnNodesOffset = kLdnLdnOffset + 0x18;
inline constexpr std::size_t kLdnAdvertiseDataSizeOffset = kLdnLdnOffset + 0x21A;
inline constexpr std::size_t kLdnAdvertiseDataOffset = kLdnLdnOffset + 0x21C;
inline constexpr std::size_t kLdnRandomAuthIdOffset = kLdnLdnOffset + 0x428;

enum class LdnPacketType : std::uint8_t {
    Scan = 0,
    ScanResp = 1,
    Connect = 2,
    SyncNetwork = 3,
    Disconnect = 4,
    DestroyNetwork = 5,
};
inline constexpr std::size_t kLdnPacketTypeCount = 6;

// Exact body length per packet type (0 means "no body at all").
constexpr std::size_t ldn_body_size(LdnPacketType t) noexcept {
    switch (t) {
    case LdnPacketType::Scan:
        return 0;
    case LdnPacketType::ScanResp:
        return kLdnNetworkInfoSize;
    case LdnPacketType::Connect:
        return kLdnNodeInfoSize;
    case LdnPacketType::SyncNetwork:
        return kLdnNetworkInfoSize;
    case LdnPacketType::Disconnect:
        return kLdnNodeInfoSize;
    case LdnPacketType::DestroyNetwork:
        return 0;
    }
    return 0;
}

enum class SecurityMode : std::uint16_t { All = 0, Retail = 1, Debug = 2 };
enum class AcceptPolicy : std::uint8_t { AcceptAll = 0, RejectAll = 1, BlackList = 2, WhiteList = 3 };
enum class NetworkType : std::uint32_t { None = 0, General = 1, Ldn = 2, All = 3 };
enum class PackedNetworkType : std::uint8_t { None = 0, General = 1, Ldn = 2, All = 3 };
enum class WifiChannel : std::int16_t {
    Default = 0,
    Wifi24_1 = 1,
    Wifi24_6 = 6,
    Wifi24_11 = 11,
    Wifi50_36 = 36,
    Wifi50_40 = 40,
    Wifi50_44 = 44,
    Wifi50_48 = 48,
};
enum class LinkLevel : std::int8_t { Bad = 0, Low = 1, Good = 2, Excellent = 3 };
enum class NodeStatus : std::uint8_t { Disconnected = 0, Connected = 1 };
enum class LdnState : std::uint32_t {
    None = 0,
    Initialized = 1,
    AccessPointOpened = 2,
    AccessPointCreated = 3,
    StationOpened = 4,
    StationConnected = 5,
    Error = 6,
};
enum class DisconnectReason : std::int16_t {
    Unknown = -1,
    None = 0,
    DisconnectedByUser = 1,
    DisconnectedBySystem = 2,
    DestroyedByUser = 3,
    DestroyedBySystem = 4,
    Rejected = 5,
    SignalLost = 6,
};
enum class NodeStateChange : std::uint8_t {
    None = 0,
    Connect = 1,
    Disconnect = 2,
    DisconnectAndConnect = 3,
};

struct SessionId {
    std::uint64_t high = 0;
    std::uint64_t low = 0;
};

struct IntentId {
    std::uint64_t local_communication_id = 0;
    std::uint16_t scene_id = 0;
};

struct NetworkId {
    IntentId intent_id;
    SessionId session_id;
};

struct Ssid {
    std::uint8_t length = 0;
    std::array<std::uint8_t, kLdnSsidLengthMax + 1> raw{};  // char[33]
};

struct CommonNetworkInfo {
    MacAddress bssid{};
    Ssid ssid;
    std::int16_t channel = 0;
    std::int8_t link_level = 0;
    std::uint8_t network_type = 0;  // PackedNetworkType
};

struct LdnNodeInfo {
    std::array<std::uint8_t, 4> ipv4_address{};
    MacAddress mac_address{};
    std::int8_t node_id = 0;
    std::uint8_t is_connected = 0;  // NodeStatus
    std::array<std::uint8_t, kLdnUserNameBytesMax + 1> user_name{};
    std::int16_t local_communication_version = 0;
};

struct LdnNetworkInfo {
    std::array<std::uint8_t, 0x10> security_parameter{};
    SecurityMode security_mode = SecurityMode::All;
    AcceptPolicy station_accept_policy = AcceptPolicy::AcceptAll;
    std::uint8_t has_action_frame = 0;
    std::uint8_t node_count_max = 0;
    std::uint8_t node_count = 0;
    std::array<LdnNodeInfo, kLdnNodeCountMax> nodes{};
    std::uint16_t advertise_data_size = 0;
    std::array<std::uint8_t, kLdnAdvertiseDataSizeMax> advertise_data{};
    std::array<std::uint8_t, 0x8C> reserved{};
    std::uint64_t random_authentication_id = 0;
};

struct LdnNetworkInfoBody {
    NetworkId network_id;
    CommonNetworkInfo common;
    LdnNetworkInfo ldn;
};

enum class LdnBodyKind { Empty, NodeInfo, NetworkInfo };

struct LdnBody {
    LdnBodyKind kind = LdnBodyKind::Empty;
    LdnNodeInfo node;
    LdnNetworkInfoBody network;
};

// True for the subset of channels the mapping layer accepts (documented
// domain); everything else is rejected and counted as channel_rejected.
bool ldn_channel_ok(std::int16_t channel) noexcept;

Res<std::vector<std::uint8_t>> serialize_ldn_node_info(const LdnNodeInfo& v, Diag* diag = nullptr);
Res<LdnNodeInfo> parse_ldn_node_info(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);
Res<std::vector<std::uint8_t>> serialize_ldn_network_info(const LdnNetworkInfoBody& v, Diag* diag = nullptr);
Res<LdnNetworkInfoBody> parse_ldn_network_info(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);

// Typed body codec: applies the exact-length gate for the given packet type.
Res<std::vector<std::uint8_t>> serialize_ldn_body(LdnPacketType type, const LdnNodeInfo& node,
                                                  const LdnNetworkInfoBody& network, Diag* diag = nullptr);
Res<LdnBody> parse_ldn_body(LdnPacketType type, const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);

} // namespace citra_control
