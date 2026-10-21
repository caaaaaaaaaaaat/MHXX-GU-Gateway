// SPDX-FileCopyrightText: Copyright 2017 Citra Emulator Project
// SPDX-FileCopyrightText: Copyright 2022 yuzu Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 LAN codec contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Explicit serialization derived from field definitions, not native structure layouts.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lan_codec {
using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using Input = std::span<const Byte>;
enum class Error {
    none, truncated, oversized, size_mismatch, invalid_header, invalid_enum,
    invalid_field, invalid_zstd, unknown_content_size, incomplete_frame,
    trailing_data, limit_exceeded, memory_failure
};
const char* error_name(Error error) noexcept;
template<class T> struct Result {
    Error error = Error::none;
    std::size_t offset = 0;
    T value{};
    explicit operator bool() const noexcept { return error == Error::none; }
};
inline constexpr std::size_t uds_header_size = 22;
inline constexpr std::size_t uds_application_max = 0x5C6;
struct UdsData {
    Byte channel = 0;
    std::uint16_t destination = 0;
    std::uint16_t source = 0;
    std::uint16_t sequence = 0;
    Bytes application; // Opaque: no MH field, checksum, crypto or content-ID interpretation.
    bool operator==(const UdsData&) const = default;
};
Result<UdsData> decode_uds(Input wire);
Result<Bytes> encode_uds(const UdsData& data);

inline constexpr std::size_t node_info_size = 0x40;
inline constexpr std::size_t network_info_size = 0x480;
using Ipv4Bytes = std::array<Byte, 4>;
// Pure byte-order helper only: no allocation, address assignment or identity mapping.
Ipv4Bytes node_ipv4_from_room_bytes(Ipv4Bytes raw_room_bytes) noexcept;
struct NodeInfo {
    Ipv4Bytes node_ipv4{}; // Reversed relative to room IPv4 bytes in this Yuzu snapshot.
    std::array<Byte, 6> mac{};
    std::int8_t node_id = 0;
    Byte is_connected = 0;
    std::array<Byte, 33> user_name{}; // Never treated as an unbounded C string.
    Byte reserved_2d = 0;
    std::int16_t communication_version = 0;
    std::array<Byte, 16> reserved_30{};
    bool operator==(const NodeInfo&) const = default;
};
struct NetworkInfo {
    std::uint64_t local_communication_id = 0; // Caller data, never inferred from a game.
    std::array<Byte, 2> reserved_08{};
    std::uint16_t scene_id = 0;
    std::array<Byte, 4> reserved_0c{};
    std::uint64_t session_high = 0;
    std::uint64_t session_low = 0;
    std::array<Byte, 6> bssid{};
    Byte ssid_length = 0;
    std::array<Byte, 33> ssid{};
    std::int16_t channel = 0;
    std::int8_t link_level = 0;
    Byte network_type = 0;
    std::array<Byte, 4> reserved_4c{};
    std::array<Byte, 16> security_parameter{};
    std::uint16_t security_mode = 0;
    Byte accept_policy = 0;
    Byte has_action_frame = 0; // Opaque u8: field name is not evidence of a Boolean domain.
    std::array<Byte, 2> reserved_64{};
    Byte node_count_max = 0;
    Byte node_count = 0;
    std::array<NodeInfo, 8> nodes{};
    std::array<Byte, 2> reserved_268{};
    std::uint16_t advertise_size = 0;
    std::array<Byte, 384> advertise{};
    std::array<Byte, 140> reserved_3ec{};
    std::uint64_t authentication_id = 0;
    bool operator==(const NetworkInfo&) const = default;
};
// Pinned raw-body profile: little-endian Yuzu ABI, not an endian-independent LDN standard.
Result<NodeInfo> decode_node(Input wire);
Result<Bytes> encode_node(const NodeInfo& node);
// Strict created-network subset: host active; IDs match slots; counts match active slots.
Result<NetworkInfo> decode_network(Input wire);
Result<Bytes> encode_network(const NetworkInfo& network);
enum class LdnType : Byte { scan, scan_response, connect, sync_network, disconnect, destroy_network };
struct LdnBody { LdnType type = LdnType::scan; NodeInfo node{}; NetworkInfo network{}; };
Result<LdnBody> decode_ldn(Byte raw_type, Input body);
Result<Bytes> encode_ldn(const LdnBody& body);

// Resource policy, NOT a discovered Proxy/MH protocol limit. No network functions exist here.
inline constexpr std::size_t hard_resource_cap = 1024 * 1024;
struct ZstdLimits { std::size_t compressed = 64 * 1024; std::size_t decompressed = 64 * 1024; };
Result<Bytes> decode_zstd_single(Input frame, ZstdLimits limits = {});
Result<Bytes> encode_zstd_default(Input application, ZstdLimits limits = {});
} // namespace lan_codec
