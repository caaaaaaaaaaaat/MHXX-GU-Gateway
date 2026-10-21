// SPDX-FileCopyrightText: Copyright 2017 Citra Emulator Project
// SPDX-FileCopyrightText: Copyright 2022 yuzu Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 LAN codec contributors
// SPDX-License-Identifier: GPL-3.0-or-later
#include "lan_codecs.h"
#include <algorithm>
#include <bit>
#include <new>

namespace lan_codec {
namespace {
template<class T> Result<T> fail(Error e, std::size_t at = 0) { return {e, at, {}}; }
std::uint16_t be16(Input s, std::size_t p) { return (std::uint16_t(s[p]) << 8) | s[p + 1]; }
std::uint16_t le16(Input s, std::size_t p) { return s[p] | (std::uint16_t(s[p + 1]) << 8); }
std::uint64_t le64(Input s, std::size_t p) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) v |= std::uint64_t(s[p + i]) << (8 * i);
    return v;
}
void put_be16(Bytes& b, std::size_t p, std::uint16_t v) { b[p] = Byte(v >> 8); b[p + 1] = Byte(v); }
void put_le16(Bytes& b, std::size_t p, std::uint16_t v) { b[p] = Byte(v); b[p + 1] = Byte(v >> 8); }
void put_le64(Bytes& b, std::size_t p, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) b[p + i] = Byte(v >> (8 * i));
}
template<std::size_t N> void get_array(Input s, std::size_t p, std::array<Byte, N>& a) {
    std::copy_n(s.begin() + static_cast<std::ptrdiff_t>(p), N, a.begin());
}
template<std::size_t N> void put_array(Bytes& b, std::size_t p, const std::array<Byte, N>& a) {
    std::copy(a.begin(), a.end(), b.begin() + static_cast<std::ptrdiff_t>(p));
}
Result<Bytes> exact_size(Input s, std::size_t expected) {
    if (s.size() < expected) return fail<Bytes>(Error::truncated, s.size());
    if (s.size() > expected) return fail<Bytes>(Error::oversized, expected);
    return {};
}
Result<UdsData> validate_uds(const UdsData& d) {
    if (d.application.size() > uds_application_max) return fail<UdsData>(Error::limit_exceeded, 22);
    if (!d.destination) return fail<UdsData>(Error::invalid_field, 18);
    if (!d.source || d.destination == d.source) return fail<UdsData>(Error::invalid_field, 20);
    return {};
}
Result<NodeInfo> validate_node(const NodeInfo& n) {
    if (n.node_id < 0 || n.node_id > 7) return fail<NodeInfo>(Error::invalid_field, 10);
    if (n.is_connected > 1) return fail<NodeInfo>(Error::invalid_field, 11);
    return {};
}
NodeInfo read_node(Input b) {
    NodeInfo n;
    get_array(b, 0, n.node_ipv4); get_array(b, 4, n.mac);
    n.node_id = std::bit_cast<std::int8_t>(b[10]); n.is_connected = b[11];
    get_array(b, 12, n.user_name); n.reserved_2d = b[45];
    n.communication_version = std::bit_cast<std::int16_t>(le16(b, 46));
    get_array(b, 48, n.reserved_30);
    return n;
}
void write_node(Bytes& b, std::size_t p, const NodeInfo& n) {
    put_array(b, p, n.node_ipv4); put_array(b, p + 4, n.mac);
    b[p + 10] = std::bit_cast<Byte>(n.node_id); b[p + 11] = n.is_connected;
    put_array(b, p + 12, n.user_name); b[p + 45] = n.reserved_2d;
    put_le16(b, p + 46, std::bit_cast<std::uint16_t>(n.communication_version));
    put_array(b, p + 48, n.reserved_30);
}
bool known_channel(std::int16_t c) { return c == 0 || c == 1 || c == 6 || c == 11 || c == 36 || c == 40 || c == 44 || c == 48; }
Result<NetworkInfo> validate_network(const NetworkInfo& n) {
    if (n.ssid_length > 32) return fail<NetworkInfo>(Error::invalid_field, 0x26);
    if (!known_channel(n.channel)) return fail<NetworkInfo>(Error::invalid_enum, 0x48);
    if (n.link_level < 0 || n.link_level > 3) return fail<NetworkInfo>(Error::invalid_enum, 0x4A);
    if (n.network_type > 3) return fail<NetworkInfo>(Error::invalid_enum, 0x4B);
    if (n.security_mode > 2) return fail<NetworkInfo>(Error::invalid_enum, 0x60);
    if (n.accept_policy > 3) return fail<NetworkInfo>(Error::invalid_enum, 0x62);
    if (n.node_count_max < 1 || n.node_count_max > 8) return fail<NetworkInfo>(Error::invalid_field, 0x66);
    if (n.node_count < 1 || n.node_count > n.node_count_max) return fail<NetworkInfo>(Error::invalid_field, 0x67);
    std::size_t connected = 0;
    for (std::size_t i = 0; i < n.nodes.size(); ++i) {
        auto r = validate_node(n.nodes[i]);
        if (!r) return fail<NetworkInfo>(r.error, 0x68 + 0x40 * i + r.offset);
        if (n.nodes[i].node_id != static_cast<std::int8_t>(i)) return fail<NetworkInfo>(Error::invalid_field, 0x68 + 0x40 * i + 10);
        connected += n.nodes[i].is_connected;
    }
    if (n.nodes[0].is_connected != 1 || connected != n.node_count) return fail<NetworkInfo>(Error::invalid_field, 0x67);
    if (n.advertise_size > 384) return fail<NetworkInfo>(Error::invalid_field, 0x26A);
    return {};
}
} // namespace
const char* error_name(Error e) noexcept {
    switch (e) {
#define NAME(x) case Error::x: return #x
    NAME(none); NAME(truncated); NAME(oversized); NAME(size_mismatch); NAME(invalid_header);
    NAME(invalid_enum); NAME(invalid_field); NAME(invalid_zstd); NAME(unknown_content_size);
    NAME(incomplete_frame); NAME(trailing_data); NAME(limit_exceeded); NAME(memory_failure);
#undef NAME
    }
    return "unknown_error";
}
Result<UdsData> decode_uds(Input b) {
    if (b.size() < uds_header_size) return fail<UdsData>(Error::truncated, b.size());
    if (b.size() > uds_header_size + uds_application_max) return fail<UdsData>(Error::limit_exceeded, 22);
    constexpr std::array<Byte, 8> llc = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x87, 0x6D};
    for (std::size_t i = 0; i < llc.size(); ++i) if (b[i] != llc[i]) return fail<UdsData>(Error::invalid_header, i);
    // Citra-generated application subset only. Unknown container bits are not reinterpreted.
    if (b[10] || b[11] || b[14]) return fail<UdsData>(Error::invalid_header, b[10] ? 10 : b[11] ? 11 : 14);
    const std::size_t protocol = be16(b, 8);
    const std::size_t secure = be16(b, 12);
    if (protocol < 14 || secure < 10 || secure != protocol - 4) return fail<UdsData>(Error::size_mismatch, 8);
    if (protocol - 14 > uds_application_max) return fail<UdsData>(Error::limit_exceeded, 8);
    if (b.size() != 8 + protocol) return fail<UdsData>(Error::size_mismatch, 8);
    UdsData d;
    d.channel = b[15]; d.sequence = be16(b, 16); d.destination = be16(b, 18); d.source = be16(b, 20);
    try { d.application.assign(b.begin() + 22, b.end()); }
    catch (const std::bad_alloc&) { return fail<UdsData>(Error::memory_failure); }
    const auto valid = validate_uds(d);
    if (!valid) return valid;
    return {Error::none, 0, std::move(d)};
}
Result<Bytes> encode_uds(const UdsData& d) {
    auto valid = validate_uds(d); if (!valid) return fail<Bytes>(valid.error, valid.offset);
    try {
        Bytes b(uds_header_size + d.application.size(), 0);
        const std::array<Byte, 8> llc = {0xAA, 0xAA, 3, 0, 0, 0, 0x87, 0x6D};
        put_array(b, 0, llc); put_be16(b, 8, static_cast<std::uint16_t>(14 + d.application.size()));
        put_be16(b, 12, static_cast<std::uint16_t>(10 + d.application.size())); b[15] = d.channel;
        put_be16(b, 16, d.sequence); put_be16(b, 18, d.destination); put_be16(b, 20, d.source);
        std::copy(d.application.begin(), d.application.end(), b.begin() + 22);
        return {Error::none, 0, std::move(b)};
    } catch (const std::bad_alloc&) { return fail<Bytes>(Error::memory_failure); }
}
Ipv4Bytes node_ipv4_from_room_bytes(Ipv4Bytes b) noexcept { std::reverse(b.begin(), b.end()); return b; }
Result<NodeInfo> decode_node(Input b) {
    auto size = exact_size(b, node_info_size); if (!size) return fail<NodeInfo>(size.error, size.offset);
    auto n = read_node(b); auto valid = validate_node(n); if (!valid) return valid;
    return {Error::none, 0, n};
}
Result<Bytes> encode_node(const NodeInfo& n) {
    auto valid = validate_node(n); if (!valid) return fail<Bytes>(valid.error, valid.offset);
    try { Bytes b(node_info_size); write_node(b, 0, n); return {Error::none, 0, std::move(b)}; }
    catch (const std::bad_alloc&) { return fail<Bytes>(Error::memory_failure); }
}
Result<NetworkInfo> decode_network(Input b) {
    auto size = exact_size(b, network_info_size); if (!size) return fail<NetworkInfo>(size.error, size.offset);
    NetworkInfo n;
    n.local_communication_id = le64(b, 0); get_array(b, 8, n.reserved_08); n.scene_id = le16(b, 10);
    get_array(b, 12, n.reserved_0c); n.session_high = le64(b, 16); n.session_low = le64(b, 24);
    get_array(b, 32, n.bssid); n.ssid_length = b[38]; get_array(b, 39, n.ssid);
    n.channel = std::bit_cast<std::int16_t>(le16(b, 0x48)); n.link_level = std::bit_cast<std::int8_t>(b[0x4A]);
    n.network_type = b[0x4B]; get_array(b, 0x4C, n.reserved_4c); get_array(b, 0x50, n.security_parameter);
    n.security_mode = le16(b, 0x60); n.accept_policy = b[0x62]; n.has_action_frame = b[0x63];
    get_array(b, 0x64, n.reserved_64); n.node_count_max = b[0x66]; n.node_count = b[0x67];
    for (std::size_t i = 0; i < n.nodes.size(); ++i) n.nodes[i] = read_node(b.subspan(0x68 + 0x40 * i, 0x40));
    get_array(b, 0x268, n.reserved_268); n.advertise_size = le16(b, 0x26A); get_array(b, 0x26C, n.advertise);
    get_array(b, 0x3EC, n.reserved_3ec); n.authentication_id = le64(b, 0x478);
    auto valid = validate_network(n); if (!valid) return valid;
    return {Error::none, 0, n};
}
Result<Bytes> encode_network(const NetworkInfo& n) {
    auto valid = validate_network(n); if (!valid) return fail<Bytes>(valid.error, valid.offset);
    try {
        Bytes b(network_info_size);
        put_le64(b, 0, n.local_communication_id); put_array(b, 8, n.reserved_08); put_le16(b, 10, n.scene_id);
        put_array(b, 12, n.reserved_0c); put_le64(b, 16, n.session_high); put_le64(b, 24, n.session_low);
        put_array(b, 32, n.bssid); b[38] = n.ssid_length; put_array(b, 39, n.ssid);
        put_le16(b, 0x48, std::bit_cast<std::uint16_t>(n.channel)); b[0x4A] = std::bit_cast<Byte>(n.link_level);
        b[0x4B] = n.network_type; put_array(b, 0x4C, n.reserved_4c); put_array(b, 0x50, n.security_parameter);
        put_le16(b, 0x60, n.security_mode); b[0x62] = n.accept_policy; b[0x63] = n.has_action_frame;
        put_array(b, 0x64, n.reserved_64); b[0x66] = n.node_count_max; b[0x67] = n.node_count;
        for (std::size_t i = 0; i < n.nodes.size(); ++i) write_node(b, 0x68 + 0x40 * i, n.nodes[i]);
        put_array(b, 0x268, n.reserved_268); put_le16(b, 0x26A, n.advertise_size); put_array(b, 0x26C, n.advertise);
        put_array(b, 0x3EC, n.reserved_3ec); put_le64(b, 0x478, n.authentication_id);
        return {Error::none, 0, std::move(b)};
    } catch (const std::bad_alloc&) { return fail<Bytes>(Error::memory_failure); }
}
Result<LdnBody> decode_ldn(Byte raw, Input b) {
    if (raw > 5) return fail<LdnBody>(Error::invalid_enum);
    LdnBody body; body.type = static_cast<LdnType>(raw);
    if (body.type == LdnType::scan || body.type == LdnType::destroy_network) {
        auto s = exact_size(b, 0); if (!s) return fail<LdnBody>(s.error, s.offset);
    } else if (body.type == LdnType::connect || body.type == LdnType::disconnect) {
        auto n = decode_node(b); if (!n) return fail<LdnBody>(n.error, n.offset); body.node = n.value;
    } else {
        auto n = decode_network(b); if (!n) return fail<LdnBody>(n.error, n.offset); body.network = n.value;
    }
    return {Error::none, 0, body};
}
Result<Bytes> encode_ldn(const LdnBody& b) {
    switch (b.type) {
    case LdnType::scan: case LdnType::destroy_network: return {};
    case LdnType::connect: case LdnType::disconnect: return encode_node(b.node);
    case LdnType::scan_response: case LdnType::sync_network: return encode_network(b.network);
    }
    return fail<Bytes>(Error::invalid_enum);
}
} // namespace lan_codec
