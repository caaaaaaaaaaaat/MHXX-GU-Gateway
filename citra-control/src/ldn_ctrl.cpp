// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - Yuzu LDN body codec.
#include "citra_control/ldn_ctrl.hpp"

namespace citra_control {

static_assert(kLdnSsidSize == 1 + kLdnSsidLengthMax + 1, "Ssid layout");
static_assert(kLdnCommonNetworkInfoSize == 6 + kLdnSsidSize + 2 + 1 + 1 + 4, "CommonNetworkInfo layout");
static_assert(kLdnNodeInfoSize == 4 + 6 + 1 + 1 + kLdnUserNameBytesMax + 1 + 1 + 2 + 0x10, "NodeInfo layout");
static_assert(kLdnLdnNetworkInfoSize == 0x10 + 2 + 1 + 1 + 2 + 1 + 1 + kLdnNodeCountMax * kLdnNodeInfoSize + 2 + 2 +
                                                    kLdnAdvertiseDataSizeMax + 0x8C + 8,
              "LdnNetworkInfo layout");
static_assert(kLdnNetworkInfoSize == 0x20 + kLdnCommonNetworkInfoSize + kLdnLdnNetworkInfoSize, "NetworkInfo layout");
static_assert(kLdnAdvertiseDataSizeOffset == 0x26A, "advertise_data_size offset");
static_assert(kLdnAdvertiseDataOffset == 0x26C, "advertise_data offset");
static_assert(kLdnNodesOffset == 0x68, "nodes offset");
static_assert(kLdnRandomAuthIdOffset == 0x478, "random_authentication_id offset");

namespace {

bool valid_security_mode(std::uint16_t v) {
    return v <= 2;
}

bool valid_accept_policy(std::uint8_t v) {
    return v <= 3;
}

bool valid_network_type(std::uint8_t v) {
    return v <= 3;
}

bool valid_link_level(std::int8_t v) {
    return v >= 0 && v <= 3;
}

bool nul_terminated(const std::array<std::uint8_t, kLdnUserNameBytesMax + 1>& name) {
    for (std::size_t i = 0; i < name.size(); ++i) {
        if (name[i] == 0) {
            return true;
        }
    }
    return false;
}

Err validate_node_info(const LdnNodeInfo& v) {
    if (v.is_connected > static_cast<std::uint8_t>(NodeStatus::Connected)) {
        return Err::BadEnum;
    }
    if (!nul_terminated(v.user_name)) {
        return Err::Encoding;
    }
    return Err::Ok;
}

Err validate_network_info(const LdnNetworkInfoBody& v, Diag* diag) {
    if (v.common.ssid.length > kLdnSsidLengthMax) {
        return Err::Range;
    }
    if (!valid_network_type(v.common.network_type)) {
        return Err::BadEnum;
    }
    if (!valid_link_level(v.common.link_level)) {
        return Err::BadEnum;
    }
    if (!ldn_channel_ok(v.common.channel)) {
        if (diag != nullptr) {
            ++diag->c.channel_rejected;
        }
        return Err::BadEnum;
    }
    if (!valid_security_mode(static_cast<std::uint16_t>(v.ldn.security_mode))) {
        return Err::BadEnum;
    }
    if (!valid_accept_policy(static_cast<std::uint8_t>(v.ldn.station_accept_policy))) {
        return Err::BadEnum;
    }
    if (v.ldn.node_count_max > kLdnNodeCountMax || v.ldn.node_count > kLdnNodeCountMax) {
        return Err::Range;
    }
    if (v.ldn.node_count > v.ldn.node_count_max) {
        return Err::Range;
    }
    if (v.ldn.advertise_data_size > kLdnAdvertiseDataSizeMax) {
        return Err::Oversize;
    }
    for (std::size_t i = 0; i < kLdnNodeCountMax; ++i) {
        const Err e = validate_node_info(v.ldn.nodes[i]);
        if (e != Err::Ok) {
            return e;
        }
    }
    return Err::Ok;
}

void write_node_info(Writer& w, const LdnNodeInfo& v) {
    w.bytes(v.ipv4_address);
    w.bytes(v.mac_address);
    w.s8(v.node_id);
    w.u8(v.is_connected);
    w.bytes(v.user_name);
    w.u8(0);
    w.u16le(static_cast<std::uint16_t>(v.local_communication_version));
    w.zeros(0x10);
}

Res<LdnNodeInfo> read_node_info(Reader& r) {
    LdnNodeInfo v;
    r.copy_to(v.ipv4_address.data(), 4);
    r.copy_to(v.mac_address.data(), 6);
    v.node_id = r.s8();
    v.is_connected = r.u8();
    r.copy_to(v.user_name.data(), v.user_name.size());
    r.skip(1);
    v.local_communication_version = r.s16le();
    r.skip(0x10);
    if (!r.ok()) {
        return fail<LdnNodeInfo>(r.err());
    }
    return ok(v);
}

void write_network_id(Writer& w, const NetworkId& v) {
    w.u64le(v.intent_id.local_communication_id);
    w.zeros(2);
    w.u16le(v.intent_id.scene_id);
    w.zeros(4);
    w.u64le(v.session_id.high);
    w.u64le(v.session_id.low);
}

void read_network_id(Reader& r, NetworkId& v) {
    v.intent_id.local_communication_id = r.u64le();
    r.skip(2);
    v.intent_id.scene_id = r.u16le();
    r.skip(4);
    v.session_id.high = r.u64le();
    v.session_id.low = r.u64le();
}

void write_common(Writer& w, const CommonNetworkInfo& v) {
    w.bytes(v.bssid);
    w.u8(v.ssid.length);
    w.bytes(v.ssid.raw);
    w.u16le(static_cast<std::uint16_t>(v.channel));
    w.s8(v.link_level);
    w.u8(v.network_type);
    w.zeros(4);
}

void read_common(Reader& r, CommonNetworkInfo& v) {
    r.copy_to(v.bssid.data(), 6);
    v.ssid.length = r.u8();
    r.copy_to(v.ssid.raw.data(), v.ssid.raw.size());
    v.channel = r.s16le();
    v.link_level = r.s8();
    v.network_type = r.u8();
    r.skip(4);
}

void write_ldn(Writer& w, const LdnNetworkInfo& v) {
    w.bytes(v.security_parameter);
    w.u16le(static_cast<std::uint16_t>(v.security_mode));
    w.u8(static_cast<std::uint8_t>(v.station_accept_policy));
    w.u8(v.has_action_frame);
    w.zeros(2);
    w.u8(v.node_count_max);
    w.u8(v.node_count);
    for (std::size_t i = 0; i < kLdnNodeCountMax; ++i) {
        write_node_info(w, v.nodes[i]);
    }
    w.zeros(2);
    w.u16le(v.advertise_data_size);
    w.bytes(v.advertise_data);
    w.bytes(v.reserved);
    w.u64le(v.random_authentication_id);
}

void read_ldn(Reader& r, LdnNetworkInfo& v) {
    r.copy_to(v.security_parameter.data(), v.security_parameter.size());
    v.security_mode = static_cast<SecurityMode>(r.u16le());
    v.station_accept_policy = static_cast<AcceptPolicy>(r.u8());
    v.has_action_frame = r.u8();
    r.skip(2);
    v.node_count_max = r.u8();
    v.node_count = r.u8();
    for (std::size_t i = 0; i < kLdnNodeCountMax; ++i) {
        const Res<LdnNodeInfo> n = read_node_info(r);
        if (!n.ok()) {
            return;
        }
        v.nodes[i] = n.value;
    }
    r.skip(2);
    v.advertise_data_size = r.u16le();
    r.copy_to(v.advertise_data.data(), v.advertise_data.size());
    r.copy_to(v.reserved.data(), v.reserved.size());
    v.random_authentication_id = r.u64le();
}

} // namespace

bool ldn_channel_ok(std::int16_t channel) noexcept {
    switch (channel) {
    case 0:
    case 1:
    case 6:
    case 11:
    case 36:
    case 40:
    case 44:
    case 48:
        return true;
    default:
        return false;
    }
}

Res<std::vector<std::uint8_t>> serialize_ldn_node_info(const LdnNodeInfo& v, Diag* diag) {
    const Err ve = validate_node_info(v);
    if (ve != Err::Ok) {
        if (diag != nullptr) {
            diag->note_reject("ldn_node_info", ve);
        }
        return fail<std::vector<std::uint8_t>>(ve);
    }
    Writer w;
    write_node_info(w, v);
    if (w.size() != kLdnNodeInfoSize) {
        if (diag != nullptr) {
            diag->note_reject("ldn_node_info", Err::BadLength);
        }
        return fail<std::vector<std::uint8_t>>(Err::BadLength);
    }
    if (diag != nullptr) {
        ++diag->c.frames_serialized;
    }
    return ok(std::move(w.buf));
}

Res<LdnNodeInfo> parse_ldn_node_info(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("ldn_node_info", e);
        }
        return fail<LdnNodeInfo>(e);
    };
    if (size < kLdnNodeInfoSize) {
        return rej(Err::Short);
    }
    if (size > kLdnNodeInfoSize) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    const Res<LdnNodeInfo> v = read_node_info(r);
    if (!v.ok()) {
        return rej(v.err);
    }
    if (!r.at_end()) {
        return rej(Err::Trailing);
    }
    const Err ve = validate_node_info(v.value);
    if (ve != Err::Ok) {
        return rej(ve);
    }
    if (diag != nullptr) {
        ++diag->c.frames_parsed;
        diag->note_ok("ldn_node_info", "parse");
    }
    return ok(v.value);
}

Res<std::vector<std::uint8_t>> serialize_ldn_network_info(const LdnNetworkInfoBody& v, Diag* diag) {
    const Err ve = validate_network_info(v, diag);
    if (ve != Err::Ok) {
        if (diag != nullptr) {
            diag->note_reject("ldn_network_info", ve);
        }
        return fail<std::vector<std::uint8_t>>(ve);
    }
    Writer w;
    write_network_id(w, v.network_id);
    write_common(w, v.common);
    write_ldn(w, v.ldn);
    if (w.size() != kLdnNetworkInfoSize) {
        if (diag != nullptr) {
            diag->note_reject("ldn_network_info", Err::BadLength);
        }
        return fail<std::vector<std::uint8_t>>(Err::BadLength);
    }
    if (diag != nullptr) {
        ++diag->c.frames_serialized;
    }
    return ok(std::move(w.buf));
}

Res<LdnNetworkInfoBody> parse_ldn_network_info(const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("ldn_network_info", e);
        }
        return fail<LdnNetworkInfoBody>(e);
    };
    if (size < kLdnNetworkInfoSize) {
        return rej(Err::Short);
    }
    if (size > kLdnNetworkInfoSize) {
        return rej(Err::Trailing);
    }
    Reader r(data, size);
    LdnNetworkInfoBody v;
    read_network_id(r, v.network_id);
    read_common(r, v.common);
    read_ldn(r, v.ldn);
    if (!r.ok()) {
        return rej(r.err());
    }
    if (!r.at_end()) {
        return rej(Err::Trailing);
    }
    const Err ve = validate_network_info(v, diag);
    if (ve != Err::Ok) {
        return rej(ve);
    }
    if (diag != nullptr) {
        ++diag->c.frames_parsed;
        diag->note_ok("ldn_network_info", "parse");
    }
    return ok(v);
}

Res<std::vector<std::uint8_t>> serialize_ldn_body(LdnPacketType type, const LdnNodeInfo& node,
                                                  const LdnNetworkInfoBody& network, Diag* diag) {
    Res<std::vector<std::uint8_t>> out = fail<std::vector<std::uint8_t>>(Err::NotImplemented);
    switch (type) {
    case LdnPacketType::Scan:
    case LdnPacketType::DestroyNetwork:
        out = ok(std::vector<std::uint8_t>{});
        break;
    case LdnPacketType::Connect:
    case LdnPacketType::Disconnect:
        out = serialize_ldn_node_info(node, diag);
        break;
    case LdnPacketType::ScanResp:
    case LdnPacketType::SyncNetwork:
        out = serialize_ldn_network_info(network, diag);
        break;
    }
    if (!out.ok()) {
        if (diag != nullptr) {
            ++diag->c.ldn_size_reject;
            diag->note_reject("ldn_body", out.err);
        }
        return out;
    }
    const std::size_t expected = ldn_body_size(type);
    if (out.value.size() != expected) {
        if (diag != nullptr) {
            ++diag->c.ldn_size_reject;
            diag->note_reject("ldn_body", Err::BadLength);
        }
        return fail<std::vector<std::uint8_t>>(Err::BadLength);
    }
    if (diag != nullptr) {
        diag->note_ok("ldn_body", "serialize");
    }
    return out;
}

Res<LdnBody> parse_ldn_body(LdnPacketType type, const std::uint8_t* data, std::size_t size, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            ++diag->c.ldn_size_reject;
            diag->note_reject("ldn_body", e);
        }
        return fail<LdnBody>(e);
    };
    const std::size_t expected = ldn_body_size(type);
    const std::size_t idx = static_cast<std::size_t>(type);
    if (idx >= kLdnPacketTypeCount) {
        return rej(Err::BadEnum);
    }
    // Memory-safety gate: the body length must match the type exactly.  A real
    // Yuzu client memcpy's sizeof(NodeInfo/NetworkInfo) with no length check.
    if (size != expected) {
        return rej(Err::BadLength);
    }
    LdnBody body;
    switch (type) {
    case LdnPacketType::Scan:
    case LdnPacketType::DestroyNetwork:
        body.kind = LdnBodyKind::Empty;
        break;
    case LdnPacketType::Connect:
    case LdnPacketType::Disconnect: {
        const Res<LdnNodeInfo> n = parse_ldn_node_info(data, size, diag);
        if (!n.ok()) {
            return rej(n.err);
        }
        body.kind = LdnBodyKind::NodeInfo;
        body.node = n.value;
        break;
    }
    case LdnPacketType::ScanResp:
    case LdnPacketType::SyncNetwork: {
        const Res<LdnNetworkInfoBody> n = parse_ldn_network_info(data, size, diag);
        if (!n.ok()) {
            return rej(n.err);
        }
        body.kind = LdnBodyKind::NetworkInfo;
        body.network = n.value;
        break;
    }
    }
    if (diag != nullptr) {
        ++diag->c.ldn_body_ok[idx];
        diag->note_ok("ldn_body", "parse");
    }
    return ok(body);
}

} // namespace citra_control
