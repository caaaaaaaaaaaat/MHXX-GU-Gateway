// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - Yuzu LDN body tests (exact-size gate, round trip, all
// prefixes, unknown enums, oversize).
#include <string>

#include "citra_control/ldn_ctrl.hpp"
#include "util.hpp"

using namespace citra_control;
using ttx::hx;

namespace {

LdnNodeInfo sample_node(int index) {
    LdnNodeInfo n;
    n.ipv4_address = {10, 83, 0, static_cast<std::uint8_t>(index + 1)};
    n.mac_address = {0x02, 0x00, 0x00, 0x00, 0x00, static_cast<std::uint8_t>(0x10 + index)};
    n.node_id = static_cast<std::int8_t>(index + 1);
    n.is_connected = 1;
    const char* name = (index == 0) ? "PLAYER1" : "PLAYER2";
    for (std::size_t i = 0; name[i] != 0; ++i) {
        n.user_name[i] = static_cast<std::uint8_t>(name[i]);
    }
    n.local_communication_version = 1;
    return n;
}

LdnNetworkInfoBody sample_network() {
    LdnNetworkInfoBody v;
    v.network_id.intent_id.local_communication_id = 0x1122334455667788ull;
    v.network_id.intent_id.scene_id = 0x2A;
    v.network_id.session_id.high = 0x0102030405060708ull;
    v.network_id.session_id.low = 0x1112131415161718ull;
    v.common.bssid = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    const char* ssid = "M4-ROOM";
    v.common.ssid.length = 7;
    for (std::size_t i = 0; i < 7; ++i) {
        v.common.ssid.raw[i] = static_cast<std::uint8_t>(ssid[i]);
    }
    v.common.channel = 6;
    v.common.link_level = 3;
    v.common.network_type = static_cast<std::uint8_t>(PackedNetworkType::Ldn);
    for (std::size_t i = 0; i < v.ldn.security_parameter.size(); ++i) {
        v.ldn.security_parameter[i] = static_cast<std::uint8_t>(i);
    }
    v.ldn.security_mode = SecurityMode::Retail;
    v.ldn.station_accept_policy = AcceptPolicy::AcceptAll;
    v.ldn.has_action_frame = 0;
    v.ldn.node_count_max = 8;
    v.ldn.node_count = 2;
    v.ldn.nodes[0] = sample_node(0);
    v.ldn.nodes[1] = sample_node(1);
    v.ldn.advertise_data_size = 4;
    v.ldn.advertise_data[0] = 0xDE;
    v.ldn.advertise_data[1] = 0xAD;
    v.ldn.advertise_data[2] = 0xBE;
    v.ldn.advertise_data[3] = 0xEF;
    v.ldn.random_authentication_id = 0xCAFEBABEDEADBEEFull;
    return v;
}

} // namespace

TT_SUITE(ldn_node_info) {
    const LdnNodeInfo node = sample_node(0);
    const std::vector<std::uint8_t> bytes = serialize_ldn_node_info(node).value;

    TT_CASE();
    TT_CHECK(bytes.size() == kLdnNodeInfoSize);
    TT_CHECK(kLdnNodeInfoSize == 0x40);

    TT_CASE();
    {
        Diag d;
        const Res<LdnNodeInfo> back = parse_ldn_node_info(bytes.data(), bytes.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.mac_address == node.mac_address);
        TT_CHECK(back.ok() && back.value.node_id == node.node_id);
        TT_CHECK(back.ok() && back.value.user_name == node.user_name);
        TT_CHECK(back.ok() && back.value.local_communication_version == node.local_communication_version);
        TT_CHECK(back.ok() && serialize_ldn_node_info(back.value).value == bytes);
        TT_CHECK(d.c.frames_parsed == 1);
    }

    TT_CASE();
    ttx::all_prefixes_reject(bytes, [](const std::uint8_t* p, std::size_t n) {
        Diag d;
        d.events_enabled = false;
        return parse_ldn_node_info(p, n, &d);
    });

    TT_CASE();
    ttx::trailing_byte_rejected(bytes, [](const std::uint8_t* p, std::size_t n) {
        Diag d;
        d.events_enabled = false;
        return parse_ldn_node_info(p, n, &d);
    });

    TT_CASE();
    {
        // user_name without a NUL byte inside 33 is refused, never guessed.
        LdnNodeInfo no_nul;
        for (std::size_t i = 0; i < no_nul.user_name.size(); ++i) {
            no_nul.user_name[i] = 'A';
        }
        Diag d;
        d.events_enabled = false;
        TT_CHECK(serialize_ldn_node_info(no_nul, &d).err == Err::Encoding);
    }
}

TT_SUITE(ldn_network_info) {
    const LdnNetworkInfoBody net = sample_network();
    const std::vector<std::uint8_t> bytes = serialize_ldn_network_info(net).value;

    TT_CASE();
    TT_CHECK(bytes.size() == kLdnNetworkInfoSize);
    TT_CHECK(kLdnNetworkInfoSize == 0x480);
    TT_CHECK(bytes.size() == 0x20 + kLdnCommonNetworkInfoSize + kLdnLdnNetworkInfoSize);

    TT_CASE();
    {
        Diag d;
        const Res<LdnNetworkInfoBody> back = parse_ldn_network_info(bytes.data(), bytes.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.network_id.intent_id.local_communication_id ==
                                  net.network_id.intent_id.local_communication_id);
        TT_CHECK(back.ok() && back.value.network_id.session_id.high == net.network_id.session_id.high);
        TT_CHECK(back.ok() && back.value.common.ssid.length == 7);
        TT_CHECK(back.ok() && back.value.common.bssid == net.common.bssid);
        TT_CHECK(back.ok() && back.value.common.channel == 6);
        TT_CHECK(back.ok() && back.value.ldn.node_count == 2);
        TT_CHECK(back.ok() && back.value.ldn.nodes[1].user_name == net.ldn.nodes[1].user_name);
        TT_CHECK(back.ok() && back.value.ldn.advertise_data[0] == 0xDE);
        TT_CHECK(back.ok() && back.value.ldn.random_authentication_id == 0xCAFEBABEDEADBEEFull);
        TT_CHECK(back.ok() && serialize_ldn_network_info(back.value).value == bytes);
    }

    TT_CASE();
    ttx::all_prefixes_reject(bytes, [](const std::uint8_t* p, std::size_t n) {
        Diag d;
        d.events_enabled = false;
        return parse_ldn_network_info(p, n, &d);
    });

    TT_CASE();
    ttx::trailing_byte_rejected(bytes, [](const std::uint8_t* p, std::size_t n) {
        Diag d;
        d.events_enabled = false;
        return parse_ldn_network_info(p, n, &d);
    });

    TT_CASE();
    {
        // Field-level validation: every one of these must be refused.
        Diag d;
        d.events_enabled = false;
        LdnNetworkInfoBody bad = net;
        bad.common.channel = 5;
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::BadEnum);
        TT_CHECK(d.c.channel_rejected == 1);

        bad = net;
        bad.ldn.node_count_max = 9;
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::Range);

        bad = net;
        bad.ldn.node_count = 0;
        bad.ldn.node_count_max = 0;
        bad.ldn.node_count = 1; // node_count > node_count_max
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::Range);

        bad = net;
        bad.ldn.security_mode = static_cast<SecurityMode>(3);
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::BadEnum);

        bad = net;
        bad.ldn.station_accept_policy = static_cast<AcceptPolicy>(4);
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::BadEnum);

        bad = net;
        bad.common.network_type = 4;
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::BadEnum);

        bad = net;
        bad.common.link_level = static_cast<std::int8_t>(4);
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::BadEnum);

        bad = net;
        bad.ldn.advertise_data_size = 0x181;
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::Oversize);

        bad = net;
        bad.common.ssid.length = 33;
        TT_CHECK(serialize_ldn_network_info(bad, &d).err == Err::Range);
    }
}

TT_SUITE(ldn_body_gate) {
    const LdnNodeInfo node = sample_node(0);
    const LdnNetworkInfoBody net = sample_network();
    const LdnPacketType types[6] = {LdnPacketType::Scan,          LdnPacketType::ScanResp,
                                    LdnPacketType::Connect,       LdnPacketType::SyncNetwork,
                                    LdnPacketType::Disconnect,    LdnPacketType::DestroyNetwork};

    TT_CASE();
    {
        TT_CHECK(ldn_body_size(LdnPacketType::Scan) == 0);
        TT_CHECK(ldn_body_size(LdnPacketType::ScanResp) == 0x480);
        TT_CHECK(ldn_body_size(LdnPacketType::Connect) == 0x40);
        TT_CHECK(ldn_body_size(LdnPacketType::SyncNetwork) == 0x480);
        TT_CHECK(ldn_body_size(LdnPacketType::Disconnect) == 0x40);
        TT_CHECK(ldn_body_size(LdnPacketType::DestroyNetwork) == 0);
    }

    for (int i = 0; i < 6; ++i) {
        TT_CASE();
        Diag d;
        d.events_enabled = false;
        const Res<std::vector<std::uint8_t>> body = serialize_ldn_body(types[i], node, net, &d);
        TT_CHECK(body.ok());
        TT_CHECK(body.ok() && body.value.size() == ldn_body_size(types[i]));

        Diag d2;
        d2.events_enabled = false;
        const Res<LdnBody> back = parse_ldn_body(types[i], body.value.data(), body.value.size(), &d2);
        TT_CHECK(back.ok());
        TT_CHECK(d2.c.ldn_body_ok[static_cast<std::size_t>(types[i])] == 1);

        // exact-size gate: one byte short and one byte long must both reject
        Diag d3;
        d3.events_enabled = false;
        if (body.value.size() > 0) {
            TT_CHECK(parse_ldn_body(types[i], body.value.data(), body.value.size() - 1, &d3).err == Err::BadLength);
            const std::uint64_t before = d3.c.ldn_size_reject;
            TT_CHECK(before == 1);
        }
        std::vector<std::uint8_t> longer = body.value;
        longer.push_back(0x00);
        TT_CHECK(parse_ldn_body(types[i], longer.data(), longer.size(), &d3).err == Err::BadLength);
        TT_CHECK(d3.c.ldn_size_reject == (body.value.size() > 0 ? 2u : 1u));
    }

    TT_CASE();
    {
        // wrong body for the type: NodeInfo bytes offered as ScanResp
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> ni = serialize_ldn_node_info(node).value;
        TT_CHECK(parse_ldn_body(LdnPacketType::ScanResp, ni.data(), ni.size(), &d).err == Err::BadLength);
    }

    TT_CASE();
    {
        // Unknown packet type value is refused.
        Diag d;
        d.events_enabled = false;
        const LdnPacketType bogus = static_cast<LdnPacketType>(9);
        TT_CHECK(parse_ldn_body(bogus, nullptr, 0, &d).err == Err::BadEnum);
    }

    TT_CASE();
    {
        TT_CHECK(ldn_channel_ok(0));
        TT_CHECK(ldn_channel_ok(1));
        TT_CHECK(ldn_channel_ok(6));
        TT_CHECK(ldn_channel_ok(11));
        TT_CHECK(ldn_channel_ok(36));
        TT_CHECK(!ldn_channel_ok(2));
        TT_CHECK(!ldn_channel_ok(-1));
        TT_CHECK(!ldn_channel_ok(165));
    }
}
