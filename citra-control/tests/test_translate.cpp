// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - G4 translation layer tests (docs/G4-TRANSLATE-SPEC.md section 7).
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "citra_control/ldn_ctrl.hpp"
#include "citra_control/map.hpp"
#include "citra_control/translate.hpp"
#include "citra_control/uds_frames.hpp"
#include "util.hpp"

using namespace citra_control;
using ttx::hx;

namespace {

MacAddress mac_of(std::uint8_t last) { return MacAddress{0x02, 0x00, 0x00, 0x00, 0x00, last}; }

std::array<std::uint8_t, 4> ipv4_of(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return std::array<std::uint8_t, 4>{a, b, c, d};
}

UserNameBytes name_bytes(const char* text) {
    UserNameBytes out{};
    std::size_t i = 0;
    for (; text[i] != 0 && i < out.size() - 1; ++i) {
        out[i] = static_cast<std::uint8_t>(text[i]);
    }
    out[i] = 0;
    return out;
}

Username uname(const char* text) {
    Username out{};
    for (std::size_t i = 0; text[i] != 0 && i < out.size(); ++i) {
        out[i] = static_cast<std::uint16_t>(static_cast<std::uint8_t>(text[i]));
    }
    return out;
}

std::vector<std::uint8_t> slice(const std::vector<std::uint8_t>& v, std::size_t off, std::size_t len) {
    if (off + len > v.size()) {
        return std::vector<std::uint8_t>();
    }
    return std::vector<std::uint8_t>(v.begin() + static_cast<std::ptrdiff_t>(off),
                                     v.begin() + static_cast<std::ptrdiff_t>(off + len));
}

// Hand-written UDS GuestNetworkInfo (0x108), in wire order: host_mac, channel,
// pad, initialized, zeros3, oui_value, oui_type, wlan_comm_id u32_be, id, pad,
// attributes u16_be, network_id u32_be, total_nodes, max_nodes, zeros2,
// reserved[31], application_data_size, application_data[200].
std::string guest_net_hex() {
    std::string s;
    s += "020000000001";            // host_mac_address
    s += "01";                      // channel
    s += "00";                      // pad
    s += "01";                      // initialized
    s += "000000";                  // zeros
    s += "001f32";                  // oui_value
    s += "15";                      // oui_type (NetworkInfo)
    s += "11223344";                // wlan_comm_id u32_be
    s += "07";                      // id
    s += "00";                      // pad
    s += "0102";                    // attributes u16_be
    s += "aabbccdd";                // network_id u32_be
    s += "01";                      // total_nodes
    s += "01";                      // max_nodes
    s += "0000";                    // zeros
    s += std::string(31 * 2, '0');  // reserved
    s += "00";                      // application_data_size
    s += std::string(200 * 2, '0'); // application_data
    return s;
}

LdnNetworkInfoBody make_ldn_body() {
    LdnNetworkInfoBody body{};
    body.common.bssid = mac_of(1);
    body.common.channel = 1;
    body.common.link_level = 2;
    body.common.network_type = static_cast<std::uint8_t>(PackedNetworkType::Ldn);
    body.ldn.node_count_max = 8;
    body.ldn.node_count = 1;
    body.ldn.advertise_data_size = 0;
    return body;
}

const MacAddress kBeaconSourceMac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

std::vector<std::uint8_t> build_compliant_beacon(Diag* d) {
    BeaconParams p;
    p.network_info.host_mac_address = kBeaconSourceMac;
    p.network_info.channel = 1;
    p.network_info.initialized = 1;
    p.network_info.wlan_comm_id = 0x11223344;
    p.network_info.id = 0x07;
    p.network_info.attributes = 0x0102;
    p.network_info.network_id = 0xAABBCCDD;
    // Real Citra shape: max_nodes (record capacity) = 2 while total_nodes
    // (the connected count) stays 1; build_beacon_frame treats nodes.size() as
    // max_nodes (ni.max_nodes = nodes.size()) and never as total_nodes.
    p.network_info.total_nodes = 1;
    p.appdata_size = 0;
    for (std::size_t k = 0; k < 2; ++k) {
        BeaconNodeInfo bn{};
        bn.friend_code_seed = 0x0102030405060708ull + k;
        bn.username = uname("NODE1");
        bn.network_node_id = static_cast<std::uint16_t>(k + 1);
        p.nodes.push_back(bn);
    }
    p.bitmask = 0x0003;
    p.source_mac = kBeaconSourceMac;
    const Res<std::vector<std::uint8_t>> frame = build_beacon_frame(p, d);
    if (!frame.ok()) {
        return std::vector<std::uint8_t>();
    }
    return frame.value;
}

} // namespace

// ---------------------------------------------------------------------------
// translate_net - Group A network info mapping.
// ---------------------------------------------------------------------------
TT_SUITE(translate_net) {
    TT_CASE();
    {
        Diag d;
        d.events_enabled = false;
        const std::string uh = guest_net_hex();
        const std::vector<std::uint8_t> ub = hx(uh.c_str());
        TT_CHECK(ub.size() == kGuestNetworkInfoSize);
        const Res<GuestNetworkInfo> g = parse_guest_network_info(ub.data(), ub.size(), &d);
        TT_CHECK(g.ok());

        UdsToLdnNetworkInput in;
        in.guest = g.value;
        in.ids.intent_id.local_communication_id = 0x0102030405060708ull;
        in.ids.intent_id.scene_id = 0x1234;
        in.ids.session_id.high = 0x1122334455667788ull;
        in.ids.session_id.low = 0x99AABBCCDDEEFF00ull;
        in.ssid.length = 4;
        in.ssid.raw[0] = 'T';
        in.ssid.raw[1] = 'E';
        in.ssid.raw[2] = 'S';
        in.ssid.raw[3] = 'T';
        in.channel = 1;
        in.link_level = 2;
        LdnNodeInfo n{};
        n.ipv4_address = ipv4_of(10, 83, 0, 5);
        n.mac_address = mac_of(5);
        n.node_id = 1;
        n.is_connected = 1;
        n.user_name = name_bytes("HOST");
        n.local_communication_version = 2;
        in.nodes.push_back(n);

        const Res<LdnNetworkInfoBody> out = uds_network_to_ldn(in, &d);
        TT_CHECK(out.ok());
        TT_CHECK(out.value.network_id.intent_id.local_communication_id == 0x0102030405060708ull);
        TT_CHECK(out.value.network_id.intent_id.scene_id == 0x1234);
        TT_CHECK(out.value.network_id.session_id.high == 0x1122334455667788ull);
        TT_CHECK(out.value.network_id.session_id.low == 0x99AABBCCDDEEFF00ull);
        TT_CHECK(out.value.common.bssid == mac_of(1));
        TT_CHECK(out.value.common.ssid.length == 4 && out.value.common.ssid.raw[0] == 'T');
        TT_CHECK(out.value.common.channel == 1);
        TT_CHECK(out.value.common.link_level == 2);
        TT_CHECK(out.value.common.network_type == static_cast<std::uint8_t>(PackedNetworkType::Ldn));
        TT_CHECK(out.value.ldn.security_mode == SecurityMode::All);
        TT_CHECK(out.value.ldn.station_accept_policy == AcceptPolicy::AcceptAll);
        TT_CHECK(out.value.ldn.has_action_frame == 0);
        TT_CHECK(out.value.ldn.node_count_max == kLdnNodeCountMax);
        TT_CHECK(out.value.ldn.node_count == 1);
        TT_CHECK(out.value.ldn.nodes[0].user_name == name_bytes("HOST"));
        TT_CHECK(out.value.ldn.nodes[0].node_id == 1);
        TT_CHECK(out.value.ldn.advertise_data_size == 0);
        TT_CHECK(out.value.ldn.random_authentication_id == 0);
        TT_CHECK(d.c.invented_fields == 1);

        const Res<std::vector<std::uint8_t>> wire = serialize_ldn_network_info(out.value, &d);
        TT_CHECK(wire.ok());
        TT_CHECK(wire.value.size() == kLdnNetworkInfoSize);
        TT_CHECK(ttx::hex(slice(wire.value, 0x20, 6)) == "020000000001");
        TT_CHECK(wire.value[0x26] == 4);
        TT_CHECK(wire.value[0x27] == 'T');
        TT_CHECK(wire.value[0x48] == 0x01 && wire.value[0x49] == 0x00);
        TT_CHECK(wire.value[0x4A] == 0x02);
        TT_CHECK(wire.value[0x4B] == 0x02);
        TT_CHECK(wire.value[0x66] == kLdnNodeCountMax);
        TT_CHECK(wire.value[0x67] == 1);
        TT_CHECK(ttx::hex(slice(wire.value, 0x68, 4)) == "0a530005");
        TT_CHECK(ttx::hex(slice(wire.value, 0x6C, 6)) == "020000000005");
        TT_CHECK(wire.value[0x72] == 0x01);
        TT_CHECK(wire.value[0x73] == 0x01);
        TT_CHECK(ttx::hex(slice(wire.value, 0x74, 5)) == "484f535400");
        TT_CHECK(wire.value[0x26A] == 0x00 && wire.value[0x26B] == 0x00);
    }

    TT_CASE();
    { // Determinism: the same input serializes to identical bytes.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> ub = hx(guest_net_hex().c_str());
        const Res<GuestNetworkInfo> g = parse_guest_network_info(ub.data(), ub.size(), &d);
        UdsToLdnNetworkInput in;
        in.guest = g.value;
        in.channel = 1;
        in.link_level = 2;
        const Res<LdnNetworkInfoBody> a = uds_network_to_ldn(in, &d);
        const Res<LdnNetworkInfoBody> b = uds_network_to_ldn(in, &d);
        const Res<std::vector<std::uint8_t>> wa = serialize_ldn_network_info(a.value, &d);
        const Res<std::vector<std::uint8_t>> wb = serialize_ldn_network_info(b.value, &d);
        TT_CHECK(a.ok() && b.ok() && wa.ok() && wb.ok());
        TT_CHECK(wa.value == wb.value);
    }

    TT_CASE();
    { // Illegal channel -> BadEnum + channel_rejected.
        Diag d;
        d.events_enabled = false;
        UdsToLdnNetworkInput in;
        in.channel = 2;
        in.link_level = 2;
        const Res<LdnNetworkInfoBody> r = uds_network_to_ldn(in, &d);
        TT_CHECK(!r.ok() && r.err == Err::BadEnum);
        TT_CHECK(d.c.channel_rejected == 1);
    }

    TT_CASE();
    { // Overfull node vector -> Range + oversize_rejected, never truncated.
        Diag d;
        d.events_enabled = false;
        UdsToLdnNetworkInput in;
        in.channel = 1;
        in.link_level = 2;
        in.nodes.resize(9);
        const Res<LdnNetworkInfoBody> r = uds_network_to_ldn(in, &d);
        TT_CHECK(!r.ok() && r.err == Err::Range);
        TT_CHECK(d.c.oversize_rejected == 1);
    }

    TT_CASE();
    { // 0xC8 appdata is always representable UDS -> LDN.
        Diag d;
        d.events_enabled = false;
        UdsToLdnNetworkInput in;
        in.channel = 1;
        in.link_level = 2;
        in.appdata_size = kApplicationDataSize;
        for (std::size_t i = 0; i < in.appdata.size(); ++i) {
            in.appdata[i] = static_cast<std::uint8_t>(i);
        }
        const Res<LdnNetworkInfoBody> r = uds_network_to_ldn(in, &d);
        TT_CHECK(r.ok());
        TT_CHECK(r.value.ldn.advertise_data_size == kApplicationDataSize);
        TT_CHECK(r.value.ldn.advertise_data[0] == 0x00);
        TT_CHECK(r.value.ldn.advertise_data[kApplicationDataSize - 1] == 0xC7);
    }

    TT_CASE();
    { // LDN -> UDS 0xC9 overflow is refused with no partial output.
        Diag d;
        d.events_enabled = false;
        LdnToUdsNetworkInput in;
        in.ldn = make_ldn_body();
        in.ids.wlan_comm_id = 0x11223344;
        in.ids.network_id = 0xAABBCCDD;
        in.id = 7;
        in.total_nodes = 1;
        in.ldn.ldn.advertise_data_size = 0xC9;
        const Res<GuestNetworkInfo> r = ldn_network_to_uds(in, &d);
        TT_CHECK(!r.ok() && r.err == Err::Capacity);
        TT_CHECK(d.c.oversize_rejected == 1);
        TT_CHECK(r.value.application_data_size == 0);
    }

    TT_CASE();
    { // LDN -> UDS node capacity overflow.
        Diag d;
        d.events_enabled = false;
        LdnToUdsNetworkInput in;
        in.ldn = make_ldn_body();
        in.total_nodes = 1;
        in.ldn.ldn.node_count = 9;
        const Res<GuestNetworkInfo> r = ldn_network_to_uds(in, &d);
        TT_CHECK(!r.ok() && r.err == Err::Range);
        TT_CHECK(d.c.oversize_rejected == 1);
    }

    TT_CASE();
    { // Reverse determinism and total_nodes boundaries.
        Diag d;
        d.events_enabled = false;
        LdnToUdsNetworkInput in;
        in.ldn = make_ldn_body();
        in.ids.wlan_comm_id = 0x11223344;
        in.ids.network_id = 0xAABBCCDD;
        in.id = 7;
        in.total_nodes = 1;
        const Res<GuestNetworkInfo> r1 = ldn_network_to_uds(in, &d);
        const Res<GuestNetworkInfo> r2 = ldn_network_to_uds(in, &d);
        TT_CHECK(r1.ok() && r2.ok());
        TT_CHECK(serialize_guest_network_info(r1.value) == serialize_guest_network_info(r2.value));

        in.total_nodes = 8;
        TT_CHECK(ldn_network_to_uds(in, &d).ok());
        in.total_nodes = 0;
        {
            Diag dz;
            dz.events_enabled = false;
            const Res<GuestNetworkInfo> rz = ldn_network_to_uds(in, &dz);
            TT_CHECK(!rz.ok() && rz.err == Err::Range);
            TT_CHECK(dz.c.oversize_rejected == 1);
        }
        in.total_nodes = 9;
        {
            Diag dz;
            dz.events_enabled = false;
            const Res<GuestNetworkInfo> rz = ldn_network_to_uds(in, &dz);
            TT_CHECK(!rz.ok() && rz.err == Err::Range);
            TT_CHECK(dz.c.oversize_rejected == 1);
        }
    }
}

// ---------------------------------------------------------------------------
// translate_nodes - Group B node mapping.
// ---------------------------------------------------------------------------
TT_SUITE(translate_nodes) {
    TT_CASE();
    { // GuestNodeInfo (little-endian) -> LdnNodeInfo.
        Diag d;
        d.events_enabled = false;
        const MacAddress mac = mac_of(5);
        const std::array<std::uint8_t, 4> ip = ipv4_of(10, 83, 0, 5);
        GuestNodeInfo g{};
        g.friend_code_seed = 0x0102030405060708ull;
        g.username = uname("HOST");
        g.network_node_id = 1;
        const std::vector<std::uint8_t> gw = serialize_guest_node_info(g);
        TT_CHECK(gw.size() == kGuestNodeInfoSize);
        TT_CHECK(gw[8] == 0x48 && gw[9] == 0x00); // little-endian 'H'
        const Res<LdnNodeInfo> r = uds_node_to_ldn(g, mac, ip, 1, 2, &d);
        TT_CHECK(r.ok());
        TT_CHECK(r.value.user_name == name_bytes("HOST"));
        TT_CHECK(r.value.node_id == 1);
        TT_CHECK(r.value.mac_address == mac);
        TT_CHECK(r.value.ipv4_address == ip);
        TT_CHECK(r.value.is_connected == static_cast<std::uint8_t>(NodeStatus::Connected));
        TT_CHECK(r.value.local_communication_version == 2);
        TT_CHECK(d.c.invented_fields == 1); // friend_code_to_ldn zeroes and counts
        TT_CHECK(d.c.undefined_fields == 0);
    }

    TT_CASE();
    { // EapolNodeInfo (big-endian) -> LdnNodeInfo; same logical name.
        Diag d;
        d.events_enabled = false;
        EapolNodeInfo e{};
        e.friend_code_seed = 0x0102030405060708ull;
        e.username = uname("HOST");
        e.network_node_id = 1;
        Writer w;
        write_eapol_node_info(w, e);
        TT_CHECK(w.buf.size() == kEapolNodeInfoSize);
        TT_CHECK(w.buf[8] == 0x00 && w.buf[9] == 0x48); // big-endian 'H'
        const Res<LdnNodeInfo> r = eapol_node_to_ldn(e, mac_of(5), ipv4_of(10, 83, 0, 5), 1, 2, &d);
        TT_CHECK(r.ok());
        TT_CHECK(r.value.user_name == name_bytes("HOST"));
        TT_CHECK(r.value.node_id == 1 && r.value.mac_address == mac_of(5));
    }

    TT_CASE();
    { // BeaconNodeInfo (0x1E, big-endian) -> LdnNodeInfo.
        Diag d;
        d.events_enabled = false;
        BeaconNodeInfo b{};
        b.friend_code_seed = 0x0102030405060708ull;
        b.username = uname("HOST");
        b.network_node_id = 1;
        const Res<LdnNodeInfo> r = beacon_node_to_ldn(b, mac_of(5), ipv4_of(10, 83, 0, 5), 1, 2, &d);
        TT_CHECK(r.ok());
        TT_CHECK(r.value.user_name == name_bytes("HOST"));
        TT_CHECK(r.value.node_id == 1);
    }

    TT_CASE();
    { // Reverse, Guest form.
        Diag d;
        d.events_enabled = false;
        LdnNodeInfo n{};
        n.ipv4_address = ipv4_of(10, 83, 0, 5);
        n.mac_address = mac_of(5);
        n.node_id = 1;
        n.is_connected = 1;
        n.user_name = name_bytes("HOST");
        n.local_communication_version = 2;
        const Res<GuestNodeInfo> r = ldn_node_to_uds_guest(n, &d);
        TT_CHECK(r.ok());
        TT_CHECK(r.value.friend_code_seed == 0);
        TT_CHECK(r.value.username == uname("HOST"));
        TT_CHECK(r.value.network_node_id == 1);
        // map.cpp:293-296 counts undefined_fields for friend_code_from_ldn (the
        // spec text and section 7 say invented_fields; the repo helper is the
        // opposite, and map.cpp must not be changed).
        TT_CHECK(d.c.undefined_fields == 1);
    }

    TT_CASE();
    { // Reverse, EAPoL form.
        Diag d;
        d.events_enabled = false;
        LdnNodeInfo n{};
        n.node_id = 1;
        n.user_name = name_bytes("HOST");
        const Res<EapolNodeInfo> r = ldn_node_to_eapol(n, &d);
        TT_CHECK(r.ok());
        TT_CHECK(r.value.friend_code_seed == 0);
        TT_CHECK(r.value.username == uname("HOST"));
        TT_CHECK(d.c.undefined_fields == 1);
    }

    TT_CASE();
    { // Reverse, beacon form.
        Diag d;
        d.events_enabled = false;
        LdnNodeInfo n{};
        n.node_id = 1;
        n.user_name = name_bytes("HOST");
        const Res<BeaconNodeInfo> r = ldn_node_to_beacon(n, &d);
        TT_CHECK(r.ok());
        TT_CHECK(r.value.friend_code_seed == 0);
        TT_CHECK(r.value.username == uname("HOST"));
        TT_CHECK(d.c.undefined_fields == 1);
    }

    TT_CASE();
    { // Node id out of range (UDS source candidate) is refused and counted.
        Diag d;
        d.events_enabled = false;
        const Res<std::int8_t> bad = check_node_id(200, &d);
        TT_CHECK(!bad.ok() && bad.err == Err::Range);
        TT_CHECK(d.c.node_id_out_of_range == 1);
    }

    TT_CASE();
    { // Negative LDN node id cannot be expressed as a UDS node id.
        Diag d;
        d.events_enabled = false;
        LdnNodeInfo n{};
        n.node_id = -1;
        n.user_name = name_bytes("HOST");
        const Res<GuestNodeInfo> r = ldn_node_to_uds_guest(n, &d);
        TT_CHECK(!r.ok() && r.err == Err::Range);
        TT_CHECK(d.c.node_id_out_of_range == 1);
        TT_CHECK(d.c.username_rejected == 0);
    }

    TT_CASE();
    { // Unrepresentable user_name: not NUL terminated, and control bytes.
        Diag d;
        d.events_enabled = false;
        LdnNodeInfo n{};
        n.node_id = 1;
        n.user_name.fill(static_cast<std::uint8_t>('A'));
        const Res<GuestNodeInfo> r = ldn_node_to_uds_guest(n, &d);
        TT_CHECK(!r.ok() && r.err == Err::Encoding);
        TT_CHECK(d.c.username_rejected == 1);

        Diag d2;
        d2.events_enabled = false;
        LdnNodeInfo bad{};
        bad.node_id = 1;
        bad.user_name[0] = 0x01;
        bad.user_name[1] = 0x00;
        const Res<GuestNodeInfo> r2 = ldn_node_to_uds_guest(bad, &d2);
        TT_CHECK(!r2.ok() && r2.err == Err::Encoding);
        TT_CHECK(d2.c.username_rejected == 1);
    }
}

// ---------------------------------------------------------------------------
// translate_guards - Group C gates G1..G7.
// ---------------------------------------------------------------------------
TT_SUITE(translate_guards) {
    TT_CASE();
    { // G1: non-zero AssociationResponse status would abort a real Citra.
        Diag d;
        d.events_enabled = false;
        TT_CHECK(guard_association_response(0, &d) == Err::Ok);
        TT_CHECK(guard_association_response(1, &d) == Err::Unsafe);
        TT_CHECK(guard_association_response(0xFFFF, &d) == Err::Unsafe);
        TT_CHECK(d.c.unsafe_assoc_blocked == 2);
    }

    TT_CASE();
    { // G2: asymmetric advertise capacity.
        Diag d;
        d.events_enabled = false;
        TT_CHECK(guard_advertise_capacity(AdvertiseDirection::LdnToUds, kApplicationDataSize, &d) == Err::Ok);
        TT_CHECK(guard_advertise_capacity(AdvertiseDirection::LdnToUds, kApplicationDataSize + 1, &d) ==
                 Err::Capacity);
        TT_CHECK(d.c.oversize_rejected == 1);
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(guard_advertise_capacity(AdvertiseDirection::UdsToLdn, kApplicationDataSize, &d2) == Err::Ok);
    }

    TT_CASE();
    { // G3: converged node capacity is 8 on both axes.
        Diag d;
        d.events_enabled = false;
        TT_CHECK(guard_node_capacity(8, 8, &d) == Err::Ok);
        TT_CHECK(guard_node_capacity(9, 8, &d) == Err::Range);
        TT_CHECK(guard_node_capacity(1, 9, &d) == Err::Range);
        TT_CHECK(d.c.oversize_rejected == 2);
    }

    TT_CASE();
    { // G5: only the UDS/Yuzu comm id is a legal match key.
        Diag d;
        d.events_enabled = false;
        TT_CHECK(guard_match_key(MatchKey::CommId, &d) == Err::Ok);
        TT_CHECK(guard_match_key(MatchKey::TitleId, &d) == Err::BadEnum);
        TT_CHECK(guard_match_key(MatchKey::SessionId, &d) == Err::BadEnum);
        TT_CHECK(guard_match_key(MatchKey::Ssid, &d) == Err::BadEnum);
        TT_CHECK(guard_match_key(MatchKey::Bssid, &d) == Err::BadEnum);
        TT_CHECK(d.c.err[static_cast<std::size_t>(Err::BadEnum)] == 4);
    }

    TT_CASE();
    { // G4: the CRLY wrapper must never reach the translation layer.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> crly = hx("43524c590000");
        TT_CHECK(guard_no_crly(crly.data(), crly.size(), &d) == Err::BadMagic);
        const std::vector<std::uint8_t> lower = hx("63726c79");
        TT_CHECK(guard_no_crly(lower.data(), lower.size(), &d) == Err::Ok);
        const std::vector<std::uint8_t> three = hx("43524c");
        TT_CHECK(guard_no_crly(three.data(), three.size(), &d) == Err::Ok);
    }

    TT_CASE();
    { // G6: cross-side direction discipline.
        Diag d;
        d.events_enabled = false;
        TT_CHECK(guard_cross_side(CrossSideKind::CitraPrivateNodeMap, Side::Yuzu, &d) == Err::Unsafe);
        TT_CHECK(guard_cross_side(CrossSideKind::LdnControlBody, Side::Citra, &d) == Err::Unsafe);
        TT_CHECK(guard_cross_side(CrossSideKind::DataPayload, Side::Yuzu, &d) == Err::Ok);
        TT_CHECK(guard_cross_side(CrossSideKind::DataPayload, Side::Citra, &d) == Err::Ok);
        TT_CHECK(guard_cross_side(CrossSideKind::CitraPrivateNodeMap, Side::Citra, &d) == Err::Ok);
        TT_CHECK(guard_cross_side(CrossSideKind::LdnControlBody, Side::Yuzu, &d) == Err::Ok);
        TT_CHECK(d.c.cross_side_leak_blocked == 2);
    }

    TT_CASE();
    { // G7: a compliant beacon passes every check.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> frame = build_compliant_beacon(&d);
        TT_CHECK(!frame.empty());
        const Res<BeaconLayoutReport> rep = guard_beacon_layout(frame.data(), frame.size(), kBeaconSourceMac, &d);
        TT_CHECK(rep.ok());
        TT_CHECK(rep.value.tags_ok && rep.value.sha1_ok && rep.value.md5_ok);
        TT_CHECK(rep.value.oui_occurrences == 1);
        TT_CHECK(rep.value.node_count == 2);
        TT_CHECK(rep.value.appdata_size == 0);
        TT_CHECK(rep.value.total_size == frame.size());
    }

    TT_CASE();
    { // G7: wrong NetworkInfo tag length.
        Diag d;
        d.events_enabled = false;
        std::vector<std::uint8_t> frame = build_compliant_beacon(&d);
        frame[32] = 0x38; // 56, not 52 + appdata_size
        const Res<BeaconLayoutReport> rep = guard_beacon_layout(frame.data(), frame.size(), kBeaconSourceMac, &d);
        TT_CHECK(!rep.ok() && (rep.err == Err::BadLength || rep.err == Err::BadTag));
    }

    TT_CASE();
    { // G7: SHA-1 mismatch is counted by the delegated parser.
        Diag d;
        d.events_enabled = false;
        std::vector<std::uint8_t> frame = build_compliant_beacon(&d);
        frame[64] ^= 0xFF; // first byte of the tag's SHA-1 field
        const Res<BeaconLayoutReport> rep = guard_beacon_layout(frame.data(), frame.size(), kBeaconSourceMac, &d);
        TT_CHECK(!rep.ok() && rep.err == Err::BadDigest);
        TT_CHECK(d.c.sha1_verify_fail == 1);
    }

    TT_CASE();
    { // G7: ciphertext tamper -> MD5 mismatch, counted by the delegated parser.
        Diag d;
        d.events_enabled = false;
        std::vector<std::uint8_t> frame = build_compliant_beacon(&d);
        frame[91] ^= 0xFF; // first ciphertext byte
        const Res<BeaconLayoutReport> rep = guard_beacon_layout(frame.data(), frame.size(), kBeaconSourceMac, &d);
        TT_CHECK(!rep.ok() && rep.err == Err::BadDigest);
        TT_CHECK(d.c.md5_verify_fail == 1);
    }

    TT_CASE();
    { // G7: the Nintendo OUI/type magic must appear exactly once in the tag.
        Diag d;
        d.events_enabled = false;
        std::vector<std::uint8_t> frame = build_compliant_beacon(&d);
        frame[53] = 0x00;
        frame[54] = 0x1F;
        frame[55] = 0x32;
        frame[56] = 0x15;
        const Res<BeaconLayoutReport> rep = guard_beacon_layout(frame.data(), frame.size(), kBeaconSourceMac, &d);
        TT_CHECK(!rep.ok());
        TT_CHECK(rep.err == Err::BadTag);
    }

    TT_CASE();
    { // G7: no strict prefix of a compliant beacon may be accepted.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> frame = build_compliant_beacon(&d);
        const MacAddress sm = kBeaconSourceMac;
        ttx::all_prefixes_reject(frame, [&sm](const std::uint8_t* p, std::size_t n) {
            Diag dd;
            dd.events_enabled = false;
            return guard_beacon_layout(p, n, sm, &dd);
        });
    }

    TT_CASE();
    { // R7: max_nodes = 1 (nib[17]) is refused before the length/hash checks.
        Diag d;
        d.events_enabled = true;
        std::vector<std::uint8_t> frame = build_compliant_beacon(&d);
        frame[50] = 1; // NetworkInfo tag body starts at 33; max_nodes is body[17]
        const Res<BeaconLayoutReport> rep = guard_beacon_layout(frame.data(), frame.size(), kBeaconSourceMac, &d);
        TT_CHECK(!rep.ok() && rep.err == Err::BadLength);
        TT_CHECK(d.c.beacon_node_reject == 1);
        bool saw = false;
        for (std::size_t i = 0; i < d.log.lines.size(); ++i) {
            if (d.log.lines[i].find("beacon_max_nodes_too_small") != std::string::npos) saw = true;
        }
        TT_CHECK(saw);
    }

    TT_CASE();
    { // R1: one byte short of 0x28n is refused by the layout guard.
        Diag d;
        d.events_enabled = false;
        std::vector<std::uint8_t> frame = build_compliant_beacon(&d);
        TT_CHECK(frame[86] == 4 + 0x28 * 2);
        frame[86] = static_cast<std::uint8_t>(frame[86] - 1);
        frame.pop_back();
        const Res<BeaconLayoutReport> rep = guard_beacon_layout(frame.data(), frame.size(), kBeaconSourceMac, &d);
        TT_CHECK(!rep.ok() && rep.err == Err::BadLength);
    }

    TT_CASE();
    { // R6: a caller-supplied max_nodes disagreeing with the record count fails closed.
        Diag d;
        d.events_enabled = false;
        BeaconParams p;
        p.network_info.host_mac_address = kBeaconSourceMac;
        p.network_info.wlan_comm_id = 0x11223344;
        p.network_info.id = 0x07;
        p.network_info.network_id = 0xAABBCCDD;
        p.network_info.max_nodes = 3;
        p.source_mac = kBeaconSourceMac;
        for (std::size_t k = 0; k < 2; ++k) {
            BeaconNodeInfo bn{};
            bn.friend_code_seed = 0x0102030405060708ull + k;
            bn.network_node_id = static_cast<std::uint16_t>(k + 1);
            p.nodes.push_back(bn);
        }
        TT_CHECK(build_beacon_frame(p, &d).err == Err::BadLength);
    }
}

// ---------------------------------------------------------------------------
// translate_data - Group D, the 22-byte UDS data prefix.
// ---------------------------------------------------------------------------
TT_SUITE(translate_data) {
    TT_CASE();
    { // Round-trip identity, empty payload.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> payload;
        SecureDataHeader h;
        h.data_channel = 0;
        h.dest_node_id = 2;
        h.src_node_id = 1;
        const Res<std::vector<std::uint8_t>> frame = wrap_ldn_payload_as_uds_data(payload, h, &d);
        TT_CHECK(frame.ok());
        const Res<std::vector<std::uint8_t>> back =
            strip_uds_data_prefix(frame.value.data(), frame.value.size(), &d);
        TT_CHECK(back.ok() && back.value == payload);
    }

    TT_CASE();
    { // Round-trip identity, one byte.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> payload = {0xA5};
        SecureDataHeader h;
        const Res<std::vector<std::uint8_t>> frame = wrap_ldn_payload_as_uds_data(payload, h, &d);
        TT_CHECK(frame.ok());
        const Res<std::vector<std::uint8_t>> back =
            strip_uds_data_prefix(frame.value.data(), frame.value.size(), &d);
        TT_CHECK(back.ok() && back.value == payload);
    }

    TT_CASE();
    { // Round-trip identity, largest LDN advertise body 0x5C6.
        Diag d;
        d.events_enabled = false;
        std::vector<std::uint8_t> payload(0x5C6);
        for (std::size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<std::uint8_t>(i * 7 + 1);
        }
        SecureDataHeader h;
        const Res<std::vector<std::uint8_t>> frame = wrap_ldn_payload_as_uds_data(payload, h, &d);
        TT_CHECK(frame.ok());
        const Res<std::vector<std::uint8_t>> back =
            strip_uds_data_prefix(frame.value.data(), frame.value.size(), &d);
        TT_CHECK(back.ok() && back.value == payload);
    }

    TT_CASE();
    { // The first 22 bytes carry LLC + SecureDataHeader, forced non-management.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> payload = {1, 2, 3};
        SecureDataHeader h;
        h.data_channel = 0x05;
        h.sequence_number = 0x2222; // forced to 0 by the wrapper
        h.dest_node_id = 2;
        h.src_node_id = 1;
        const Res<std::vector<std::uint8_t>> frame = wrap_ldn_payload_as_uds_data(payload, h, &d);
        TT_CHECK(frame.ok());
        TT_CHECK(ttx::hex(slice(frame.value, 0, 8)) == "aaaa03000000876d");
        TT_CHECK(frame.value[14] == 0x00);
        TT_CHECK(frame.value[15] == 0x05);
        TT_CHECK(load_u16be(frame.value.data() + 16) == 0x0000);
        TT_CHECK(load_u16be(frame.value.data() + 18) == 2);
        TT_CHECK(load_u16be(frame.value.data() + 20) == 1);
        const Res<SecureDataFrame> sd = parse_secure_data_frame(frame.value.data(), frame.value.size(), &d);
        TT_CHECK(sd.ok());
        TT_CHECK(sd.value.header.sequence_number == 0);
        TT_CHECK(sd.value.header.dest_node_id == 2 && sd.value.header.src_node_id == 1);
        TT_CHECK(sd.value.payload == payload);
    }

    TT_CASE();
    { // Short frame and non-SecureData EtherType are refused.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> tiny = hx("00112233445566778899");
        const Res<std::vector<std::uint8_t>> shortr = strip_uds_data_prefix(tiny.data(), tiny.size(), &d);
        TT_CHECK(!shortr.ok() && shortr.err == Err::Short);

        Diag d2;
        d2.events_enabled = false;
        const std::vector<std::uint8_t> payload = {9};
        SecureDataHeader h;
        Res<std::vector<std::uint8_t>> frame = wrap_ldn_payload_as_uds_data(payload, h, &d2);
        TT_CHECK(frame.ok());
        frame.value[6] = 0x88;
        frame.value[7] = 0x8E; // EAPoL, not SecureData
        const Res<std::vector<std::uint8_t>> bad = strip_uds_data_prefix(frame.value.data(), frame.value.size(), &d2);
        TT_CHECK(!bad.ok() && bad.err == Err::BadTag);
        TT_CHECK(d2.c.err[static_cast<std::size_t>(Err::BadTag)] == 1);
    }

    TT_CASE();
    { // No strict prefix of a data frame may be accepted.
        Diag d;
        d.events_enabled = false;
        const std::vector<std::uint8_t> payload = {1, 2, 3, 4, 5};
        SecureDataHeader h;
        const Res<std::vector<std::uint8_t>> frame = wrap_ldn_payload_as_uds_data(payload, h, &d);
        TT_CHECK(frame.ok());
        ttx::all_prefixes_reject(frame.value, [](const std::uint8_t* p, std::size_t n) {
            Diag dd;
            dd.events_enabled = false;
            return strip_uds_data_prefix(p, n, &dd);
        });
    }
}
