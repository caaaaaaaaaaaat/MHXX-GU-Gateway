// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - mapping layer tests (docs/M4-CONTROL-PLANE.md section 3).
#include <string>

#include "citra_control/map.hpp"
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

} // namespace

TT_SUITE(map_session) {
    TT_CASE();
    {
        SessionMap m;
        m.bind(mac_of(1));
        m.bind(mac_of(2));
        const auto survivor = m.bind(mac_of(3));
        TT_CHECK(m.remove(mac_of(2)));
        const auto replacement = m.bind(mac_of(4));
        TT_CHECK(replacement.ok() && replacement.value.node_id == 2);
        TT_CHECK(replacement.ok() && replacement.value.ipv4 == ipv4_of(10, 83, 0, 2));
        TT_CHECK(m.lookup_node_id(2).value.mac == mac_of(4));
        TT_CHECK(m.lookup_ipv4({10, 83, 0, 2}).value == mac_of(4));
        const auto stable = m.bind(mac_of(3));
        TT_CHECK(stable.ok() && stable.value.node_id == survivor.value.node_id &&
                 stable.value.ipv4 == survivor.value.ipv4);
        TT_CHECK(m.size() == 3);
        m.clear();
        TT_CHECK(m.bind(mac_of(4)).value.node_id == 1);
    }

    TT_CASE();
    {
        SessionMap m;
        Diag d;
        d.events_enabled = false;
        const Res<NodeBinding> a = m.bind(mac_of(1), &d);
        const Res<NodeBinding> b = m.bind(mac_of(2), &d);
        const Res<NodeBinding> c = m.bind(mac_of(3), &d);
        TT_CHECK(a.ok() && b.ok() && c.ok());
        TT_CHECK(a.ok() && a.value.ipv4 == ipv4_of(10, 83, 0, 1));
        TT_CHECK(b.ok() && b.value.ipv4 == ipv4_of(10, 83, 0, 2));
        TT_CHECK(a.ok() && a.value.node_id == 1);
        TT_CHECK(b.ok() && b.value.node_id == 2);
        TT_CHECK(c.ok() && c.value.node_id == 3);
        TT_CHECK(m.size() == 3);
        TT_CHECK(d.c.mac_map_inserts == 3);
        TT_CHECK(d.c.node_id_assigned == 3);

        // Idempotent: the same MAC keeps its IPv4 and node id (V-016n rule 3).
        const Res<NodeBinding> again = m.bind(mac_of(1), &d);
        TT_CHECK(again.ok() && again.value.ipv4 == a.value.ipv4 && again.value.node_id == a.value.node_id);
        TT_CHECK(m.size() == 3);

        TT_CHECK(m.lookup_mac(mac_of(2), &d).ok());
        TT_CHECK(m.lookup_ipv4({10, 83, 0, 2}, &d).ok());
        const Res<NodeBinding> byid = m.lookup_node_id(3, &d);
        TT_CHECK(byid.ok() && byid.value.mac == mac_of(3));
        TT_CHECK(m.lookup_mac(mac_of(9), &d).err == Err::NotFound);
        TT_CHECK(m.lookup_ipv4({10, 83, 0, 9}, &d).err == Err::NotFound);
        TT_CHECK(m.lookup_node_id(9, &d).err == Err::NotFound);
        TT_CHECK(d.c.mac_map_misses == 3);
    }

    TT_CASE();
    {
        SessionMap m;
        Diag d;
        d.events_enabled = false;
        TT_CHECK(!m.bind({0, 0, 0, 0, 0, 0}, &d).ok());
        TT_CHECK(m.bind({0, 0, 0, 0, 0, 0}, &d).err == Err::BadMac);
        TT_CHECK(m.bind({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, &d).err == Err::BadMac);
        TT_CHECK(m.size() == 0);
        TT_CHECK(m.remove(mac_of(1), &d) == false);
        const Res<NodeBinding> one = m.bind(mac_of(1), &d);
        TT_CHECK(one.ok());
        TT_CHECK(m.remove(mac_of(1), &d) == true);
        TT_CHECK(m.size() == 0);
        TT_CHECK(d.c.mac_map_removes == 1); // only successful removals are counted
    }

    TT_CASE();
    {
        SessionMap m({192, 168, 7});
        Diag d;
        d.events_enabled = false;
        const Res<NodeBinding> a = m.bind(mac_of(1), &d);
        TT_CHECK(a.ok() && a.value.ipv4 == ipv4_of(192, 168, 7, 1));

        // s8 domain gate (fail-closed).
        TT_CHECK(check_node_id(127, &d).ok());
        TT_CHECK(check_node_id(-128, &d).ok());
        TT_CHECK(check_node_id(128, &d).err == Err::Range);
        TT_CHECK(check_node_id(-129, &d).err == Err::Range);
        TT_CHECK(d.c.node_id_out_of_range == 2);

        // Filling the table past the s8 domain must fail rather than wrap.
        SessionMap small;
        small.bind({0x02, 0, 0, 0, 0, 0x80}, &d); // node id 1
        for (std::uint8_t i = 1; i < 0x7F; ++i) {
            small.bind({0x02, 0, 0, 0, i, i}, &d);
        }
        TT_CHECK(small.size() == 127);
        const Res<NodeBinding> overflow = small.bind({0x02, 0, 0, 0, 0xEE, 0xEE}, &d);
        TT_CHECK(overflow.err == Err::Range);
        TT_CHECK(small.size() == 127);
        TT_CHECK(small.remove({0x02, 0, 0, 0, 1, 1}, &d));
        const auto reused = small.bind({0x02, 0, 0, 0, 0xEE, 0xEE}, &d);
        TT_CHECK(reused.ok() && reused.value.node_id == 2);
        TT_CHECK(reused.ok() && reused.value.ipv4 == ipv4_of(10, 83, 0, 2));
        TT_CHECK(small.size() == 127);
        TT_CHECK(small.lookup_node_id(127).value.mac == MacAddress({0x02, 0, 0, 0, 126, 126}));
    }
}

TT_SUITE(map_netid) {
    TT_CASE();
    {
        Diag d;
        d.events_enabled = false;
        const Res<UdsNetworkIds> a = derive_uds_network_ids(0x12345678u, &d);
        const Res<UdsNetworkIds> b = derive_uds_network_ids(0x12345678u, &d);
        const Res<UdsNetworkIds> c = derive_uds_network_ids(0x12345679u, &d);
        TT_CHECK(a.ok() && b.ok() && c.ok());
        TT_CHECK(a.ok() && b.ok() && a.value.wlan_comm_id == b.value.wlan_comm_id);
        TT_CHECK(a.ok() && b.ok() && a.value.network_id == b.value.network_id);
        TT_CHECK(a.ok() && c.ok() && a.value.wlan_comm_id != c.value.wlan_comm_id);
        TT_CHECK(a.ok() && a.value.wlan_comm_id != a.value.network_id);
        TT_CHECK(d.c.netid_derived == 3);

        SessionId session;
        session.high = 0x0102030405060708ull;
        session.low = 0x1112131415161718ull;
        const Res<NetworkId> n = derive_ldn_network_id(7, 9, session, &d);
        TT_CHECK(n.ok());
        TT_CHECK(n.ok() && n.value.intent_id.scene_id == 9);
        TT_CHECK(n.ok() && n.value.session_id.high == session.high && n.value.session_id.low == session.low);
        TT_CHECK(n.ok() && n.value.intent_id.local_communication_id == derive_ldn_network_id(7, 9, session, &d).value.intent_id.local_communication_id);
    }

    TT_CASE();
    {
        // One-way: the seed is never recovered from either side.
        Diag d;
        d.events_enabled = false;
        UdsNetworkIds uds;
        uds.wlan_comm_id = 5;
        uds.network_id = 6;
        TT_CHECK(recover_seed_from_uds(uds, &d).err == Err::Irreversible);
        NetworkId id;
        TT_CHECK(recover_seed_from_ldn(id, &d).err == Err::Irreversible);
        TT_CHECK(d.c.netid_irreversible_refused == 2);
    }
}

TT_SUITE(map_ssid) {
    TT_CASE();
    {
        Diag d;
        d.events_enabled = false;
        const Res<Ssid> s = ssid_from_room_name("M4-ROOM", &d);
        TT_CHECK(s.ok());
        TT_CHECK(s.ok() && s.value.length == 7);
        if (s.ok()) {
            TT_CHECK(std::string(reinterpret_cast<const char*>(s.value.raw.data()), 7) == "M4-ROOM");
        }
        // Deterministic: identical input, identical bytes.
        TT_CHECK(s.ok() && ssid_from_room_name("M4-ROOM", &d).value.raw == s.value.raw);
        TT_CHECK(d.c.ssid_derived == 2);

        TT_CHECK(ssid_from_room_name("", &d).err == Err::BadSsid);
        std::string long_name(33, 'A');
        TT_CHECK(ssid_from_room_name(long_name, &d).err == Err::Range);
        TT_CHECK(ssid_from_room_name("bad\x01name", &d).err == Err::Encoding);

        // Reverse is refused (irreversible by design).
        Ssid raw{};
        TT_CHECK(room_name_from_ssid(raw, &d).err == Err::Irreversible);
        TT_CHECK(d.c.ssid_irreversible_refused == 1);
    }
}

TT_SUITE(map_username) {
    TT_CASE();
    {
        Diag d;
        d.events_enabled = false;
        const UserNameBytes src = name_bytes("PLAYER1");
        const Res<Username> u = username_from_bytes(src, &d);
        TT_CHECK(u.ok());
        TT_CHECK(u.ok() && u.value[0] == 'P' && u.value[6] == '1');
        TT_CHECK(u.ok() && u.value[7] == 0);
        const Res<UserNameBytes> back = username_to_bytes(u.value, &d);
        TT_CHECK(back.ok() && back.value == src);
        TT_CHECK(d.c.username_ok == 2);

        // Empty name round-trips to zeroes.
        UserNameBytes empty{};
        const Res<Username> eu = username_from_bytes(empty, &d);
        TT_CHECK(eu.ok());
        TT_CHECK(eu.ok() && username_to_bytes(eu.value, &d).ok());
    }

    TT_CASE();
    {
        Diag d;
        d.events_enabled = false;
        // Overlong (>10 characters before the terminator).
        const UserNameBytes long_name = name_bytes("ABCDEFGHIJK");
        TT_CHECK(username_from_bytes(long_name, &d).err == Err::Range);

        // Unrepresentable byte (not printable ASCII).
        UserNameBytes non_ascii = name_bytes("AB");
        non_ascii[0] = 0x80;
        TT_CHECK(username_from_bytes(non_ascii, &d).err == Err::Encoding);

        // No NUL terminator inside the 33 bytes.
        UserNameBytes no_nul;
        no_nul.fill('A');
        TT_CHECK(username_from_bytes(no_nul, &d).err == Err::Encoding);

        // A u16 that is not a printable ASCII byte.
        Username bad{};
        bad[0] = 0x1234;
        TT_CHECK(username_to_bytes(bad, &d).err == Err::Encoding);

        // Non-zero data after the terminator.
        Username trailing{};
        trailing[0] = 'A';
        trailing[1] = 0;
        trailing[2] = 'B';
        TT_CHECK(username_to_bytes(trailing, &d).err == Err::Encoding);

        // Ten characters fill the 3DS field exactly; the terminator is added.
        Username full{};
        full.fill('A');
        const Res<UserNameBytes> fb = username_to_bytes(full, &d);
        TT_CHECK(fb.ok() && fb.value[9] == 'A' && fb.value[10] == 0);
        TT_CHECK(d.c.username_rejected == 5);
    }
}

TT_SUITE(map_invented) {
    TT_CASE();
    {
        Diag d;
        d.events_enabled = false;
        // friend_code_seed has no Yuzu field: it is zeroed and counted.
        TT_CHECK(friend_code_to_ldn(0x1122334455667788ull, &d) == 0);
        TT_CHECK(friend_code_from_ldn(&d) == 0);
        TT_CHECK(d.c.invented_fields == 1);
        TT_CHECK(d.c.undefined_fields == 1);
    }

    TT_CASE();
    {
        Diag d;
        d.events_enabled = false;
        // The UDS source is capped at 0xC8; anything larger is malformed.
        TT_CHECK(check_advertise_size(AdvertiseDirection::UdsToLdn, 0xC8, &d).ok());
        TT_CHECK(check_advertise_size(AdvertiseDirection::UdsToLdn, 0xC9, &d).err == Err::Oversize);

        // LDN -> UDS stops at 0xC8: never truncated, never best-effort.
        TT_CHECK(check_advertise_size(AdvertiseDirection::LdnToUds, 0xC8, &d).ok());
        TT_CHECK(check_advertise_size(AdvertiseDirection::LdnToUds, 0xC9, &d).err == Err::Capacity);
        TT_CHECK(check_advertise_size(AdvertiseDirection::LdnToUds, 0x180, &d).err == Err::Capacity);
        // oversize_rejected counts exactly the asymmetric LDN -> UDS refusals
        // (the UdsToLdn case is a malformed source and lands in the error table).
        TT_CHECK(d.c.oversize_rejected == 2);
        TT_CHECK(d.c.decode_reject == 3);
        TT_CHECK(d.c.err[static_cast<std::size_t>(Err::Oversize)] == 1);
        TT_CHECK(d.c.err[static_cast<std::size_t>(Err::Capacity)] == 2);
    }
}
