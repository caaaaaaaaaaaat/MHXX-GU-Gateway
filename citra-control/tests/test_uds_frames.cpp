// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - Citra-side frame tests: round trips, all-prefix truncation,
// over/undersize, unknown enums, illegal sentinels, trailing bytes.
#include <string>
#include <vector>

#include "citra_control/uds_frames.hpp"
#include "util.hpp"

using namespace citra_control;
using ttx::hx;

namespace {

GuestNodeInfo sample_guest_node() {
    GuestNodeInfo n;
    n.friend_code_seed = 0x0102030405060708ull;
    for (std::size_t i = 0; i < n.username.size(); ++i) {
        n.username[i] = static_cast<std::uint16_t>(0x0041 + i);
    }
    n.network_node_id = 2;
    return n;
}

EapolNodeInfo sample_eapol_node() {
    EapolNodeInfo n;
    n.friend_code_seed = 0x0102030405060708ull;
    for (std::size_t i = 0; i < n.username.size(); ++i) {
        n.username[i] = static_cast<std::uint16_t>(0x0041 + i);
    }
    n.network_node_id = 2;
    return n;
}

GuestNetworkInfo sample_guest_net() {
    GuestNetworkInfo v;
    v.host_mac_address = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    v.channel = 6;
    v.initialized = 1;
    v.oui_value = kNintendoOui;
    v.oui_type = kNintendoTagIdNetworkInfo;
    v.wlan_comm_id = 0x11223344;
    v.id = 7;
    v.attributes = 0x0102;
    v.network_id = 0xAABBCCDD;
    v.total_nodes = 2;
    v.max_nodes = 2;
    v.application_data_size = 4;
    v.application_data[0] = 0xDE;
    v.application_data[1] = 0xAD;
    v.application_data[2] = 0xBE;
    v.application_data[3] = 0xEF;
    return v;
}

BeaconParams sample_beacon(std::size_t node_count, std::uint8_t appdata_size) {
    BeaconParams p;
    p.network_info = sample_guest_net();
    p.network_info.max_nodes = static_cast<std::uint8_t>(node_count);
    p.network_info.total_nodes = static_cast<std::uint8_t>(node_count);
    p.appdata_size = appdata_size;
    for (std::size_t i = 0; i < appdata_size; ++i) {
        p.appdata[i] = static_cast<std::uint8_t>(0x40 + i);
    }
    for (std::size_t i = 0; i < node_count; ++i) {
        BeaconNodeInfo n;
        n.friend_code_seed = 0x0102030405060708ull + i;
        for (std::size_t k = 0; k < n.username.size(); ++k) {
            n.username[k] = static_cast<std::uint16_t>(0x0041 + k);
        }
        n.network_node_id = static_cast<std::uint16_t>(i + 1);
        p.nodes.push_back(n);
    }
    p.bitmask = (node_count >= 1) ? 0x0003 : 0x0000;
    p.source_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    return p;
}

} // namespace

TT_SUITE(uds_guest) {
    TT_CASE();
    {
        const GuestNodeInfo n = sample_guest_node();
        const std::vector<std::uint8_t> bytes = serialize_guest_node_info(n);
        TT_CHECK(bytes.size() == kGuestNodeInfoSize);
        TT_CHECK(kGuestNodeInfoSize == 40);
        Diag d;
        d.events_enabled = false;
        const Res<GuestNodeInfo> back = parse_guest_node_info(bytes.data(), bytes.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.friend_code_seed == n.friend_code_seed);
        TT_CHECK(back.ok() && back.value.username == n.username);
        TT_CHECK(back.ok() && back.value.network_node_id == n.network_node_id);
        TT_CHECK(back.ok() && serialize_guest_node_info(back.value) == bytes);
        TT_CHECK(d.c.uds_guest_nodeinfo_ok == 1);
        ttx::all_prefixes_reject(bytes, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_guest_node_info(p, s, &dd);
        });
        ttx::trailing_byte_rejected(bytes, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_guest_node_info(p, s, &dd);
        });
    }

    TT_CASE();
    {
        // Little-endian guest layout: friend code seed is u64_le at offset 0.
        GuestNodeInfo n;
        n.friend_code_seed = 1;
        const std::vector<std::uint8_t> bytes = serialize_guest_node_info(n);
        TT_CHECK(ttx::hex(bytes).substr(0, 16) == "0100000000000000");
    }

    TT_CASE();
    {
        const GuestNetworkInfo v = sample_guest_net();
        const std::vector<std::uint8_t> bytes = serialize_guest_network_info(v);
        TT_CHECK(bytes.size() == kGuestNetworkInfoSize);
        TT_CHECK(kGuestNetworkInfoSize == 0x108);
        // On-wire (game) big-endian fields.
        TT_CHECK(ttx::hex(bytes).substr(0x10 * 2, 8) == "11223344"); // wlan_comm_id u32_be
        TT_CHECK(ttx::hex(bytes).substr(0x18 * 2, 8) == "aabbccdd"); // network_id u32_be
        Diag d;
        d.events_enabled = false;
        const Res<GuestNetworkInfo> back = parse_guest_network_info(bytes.data(), bytes.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.wlan_comm_id == 0x11223344);
        TT_CHECK(back.ok() && back.value.network_id == 0xAABBCCDD);
        TT_CHECK(back.ok() && back.value.attributes == 0x0102);
        TT_CHECK(back.ok() && back.value.application_data_size == 4);
        TT_CHECK(back.ok() && back.value.application_data[3] == 0xEF);
        TT_CHECK(back.ok() && serialize_guest_network_info(back.value) == bytes);
        TT_CHECK(d.c.uds_guest_netinfo_ok == 1);
        ttx::all_prefixes_reject(bytes, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_guest_network_info(p, s, &dd);
        });
        ttx::trailing_byte_rejected(bytes, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_guest_network_info(p, s, &dd);
        });

        // appdata_size above 0xC8 is refused, never truncated.
        std::vector<std::uint8_t> bad = bytes;
        bad[0x3F] = 0xC9;
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(parse_guest_network_info(bad.data(), bad.size(), &d2).err == Err::Oversize);

        // Wrong Nintendo OUI / oui_type is refused.
        std::vector<std::uint8_t> bad_oui = bytes;
        bad_oui[0x0C] = 0x01;
        Diag d3;
        d3.events_enabled = false;
        TT_CHECK(parse_guest_network_info(bad_oui.data(), bad_oui.size(), &d3).err == Err::BadTag);
    }

    TT_CASE();
    {
        ConnectionStatus cs;
        cs.status = NetworkStatus::ConnectedAsHost;
        cs.status_change_reason = NetworkStatusChangeReason::ConnectionEstablished;
        cs.network_node_id = 1;
        cs.changed_nodes = 2;
        cs.nodes[0] = 1;
        cs.nodes[1] = 2;
        cs.total_nodes = 2;
        cs.max_nodes = 8;
        cs.node_bitmask = 0x0003;
        const std::vector<std::uint8_t> bytes = serialize_connection_status(cs);
        TT_CHECK(bytes.size() == kConnectionStatusSize);
        TT_CHECK(kConnectionStatusSize == 0x30);
        Diag d;
        d.events_enabled = false;
        const Res<ConnectionStatus> back = parse_connection_status(bytes.data(), bytes.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.status == NetworkStatus::ConnectedAsHost);
        TT_CHECK(back.ok() && back.value.status_change_reason == NetworkStatusChangeReason::ConnectionEstablished);
        TT_CHECK(back.ok() && back.value.nodes[1] == 2);
        TT_CHECK(back.ok() && back.value.node_bitmask == 0x0003);
        TT_CHECK(back.ok() && serialize_connection_status(back.value) == bytes);
        TT_CHECK(d.c.uds_connection_status_ok == 1);
        ttx::all_prefixes_reject(bytes, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_connection_status(p, s, &dd);
        });
        ttx::trailing_byte_rejected(bytes, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_connection_status(p, s, &dd);
        });

        std::vector<std::uint8_t> bad = bytes;
        store_u32le(bad.data(), 0x00000063u); // not a NetworkStatus
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(parse_connection_status(bad.data(), bad.size(), &d2).err == Err::BadEnum);
    }
}

TT_SUITE(uds_connection) {
    TT_CASE();
    {
        AuthenticationFrame f;
        f.auth_seq = AuthenticationSeq::Seq1;
        const Res<std::vector<std::uint8_t>> built = build_authentication_frame(f, nullptr);
        TT_CHECK(built.ok());
        TT_CHECK(built.ok() && built.value.size() == kAuthFrameSize);
        ttx::expect_hex(built.value, "0000 0100 0000");
        Diag d;
        d.events_enabled = false;
        const Res<AuthenticationFrame> back = parse_authentication_frame(built.value.data(), built.value.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.auth_seq == AuthenticationSeq::Seq1);
        TT_CHECK(back.ok() && back.value.auth_algorithm == AuthAlgorithm::OpenSystem);
        TT_CHECK(d.c.uds_auth_ok == 1);
        ttx::all_prefixes_reject(built.value, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_authentication_frame(p, s, &dd);
        });
        ttx::trailing_byte_rejected(built.value, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_authentication_frame(p, s, &dd);
        });

        // Unknown sequence number is refused (never guessed).
        const std::vector<std::uint8_t> bogus = hx("000003000000");
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(parse_authentication_frame(bogus.data(), bogus.size(), &d2).err == Err::BadEnum);

        AuthenticationFrame bad_seq;
        bad_seq.auth_seq = static_cast<AuthenticationSeq>(3);
        Diag d3;
        d3.events_enabled = false;
        TT_CHECK(build_authentication_frame(bad_seq, &d3).err == Err::BadEnum);
    }

    TT_CASE();
    {
        AssociationResponse a;
        a.capabilities = kDefaultExtraCapabilities;
        a.status_code = AssocStatus::Successful;
        a.association_id = 0x1234;
        a.network_id = 0xDEADBEEFu;
        const Res<std::vector<std::uint8_t>> built = build_association_response_frame(a, nullptr);
        TT_CHECK(built.ok());
        TT_CHECK(built.ok() && built.value.size() == kAssocResponseTotalSize);
        ttx::expect_hex(built.value, "3104 0000 34d2 0008 4445414442454546");
        Diag d;
        d.events_enabled = false;
        const Res<AssociationResponse> back = parse_association_response_frame(built.value.data(), built.value.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && (back.value.association_id & 0x3FFF) == 0x1234);
        TT_CHECK(back.ok() && back.value.network_id == 0xDEADBEEFu);
        TT_CHECK(back.ok() && back.value.status_code == AssocStatus::Successful);
        TT_CHECK(d.c.uds_assoc_ok == 1);

        // V-016k: a non-successful status would trip Citra's ASSERT, so it is
        // refused on both build and parse and counted.
        AssociationResponse bad;
        bad.status_code = static_cast<AssocStatus>(1);
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(build_association_response_frame(bad, &d2).err == Err::Unsafe);
        TT_CHECK(d2.c.unsafe_assoc_blocked == 1);

        std::vector<std::uint8_t> bad_status = built.value;
        bad_status[2] = 0x01;
        Diag d3;
        d3.events_enabled = false;
        TT_CHECK(parse_association_response_frame(bad_status.data(), bad_status.size(), &d3).err == Err::Unsafe);
        TT_CHECK(d3.c.unsafe_assoc_blocked == 1);

        // assoc_id above the 14-bit field is refused.
        AssociationResponse big = a;
        big.association_id = 0x4000;
        Diag d4;
        d4.events_enabled = false;
        TT_CHECK(build_association_response_frame(big, &d4).err == Err::Range);

        // SSID tag must be {0x00, 0x08, "XXXXXXXX"} uppercase hex of network_id.
        std::vector<std::uint8_t> bad_tag = built.value;
        bad_tag[6] = 0x42;
        Diag d5;
        d5.events_enabled = false;
        TT_CHECK(parse_association_response_frame(bad_tag.data(), bad_tag.size(), &d5).err == Err::BadTag);

        std::vector<std::uint8_t> bad_text = built.value;
        bad_text[14] = 'x'; // lowercase is not formattable as %08X
        Diag d6;
        d6.events_enabled = false;
        TT_CHECK(parse_association_response_frame(bad_text.data(), bad_text.size(), &d6).err == Err::Encoding);

        ttx::all_prefixes_reject(built.value, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_association_response_frame(p, s, &dd);
        });
        ttx::trailing_byte_rejected(built.value, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_association_response_frame(p, s, &dd);
        });
    }
}

TT_SUITE(uds_eapol) {
    TT_CASE();
    {
        EapolStartPacket p;
        p.association_id = 5;
        p.node = sample_eapol_node();
        const Res<std::vector<std::uint8_t>> built = build_eapol_start_frame(p, nullptr);
        TT_CHECK(built.ok());
        TT_CHECK(built.ok() && built.value.size() == kLlcSize + kEapolStartPacketSize);
        TT_CHECK(ttx::hex(built.value).substr(0, 16) == "aaaa03000000888e");
        TT_CHECK(ttx::hex(built.value).substr(16, 4) == "0201"); // magic u16_be
        Diag d;
        d.events_enabled = false;
        const Res<EapolStartPacket> back = parse_eapol_start_frame(built.value.data(), built.value.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.association_id == 5);
        TT_CHECK(back.ok() && back.value.node.username == p.node.username);
        TT_CHECK(back.ok() && back.value.node.friend_code_seed == p.node.friend_code_seed);
        TT_CHECK(d.c.uds_eapol_start_ok == 1);
        TT_CHECK(d.c.uds_eapol_nodeinfo_ok == 1);
        ttx::all_prefixes_reject(built.value, [](const std::uint8_t* p2, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_eapol_start_frame(p2, s, &dd);
        });
        ttx::trailing_byte_rejected(built.value, [](const std::uint8_t* p2, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_eapol_start_frame(p2, s, &dd);
        });

        // eapol_frame_type / llc_ether_type helpers.
        Diag d2;
        d2.events_enabled = false;
        const Res<std::uint16_t> ft = eapol_frame_type(built.value.data(), built.value.size(), &d2);
        TT_CHECK(ft.ok() && ft.value == kEapolStartMagic);
        const Res<EtherType> et = llc_ether_type(built.value.data(), built.value.size(), &d2);
        TT_CHECK(et.ok() && et.value == EtherType::Eapol);

        // Wrong magic.
        std::vector<std::uint8_t> bad_magic = built.value;
        bad_magic[8] = 0x03;
        Diag d3;
        d3.events_enabled = false;
        TT_CHECK(parse_eapol_start_frame(bad_magic.data(), bad_magic.size(), &d3).err == Err::BadMagic);

        // Wrong LLC protocol -> BadEnum.
        std::vector<std::uint8_t> bad_llc = built.value;
        bad_llc[7] = 0x00;
        Diag d4;
        d4.events_enabled = false;
        TT_CHECK(parse_eapol_start_frame(bad_llc.data(), bad_llc.size(), &d4).err == Err::BadEnum);

        // The hardcoded "unknown" field must stay 1.
        std::vector<std::uint8_t> bad_unknown = built.value;
        bad_unknown[13] = 0x00;
        Diag d5;
        d5.events_enabled = false;
        TT_CHECK(parse_eapol_start_frame(bad_unknown.data(), bad_unknown.size(), &d5).err == Err::BadSentinel);
    }

    TT_CASE();
    {
        EapolLogoffPacket p;
        p.assigned_node_id = 3;
        p.client_mac_address = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        p.connected_nodes = 2;
        p.max_nodes = 8;
        p.nodes[0] = sample_eapol_node();
        p.nodes[1] = sample_eapol_node();
        const Res<std::vector<std::uint8_t>> built = build_eapol_logoff_frame(p, nullptr);
        TT_CHECK(built.ok());
        TT_CHECK(built.ok() && built.value.size() == kLlcSize + kEapolLogoffPacketSize);
        TT_CHECK(ttx::hex(built.value).substr(16, 4) == "0202");
        Diag d;
        d.events_enabled = false;
        const Res<EapolLogoffPacket> back = parse_eapol_logoff_frame(built.value.data(), built.value.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.assigned_node_id == 3);
        TT_CHECK(back.ok() && back.value.client_mac_address == p.client_mac_address);
        TT_CHECK(back.ok() && back.value.nodes[1].network_node_id == p.nodes[1].network_node_id);
        TT_CHECK(d.c.uds_eapol_logoff_ok == 1);
        ttx::all_prefixes_reject(built.value, [](const std::uint8_t* p2, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_eapol_logoff_frame(p2, s, &dd);
        });
        ttx::trailing_byte_rejected(built.value, [](const std::uint8_t* p2, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_eapol_logoff_frame(p2, s, &dd);
        });

        std::vector<std::uint8_t> bad_magic = built.value;
        bad_magic[8] = 0x01;
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(parse_eapol_logoff_frame(bad_magic.data(), bad_magic.size(), &d2).err == Err::BadMagic);

        EapolLogoffPacket too_many = p;
        too_many.connected_nodes = 17;
        Diag d3;
        d3.events_enabled = false;
        TT_CHECK(build_eapol_logoff_frame(too_many, &d3).err == Err::Range);
    }
}

TT_SUITE(uds_data) {
    TT_CASE();
    {
        SecureDataFrame f;
        f.header.data_channel = 6;
        f.header.sequence_number = 0x1234;
        f.header.dest_node_id = 2;
        f.header.src_node_id = 1;
        f.payload = hx("deadbeef");
        const Res<std::vector<std::uint8_t>> built = build_secure_data_frame(f, nullptr);
        TT_CHECK(built.ok());
        TT_CHECK(built.ok() && built.value.size() == kLlcSize + kSecureDataHeaderSize + 4);
        ttx::expect_hex(built.value, "aaaa03000000876d 0012 0000 000e 00 06 1234 0002 0001 deadbeef");
        Diag d;
        d.events_enabled = false;
        const Res<SecureDataFrame> back = parse_secure_data_frame(built.value.data(), built.value.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.payload == f.payload);
        TT_CHECK(back.ok() && back.value.header.data_channel == 6);
        TT_CHECK(back.ok() && back.value.header.sequence_number == 0x1234);
        TT_CHECK(back.ok() && back.value.header.dest_node_id == 2);
        TT_CHECK(back.ok() && back.value.header.src_node_id == 1);
        TT_CHECK(d.c.uds_secure_data_ok == 1);
        ttx::all_prefixes_reject(built.value, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_secure_data_frame(p, s, &dd);
        });
        ttx::trailing_byte_rejected(built.value, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_secure_data_frame(p, s, &dd);
        });

        // V-016k: is_management must stay 0 (Citra ASSERTs otherwise).
        std::vector<std::uint8_t> mgmt = built.value;
        mgmt[kLlcSize + 6] = 0x01;
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(parse_secure_data_frame(mgmt.data(), mgmt.size(), &d2).err == Err::Unsafe);
        TT_CHECK(d2.c.secure_data_management_rejected == 1);

        // Inconsistent self-describing lengths.
        std::vector<std::uint8_t> bad_len = built.value;
        bad_len[kLlcSize + 1] = 0x20;
        Diag d3;
        d3.events_enabled = false;
        TT_CHECK(parse_secure_data_frame(bad_len.data(), bad_len.size(), &d3).err == Err::BadLength);

        // Oversize payload cannot be described in the u16 length.
        SecureDataFrame huge;
        huge.payload.assign(0xFFF2, 0x00);
        Diag d4;
        d4.events_enabled = false;
        TT_CHECK(build_secure_data_frame(huge, &d4).err == Err::Oversize);
    }

    TT_CASE();
    {
        std::vector<NodeMapEntry> entries;
        NodeMapEntry a;
        a.mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        a.node_id = 1;
        NodeMapEntry b;
        b.mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
        b.node_id = 2;
        entries.push_back(a);
        entries.push_back(b);
        const Res<std::vector<std::uint8_t>> built = build_node_map(entries, nullptr);
        TT_CHECK(built.ok());
        TT_CHECK(built.ok() && built.value.size() == 8 + 2 * 8);
        ttx::expect_hex(built.value, "0200000000000000 020000000001 0100 020000000002 0200");
        Diag d;
        d.events_enabled = false;
        const Res<std::vector<NodeMapEntry>> back = parse_node_map(built.value.data(), built.value.size(), &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.size() == 2);
        TT_CHECK(back.ok() && back.value[1].mac == b.mac && back.value[1].node_id == 2);
        TT_CHECK(d.c.uds_nodemap_ok == 1);
        ttx::all_prefixes_reject(built.value, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_node_map(p, s, &dd);
        });
        ttx::trailing_byte_rejected(built.value, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_node_map(p, s, &dd);
        });

        // Entry count larger than the data -> refused.
        std::vector<std::uint8_t> bad_count = built.value;
        bad_count[0] = 0x03;
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(!parse_node_map(bad_count.data(), bad_count.size(), &d2).ok());

        std::vector<NodeMapEntry> too_many(17);
        Diag d3;
        d3.events_enabled = false;
        TT_CHECK(build_node_map(too_many, &d3).err == Err::Range);
    }

    TT_CASE();
    {
        // Deauthentication carries an empty body (Citra sets deauth.data = {}).
        const Res<std::vector<std::uint8_t>> built = build_deauthentication_frame(nullptr);
        TT_CHECK(built.ok());
        TT_CHECK(built.ok() && built.value.empty());
        Diag d;
        d.events_enabled = false;
        TT_CHECK(parse_deauthentication_frame(built.value.data(), 0, &d).ok());
        TT_CHECK(d.c.uds_deauth_ok == 1);
        const std::vector<std::uint8_t> one = hx("00");
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(parse_deauthentication_frame(one.data(), one.size(), &d2).err == Err::Trailing);
    }
}

TT_SUITE(uds_beacon) {
    TT_CASE();
    {
        const AesBlock ctr = make_beacon_ctr({0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, 0x11223344, 0x07, 0xAABBCCDD);
        TT_CHECK(ttx::hex(ctr) == "020000000001443322110700ddccbbaa");
    }

    TT_CASE();
    {
        const std::vector<std::uint8_t> bytes = build_beacon_frame(sample_beacon(2, 4), nullptr).value;
        // Fixed prefix: BeaconFrameHeader(12) + SSID tag(10) + DummyTag(9).
        TT_CHECK(ttx::hex(bytes).substr(0, 24) == "00e9a43500000000" + std::string("6400") + std::string("3104"));
        TT_CHECK(ttx::hex(bytes).substr(24, 20) == "00080000000000000000");
        TT_CHECK(ttx::hex(bytes).substr(44, 18) == "dd07001f32140a0000");
        // Walk IEEE 802.11 IEs independently of our parser. Citra's
        // NetworkInfoTag is 54 bytes including its two-byte IE header.
        TT_CHECK(bytes[31] == 0xDD && bytes[32] == 56);
        TT_CHECK(bytes[33] == 0x00 && bytes[34] == 0x1F && bytes[35] == 0x32 && bytes[36] == 0x15);
        TT_CHECK(bytes[89] == 0xDD && bytes[94] == kNintendoTagIdEncryptedData0);
        std::size_t offset = 12;
        std::size_t tags = 0;
        while (offset + 2 <= bytes.size()) {
            const std::size_t end = offset + 2 + bytes[offset + 1];
            if (end > bytes.size()) break;
            offset = end;
            ++tags;
        }
        TT_CHECK(offset == bytes.size());
        TT_CHECK(tags == 4);
        // Recreate the former duplicate OUI layout: it must be rejected.
        auto legacy = bytes;
        legacy.insert(legacy.begin() + 33, {0x00, 0x1F, 0x32, 0x15});
        TT_CHECK(!parse_beacon_frame(legacy.data(), legacy.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, nullptr).ok());
        Diag d;
        d.events_enabled = false;
        const Res<BeaconFrame> back = parse_beacon_frame(bytes.data(), bytes.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.nodes.size() == 2);
        TT_CHECK(back.ok() && back.value.bitmask == 0x0003);
        TT_CHECK(back.ok() && back.value.nodes[0].network_node_id == 1);
        TT_CHECK(back.ok() && back.value.appdata_size == 4);
        TT_CHECK(back.ok() && back.value.appdata[3] == 0x43);
        TT_CHECK(d.c.uds_beacon_ok == 1);
        if (back.ok()) {
            TT_CHECK(build_beacon_frame(sample_beacon(2, 4), nullptr).value == bytes);
        }
    }

    TT_CASE();
    {
        // Eight node records make the encrypted plaintext (0x12 + 8*0x1E = 0x102)
        // larger than the 0xFA first-tag cutoff, so a second tag is required.
        const std::vector<std::uint8_t> bytes = build_beacon_frame(sample_beacon(8, 0), nullptr).value;
        const std::string h = ttx::hex(bytes);
        TT_CHECK(h.find("18") != std::string::npos);
        TT_CHECK(h.find("dd") != std::string::npos);
        Diag d;
        d.events_enabled = false;
        const Res<BeaconFrame> back = parse_beacon_frame(bytes.data(), bytes.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d);
        TT_CHECK(back.ok());
        TT_CHECK(back.ok() && back.value.nodes.size() == 8);
        ttx::all_prefixes_reject(bytes, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_beacon_frame(p, s, {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &dd);
        });
        ttx::trailing_byte_rejected(bytes, [](const std::uint8_t* p, std::size_t s) {
            Diag dd;
            dd.events_enabled = false;
            return parse_beacon_frame(p, s, {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &dd);
        });
    }

    TT_CASE();
    {
        const std::vector<std::uint8_t> bytes = build_beacon_frame(sample_beacon(2, 4), nullptr).value;
        // Layout: header 12 | SSID tag 10 | Dummy tag 9 | NetworkInfoTag 54+4 |
        // EncryptedData0 tag header 6; the first encrypted byte is the MD5 digest at 95.
        std::vector<std::uint8_t> tampered = bytes;
        tampered[95] ^= 0x01;
        Diag d;
        d.events_enabled = false;
        TT_CHECK(parse_beacon_frame(tampered.data(), tampered.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d).err == Err::BadDigest);
        TT_CHECK(d.c.md5_verify_fail == 1);
    }

    TT_CASE();
    {
        const std::vector<std::uint8_t> bytes = build_beacon_frame(sample_beacon(2, 4), nullptr).value;
        // sha_hash lives at 31 (tag) + 2 + 0x1F = 64.
        std::vector<std::uint8_t> tampered = bytes;
        tampered[64] ^= 0x01;
        Diag d;
        d.events_enabled = false;
        TT_CHECK(parse_beacon_frame(tampered.data(), tampered.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d).err == Err::BadDigest);
        TT_CHECK(d.c.sha1_verify_fail == 1);
    }

    TT_CASE();
    {
        // SSID tag must be {0x00, 0x08, eight zero bytes}.
        std::vector<std::uint8_t> bad = build_beacon_frame(sample_beacon(2, 4), nullptr).value;
        bad[12] = 0x42;
        Diag d;
        d.events_enabled = false;
        TT_CHECK(parse_beacon_frame(bad.data(), bad.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d).err == Err::BadTag);

        std::vector<std::uint8_t> bad_len = build_beacon_frame(sample_beacon(2, 4), nullptr).value;
        bad_len[13] = 0x07; // wrong SSID tag length
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(parse_beacon_frame(bad_len.data(), bad_len.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d2).err == Err::BadTag);

        std::vector<std::uint8_t> bad_ssid = build_beacon_frame(sample_beacon(2, 4), nullptr).value;
        bad_ssid[14] = 0x01; // SSID body must be eight zero bytes
        Diag d2b;
        d2b.events_enabled = false;
        TT_CHECK(parse_beacon_frame(bad_ssid.data(), bad_ssid.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d2b).err == Err::BadSsid);

        // Unknown oui_type on the first encrypted tag.
        std::vector<std::uint8_t> bad_type = build_beacon_frame(sample_beacon(2, 4), nullptr).value;
        bad_type[94] = 0x30;
        Diag d3;
        d3.events_enabled = false;
        TT_CHECK(!parse_beacon_frame(bad_type.data(), bad_type.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d3).ok());

        // Oversize: appdata above 0xC8 is refused by the builder.
        Diag d4;
        d4.events_enabled = false;
        BeaconParams oversize = sample_beacon(2, 0);
        oversize.appdata_size = 0xC9;
        TT_CHECK(build_beacon_frame(oversize, &d4).err == Err::Oversize);
    }

    TT_CASE();
    {
        // A node count above UDSMaxNodes is refused by the builder.
        BeaconParams too_many = sample_beacon(16, 0);
        Diag d;
        d.events_enabled = false;
        const Res<std::vector<std::uint8_t>> ok16 = build_beacon_frame(too_many, &d);
        TT_CHECK(ok16.ok()); // 16 is the UDS maximum
        too_many.nodes.push_back(BeaconNodeInfo{});
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(build_beacon_frame(too_many, &d2).err == Err::Range);
    }

    TT_CASE();
    {
        // Real Citra shape: max_nodes = 2 record slots, total_nodes = 1 connected.
        BeaconParams p = sample_beacon(2, 4);
        p.network_info.total_nodes = 1;
        p.network_info.max_nodes = 2;
        Diag d;
        d.events_enabled = false;
        const Res<std::vector<std::uint8_t>> built = build_beacon_frame(p, &d);
        TT_CHECK(built.ok());
        if (built.ok()) {
            // header 12 + SSID 10 + Dummy 9 | NI tag 58 | enc tag 6 + 0x28*2
            TT_CHECK(built.value.size() == 175);
            TT_CHECK(built.value[49] == 1 && built.value[50] == 2);
            const Res<BeaconFrame> back = parse_beacon_frame(built.value.data(), built.value.size(),
                                                             {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d);
            TT_CHECK(back.ok());
            TT_CHECK(back.ok() && back.value.nodes.size() == 2);
            TT_CHECK(back.ok() && back.value.network_info.total_nodes == 1);
            TT_CHECK(back.ok() && back.value.network_info.max_nodes == 2);
        }
    }

    TT_CASE();
    {
        // spec R7: n = 1 is Citra's own inconsistent boundary; the builder refuses it.
        Diag d;
        d.events_enabled = true;
        const Res<std::vector<std::uint8_t>> one = build_beacon_frame(sample_beacon(1, 4), &d);
        TT_CHECK(!one.ok() && one.err == Err::BadLength);
        TT_CHECK(d.c.beacon_node_reject == 1);
        bool saw = false;
        for (std::size_t i = 0; i < d.log.lines.size(); ++i) {
            if (d.log.lines[i].find("beacon_max_nodes_too_small") != std::string::npos) saw = true;
        }
        TT_CHECK(saw);
    }

    TT_CASE();
    {
        // spec R1/R5: a payload one byte short of 0x28n must be rejected.
        std::vector<std::uint8_t> bytes = build_beacon_frame(sample_beacon(2, 0), nullptr).value;
        bytes[86] = static_cast<std::uint8_t>(bytes[86] - 1); // enc tag length = 4 + (0x28n - 1)
        bytes.pop_back();
        Diag d;
        d.events_enabled = false;
        TT_CHECK(parse_beacon_frame(bytes.data(), bytes.size(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, &d).err ==
                 Err::BadLength);
    }

    TT_CASE();
    {
        // spec R3: an MD5 over the whole 0x28n payload (the old model) must not verify.
        const MacAddress sm = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        std::vector<std::uint8_t> bytes = build_beacon_frame(sample_beacon(2, 0), nullptr).value;
        const std::size_t total = 0x28 * 2;
        const std::size_t off = 31 + (2 + 52) + 6; // first ciphertext byte = 91
        std::vector<std::uint8_t> cipher(bytes.begin() + off, bytes.end());
        TT_CHECK(cipher.size() == total);
        const AesBlock ctr = make_beacon_ctr(sm, 0x11223344, 0x07, 0xAABBCCDD);
        const AesBlock key{};
        Aes128 aes;
        aes.expand(key.data());
        Diag d;
        d.events_enabled = false;
        TT_CHECK(aes128_ctr_xcrypt_stream(aes, ctr, cipher.data(), cipher.size(), &d) == Err::Ok);
        const Md5Digest wrong = md5(cipher.data() + 0x10, total - 0x10);
        for (std::size_t i = 0; i < wrong.size(); ++i) cipher[i] = wrong[i];
        TT_CHECK(aes128_ctr_xcrypt_stream(aes, ctr, cipher.data(), cipher.size(), &d) == Err::Ok);
        for (std::size_t i = 0; i < cipher.size(); ++i) bytes[off + i] = cipher[i];
        Diag d2;
        d2.events_enabled = false;
        TT_CHECK(parse_beacon_frame(bytes.data(), bytes.size(), sm, &d2).err == Err::BadDigest);
        TT_CHECK(d2.c.md5_verify_fail == 1);
    }

    TT_CASE();
    {
        // spec R6: a caller max_nodes that disagrees with nodes.size() fails closed.
        BeaconParams p = sample_beacon(2, 0);
        p.network_info.max_nodes = 3;
        Diag d;
        d.events_enabled = false;
        TT_CHECK(build_beacon_frame(p, &d).err == Err::BadLength);
    }
}
