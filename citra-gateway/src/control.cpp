// SPDX-License-Identifier: GPL-2.0-or-later
// G-b' control-plane bridge implementation.  See control.hpp for the contract.
#include "citra_gateway/control.hpp"

#include "citra_control/crypto.hpp"
#include "citra_control/heartbeat.hpp"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <sstream>

namespace citra_gateway {

namespace {

using citra_control::Err;

// V-277: defined in the anonymous-namespace block further down; Impl::
// translate_mh_packet consumes both.
bool restructure_gu_join_request(citra_room::Bytes& packet);
bool expand_xx_join_accept(const citra_room::Bytes& packet, const std::uint8_t* gu_endpoint,
                           const std::uint8_t* gu_short, citra_room::Bytes& out);

struct MhInnerPacket {
    std::vector<citra_room::Bytes> messages;
    citra_room::Bytes trailer;
    bool malformed = false;
};

// Parse the unencrypted MH body framing used by PIA: 12-byte outer header,
// then 20-byte inner headers plus BE16 payload lengths, rounded to 4 bytes.
// A malformed tail is reported only after at least one complete message so a
// legacy standalone packet keeps its historical path.
MhInnerPacket split_mh_inner_messages(const citra_room::Bytes& packet) {
    MhInnerPacket result;
    if (packet.size() < 32 || packet[4] != 1) {
        return result;
    }
    std::size_t offset = 12;
    while (offset < packet.size()) {
        if (packet[offset] == 0xff) {
            result.trailer.assign(packet.begin() + static_cast<std::ptrdiff_t>(offset), packet.end());
            break;
        }
        if (offset + 20 > packet.size()) {
            result.malformed = !result.messages.empty();
            break;
        }
        const std::size_t payload = citra_control::load_u16be(packet.data() + offset + 2);
        // Legacy standalone callers may leave this field unset. Do not
        // reinterpret their body bytes as additional inner headers.
        if (payload == 0 && result.messages.empty()) {
            return result;
        }
        const std::size_t raw_size = 20 + payload;
        const std::size_t stride = (raw_size + 3) & ~std::size_t{3};
        if (stride > packet.size() - offset) {
            result.malformed = !result.messages.empty();
            break;
        }
        result.messages.emplace_back(packet.begin() + static_cast<std::ptrdiff_t>(offset),
                                     packet.begin() + static_cast<std::ptrdiff_t>(offset + stride));
        offset += stride;
    }
    return result;
}

citra_room::Bytes make_mh_inner_packet(const citra_room::Bytes& outer,
                                       const citra_room::Bytes& message) {
    citra_room::Bytes packet(outer.begin(), outer.begin() + 12);
    packet.insert(packet.end(), message.begin(), message.end());
    return packet;
}

// G2/G3 capacity rule (docs/G4-GATEWAY-BEACON-FIX-SPEC.md) plus the D3 node id
// table (docs/G4-UDS-NODE-ID-FIX-SPEC.md section 1): one calculation shared by
// the Citra Beacon and the EAPoL-Logoff advertisement.  `connected` is
// total_nodes (the host + the joined Citra peer + the joined stations);
// `capacity` is max_nodes -- at least kControlBeaconCapacity and at least deep
// enough to cover the highest UDS id the room can address, because node id N
// lives at record N - 1 (Citra's own index rule, spec section 0.2).  Citra
// requires the record count to equal max_nodes and rejects total_nodes >
// max_nodes, so beacon and logoff carry exactly `capacity` records and the
// spare slots stay as empty records.
struct ControlBeaconShape {
    std::size_t connected = 1;
    std::size_t capacity = kControlBeaconCapacity;
};

// The highest UDS id the room can address right now.  The Citra peer id is the
// floor: ids 1 and 2 are reserved even before anybody joins.
std::size_t control_highest_uds_node_id(const std::vector<ControlStation>& stations) {
    std::size_t highest = kControlCitraPeerNodeId;
    for (const ControlStation& station : stations) {
        highest = std::max<std::size_t>(highest, station_uds_node_id(station.node_id));
    }
    return highest;
}

ControlBeaconShape control_beacon_shape(bool citra_node_joined,
                                        const std::vector<ControlStation>& stations) {
    ControlBeaconShape shape;
    shape.connected = 1 + stations.size();
    if (citra_node_joined) {
        ++shape.connected;
    }
    shape.capacity = std::max<std::size_t>(kControlBeaconCapacity, control_highest_uds_node_id(stations));
    return shape;
}

// D3/N3+N4: the record that belongs to one UDS id, shared by the Beacon and the
// Logoff so the two advertisements can never disagree about who owns which node
// id. The synthetic host has no *captured* source identity, so it advertises
// the profile's reference identity (D4: a real MHXX host beacon decodes node 1
// as seed 0x856d00022c01afe1 / username "CITRA"). LDN stations retain their
// converted name but have no friend-code counterpart; the Citra peer echoes the
// seed and username it sent in its EAPoL-Start.  `uds_node_id` is 1 based and
// is stored at record uds_node_id - 1.
struct ControlUdsRecord {
    bool present = false;
    std::uint64_t friend_code_seed = 0;
    citra_control::Username username{};
};

ControlUdsRecord control_uds_record(std::uint16_t uds_node_id, bool citra_node_joined,
                                    const citra_control::EapolNodeInfo& citra_node_info,
                                    const std::vector<ControlStation>& stations,
                                    std::uint64_t host_seed,
                                    const citra_control::Username& host_username) {
    ControlUdsRecord record;
    if (uds_node_id == kControlHostNodeId) {
        record.present = true;
        // D4: the host node is not anonymous on the wire -- a real MHXX host
        // beacon carries seed 0x856d00022c01afe1 and the name "CITRA" here.
        record.friend_code_seed = host_seed;
        record.username = host_username;
        return record;
    }
    if (uds_node_id == kControlCitraPeerNodeId) {
        if (citra_node_joined) {
            record.present = true;
            record.friend_code_seed = citra_node_info.friend_code_seed;
            record.username = citra_node_info.username;
        }
        return record;
    }
    for (const ControlStation& station : stations) {
        if (station_uds_node_id(station.node_id) == uds_node_id) {
            record.present = true;
            record.username = station.uds_username;
            return record;
        }
    }
    return record;
}

const std::vector<std::string>& counter_key_list() {
    static const std::vector<std::string> keys = {
        "ap_started",
        "ap_initialized",
        "ap_opened",
        "ap_created",
        "ap_rejected",
        "beacon_emitted",
        "beacon_skipped",
        "auth_seq1_accepted",
        "auth_rejected",
        "auth_refused",
        "auth_seq2_emitted",
        "assoc_response_emitted",
        "eapol_start_accepted",
        "eapol_logoff_accepted",
        "eapol_rejected",
        "node_map_emitted",
        "logoff_frame_emitted",
        "deauth_accepted",
        "deauth_rejected",
        "citra_wrong_direction",
        "citra_data_accepted",
        "citra_data_not_connected",
        "citra_opaque_data_forwarded",
        "ldn_scan_accepted",
        "ldn_scan_rejected",
        "ldn_connect_accepted",
        "ldn_connect_rejected",
        "ldn_disconnect_accepted",
        "gu_host_scan_emitted",
        "gu_host_hall_accepted",
        "gu_host_hall_rejected",
        "gu_host_hall_expired",
        "gu_host_beacon_emitted",
        "ldn_disconnect_rejected",
        "ldn_destroy_accepted",
        "ldn_destroy_rejected",
        "ldn_bad_length",
        "ldn_bad_body",
        "ldn_bad_source",
        "ldn_capacity_rejected",
        "ldn_unknown_source",
        "ldn_direction_rejected",
        "ldn_mac_filled",
        "ldn_non_owner_ignored",
        "scan_resp_emitted",
        "sync_network_emitted",
        "heartbeat_pair_learned",
        "heartbeat_observations",
        "announce_forwarded",
        "announce_word_replacements",
        "announce_word_replacements_total",
        "announce_route_rejected",
        "announce_no_identity_word",
        "announce_prereq_rejected",
        "announce_pair_rejected",
        "announce_host_payloads",
        "announce_host_rejected",
        "announce_host_pending",
        "announce_host_flushed",
        // V-266: reverse UDS association injection (one counter per way the
        // synthesised guest handshake can advance or fail, so a live run never
        // leaves a half-finished injection unexplained).
        "citra_beacon_seen",
        "guest_inject_started",
        "guest_inject_no_host",
        "guest_inject_duplicate",
        "guest_inject_auth_seq1_emitted",
        "guest_inject_auth_seq2",
        "guest_inject_assoc_ok",
        "guest_inject_assoc_refused",
        "guest_inject_assoc_bad",
        "guest_inject_eapol_start_emitted",
        "guest_inject_logoff_ok",
        "guest_inject_logoff_ordered",
        "guest_inject_logoff_unmatched",
        "guest_inject_timeout",
        "guest_inject_emit_failed",
        // V-268: the member-table endpoint mapping.  A guest slot is rewritten
        // because its word matched a station derived MHXX word
        // (announce_guest_word_replaced) or because its slot index named a
        // station Citra gave a node id (announce_guest_slot_replaced); an
        // occupied slot neither rule could claim is counted as
        // announce_guest_word_unmatched and left byte for byte.
        "announce_guest_word_replaced",
        "announce_guest_slot_replaced",
        "announce_guest_word_unmatched",
        // V-267: where the LDN advertise_data of every ScanResp/SyncNetwork came
        // from (one counter per source, plus the reasons a Citra appdata was not
        // adopted).  Exactly one of the three *_from_* / empty counters increments
        // per emitted body.
        "advertise_from_citra",
        "advertise_from_cli",
        "advertise_empty",
        "advertise_citra_received",
        "advertise_citra_rejected",
        "advertise_citra_expired",
        "advertise_beacon_unparsed",
        "advertise_live_disabled",
        "mirror_applied",
        "mirror_suppressed",
        "synthesized_network_info",
        "synthesized_beacon",
        "synthesized_node_map",
        "synthesized_logoff",
        // V-277: the join-conversion counters.  They were first left out of
        // this list, so the live run's counters.json silently reported zeros
        // for conversions the trace plainly showed — the fixed key set is also
        // the dump schema, not just a default-zero initializer.
        "join_request_restructured",
        "join_accept_expanded",
        // V-279: the XX→GU structure converters.
        "member_table_converted",
        "session_blob_expanded",
        "advertise_gu_converted",
        // V-281: the GU→XX blob converter (the frame that unlocks the XX
        // bulk pump by granting the sender's station status 5).
        "session_blob_xx_converted",
        "compound_malformed",
        "compound_oversize",
        "compound_datagrams_translated",
        "invented_fields",
        "undefined_fields",
        "ssid_fallback",
        "emit_failed",
        "outbox_invalid",
    };
    return keys;
}

bool ip_is_zero(const room_client::IPv4& ip) {
    return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0;
}

bool mac_is_zero(const citra_room::MacAddress& mac) {
    for (std::uint8_t byte : mac) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
}

bool mac_is_usable(const citra_room::MacAddress& mac) {
    return !mac_is_zero(mac) && !is_sentinel_mac(mac);
}

room_client::IPv4 reverse_ip(const room_client::IPv4& ip) {
    return room_client::IPv4{ip[3], ip[2], ip[1], ip[0]};
}

citra_control::LdnPacketType to_ldn_type(room_client::LdnType type) {
    switch (type) {
    case room_client::LdnType::Scan: return citra_control::LdnPacketType::Scan;
    case room_client::LdnType::ScanResponse: return citra_control::LdnPacketType::ScanResp;
    case room_client::LdnType::Connect: return citra_control::LdnPacketType::Connect;
    case room_client::LdnType::SyncNetwork: return citra_control::LdnPacketType::SyncNetwork;
    case room_client::LdnType::Disconnect: return citra_control::LdnPacketType::Disconnect;
    case room_client::LdnType::DestroyNetwork: return citra_control::LdnPacketType::DestroyNetwork;
    }
    return citra_control::LdnPacketType::Scan;
}

} // namespace

std::uint32_t control_fnv1a32(const std::string& text) {
    std::uint32_t hash = 2166136261u;
    for (unsigned char byte : text) {
        hash ^= static_cast<std::uint32_t>(byte);
        hash *= 16777619u;
    }
    return hash;
}

const std::vector<std::string>& control_counter_keys() { return counter_key_list(); }

std::optional<citra_room::Bytes> convert_gu_hall_advertise(const citra_room::Bytes& gu) {
    // Paired native layouts: v278-advertise-blob/REPORT.md section 1.2.
    // GU's host-id slot is absent in XX; its password/players start eight
    // bytes later. This is a field conversion, not a whole-buffer shift.
    if (gu.size() != 200 || citra_control::load_u32le(gu.data() + 8) != 1 ||
        citra_control::load_u32le(gu.data() + 0x1c) != 1 ||
        citra_control::load_u32le(gu.data() + 0x20) != 1) {
        return std::nullopt;
    }
    citra_room::Bytes xx(200, 0);
    std::copy_n(gu.begin(), 0x0c, xx.begin());
    std::copy(gu.begin() + 0x1c, gu.begin() + 0x50, xx.begin() + 0x1c);
    std::copy_n(gu.begin() + 0x58, 8, xx.begin() + 0x50);
    std::copy_n(gu.begin() + 0x64, 4, xx.begin() + 0x5c);
    std::copy_n(gu.begin() + 0x68, 8, xx.begin() + 0x60);
    std::copy_n(gu.begin() + 0x70, 0x50, xx.begin() + 0x68);
    std::copy_n(gu.begin() + 0xc0, 2, xx.begin() + 0xb8);
    return xx;
}

std::string control_counters_json(const std::map<std::string, std::uint64_t>& merged) {
    std::string out = "{";
    bool first = true;
    for (const std::string& key : counter_key_list()) {
        if (!first) {
            out += ",";
        }
        first = false;
        const auto it = merged.find(key);
        out += "\"" + key + "\":";
        out += std::to_string(it == merged.end() ? 0 : it->second);
    }
    out += "}";
    return out;
}

namespace {
std::uint64_t native_gu_seed(const room_client::IPv4& ip) {
    return 0x4755000000000000ULL | citra_control::load_u32be(ip.data());
}
std::array<std::uint8_t, 70> canonical_gu_descriptor(
    const std::array<std::uint8_t, 70>& native, const std::array<std::uint8_t, 4>& word) {
    std::array<std::uint8_t, 70> out{};
    for (const auto sub : {0u, 35u}) {
        for (const auto at : {sub, sub + 6, sub + 29}) {
            std::copy(word.begin(), word.end(), out.begin() + at);
            out[at + 4] = 0x30; out[at + 5] = 0x39;
        }
        std::copy_n(native.begin() + 12, 2, out.begin() + sub + 12);
        std::copy(word.begin(), word.end(), out.begin() + sub + 18);
    }
    return out;
}
}

struct ReturnState {
    bool have_return_join_fields = false;
    std::array<std::uint8_t, 6> return_gu_endpoint{};
    std::array<std::uint8_t, 2> return_gu_short{};
    std::array<std::uint8_t, 6> return_gu_station_id{};
    std::array<std::uint8_t, 70> return_gu_descriptor{};
    std::uint8_t return_gu_kind{};
    std::uint8_t return_xx_kind{};
    bool have_return_xx_kind{};
    // V-279: the newest counter MHGU itself announced (40B 05 00 00 00 + u32
    // on route 01000000).  The 828B session blob's tail @0x338 names the
    // receiver's current counter (.verify-r26/g4/v278-advertise-blob §2.2).
    bool have_gu_announce_counter = false;
    std::array<std::uint8_t, 4> gu_announce_counter{};
    // V-281: the newest counter MHXX itself announced (40B 05 00 00 00 + u32
    // from the host, route 01000000) — the reference for the XX-dialect blob
    // tail when MHGU's blob is converted for the family-02 handler.
    bool have_mhxx_announce_counter = false;
    std::array<std::uint8_t, 4> mhxx_announce_counter{};
    // V-281: the rescaled GU-side keepalive tick (V-280 keepalive-roster: the
    // XX tail advances at the 3DS tick rate, MHGU expects its own).
    bool keepalive_tick_seen = false;
    std::uint32_t last_xx_tick = 0;
    std::uint64_t gu_tick = 0;
};

struct ControlBridge::Impl : ReturnState {
    ControlOptions opt;
    room_client::IPv4 session_fake_ip{};
    citra_room::MacAddress session_mac{};
    citra_control::ControlPlane plane;
    citra_control::Diag diag;
    std::uint32_t seed = 0;
    citra_room::MacAddress bssid{};
    citra_control::Ssid ssid{};
    std::uint32_t wlan_comm_id = 0;
    std::uint32_t network_id = 0;
    citra_control::NetworkId ldn_network_id{};
    std::vector<std::uint8_t> ldn_advertise_data;
    // V-267: the most recent usable Citra beacon application data, the MAC it
    // came from and the bridge clock it arrived at.  Empty means "no usable
    // appdata"; kCitraAppdataMaxAgeMs retires a value the peer stopped repeating.
    bool live_advertise = true;
    std::vector<std::uint8_t> citra_appdata;
    citra_room::MacAddress citra_appdata_source_mac{};
    std::uint64_t citra_appdata_ms = 0;
    std::vector<citra_control::HeartbeatObservation> heartbeat_window;
    citra_control::HeartbeatLearnerOptions heartbeat_options{};
    // V-259: cross-game identity word pairs (XX word -> GU word) and the
    // announce-forward gate, from Options.
    std::vector<std::pair<std::array<std::uint8_t, 4>, std::array<std::uint8_t, 4>>> identity_pairs;
    bool announce_forward = false;
    std::vector<ControlStation> stations;
    std::uint64_t last_beacon_ms = 0;
    std::uint64_t beacons = 0;
    // V-266: reverse UDS association injection gate plus the two facts it needs:
    // a bridge clock (fed by start/tick/on_citra_wifi/on_citra_eapol, the calls
    // that already carry a timestamp) and "the Citra peer has beaconed", which is
    // the only evidence that Citra is really hosting the UDS network.
    bool guest_inject = false;
    std::uint64_t clock_ms = 0;
    bool citra_beacon_seen = false;
    struct GuHostHall {
        room_client::IPv4 source{};
        std::uint64_t received_ms = 0;
        ControlEmission beacon;
        citra_control::LdnNetworkInfoBody network;
    };
    std::map<citra_room::MacAddress, GuHostHall> gu_host_halls;
    struct GuAdmission {
        enum class State { AwaitStart, AwaitSync, Connected };
        State state = State::AwaitStart;
        GuHostHall hall;
        citra_room::MacAddress guest{};
        citra_control::EapolNodeInfo identity{};
        citra_control::LdnNodeInfo node{};
        std::uint64_t started_ms = 0;
        bool have_host_short = false;
        std::array<std::uint8_t, 2> host_short{};
        bool have_guest_descriptor = false;
        std::array<std::uint8_t, 70> guest_descriptor{};
        bool have_host_descriptor = false;
        std::array<std::uint8_t, 70> host_descriptor{};
        std::uint8_t host_stream_kind = 0;
        std::uint8_t guest_stream_kind = 0;
    };
    std::optional<GuAdmission> gu_admission;
    std::map<citra_room::MacAddress, CitraHostPeerIdentity> local_citra_peers;
    std::map<std::pair<citra_room::MacAddress, room_client::IPv4>,
             std::unique_ptr<ControlBridge>> citra_host_peers;
    std::map<citra_room::MacAddress, GuHostGuestIdentity> gu_guest_identities;
    std::vector<room_client::IPv4> gu_native_members;
    std::map<citra_room::MacAddress, GuHostGuestIdentity> gu_native_peers;
    std::map<room_client::IPv4, std::unique_ptr<ControlBridge>> gu_native_reverse_codecs;
    std::map<room_client::IPv4, std::unique_ptr<ControlBridge>> gu_native_forward_codecs;
    std::map<citra_room::MacAddress, GuHostGuestIdentity> all_gu_guests() const {
        auto peers = gu_native_peers;
        peers.insert(gu_guest_identities.begin(), gu_guest_identities.end());
        return peers;
    }
    ControlBridge* native_reverse_codec(const GuHostGuestIdentity& peer);
    bool gu_scan_started = false;
    std::uint64_t gu_last_scan_ms = 0;
    std::uint64_t gu_last_beacon_ms = 0;
    // D3/N2 (docs/G4-UDS-NODE-ID-FIX-SPEC.md section 2): what the joined Citra
    // peer told us.  Its declared network_node_id is never trusted -- real
    // clients send an uninitialised 0 -- so the peer is pinned to the reserved
    // id kControlCitraPeerNodeId; only the seed and username are kept, for the
    // Logoff and Beacon echo.
    bool citra_node_joined = false;
    citra_control::EapolNodeInfo citra_node_info{};
    bool ap_started = false;
    std::map<std::string, std::uint64_t> counters;

    Impl(const ControlOptions& options, const room_client::IPv4& fake_ip, const citra_room::MacAddress& mac)
        : opt(options), session_fake_ip(fake_ip), session_mac(mac) {
        for (const std::string& key : counter_key_list()) {
            counters[key] = 0;
        }
        seed = opt.room_seed;
        const std::uint32_t h =
            control_fnv1a32("citra-gateway-bssid:" + opt.room_name + ":" + std::to_string(seed));
        bssid = citra_room::MacAddress{0x02, 0x00, static_cast<std::uint8_t>((h >> 24) & 0xFF),
                                       static_cast<std::uint8_t>((h >> 16) & 0xFF),
                                       static_cast<std::uint8_t>((h >> 8) & 0xFF),
                                       static_cast<std::uint8_t>(h & 0xFF)};
        const auto parsed_ssid = citra_control::ssid_from_room_name(opt.room_name, &diag);
        if (parsed_ssid.ok()) {
            ssid = parsed_ssid.value;
        } else {
            ++counters["ssid_fallback"];
            const auto fallback = citra_control::ssid_from_room_name(kControlFallbackSsid, &diag);
            if (fallback.ok()) {
                ssid = fallback.value;
            }
        }
        const auto uds = citra_control::derive_uds_network_ids(seed, &diag);
        if (uds.ok()) {
            wlan_comm_id = uds.value.wlan_comm_id;
            network_id = uds.value.network_id;
        }
        const citra_control::SessionId session{0, 0};
        const auto ldn = citra_control::derive_ldn_network_id(seed, opt.scene_id, session, &diag);
        if (ldn.ok()) {
            ldn_network_id = ldn.value;
        }
        // V-239: cross-game identity override.  A real Yuzu client drops every
        // ScanResp whose IntentId.local_communication_id differs from its own
        // game's (measured: MHGU advertises 0x0100770008dd8000 and filters on
        // it), so a cross-game hall must advertise the client game's id.  The
        // override is explicit CLI input, never a guessed value.  A zero
        // session never occurs on a real AP; give a stable per-room one.
        if (opt.ldn_comm_id_override != 0) {
            ldn_network_id.intent_id.local_communication_id = opt.ldn_comm_id_override;
            ldn_network_id.session_id.high = 0;
            ldn_network_id.session_id.low = opt.ldn_session_id != 0
                                                ? opt.ldn_session_id
                                                : (0x6C646E3100000000ULL | seed);
        }
        // V-259: identity word pairs for the cross-game announce translation.
        // The V-249 primitive refuses an ambiguous table (from == to, two equal
        // "from" words, more than four entries); the bridge keeps the same
        // guards as a fail-closed filter instead of a throw, because a bad pair
        // must never turn into a silent half-translation.  main.cpp rejects the
        // same shapes at the CLI, so this counter is the defence in depth.
        for (const auto& pair : opt.ldn_identity_pairs) {
            bool usable = pair.xx_word != pair.gu_word;
            for (const auto& existing : identity_pairs) {
                if (existing.first == pair.xx_word) {
                    usable = false;
                }
            }
            if (!usable || identity_pairs.size() >= 4) {
                ++counters["announce_pair_rejected"];
                continue;
            }
            identity_pairs.push_back({pair.xx_word, pair.gu_word});
        }
        announce_forward = opt.ldn_announce_forward;
        guest_inject = opt.ldn_guest_inject;
        // V-239: carry the caller-provided game advertise data verbatim; the
        // game decides hall visibility from this structure, not from LDN.
        ldn_advertise_data = opt.ldn_advertise_data;
        live_advertise = opt.ldn_live_advertise;
        plane.reset(&diag);
    }

    std::vector<ControlEmission> drain();
    ControlEmission citra_intent_emission(const citra_control::CitraFrameIntent& intent);
    ControlEmission ldn_intent_emission(const citra_control::LdnIntent& intent);
    // V-267: not const any more -- it counts which advertise_data source it used.
    citra_control::LdnNetworkInfoBody make_network_info();
    // V-267: store one beacon application data value (length gate + gate check).
    void on_citra_beacon_appdata(const citra_room::Bytes& appdata,
                                 const citra_room::MacAddress& source_mac, std::uint64_t now_ms);
    // V-267: the advertise_data of the next ScanResp/SyncNetwork plus the counter
    // that names its source: Citra live appdata > CLI template > empty.
    std::vector<std::uint8_t> advertise_data();
    bool live_hall_available();
    std::vector<std::uint8_t> node_map_bytes();
    std::vector<std::uint8_t> logoff_bytes();
    ControlEmission beacon_emission();
    std::vector<ControlEmission> gu_host_tick();
    LdnHandling gu_host_response(const room_client::LdnPacket& packet);
    LdnHandling gu_host_sync(const room_client::LdnPacket& packet);
    std::vector<ControlEmission> gu_host_wifi(const citra_room::WifiPacket& wifi);
    std::vector<ControlEmission> gu_host_depart(bool notify_host);
    ControlEmission sync_emission(const room_client::IPv4& ip);
    ControlEmission scan_resp_emission(const room_client::IPv4& ip);
    std::int8_t allocate_node_id() const;
    void add_station(const citra_room::MacAddress& mac, const room_client::IPv4& ip,
                     const std::array<std::uint8_t, 4>& declared_ipv4, bool have_declared_ipv4,
                     const citra_control::UserNameBytes& user_name,
                     const citra_control::Username& uds_username, std::int16_t version);
    bool remove_station(const room_client::IPv4& ip);
    std::vector<ControlEmission> sync_all_stations();
    // V-261: bounded, de-duplicated samples of inbound Data frames.
    std::map<std::string, std::vector<DataFrameSample>> data_samples;
    void note_data_frame(const char* verdict, const citra_room::Bytes& data, int base);
    // V-263: shared kind-0/kind-1 translation.  base is the offset of the
    // 32AB9864 magic inside src; the identity words from body offset 32 are
    // substituted and the packet is appended to out as a room proxy frame of
    // the given kind.  Returns false when the route is outside the measured
    // set or no identity word matched (both counted, frame stays dropped).
    bool translate_mh_packet(const citra_room::Bytes& src, std::size_t base, std::string kind,
                             std::vector<ControlEmission>& out);
    // V-268: rewrite the member endpoints of an 0x0111 table in place.  body is
    // the offset of the 0x0111 type inside bytes; slot 0 is the host and is left
    // to the identity-pair scan, slots 1..count-1 are the guests.  Returns the
    // number of substitutions, 0 when the body is not a member table.
    std::size_t translate_member_endpoints(citra_room::Bytes& bytes, std::size_t body);
    // V-264: offset of the 32AB9864 magic in a host-side payload (0, behind the
    // 22 byte UDS prefix, or behind the 41 byte head); src.size() when absent.
    std::size_t host_magic_base(const citra_room::Bytes& src) const;
    // V-264: the host announces its member table once, normally before any
    // Yuzu station exists.  Those payloads wait here (bounded) and are flushed
    // as soon as a station is admitted, so side ordering no longer decides.
    std::vector<citra_room::Bytes> pending_host_payloads;
    void flush_pending_host_payloads(std::vector<ControlEmission>& out);
    // V-266: reverse UDS association injection.  All of these are no-ops while
    // guest_inject is false.
    void note_clock(std::uint64_t now);
    ControlStation* awaiting_station(GuestInjectionState state,
                                     const citra_room::MacAddress& addressed_to);
    ControlEmission guest_auth_emission(const ControlStation& station);
    ControlEmission guest_eapol_start_emission(ControlStation& station);
    void begin_guest_injection(ControlStation& station, std::vector<ControlEmission>& out);
    bool take_guest_logoff(const citra_control::EapolLogoffPacket& packet);
    void expire_guest_injections();

    // V-279: three XX→GU structure converters under the --ldn-game-return gate.
    // Field maps audit-verified by .verify-r26/g4/v278-{member-table,advertise-blob}.
    std::map<room_client::IPv4, ReturnState> return_states;
    std::optional<room_client::IPv4> active_return_ip;
    std::optional<room_client::IPv4> bound_return_source;
    void select_return_peer(const room_client::IPv4& ip) {
        if (active_return_ip == ip) return;
        if (!active_return_ip) {
            active_return_ip = ip;
            const auto found = return_states.find(ip);
            if (found != return_states.end()) static_cast<ReturnState&>(*this) = found->second;
            return;
        }
        if (active_return_ip) return_states[*active_return_ip] = static_cast<const ReturnState&>(*this);
        static_cast<ReturnState&>(*this) = return_states[ip];
        active_return_ip = ip;
    }
    void forget_return_peer(const room_client::IPv4& ip) {
        return_states.erase(ip);
        if (active_return_ip == ip) {
            static_cast<ReturnState&>(*this) = ReturnState{};
            active_return_ip.reset();
        }
    }
    // V-279: XX→GU identity words (pair words plus injected-station words),
    // shared by the member-table and blob converters.
    std::map<std::array<std::uint8_t, 4>, std::array<std::uint8_t, 4>> xx_to_gu_words() const;
    std::optional<citra_room::Bytes> convert_member_table_xx_to_gu(
        const citra_room::Bytes& xx, std::size_t& words_mapped) const;
    std::optional<citra_room::Bytes> convert_session_blob_xx_to_gu(
        const citra_room::Bytes& xx, std::size_t& words_mapped) const;
    // V-281: MHGU's 828B GU-dialect blob → MHXX's 268B family-02 blob (the
    // frame whose handling grants the sender's station status 5 and unlocks
    // the XX bulk pump).
    std::optional<citra_room::Bytes> convert_blob_gu_to_xx(const citra_room::Bytes& gu) const;
};

namespace {
// V-279 constants, audit-verified by .verify-r26/g4/v278-advertise-blob:
// the GU-side 8-byte host identifier carried by the GU advertise @0x14 and
// the GU session blob @0x25 (same value in every healthy sample).
constexpr std::array<std::uint8_t, 8> kGuHostIdBytes = {0xc6, 0x23, 0xab, 0x25,
                                                        0x3e, 0x0e, 0xe0, 0xa6};
// UTF-16LE name slot (0-terminated) to UTF-8, BMP only; unpaired surrogates
// become '?'.  Hunter/hall names in these structures never exceed the BMP.
std::vector<std::uint8_t> utf16le_slot_to_utf8(const std::uint8_t* begin, std::size_t capacity) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < capacity; i += 2) {
        const std::uint32_t unit = static_cast<std::uint32_t>(begin[i]) |
                                   static_cast<std::uint32_t>(begin[i + 1]) << 8;
        if (unit == 0) {
            break;
        }
        if (unit >= 0xD800 && unit <= 0xDFFF) {
            out.push_back('?');
            continue;
        }
        if (unit < 0x80) {
            out.push_back(static_cast<std::uint8_t>(unit));
        } else if (unit < 0x800) {
            out.push_back(static_cast<std::uint8_t>(0xC0 | unit >> 6));
            out.push_back(static_cast<std::uint8_t>(0x80 | (unit & 0x3F)));
        } else {
            out.push_back(static_cast<std::uint8_t>(0xE0 | unit >> 12));
            out.push_back(static_cast<std::uint8_t>(0x80 | (unit >> 6 & 0x3F)));
            out.push_back(static_cast<std::uint8_t>(0x80 | (unit & 0x3F)));
        }
    }
    return out;
}

// V-281: UTF-8 text to a UTF-16LE slot body (no terminator; the caller writes
// it).  Invalid sequences become '?' like the forward direction.
std::vector<std::uint8_t> utf8_to_utf16le(const std::uint8_t* begin, std::size_t size) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i < size;) {
        std::uint32_t unit = 0x3F;  // '?' for invalid sequences
        const std::uint8_t lead = begin[i];
        if (lead == 0x00) {
            break;  // NUL terminator: the rest of the slot is zero padding
        }
        if (lead < 0x80) {
            unit = lead;
            i += 1;
        } else if (lead >> 5 == 0x6 && i + 1 < size && begin[i + 1] >> 6 == 0x2) {
            unit = (lead & 0x1F) << 6 | (begin[i + 1] & 0x3F);
            i += 2;
        } else if (lead >> 4 == 0xE && i + 2 < size && begin[i + 1] >> 6 == 0x2 &&
                   begin[i + 2] >> 6 == 0x2) {
            unit = (lead & 0x0F) << 12 | (begin[i + 1] & 0x3F) << 6 | (begin[i + 2] & 0x3F);
            i += 3;
        } else {
            i += 1;
        }
        out.push_back(static_cast<std::uint8_t>(unit & 0xFF));
        out.push_back(static_cast<std::uint8_t>(unit >> 8));
    }
    return out;
}
}  // namespace

std::map<std::array<std::uint8_t, 4>, std::array<std::uint8_t, 4>>
ControlBridge::Impl::xx_to_gu_words() const {
    std::map<std::array<std::uint8_t, 4>, std::array<std::uint8_t, 4>> words;
    for (const auto& pair : identity_pairs) {
        words.emplace(pair.first, pair.second);
    }
    for (const auto& [mac, local] : local_citra_peers) {
        (void)mac;
        words.emplace(mhxx_identity_word_from_seed(local.node.friend_code_seed), local.ip);
    }
    if (guest_inject && citra_beacon_seen) {
        for (const ControlStation& station : stations) {
            if (station.guest_inject_state == GuestInjectionState::Done &&
                station.have_uds_node_id && station.uds_node_id >= 2 &&
                station.uds_node_id <= citra_control::kUdsMaxNodes &&
                station.have_guest_identity_word) {
                words.emplace(station.guest_identity_word, station.fake_ip);
            }
        }
    }
    return words;
}

std::optional<citra_room::Bytes> ControlBridge::Impl::convert_member_table_xx_to_gu(
    const citra_room::Bytes& xx, std::size_t& words_mapped) const {
    // Shape gate: the XX 0111 table is exactly 176 bytes with len@14 == 141
    // (V-278 member-table §5 invariants len@14 = N*9+33, XX N=12).
    if (xx.size() != 176 || citra_control::load_u32be(xx.data() + 24) != 0x03003039u ||
        xx[32] != 0x01 || xx[33] != 0x11 ||
        citra_control::load_u16be(xx.data() + 14) != 141) {
        return std::nullopt;
    }
    const auto words = xx_to_gu_words();
    citra_room::Bytes out(140, 0x00);
    // Header: everything passes through except the payload length; the sender
    // word was already mapped by the V-275 block before this runs.
    std::copy(xx.begin(), xx.begin() + 32, out.begin());
    out[14] = 0x00;
    out[15] = 105;  // 8*9+33
    // Body fixed head: type/bodylen passthrough fields, count clamped to 8.
    std::copy(xx.begin() + 32, xx.begin() + 44, out.begin() + 32);
    out[34] = 73;  // 8*9+1, LE16 low byte; high byte stays 0
    const std::uint32_t count = static_cast<std::uint32_t>(xx[44]) |
                                static_cast<std::uint32_t>(xx[45]) << 8 |
                                static_cast<std::uint32_t>(xx[46]) << 16 |
                                static_cast<std::uint32_t>(xx[47]) << 24;
    const std::uint32_t clamped = count > 8 ? 8 : count;
    out[44] = static_cast<std::uint8_t>(clamped);
    out[45] = static_cast<std::uint8_t>(clamped >> 8);
    out[46] = static_cast<std::uint8_t>(clamped >> 16);
    out[47] = static_cast<std::uint8_t>(clamped >> 24);
    std::copy(xx.begin() + 48, xx.begin() + 64, out.begin() + 48);  // A/B + u32=1 + zeros
    // Slots 0..7: id word-mapped (positional fallback via the XX node-id byte
    // at +7), port passthrough, +6/+7 zeroed (GU native), +8 = slot index.
    for (std::size_t k = 0; k < 8; ++k) {
        const std::uint8_t* src = xx.data() + 64 + 9 * k;
        std::uint8_t* dst = out.data() + 64 + 9 * k;
        const bool occupied = src[0] || src[1] || src[2] || src[3];
        if (!occupied) {
            // 00*8 + ff: the GU empty slot, byte for byte the XX empty slot.
            std::copy(src, src + 9, dst);
            continue;
        }
        std::array<std::uint8_t, 4> id{src[0], src[1], src[2], src[3]};
        const auto found = words.find(id);
        if (found != words.end()) {
            std::copy(found->second.begin(), found->second.end(), dst);
            ++words_mapped;
        } else if (src[7] >= 2 && src[7] <= citra_control::kUdsMaxNodes) {
            // Positional rule (V-268): slot k lists node k+1; the XX table
            // repeats that node id at +7, so an unmapped word can still claim
            // its station by node id.
            const ControlStation* by_node = nullptr;
            for (const ControlStation& station : stations) {
                if (station.have_uds_node_id &&
                    static_cast<std::uint8_t>(station.uds_node_id) == src[7] &&
                    !ip_is_zero(station.fake_ip)) {
                    by_node = &station;
                    break;
                }
            }
            if (by_node != nullptr) {
                std::copy(by_node->fake_ip.begin(), by_node->fake_ip.end(), dst);
                ++words_mapped;
            } else {
                std::copy(src, src + 4, dst);  // unknown member: keep as-is
            }
        } else {
            std::copy(src, src + 4, dst);
        }
        dst[4] = src[4];
        dst[5] = src[5];  // port 3039, same encoding both sides
        dst[6] = 0x00;
        dst[7] = 0x00;  // XX wrote k+1 here; GU native is 0 (V-278 open item 1)
        dst[8] = static_cast<std::uint8_t>(k);
    }
    // Tail: count-occupied passthrough (stable 0, transitional 1).
    std::copy(xx.begin() + 172, xx.begin() + 176, out.begin() + 136);
    return out;
}

std::optional<citra_room::Bytes> ControlBridge::Impl::convert_session_blob_xx_to_gu(
    const citra_room::Bytes& xx, std::size_t& words_mapped) const {
    // Shape gate: the XX host blob is exactly 268 bytes, kind 0, route
    // 01000000, body 02 00 07 02, len@14 == 235 (V-278 advertise-blob §2).
    if (xx.size() != 268 || xx[5] != 0 || citra_control::load_u32be(xx.data() + 24) != 0x01000000u ||
        xx[32] != 0x02 || xx[33] != 0x00 || xx[34] != 0x07 || xx[35] != 0x02 ||
        citra_control::load_u16be(xx.data() + 14) != 235) {
        return std::nullopt;
    }
    citra_room::Bytes out(828, 0x00);
    // Header: passthrough except the payload length; kind stays 0 and the
    // sender word was already mapped by the V-275 block.
    std::copy(xx.begin(), xx.begin() + 32, out.begin());
    out[14] = 0x03;
    out[15] = 0x1c;  // 796 = 828-32
    // Body head: GU dialect subcode 04 (byte 35).
    out[32] = 0x02;
    out[33] = 0x00;
    out[34] = 0x07;
    out[35] = 0x04;
    // GU-only 8B host id @0x25.
    std::copy(kGuHostIdBytes.begin(), kGuHostIdBytes.end(), out.begin() + 0x25);
    // Session id @0x45: byte-for-byte copy from the XX blob (the advertise
    // stores it LE, the blob BE — the XX blob already carries the BE form).
    std::copy(xx.begin() + 0x45, xx.begin() + 0x49, out.begin() + 0x45);
    // Three flags @0x49 (01 01 01 in every sample).
    out[0x49] = 0x01;
    out[0x4a] = 0x01;
    out[0x4b] = 0x01;
    // Name slot 1 @0x4c: UTF-8 (XX carried the sender's name as UTF-16 at
    // 0x4d behind a 00 flag byte at 0x4c).
    const std::vector<std::uint8_t> name = utf16le_slot_to_utf8(xx.data() + 0x4d, 0x9c - 0x4d);
    if (!name.empty() && name.size() <= 0x4f) {
        std::copy(name.begin(), name.end(), out.begin() + 0x4c);
        out[0x4c + name.size()] = 0x00;
    }
    // Width flag + name slot 2: single-byte width prefix then the same name.
    out[0x9c] = 0x01;
    if (!name.empty() && name.size() <= 0x27) {
        std::copy(name.begin(), name.end(), out.begin() + 0x9d);
        out[0x9d + name.size()] = 0x00;
    }
    out[0xc5] = 0x01;
    out[0xc6] = 0x01;
    // Tail counter @0x338: the receiver's (MHGU's) current counter.  The XX
    // blob already computed it at 0x107 (V-277 live: XX tail == GU counter+1);
    // fall back to the stashed GU announce counter when the XX tail is zero.
    std::array<std::uint8_t, 4> counter{};
    std::copy(xx.begin() + 0x107, xx.begin() + 0x10b, counter.begin());
    if (counter == std::array<std::uint8_t, 4>{0, 0, 0, 0} && have_gu_announce_counter) {
        counter = gu_announce_counter;
    }
    std::copy(counter.begin(), counter.end(), out.begin() + 0x338);
    ++words_mapped;  // the sender word was mapped by the V-275 block
    return out;
}

std::optional<citra_room::Bytes> ControlBridge::Impl::convert_blob_gu_to_xx(
    const citra_room::Bytes& gu) const {
    // Shape gate: the GU guest blob is exactly 828 bytes, kind 1, route
    // 01000000, body 02 00 07 04, len@14 == 796 (V-278 advertise-blob §2).
    if (gu.size() != 828 || gu[5] != 1 ||
        citra_control::load_u32be(gu.data() + 24) != 0x01000000u || gu[32] != 0x02 ||
        gu[33] != 0x00 || gu[34] != 0x07 || gu[35] != 0x04 ||
        citra_control::load_u16be(gu.data() + 14) != 796) {
        return std::nullopt;
    }
    citra_room::Bytes out(268, 0x00);
    // Header passthrough; len@14 becomes 235.  kind stays 1 and the sender
    // field stays 0 — the guest blob form in every healthy XX sample.
    std::copy(gu.begin(), gu.begin() + 32, out.begin());
    out[14] = 0x00;
    out[15] = 235;
    out[32] = 0x02;
    out[33] = 0x00;
    out[34] = 0x07;
    out[35] = 0x02;  // XX dialect subcode
    // @0x25..0x2d stays zero: XX never fills the 8-byte host id there.
    // Session id @0x45: byte for byte (GU already derived the same value).
    std::copy(gu.begin() + 0x45, gu.begin() + 0x49, out.begin() + 0x45);
    out[0x49] = 0x01;
    out[0x4a] = 0x01;
    out[0x4b] = 0x01;
    // Name slot 1 @0x4c: 00 flag byte, then the sender's name as UTF-16LE
    // (GU carried it as UTF-8 at 0x4c).  Zero-fill to 0x9c.
    out[0x4c] = 0x00;
    {
        const std::vector<std::uint8_t> name = utf8_to_utf16le(gu.data() + 0x4c, 0x9c - 0x4c);
        if (!name.empty() && name.size() <= 0x9c - 0x4d) {
            std::copy(name.begin(), name.end(), out.begin() + 0x4d);
        }
    }
    // Width flag 02 + name slot 2 (UTF-16LE again) at 0x9e.
    out[0x9c] = 0x02;
    out[0x9d] = 0x00;
    {
        const std::vector<std::uint8_t> name = utf8_to_utf16le(gu.data() + 0x4c, 0x9c - 0x4c);
        if (!name.empty() && name.size() <= 0xc5 - 0x9e) {
            std::copy(name.begin(), name.end(), out.begin() + 0x9e);
        }
    }
    out[0xc5] = 0x02;
    out[0xc6] = 0x01;
    // V-292: both healthy XX traces bind this token to the opposite side's
    // announce series (+1), just as the original GU guest blob does. Keep
    // that token; substituting the GU sender's own counter breaks the binding.
    std::copy(gu.begin() + 0x338, gu.begin() + 0x33c, out.begin() + 0x107);
    return out;
}

bool ControlBridge::Impl::live_hall_available() {
    if (!citra_appdata.empty() && clock_ms >= citra_appdata_ms &&
        clock_ms - citra_appdata_ms > kCitraAppdataMaxAgeMs) {
        citra_appdata.clear();
        citra_appdata_source_mac = citra_room::MacAddress{};
        ++counters["advertise_citra_expired"];
    }
    return live_advertise && !citra_appdata.empty();
}

std::vector<std::uint8_t> ControlBridge::Impl::advertise_data() {
    if (opt.ldn_require_live_hall && !live_hall_available()) {
        return {};
    }
    if (live_advertise && !citra_appdata.empty()) {
        if (clock_ms >= citra_appdata_ms && clock_ms - citra_appdata_ms > kCitraAppdataMaxAgeMs) {
            // The peer stopped repeating its hall description.  Retire it once
            // (advertise_citra_expired) and fall through to the CLI template,
            // rather than keeping a hall name alive that no beacon backs.
            citra_appdata.clear();
            citra_appdata_source_mac = citra_room::MacAddress{};
            ++counters["advertise_citra_expired"];
        } else {
            ++counters["advertise_from_citra"];
            // V-279: the live Citra appdata is an XX-layout advertise; MHGU
            // reads player names, HR and the password slot 8 bytes further
            // back (.verify-r26/g4/v278-advertise-blob §1.2), so an untouched
            // XX advertise makes GU hallucinate a password and wrong hunters.
            if (opt.ldn_game_return && citra_appdata.size() == 200) {
                std::vector<std::uint8_t> converted(200, 0x00);
                const auto& xx = citra_appdata;
                std::copy(xx.begin(), xx.begin() + 0x0c, converted.begin());      // session id + 1s
                // 0x0c..0x14: XX per-beacon churn word; GU writes 0.
                std::copy(kGuHostIdBytes.begin(), kGuHostIdBytes.end(),
                          converted.begin() + 0x14);                               // GU host id
                std::copy(xx.begin() + 0x1c, xx.begin() + 0x50, converted.begin() + 0x1c);
                std::copy(xx.begin() + 0x50, xx.begin() + 0x58, converted.begin() + 0x58);  // password +8
                std::copy(xx.begin() + 0x5c, xx.begin() + 0x60, converted.begin() + 0x64);  // per-player u8
                std::copy(xx.begin() + 0x60, xx.begin() + 0x68, converted.begin() + 0x68);  // HR u16s
                std::copy(xx.begin() + 0x68, xx.begin() + 0xb8, converted.begin() + 0x70);  // name slots
                std::copy(xx.begin() + 0xb8, xx.begin() + 0xba, converted.begin() + 0xc0);  // ffff
                ++counters["advertise_gu_converted"];
                return converted;
            }
            return citra_appdata;
        }
    }
    if (!ldn_advertise_data.empty()) {
        ++counters["advertise_from_cli"];
        return ldn_advertise_data;
    }
    ++counters["advertise_empty"];
    return {};
}

void ControlBridge::Impl::on_citra_beacon_appdata(const citra_room::Bytes& appdata,
                                                  const citra_room::MacAddress& source_mac,
                                                  std::uint64_t now_ms) {
    note_clock(now_ms);
    // Length gate first, independent of the gate: an empty appdata names no hall
    // and an oversize one cannot be carried by the frozen LDN NetworkInfo
    // (advertise_data is kLdnAdvertiseDataSizeMax = 0x180 bytes).
    if (appdata.empty() || appdata.size() > citra_control::kLdnAdvertiseDataSizeMax) {
        // An explicit empty beacon withdraws the previous hall immediately.
        if (appdata.empty() && opt.ldn_require_live_hall) {
            citra_appdata.clear();
            citra_appdata_source_mac = citra_room::MacAddress{};
        }
        ++counters["advertise_citra_rejected"];
        return;
    }
    if (!live_advertise) {
        // Recorded, never adopted: with --no-ldn-live-advertise the LDN side has
        // to stay byte for byte what it was before this stage.
        ++counters["advertise_live_disabled"];
        return;
    }
    citra_appdata.assign(appdata.begin(), appdata.end());
    citra_appdata_source_mac = source_mac;
    citra_appdata_ms = clock_ms;
    ++counters["advertise_citra_received"];
}

citra_control::LdnNetworkInfoBody ControlBridge::Impl::make_network_info() {
    citra_control::LdnNetworkInfoBody body;
    body.network_id = ldn_network_id;
    body.common.bssid = bssid;
    body.common.ssid = ssid;
    body.common.channel = opt.channel;
    body.common.link_level = static_cast<std::int8_t>(kControlLinkLevel);
    body.common.network_type = kControlNetworkType;

    body.ldn.security_mode = citra_control::SecurityMode::All;
    body.ldn.station_accept_policy = citra_control::AcceptPolicy::AcceptAll;
    body.ldn.has_action_frame = 0;
    // V-239 measured: a real MHGU hub advertises node_count_max=4 (its hall
    // capacity), while the frozen LDN max is 8.  Games may reject or mis-render
    // a hub whose capacity exceeds their own; present the measured value.
    body.ldn.node_count_max = 4;
    body.ldn.node_count = static_cast<std::uint8_t>(1 + stations.size() + local_citra_peers.size());
    // V-239: a real MHGU hub host carries a non-empty hunter name on node 0
    // (measured 'Xiaoyi'); an all-zero name is another visible difference.
    {
        const std::string host_name = "Alice";
        for (std::size_t i = 0; i < host_name.size() && i < body.ldn.nodes[0].user_name.size() - 1; ++i) {
            body.ldn.nodes[0].user_name[i] = static_cast<std::uint8_t>(host_name[i]);
        }
    }
    // V-239: advertise data up to the frozen 384-byte bound; oversize input is
    // truncated at the CLI layer, never silently here.  V-267: the value now comes
    // from advertise_data(), whose precedence is Citra live appdata >
    // --ldn-advertise-hex template > empty (each counted), so the Yuzu list shows
    // the MHXX hall name while the Citra peer is beaconing.  Size 0 when empty,
    // exactly as before.
    {
        const std::vector<std::uint8_t> advertised = advertise_data();
        const std::size_t n = std::min(advertised.size(),
                                       citra_control::kLdnAdvertiseDataSizeMax);
        body.ldn.advertise_data_size = static_cast<std::uint16_t>(n);
        std::copy_n(advertised.begin(), n, body.ldn.advertise_data.begin());
    }
    body.ldn.random_authentication_id = 0;

    citra_control::LdnNodeInfo& host = body.ldn.nodes[0];
    host.ipv4_address = reverse_ip(session_fake_ip);
    host.mac_address = bssid;
    host.node_id = 0;
    host.is_connected = static_cast<std::uint8_t>(citra_control::NodeStatus::Connected);
    host.local_communication_version = kControlVersion;

    for (std::size_t i = 0; i < stations.size(); ++i) {
        // Native LANDiscovery binds station N to nodes[N]. Removing another
        // station must leave a hole rather than compacting this node's slot.
        citra_control::LdnNodeInfo& node = body.ldn.nodes[stations[i].node_id];
        node.ipv4_address = stations[i].have_declared_ipv4 ? stations[i].declared_ipv4
                                                          : reverse_ip(stations[i].fake_ip);
        node.mac_address = stations[i].mac;
        node.node_id = stations[i].node_id;
        node.is_connected = static_cast<std::uint8_t>(citra_control::NodeStatus::Connected);
        node.user_name = stations[i].user_name;
        node.local_communication_version = stations[i].local_communication_version;
    }
    for (const auto& [mac, local] : local_citra_peers) {
        const auto slot = static_cast<std::size_t>(local.assigned_node_id - 1);
        if (slot < 1 || slot >= body.ldn.node_count_max) continue;
        auto& node = body.ldn.nodes[slot];
        node.ipv4_address = reverse_ip(local.ip);
        node.mac_address = mac;
        node.node_id = static_cast<std::int8_t>(slot);
        node.is_connected = static_cast<std::uint8_t>(citra_control::NodeStatus::Connected);
        const auto name = citra_control::username_to_bytes(local.node.username);
        if (name.ok()) node.user_name = name.value;
        node.local_communication_version = kControlVersion;
    }
    return body;
}

std::int8_t ControlBridge::Impl::allocate_node_id() const {
    const auto limit = local_citra_peers.empty() ? kControlMaxStations : std::size_t{3};
    for (std::int8_t candidate = 1; candidate <= static_cast<std::int8_t>(limit); ++candidate) {
        bool used = false;
        for (const ControlStation& station : stations) {
            if (station.node_id == candidate) {
                used = true;
                break;
            }
        }
        for (const auto& [mac, local] : local_citra_peers) {
            (void)mac;
            used |= local.assigned_node_id - 1 == candidate;
        }
        if (!used) {
            return candidate;
        }
    }
    return 0;
}

void ControlBridge::Impl::add_station(const citra_room::MacAddress& mac,
                                     const room_client::IPv4& ip,
                                     const std::array<std::uint8_t, 4>& declared_ipv4,
                                     bool have_declared_ipv4,
                                     const citra_control::UserNameBytes& user_name,
                                     const citra_control::Username& uds_username, std::int16_t version) {
    ControlStation station;
    station.mac = mac;
    station.fake_ip = ip;
    station.declared_ipv4 = declared_ipv4;
    station.have_declared_ipv4 = have_declared_ipv4;
    station.node_id = allocate_node_id();
    station.user_name = user_name;
    station.uds_username = uds_username;
    station.local_communication_version = version;
    (void)citra_control::friend_code_from_ldn(&diag);
    stations.push_back(station);
}

bool ControlBridge::Impl::remove_station(const room_client::IPv4& ip) {
    for (auto it = stations.begin(); it != stations.end(); ++it) {
        if (it->fake_ip == ip) {
            forget_return_peer(ip);
            stations.erase(it);
            for (auto peer = citra_host_peers.begin(); peer != citra_host_peers.end();) {
                if (peer->first.second == ip) peer = citra_host_peers.erase(peer);
                else ++peer;
            }
            return true;
        }
    }
    return false;
}

std::vector<std::uint8_t> ControlBridge::Impl::node_map_bytes() {
    std::vector<citra_control::NodeMapEntry> entries;
    citra_control::NodeMapEntry self;
    self.mac = session_mac;
    // D3/N5: the peer always appears as the reserved id 2.
    self.node_id = kControlCitraPeerNodeId;
    entries.push_back(self);
    for (const ControlStation& station : stations) {
        citra_control::NodeMapEntry entry;
        entry.mac = station.mac;
        entry.node_id = station_uds_node_id(station.node_id);
        entries.push_back(entry);
    }
    const auto built = citra_control::build_node_map(entries, &diag);
    if (!built.ok()) {
        ++counters["emit_failed"];
        return {};
    }
    ++counters["synthesized_node_map"];
    ++counters["invented_fields"];
    return built.value;
}

std::vector<std::uint8_t> ControlBridge::Impl::logoff_bytes() {
    citra_control::EapolLogoffPacket packet;
    // D3/N4: the assigned id is this bridge's peer id, never the id the client
    // declared in its Start (a real client declares an uninitialised 0 -- spec
    // section 0.1).  client_mac_address stays all zero: Citra's own Logoff
    // generator never writes it either (spec section 0.2).
    packet.assigned_node_id = kControlCitraPeerNodeId;
    // G3: the Logoff advertisement shares the Beacon's connected/capacity
    // calculation (it used to advertise the hardcoded kUdsMaxNodes = 16) and
    // its id -> record placement rule.
    const ControlBeaconShape shape = control_beacon_shape(citra_node_joined, stations);
    packet.connected_nodes = static_cast<std::uint8_t>(shape.connected);
    packet.max_nodes = static_cast<std::uint8_t>(shape.capacity);
    // D3/N4: record i belongs to UDS id i + 1; a slot with no member stays an
    // empty record (id 0, zero seed/username).
    for (std::size_t i = 0; i < shape.capacity; ++i) {
        const ControlUdsRecord record =
            control_uds_record(static_cast<std::uint16_t>(i + 1), citra_node_joined, citra_node_info, stations,
                               opt.have_uds_host_seed ? opt.uds_host_seed : 0,
                               opt.have_uds_host_username ? opt.uds_host_username : citra_control::Username{});
        if (record.present) {
            packet.nodes[i].network_node_id = static_cast<std::uint16_t>(i + 1);
            packet.nodes[i].friend_code_seed = record.friend_code_seed;
            packet.nodes[i].username = record.username;
        }
    }
    const auto built = citra_control::build_eapol_logoff_frame(packet, &diag);
    if (!built.ok()) {
        ++counters["emit_failed"];
        return {};
    }
    ++counters["synthesized_logoff"];
    ++counters["invented_fields"];
    return built.value;
}

// V-111 (docs/G4-UDS-BEACON-PROFILE-SPEC.md): the frozen citra-control Beacon
// encoder writes two zero bytes straight after max_nodes -- wire
// NetworkInfo[0x1E..0x1F], mirrors.hpp NetworkInfoTag -- and exposes no field
// that can set them.  A real MHXX host advertises 0x0001 there, so the gateway
// patches the finished frame and recomputes the tag SHA-1, which covers those
// two bytes (citra-master .../uds_beacon.cpp GenerateNintendoNetworkInfoTag).
// Payload-relative offsets, measured against the real 371/451 byte host beacons
// in .verify-v111: [31] 0xDD NetworkInfo tag id, [32] tag length 52 + appdata
// size, [33..63] tag body (wire NetworkInfo 0x0C..0x2A), [51..52] the two bytes
// to patch, [64..83] SHA-1 (wire 0x2B), [84] appdata size, [85..] appdata.
bool patch_beacon_tag_word(std::vector<std::uint8_t>& frame, std::uint16_t word) {
    constexpr std::size_t tag = 31;
    constexpr std::size_t nib_size = 0x1F;
    constexpr std::size_t sha_size = 0x14;
    const std::size_t appdata_size_offset = tag + 2 + nib_size + sha_size;
    if (frame.size() < appdata_size_offset + 1) {
        return false;
    }
    if (frame[tag] != 0xDD) {
        return false;
    }
    const std::size_t appdata_size = frame[appdata_size_offset];
    if (appdata_size > citra_control::kApplicationDataSize) {
        return false;
    }
    if (frame[tag + 1] != static_cast<std::uint8_t>(52 + appdata_size)) {
        return false;
    }
    if (frame.size() < appdata_size_offset + 1 + appdata_size) {
        return false;
    }
    frame[tag + 2 + 0x12] = static_cast<std::uint8_t>(word >> 8);
    frame[tag + 2 + 0x13] = static_cast<std::uint8_t>(word & 0xFF);
    std::vector<std::uint8_t> body;
    body.reserve(nib_size + sha_size + 1 + appdata_size);
    body.insert(body.end(), frame.begin() + static_cast<std::ptrdiff_t>(tag + 2),
                frame.begin() + static_cast<std::ptrdiff_t>(tag + 2 + nib_size));
    body.insert(body.end(), sha_size, 0);
    body.push_back(static_cast<std::uint8_t>(appdata_size));
    body.insert(body.end(), frame.begin() + static_cast<std::ptrdiff_t>(appdata_size_offset + 1),
                frame.begin() + static_cast<std::ptrdiff_t>(appdata_size_offset + 1 + appdata_size));
    const citra_control::Sha1Digest digest = citra_control::sha1(body);
    // The hash field starts right after the nib (the encoder's own layout), NOT
    // after the hash: writing it at tag + 2 + nib_size + sha_size would overwrite
    // the appdata_size byte and the first 19 appdata bytes.
    std::copy(digest.begin(), digest.end(),
              frame.begin() + static_cast<std::ptrdiff_t>(tag + 2 + nib_size));
    return true;
}

std::vector<ControlEmission> ControlBridge::Impl::gu_host_depart(bool notify_host) {
    gu_native_peers.clear();
    gu_native_reverse_codecs.clear(); gu_native_forward_codecs.clear();

    std::vector<ControlEmission> out;
    if (!gu_admission) return out;
    if (notify_host && gu_admission->state != GuAdmission::State::AwaitStart) {
        const auto body = citra_control::serialize_ldn_node_info(gu_admission->node, &diag);
        if (body.ok()) {
            ControlEmission disconnect;
            disconnect.kind = "room.gu_host.disconnect";
            disconnect.ldn_type = room_client::LdnType::Disconnect;
            disconnect.ldn_remote_ip = gu_admission->hall.source;
            disconnect.ldn_body = body.value;
            out.push_back(std::move(disconnect));
        }
    }
    ControlEmission deauth;
    deauth.to_citra = true;
    deauth.kind = "citra.gu_host.deauthentication";
    deauth.citra_type = citra_room::FrameType::Deauthentication;
    deauth.have_citra_addresses = true;
    deauth.citra_transmitter = gu_admission->hall.network.common.bssid;
    deauth.citra_destination = gu_admission->guest;
    out.push_back(std::move(deauth));
    gu_admission.reset();
    ++counters["gu_host_departure"];
    return out;
}

std::vector<ControlEmission> ControlBridge::Impl::gu_host_wifi(
    const citra_room::WifiPacket& wifi) {
    std::vector<ControlEmission> out;
    if (!opt.ldn_gu_host_admission || wifi.transmitter != session_mac) return out;
    if (wifi.type == citra_room::FrameType::Authentication) {
        const auto parsed = citra_control::parse_authentication_frame(
            wifi.data.data(), wifi.data.size(), &diag);
        const auto hall = gu_host_halls.find(wifi.destination);
        if (!parsed.ok() || parsed.value.auth_seq != citra_control::AuthenticationSeq::Seq1 ||
            hall == gu_host_halls.end() ||
            clock_ms - hall->second.received_ms > kCitraAppdataMaxAgeMs || gu_admission ||
            hall->second.network.ldn.node_count >= hall->second.network.ldn.node_count_max) {
            ++counters["gu_host_auth_rejected"];
            return out;
        }
        citra_control::AuthenticationFrame reply;
        reply.auth_seq = citra_control::AuthenticationSeq::Seq2;
        const auto auth = citra_control::build_authentication_frame(reply, &diag);
        citra_control::AssociationResponse association;
        association.capabilities = citra_control::kDefaultExtraCapabilities;
        association.association_id = 1;
        association.network_id = opt.uds_network_id;
        const auto assoc = citra_control::build_association_response_frame(association, &diag);
        if (!auth.ok() || !assoc.ok()) return out;
        GuAdmission pending;
        pending.hall = hall->second;
        pending.guest = wifi.transmitter;
        pending.started_ms = clock_ms;
        gu_admission = pending;
        for (const bool is_auth : {true, false}) {
            ControlEmission emission;
            emission.to_citra = true;
            emission.kind = is_auth ? "citra.gu_host.auth_seq2" : "citra.gu_host.association";
            emission.citra_type = is_auth ? citra_room::FrameType::Authentication
                                        : citra_room::FrameType::AssociationResponse;
            emission.have_citra_addresses = true;
            emission.citra_transmitter = wifi.destination;
            emission.citra_destination = wifi.transmitter;
            emission.citra_data = is_auth ? auth.value : assoc.value;
            out.push_back(std::move(emission));
        }
        ++counters["gu_host_auth_accepted"];
        return out;
    }
    if (!gu_admission || wifi.destination != gu_admission->hall.network.common.bssid) return out;
    if (wifi.type == citra_room::FrameType::Deauthentication && wifi.data.empty()) {
        return gu_host_depart(true);
    }
    if (wifi.type != citra_room::FrameType::Data ||
        gu_admission->state != GuAdmission::State::AwaitStart) return out;
    const auto start = citra_control::parse_eapol_start_frame(
        wifi.data.data(), wifi.data.size(), &diag);
    if (!start.ok() || start.value.association_id != 1) return out;
    const auto name = citra_control::username_to_bytes(start.value.node.username, &diag);
    if (!name.ok()) return out;
    citra_control::LdnNodeInfo node;
    node.ipv4_address = reverse_ip(session_fake_ip);
    node.mac_address = wifi.transmitter;
    node.is_connected = 1;
    node.user_name = name.value;
    node.local_communication_version =
        gu_admission->hall.network.ldn.nodes[0].local_communication_version;
    const auto body = citra_control::serialize_ldn_node_info(node, &diag);
    if (!body.ok()) return out;
    gu_admission->identity = start.value.node;
    gu_admission->node = node;
    gu_admission->state = GuAdmission::State::AwaitSync;
    gu_admission->started_ms = clock_ms;
    ControlEmission connect;
    connect.kind = "room.gu_host.connect";
    connect.ldn_type = room_client::LdnType::Connect;
    connect.ldn_remote_ip = gu_admission->hall.source;
    connect.ldn_body = body.value;
    out.push_back(std::move(connect));
    ++counters["gu_host_connect_emitted"];
    return out;
}

std::vector<ControlEmission> ControlBridge::Impl::gu_host_tick() {
    std::vector<ControlEmission> out;
    if (gu_admission && gu_admission->state != GuAdmission::State::Connected &&
        clock_ms - gu_admission->started_ms > 5000) {
        out = gu_host_depart(true);
        ++counters["gu_host_admission_timeout"];
    }
    if (gu_admission && gu_admission->state == GuAdmission::State::Connected &&
        clock_ms - gu_admission->hall.received_ms > 5000) {
        out = gu_host_depart(true);
        ++counters["gu_host_connection_timeout"];
    }
    if (!gu_scan_started || clock_ms - gu_last_scan_ms >= 1000) {
        gu_scan_started = true;
        gu_last_scan_ms = clock_ms;
        ControlEmission scan;
        scan.kind = "room.gu_host.scan";
        scan.ldn_type = room_client::LdnType::Scan;
        scan.ldn_broadcast = true;
        out.push_back(std::move(scan));
        ++counters["gu_host_scan_emitted"];
    }
    for (auto it = gu_host_halls.begin(); it != gu_host_halls.end();) {
        if (clock_ms - it->second.received_ms > kCitraAppdataMaxAgeMs) {
            it = gu_host_halls.erase(it);
            ++counters["gu_host_hall_expired"];
        } else {
            ++it;
        }
    }
    if (clock_ms - gu_last_beacon_ms >= opt.beacon_interval_ms) {
        gu_last_beacon_ms = clock_ms;
        for (const auto& [mac, hall] : gu_host_halls) {
            (void)mac;
            out.push_back(hall.beacon);
            ++counters["gu_host_beacon_emitted"];
        }
    }
    return out;
}

LdnHandling ControlBridge::Impl::gu_host_sync(const room_client::LdnPacket& packet) {
    LdnHandling handling;
    handling.type = packet.type;
    if (!opt.ldn_gu_host_admission || !gu_admission || packet.broadcast ||
        packet.remote_ip != session_fake_ip || packet.local_ip != gu_admission->hall.source ||
        gu_admission->state == GuAdmission::State::AwaitStart) return handling;
    const auto parsed = citra_control::parse_ldn_network_info(
        packet.data.data(), packet.data.size(), &diag);
    if (!parsed.ok()) return handling;
    const auto& network = parsed.value;
    const auto& selected = gu_admission->hall.network;
    if (network.common.bssid != selected.common.bssid ||
        network.network_id.intent_id.local_communication_id != opt.ldn_comm_id_override ||
        network.network_id.intent_id.scene_id != opt.scene_id ||
        network.network_id.session_id.high != selected.network_id.session_id.high ||
        network.network_id.session_id.low != selected.network_id.session_id.low ||
        network.common.network_type != 2 || network.ldn.node_count_max != selected.ldn.node_count_max ||
        network.ldn.node_count < 1 || network.ldn.node_count > network.ldn.node_count_max ||
        !network.ldn.nodes[0].is_connected ||
        network.ldn.nodes[0].mac_address != selected.common.bssid) return handling;
    citra_control::EapolLogoffPacket logoff;
    logoff.connected_nodes = network.ldn.node_count;
    logoff.max_nodes = network.ldn.node_count_max;
    std::vector<citra_control::NodeMapEntry> entries;
    std::size_t guests = 0;
    std::map<citra_room::MacAddress, GuHostGuestIdentity> natives;
    for (std::size_t i = 0; i < network.ldn.node_count_max; ++i) {
        const auto& node = network.ldn.nodes[i];
        if (!node.is_connected) continue;
        if (node.node_id != static_cast<int>(i) || !mac_is_usable(node.mac_address) ||
            std::any_of(entries.begin(), entries.end(), [&](const auto& entry) {
                return entry.mac == node.mac_address;
            })) return handling;
        const auto name = citra_control::username_from_bytes(node.user_name, &diag);
        if (!name.ok()) return handling;
        const auto id = static_cast<std::uint16_t>(i + 1);
        logoff.nodes[i].network_node_id = id;
        logoff.nodes[i].username = name.value;
        const auto known = gu_guest_identities.find(node.mac_address);
        if (i != 0 && known != gu_guest_identities.end()) {
            const auto peer_name = citra_control::username_to_bytes(known->second.node.username);
            if (reverse_ip(known->second.guest_ip) != node.ipv4_address ||
                !peer_name.ok() || peer_name.value != node.user_name) return handling;
            logoff.nodes[i] = known->second.node;
            logoff.nodes[i].network_node_id = id;
        }
        if (i == 0 && opt.have_uds_host_seed) logoff.nodes[i].friend_code_seed = opt.uds_host_seed;
        if (node.mac_address == gu_admission->guest) {
            if (i == 0 || node.ipv4_address != gu_admission->node.ipv4_address ||
                node.user_name != gu_admission->node.user_name) return handling;
            ++guests;
            logoff.assigned_node_id = id;
            logoff.nodes[i] = gu_admission->identity;
            logoff.nodes[i].network_node_id = id;
        }
        const auto ip = reverse_ip(node.ipv4_address);
        if (i && node.mac_address != gu_admission->guest &&
            known == gu_guest_identities.end() &&
            std::find(gu_native_members.begin(), gu_native_members.end(), ip) != gu_native_members.end()) {
            GuHostGuestIdentity peer;
            peer.host_ip = packet.local_ip; peer.guest_ip = ip; peer.mac = node.mac_address;
            peer.session_high = network.network_id.session_id.high;
            peer.session_low = network.network_id.session_id.low;
            peer.node.username = name.value;
            peer.node.friend_code_seed = native_gu_seed(ip);
            peer.node.network_node_id = id;
            const auto old = gu_native_peers.find(peer.mac);
            if (old != gu_native_peers.end() && old->second.guest_ip == ip &&
                old->second.node.username == peer.node.username) {
                peer.have_descriptor = old->second.have_descriptor;
                peer.descriptor = old->second.descriptor;
            }
            natives.emplace(peer.mac, peer);
            logoff.nodes[i] = peer.node;
        }
        entries.push_back({node.mac_address, id});
    }
    if (entries.size() != network.ldn.node_count) return handling;
    if (guests == 0 && gu_admission->state == GuAdmission::State::Connected) {
        handling.emissions = gu_host_depart(false);
        handling.accepted = true;
        return handling;
    }
    if (guests != 1) return handling;
    const auto map = citra_control::build_node_map(entries, &diag);
    const auto frame = citra_control::build_eapol_logoff_frame(logoff, &diag);
    if (!map.ok() || !frame.ok()) return handling;
    for (const bool is_map : {true, false}) {
        ControlEmission emission;
        emission.to_citra = true;
        emission.kind = is_map ? "citra.gu_host.node_map" : "citra.gu_host.logoff";
        emission.citra_type = is_map ? citra_room::FrameType::NodeMap : citra_room::FrameType::Data;
        emission.have_citra_addresses = true;
        emission.citra_transmitter = selected.common.bssid;
        emission.citra_destination = gu_admission->guest;
        emission.citra_data = is_map ? map.value : frame.value;
        handling.emissions.push_back(std::move(emission));
    }
    for (const auto& [mac, peer] : gu_native_peers) {
        const auto retained = natives.find(mac);
        if (retained == natives.end() || retained->second.guest_ip != peer.guest_ip ||
            retained->second.node.username != peer.node.username) {
            gu_native_reverse_codecs.erase(peer.guest_ip);
            gu_native_forward_codecs.erase(peer.guest_ip);
        }
    }
    gu_native_peers = std::move(natives);
    gu_admission->hall.network = network;
    gu_admission->hall.received_ms = clock_ms;
    gu_admission->state = GuAdmission::State::Connected;
    handling.accepted = true;
    ++counters["gu_host_sync_accepted"];
    return handling;
}

LdnHandling ControlBridge::Impl::gu_host_response(const room_client::LdnPacket& packet) {
    if (packet.type == room_client::LdnType::SyncNetwork) return gu_host_sync(packet);
    LdnHandling handling;
    handling.type = packet.type;
    const auto reject = [&]() {
        ++counters["gu_host_hall_rejected"];
        return handling;
    };
    if (packet.type == room_client::LdnType::DestroyNetwork) {
        if ((!packet.broadcast && packet.remote_ip != session_fake_ip) || !packet.data.empty()) {
            return reject();
        }
        if (gu_admission && gu_admission->hall.source == packet.local_ip) {
            handling.emissions = gu_host_depart(false);
        }
        for (auto it = gu_host_halls.begin(); it != gu_host_halls.end();) {
            if (it->second.source == packet.local_ip) it = gu_host_halls.erase(it);
            else ++it;
        }
        handling.accepted = true;
        return handling;
    }
    if (packet.type != room_client::LdnType::ScanResponse || packet.broadcast ||
        packet.remote_ip != session_fake_ip || ip_is_zero(packet.local_ip) ||
        packet.local_ip == session_fake_ip || !gu_scan_started ||
        clock_ms - gu_last_scan_ms > 1000 || !opt.have_uds_wlan_comm_id) {
        return reject();
    }
    const auto parsed = citra_control::parse_ldn_network_info(
        packet.data.data(), packet.data.size(), &diag);
    if (!parsed.ok()) return reject();
    const auto& network = parsed.value;
    if (network.network_id.intent_id.local_communication_id != opt.ldn_comm_id_override ||
        network.network_id.intent_id.scene_id != opt.scene_id ||
        network.common.network_type != 2 || !mac_is_usable(network.common.bssid) ||
        network.ldn.node_count == 0 || network.ldn.node_count > 4 ||
        network.ldn.node_count_max < 2 || network.ldn.node_count_max > 4 ||
        network.ldn.node_count > network.ldn.node_count_max ||
        network.ldn.advertise_data_size != 200 ||
        !network.ldn.nodes[0].is_connected ||
        network.ldn.nodes[0].mac_address != network.common.bssid) {
        return reject();
    }
    if (opt.ldn_gu_host_admission && !gu_admission) {
        for (std::size_t i = 1; i < network.ldn.node_count_max; ++i) {
            const auto& node = network.ldn.nodes[i];
            if (!node.is_connected || node.mac_address != session_mac ||
                node.ipv4_address != reverse_ip(session_fake_ip)) continue;
            // GU Connect inserts without deduplication. A prior bridge session
            // can leave this exact local identity behind. Let the native host
            // remove it, then wait for a fresh clean ScanResponse before listing
            // the hall or admitting another Connect. Never subtract GUI counts.
            const auto body = citra_control::serialize_ldn_node_info(node, &diag);
            if (!body.ok()) return reject();
            gu_host_halls.erase(network.common.bssid);
            ControlEmission cleanup;
            cleanup.kind = "room.gu_host.stale_self_disconnect";
            cleanup.ldn_type = room_client::LdnType::Disconnect;
            cleanup.ldn_remote_ip = packet.local_ip;
            cleanup.ldn_body = body.value;
            handling.emissions.push_back(std::move(cleanup));
            handling.accepted = true;
            ++counters["gu_host_stale_self_cleanup"];
            return handling;
        }
    }
    const auto xx = convert_gu_hall_advertise(citra_room::Bytes(
        network.ldn.advertise_data.begin(), network.ldn.advertise_data.begin() + 200));
    if (!xx) return reject();
    if (!gu_host_halls.contains(network.common.bssid) && gu_host_halls.size() >= 8) return reject();
    citra_control::BeaconParams params;
    params.source_mac = network.common.bssid;
    params.network_info.host_mac_address = params.source_mac;
    params.network_info.channel = static_cast<std::uint8_t>(opt.channel);
    params.network_info.initialized = kControlInitialized;
    params.network_info.wlan_comm_id = opt.uds_wlan_comm_id;
    params.network_info.id = opt.uds_beacon_id;
    params.network_info.attributes = opt.uds_attributes;
    params.network_info.network_id = opt.uds_network_id;
    params.network_info.total_nodes = network.ldn.node_count;
    params.network_info.max_nodes = network.ldn.node_count_max;
    params.appdata_size = 200;
    std::copy(xx->begin(), xx->end(), params.appdata.begin());
    for (std::size_t i = 0; i < network.ldn.node_count_max; ++i) {
        citra_control::BeaconNodeInfo node;
        if (network.ldn.nodes[i].is_connected) {
            const auto name = citra_control::username_from_bytes(network.ldn.nodes[i].user_name, &diag);
            if (!name.ok()) return reject();
            node.network_node_id = static_cast<std::uint16_t>(i + 1);
            node.username = name.value;
            node.friend_code_seed = i == 0 && opt.have_uds_host_seed ? opt.uds_host_seed : 0;
            const auto peer = gu_guest_identities.find(network.ldn.nodes[i].mac_address);
            if (i && peer != gu_guest_identities.end()) node.friend_code_seed = peer->second.node.friend_code_seed;
            else if (i) {
                const auto ip = reverse_ip(network.ldn.nodes[i].ipv4_address);
                if (std::find(gu_native_members.begin(), gu_native_members.end(), ip) != gu_native_members.end())
                    node.friend_code_seed = native_gu_seed(ip);
            }
            params.bitmask |= static_cast<std::uint16_t>(1u << i);
        }
        params.nodes.push_back(node);
    }
    const auto built = citra_control::build_beacon_frame(params, &diag);
    if (!built.ok()) return reject();
    ControlEmission beacon;
    beacon.to_citra = true;
    beacon.kind = "citra.gu_host.beacon";
    beacon.citra_type = citra_room::FrameType::Beacon;
    beacon.have_citra_addresses = true;
    beacon.citra_transmitter = params.source_mac;
    beacon.citra_destination = citra_room::broadcast_mac;
    beacon.citra_data = built.value;
    if (opt.have_uds_tag_word && !patch_beacon_tag_word(beacon.citra_data, opt.uds_tag_word)) {
        return reject();
    }
    gu_host_halls[network.common.bssid] = GuHostHall{packet.local_ip, clock_ms, beacon, network};
    if (gu_admission && gu_admission->hall.source == packet.local_ip &&
        gu_admission->hall.network.common.bssid == network.common.bssid &&
        gu_admission->hall.network.network_id.session_id.high == network.network_id.session_id.high &&
        gu_admission->hall.network.network_id.session_id.low == network.network_id.session_id.low) {
        gu_admission->hall.received_ms = clock_ms;
    }
    handling.accepted = true;
    handling.emissions.push_back(std::move(beacon));
    ++counters["gu_host_hall_accepted"];
    ++counters["gu_host_beacon_emitted"];
    return handling;
}

ControlEmission ControlBridge::Impl::beacon_emission() {
    citra_control::BeaconParams params;
    params.header = citra_control::BeaconFrameHeader{};
    params.network_info.host_mac_address = bssid;
    params.network_info.channel = static_cast<std::uint8_t>(opt.channel);
    params.network_info.initialized = kControlInitialized;
    // V-111: the opt-in UDS profile replaces the derived identity with what a
    // real MHXX host advertises; unset flags keep the previous values.
    params.network_info.wlan_comm_id =
        opt.have_uds_wlan_comm_id ? opt.uds_wlan_comm_id : wlan_comm_id;
    params.network_info.id = opt.have_uds_beacon_id ? opt.uds_beacon_id : kControlBeaconId;
    params.network_info.attributes = opt.have_uds_attributes ? opt.uds_attributes : 0;
    params.network_info.network_id = opt.have_uds_network_id ? opt.uds_network_id : network_id;
    const ControlBeaconShape shape = control_beacon_shape(citra_node_joined, stations);
    params.network_info.total_nodes = static_cast<std::uint8_t>(shape.connected);
    params.network_info.max_nodes = static_cast<std::uint8_t>(shape.capacity);
    params.appdata_size = opt.have_uds_appdata ? opt.uds_appdata.size() : 0;
    if (opt.have_uds_appdata) {
        std::copy(opt.uds_appdata.begin(), opt.uds_appdata.end(), params.appdata.begin());
    }
    params.bitmask = 0;
    params.source_mac = bssid;
    // D3/N3 + G2: record i belongs to UDS id i + 1 (host 1, peer 2, station
    // slot k at k + 2); a slot with no member stays an empty record.  Transmit
    // exactly `capacity` records -- build_beacon_frame R6 rejects a record
    // count that differs from max_nodes.
    for (std::size_t i = 0; i < shape.capacity; ++i) {
        citra_control::BeaconNodeInfo node;
        const ControlUdsRecord record =
            control_uds_record(static_cast<std::uint16_t>(i + 1), citra_node_joined, citra_node_info, stations,
                               opt.have_uds_host_seed ? opt.uds_host_seed : 0,
                               opt.have_uds_host_username ? opt.uds_host_username : citra_control::Username{});
        if (record.present) {
            node.network_node_id = static_cast<std::uint16_t>(i + 1);
            node.friend_code_seed = record.friend_code_seed;
            node.username = record.username;
        }
        params.nodes.push_back(node);
    }

    ControlEmission emission;
    emission.to_citra = true;
    emission.kind = "citra.beacon";
    emission.citra_type = citra_room::FrameType::Beacon;
    emission.citra_broadcast = true;
    const auto frame = citra_control::build_beacon_frame(params, &diag);
    if (!frame.ok()) {
        ++counters["emit_failed"];
        return emission;
    }
    emission.citra_data = frame.value;
    if (opt.have_uds_tag_word && !patch_beacon_tag_word(emission.citra_data, opt.uds_tag_word)) {
        // Fail closed: an unpatched frame still carries the encoder's SHA-1,
        // which does not cover the word the guest reads.
        emission.citra_data.clear();
        ++counters["emit_failed"];
        ++counters["beacon_tag_word_patch_failed"];
        return emission;
    }
    if (opt.have_uds_tag_word) {
        ++counters["beacon_tag_word_patched"];
    }
    ++counters["beacon_emitted"];
    ++counters["synthesized_beacon"];
    ++counters["invented_fields"];
    ++beacons;
    return emission;
}

ControlEmission ControlBridge::Impl::sync_emission(const room_client::IPv4& ip) {
    ControlEmission emission;
    emission.to_citra = false;
    emission.kind = "room.sync_network";
    emission.ldn_type = room_client::LdnType::SyncNetwork;
    emission.ldn_remote_ip = ip;
    emission.ldn_broadcast = false;
    citra_control::LdnNodeInfo node;
    const auto body = citra_control::serialize_ldn_body(citra_control::LdnPacketType::SyncNetwork, node,
                                                        make_network_info(), &diag);
    if (!body.ok()) {
        ++counters["emit_failed"];
        return emission;
    }
    emission.ldn_body = body.value;
    ++counters["sync_network_emitted"];
    ++counters["synthesized_network_info"];
    counters["invented_fields"] += 3;
    counters["undefined_fields"] += 3;
    return emission;
}

ControlEmission ControlBridge::Impl::scan_resp_emission(const room_client::IPv4& ip) {
    ControlEmission emission;
    emission.to_citra = false;
    emission.kind = "room.scan_resp";
    emission.ldn_type = room_client::LdnType::ScanResponse;
    emission.ldn_remote_ip = ip;
    emission.ldn_broadcast = false;
    citra_control::LdnNodeInfo node;
    const auto body = citra_control::serialize_ldn_body(citra_control::LdnPacketType::ScanResp, node,
                                                        make_network_info(), &diag);
    if (!body.ok()) {
        ++counters["emit_failed"];
        return emission;
    }
    emission.ldn_body = body.value;
    ++counters["scan_resp_emitted"];
    ++counters["synthesized_network_info"];
    counters["invented_fields"] += 3;
    counters["undefined_fields"] += 3;
    return emission;
}

ControlEmission ControlBridge::Impl::citra_intent_emission(const citra_control::CitraFrameIntent& intent) {
    ControlEmission emission;
    emission.to_citra = true;
    emission.citra_broadcast = intent.broadcast;
    switch (intent.kind) {
    case citra_control::CitraFrameKind::AuthSeq2: {
        citra_control::AuthenticationFrame frame;
        frame.auth_algorithm = citra_control::AuthAlgorithm::OpenSystem;
        frame.auth_seq = citra_control::AuthenticationSeq::Seq2;
        frame.status_code = citra_control::AuthStatus::Successful;
        const auto built = citra_control::build_authentication_frame(frame, &diag);
        emission.kind = "citra.auth_seq2";
        emission.citra_type = citra_room::FrameType::Authentication;
        if (built.ok()) {
            emission.citra_data = built.value;
            ++counters["auth_seq2_emitted"];
        } else {
            ++counters["emit_failed"];
        }
        break;
    }
    case citra_control::CitraFrameKind::AssocResponse: {
        citra_control::AssociationResponse frame;
        frame.capabilities = citra_control::kDefaultExtraCapabilities;
        frame.status_code = citra_control::AssocStatus::Successful;
        frame.association_id = kControlAssociationId;
        // The SSID tag carries the network id, so it must be the id the Beacon
        // advertizes, not the derived one (gc7: a real MHXX host sends ASCII
        // "00000000" here because its beacon says network_id 0, while an
        // unprofiled room keeps the derived value).
        frame.network_id = opt.have_uds_network_id ? opt.uds_network_id : network_id;
        const auto built = citra_control::build_association_response_frame(frame, &diag);
        emission.kind = "citra.assoc_response";
        emission.citra_type = citra_room::FrameType::AssociationResponse;
        if (built.ok()) {
            emission.citra_data = built.value;
            ++counters["assoc_response_emitted"];
        } else {
            ++counters["emit_failed"];
        }
        break;
    }
    case citra_control::CitraFrameKind::NodeMap: {
        emission.kind = "citra.node_map";
        emission.citra_type = citra_room::FrameType::NodeMap;
        emission.citra_data = node_map_bytes();
        ++counters["node_map_emitted"];
        break;
    }
    case citra_control::CitraFrameKind::Logoff: {
        emission.kind = "citra.eapol_logoff";
        emission.citra_type = citra_room::FrameType::Data;
        emission.citra_data = logoff_bytes();
        ++counters["logoff_frame_emitted"];
        break;
    }
    }
    return emission;
}

ControlEmission ControlBridge::Impl::ldn_intent_emission(const citra_control::LdnIntent& intent) {
    ControlEmission emission;
    emission.to_citra = false;
    emission.ldn_type = static_cast<room_client::LdnType>(static_cast<std::uint8_t>(intent.type));
    emission.ldn_remote_ip = intent.remote_ip;
    emission.ldn_broadcast = intent.broadcast;
    citra_control::LdnNodeInfo node;
    const auto body =
        citra_control::serialize_ldn_body(intent.type, node, make_network_info(), &diag);
    if (!body.ok()) {
        ++counters["emit_failed"];
        return emission;
    }
    emission.ldn_body = body.value;
    if (intent.type == citra_control::LdnPacketType::ScanResp) {
        emission.kind = "room.scan_resp";
        ++counters["scan_resp_emitted"];
    } else if (intent.type == citra_control::LdnPacketType::SyncNetwork) {
        emission.kind = "room.sync_network";
        ++counters["sync_network_emitted"];
    } else {
        emission.kind = "room.unsupported";
        ++counters["emit_failed"];
    }
    ++counters["synthesized_network_info"];
    counters["invented_fields"] += 3;
    counters["undefined_fields"] += 3;
    return emission;
}

void ControlBridge::Impl::note_data_frame(const char* verdict, const citra_room::Bytes& data,
                                         int base) {
    auto& bucket = data_samples[verdict];
    if (bucket.size() >= 4) {
        return;
    }
    DataFrameSample sample;
    sample.verdict = verdict;
    sample.bytes = data.size();
    sample.base = base;
    const std::size_t shown = std::min<std::size_t>(48, data.size());
    static const char* digits = "0123456789abcdef";
    sample.head_hex.reserve(shown * 2);
    for (std::size_t i = 0; i < shown; ++i) {
        sample.head_hex.push_back(digits[data[i] >> 4]);
        sample.head_hex.push_back(digits[data[i] & 0x0f]);
    }
    bucket.push_back(std::move(sample));
}

std::size_t ControlBridge::Impl::host_magic_base(const citra_room::Bytes& src) const {
    // Measured host shapes: bare MH packet at offset 0, behind the 22 byte UDS
    // secure-data prefix, or behind the 41 byte encapsulation head.  Kind 0 and
    // kind 1 both occur (the guest path only ever measured kind 0).
    for (const std::size_t candidate : {std::size_t{0}, std::size_t{22}, std::size_t{41}}) {
        if (candidate + 32 > src.size()) {
            continue;
        }
        const std::uint8_t* head = src.data() + candidate;
        if (head[0] == 0x32 && head[1] == 0xab && head[2] == 0x98 && head[3] == 0x64
            && head[4] == 1 && (head[5] == 0 || head[5] == 1 ||
                (opt.ldn_game_return && have_return_join_fields && have_return_xx_kind &&
                 head[5] == return_xx_kind))) {
            return candidate;
        }
    }
    return src.size();
}

void ControlBridge::Impl::flush_pending_host_payloads(std::vector<ControlEmission>& out) {
    if (stations.empty() || pending_host_payloads.empty()) {
        return;
    }
    std::vector<citra_room::Bytes> pending;
    pending.swap(pending_host_payloads);
    for (const citra_room::Bytes& payload : pending) {
        const std::size_t base = host_magic_base(payload);
        if (base == payload.size()) {
            continue;
        }
        ++counters["announce_host_payloads"];
        ++counters["announce_host_flushed"];
        if (!translate_mh_packet(payload, base, "room.proxy.announce.host", out)) {
            ++counters["announce_host_rejected"];
        }
    }
}
// ---------------------------------------------------------------------------
// V-266: reverse UDS association injection.
//
// Every step below is the *synthesised* guest side of citra-master's own UDS
// association, and each one is checked by Citra before it advances:
//   1. Authentication SEQ1 -> HandleAuthenticationFrame :427-463 (status must be
//      ConnectedAsHost, MAC not yet in node_map, room not full) answers SEQ2 and
//      an AssociationResponse addressed to the frame's transmitter;
//   2. EAPoL-Start -> HandleEAPoLPacket :192-320 (the MAC must be in node_map and
//      not yet connected) assigns the node id and broadcasts the Logoff;
//   3. EAPoL-Logoff -> the assigned node id and the served guest's MAC.
// The frames themselves always come from citra_control encoders; this file only
// decides when to emit them and what to remember.
// ---------------------------------------------------------------------------
void ControlBridge::Impl::note_clock(std::uint64_t now) {
    if (now > clock_ms) {
        clock_ms = now;
    }
}

ControlStation* ControlBridge::Impl::awaiting_station(GuestInjectionState state,
                                                     const citra_room::MacAddress& addressed_to) {
    ControlStation* oldest = nullptr;
    for (ControlStation& station : stations) {
        if (station.guest_inject_state != state) {
            continue;
        }
        if (station.mac == addressed_to) {
            return &station;
        }
        if (oldest == nullptr) {
            oldest = &station;
        }
    }
    // Citra addresses both answers (SEQ2/AssociationResponse) to the guest MAC it
    // just served, so a MAC match is authoritative.  A broadcast answer cannot
    // be attributed that way; the oldest awaiting station is then the one Citra
    // answered first.  Anything else is left unattributed instead of guessed.
    if (oldest != nullptr && addressed_to == citra_room::broadcast_mac) {
        return oldest;
    }
    return nullptr;
}

ControlEmission ControlBridge::Impl::guest_auth_emission(const ControlStation& station) {
    ControlEmission emission;
    citra_control::AuthenticationFrame frame;
    frame.auth_algorithm = citra_control::AuthAlgorithm::OpenSystem;
    frame.auth_seq = citra_control::AuthenticationSeq::Seq1;
    frame.status_code = citra_control::AuthStatus::Successful;
    const auto built = citra_control::build_authentication_frame(frame, &diag);
    if (!built.ok()) {
        ++counters["guest_inject_emit_failed"];
        return emission;
    }
    emission.to_citra = true;
    emission.kind = "citra.guest.auth_seq1";
    emission.citra_type = citra_room::FrameType::Authentication;
    emission.citra_data = built.value;
    emission.have_citra_addresses = true;
    emission.citra_transmitter = station.mac;
    emission.citra_destination = bssid;
    return emission;
}

ControlEmission ControlBridge::Impl::guest_eapol_start_emission(ControlStation& station) {
    ControlEmission emission;
    citra_control::EapolStartPacket packet;
    // Citra's own client echoes the masked association id it got from
    // GetAssociationResult (uds_connection.cpp:77-83), i.e. 1 and not 0xC001.
    // HandleEAPoLPacket ignores the field; the value is echoed for wire fidelity,
    // not because Citra checks it.
    packet.association_id = station.guest_inject_assoc_id;
    // The station's declared name is the only identity the bridge has for it and
    // the one Citra copies into node_info[node_id - 1].
    packet.node.username = station.uds_username;
    // Declared: a real client leaves network_node_id uninitialised and lets the
    // host assign it (uds_data.cpp GenerateEAPoLStartFrame note).  Writing the
    // gateway's own numbering here would be an invented value.
    packet.node.network_node_id = 0;
    // Keep the first station's historical seed, but never declare the same
    // game identity twice in one hall. Persist the seed through its lifetime.
    if (!station.have_guest_identity_word) {
        station.guest_seed = stations.size() == 1 ? kGuestDeclaredSeed :
            (0x4755000000000000ULL | citra_control::load_u32be(station.fake_ip.data()));
        auto word = mhxx_identity_word_from_seed(station.guest_seed);
        while (std::any_of(stations.begin(), stations.end(), [&](const auto& other) {
            return &other != &station && other.have_guest_identity_word && other.guest_identity_word == word;
        })) word = mhxx_identity_word_from_seed(++station.guest_seed);
    }
    packet.node.friend_code_seed = station.guest_seed;
    const auto built = citra_control::build_eapol_start_frame(packet, &diag);
    if (!built.ok()) {
        ++counters["guest_inject_emit_failed"];
        return emission;
    }
    // The word must derive from exactly the seed declared on the wire.
    station.guest_identity_word = mhxx_identity_word_from_seed(station.guest_seed);
    station.have_guest_identity_word = true;
    emission.to_citra = true;
    emission.kind = "citra.guest.eapol_start";
    // EAPoL travels as a Data frame in Citra (HandleDataFrame -> HandleEAPoLPacket).
    emission.citra_type = citra_room::FrameType::Data;
    emission.citra_data = built.value;
    emission.have_citra_addresses = true;
    emission.citra_transmitter = station.mac;
    emission.citra_destination = bssid;
    return emission;
}

void ControlBridge::Impl::begin_guest_injection(ControlStation& station,
                                                std::vector<ControlEmission>& out) {
    // The criterion: a Citra peer can only emit a Beacon while it hosts a UDS
    // network (nwm_uds.cpp BeaconBroadcastCallback :1439-1445 returns unless
    // status == ConnectedAsHost).  Without one, SEQ1 is never sent -- Citra would
    // drop it and the station would look "refused" for the wrong reason.
    if (!citra_beacon_seen) {
        ++counters["guest_inject_no_host"];
        return;
    }
    // One injection per MAC: a second station with the same MAC (a re-connect
    // from a different fake IP, or a duplicated room Connect) must not arm a
    // second handshake -- Citra would reject the SEQ1 anyway, because the MAC is
    // already in its node_map.
    for (const ControlStation& other : stations) {
        if (&other == &station) {
            continue;
        }
        if (other.mac == station.mac && other.guest_inject_state != GuestInjectionState::Idle) {
            ++counters["guest_inject_duplicate"];
            return;
        }
    }
    station.guest_inject_state = GuestInjectionState::AwaitAssocResp;
    station.guest_inject_armed_ms = clock_ms;
    ControlEmission auth = guest_auth_emission(station);
    if (auth.citra_data.empty()) {
        station.guest_inject_state = GuestInjectionState::Idle;
        return;
    }
    ++counters["guest_inject_started"];
    ++counters["guest_inject_auth_seq1_emitted"];
    out.push_back(std::move(auth));
}

bool ControlBridge::Impl::take_guest_logoff(const citra_control::EapolLogoffPacket& packet) {
    ControlStation* matched = nullptr;
    bool any_awaiting = false;
    ControlStation* oldest = nullptr;
    // V-266: citra-master's GenerateEAPoLLogoffFrame never writes
    // client_mac_address -- uds_data.cpp:349-373 value-initialises the packet and
    // copies only the node records, so its mac_address parameter is dead and the
    // field is six zero bytes on the wire.  A zero field therefore means "Citra's
    // own logoff", not "attribution failed"; a non-zero field is honoured only
    // when it names a station we are actually waiting for.
    const bool have_wire_mac = !mac_is_zero(packet.client_mac_address);
    for (ControlStation& station : stations) {
        if (station.guest_inject_state != GuestInjectionState::AwaitLogoff) {
            continue;
        }
        any_awaiting = true;
        if (oldest == nullptr) {
            oldest = &station;
        }
        if (have_wire_mac && station.mac == packet.client_mac_address) {
            matched = &station;
            break;
        }
    }
    if (!any_awaiting) {
        // No injection is waiting for a logoff: the frame belongs to the
        // peer-side association fold, not to this path.
        return false;
    }
    if (packet.assigned_node_id == 0) {
        // Fail closed: a logoff without a usable node id never becomes a node id.
        ControlStation* target = matched != nullptr ? matched : oldest;
        if (target != nullptr) {
            target->guest_inject_state = GuestInjectionState::Idle;
        }
        ++counters["guest_inject_logoff_unmatched"];
        return true;
    }
    if (matched == nullptr) {
        if (have_wire_mac) {
            // Citra named a MAC that no injection is waiting for.  That is not
            // this path's answer, so nothing is assigned and the waiting station
            // keeps its armed state (its own timeout still bounds it).
            ++counters["guest_inject_logoff_unmatched"];
            return true;
        }
        // Citra's real logoff carries no MAC, so the only defensible attribution
        // is arrival order: Citra serves the EAPoL-Starts it accepted in the
        // order they arrived, and every other awaiting station simply keeps
        // waiting for its own logoff.  guest_inject_logoff_ordered records that
        // the node id was attributed by order rather than by MAC.
        matched = oldest;
        ++counters["guest_inject_logoff_ordered"];
    }
    matched->uds_node_id = packet.assigned_node_id;
    matched->have_uds_node_id = true;
    matched->guest_inject_state = GuestInjectionState::Done;
    ++counters["guest_inject_logoff_ok"];
    return true;
}

void ControlBridge::Impl::expire_guest_injections() {
    for (ControlStation& station : stations) {
        if (station.guest_inject_state != GuestInjectionState::AwaitAssocResp &&
            station.guest_inject_state != GuestInjectionState::AwaitLogoff) {
            continue;
        }
        if (clock_ms < station.guest_inject_armed_ms ||
            clock_ms - station.guest_inject_armed_ms < kControlGuestInjectTimeoutMs) {
            continue;
        }
        // Back to Idle, not to a new terminal state: nothing about the station
        // changed, it simply gave up waiting, and guest_inject_timeout records it.
        station.guest_inject_state = GuestInjectionState::Idle;
        ++counters["guest_inject_timeout"];
    }
}

// V-268: the member table is the one measured body whose entries are identity
// endpoints rather than opaque bytes, and it is why a Yuzu peer that joined
// through LDN saw a word (6522df69 in V-267) that named no peer it knew.  The
// layout comes from the 198 byte frame a real MHXX host broadcasts
// (fixtures/mhxx-host-enter.script line 21 -- the same shape as the V-267
// capture):
//   body + 0..1    message type 0x0111
//   body + 2       body length byte (0x6d on the measured frame)
//   body + 12      member count (2)
//   body + 16..23  the host eight byte P2P identifier
//   body + 32..    count nine byte slots: a 4 byte endpoint word, the 2 byte
//                  port 0x3039, 3 bytes of flags; an unused slot starts 0xff.
// Only the four word bytes of slots 1..count-1 are touched and always in place,
// so every length invariant of the frame survives.  Slot 0 is the host and is
// deliberately left to the identity-pair scan: the host word is CLI input, not
// something this bridge can derive.
std::size_t ControlBridge::Impl::translate_member_endpoints(citra_room::Bytes& bytes,
                                                            std::size_t body) {
    if (body + 32 > bytes.size()) {
        return 0;
    }
    if (bytes[body] != 0x01 || bytes[body + 1] != 0x11) {
        return 0;
    }
    const std::size_t count = bytes[body + 12];
    if (count < 2 || count > kMemberTableMaxCount) {
        return 0;
    }
    const std::size_t slots = body + 32;
    if (slots + count * 9 > bytes.size()) {
        return 0;
    }
    std::size_t replaced = 0;
    for (std::size_t index = 1; index < count; ++index) {
        std::uint8_t* const slot = bytes.data() + slots + index * 9;
        // A station can only stand in for a slot when it carries a routable
        // room address; a zero or broadcast fake IP is not an identity.
        const auto usable = [](const ControlStation& station) {
            return !ip_is_zero(station.fake_ip) && !is_sentinel_ip(station.fake_ip);
        };
        // (a) derived word: the word MHXX computed from the seed this bridge
        // declared for the station.  Only a unique match may be used -- every
        // injected station declares the same seed, so a two-guest hall has no
        // discriminating word and falls through to the slot rule below.
        ControlStation* by_word = nullptr;
        std::size_t word_matches = 0;
        for (ControlStation& station : stations) {
            if (!station.have_guest_identity_word || !usable(station)) {
                continue;
            }
            if (!std::equal(station.guest_identity_word.begin(),
                            station.guest_identity_word.end(), slot)) {
                continue;
            }
            by_word = &station;
            ++word_matches;
        }
        ControlStation* target = word_matches == 1 ? by_word : nullptr;
        bool by_position = false;
        // (b) position: the member table lists nodes in node order, so slot i
        // belongs to the node whose Citra-assigned id is i + 1 (the host is 1,
        // the first guest 2 -- the same off-by-one kControlCitraPeerNodeId
        // encodes).  This is the rule that must not fail: it needs no knowledge
        // of how MHXX derives the word.
        if (target == nullptr) {
            for (ControlStation& station : stations) {
                if (!station.have_uds_node_id || station.uds_node_id < 1 || !usable(station)) {
                    continue;
                }
                if (static_cast<std::size_t>(station.uds_node_id) - 1 != index) {
                    continue;
                }
                target = &station;
                by_position = true;
            }
        }
        if (target == nullptr) {
            // Occupied but unclaimable: leave the bytes exactly as they are and
            // say so.  An unused slot (all zero, or the 0xff filler) names no
            // member and stays silent.
            const bool all_zero = slot[0] == 0 && slot[1] == 0 && slot[2] == 0 && slot[3] == 0;
            if (!all_zero && slot[0] != 0xFF) {
                ++counters["announce_guest_word_unmatched"];
            }
            continue;
        }
        if (std::equal(target->fake_ip.begin(), target->fake_ip.end(), slot)) {
            // Already the station own word (the pair scan can have written it):
            // nothing to rewrite, so nothing to count either.
            continue;
        }
        std::copy(target->fake_ip.begin(), target->fake_ip.end(), slot);
        ++counters[by_position ? "announce_guest_slot_replaced" : "announce_guest_word_replaced"];
        ++replaced;
    }
    return replaced;
}

bool ControlBridge::Impl::translate_mh_packet(const citra_room::Bytes& src, std::size_t base,
                                             std::string kind,
                                             std::vector<ControlEmission>& out) {
    if (base <= src.size() && src.size() - base >= 32 && src[base + 4] == 1) {
        citra_room::Bytes physical(src.begin() + static_cast<std::ptrdiff_t>(base), src.end());
        const MhInnerPacket framed = split_mh_inner_messages(physical);
        if (framed.malformed) {
            ++counters["compound_malformed"];
            return false;
        }
        if (framed.messages.size() > 1) {
            if (physical.size() > 1472) {
                ++counters["compound_oversize"];
                return false;
            }
            std::vector<citra_room::Bytes> converted;
            std::vector<ControlEmission> side_emissions;
            std::size_t total = 12 + framed.trailer.size();
            // Validate the complete physical framing before invoking any
            // converter; a truncated later header must not partially emit.
            for (const auto& message : framed.messages) {
                std::vector<ControlEmission> one;
                auto standalone = make_mh_inner_packet(physical, message);
                if (!translate_mh_packet(standalone, 0, kind, one)) {
                    continue;
                }
                bool found_packet = false;
                for (auto& emission : one) {
                    if (emission.room_proxy) {
                        if (!found_packet) {
                            const auto& packet = emission.proxy_data;
                            if (packet.size() < 32 || packet.size() - 12 > 1460) {
                                ++counters["compound_oversize"];
                                return false;
                            }
                            converted.emplace_back(packet.begin() + 12, packet.end());
                            total += packet.size() - 12;
                            found_packet = true;
                        } else {
                            side_emissions.push_back(std::move(emission));
                        }
                    } else {
                        side_emissions.push_back(std::move(emission));
                    }
                }
                if (total > 1472) {
                    ++counters["compound_oversize"];
                    return false;
                }
            }
            if (converted.empty()) {
                return false;
            }
            citra_room::Bytes joined(physical.begin(), physical.begin() + 12);
            for (const auto& message : converted) {
                joined.insert(joined.end(), message.begin(), message.end());
            }
            joined.insert(joined.end(), framed.trailer.begin(), framed.trailer.end());
            ControlEmission emission;
            emission.to_citra = false;
            emission.kind = std::move(kind);
            emission.room_proxy = true;
            emission.proxy_broadcast = true;
            emission.proxy_data = std::move(joined);
            out.push_back(std::move(emission));
            out.insert(out.end(), std::make_move_iterator(side_emissions.begin()),
                       std::make_move_iterator(side_emissions.end()));
            ++counters["compound_datagrams_translated"];
            return true;
        }
    }
    // V-249 route whitelist: the four measured session routes.  A route
    // outside it is not a session packet and stays dropped.
    const std::uint32_t route = citra_control::load_u32be(src.data() + base + 24);
    const bool stream_route = route == 0x20000000u || route == 0x02100000u ||
                              route == 0x02000001u;
    const bool admitted_stream = opt.ldn_game_return && have_return_join_fields &&
        have_return_xx_kind && src[base + 5] == return_xx_kind &&
        std::any_of(stations.begin(), stations.end(), [&](const auto& s) {
            return s.guest_inject_state == GuestInjectionState::Done &&
                   std::equal(s.fake_ip.begin(), s.fake_ip.end(), return_gu_endpoint.begin());
        });
    if (route != 0x03003039u && route != 0x02000000u && route != 0x01000000u
        && route != 0x06000000u && !(stream_route && admitted_stream)) {
        note_data_frame("route", src, static_cast<int>(base));
        ++counters["announce_route_rejected"];
        ++counters["citra_wrong_direction"];
        return false;
    }
    // V-272: the room proxy channel carries bare MH packets, not UDS frames.
    // Measured on the proven relay path (two Yuzu MHGU clients, trace
    // C:\g4roomtmp\v271\trace.jsonl): every ProxyPacket plain payload starts
    // at 32ab9864 with its 12 byte packet header, and the 22 byte LLC +
    // SecureData prefix never appears on that path.  V-265 assumed the
    // opposite and forwarded whole UDS frames, which is why the Yuzu side
    // consumed nothing (proxy_frames_consumed stayed 0 while emitted was 1).
    // The prefix is therefore stripped for every base (22 or 41) and only the
    // identity words inside the bare packet change.
    const std::size_t copy_from = base;
    citra_room::Bytes translated(src.begin() + static_cast<std::ptrdiff_t>(copy_from),
                                 src.end());
    // V-249 parity: the substitution starts at the body (packet offset 32).
    // The message-header sender word stays put; a GU-side receive path for it
    // is not measured yet and must not be guessed.
    const std::size_t word_start = 32;
    std::size_t replacements = 0;
    // V-275: V-274 elicited 30 real 36-byte Citra replies on route 01000000.
    // Their only identity word is sender@20, so the body-only rule dropped
    // every reply. Map that exact field under the bidirectional opt-in gate;
    // do not infer any address from a short body or alter other header words.
    if (opt.ldn_game_return) {
        for (const auto& pair : identity_pairs) {
            if (std::equal(pair.first.begin(), pair.first.end(), translated.data() + 20)) {
                std::copy(pair.second.begin(), pair.second.end(), translated.data() + 20);
                ++replacements;
                break;
            }
        }
    }
    // V-277: MHXX's 112-byte family-01 accept cannot satisfy MHGU's
    // AnalyzeJoinResponse; rebuild it into the 120-byte layout with the
    // requester fields learned from the restructured join request.  Host fields
    // keep their pre-scan words here — the body scan below still maps them.
    if (opt.ldn_game_return && have_return_join_fields) {
        citra_room::Bytes expanded;
        if (expand_xx_join_accept(translated, return_gu_endpoint.data(),
                                  return_gu_short.data(), expanded)) {
            return_xx_kind = translated[33];
            have_return_xx_kind = true;
            translated = std::move(expanded);
            ++counters["join_accept_expanded"];
        }
    }
    // V-279: restructure the two XX-only session structures into their GU
    // shapes.  Both converters map the identity words themselves, so their
    // mappings must count towards the replacement gate below.
    if (opt.ldn_game_return) {
        std::size_t structure_words = 0;
        if (auto table = convert_member_table_xx_to_gu(translated, structure_words)) {
            translated = std::move(*table);
            replacements += structure_words;
            ++counters["member_table_converted"];
        } else if (auto blob = convert_session_blob_xx_to_gu(translated, structure_words)) {
            translated = std::move(*blob);
            replacements += structure_words;
            ++counters["session_blob_expanded"];
        }
    }
    // V-281: track the XX host's own announce counter (40B 05 00 00 00 + u32
    // from sender = the host word) — reference for the GU→XX blob tail.
    if (opt.ldn_game_return && translated.size() == 40 && translated[5] == 0 &&
        translated[32] == 0x05 && translated[33] == 0x00 && translated[34] == 0x00 &&
        translated[35] == 0x00) {
        std::copy_n(translated.begin() + 36, 4, mhxx_announce_counter.begin());
        have_mhxx_announce_counter = true;
    }
    // V-281: the scan covers the injected station's word too — the rosters
    // the host broadcasts name the guest by its XX word (6522df69), and the
    // pair-only scan let those reach MHGU unmapped (V-280 live defect ①).
    // Member tables (0111) keep their dedicated V-268 guest-slot pass, so the
    // extra words apply everywhere else.
    const bool is_member_table = citra_control::load_u32be(translated.data() + 24) ==
                                     0x03003039u &&
                                 translated.size() >= 34 && translated[32] == 0x01 &&
                                 translated[33] == 0x11;
    const auto scan_words = xx_to_gu_words();
    for (std::size_t pos = stream_route ? translated.size() : word_start;
         pos + 4 <= translated.size(); ++pos) {
        if (!is_member_table) {
            const auto found_station = scan_words.find(
                std::array<std::uint8_t, 4>{translated[pos], translated[pos + 1],
                                            translated[pos + 2], translated[pos + 3]});
            if (found_station != scan_words.end() &&
                std::equal(found_station->first.begin(), found_station->first.end(),
                           translated.data() + pos)) {
                std::copy(found_station->second.begin(), found_station->second.end(),
                          translated.data() + pos);
                ++replacements;
                pos += 3;
                continue;
            }
        }
        for (const auto& pair : identity_pairs) {
            if (std::equal(pair.first.begin(), pair.first.end(), translated.data() + pos)) {
                std::copy(pair.second.begin(), pair.second.end(), translated.data() + pos);
                ++replacements;
                break;
            }
        }
    }
    // V-281: the 48B keepalive tail is the sender's monotonic tick — XX runs
    // it at the 3DS rate while MHGU expects the Switch rate (14x apart,
    // V-280 keepalive-roster §Keepalive).  Rescale the inter-arrival delta
    // into a virtual GU tick so the stream advances at MHGU's pace.
    if (opt.ldn_game_return && translated.size() == 48 &&
        citra_control::load_u32be(translated.data() + 24) == 0x06000000u) {
        const std::uint32_t xx_tail = citra_control::load_u32be(translated.data() + 44);
        if (!keepalive_tick_seen) {
            gu_tick = 0;
        } else {
            const std::uint32_t dt_xx = xx_tail - last_xx_tick;  // natural wrap
            const double dt_ms = static_cast<double>(dt_xx) / 268123.48;
            gu_tick += static_cast<std::uint64_t>(dt_ms * 19200.0);
        }
        last_xx_tick = xx_tail;
        keepalive_tick_seen = true;
        translated[44] = static_cast<std::uint8_t>(gu_tick >> 24);
        translated[45] = static_cast<std::uint8_t>(gu_tick >> 16);
        translated[46] = static_cast<std::uint8_t>(gu_tick >> 8);
        translated[47] = static_cast<std::uint8_t>(gu_tick);
    }
    if (replacements == 0) {
        note_data_frame("no-word", src, static_cast<int>(base));
        ++counters["announce_no_identity_word"];
        ++counters["citra_wrong_direction"];
        return false;
    }
    // V-268: the guest endpoints of a member table.  Runs only once the frame is
    // known to be forwarded, so a counter can never claim a guest substitution
    // on a frame that stayed dropped, and it runs after the pair scan so slot 0
    // (the host) already carries its GU word.
    translate_member_endpoints(translated, word_start);
    // V-285: injected UDS associations lack the GU descriptor's remaining
    // fields. Restore them only in an otherwise empty guest roster entry,
    // using the original GU request, after endpoint word translation.
    if (opt.ldn_game_return &&
        citra_control::load_u32be(translated.data() + 24) == 0x02000000u &&
        translated[5] == 0) {
        // The host can add a native Citra before or after the injected GU
        // guest. Locate the exact guest descriptor in every occupied slot;
        // the two-player offset does not describe a three/four-player roster.
        std::size_t first_entry = 0, entry_count = 0;
        const std::size_t count = translated[33];
        if (translated[32] == 0x02 && count >= 2 && count <= 4 &&
            translated.size() == 52 + count * 72) {
            first_entry = 48;
            entry_count = count;
        } else if ((translated.size() == 332 || translated.size() == 368) &&
                   translated[32] == 0x20 && count >= 2 && count <= 4) {
            first_entry = 44;
            entry_count = count;
        }
        auto saved = return_states;
        if (active_return_ip) saved[*active_return_ip] = static_cast<const ReturnState&>(*this);
        // Standalone legacy bridge callers may not yet have selected a member.
        if (saved.empty() && have_return_join_fields) saved[{}] = static_cast<const ReturnState&>(*this);
        for (const auto& [ip, state] : saved) {
        (void)ip;
        if (!state.have_return_join_fields) continue;
        const auto& return_gu_endpoint = state.return_gu_endpoint;
        const auto& return_gu_short = state.return_gu_short;
        const auto& return_gu_station_id = state.return_gu_station_id;
        const auto& return_gu_descriptor = state.return_gu_descriptor;
        for (std::size_t slot = 1; slot < entry_count; ++slot) {
        const std::size_t entry = first_entry + slot * 72;
        const bool admitted = std::any_of(stations.begin(), stations.end(), [&](const auto& s) {
            return s.guest_inject_state == GuestInjectionState::Done &&
                   std::equal(s.fake_ip.begin(), s.fake_ip.end(), return_gu_endpoint.begin());
        });
        // V300: XX now retains our canonical nonzero identity. Recognize only
        // that exact endpoint6+short2 value (and zero remaining fields), in
        // addition to legacy empty entries, before restoring the GU layout.
        // V301: GU's roster consumer compares both complete 35-byte
        // subrecords. Undo our exact canonical descriptor as a whole; the
        // original request also owns the trailing endpoint and secondary
        // subrecord, which a 22-byte identity repair cannot reconstruct.
        std::array<std::uint8_t, 70> canonical{};
        for (const std::size_t sub : {std::size_t{0}, std::size_t{35}}) {
            for (const std::size_t endpoint : {sub, sub + 6, sub + 29}) {
                std::copy(return_gu_endpoint.begin(), return_gu_endpoint.end(),
                          canonical.begin() + endpoint);
            }
            std::copy(return_gu_short.begin(), return_gu_short.end(),
                      canonical.begin() + sub + 12);
        }
        const auto legacy_canonical = canonical;
        for (const std::size_t sub : {std::size_t{0}, std::size_t{35}})
            std::copy_n(return_gu_endpoint.begin(), 4, canonical.begin() + sub + 18);
        const bool complete_canonical = entry && admitted &&
            (std::equal(canonical.begin(), canonical.end(), translated.begin() + entry) ||
             std::equal(legacy_canonical.begin(), legacy_canonical.end(), translated.begin() + entry));
        if (complete_canonical) {
            std::copy(return_gu_descriptor.begin(), return_gu_descriptor.end(),
                      translated.begin() + entry);
        }
        // Retain compatibility with the previous empty/partial fixtures only
        // when their unhandled remainder is empty. Unknown secondary native
        // fields must never be partially overwritten.
        const bool empty_remainder = entry &&
            std::all_of(translated.begin() + entry + 22,
                        translated.begin() + entry + 70,
                        [](std::uint8_t b) { return b == 0; });
        const bool known_identity = entry &&
            std::equal(return_gu_endpoint.begin(), return_gu_endpoint.end(),
                       translated.begin() + static_cast<std::ptrdiff_t>(entry + 6)) &&
            std::equal(return_gu_short.begin(), return_gu_short.end(),
                       translated.begin() + static_cast<std::ptrdiff_t>(entry + 12)) &&
            std::all_of(translated.begin() + static_cast<std::ptrdiff_t>(entry + 14),
                        translated.begin() + static_cast<std::ptrdiff_t>(entry + 22),
                        [](std::uint8_t b) { return b == 0; });
        if (!complete_canonical && entry && admitted && empty_remainder &&
            std::equal(return_gu_endpoint.begin(), return_gu_endpoint.end(),
                       translated.begin() + static_cast<std::ptrdiff_t>(entry)) &&
            (known_identity || std::all_of(translated.begin() + static_cast<std::ptrdiff_t>(entry + 6),
                        translated.begin() + static_cast<std::ptrdiff_t>(entry + 22),
                        [](std::uint8_t b) { return b == 0; }))) {
            std::copy(return_gu_endpoint.begin(), return_gu_endpoint.end(),
                      translated.begin() + static_cast<std::ptrdiff_t>(entry + 6));
            std::copy(return_gu_station_id.begin(), return_gu_station_id.end(),
                      translated.begin() + static_cast<std::ptrdiff_t>(entry + 12));
            std::copy_n(return_gu_endpoint.begin(), 4,
                        translated.begin() + static_cast<std::ptrdiff_t>(entry + 18));
        }
        }
    }
        }
    ControlEmission emission;
    emission.to_citra = false;
    emission.kind = std::move(kind);
    emission.room_proxy = true;
    emission.proxy_broadcast = true;
    emission.proxy_data = std::move(translated);
    out.push_back(std::move(emission));
    for (auto& drained : drain()) {
        out.push_back(std::move(drained));
    }
    note_data_frame("forwarded", src, static_cast<int>(base));
    ++counters["announce_forwarded"];
    ++counters["announce_word_replacements"];
    counters["announce_word_replacements_total"] += replacements;
    return true;
}
std::vector<ControlEmission> ControlBridge::Impl::drain() {
    std::vector<ControlEmission> out;
    if (plane.validate_outbox() != Err::Ok) {
        ++counters["outbox_invalid"];
        plane.clear_outbox();
        return out;
    }
    for (const citra_control::OutIntent& intent : plane.outbox()) {
        if (intent.is_citra()) {
            out.push_back(citra_intent_emission(intent.citra));
        } else {
            if (opt.ldn_require_live_hall && !live_hall_available()) {
                continue;
            }
            out.push_back(ldn_intent_emission(intent.ldn));
        }
    }
    plane.clear_outbox();
    return out;
}

std::vector<ControlEmission> ControlBridge::Impl::sync_all_stations() {
    std::vector<ControlEmission> out;
    if (opt.ldn_require_live_hall && !live_hall_available()) {
        return out;
    }
    for (const ControlStation& station : stations) {
        out.push_back(sync_emission(station.fake_ip));
    }
    return out;
}

ControlBridge::ControlBridge(const ControlOptions& options, const room_client::IPv4& session_fake_ip,
                             const citra_room::MacAddress& session_mac)
    : impl_(std::make_unique<Impl>(options, session_fake_ip, session_mac)) {}

ControlBridge::~ControlBridge() = default;

std::vector<ControlEmission> ControlBridge::start() {
    std::vector<ControlEmission> out;
    if (impl_->ap_started) {
        return out;
    }
    impl_->ap_started = true;
    ++impl_->counters["ap_started"];
    if (impl_->opt.ldn_gu_host_discovery) {
        return out;
    }
    if (impl_->plane.ap_initialized(&impl_->diag) == Err::Ok) {
        ++impl_->counters["ap_initialized"];
    } else {
        ++impl_->counters["ap_rejected"];
    }
    if (impl_->plane.ap_opened(&impl_->diag) == Err::Ok) {
        ++impl_->counters["ap_opened"];
    } else {
        ++impl_->counters["ap_rejected"];
    }
    if (impl_->plane.ap_created(&impl_->diag) == Err::Ok) {
        ++impl_->counters["ap_created"];
    } else {
        ++impl_->counters["ap_rejected"];
    }
    impl_->last_beacon_ms = 0;
    if (impl_->plane.citra_beacon_sent(&impl_->diag) == Err::Ok) {
        ControlEmission beacon = impl_->beacon_emission();
        if (!beacon.citra_data.empty()) {
            out.push_back(std::move(beacon));
        }
    } else {
        ++impl_->counters["beacon_skipped"];
    }
    return out;
}

std::vector<ControlEmission> ControlBridge::tick(std::uint64_t now_ms) {
    std::vector<ControlEmission> out;
    // V-266: the clock and the injection timeout run before the beacon early
    // returns, so a stalled injection is counted even while beacons are skipped.
    impl_->note_clock(now_ms);
    impl_->expire_guest_injections();
    if (!impl_->ap_started) {
        return out;
    }
    if (impl_->opt.ldn_gu_host_discovery) {
        return impl_->gu_host_tick();
    }
    if (impl_->last_beacon_ms == 0) {
        // start() already sent the first beacon; arm the periodic clock here so
        // the gateway's absolute clock origin never triggers a duplicate.
        impl_->last_beacon_ms = now_ms;
        return out;
    }
    if (now_ms - impl_->last_beacon_ms < impl_->opt.beacon_interval_ms) {
        return out;
    }
    impl_->last_beacon_ms = now_ms;
    if (impl_->plane.citra_beacon_sent(&impl_->diag) != Err::Ok) {
        ++impl_->counters["beacon_skipped"];
        return out;
    }
    ControlEmission beacon = impl_->beacon_emission();
    if (!beacon.citra_data.empty()) {
        out.push_back(std::move(beacon));
    }
    return out;
}

void ControlBridge::on_citra_beacon_appdata(const citra_room::Bytes& appdata,
                                            const citra_room::MacAddress& source_mac,
                                            std::uint64_t now_ms) {
    impl_->on_citra_beacon_appdata(appdata, source_mac, now_ms);
}

std::vector<ControlEmission> ControlBridge::on_citra_wifi(const citra_room::WifiPacket& wifi,
                                                          std::uint64_t now_ms) {
    std::vector<ControlEmission> out;
    impl_->note_clock(now_ms);
    if (impl_->opt.ldn_gu_host_discovery) {
        return impl_->gu_host_wifi(wifi);
    }
    // V-266: the injection criterion, recorded without consuming the frame.  A
    // WifiPacket of type Beacon can only come from a Citra peer that is hosting
    // the UDS network (nwm_uds.cpp BeaconBroadcastCallback :1439-1445 returns
    // immediately unless status == ConnectedAsHost), so this counter is the
    // "Citra really is the UDS host" fact guest_inject requires.  The frame
    // keeps its historical handling below (a counted wrong-direction drop).
    if (wifi.type == citra_room::FrameType::Beacon) {
        impl_->citra_beacon_seen = true;
        ++impl_->counters["citra_beacon_seen"];
        // V-267: every inbound Beacon is also the peer's live hall description
        // (NetworkInfo.application_data; the hall name sits at offset 52 as
        // 24 UTF-16LE code units).  It is decoded here because this is the one
        // place that sees *every* Beacon -- the inbound.json sampler in
        // gateway.cpp only decodes the first three frames of a type.  A frame
        // that does not parse leaves the stored value untouched (counted
        // advertise_beacon_unparsed); kCitraAppdataMaxAgeMs is what retires it.
        const auto beacon = citra_control::parse_beacon_frame(
            wifi.data.data(), wifi.data.size(), wifi.transmitter, nullptr);
        if (!beacon.ok()) {
            ++impl_->counters["advertise_beacon_unparsed"];
        } else {
            const auto& info = beacon.value.network_info;
            const std::size_t app_bytes = std::min<std::size_t>(
                info.application_data_size, info.application_data.size());
            impl_->on_citra_beacon_appdata(
                citra_room::Bytes(info.application_data.begin(),
                                   info.application_data.begin() + app_bytes),
                wifi.transmitter, now_ms);
        }
    }
    switch (wifi.type) {
    case citra_room::FrameType::Authentication: {
        const auto parsed =
            citra_control::parse_authentication_frame(wifi.data.data(), wifi.data.size(), &impl_->diag);
        if (!parsed.ok()) {
            // V-016k: the library refuses to build or parse a non-successful
            // Authentication body, yet a real Citra client may send SEQ1 with a
            // failure status.  Read the little endian fields by hand so the
            // refusal is counted as refused instead of malformed.
            if (wifi.data.size() == citra_control::kAuthFrameSize) {
                const std::uint16_t algo = citra_control::load_u16le(wifi.data.data());
                const std::uint16_t seq = citra_control::load_u16le(wifi.data.data() + 2);
                const std::uint16_t status = citra_control::load_u16le(wifi.data.data() + 4);
                if (algo == 0 && seq == 1 && status != 0) {
                    ++impl_->counters["auth_refused"];
                    (void)impl_->plane.citra_auth_seq1(citra_control::AssocOutcome::Refused,
                                                       &impl_->diag);
                    return out;
                }
            }
            ++impl_->counters["auth_rejected"];
            return out;
        }
        // V-266: SEQ2 is the host's answer to an injected SEQ1.  Citra itself
        // ignores SEQ2 on receipt (HandleAuthenticationFrame only looks at SEQ1),
        // so it carries no state here either: it records that Citra accepted the
        // injection, and the AssociationResponse below is what advances the
        // machine.  A SEQ2 that no station is waiting for stays the historical
        // auth_rejected, because nothing in the gateway can have caused it.
        if (parsed.value.auth_seq == citra_control::AuthenticationSeq::Seq2) {
            if (impl_->guest_inject &&
                impl_->awaiting_station(GuestInjectionState::AwaitAssocResp, wifi.destination) !=
                    nullptr) {
                ++impl_->counters["guest_inject_auth_seq2"];
                return out;
            }
            ++impl_->counters["auth_rejected"];
            return out;
        }
        if (parsed.value.auth_algorithm != citra_control::AuthAlgorithm::OpenSystem ||
            parsed.value.auth_seq != citra_control::AuthenticationSeq::Seq1) {
            ++impl_->counters["auth_rejected"];
            return out;
        }
        if (parsed.value.status_code != citra_control::AuthStatus::Successful) {
            // V-016k: a refused authentication must not produce an association
            // response, so the plane records the refusal and emits nothing.
            ++impl_->counters["auth_refused"];
            (void)impl_->plane.citra_auth_seq1(citra_control::AssocOutcome::Refused, &impl_->diag);
            return out;
        }
        if (impl_->plane.citra_auth_seq1(citra_control::AssocOutcome::Successful, &impl_->diag) != Err::Ok) {
            ++impl_->counters["auth_rejected"];
            return out;
        }
        ++impl_->counters["auth_seq1_accepted"];
        return impl_->drain();
    }
    case citra_room::FrameType::Deauthentication: {
        if (!wifi.data.empty()) {
            ++impl_->counters["deauth_rejected"];
            return out;
        }
        if (impl_->plane.citra_deauth(&impl_->diag) != Err::Ok) {
            ++impl_->counters["deauth_rejected"];
            return out;
        }
        // The association is gone: periodic beacons must not retain the peer
        // or its previous identity. Match the EAPoL-Logoff cleanup below.
        impl_->citra_node_joined = false;
        impl_->citra_node_info = citra_control::EapolNodeInfo{};
        ++impl_->counters["deauth_accepted"];
        return impl_->sync_all_stations();
    }
    case citra_room::FrameType::AssociationResponse: {
        // V-266: with the gate off nothing in the gateway can make Citra send
        // this frame, so it keeps the historical wrong-direction drop.
        if (!impl_->guest_inject) {
            ++impl_->counters["citra_wrong_direction"];
            return out;
        }
        ControlStation* station =
            impl_->awaiting_station(GuestInjectionState::AwaitAssocResp, wifi.destination);
        if (station == nullptr) {
            ++impl_->counters["citra_wrong_direction"];
            return out;
        }
        const auto parsed = citra_control::parse_association_response_frame(
            wifi.data.data(), wifi.data.size(), &impl_->diag);
        if (!parsed.ok()) {
            // The library refuses to parse a non-successful body (V-016k: Citra
            // ASSERTs on it), so read the status field by hand to tell "Citra
            // refused" from "malformed": a refusal ends the attempt and must
            // never be followed by an EAPoL-Start.
            station->guest_inject_state = GuestInjectionState::Idle;
            const bool refused = wifi.data.size() == citra_control::kAssocResponseTotalSize &&
                                 citra_control::load_u16le(wifi.data.data() + 2) != 0;
            ++impl_->counters[refused ? "guest_inject_assoc_refused" : "guest_inject_assoc_bad"];
            return out;
        }
        station->guest_inject_assoc_id = parsed.value.association_id;
        station->guest_inject_state = GuestInjectionState::AwaitLogoff;
        station->guest_inject_armed_ms = impl_->clock_ms;
        ++impl_->counters["guest_inject_assoc_ok"];
        ControlEmission start = impl_->guest_eapol_start_emission(*station);
        if (start.citra_data.empty()) {
            station->guest_inject_state = GuestInjectionState::Idle;
            return out;
        }
        ++impl_->counters["guest_inject_eapol_start_emitted"];
        out.push_back(std::move(start));
        return out;
    }
    case citra_room::FrameType::Data: {
        // V-259: cross-game announce forward (control.hpp ControlOptions).  An
        // MHXX kind-0 session announce is the game-layer hall advertisement the
        // V-258 root cause traced to this drop; with the gate on, its 4-byte
        // identity words are substituted per the V-249 primitive and the packet
        // leaves as a room Proxy packet towards the Yuzu members.
        if (impl_->announce_forward) {
            // The measured XX UDS Data payload carries the 32AB9864 packet at
            // offset 0 (bare MH packet) or behind the 41 byte encapsulation head
            // (V-254).  A magic hunt anywhere else would let an encrypted Pia
            // batch stream forge a match, so only these two offsets qualify.
            std::size_t base = wifi.data.size();
            for (const std::size_t candidate :
                 {std::size_t{0}, std::size_t{22}, std::size_t{41}}) {
                if (candidate + 32 > wifi.data.size()) {
                    continue;
                }
                const std::uint8_t* head = wifi.data.data() + candidate;
                if (head[0] == 0x32 && head[1] == 0xab && head[2] == 0x98 && head[3] == 0x64
                    && head[4] == 1 && head[5] == 0) {
                    base = candidate;
                    break;
                }
            }
            if (base != wifi.data.size()) {
                // Forwarding needs a joined Citra peer (the announcement source)
                // and at least one admitted station (the Yuzu member it is for).
                if (!impl_->citra_node_joined || impl_->stations.empty()) {
                    impl_->note_data_frame("prereq", wifi.data, static_cast<int>(base));
                    ++impl_->counters["announce_prereq_rejected"];
                    ++impl_->counters["citra_wrong_direction"];
                    return out;
                }
                std::vector<ControlEmission> emissions;
                if (!impl_->translate_mh_packet(wifi.data, base, "room.proxy.announce",
                                               emissions)) {
                    return out;
                }
                return emissions;
            }
            // Magic matched nowhere at offset 0 or 41: not an MH session packet.
            impl_->note_data_frame("no-magic", wifi.data, -1);
        } else {
            impl_->note_data_frame("gate-off", wifi.data, -1);
        }
        ++impl_->counters["citra_wrong_direction"];
        return out;
    }
    }
    ++impl_->counters["citra_wrong_direction"];
    return out;
}

std::vector<ControlEmission> ControlBridge::on_transport_departure() {
    if (!impl_->opt.ldn_gu_host_admission) return {};
    auto emissions = impl_->gu_host_depart(true);
    emissions.erase(std::remove_if(emissions.begin(), emissions.end(),
                                  [](const auto& e) { return e.to_citra; }), emissions.end());
    return emissions;
}


std::vector<ControlEmission> ControlBridge::on_citra_game_payload(
    const citra_room::Bytes& payload) {
    // V-263: the Citra side is the UDS host (it created the hall), so its game
    // traffic never passes the guest-side association gate.  What still applies
    // is the announce gate, at least one admitted station (the Yuzu member the
    // packet is for) and the measured payload shape.
    std::vector<ControlEmission> out;
    if (!impl_->announce_forward) {
        impl_->note_data_frame("gate-off", payload, -1);
        return out;
    }
    if (impl_->stations.empty()) {
        impl_->note_data_frame("prereq", payload, -1);
        ++impl_->counters["announce_prereq_rejected"];
        ++impl_->counters["announce_host_rejected"];
        // V-264: keep the newest few host payloads.  The host announces its
        // member table once, usually before the Yuzu member has connected;
        // without this the ordering of the two sides silently decided the run.
        if (impl_->host_magic_base(payload) == payload.size()) {
            return out;
        }
        if (impl_->pending_host_payloads.size() >= 4) {
            impl_->pending_host_payloads.erase(impl_->pending_host_payloads.begin());
        }
        impl_->pending_host_payloads.push_back(payload);
        ++impl_->counters["announce_host_pending"];
        return out;
    }
    const auto secure = citra_control::parse_secure_data_frame(payload.data(), payload.size());
    if (impl_->opt.ldn_game_return && secure.ok() && secure.value.header.src_node_id == 1) {
        for (const auto& station : impl_->stations) {
            if (station.guest_inject_state != GuestInjectionState::Done || !station.have_uds_node_id ||
                (secure.value.header.dest_node_id != 0xffff &&
                 secure.value.header.dest_node_id != station.uds_node_id)) continue;
            impl_->select_return_peer(station.fake_ip);
            const auto base = impl_->host_magic_base(payload);
            if (base == payload.size()) continue;
            std::vector<ControlEmission> one;
            if (!impl_->translate_mh_packet(payload, base, "room.proxy.announce.host", one)) continue;
            for (auto& emission : one) {
                if (emission.room_proxy) {
                    emission.proxy_broadcast = false;
                    emission.proxy_remote_ip = station.fake_ip;
                }
                out.push_back(std::move(emission));
            }
        }
        return out;
    }
    const std::size_t base = impl_->host_magic_base(payload);
    if (base == payload.size()) {
        impl_->note_data_frame("no-magic", payload, -1);
        ++impl_->counters["announce_host_rejected"];
        return out;
    }
    ++impl_->counters["announce_host_payloads"];
    if (!impl_->translate_mh_packet(payload, base, "room.proxy.announce.host", out))
        ++impl_->counters["announce_host_rejected"];
    return out;
}
std::vector<ControlEmission> ControlBridge::on_citra_eapol(const citra_room::Bytes& frame,
                                                           std::uint64_t now_ms) {
    std::vector<ControlEmission> out;
    // Reverse association needs the sender and selected host addresses.
    if (impl_->opt.ldn_gu_host_discovery) return out;
    impl_->note_clock(now_ms);
    const auto type = citra_control::eapol_frame_type(frame.data(), frame.size(), &impl_->diag);
    if (!type.ok()) {
        ++impl_->counters["eapol_rejected"];
        return out;
    }
    if (type.value == citra_control::kEapolStartMagic) {
        const auto parsed =
            citra_control::parse_eapol_start_frame(frame.data(), frame.size(), &impl_->diag);
        if (!parsed.ok()) {
            ++impl_->counters["eapol_rejected"];
            return out;
        }
        if (impl_->plane.citra_eapol_start(&impl_->diag) != Err::Ok) {
            ++impl_->counters["eapol_rejected"];
            return out;
        }
        // D3/N2: never copy the declared network_node_id -- real clients send an
        // uninitialised 0, so the peer is pinned to the reserved id 2 by the N1
        // table.  Only the seed/username are kept, for the Logoff and Beacon
        // echo.  A repeated Start is rejected by the plane before this point, so
        // it neither double counts nor replaces these values.
        impl_->citra_node_joined = true;
        impl_->citra_node_info = parsed.value.node;
        ++impl_->counters["eapol_start_accepted"];
        return impl_->drain();
    }
    if (type.value == citra_control::kEapolLogoffMagic) {
        const auto logoff =
            citra_control::parse_eapol_logoff_frame(frame.data(), frame.size(), &impl_->diag);
        if (!logoff.ok()) {
            ++impl_->counters["eapol_rejected"];
            return out;
        }
        // V-266: Citra's own logoff answers the injected EAPoL-Start and carries
        // the node id it assigned (HandleEAPoLPacket :236-252).  Its
        // client_mac_address field is left at zero -- GenerateEAPoLLogoffFrame
        // never writes it (uds_data.cpp:349-373) -- so take_guest_logoff
        // attributes a MAC-less logoff to the oldest waiting station and counts
        // it under guest_inject_logoff_ordered.  The frame is consumed here
        // before the peer-side plane path, which models the opposite topology
        // and would only count it as rejected.
        if (impl_->guest_inject && impl_->take_guest_logoff(logoff.value)) {
            return out;
        }
        if (impl_->plane.citra_eapol_logoff(&impl_->diag) != Err::Ok) {
            ++impl_->counters["eapol_rejected"];
            return out;
        }
        // D3/N2: the peer left the room, so the beacon/Logoff stop advertising
        // it and its stale seed/username are dropped.
        impl_->citra_node_joined = false;
        impl_->citra_node_info = citra_control::EapolNodeInfo{};
        ++impl_->counters["eapol_logoff_accepted"];
        return impl_->sync_all_stations();
    }
    ++impl_->counters["eapol_rejected"];
    return out;
}

bool ControlBridge::on_citra_secure_data() {
    if (impl_->plane.citra_data_in(&impl_->diag) != Err::Ok) {
        ++impl_->counters["citra_data_not_connected"];
        return false;
    }
    ++impl_->counters["citra_data_accepted"];
    return true;
}

void ControlBridge::note_opaque_data() { ++impl_->counters["citra_opaque_data_forwarded"]; }

void ControlBridge::note_non_owner_ignored() { ++impl_->counters["ldn_non_owner_ignored"]; }

LdnHandling ControlBridge::on_ldn(const room_client::LdnPacket& packet, const LdnContext& context) {
    if (impl_->opt.ldn_gu_host_discovery) {
        return impl_->gu_host_response(packet);
    }
    LdnHandling handling;
    handling.type = packet.type;
    const citra_control::LdnPacketType expected_type = to_ldn_type(packet.type);
    if (packet.data.size() != citra_control::ldn_body_size(expected_type)) {
        ++impl_->counters["ldn_bad_length"];
        return handling;
    }
    switch (packet.type) {
    case room_client::LdnType::Scan: {
        if (impl_->opt.ldn_require_live_hall && !impl_->live_hall_available()) {
            ++impl_->counters["ldn_scan_rejected"];
            return handling;
        }
        if (ip_is_zero(packet.local_ip)) {
            ++impl_->counters["ldn_bad_source"];
            return handling;
        }
        if (impl_->plane.yuzu_scan(packet.local_ip, &impl_->diag) != Err::Ok) {
            ++impl_->counters["ldn_scan_rejected"];
            return handling;
        }
        ++impl_->counters["ldn_scan_accepted"];
        handling.accepted = true;
        // state.cpp already pushes the unicast ScanResp intent, so drain() below
        // turns that single intent into wire bytes exactly once.
        for (ControlEmission& emission : impl_->drain()) {
            handling.emissions.push_back(std::move(emission));
        }
        return handling;
    }
    case room_client::LdnType::ScanResponse:
    case room_client::LdnType::SyncNetwork:
        // Direction error: these are host -> client bodies.
        ++impl_->counters["ldn_direction_rejected"];
        return handling;
    case room_client::LdnType::Connect: {
        if (impl_->opt.ldn_require_live_hall && !impl_->live_hall_available()) {
            ++impl_->counters["ldn_connect_rejected"];
            return handling;
        }
        if (ip_is_zero(packet.local_ip)) {
            ++impl_->counters["ldn_bad_source"];
            return handling;
        }
        if (impl_->stations.size() >= kControlMaxStations ||
            (!impl_->local_citra_peers.empty() && impl_->stations.size() + impl_->local_citra_peers.size() >= 3)) {
            ++impl_->counters["ldn_capacity_rejected"];
            return handling;
        }
        const auto parsed =
            citra_control::parse_ldn_node_info(packet.data.data(), packet.data.size(), &impl_->diag);
        citra_room::MacAddress station_mac{};
        bool have_mac = false;
        std::array<std::uint8_t, 4> declared_ipv4{};
        if (parsed.ok()) {
            declared_ipv4 = parsed.value.ipv4_address;
        }
        if (!parsed.ok()) {
            ++impl_->counters["ldn_bad_body"];
            return handling;
        } else if (mac_is_usable(parsed.value.mac_address)) {
            station_mac = parsed.value.mac_address;
            have_mac = true;
        }
        if (!have_mac && context.have_mapped_mac && mac_is_usable(context.mapped_mac)) {
            station_mac = context.mapped_mac;
            have_mac = true;
            if (parsed.ok()) {
                ++impl_->counters["ldn_mac_filled"];
            }
        }
        if (!have_mac) {
            ++impl_->counters["ldn_bad_source"];
            return handling;
        }
        const auto name = citra_control::username_from_bytes(parsed.value.user_name, &impl_->diag);
        if (!name.ok()) {
            ++impl_->counters["ldn_bad_body"];
            return handling;
        }
        if (impl_->plane.yuzu_connect(packet.local_ip, &impl_->diag) != Err::Ok) {
            ++impl_->counters["ldn_connect_rejected"];
            return handling;
        }
        impl_->add_station(station_mac, packet.local_ip, declared_ipv4, !ip_is_zero(declared_ipv4),
                           parsed.value.user_name, name.value, parsed.value.local_communication_version);
        ++impl_->counters["ldn_connect_accepted"];
        // V-243: surface the session-phase advance for the cross-game state machine.
        if (impl_->plane.session_phase() == citra_control::SessionPhase::StationAdmitted) {
            ++impl_->counters["session_phase_station_admitted"];
        }
        handling.accepted = true;
        handling.emissions = impl_->drain();
        // V-264: a station now exists, so any host payload that arrived too early
        // can finally be translated and broadcast to it.
        impl_->flush_pending_host_payloads(handling.emissions);
        // V-266: and now present the same station to Citra as a joining UDS
        // guest, so Citra's node_map gains an entry MHXX can see.  This runs
        // only after both planes accepted the station, so a rejected Connect
        // never leaves a half-armed injection behind.  Mirrored sessions (other
        // Citra clients) never reach here: only the control owner runs on_ldn.
        if (impl_->guest_inject) {
            impl_->begin_guest_injection(impl_->stations.back(), handling.emissions);
        }
        return handling;
    }
    case room_client::LdnType::Disconnect: {
        if (ip_is_zero(packet.local_ip)) {
            ++impl_->counters["ldn_bad_source"];
            return handling;
        }
        const auto parsed =
            citra_control::parse_ldn_node_info(packet.data.data(), packet.data.size(), &impl_->diag);
        if (!parsed.ok()) {
            ++impl_->counters["ldn_bad_body"];
            return handling;
        }
        const Err result = impl_->plane.yuzu_disconnect(packet.local_ip, &impl_->diag);
        if (result == Err::NotFound) {
            ++impl_->counters["ldn_unknown_source"];
            return handling;
        }
        if (result != Err::Ok) {
            ++impl_->counters["ldn_disconnect_rejected"];
            return handling;
        }
        // V-302: removing only our station leaves its MAC in the Citra host's
        // node_map. HandleAuthenticationFrame then silently refuses the next
        // SEQ1 from that MAC. Mirror the native guest's DisconnectNetwork:
        // an empty Deauthentication from the admitted guest to its host.
        // Include unfinished injections: Citra inserts a node_map entry before
        // answering authentication, not only after EAPoL completes.
        if (impl_->guest_inject && impl_->citra_beacon_seen) {
            const auto departing = std::find_if(impl_->stations.begin(), impl_->stations.end(),
                [&](const ControlStation& station) { return station.fake_ip == packet.local_ip; });
            if (departing != impl_->stations.end()) {
                const auto same_mac = std::count_if(impl_->stations.begin(), impl_->stations.end(),
                    [&](const ControlStation& station) { return station.mac == departing->mac; });
                if (same_mac == 1) {
                    ControlEmission deauth;
                    deauth.to_citra = true;
                    deauth.kind = "citra.guest.deauthentication";
                    deauth.citra_type = citra_room::FrameType::Deauthentication;
                    deauth.have_citra_addresses = true;
                    deauth.citra_transmitter = departing->mac;
                    deauth.citra_destination = impl_->session_mac;
                    handling.emissions.push_back(std::move(deauth));
                }
            }
        }
        impl_->remove_station(packet.local_ip);
        ++impl_->counters["ldn_disconnect_accepted"];
        handling.accepted = true;
        for (ControlEmission& emission : impl_->drain()) {
            handling.emissions.push_back(std::move(emission));
        }
        return handling;
    }
    case room_client::LdnType::DestroyNetwork: {
        if (impl_->plane.yuzu_destroy_network(&impl_->diag) != Err::Ok) {
            ++impl_->counters["ldn_destroy_rejected"];
            return handling;
        }
        impl_->stations.clear();
        invalidate_game_return_admission();
        ++impl_->counters["ldn_destroy_accepted"];
        handling.accepted = true;
        return handling;
    }
    }
    ++impl_->counters["ldn_bad_body"];
    return handling;
}

void ControlBridge::mirror_connect(const room_client::IPv4& from,
                                   const citra_room::MacAddress& station_mac,
                                   const std::array<std::uint8_t, 4>& declared_ipv4,
                                   bool have_declared_ipv4,
                                   const citra_control::UserNameBytes& user_name, std::int16_t version) {
    if (impl_->stations.size() >= kControlMaxStations ||
        (!impl_->local_citra_peers.empty() && impl_->stations.size() + impl_->local_citra_peers.size() >= 3)) {
        ++impl_->counters["mirror_suppressed"];
        return;
    }
    const auto name = citra_control::username_from_bytes(user_name, &impl_->diag);
    if (!name.ok()) {
        ++impl_->counters["mirror_suppressed"];
        return;
    }
    if (impl_->plane.yuzu_connect(from, &impl_->diag) != Err::Ok) {
        ++impl_->counters["mirror_suppressed"];
        return;
    }
    impl_->add_station(station_mac, from, declared_ipv4, have_declared_ipv4,
                       user_name, name.value, version);
    ++impl_->counters["mirror_applied"];
    impl_->counters["mirror_suppressed"] += impl_->plane.outbox().size();
    impl_->plane.clear_outbox();
}

void ControlBridge::mirror_disconnect(const room_client::IPv4& from) {
    if (impl_->plane.yuzu_disconnect(from, &impl_->diag) != Err::Ok) {
        ++impl_->counters["mirror_suppressed"];
        return;
    }
    impl_->remove_station(from);
    ++impl_->counters["mirror_applied"];
    impl_->counters["mirror_suppressed"] += impl_->plane.outbox().size();
    impl_->plane.clear_outbox();
}

void ControlBridge::mirror_destroy() {
    if (impl_->plane.yuzu_destroy_network(&impl_->diag) != Err::Ok) {
        ++impl_->counters["mirror_suppressed"];
        return;
    }
    impl_->stations.clear();
    invalidate_game_return_admission();
    ++impl_->counters["mirror_applied"];
}

bool ControlBridge::ap_established() const { return impl_->plane.ap_established(); }
bool ControlBridge::citra_connected() const { return impl_->plane.connected(); }
bool ControlBridge::citra_association_complete() const {
    return impl_->plane.citra_state() == citra_control::CitraState::Connected &&
           impl_->plane.association().complete();
}
std::size_t ControlBridge::station_count() const { return impl_->stations.size(); }
const char* ControlBridge::session_phase() const {
    return citra_control::session_phase_name(impl_->plane.session_phase());
}

void ControlBridge::observe_heartbeat(const std::array<std::uint8_t, 4>& sender, std::uint8_t kind,
                                      std::uint16_t seq, std::uint16_t rel_time,
                                      std::uint16_t time_echo) {
    auto& window = impl_->heartbeat_window;
    window.push_back({kind, sender, seq, rel_time, time_echo});
    ++impl_->counters["heartbeat_observations"];
    if (window.size() > kHeartbeatWindowMax) {
        window.erase(window.begin(), window.begin() + (window.size() - kHeartbeatWindowMax));
    }
    const auto learned = citra_control::learn_heartbeat_pair(window, impl_->heartbeat_options);
    if (learned.learned && impl_->counters["heartbeat_pair_learned"] == 0) {
        ++impl_->counters["heartbeat_pair_learned"];
        impl_->diag.note_event("heartbeat_pair", "learned");
    }
}

bool ControlBridge::heartbeat_pair_learned() const {
    return impl_->counters.at("heartbeat_pair_learned") != 0;
}
const std::vector<ControlStation>& ControlBridge::stations() const { return impl_->stations; }

namespace {
// V-277: MHGU join requests (kind 1, route 01000000, 120 bytes, built by
// JoinMeshJob::SendJoinRequest) carry the hall-host endpoint first, while MHXX
// parses an 80-byte body whose descriptor must open with the requester's own
// endpoint (.verify-r26/g4/v276-mhxx-kind0/REPORT.md §3,
// docs/mhgu-join-response-static-evidence.json).  GU body offsets from packet
// offset 32: +4 host endpoint(6), +10 host short id(2), +12 self endpoint(6),
// +18 self endpoint(6), +24 self id(6), +30 self word(4), +34..81 zeros,
// +82 counter(4), +86 trailer(2).  The XX body keeps the self endpoint at +4
// and supplies a canonical nonzero XX identity in BOTH subrecords. XX can
// resync an existing station by endpoint after its full-descriptor lookup
// misses (7EA958 -> 7EAA90 -> 7EAE94). Both identities must be valid, otherwise
// the asymmetric partial-identity rejection at7EA90C may run. Zeroing both
// bypassed that rejection but later made7DE554 skip the remote game member.
// Counter moves to +74, trailer to +78 — eight bytes shorter.  Returns false
// (packet untouched) for anything that is not the measured join-request shape.
bool restructure_gu_join_request(citra_room::Bytes& packet) {
    if (packet.size() != 120 || packet[5] != 1 || packet[32] != 0x01 ||
        packet[34] != 0x07 || packet[35] != 0x00) {
        return false;
    }
    if (citra_control::load_u32be(packet.data() + 24) != 0x01000000u) {
        return false;
    }
    const std::uint8_t* self_word = packet.data() + 44;
    const std::uint8_t* host_word = packet.data() + 36;
    if (!std::equal(self_word, self_word + 4, packet.data() + 50) ||
        !std::equal(self_word, self_word + 4, packet.data() + 62) ||
        std::equal(self_word, self_word + 4, host_word)) {
        return false;
    }
    citra_room::Bytes out;
    out.reserve(112);
    out.insert(out.end(), packet.begin(), packet.begin() + 36);
    out.insert(out.end(), packet.begin() + 44, packet.begin() + 50);
    out.resize(106, 0x00);
    // XX's identity includes its endpoint6; retain the original GU station's
    // short id as the final2 bytes. The existing word translator maps every
    // endpoint consistently. Repeating the same identity in both descriptors
    // selects XX's native endpoint-resync path, which copies it into the
    // registry before admission. No emulator memory or callback is patched.
    std::array<std::uint8_t, 8> identity{};
    std::copy_n(packet.begin() + 44, 6, identity.begin());
    std::copy_n(packet.begin() + 56, 2, identity.begin() + 6);
    for (const std::size_t endpoint : {36u, 65u, 71u, 100u}) {
        std::copy_n(packet.begin() + 44, 6, out.begin() + endpoint);
    }
    for (const std::size_t id : {42u, 77u}) {
        std::copy(identity.begin(), identity.end(), out.begin() + id);
    }
    // XX's endpoint fallback also searches descriptor+0x24, decoded from
    // subrecord wire+18. Zero here aliases the first admitted guest when a
    // later endpoint has no station yet (7EA9C4 -> AC3638 -> 7EAA70 state6).
    // Bind both embedded address words to the same guest as its endpoints.
    for (const std::size_t embedded : {54u, 89u})
        std::copy_n(packet.begin() + 44, 4, out.begin() + embedded);
    out.insert(out.end(), packet.begin() + 114, packet.begin() + 118);
    out.push_back(0x00);
    out.push_back(0x00);
    out[14] = 0x00;
    out[15] = 78;
    packet = std::move(out);
    return true;
}

// V-277: MHXX's join accept (kind 0, route 01000000, 112 bytes, body
// [01 tag 07 01][host endpoint(6)][host endpoint(6)][host id(6)][host word(4)]
// [zeros 48][counter(4)][trailer(2)]) must reach MHGU in its own 120-byte
// layout [01 tag 07 01][gu endpoint(6)][gu short(2)][host endpoint(6)]
// [host endpoint(6)][host id(6)][host word(4)][zeros 48][counter(4)]
// [trailer(2)] — AnalyzeJoinResponse validates the requester endpoint first.
// The GU endpoint and short id come from the stashed join request.
bool expand_xx_join_accept(const citra_room::Bytes& packet, const std::uint8_t* gu_endpoint,
                           const std::uint8_t* gu_short, citra_room::Bytes& out) {
    if (packet.size() != 112 || packet[5] != 0 || packet[32] != 0x01 ||
        packet[34] != 0x07 || packet[35] != 0x01) {
        return false;
    }
    if (citra_control::load_u32be(packet.data() + 24) != 0x01000000u) {
        return false;
    }
    out.assign(packet.begin(), packet.begin() + 36);
    out.insert(out.end(), gu_endpoint, gu_endpoint + 6);
    out.insert(out.end(), gu_short, gu_short + 2);
    out.insert(out.end(), packet.begin() + 36, packet.begin() + 58);
    out.insert(out.end(), 48, 0x00);
    out.insert(out.end(), packet.begin() + 106, packet.begin() + 110);
    out.push_back(0x00);
    out.push_back(0x00);
    out[14] = 0x00;
    out[15] = 86;
    return true;
}
}  // namespace

std::vector<ControlEmission> ControlBridge::on_gu_host_proxy(
    const room_client::IPv4& source, const citra_room::Bytes& plain) {
    if (!gu_host_source(source) || plain.size() > 1472) return {};
    const auto framed = split_mh_inner_messages(plain);
    if (framed.malformed) return {};
    if (framed.messages.size() > 1) {
        citra_room::Bytes joined(plain.begin(), plain.begin() + 12);
        std::vector<ControlEmission> result;
        citra_control::SecureDataFrame secure;
        for (const auto& message : framed.messages) {
            const auto converted = on_gu_host_proxy(source, make_mh_inner_packet(plain, message));
            if (converted.size() != 1 || !converted[0].to_citra) return {};
            const auto decoded = citra_control::parse_secure_data_frame(
                converted[0].citra_data.data(), converted[0].citra_data.size());
            if (!decoded.ok()) return {};
            if (result.empty()) { result = converted; secure = decoded.value; }
            else if (secure.header.dest_node_id != decoded.value.header.dest_node_id) return {};
            joined.insert(joined.end(), decoded.value.payload.begin() + 12, decoded.value.payload.end());
        }
        joined.insert(joined.end(), framed.trailer.begin(), framed.trailer.end());
        secure.payload = std::move(joined);
        const auto encoded = citra_control::build_secure_data_frame(secure);
        if (!encoded.ok() || secure.payload.size() > 1472) return {};
        result[0].citra_data = encoded.value;
        result[0].kind = "citra.gu_host.compound";
        return result;
    }
    auto translated = translate_gu_host_announcement(source, plain);
    if (translated) {
        // Native GU table B is a LE pair of halfwords; JoinRequest's target
        // short serializes the first halfword BE (healthy v266 paired wire).
        impl_->gu_admission->host_short = {plain[53], plain[52]};
        impl_->gu_admission->have_host_short = true;
    } else if (gu_host_source(source) && plain.size() == 120 &&
               impl_->gu_admission->have_guest_descriptor &&
               plain[0] == 0x32 && plain[1] == 0xab && plain[2] == 0x98 &&
               plain[3] == 0x64 && plain[4] == 1 && (plain[5] == 0 || plain[5] == 1) &&
               citra_control::load_u16be(plain.data() + 14) == 86 &&
               citra_control::load_u32be(plain.data() + 24) == 0x01000000u &&
               plain[32] == 1 && plain[34] == 7 && plain[35] == 1 &&
               std::equal(impl_->session_fake_ip.begin(), impl_->session_fake_ip.end(), plain.begin() + 36) &&
               plain[40] == 0x30 && plain[41] == 0x39 &&
               plain[42] == impl_->gu_admission->guest_descriptor[12] &&
               plain[43] == impl_->gu_admission->guest_descriptor[13] &&
               std::equal(source.begin(), source.end(), plain.begin() + 44) &&
               std::equal(source.begin(), source.end(), plain.begin() + 50) &&
               std::equal(source.begin(), source.end(), plain.begin() + 62)) {
        citra_room::Bytes reply(plain.begin(), plain.begin() + 36);
        // Remove only the GU-only addressed endpoint8. Preserve BOTH complete
        // serialized descriptor subrecords (70B), plus counter and trailer.
        reply.insert(reply.end(), plain.begin() + 44, plain.end());
        reply[15] = 78;
        reply[5] = 0;
        const auto host_word = mhxx_identity_word_from_seed(
            impl_->opt.have_uds_host_seed ? impl_->opt.uds_host_seed : 0);
        if (std::equal(source.begin(), source.end(), reply.begin() + 20))
            std::copy(host_word.begin(), host_word.end(), reply.begin() + 20);
        // Endpoint fields of the two native 35B subrecords only; never scan
        // arbitrary identity/counter bytes for accidental IP matches.
        for (const auto offset : {36u, 42u, 54u, 65u, 71u, 89u, 100u}) {
            if (std::equal(source.begin(), source.end(), reply.begin() + offset))
                std::copy(host_word.begin(), host_word.end(), reply.begin() + offset);
        }
        translated = std::move(reply);
        std::copy_n(plain.begin() + 44, 70, impl_->gu_admission->host_descriptor.begin());
        impl_->gu_admission->host_stream_kind = plain[33];
        impl_->gu_admission->have_host_descriptor = true;
    } else if (gu_host_source(source) && impl_->gu_admission->have_host_descriptor &&
               plain.size() >= 36 && plain.size() <= 1472 &&
               plain[0] == 0x32 && plain[1] == 0xab && plain[2] == 0x98 &&
               plain[3] == 0x64 && plain[4] == 1 &&
               std::equal(source.begin(), source.end(), plain.begin() + 20) &&
               (citra_control::load_u32be(plain.data() + 24) == 0x20000000u ||
                citra_control::load_u32be(plain.data() + 24) == 0x02100000u ||
                citra_control::load_u32be(plain.data() + 24) == 0x02000001u) &&
               plain[5] == impl_->gu_admission->host_stream_kind &&
               citra_control::load_u16be(plain.data() + 14) >= 4 &&
               citra_control::load_u16be(plain.data() + 14) <= plain.size() - 32) {
        // Negotiated stream body is opaque. Only its outer sender is mapped.
        translated = plain;
        const auto word = mhxx_identity_word_from_seed(
            impl_->opt.have_uds_host_seed ? impl_->opt.uds_host_seed : 0);
        std::copy(word.begin(), word.end(), translated->begin() + 20);
    } else if (gu_host_source(source) && impl_->gu_admission->have_host_descriptor &&
               plain.size() >= 196 && plain.size() <= 340 &&
               plain[0] == 0x32 && plain[1] == 0xab && plain[2] == 0x98 &&
               plain[3] == 0x64 && plain[4] == 1 && plain[5] == 0 &&
               citra_control::load_u32be(plain.data() + 24) == 0x02000000u &&
               plain[33] >= 2 && plain[33] <= 4 && plain[34] == 0 &&
               ((plain[32] == 2 && plain[35] == plain[33] - 1 &&
                 plain.size() == 52u + 72u * plain[33] &&
                 citra_control::load_u16be(plain.data() + 14) == plain.size() - 32) ||
                (plain[32] == 0x20 && plain[35] == 0 && plain.size() == 332 &&
                 citra_control::load_u16be(plain.data() + 14) == 300)) &&
               std::equal(source.begin(), source.end(), plain.begin() + 20)) {
        const auto& admission = *impl_->gu_admission;
        const std::size_t host_offset = plain[32] == 2 ? 48 : 44;
        const auto count = plain[33];
        if (!std::equal(admission.host_descriptor.begin(), admission.host_descriptor.end(),
                        plain.begin() + host_offset)) return {};
        auto peers = impl_->all_gu_guests();
        for (unsigned slot = 1; slot < count; ++slot) {
            const auto offset = host_offset + 72 * slot;
            for (auto& [mac, peer] : peers) {
                if (!impl_->gu_native_peers.count(mac)) continue;
                if (!std::equal(peer.guest_ip.begin(), peer.guest_ip.end(), plain.begin() + offset) ||
                    plain[offset + 4] != 0x30 || plain[offset + 5] != 0x39 ||
                    !std::equal(peer.guest_ip.begin(), peer.guest_ip.end(), plain.begin() + offset + 6) ||
                    !std::equal(peer.guest_ip.begin(), peer.guest_ip.end(), plain.begin() + offset + 18)) continue;
                if (peer.have_descriptor && !std::equal(peer.descriptor.begin(), peer.descriptor.end(),
                                                        plain.begin() + offset)) return {};
                std::copy_n(plain.begin() + offset, 70, peer.descriptor.begin());
                peer.have_descriptor = true;
            }
        }
        translated = plain;
        bool own_seen = false;
        std::vector<citra_room::MacAddress> seen;
        for (unsigned slot = 1; slot < count; ++slot) {
            const auto offset = host_offset + 72 * slot;
            bool matched = false;
            for (const auto& [mac, peer] : peers) {
                if (!peer.have_descriptor || std::find(seen.begin(), seen.end(), mac) != seen.end()) continue;
                const auto& network = admission.hall.network;
                const auto name = citra_control::username_to_bytes(peer.node.username);
                const bool authenticated = std::any_of(network.ldn.nodes.begin(), network.ldn.nodes.end(),
                    [&](const auto& node) {
                        auto ip = node.ipv4_address; std::reverse(ip.begin(), ip.end());
                        return node.is_connected && node.mac_address == mac && ip == peer.guest_ip &&
                               name.ok() && name.value == node.user_name;
                    });
                if (!authenticated) continue;
                auto native = peer.descriptor;
                const auto word = mhxx_identity_word_from_seed(peer.node.friend_code_seed);
                for (const auto field : {0u, 6u, 18u, 29u, 35u, 53u, 64u})
                    if (std::equal(word.begin(), word.end(), native.begin() + field))
                        std::copy(peer.guest_ip.begin(), peer.guest_ip.end(), native.begin() + field);
                if (!std::equal(native.begin(), native.end(), plain.begin() + offset)) continue;
                const auto xx = impl_->gu_native_peers.count(mac) ?
                    canonical_gu_descriptor(peer.descriptor, word) : peer.descriptor;
                std::copy(xx.begin(), xx.end(), translated->begin() + offset);
                seen.push_back(mac); own_seen |= mac == admission.guest; matched = true; break;
            }
            // Preserve the standalone two-player bridge API as well as gateway snapshots.
            if (!matched && !own_seen) {
                auto native = admission.guest_descriptor;
                const auto word = mhxx_identity_word_from_seed(admission.identity.friend_code_seed);
                for (const auto field : {0u, 6u, 18u, 29u, 35u, 53u, 64u})
                    if (std::equal(word.begin(), word.end(), native.begin() + field))
                        std::copy(impl_->session_fake_ip.begin(), impl_->session_fake_ip.end(), native.begin() + field);
                if (std::equal(native.begin(), native.end(), plain.begin() + offset)) {
                    std::copy(admission.guest_descriptor.begin(), admission.guest_descriptor.end(),
                              translated->begin() + offset);
                    own_seen = matched = true;
                }
            }
            if (!matched) return {};
        }
        if (!own_seen) return {};
        for (auto& [mac, peer] : impl_->gu_native_peers) peer = peers.at(mac);
        const auto word = mhxx_identity_word_from_seed(
            impl_->opt.have_uds_host_seed ? impl_->opt.uds_host_seed : 0);
        std::copy(word.begin(), word.end(), translated->begin() + 20);
        for (const auto field : {0u, 6u, 18u, 29u, 35u, 53u, 64u})
            if (std::equal(source.begin(), source.end(), translated->begin() + host_offset + field))
                std::copy(word.begin(), word.end(), translated->begin() + host_offset + field);
    } else if (gu_host_source(source) && impl_->gu_admission->have_host_descriptor &&
               plain.size() == 48 && plain[0] == 0x32 && plain[1] == 0xab &&
               plain[2] == 0x98 && plain[3] == 0x64 && plain[4] == 1 &&
               (plain[5] == 0 || plain[5] == impl_->gu_admission->host_stream_kind) &&
               citra_control::load_u32be(plain.data() + 24) == 0x06000000u &&
               citra_control::load_u16be(plain.data() + 14) == 16 &&
               std::equal(source.begin(), source.end(), plain.begin() + 20)) {
        translated = plain;
        const auto word = mhxx_identity_word_from_seed(
            impl_->opt.have_uds_host_seed ? impl_->opt.uds_host_seed : 0);
        std::copy(word.begin(), word.end(), translated->begin() + 20);
    } else if (gu_host_source(source) && impl_->gu_admission->have_guest_descriptor &&
               (plain.size() == 40 || plain.size() == 828) &&
               plain[0] == 0x32 && plain[1] == 0xab && plain[2] == 0x98 &&
               plain[3] == 0x64 && plain[4] == 1 && plain[5] == 0 &&
               citra_control::load_u32be(plain.data() + 24) == 0x01000000u &&
               std::equal(source.begin(), source.end(), plain.begin() + 20)) {
        if (plain.size() == 40 &&
            citra_control::load_u16be(plain.data() + 14) == 8 &&
            plain[32] == 5 && plain[33] == 0 && plain[34] == 0 && plain[35] == 0) {
            translated = plain;
        } else if (plain.size() == 828) {
            // V309 native V308 host replies use the same GU blob layout as
            // the measured forward guest. Adapt role only around the codec.
            auto guest_form = plain;
            guest_form[5] = 1;
            translated = impl_->convert_blob_gu_to_xx(guest_form);
            if (translated) (*translated)[5] = 0;
        }
        if (translated) {
            const auto host_word = mhxx_identity_word_from_seed(
                impl_->opt.have_uds_host_seed ? impl_->opt.uds_host_seed : 0);
            std::copy(host_word.begin(), host_word.end(), translated->begin() + 20);
        }
    } else if (gu_host_source(source) && plain.size() == 52 &&
               plain[0] == 0x32 && plain[1] == 0xab && plain[2] == 0x98 &&
               plain[3] == 0x64 && plain[4] == 1 && (plain[5] == 0 || plain[5] == 1) &&
               citra_control::load_u16be(plain.data() + 14) == 20 &&
               citra_control::load_u32be(plain.data() + 24) == 0x03003039u &&
               plain[32] == 1 && plain[33] == 0x21 && plain[34] == 0 && plain[35] == 0) {
        translated = plain;
        const auto host_word = mhxx_identity_word_from_seed(
            impl_->opt.have_uds_host_seed ? impl_->opt.uds_host_seed : 0);
        if (std::equal(source.begin(), source.end(), translated->begin() + 20))
            std::copy(host_word.begin(), host_word.end(), translated->begin() + 20);
    }
    if (!translated) return {};
    citra_control::SecureDataFrame secure;
    // Real MHXX PIA channel: healthy V301 (1478 decoded frames) and V304/V305.
    // 33 belongs only to the generic SecureData codec test fixture.
    secure.header.data_channel = 243;
    secure.header.src_node_id = 1;
    secure.header.dest_node_id = 0xffff;
    if (plain.size() != 140 && plain.size() != 52) {
        const auto& network = impl_->gu_admission->hall.network;
        for (std::size_t i = 1; i < network.ldn.node_count_max; ++i)
            if (network.ldn.nodes[i].is_connected &&
                network.ldn.nodes[i].mac_address == impl_->gu_admission->guest)
                secure.header.dest_node_id = static_cast<std::uint16_t>(i + 1);
    }
    secure.payload = *translated;
    const auto encoded = citra_control::build_secure_data_frame(secure, nullptr);
    if (!encoded.ok()) return {};
    ControlEmission emission;
    emission.to_citra = true;
    emission.kind = plain.size() == 140 ? "citra.gu_host.announcement" :
        (plain.size() == 120 ? "citra.gu_host.join_accept" :
         (plain.size() == 40 ? "citra.gu_host.ack" :
          (plain.size() == 828 ? "citra.gu_host.session_blob" : "citra.gu_host.session")));
    emission.citra_type = citra_room::FrameType::Data;
    emission.have_citra_addresses = true;
    emission.citra_transmitter = impl_->gu_admission->hall.network.common.bssid;
    emission.citra_destination = impl_->gu_admission->guest;
    emission.citra_data = encoded.value;
    return {emission};
}

bool ControlBridge::accepts_gu_host_peer_wifi(const citra_room::WifiPacket& wifi) const {
    if (!impl_->gu_admission || !gu_host_source(impl_->gu_admission->hall.source) ||
        wifi.type != citra_room::FrameType::Data || wifi.transmitter == impl_->gu_admission->guest ||
        (wifi.destination != impl_->gu_admission->guest && wifi.destination != citra_room::broadcast_mac))
        return false;
    const auto peer = impl_->gu_guest_identities.find(wifi.transmitter);
    if (peer == impl_->gu_guest_identities.end()) return false;
    const auto secure = citra_control::parse_secure_data_frame(wifi.data.data(), wifi.data.size());
    if (!secure.ok() || secure.value.header.data_channel != 243) return false;
    const auto& network = impl_->gu_admission->hall.network;
    std::uint16_t source_id = 0, destination_id = 0;
    const auto name = citra_control::username_to_bytes(peer->second.node.username);
    if (!name.ok()) return false;
    for (std::size_t i = 1; i < network.ldn.node_count_max; ++i) {
        const auto& node = network.ldn.nodes[i];
        if (!node.is_connected || node.node_id != static_cast<int>(i)) continue;
        if (node.mac_address == impl_->gu_admission->guest) destination_id = i + 1;
        if (node.mac_address == wifi.transmitter) {
            auto ip = node.ipv4_address; std::reverse(ip.begin(), ip.end());
            if (ip != peer->second.guest_ip || node.user_name != name.value) return false;
            source_id = i + 1;
        }
    }
    return source_id && destination_id && secure.value.header.src_node_id == source_id &&
           secure.value.header.dest_node_id ==
               (wifi.destination == citra_room::broadcast_mac ? 0xffff : destination_id);
}

std::vector<ControlEmission> ControlBridge::on_gu_host_guest_game(
    const citra_room::WifiPacket& wifi) {
    if (!impl_->gu_admission || !gu_host_source(impl_->gu_admission->hall.source)) return {};
    auto& admission = *impl_->gu_admission;
    const auto& host = admission.hall.network.common.bssid;
    if (wifi.transmitter != admission.guest ||
        (wifi.destination != host && wifi.destination != citra_room::broadcast_mac)) return {};
    const auto secure = citra_control::parse_secure_data_frame(wifi.data.data(), wifi.data.size());
    if (!secure.ok() || secure.value.header.data_channel != 243 ||
        (secure.value.header.dest_node_id != 1 && secure.value.header.dest_node_id != 0xffff)) return {};
    std::uint16_t assigned = 0;
    for (std::size_t i = 1; i < admission.hall.network.ldn.node_count_max; ++i)
        if (admission.hall.network.ldn.nodes[i].is_connected &&
            admission.hall.network.ldn.nodes[i].mac_address == admission.guest)
            assigned = static_cast<std::uint16_t>(i + 1);
    if (!assigned || secure.value.header.src_node_id != assigned) return {};
    const auto& plain = secure.value.payload;
    const auto framed = split_mh_inner_messages(plain);
    if (framed.malformed || plain.size() > 1472) return {};
    if (framed.messages.size() > 1) {
        citra_room::Bytes joined(plain.begin(), plain.begin() + 12);
        for (const auto& message : framed.messages) {
            auto inner = secure.value;
            inner.payload = make_mh_inner_packet(plain, message);
            auto nested = wifi;
            const auto encoded = citra_control::build_secure_data_frame(inner);
            if (!encoded.ok()) return {};
            nested.data = encoded.value;
            const auto converted = on_gu_host_guest_game(nested);
            if (converted.size() != 1 || !converted[0].room_proxy ||
                converted[0].proxy_broadcast) return {};
            const auto& bytes = converted[0].proxy_data;
            joined.insert(joined.end(), bytes.begin() + 12, bytes.end());
        }
        joined.insert(joined.end(), framed.trailer.begin(), framed.trailer.end());
        if (joined.size() > 1472) return {};
        ControlEmission emission;
        emission.kind = "room.gu_host.compound";
        emission.room_proxy = true;
        emission.proxy_remote_ip = admission.hall.source;
        emission.proxy_data = std::move(joined);
        return {emission};
    }
    if (plain.size() < 36 || plain[0] != 0x32 || plain[1] != 0xab || plain[2] != 0x98 ||
        plain[3] != 0x64 || plain[4] != 1) return {};
    const auto route = citra_control::load_u32be(plain.data() + 24);
    const bool stream = admission.have_host_descriptor &&
        plain[5] == admission.guest_stream_kind &&
        (route == 0x20000000u || route == 0x02100000u || route == 0x02000001u) &&
        citra_control::load_u16be(plain.data() + 14) >= 4 &&
        citra_control::load_u16be(plain.data() + 14) <= plain.size() - 32;
    // Native XX switches session control from role1 to role0 after connect;
    // heartbeat can also carry the negotiated guest kind. Compound packets
    // inherit their outer kind for every inner message.
    const bool session_kind = admission.have_host_descriptor &&
        (plain[5] == 0 || plain[5] == admission.guest_stream_kind);
    const bool keepalive = session_kind && plain.size() == 48 && route == 0x06000000u &&
        citra_control::load_u16be(plain.data() + 14) == 16;
    const bool control_stream_ack = session_kind && plain.size() == 48 && route == 0x02100000u &&
        citra_control::load_u16be(plain.data() + 14) == 16;
    const bool management = plain.size() == 52 && route == 0x03003039u &&
        citra_control::load_u16be(plain.data() + 14) == 20 &&
        plain[32] == 1 && plain[33] == 0x21 && plain[34] == 0 && plain[35] == 0;
    const bool request = plain.size() == 112 && route == 0x01000000u &&
        citra_control::load_u16be(plain.data() + 14) == 78 &&
        plain[32] == 1 && plain[34] == 7 && plain[35] == 0;
    // V308: actual V307 guest traffic advances beyond accept to ACK40 and
    // family02 blob268 (also coalesced as296). Keep their native counters.
    const bool ack = plain.size() == 40 && route == 0x01000000u &&
        citra_control::load_u16be(plain.data() + 14) == 8 &&
        plain[32] == 5 && plain[33] == 0 && plain[34] == 0 && plain[35] == 0;
    const bool blob = plain.size() == 268 && route == 0x01000000u &&
        citra_control::load_u16be(plain.data() + 14) == 235 &&
        plain[32] == 2 && plain[33] == 0 && plain[34] == 7 && plain[35] == 2;
    const bool connect = plain.size() == 48 && route == 0x02000000u &&
        citra_control::load_u16be(plain.data() + 14) == 14 &&
        plain[32] == 1 && plain[34] == 0 && plain[35] == 0 &&
        plain[40] == 0x30 && plain[41] == 0x39;
    // Local XX peers switch to role0 after accepting a direct connection,
    // including their family02 session blob. Require the established peer
    // descriptor and the same session-kind gate used by post-accept ACKs.
    if (!stream && plain[5] != 1 && !keepalive && !control_stream_ack &&
        !((ack || blob) && session_kind)) return {};
    if (!management && !request && !ack && !blob && !connect && !stream && !keepalive && !control_stream_ack) return {};
    if ((ack || blob || connect) && !admission.have_guest_descriptor) return {};
    const auto guest_word = mhxx_identity_word_from_seed(admission.identity.friend_code_seed);
    const auto host_word = mhxx_identity_word_from_seed(
        impl_->opt.have_uds_host_seed ? impl_->opt.uds_host_seed : 0);
    citra_room::Bytes translated = plain;
    if (connect) {
        if (!std::equal(guest_word.begin(), guest_word.end(), plain.begin() + 36)) return {};
        std::copy(impl_->session_fake_ip.begin(), impl_->session_fake_ip.end(), translated.begin() + 36);
    }
    if (blob) {
        auto host_form = plain;
        host_form[5] = 0;
        std::size_t mapped = 0;
        auto expanded = impl_->convert_session_blob_xx_to_gu(host_form, mapped);
        if (!expanded || admission.hall.network.ldn.advertise_data_size != 200) return {};
        translated = std::move(*expanded);
        translated[5] = 1;
        // The reversed host's identifier comes from THIS hall, never the
        // forward host template embedded by the existing layout converter.
        const auto& advert = admission.hall.network.ldn.advertise_data;
        std::copy_n(advert.begin() + 0x14, 8, translated.begin() + 0x25);
    }
    if (request) {
        if (!admission.have_host_short ||
            !std::equal(guest_word.begin(), guest_word.end(), plain.begin() + 36) ||
            !std::equal(guest_word.begin(), guest_word.end(), plain.begin() + 42) ||
            !std::equal(guest_word.begin(), guest_word.end(), plain.begin() + 54) ||
            plain[40] != 0x30 || plain[41] != 0x39 || plain[46] != 0x30 || plain[47] != 0x39)
            return {};
        translated.assign(plain.begin(), plain.begin() + 36);
        translated.insert(translated.end(), admission.hall.source.begin(), admission.hall.source.end());
        translated.insert(translated.end(), {0x30, 0x39});
        translated.insert(translated.end(), admission.host_short.begin(), admission.host_short.end());
        translated.insert(translated.end(), plain.begin() + 36, plain.end());
        translated[15] = 86;
        for (const auto offset : {44u, 50u, 62u, 73u, 79u, 97u, 108u}) {
            if (std::equal(guest_word.begin(), guest_word.end(), translated.begin() + offset))
                std::copy(impl_->session_fake_ip.begin(), impl_->session_fake_ip.end(), translated.begin() + offset);
        }
    }
    if (std::equal(guest_word.begin(), guest_word.end(), translated.begin() + 20))
        std::copy(impl_->session_fake_ip.begin(), impl_->session_fake_ip.end(), translated.begin() + 20);
    else if (std::equal(host_word.begin(), host_word.end(), translated.begin() + 20)) return {};
    else if (std::any_of(translated.begin() + 20, translated.begin() + 24, [](auto b) { return b != 0; })) return {};
    if (request) {
        std::copy_n(plain.begin() + 36, 70, admission.guest_descriptor.begin());
        admission.have_guest_descriptor = true;
        admission.guest_stream_kind = plain[33];
    }
    ControlEmission emission;
    emission.kind = request ? "room.gu_host.join_request" :
        (ack ? "room.gu_host.ack" : (blob ? "room.gu_host.session_blob" :
         (connect ? "room.gu_host.connect" : "room.gu_host.management")));
    emission.room_proxy = true;
    emission.proxy_broadcast = management;
    emission.proxy_remote_ip = admission.hall.source;
    emission.proxy_data = std::move(translated);
    return {emission};
}

std::vector<ControlEmission> ControlBridge::on_citra_host_peer_game(
    const citra_room::WifiPacket& wifi, const CitraHostPeerIdentity& local,
    std::uint64_t now_ms) {
    if (!impl_->opt.ldn_game_return || !impl_->citra_beacon_seen ||
        wifi.type != citra_room::FrameType::Data || wifi.transmitter != local.mac ||
        local.assigned_node_id < 2 || local.assigned_node_id > 4 ||
        ip_is_zero(local.ip) || is_sentinel_ip(local.ip)) return {};
    const auto secure = citra_control::parse_secure_data_frame(wifi.data.data(), wifi.data.size());
    if (!secure.ok() || secure.value.header.data_channel != 243 ||
        secure.value.header.src_node_id != local.assigned_node_id) return {};
    impl_->local_citra_peers[local.mac] = local;
    if (wifi.destination == citra_room::broadcast_mac) {
        if (secure.value.header.dest_node_id != 0xffff) return {};
        std::vector<ControlEmission> result;
        for (const auto& station : impl_->stations) {
            if (station.guest_inject_state != GuestInjectionState::Done || !station.have_uds_node_id) continue;
            auto directed = secure.value;
            directed.header.dest_node_id = station.uds_node_id;
            const auto encoded = citra_control::build_secure_data_frame(directed);
            if (!encoded.ok()) return {};
            auto packet = wifi;
            packet.destination = station.mac;
            packet.data = encoded.value;
            auto emissions = on_citra_host_peer_game(packet, local, now_ms);
            result.insert(result.end(), emissions.begin(), emissions.end());
        }
        return result;
    }
    const ControlStation* remote = nullptr;
    for (const auto& station : impl_->stations) {
        if (station.mac == wifi.destination && station.have_uds_node_id &&
            station.uds_node_id == secure.value.header.dest_node_id &&
            station.guest_inject_state == GuestInjectionState::Done &&
            station.have_guest_identity_word) remote = &station;
    }
    if (remote) impl_->select_return_peer(remote->fake_ip);
    if (!remote || remote->uds_node_id == local.assigned_node_id ||
        !impl_->have_return_join_fields ||
        !std::equal(remote->fake_ip.begin(), remote->fake_ip.end(),
                    impl_->return_gu_endpoint.begin())) return {};
    const auto key = std::make_pair(local.mac, remote->fake_ip);
    auto& codec = impl_->citra_host_peers[key];
    if (codec && (codec->impl_->gu_admission->identity.friend_code_seed != local.node.friend_code_seed ||
                  codec->impl_->gu_admission->identity.username != local.node.username ||
                  codec->impl_->gu_admission->node.node_id != local.assigned_node_id - 1 ||
                  codec->impl_->gu_admission->host_short != impl_->return_gu_short)) codec.reset();
    if (!codec) {
        ControlOptions options;
        options.ldn_gu_host_discovery = options.ldn_gu_host_admission = true;
        options.have_uds_host_seed = true;
        options.uds_host_seed = remote->guest_seed;
        options.ldn_identity_pairs = {{remote->guest_identity_word, remote->fake_ip},
            {mhxx_identity_word_from_seed(local.node.friend_code_seed), local.ip}};
        codec = std::make_unique<ControlBridge>(options, local.ip, local.mac);
        Impl::GuAdmission admission;
        admission.state = Impl::GuAdmission::State::Connected;
        admission.guest = local.mac;
        admission.identity = local.node;
        admission.node.node_id = static_cast<std::int8_t>(local.assigned_node_id - 1);
        admission.hall.source = remote->fake_ip;
        admission.hall.network.common.bssid = remote->mac;
        auto& network = admission.hall.network.ldn;
        network.node_count_max = 4;
        network.node_count = 2;
        network.nodes[0].mac_address = remote->mac;
        network.nodes[0].is_connected = 1;
        auto& guest = network.nodes[local.assigned_node_id - 1];
        guest.mac_address = local.mac;
        guest.is_connected = 1;
        guest.node_id = static_cast<std::int8_t>(local.assigned_node_id - 1);
        network.advertise_data_size = 200;
        const auto advert = impl_->advertise_data();
        if (advert.size() == 200) std::copy(advert.begin(), advert.end(), network.advertise_data.begin());
        admission.have_host_short = true;
        admission.host_short = impl_->return_gu_short;
        codec->impl_->gu_admission = std::move(admission);
    }
    codec->impl_->clock_ms = now_ms;
    codec->impl_->gu_admission->hall.received_ms = now_ms;
    auto normalized = secure.value;
    normalized.header.dest_node_id = 1;
    // Normalize only for the shared guest-to-host decoder. Native GU peer
    // requests retain their negotiated kind; peer family02 blobs use role0,
    // unlike the role1 wrapper used when joining a GU host.
    auto& payload = normalized.payload;
    if (payload.size() == 112 && payload[32] == 1 && payload[34] == 7 && payload[35] == 0 &&
        citra_control::load_u32be(payload.data() + 24) == 0x01000000u &&
        citra_control::load_u16be(payload.data() + 14) == 78 && payload[5] == payload[33])
        payload[5] = 1;
    auto packet = wifi;
    const auto encoded = citra_control::build_secure_data_frame(normalized);
    if (!encoded.ok()) return {};
    packet.data = encoded.value;
    auto emissions = codec->on_gu_host_guest_game(packet);
    for (auto& emission : emissions) {
        auto& native = emission.proxy_data;
        if (native.size() == 120 && native[32] == 1 && native[34] == 7 && native[35] == 0 &&
            citra_control::load_u32be(native.data() + 24) == 0x01000000u)
            native[5] = secure.value.payload[5];
        else if (native.size() == 828 && native[32] == 2 && native[33] == 0 &&
                 native[34] == 7 && native[35] == 4 &&
                 citra_control::load_u32be(native.data() + 24) == 0x01000000u)
            native[5] = 0;
        emission.proxy_broadcast = false;
        emission.kind = "room.citra_host.peer";
    }
    return emissions;
}

std::vector<ControlEmission> ControlBridge::on_citra_host_peer_proxy(
    const room_client::IPv4& source, const citra_room::Bytes& plain,
    const CitraHostPeerIdentity& local, std::uint64_t now_ms) {
    const auto station = game_return_station(source);
    if (station) impl_->select_return_peer(source);
    const auto found = impl_->citra_host_peers.find({local.mac, source});
    if (!station || found == impl_->citra_host_peers.end() ||
        local.assigned_node_id < 2 || local.assigned_node_id > 4) return {};
    auto& codec = *found->second;
    if (!codec.impl_->gu_admission ||
        codec.impl_->gu_admission->identity.friend_code_seed != local.node.friend_code_seed ||
        codec.impl_->gu_admission->identity.username != local.node.username ||
        codec.impl_->gu_admission->hall.network.common.bssid != station->mac ||
        !impl_->have_return_join_fields || codec.impl_->gu_admission->host_short != impl_->return_gu_short ||
        codec.impl_->gu_admission->node.node_id != local.assigned_node_id - 1) return {};
    codec.impl_->clock_ms = now_ms;
    codec.impl_->gu_admission->hall.received_ms = now_ms;
    auto normalized = plain;
    const bool accept_shape = plain.size() == 120 && plain[32] == 1 && plain[34] == 7 &&
        plain[35] == 1 &&
        citra_control::load_u32be(plain.data() + 24) == 0x01000000u &&
        citra_control::load_u16be(plain.data() + 14) == 86;
    // The direct peer must be the same GU member already admitted by this
    // host. Its native descriptor is restored on GU-bound roster traffic;
    // XX peers must instead see the exact canonical descriptor installed by
    // the host's original join conversion, including both subrecords.
    if (accept_shape && !std::equal(impl_->return_gu_descriptor.begin(),
                                  impl_->return_gu_descriptor.end(), plain.begin() + 44)) return {};
    const bool peer_accept = accept_shape && plain[5] == plain[33];
    // Real non-host peers reply with their negotiated stream kind in BOTH
    // headers. The shared host codec expects a role wrapper; preserve the
    // actual peer kind when restoring its XX response, as native XX does.
    if (peer_accept) normalized[5] = 1;
    auto emissions = codec.on_gu_host_proxy(source, normalized);
    for (auto& emission : emissions) {
        const auto decoded = citra_control::parse_secure_data_frame(
            emission.citra_data.data(), emission.citra_data.size());
        if (!decoded.ok()) return {};
        auto frame = decoded.value;
        frame.header.src_node_id = station->uds_node_id;
        frame.header.dest_node_id = local.assigned_node_id;
        if (peer_accept) frame.payload[5] = plain[5];
        if (accept_shape) {
            if (frame.payload.size() != 112) return {};
            const auto canonical = canonical_gu_descriptor(impl_->return_gu_descriptor,
                                                             station->guest_identity_word);
            std::copy(canonical.begin(), canonical.end(), frame.payload.begin() + 36);
        }
        const auto encoded = citra_control::build_secure_data_frame(frame);
        if (!encoded.ok()) return {};
        emission.citra_data = encoded.value;
        emission.kind = "citra.citra_host.peer";
    }
    return emissions;
}

std::vector<ControlEmission> ControlBridge::register_citra_host_peer(const CitraHostPeerIdentity& local) {
    if (!impl_->opt.ldn_game_return || !impl_->citra_beacon_seen ||
        local.assigned_node_id < 2 || local.assigned_node_id > 4 ||
        local.node.network_node_id != local.assigned_node_id ||
        is_sentinel_mac(local.mac) || local.mac == impl_->session_mac ||
        ip_is_zero(local.ip) || is_sentinel_ip(local.ip) || local.ip == impl_->session_fake_ip ||
        !citra_control::username_to_bytes(local.node.username).ok()) return {};
    for (const auto& station : impl_->stations)
        if (station.node_id == local.assigned_node_id - 1 || station.mac == local.mac ||
            station.fake_ip == local.ip) return {};
    for (const auto& [mac, peer] : impl_->local_citra_peers)
        if (mac != local.mac && (peer.assigned_node_id == local.assigned_node_id || peer.ip == local.ip)) return {};
    const auto old = impl_->local_citra_peers.find(local.mac);
    if (old == impl_->local_citra_peers.end() && impl_->stations.size() + impl_->local_citra_peers.size() >= 3)
        return {};
    if (old != impl_->local_citra_peers.end() && old->second.ip == local.ip &&
        old->second.assigned_node_id == local.assigned_node_id &&
        old->second.node.friend_code_seed == local.node.friend_code_seed &&
        old->second.node.username == local.node.username) return {};
    if (old != impl_->local_citra_peers.end()) (void)forget_citra_host_peer(local.mac);
    impl_->local_citra_peers[local.mac] = local;
    std::vector<ControlEmission> result;
    for (const auto& station : impl_->stations) result.push_back(impl_->sync_emission(station.fake_ip));
    return result;
}

std::vector<ControlEmission> ControlBridge::forget_citra_host_peer(const citra_room::MacAddress& mac) {
    const bool removed = impl_->local_citra_peers.erase(mac) != 0;
    for (auto it = impl_->citra_host_peers.begin(); it != impl_->citra_host_peers.end();) {
        if (it->first.first == mac) it = impl_->citra_host_peers.erase(it);
        else ++it;
    }
    std::vector<ControlEmission> result;
    if (removed)
        for (const auto& station : impl_->stations) result.push_back(impl_->sync_emission(station.fake_ip));
    return result;
}

bool ControlBridge::gu_host_source(const room_client::IPv4& source) const {
    return impl_->opt.ldn_gu_host_admission && impl_->gu_admission &&
        impl_->gu_admission->state == Impl::GuAdmission::State::Connected &&
        impl_->gu_admission->hall.source == source &&
        impl_->clock_ms - impl_->gu_admission->hall.received_ms <= 5000;
}

std::optional<GuHostGuestIdentity> ControlBridge::gu_host_guest_identity() const {
    if (!impl_->gu_admission || impl_->gu_admission->state == Impl::GuAdmission::State::AwaitStart)
        return std::nullopt;
    const auto& a = *impl_->gu_admission;
    return GuHostGuestIdentity{a.hall.source, impl_->session_fake_ip,
                              a.hall.network.network_id.session_id.high,
                              a.hall.network.network_id.session_id.low, a.guest, a.identity,
                              a.have_guest_descriptor, a.guest_descriptor};
}

void ControlBridge::set_gu_host_guest_identities(const std::vector<GuHostGuestIdentity>& peers) {
    impl_->gu_guest_identities.clear();
    if (!impl_->gu_admission) return;
    const auto& hall = impl_->gu_admission->hall;
    for (const auto& peer : peers) {
        if (peer.host_ip == hall.source && peer.session_high == hall.network.network_id.session_id.high &&
            peer.session_low == hall.network.network_id.session_id.low)
            impl_->gu_guest_identities.emplace(peer.mac, peer);
    }
}

ControlBridge* ControlBridge::Impl::native_reverse_codec(const GuHostGuestIdentity& peer) {
    if (!gu_admission) return nullptr;
    auto& codec = gu_native_reverse_codecs[peer.guest_ip];
    if (!codec) {
        ControlOptions options;
        options.ldn_guest_inject = options.ldn_game_return = options.ldn_announce_forward = true;
        options.ldn_identity_pairs = {
            {mhxx_identity_word_from_seed(gu_admission->identity.friend_code_seed), session_fake_ip}};
        codec = std::make_unique<ControlBridge>(options, session_fake_ip, session_mac);
        codec->impl_->citra_beacon_seen = true;
        ControlStation station;
        station.mac = peer.mac; station.fake_ip = peer.guest_ip;
        station.guest_seed = peer.node.friend_code_seed;
        station.guest_identity_word = mhxx_identity_word_from_seed(station.guest_seed);
        station.have_guest_identity_word = station.have_uds_node_id = true;
        station.uds_node_id = peer.node.network_node_id;
        station.guest_inject_state = GuestInjectionState::Done;
        codec->impl_->stations.push_back(station);
    }
    codec->impl_->stations[0].uds_node_id = peer.node.network_node_id;
    return codec.get();
}

std::vector<ControlEmission> ControlBridge::on_gu_native_peer_proxy(
    const room_client::IPv4& source, const citra_room::Bytes& plain) {
    if (!gu_native_peer_source(source) || plain.size() < 36 || plain.size() > 1472 ||
        (std::any_of(plain.begin()+20,plain.begin()+24,[](auto b){return b != 0;}) &&
         !std::equal(source.begin(), source.end(), plain.begin() + 20))) return {};
    auto it = std::find_if(impl_->gu_native_peers.begin(), impl_->gu_native_peers.end(),
        [&](const auto& entry) { return entry.second.guest_ip == source; });
    if (it == impl_->gu_native_peers.end()) return {};
    auto& peer = it->second;
    const bool request = plain.size() == 120 && plain[32] == 1 && plain[34] == 7 && plain[35] == 0 &&
        citra_control::load_u32be(plain.data() + 24) == 0x01000000u &&
        citra_control::load_u16be(plain.data() + 14) == 86;
    const bool accept = plain.size() == 120 && plain[32] == 1 && plain[34] == 7 && plain[35] == 1 &&
        citra_control::load_u32be(plain.data() + 24) == 0x01000000u &&
        citra_control::load_u16be(plain.data() + 14) == 86;
    if (request || accept) {
        if (!std::equal(impl_->session_fake_ip.begin(), impl_->session_fake_ip.end(), plain.begin() + 36) ||
            plain[40] != 0x30 || plain[41] != 0x39 ||
            !std::equal(source.begin(), source.end(), plain.begin() + 44) ||
            !std::equal(source.begin(), source.end(), plain.begin() + 50) ||
            !std::equal(source.begin(), source.end(), plain.begin() + 62)) return {};
        if (!impl_->gu_admission->have_guest_descriptor ||
            !std::equal(plain.begin() + 42, plain.begin() + 44,
                        impl_->gu_admission->guest_descriptor.begin() + 12)) return {};
        if (peer.have_descriptor && !std::equal(peer.descriptor.begin(), peer.descriptor.end(), plain.begin() + 44)) return {};
    }
    auto normalized = plain;
    if ((request || accept) && plain[5] == plain[33]) normalized[5] = request ? 1 : 0;
    std::vector<ControlEmission> result;
    const auto forward = impl_->gu_native_forward_codecs.find(source);
    if (!request && forward != impl_->gu_native_forward_codecs.end()) {
        forward->second->impl_->clock_ms = impl_->clock_ms;
        forward->second->impl_->gu_admission->hall.received_ms = impl_->clock_ms;
        forward->second->impl_->gu_admission->hall.network = impl_->gu_admission->hall.network;
        forward->second->impl_->gu_admission->hall.network.common.bssid = peer.mac;
        result = forward->second->on_gu_host_proxy(source, normalized);
        if (accept && !result.empty()) {
            auto frame = citra_control::parse_secure_data_frame(result[0].citra_data.data(), result[0].citra_data.size());
            if (!frame.ok() || frame.value.payload.size() != 112) return {};
            std::array<std::uint8_t, 70> descriptor{};
            std::copy_n(plain.begin() + 44, 70, descriptor.begin());
            const auto canonical = canonical_gu_descriptor(descriptor,
                mhxx_identity_word_from_seed(peer.node.friend_code_seed));
            std::copy(canonical.begin(), canonical.end(), frame.value.payload.begin() + 36);
            frame.value.payload[5] = plain[5];
            result[0].citra_data = citra_control::build_secure_data_frame(frame.value).value;
        }
    } else {
        if (!request && !impl_->gu_native_reverse_codecs.count(source)) return {};
        auto* codec = impl_->native_reverse_codec(peer);
        const auto translated = codec->translate_game_return(source, normalized);
        if (!translated) return {};
        citra_control::SecureDataFrame frame;
        frame.header.data_channel = 243;
        frame.payload = *translated;
        if (request) frame.payload[5] = plain[5];
        ControlEmission emission;
        emission.to_citra = true; emission.citra_type = citra_room::FrameType::Data;
        emission.citra_data = citra_control::build_secure_data_frame(frame).value;
        result.push_back(std::move(emission));
    }
    std::uint16_t local_id = 0;
    const auto& network = impl_->gu_admission->hall.network.ldn;
    for (std::size_t i = 1; i < network.node_count_max; ++i)
        if (network.nodes[i].is_connected && network.nodes[i].mac_address == impl_->session_mac) local_id = i + 1;
    if (!local_id) return {};
    for (auto& emission : result) {
        auto frame = citra_control::parse_secure_data_frame(emission.citra_data.data(), emission.citra_data.size());
        if (!frame.ok()) return {};
        frame.value.header.src_node_id = peer.node.network_node_id;
        frame.value.header.dest_node_id = local_id;
        emission.citra_data = citra_control::build_secure_data_frame(frame.value).value;
        emission.have_citra_addresses = true;
        emission.citra_transmitter = peer.mac; emission.citra_destination = impl_->session_mac;
        emission.kind = "citra.gu_native.peer";
    }
    return result;
}

std::vector<ControlEmission> ControlBridge::on_gu_native_peer_game(const citra_room::WifiPacket& wifi) {
    if (!impl_->gu_admission || impl_->gu_admission->state != Impl::GuAdmission::State::Connected ||
        wifi.transmitter != impl_->session_mac || wifi.type != citra_room::FrameType::Data) return {};
    const auto secure = citra_control::parse_secure_data_frame(wifi.data.data(), wifi.data.size());
    if (!secure.ok() || secure.value.header.data_channel != 243) return {};
    std::uint16_t local_id = 0;
    const auto& network = impl_->gu_admission->hall.network.ldn;
    for (std::size_t i = 1; i < network.node_count_max; ++i)
        if (network.nodes[i].is_connected && network.nodes[i].mac_address == impl_->session_mac) local_id = i + 1;
    if (!local_id || secure.value.header.src_node_id != local_id) return {};
    std::vector<ControlEmission> result;
    for (const auto& [mac, peer] : impl_->gu_native_peers) {
        const bool broadcast = wifi.destination == citra_room::broadcast_mac && secure.value.header.dest_node_id == 0xffff;
        if (!broadcast && (wifi.destination != mac || secure.value.header.dest_node_id != peer.node.network_node_id)) continue;
        auto frame = secure.value;
        const auto& plain = frame.payload;
        const bool request = plain.size() == 112 && plain[32] == 1 && plain[34] == 7 && plain[35] == 0 &&
            citra_control::load_u32be(plain.data() + 24) == 0x01000000u;
        const bool accept = plain.size() == 112 && plain[32] == 1 && plain[34] == 7 && plain[35] == 1 &&
            citra_control::load_u32be(plain.data() + 24) == 0x01000000u;
        std::vector<ControlEmission> emissions;
        if (request || impl_->gu_native_forward_codecs.count(peer.guest_ip)) {
            auto& codec = impl_->gu_native_forward_codecs[peer.guest_ip];
            if (!codec) {
                if (!peer.have_descriptor) continue;
                auto options = impl_->opt;
                options.uds_host_seed = peer.node.friend_code_seed;
                options.have_uds_host_seed = true;
                codec = std::make_unique<ControlBridge>(options, impl_->session_fake_ip, impl_->session_mac);
                auto admission = *impl_->gu_admission;
                admission.hall.source = peer.guest_ip;
                admission.hall.network.common.bssid = mac;
                admission.have_host_short = true;
                std::copy_n(peer.descriptor.begin() + 12, 2, admission.host_short.begin());
                admission.have_host_descriptor = false;
                codec->impl_->gu_admission = admission;
            }
            codec->impl_->clock_ms = impl_->clock_ms;
            codec->impl_->gu_admission->hall.received_ms = impl_->clock_ms;
            codec->impl_->gu_admission->hall.network = impl_->gu_admission->hall.network;
            codec->impl_->gu_admission->hall.network.common.bssid = mac;
            frame.header.dest_node_id = 1;
            if (request && frame.payload[5] == frame.payload[33]) frame.payload[5] = 1;
            auto normalized = wifi; normalized.destination = mac;
            normalized.data = citra_control::build_secure_data_frame(frame).value;
            emissions = codec->on_gu_host_guest_game(normalized);
        } else if (impl_->gu_native_reverse_codecs.count(peer.guest_ip)) {
            auto* codec = impl_->native_reverse_codec(peer);
            frame.header.src_node_id = 1; frame.header.dest_node_id = peer.node.network_node_id;
            if (accept && frame.payload[5] == frame.payload[33]) frame.payload[5] = 0;
            emissions = codec->on_citra_game_payload(citra_control::build_secure_data_frame(frame).value);
            for (auto& emission : emissions) {
                if (accept && emission.proxy_data.size() == 120) {
                    // The existing Citra guest's full descriptor must match the
                    // one this native host already installed in its roster.
                    auto descriptor = impl_->gu_admission->guest_descriptor;
                    const auto word = mhxx_identity_word_from_seed(impl_->gu_admission->identity.friend_code_seed);
                    for (const auto at : {0u, 6u, 18u, 29u, 35u, 53u, 64u})
                        if (std::equal(word.begin(), word.end(), descriptor.begin() + at))
                            std::copy(impl_->session_fake_ip.begin(), impl_->session_fake_ip.end(), descriptor.begin() + at);
                    std::copy(descriptor.begin(), descriptor.end(), emission.proxy_data.begin() + 44);
                    emission.proxy_data[5] = plain[5];
                }
            }
        }
        for (auto& emission : emissions) {
            if (!emission.room_proxy) continue;
            emission.proxy_broadcast = false; emission.proxy_remote_ip = peer.guest_ip;
            emission.kind = "room.gu_native.peer";
            result.push_back(std::move(emission));
        }
    }
    return result;
}

void ControlBridge::set_gu_host_native_members(const std::vector<room_client::IPv4>& members) {
    impl_->gu_native_members = members;
    for (auto it = impl_->gu_native_peers.begin(); it != impl_->gu_native_peers.end();) {
        if (std::find(members.begin(), members.end(), it->second.guest_ip) == members.end()) {
            impl_->gu_native_reverse_codecs.erase(it->second.guest_ip);
            impl_->gu_native_forward_codecs.erase(it->second.guest_ip);
            it = impl_->gu_native_peers.erase(it);
        } else ++it;
    }
}

bool ControlBridge::gu_native_peer_source(const room_client::IPv4& source) const {
    if (!impl_->gu_admission || impl_->gu_admission->state != Impl::GuAdmission::State::Connected) return false;
    return std::any_of(impl_->gu_native_peers.begin(), impl_->gu_native_peers.end(),
        [&](const auto& entry) { return entry.second.guest_ip == source; });
}

std::optional<citra_room::Bytes> ControlBridge::translate_gu_host_announcement(
    const room_client::IPv4& source, const citra_room::Bytes& plain) const {
    if (!gu_host_source(source) || plain.size() != 140 ||
        !std::equal(plain.begin(), plain.begin() + 6,
                    citra_room::Bytes{0x32, 0xab, 0x98, 0x64, 1, 0}.begin()) ||
        citra_control::load_u16be(plain.data() + 14) != 105 ||
        citra_control::load_u32be(plain.data() + 24) != 0x03003039u ||
        plain[32] != 1 || plain[33] != 0x11 || plain[34] != 73 || plain[35] != 0 ||
        !std::equal(source.begin(), source.end(), plain.begin() + 20)) return std::nullopt;
    const auto& admission = *impl_->gu_admission;
    const auto& network = admission.hall.network;
    // Only endpoints proven by this selected SyncNetwork may become UDS identities.
    // Additional peers must be authenticated gateway guests of this exact hall.
    // Offset44 is opaque announcement metadata, not a slot count: native
    // rejoin advances it to10 with only two occupied slots. Preserve all four
    // bytes and authorize occupants exclusively against this SyncNetwork.
    if (network.ldn.node_count < 2 || network.ldn.node_count > 4) return std::nullopt;
    const auto host_word = mhxx_identity_word_from_seed(
        impl_->opt.have_uds_host_seed ? impl_->opt.uds_host_seed : 0);
    const auto guest_word = mhxx_identity_word_from_seed(admission.identity.friend_code_seed);
    citra_room::Bytes out(176, 0);
    std::copy_n(plain.begin(), 64, out.begin());
    out[15] = 141;
    out[34] = 109;
    std::copy(host_word.begin(), host_word.end(), out.begin() + 20);
    const auto peers = impl_->all_gu_guests();
    bool host_seen = false, guest_seen = false;
    for (std::size_t i = 0; i < 12; ++i) {
        auto dst = out.begin() + 64 + 9 * i;
        if (i >= 8) { dst[8] = 0xff; continue; }
        const auto src = plain.begin() + 64 + 9 * i;
        const bool occupied = src[0] || src[1] || src[2] || src[3];
        if (!occupied) {
            if (!std::all_of(src, src + 8, [](auto b) { return b == 0; }) ||
                src[8] != 0xff) return std::nullopt;
            dst[8] = 0xff;
            continue;
        }
        if (i >= network.ldn.node_count_max || !network.ldn.nodes[i].is_connected ||
            src[4] != 0x30 || src[5] != 0x39 || src[6] || src[7] || src[8] != i)
            return std::nullopt;
        const bool host = i == 0 && std::equal(source.begin(), source.end(), src);
        const bool guest = network.ldn.nodes[i].mac_address == admission.guest &&
            std::equal(impl_->session_fake_ip.begin(), impl_->session_fake_ip.end(), src);
        std::array<std::uint8_t, 4> word{};
        if (host) word = host_word;
        else if (guest) word = guest_word;
        else {
            const auto peer = peers.find(network.ldn.nodes[i].mac_address);
            if (peer == peers.end() ||
                !std::equal(peer->second.guest_ip.begin(), peer->second.guest_ip.end(), src) ||
                reverse_ip(peer->second.guest_ip) != network.ldn.nodes[i].ipv4_address)
                return std::nullopt;
            const auto name = citra_control::username_to_bytes(peer->second.node.username);
            if (!name.ok() || name.value != network.ldn.nodes[i].user_name) return std::nullopt;
            word = mhxx_identity_word_from_seed(peer->second.node.friend_code_seed);
        }
        host_seen |= host;
        guest_seen |= guest;
        std::copy_n(src, 9, dst);
        std::copy(word.begin(), word.end(), dst);
        dst[7] = static_cast<std::uint8_t>(i + 1);
    }
    if (!host_seen || !guest_seen) return std::nullopt;
    std::copy_n(plain.begin() + 136, 4, out.begin() + 172);
    return out;
}

std::optional<ControlStation> ControlBridge::game_return_station(
    const room_client::IPv4& fake_ip) const {
    if (!impl_->guest_inject || !impl_->citra_beacon_seen) {
        return std::nullopt;
    }
    const ControlStation* found = nullptr;
    for (const ControlStation& station : impl_->stations) {
        if (station.fake_ip != fake_ip) {
            continue;
        }
        if (found != nullptr) {
            return std::nullopt;
        }
        found = &station;
    }
    if (found == nullptr || found->guest_inject_state != GuestInjectionState::Done ||
        !found->have_uds_node_id || found->uds_node_id < 2 ||
        found->uds_node_id > citra_control::kUdsMaxNodes || !found->have_guest_identity_word) {
        return std::nullopt;
    }
    return *found;
}

std::optional<citra_room::Bytes> ControlBridge::translate_game_return(
    const room_client::IPv4& source, const citra_room::Bytes& plain) {
    if (!game_return_station(source)) return std::nullopt;
    if (plain.size() >= 24 &&
        std::any_of(plain.begin()+20,plain.begin()+24,[](auto b){return b != 0;}) &&
        !std::equal(source.begin(),source.end(),plain.begin()+20)) return std::nullopt;
    if (plain.size() == 120 && plain[32] == 1 && plain[34] == 7 && plain[35] == 0 &&
        !std::equal(source.begin(),source.end(),plain.begin()+44)) return std::nullopt;
    impl_->select_return_peer(source);
    struct RestoreSource {
        std::optional<room_client::IPv4>& field;
        std::optional<room_client::IPv4> previous;
        ~RestoreSource() { field = previous; }
    } restore{impl_->bound_return_source, impl_->bound_return_source};
    impl_->bound_return_source = source;
    return translate_game_return(plain);
}

std::optional<citra_room::Bytes> ControlBridge::translate_game_return(
    const citra_room::Bytes& plain) {
    if (plain.size() >= 32) {
        room_client::IPv4 source{};
        std::copy_n(plain.begin() + 20, 4, source.begin());
        if (game_return_station(source)) impl_->select_return_peer(source);
        else if (plain.size() == 120 && plain[32] == 1 && plain[34] == 7 && plain[35] == 0) {
            std::copy_n(plain.begin() + 44, 4, source.begin());
            if (game_return_station(source)) impl_->select_return_peer(source);
        }
    }
    const MhInnerPacket framed = split_mh_inner_messages(plain);
    if (framed.malformed) {
        ++impl_->counters["compound_malformed"];
        return std::nullopt;
    }
    if (framed.messages.size() > 1) {
        if (plain.size() > 1472) {
            ++impl_->counters["compound_oversize"];
            return std::nullopt;
        }
        std::vector<citra_room::Bytes> converted;
        std::size_t total = 12 + framed.trailer.size();
        // Framing is fully checked before translation so a bad later message
        // cannot leave admission state or counters partly updated.
        for (const auto& message : framed.messages) {
            auto standalone = make_mh_inner_packet(plain, message);
            auto result = impl_->bound_return_source ?
                translate_game_return(*impl_->bound_return_source, standalone) : translate_game_return(standalone);
            if (!result.has_value()) {
                continue;
            }
            if (result->size() < 32 || result->size() - 12 > 1460) {
                ++impl_->counters["compound_oversize"];
                return std::nullopt;
            }
            total += result->size() - 12;
            if (total > 1472) {
                ++impl_->counters["compound_oversize"];
                return std::nullopt;
            }
            converted.emplace_back(result->begin() + 12, result->end());
        }
        if (converted.empty()) {
            return std::nullopt;
        }
        citra_room::Bytes joined(plain.begin(), plain.begin() + 12);
        for (const auto& message : converted) {
            joined.insert(joined.end(), message.begin(), message.end());
        }
        joined.insert(joined.end(), framed.trailer.begin(), framed.trailer.end());
        ++impl_->counters["compound_datagrams_translated"];
        return joined;
    }
    if (plain.size() < 32 || plain[0] != 0x32 || plain[1] != 0xab || plain[2] != 0x98 ||
        plain[3] != 0x64 || plain[4] != 1) {
        return std::nullopt;
    }
    const std::uint32_t route = citra_control::load_u32be(plain.data() + 24);
    const bool stream_route = route == 0x20000000u || route == 0x02100000u ||
                              route == 0x02000001u;
    const bool negotiated_kind = impl_->opt.ldn_game_return && impl_->have_return_join_fields &&
        plain[5] == impl_->return_gu_kind &&
        std::equal(impl_->return_gu_endpoint.begin(), impl_->return_gu_endpoint.begin() + 4,
                   plain.begin() + 20) &&
        std::any_of(impl_->stations.begin(), impl_->stations.end(), [&](const auto& s) {
            return s.guest_inject_state == GuestInjectionState::Done &&
                   std::equal(s.fake_ip.begin(), s.fake_ip.end(), impl_->return_gu_endpoint.begin());
        });
    if (stream_route ? (!negotiated_kind || plain.size() < 36 ||
                       citra_control::load_u16be(plain.data() + 14) < 4 ||
                       citra_control::load_u16be(plain.data() + 14) > plain.size() - 32)
                     : (plain[5] != 0 && plain[5] != 1 && !negotiated_kind)) {
        return std::nullopt;
    }
    if (route != 0x03003039u && route != 0x02000000u && route != 0x01000000u &&
        route != 0x06000000u && !stream_route) {
        return std::nullopt;
    }
    // V-279: remember the newest counter MHGU itself announced (40B
    // 05 00 00 00 + u32 on this route) — the 828B blob the host answers with
    // names the receiver's current counter at its tail.
    if (plain.size() == 40 && plain[5] == 1 && plain[32] == 0x05 && plain[33] == 0x00 &&
        plain[34] == 0x00 && plain[35] == 0x00 && route == 0x01000000u) {
        std::copy_n(plain.begin() + 36, 4, impl_->gu_announce_counter.begin());
        impl_->have_gu_announce_counter = true;
    }
    // V-277: rewrite the MHGU join request into the 80-byte body MHXX parses
    // (requester endpoint first) and remember the requester fields the accept
    // expansion needs.  Applied before the word scan, so the stashed endpoint
    // keeps the GU-side words the return direction must reuse verbatim.
    citra_room::Bytes prepared = plain;
    // V-281: MHGU's 828B GU-dialect session blob must reach MHXX as a 268B
    // XX family-02 blob — the XX family-02 handler (0x7eb07c) is what grants
    // the sender's station status 5, and the XX bulk pump only transmits to
    // status-5 stations (.verify-r26/g4/v280-bulk-gate).  Without this the
    // join completes but the bulk session never starts.
    if (impl_->opt.ldn_game_return) {
        if (auto xx_blob = impl_->convert_blob_gu_to_xx(prepared)) {
            prepared = std::move(*xx_blob);
            ++impl_->counters["session_blob_xx_converted"];
        }
    }
    if (impl_->opt.ldn_game_return && restructure_gu_join_request(prepared)) {
        // Stash from the ORIGINAL layout (the restructure moved the self
        // endpoint to +4 and zeroed the rest): endpoint = body+12 (wire 44),
        // short id = high half of the self id u32 at body+24 (wire 56).
        std::copy_n(plain.begin() + 44, 6, impl_->return_gu_endpoint.begin());
        std::copy_n(plain.begin() + 56, 2, impl_->return_gu_short.begin());
        std::copy_n(plain.begin() + 56, 6, impl_->return_gu_station_id.begin());
        std::copy_n(plain.begin() + 44, 70, impl_->return_gu_descriptor.begin());
        impl_->return_gu_kind = plain[33];
        impl_->have_return_join_fields = true;
        ++impl_->counters["join_request_restructured"];
    }

    using Word = std::array<std::uint8_t, 4>;
    std::map<Word, Word> replacements;
    const auto add_replacement = [&replacements](const Word& from, const Word& to) {
        const auto [it, inserted] = replacements.emplace(from, to);
        return inserted || it->second == to;
    };
    for (const auto& pair : impl_->identity_pairs) {
        if (!add_replacement(pair.second, pair.first)) {
            return std::nullopt;
        }
    }
    if (impl_->guest_inject && impl_->citra_beacon_seen) {
        for (const ControlStation& station : impl_->stations) {
            if (station.guest_inject_state != GuestInjectionState::Done ||
                !station.have_uds_node_id || station.uds_node_id < 2 ||
                station.uds_node_id > citra_control::kUdsMaxNodes ||
                !station.have_guest_identity_word) {
                continue;
            }
            if (!add_replacement(station.fake_ip, station.guest_identity_word)) {
                return std::nullopt;
            }
        }
    }

    citra_room::Bytes translated = std::move(prepared);
    const auto replace_at = [&replacements, &translated](std::size_t offset) {
        Word word{};
        std::copy_n(translated.begin() + static_cast<std::ptrdiff_t>(offset), word.size(),
                    word.begin());
        const auto found_word = replacements.find(word);
        if (found_word == replacements.end()) {
            return false;
        }
        std::copy(found_word->second.begin(), found_word->second.end(),
                  translated.begin() + static_cast<std::ptrdiff_t>(offset));
        return true;
    };
    (void)replace_at(20);
    for (std::size_t offset = stream_route ? translated.size() : 32;
         offset + 4 <= translated.size();) {
        if (replace_at(offset)) {
            offset += 4;
        } else {
            ++offset;
        }
    }
    return translated;
}

void ControlBridge::invalidate_game_return_admission() {
    impl_->citra_host_peers.clear();
    impl_->local_citra_peers.clear();
    for (ControlStation& station : impl_->stations) {
        station.guest_inject_state = GuestInjectionState::Idle;
        station.have_uds_node_id = false;
        station.uds_node_id = 0;
    }
    // V-277: the learned requester fields die with the admission, like the
    // rest of the return eligibility.
    impl_->return_states.clear();
    impl_->active_return_ip.reset();
    static_cast<ReturnState&>(*impl_) = ReturnState{};
}
const citra_room::MacAddress& ControlBridge::bssid() const { return impl_->bssid; }
std::uint32_t ControlBridge::room_seed() const { return impl_->seed; }
std::uint32_t ControlBridge::wlan_comm_id() const { return impl_->wlan_comm_id; }
std::uint32_t ControlBridge::network_id() const { return impl_->network_id; }
std::uint64_t ControlBridge::beacon_count() const { return impl_->beacons; }
const std::map<std::string, std::uint64_t>& ControlBridge::counters() const { return impl_->counters; }
std::string ControlBridge::counters_json() const { return control_counters_json(impl_->counters); }

const std::vector<std::uint8_t>& ControlBridge::citra_advertise_appdata() const {
    return impl_->citra_appdata;
}

const citra_room::MacAddress& ControlBridge::citra_advertise_source_mac() const {
    return impl_->citra_appdata_source_mac;
}
std::string ControlBridge::diag_text() const { return impl_->diag.counters_text(); }

const std::map<std::string, std::vector<DataFrameSample>>& ControlBridge::data_frame_samples() const {
    return impl_->data_samples;
}

std::string ControlBridge::data_frame_samples_json() const {
    std::ostringstream out;
    out << "{";
    bool first_verdict = true;
    for (const auto& [verdict, samples] : impl_->data_samples) {
        if (!first_verdict) {
            out << ",";
        }
        first_verdict = false;
        out << "\"" << verdict << "\":[";
        for (std::size_t i = 0; i < samples.size(); ++i) {
            const DataFrameSample& sample = samples[i];
            if (i != 0) {
                out << ",";
            }
            out << "{\"bytes\":" << sample.bytes << ",\"base\":" << sample.base
                << ",\"head_hex\":\"" << sample.head_hex << "\"}";
        }
        out << "]";
    }
    out << "}";
    return out.str();
}

} // namespace citra_gateway
