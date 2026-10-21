// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - G4 translation layer implementation.
//
// Pure, re-entrant functions.  No I/O, no wall-clock, no RNG, no global mutable
// state.  Every input that cannot be represented exactly on the other side is
// refused and counted; nothing is ever guessed or truncated.
#include "citra_control/translate.hpp"

#include <algorithm>
#include <array>

namespace citra_control {
namespace {

void reject(Diag* diag, const char* where, Err err, const char* detail = "") {
    if (diag != nullptr) {
        diag->note_reject(where, err, detail);
    }
}

void event(Diag* diag, const char* where, const char* detail) {
    if (diag != nullptr) {
        diag->note_event(where, detail);
    }
}

std::size_t count_magic(const std::uint8_t* data, std::size_t size, const std::uint8_t* magic,
                        std::size_t magic_size) {
    std::size_t count = 0;
    if (size >= magic_size) {
        for (std::size_t i = 0; i + magic_size <= size; ++i) {
            bool hit = true;
            for (std::size_t j = 0; j < magic_size; ++j) {
                if (data[i + j] != magic[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) {
                ++count;
            }
        }
    }
    return count;
}

// Shared UDS -> LDN node conversion.  The caller owns mac/ipv4/node_id; the
// local_communication_version has no UDS counterpart and is dropped.
Res<LdnNodeInfo> build_ldn_node(const Username& username, std::uint64_t friend_code_seed,
                                const MacAddress& mac, const std::array<std::uint8_t, 4>& ipv4,
                                std::int8_t node_id, std::int16_t version, const char* where,
                                Diag* diag) {
    Res<std::int8_t> id = check_node_id(static_cast<long long>(node_id), diag);
    if (!id.ok()) {
        return fail<LdnNodeInfo>(id.err);
    }
    Res<UserNameBytes> name = username_to_bytes(username, diag);
    if (!name.ok()) {
        return fail<LdnNodeInfo>(name.err);
    }
    LdnNodeInfo out{};
    out.ipv4_address = ipv4;
    out.mac_address = mac;
    out.node_id = id.value;
    out.is_connected = static_cast<std::uint8_t>(NodeStatus::Connected);
    out.user_name = name.value;
    out.local_communication_version = version;
    (void)friend_code_to_ldn(friend_code_seed, diag);
    event(diag, where, "ldn_only_field_dropped");
    return ok(out);
}

// Shared LDN -> UDS node preconditions: the target id must fit a signed byte
// and be non-negative, and the 33-byte wire name must decode exactly.
Res<Username> open_ldn_node(const LdnNodeInfo& node, const char* where, Diag* diag) {
    if (node.node_id < 0) {
        if (diag != nullptr) {
            ++diag->c.node_id_out_of_range;
        }
        reject(diag, where, Err::Range, "negative node id");
        return fail<Username>(Err::Range);
    }
    Res<std::int8_t> id = check_node_id(static_cast<long long>(node.node_id), diag);
    if (!id.ok()) {
        return fail<Username>(id.err);
    }
    return username_from_bytes(node.user_name, diag);
}

} // namespace

// ---------------------------------------------------------------------------
// Group A: UDS -> LDN
// ---------------------------------------------------------------------------
Res<LdnNetworkInfoBody> uds_network_to_ldn(const UdsToLdnNetworkInput& in, Diag* diag) {
    if (!ldn_channel_ok(in.channel)) {
        if (diag != nullptr) {
            ++diag->c.channel_rejected;
        }
        reject(diag, "uds_network_to_ldn", Err::BadEnum, "channel");
        return fail<LdnNetworkInfoBody>(Err::BadEnum);
    }
    if (in.link_level < 0 || in.link_level > 3) {
        reject(diag, "uds_network_to_ldn", Err::Range, "link_level");
        return fail<LdnNetworkInfoBody>(Err::Range);
    }
    Res<std::size_t> adv = check_advertise_size(AdvertiseDirection::UdsToLdn, in.appdata_size, diag);
    if (!adv.ok()) {
        return fail<LdnNetworkInfoBody>(adv.err);
    }
    if (in.nodes.size() > kLdnNodeCountMax) {
        if (diag != nullptr) {
            ++diag->c.oversize_rejected;
        }
        reject(diag, "uds_network_to_ldn", Err::Range, "node_count");
        return fail<LdnNetworkInfoBody>(Err::Range);
    }
    if (in.guest.max_nodes > kLdnNodeCountMax) {
        event(diag, "uds_network_to_ldn", "max_nodes_converged");
    }

    LdnNetworkInfoBody out{};
    out.network_id = in.ids;
    out.common.bssid = in.guest.host_mac_address;
    out.common.ssid = in.ssid;
    out.common.channel = in.channel;
    out.common.link_level = in.link_level;
    out.common.network_type = static_cast<std::uint8_t>(PackedNetworkType::Ldn);
    out.ldn.security_parameter.fill(0);
    out.ldn.security_mode = SecurityMode::All;
    out.ldn.station_accept_policy = AcceptPolicy::AcceptAll;
    out.ldn.has_action_frame = 0;
    out.ldn.node_count_max = static_cast<std::uint8_t>(kLdnNodeCountMax);
    out.ldn.node_count = static_cast<std::uint8_t>(in.nodes.size());
    for (std::size_t i = 0; i < in.nodes.size(); ++i) {
        out.ldn.nodes[i] = in.nodes[i];
    }
    out.ldn.advertise_data_size = static_cast<std::uint16_t>(in.appdata_size);
    for (std::size_t i = 0; i < in.appdata_size; ++i) {
        out.ldn.advertise_data[i] = in.appdata[i];
    }
    out.ldn.reserved.fill(0);
    out.ldn.random_authentication_id = 0;
    if (diag != nullptr) {
        ++diag->c.invented_fields;
    }
    event(diag, "uds_network_to_ldn", "random_authentication_id_invented");
    return ok(out);
}

// ---------------------------------------------------------------------------
// Group A: LDN -> UDS
// ---------------------------------------------------------------------------
Res<GuestNetworkInfo> ldn_network_to_uds(const LdnToUdsNetworkInput& in, Diag* diag) {
    const std::int16_t channel = in.ldn.common.channel;
    if (channel != 0 && channel != 1 && channel != 6 && channel != 11) {
        if (diag != nullptr) {
            ++diag->c.channel_rejected;
        }
        reject(diag, "ldn_network_to_uds", Err::BadEnum, "channel");
        return fail<GuestNetworkInfo>(Err::BadEnum);
    }
    if (in.total_nodes < 1 || in.total_nodes > kLdnNodeCountMax) {
        if (diag != nullptr) {
            ++diag->c.oversize_rejected;
        }
        reject(diag, "ldn_network_to_uds", Err::Range, "total_nodes");
        return fail<GuestNetworkInfo>(Err::Range);
    }
    if (in.ldn.ldn.node_count_max > kLdnNodeCountMax || in.ldn.ldn.node_count > kLdnNodeCountMax) {
        if (diag != nullptr) {
            ++diag->c.oversize_rejected;
        }
        reject(diag, "ldn_network_to_uds", Err::Range, "node_count");
        return fail<GuestNetworkInfo>(Err::Range);
    }
    if (in.ldn.ldn.advertise_data_size > kApplicationDataSize) {
        if (diag != nullptr) {
            ++diag->c.oversize_rejected;
        }
        reject(diag, "ldn_network_to_uds", Err::Capacity, "advertise_data_size");
        return fail<GuestNetworkInfo>(Err::Capacity);
    }

    GuestNetworkInfo out{};
    out.host_mac_address = in.ldn.common.bssid;
    out.channel = static_cast<std::uint8_t>(channel);
    out.initialized = 1;
    out.oui_value = kNintendoOui;
    out.oui_type = kNintendoTagIdNetworkInfo;
    out.wlan_comm_id = in.ids.wlan_comm_id;
    out.id = in.id;
    out.attributes = 0;
    out.network_id = in.ids.network_id;
    out.total_nodes = in.total_nodes;
    const std::uint8_t max_nodes =
        static_cast<std::uint8_t>(std::min<std::size_t>(in.ldn.ldn.node_count_max, kLdnNodeCountMax));
    out.max_nodes = max_nodes;
    out.application_data_size = static_cast<std::uint8_t>(in.ldn.ldn.advertise_data_size);
    for (std::size_t i = 0; i < in.ldn.ldn.advertise_data_size; ++i) {
        out.application_data[i] = in.ldn.ldn.advertise_data[i];
    }
    if (diag != nullptr) {
        ++diag->c.undefined_fields;
    }
    event(diag, "ldn_network_to_uds", "ldn_only_field_dropped");
    return ok(out);
}

// ---------------------------------------------------------------------------
// Group B: nodes
// ---------------------------------------------------------------------------
Res<LdnNodeInfo> uds_node_to_ldn(const GuestNodeInfo& node, const MacAddress& mac,
                                 const std::array<std::uint8_t, 4>& ipv4, std::int8_t node_id,
                                 std::int16_t version, Diag* diag) {
    return build_ldn_node(node.username, node.friend_code_seed, mac, ipv4, node_id, version,
                          "uds_node_to_ldn", diag);
}

Res<LdnNodeInfo> eapol_node_to_ldn(const EapolNodeInfo& node, const MacAddress& mac,
                                   const std::array<std::uint8_t, 4>& ipv4, std::int8_t node_id,
                                   std::int16_t version, Diag* diag) {
    return build_ldn_node(node.username, node.friend_code_seed, mac, ipv4, node_id, version,
                          "eapol_node_to_ldn", diag);
}

Res<LdnNodeInfo> beacon_node_to_ldn(const BeaconNodeInfo& node, const MacAddress& mac,
                                    const std::array<std::uint8_t, 4>& ipv4, std::int8_t node_id,
                                    std::int16_t version, Diag* diag) {
    return build_ldn_node(node.username, node.friend_code_seed, mac, ipv4, node_id, version,
                          "beacon_node_to_ldn", diag);
}

Res<GuestNodeInfo> ldn_node_to_uds_guest(const LdnNodeInfo& node, Diag* diag) {
    Res<Username> name = open_ldn_node(node, "ldn_node_to_uds_guest", diag);
    if (!name.ok()) {
        return fail<GuestNodeInfo>(name.err);
    }
    GuestNodeInfo out{};
    out.friend_code_seed = friend_code_from_ldn(diag);
    out.username = name.value;
    out.network_node_id = static_cast<std::uint16_t>(node.node_id);
    return ok(out);
}

Res<EapolNodeInfo> ldn_node_to_eapol(const LdnNodeInfo& node, Diag* diag) {
    Res<Username> name = open_ldn_node(node, "ldn_node_to_eapol", diag);
    if (!name.ok()) {
        return fail<EapolNodeInfo>(name.err);
    }
    EapolNodeInfo out{};
    out.friend_code_seed = friend_code_from_ldn(diag);
    out.username = name.value;
    out.network_node_id = static_cast<std::uint16_t>(node.node_id);
    return ok(out);
}

Res<BeaconNodeInfo> ldn_node_to_beacon(const LdnNodeInfo& node, Diag* diag) {
    Res<Username> name = open_ldn_node(node, "ldn_node_to_beacon", diag);
    if (!name.ok()) {
        return fail<BeaconNodeInfo>(name.err);
    }
    BeaconNodeInfo out{};
    out.friend_code_seed = friend_code_from_ldn(diag);
    out.username = name.value;
    out.network_node_id = static_cast<std::uint16_t>(node.node_id);
    return ok(out);
}

// ---------------------------------------------------------------------------
// Group C: gates
// ---------------------------------------------------------------------------
Err guard_association_response(std::uint16_t raw_status, Diag* diag) {
    if (raw_status != 0) {
        if (diag != nullptr) {
            ++diag->c.unsafe_assoc_blocked;
        }
        reject(diag, "association_response", Err::Unsafe, "raw_status != 0");
        return Err::Unsafe;
    }
    return Err::Ok;
}

Err guard_advertise_capacity(AdvertiseDirection direction, std::size_t advertised, Diag* diag) {
    Res<std::size_t> r = check_advertise_size(direction, advertised, diag);
    return r.ok() ? Err::Ok : r.err;
}

Err guard_node_capacity(std::size_t node_count, std::size_t node_count_max, Diag* diag) {
    if (node_count > kLdnNodeCountMax || node_count_max > kLdnNodeCountMax) {
        if (diag != nullptr) {
            ++diag->c.oversize_rejected;
        }
        reject(diag, "node_capacity", Err::Range, "node count exceeds 8");
        return Err::Range;
    }
    return Err::Ok;
}

Err guard_match_key(MatchKey key, Diag* diag) {
    if (key != MatchKey::CommId) {
        reject(diag, "match_key", Err::BadEnum, "only comm id is a legal match key");
        event(diag, "guard_match_key", "illegal_match_key");
        return Err::BadEnum;
    }
    return Err::Ok;
}

Err guard_no_crly(const std::uint8_t* data, std::size_t size, Diag* diag) {
    if (data != nullptr && size >= kCrlyMagic.size() &&
        std::equal(kCrlyMagic.begin(), kCrlyMagic.end(), data)) {
        reject(diag, "crly", Err::BadMagic, "crly wrapper reached translate");
        event(diag, "guard_no_crly", "crly_reached_translate");
        return Err::BadMagic;
    }
    return Err::Ok;
}

Err guard_cross_side(CrossSideKind kind, Side destination, Diag* diag) {
    const bool leak = (kind == CrossSideKind::CitraPrivateNodeMap && destination == Side::Yuzu) ||
                      (kind == CrossSideKind::LdnControlBody && destination == Side::Citra);
    if (leak) {
        if (diag != nullptr) {
            ++diag->c.cross_side_leak_blocked;
        }
        reject(diag, "cross_side", Err::Unsafe, "direction not allowed");
        return Err::Unsafe;
    }
    return Err::Ok;
}

Res<BeaconLayoutReport> guard_beacon_layout(const std::uint8_t* frame, std::size_t size,
                                            const MacAddress& source_mac, Diag* diag) {
    BeaconLayoutReport rep;
    rep.total_size = size;
    if (frame == nullptr || size < kBeaconFrameHeaderSize) {
        reject(diag, "beacon_layout", Err::BadLength, "header");
        return fail<BeaconLayoutReport>(Err::BadLength);
    }

    // 2. SSID tag 00 08 followed by 8 zero bytes.
    std::size_t pos = kBeaconFrameHeaderSize;
    if (pos + kBeaconSsidTagSize > size) {
        reject(diag, "beacon_layout", Err::BadLength, "ssid tag");
        return fail<BeaconLayoutReport>(Err::BadLength);
    }
    if (frame[pos] != 0x00 || frame[pos + 1] != 0x08) {
        reject(diag, "beacon_layout", Err::BadTag, "ssid tag id/len");
        return fail<BeaconLayoutReport>(Err::BadTag);
    }
    for (std::size_t i = 0; i < 8; ++i) {
        if (frame[pos + 2 + i] != 0x00) {
            reject(diag, "beacon_layout", Err::BadTag, "ssid tag payload");
            return fail<BeaconLayoutReport>(Err::BadTag);
        }
    }
    pos += kBeaconSsidTagSize;

    // 3. Dummy vendor tag DD 07 00 1F 32 14 0A 00 00.
    static const std::array<std::uint8_t, 9> kDummy = {0xDD, 0x07, 0x00, 0x1F,
                                                       0x32, 0x14, 0x0A, 0x00, 0x00};
    if (pos + kDummy.size() > size) {
        reject(diag, "beacon_layout", Err::BadLength, "dummy tag");
        return fail<BeaconLayoutReport>(Err::BadLength);
    }
    if (!std::equal(kDummy.begin(), kDummy.end(), frame + pos)) {
        reject(diag, "beacon_layout", Err::BadTag, "dummy tag");
        return fail<BeaconLayoutReport>(Err::BadTag);
    }
    pos += kDummy.size();

    // 4. NetworkInfo tag: DD len, len == 52 + appdata_size, nib magic once.
    if (pos + 2 > size) {
        reject(diag, "beacon_layout", Err::BadLength, "network info tag header");
        return fail<BeaconLayoutReport>(Err::BadLength);
    }
    if (frame[pos] != 0xDD) {
        reject(diag, "beacon_layout", Err::BadTag, "network info tag id");
        return fail<BeaconLayoutReport>(Err::BadTag);
    }
    const std::size_t ni_len = frame[pos + 1];
    pos += 2;
    if (ni_len < 52 || pos + ni_len > size) {
        reject(diag, "beacon_layout", Err::BadLength, "network info tag length");
        return fail<BeaconLayoutReport>(Err::BadLength);
    }
    static const std::array<std::uint8_t, 4> kNibMagic = {0x00, 0x1F, 0x32, 0x15};
    const std::uint8_t* body = frame + pos;
    if (!std::equal(kNibMagic.begin(), kNibMagic.end(), body)) {
        reject(diag, "beacon_layout", Err::BadTag, "network info tag oui/type");
        return fail<BeaconLayoutReport>(Err::BadTag);
    }
    rep.appdata_size = body[51];
    if (ni_len != static_cast<std::size_t>(52) + rep.appdata_size) {
        reject(diag, "beacon_layout", Err::BadLength, "network info tag vs appdata_size");
        return fail<BeaconLayoutReport>(Err::BadLength);
    }
    rep.oui_occurrences = count_magic(body, ni_len, kNibMagic.data(), kNibMagic.size());
    if (rep.oui_occurrences != 1) {
        reject(diag, "beacon_layout", Err::BadTag, "network info oui repeated");
        return fail<BeaconLayoutReport>(Err::BadTag);
    }
    rep.node_count = body[17];
    pos += ni_len;

    // 6 (layout half): encrypted vendor tags 0x18 / 0x19 and their total size.
    std::size_t cipher_len = 0;
    bool have_first = false;
    bool have_second = false;
    while (pos < size) {
        if (pos + 2 > size || frame[pos] != 0xDD) {
            reject(diag, "beacon_layout", Err::BadTag, "encrypted tag id");
            return fail<BeaconLayoutReport>(Err::BadTag);
        }
        const std::size_t tag_len = frame[pos + 1];
        if (tag_len < 4 || pos + 2 + tag_len > size) {
            reject(diag, "beacon_layout", Err::BadLength, "encrypted tag length");
            return fail<BeaconLayoutReport>(Err::BadLength);
        }
        if (frame[pos + 2] != 0x00 || frame[pos + 3] != 0x1F || frame[pos + 4] != 0x32) {
            reject(diag, "beacon_layout", Err::BadTag, "encrypted tag oui");
            return fail<BeaconLayoutReport>(Err::BadTag);
        }
        const std::uint8_t tag_type = frame[pos + 5];
        if (tag_type == kNintendoTagIdEncryptedData0) {
            if (have_first || have_second) {
                reject(diag, "beacon_layout", Err::BadTag, "duplicate encrypted tag 0x18");
                return fail<BeaconLayoutReport>(Err::BadTag);
            }
            have_first = true;
        } else if (tag_type == kNintendoTagIdEncryptedData1) {
            if (!have_first || have_second) {
                reject(diag, "beacon_layout", Err::BadTag, "misordered encrypted tag 0x19");
                return fail<BeaconLayoutReport>(Err::BadTag);
            }
            have_second = true;
        } else {
            reject(diag, "beacon_layout", Err::BadTag, "unknown encrypted tag type");
            return fail<BeaconLayoutReport>(Err::BadTag);
        }
        cipher_len += tag_len - 4;
        pos += 2 + tag_len;
    }
    if (!have_first) {
        reject(diag, "beacon_layout", Err::BadTag, "missing encrypted tag 0x18");
        return fail<BeaconLayoutReport>(Err::BadTag);
    }
    // spec R7: Citra's own boundary - below 2 nodes the 0x28n payload does not
    // cover even the 0x12-byte header + bitmask, so it is refused before the
    // length and hash checks (the delegated parser applies the same rule).
    if (rep.node_count < 2) {
        if (diag != nullptr) {
            ++diag->c.beacon_node_reject;
        }
        event(diag, "beacon_layout", "beacon_max_nodes_too_small");
        reject(diag, "beacon_layout", Err::BadLength, "max_nodes < 2");
        return fail<BeaconLayoutReport>(Err::BadLength);
    }
    // spec R1: the concatenated encrypted payload is 0x28 * max_nodes (Citra's
    // nwm_uds.h NodeInfo stride), not 0x12 + 0x1E * max_nodes.
    const std::size_t expected_cipher = kBeaconNodeStride * rep.node_count;
    if (cipher_len != expected_cipher) {
        reject(diag, "beacon_layout", Err::BadLength, "ciphertext length");
        return fail<BeaconLayoutReport>(Err::BadLength);
    }

    // 5 + 6: SHA-1 / MD5 / CTR are owned by parse_beacon_frame; delegate so the
    // existing counters (sha1_verify_fail / md5_verify_fail) are used exactly
    // once and are not reimplemented here.
    Res<BeaconFrame> parsed = parse_beacon_frame(frame, size, source_mac, diag);
    if (!parsed.ok()) {
        return fail<BeaconLayoutReport>(parsed.err);
    }
    rep.tags_ok = true;
    rep.sha1_ok = true;
    rep.md5_ok = true;
    return ok(rep);
}

// ---------------------------------------------------------------------------
// Group D: 22-byte UDS data prefix
// ---------------------------------------------------------------------------
Res<std::vector<std::uint8_t>> strip_uds_data_prefix(const std::uint8_t* frame, std::size_t size,
                                                     Diag* diag) {
    if (size < kUdsDataPrefixSize) {
        reject(diag, "strip_uds_data_prefix", Err::Short, "size < 22");
        return fail<std::vector<std::uint8_t>>(Err::Short);
    }
    Reader r(frame, size);
    Res<LlcHeader> llc = read_llc(r);
    if (!llc.ok() || llc.value.protocol != EtherType::SecureData) {
        reject(diag, "strip_uds_data_prefix", Err::BadTag, "not a SecureData LLC frame");
        return fail<std::vector<std::uint8_t>>(Err::BadTag);
    }
    Res<SecureDataFrame> sd = parse_secure_data_frame(frame, size, diag);
    if (!sd.ok()) {
        return fail<std::vector<std::uint8_t>>(sd.err);
    }
    return ok(sd.value.payload);
}

Res<std::vector<std::uint8_t>> wrap_ldn_payload_as_uds_data(const std::vector<std::uint8_t>& payload,
                                                            const SecureDataHeader& routing,
                                                            Diag* diag) {
    SecureDataFrame f;
    f.header = routing;
    f.header.sequence_number = 0; // forced (SecureDataHeader comment: never managed)
    f.payload = payload;
    return build_secure_data_frame(f, diag);
}

} // namespace citra_control
