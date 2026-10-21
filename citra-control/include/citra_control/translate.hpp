// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - G4 translation layer: LDN <-> UDS field mapping, capacity
// and direction gates, and the 22-byte UDS data prefix.  Pure functions only:
// no sockets, no files, no clock, no global state.  Fail-closed everywhere:
// anything not exactly representable is refused and counted, never guessed,
// never truncated.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "citra_control/bytes.hpp"
#include "citra_control/ldn_ctrl.hpp"
#include "citra_control/map.hpp"
#include "citra_control/state.hpp"
#include "citra_control/uds_frames.hpp"

namespace citra_control {

// UDS data frame prefix: LLC(8) + SecureDataHeader(14) (docs/M4-ADAPTER-SPEC.md section 9.1).
inline constexpr std::size_t kUdsDataPrefixSize = kLlcSize + kSecureDataHeaderSize; // 22
// Peer-relay wrapper magic: must never be seen by the translation layer
// (docs/G4-PRE-ANALYSIS.md section 6).
inline constexpr std::array<std::uint8_t, 4> kCrlyMagic = {0x43, 0x52, 0x4C, 0x59}; // "CRLY"

// Match-key discipline (I8): only the UDS/Yuzu comm id may ever be used as a
// network match key.  Everything else is refused and counted.
enum class MatchKey { CommId, TitleId, SessionId, Ssid, Bssid };

// Direction discipline (section 5 rule 5): which side a payload is allowed to reach.
enum class CrossSideKind { DataPayload, CitraPrivateNodeMap, LdnControlBody };

// ---------------------------------------------------------------------------
// Group A - network info mapping.
// ---------------------------------------------------------------------------
struct UdsToLdnNetworkInput {
    GuestNetworkInfo guest{};
    std::uint8_t appdata_size = 0;
    std::array<std::uint8_t, kApplicationDataSize> appdata{};
    NetworkId ids{};        // derive_ldn_network_id(seed, scene_id, session)
    Ssid ssid{};            // ssid_from_room_name(room_name)
    std::int16_t channel = 0;
    std::int8_t link_level = 0;
    std::vector<LdnNodeInfo> nodes;  // nodes[0] is the host; caller keeps id stability
};

Res<LdnNetworkInfoBody> uds_network_to_ldn(const UdsToLdnNetworkInput& in, Diag* diag = nullptr);

struct LdnToUdsNetworkInput {
    LdnNetworkInfoBody ldn{};
    UdsNetworkIds ids{};    // derive_uds_network_ids(seed); never recovered from the LDN body
    std::uint8_t id = 0;    // UDS "id" byte (caller-owned; no LDN counterpart)
    std::uint8_t total_nodes = 1;
};

Res<GuestNetworkInfo> ldn_network_to_uds(const LdnToUdsNetworkInput& in, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Group B - node info mapping (three UDS forms, both directions).
// ---------------------------------------------------------------------------
Res<LdnNodeInfo> uds_node_to_ldn(const GuestNodeInfo& node, const MacAddress& mac,
                                 const std::array<std::uint8_t, 4>& ipv4, std::int8_t node_id,
                                 std::int16_t version, Diag* diag = nullptr);
Res<LdnNodeInfo> eapol_node_to_ldn(const EapolNodeInfo& node, const MacAddress& mac,
                                   const std::array<std::uint8_t, 4>& ipv4, std::int8_t node_id,
                                   std::int16_t version, Diag* diag = nullptr);
Res<LdnNodeInfo> beacon_node_to_ldn(const BeaconNodeInfo& node, const MacAddress& mac,
                                    const std::array<std::uint8_t, 4>& ipv4, std::int8_t node_id,
                                    std::int16_t version, Diag* diag = nullptr);
Res<GuestNodeInfo> ldn_node_to_uds_guest(const LdnNodeInfo& node, Diag* diag = nullptr);
Res<EapolNodeInfo> ldn_node_to_eapol(const LdnNodeInfo& node, Diag* diag = nullptr);
Res<BeaconNodeInfo> ldn_node_to_beacon(const LdnNodeInfo& node, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Group C - fail-closed gates.
// ---------------------------------------------------------------------------
// I5: a peer AssociationResponse whose raw status is not 0 would trip Citra's
// ASSERT_MSG (nwm_uds.cpp:165-169) and exit(1) (V-016k).
Err guard_association_response(std::uint16_t raw_status, Diag* diag = nullptr);
// I6: asymetric capacity.  0x180 -> 0xC8 overflow is refused, never truncated.
Err guard_advertise_capacity(AdvertiseDirection direction, std::size_t advertised, Diag* diag = nullptr);
// I6: Citra advertises 16 nodes but the converged LDN capacity is 8.
Err guard_node_capacity(std::size_t node_count, std::size_t node_count_max, Diag* diag = nullptr);
// I8
Err guard_match_key(MatchKey key, Diag* diag = nullptr);
// I9: the translation layer only ever sees net payloads.
Err guard_no_crly(const std::uint8_t* data, std::size_t size, Diag* diag = nullptr);
// section 5 rule 5: Citra-private signalling never reaches Yuzu; LDN bodies never
// reach Citra untranslated.
Err guard_cross_side(CrossSideKind kind, Side destination, Diag* diag = nullptr);

struct BeaconLayoutReport {
    std::size_t total_size = 0;
    std::uint8_t appdata_size = 0;
    std::size_t node_count = 0;
    std::size_t oui_occurrences = 0;  // must be exactly 1 in the NetworkInfo IE body
    bool tags_ok = false;
    bool sha1_ok = false;             // SHA-1 over nib || 20 zero bytes || appdata_size || appdata
    bool md5_ok = false;              // zero-key AES-128-CTR plaintext MD5
};

// I10: byte-level compliance check for a beacon we are about to send to Citra.
// source_mac is the 802.11 transmitter address, which the beacon frame itself
// does NOT carry; it is also the CTR host_mac (uds_frames.hpp:214-216).
Res<BeaconLayoutReport> guard_beacon_layout(const std::uint8_t* frame, std::size_t size,
                                            const MacAddress& source_mac, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Group D - the 22-byte UDS data prefix (LLC + SecureDataHeader).
// ---------------------------------------------------------------------------
Res<std::vector<std::uint8_t>> strip_uds_data_prefix(const std::uint8_t* frame, std::size_t size,
                                                     Diag* diag = nullptr);
Res<std::vector<std::uint8_t>> wrap_ldn_payload_as_uds_data(const std::vector<std::uint8_t>& payload,
                                                            const SecureDataHeader& routing,
                                                            Diag* diag = nullptr);

} // namespace citra_control
