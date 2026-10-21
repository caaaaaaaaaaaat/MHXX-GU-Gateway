// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - control-plane mapping layer (docs/M4-CONTROL-PLANE.md §3).
//
// Rules encoded here:
//  * MAC <-> fake IPv4 and node id are a session bijection; the table is owned
//    by the caller and passed in, so the library keeps no global state.
//  * Node ids must stay inside the s8 domain; anything else is refused and
//    counted (node_id_out_of_range).
//  * The network identity mapping is one-way.  The gateway picks a seed and
//    derives both sides from it; there is deliberately no function that
//    recovers the peer's original id (the recover_* entry points always fail
//    with Err::Irreversible and are counted as netid_irreversible_refused, so
//    nothing can silently claim to restore it).
//  * The SSID is derived deterministically from the room name (no randomness)
//    and the reverse direction is refused for the same reason.
//  * Usernames convert bidirectionally between 10 x u16 (3DS) and the Yuzu
//    user_name bytes; anything not exactly representable is refused and
//    counted, never guessed.
//  * friend_code_seed has no Yuzu field: it is zeroed and counted as an
//    invented/undefined field, never silently dropped.
//  * Advertise/app-data capacity is asymmetric (0xC8 vs 0x180): 0x180 -> 0xC8
//    overflow is refused and counted (oversize_rejected); truncation is never
//    performed.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "citra_control/bytes.hpp"
#include "citra_control/ldn_ctrl.hpp"

namespace citra_control {

// ---------------------------------------------------------------------------
// Session identity table (no global state: the caller owns it).
// ---------------------------------------------------------------------------
struct NodeBinding {
    MacAddress mac{};
    std::array<std::uint8_t, 4> ipv4{};
    std::int8_t node_id = 0;
};

class SessionMap {
public:
    SessionMap() = default;
    explicit SessionMap(const std::array<std::uint8_t, 3>& subnet24) noexcept : subnet_(subnet24) {}

    void clear() noexcept;
    std::size_t size() const noexcept { return entries_.size(); }
    const std::vector<NodeBinding>& bindings() const noexcept { return entries_; }

    // Idempotent: binding the same MAC twice returns the same fake IPv4 and
    // node id (V-016n rule 3: per-client MAC and per-room BSSID must be stable).
    Res<NodeBinding> bind(const MacAddress& mac, Diag* diag = nullptr);
    bool remove(const MacAddress& mac, Diag* diag = nullptr);

    Res<NodeBinding> lookup_mac(const MacAddress& mac, Diag* diag = nullptr) const;
    Res<MacAddress> lookup_ipv4(const std::array<std::uint8_t, 4>& ipv4, Diag* diag = nullptr) const;
    Res<NodeBinding> lookup_node_id(std::int8_t node_id, Diag* diag = nullptr) const;

private:
    std::array<std::uint8_t, 3> subnet_{{10, 83, 0}};
    std::vector<NodeBinding> entries_;
};

// s8 domain gate for a caller-supplied node id.
Res<std::int8_t> check_node_id(long long value, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Irreversible network identity.
// ---------------------------------------------------------------------------
struct UdsNetworkIds {
    std::uint32_t wlan_comm_id = 0;
    std::uint32_t network_id = 0;
};

// Documented 32-bit finalizer ("lowbias32", C. Wellons, public domain).
std::uint32_t mix32(std::uint32_t x) noexcept;

Res<UdsNetworkIds> derive_uds_network_ids(std::uint32_t seed, Diag* diag = nullptr);
Res<NetworkId> derive_ldn_network_id(std::uint32_t seed, std::uint16_t scene_id, const SessionId& session,
                                     Diag* diag = nullptr);
// Both always fail: they are the explicit "we do not claim to recover the
// peer's original id" entry points.
Res<std::uint32_t> recover_seed_from_uds(const UdsNetworkIds& ids, Diag* diag = nullptr);
Res<std::uint32_t> recover_seed_from_ldn(const NetworkId& id, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// SSID (deterministic forward derivation, reverse refused).
// ---------------------------------------------------------------------------
Res<Ssid> ssid_from_room_name(const std::string& room_name, Diag* diag = nullptr);
Res<std::string> room_name_from_ssid(const Ssid& ssid, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Username (bidirectional, exact).
// ---------------------------------------------------------------------------
using UserNameBytes = std::array<std::uint8_t, kLdnUserNameBytesMax + 1>;

Res<Username> username_from_bytes(const UserNameBytes& name, Diag* diag = nullptr);
Res<UserNameBytes> username_to_bytes(const Username& name, Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// friend_code_seed has no Yuzu field.
// ---------------------------------------------------------------------------
std::uint64_t friend_code_to_ldn(std::uint64_t wire_friend_code_seed, Diag* diag = nullptr);
std::uint64_t friend_code_from_ldn(Diag* diag = nullptr);

// ---------------------------------------------------------------------------
// Advertise/app-data capacity asymmetry.
// ---------------------------------------------------------------------------
enum class AdvertiseDirection { UdsToLdn, LdnToUds };

Res<std::size_t> check_advertise_size(AdvertiseDirection direction, std::size_t size, Diag* diag = nullptr);

} // namespace citra_control
