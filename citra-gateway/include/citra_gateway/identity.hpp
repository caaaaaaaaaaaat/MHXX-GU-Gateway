// SPDX-License-Identifier: GPL-2.0-or-later
// G-b Citra <-> Yuzu session identity mapping (ADR-009).
//
// One Citra client == one Yuzu room peer. The identity map is the session
// scoped bidirectional permutation between the Citra 6-byte MAC and the Yuzu
// 4-byte fake IPv4. Sentinels (Citra NoPreferredMac / BroadcastMac and Yuzu
// NoPreferredIP) are never stored. The Citra console_id_hash never enters this
// table and is never forwarded.
#pragma once

#include "citra_room/protocol.hpp"
#include "room_client/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace citra_gateway {

using MacAddress = citra_room::MacAddress;
using IPv4 = room_client::IPv4;

// True when every octet is 0xFF. Citra defines NoPreferredMac == BroadcastMac ==
// FF:FF:FF:FF:FF:FF (citra-master/src/network/room.h:46-49), so both are sentinels.
bool is_sentinel_mac(const MacAddress& mac) noexcept;

// True when every octet is 0xFF (Yuzu NoPreferredIP, room.h:34).
bool is_sentinel_ip(const IPv4& ip) noexcept;

// Nintendo OUI 00:1F:32 prefix test (citra-master/src/core/hle/service/nwm/
// uds_beacon.h:17). This is NOT Citra's IsValidMacAddress: that one is purely a
// uniqueness test (citra-master/src/network/room.cpp:578-583). Used to assert
// the OUI of gateway generated MACs.
bool is_valid_mac_address(const MacAddress& mac) noexcept;

// Nintendo OUI 00:1F:32 followed by the low three bytes of counter.
MacAddress make_generated_mac(std::uint32_t counter) noexcept;

// V-268: CRC-32/ISO-HDLC (reflected, polynomial 0xEDB88320, init 0xFFFFFFFF,
// final xor 0xFFFFFFFF) -- the hash MHXX's local UDS provider applies to the
// eight NodeInfo seed bytes before using the result as its application endpoint
// (citra-master 0x007B465C; the offline model is
// crossplay/tools/mhxx-endpoint.mjs with independently computed zlib goldens).
std::uint32_t crc32_iso_hdlc(const std::uint8_t* data, std::size_t size) noexcept;

// V-268: the 4-byte MHXX identity word a given NodeInfo friend_code_seed
// produces, in wire (big-endian) order.  Golden values from the same offline
// model: seed 0 -> 65 22 df 69, 0x0807060504030201 -> 3f ca 88 c5,
// 0x3837363534333231 -> 9a e0 da af, 0xffffffffffffffff -> 21 44 df 1c.
// The seed is hashed in its little-endian memory order; the gateway only ever
// declares a zero seed (kGuestDeclaredSeed), where both orders coincide, so the
// order choice is not load-bearing for anything this file feeds.
std::array<std::uint8_t, 4> mhxx_identity_word_from_seed(std::uint64_t seed) noexcept;

// "00:1f:32:11:22:33" (lower-case, colon separated).
std::string mac_to_string(const MacAddress& mac);
// "192.168.1.7".
std::string ip_to_string(const IPv4& ip);

struct IdentityEntry {
    MacAddress mac{};
    IPv4 fake_ip{};
    std::string nickname;
    bool operator==(const IdentityEntry&) const = default;
};

// Session scoped MAC <-> fake IPv4 map. Capacity 254 matches both rooms'
// MaxConcurrentConnections.
class IdentityTable {
public:
    static constexpr std::size_t capacity = 254;
    static constexpr std::uint8_t pool_second_octet = 168;
    static constexpr std::uint8_t pool_third_octet = 1;

    // Rejects sentinels, full tables and any duplicate MAC or IP. The nickname
    // is carried for observability only.
    bool insert(const MacAddress& mac, const IPv4& fake_ip, std::string nickname);
    void erase_mac(const MacAddress& mac);
    void erase_ip(const IPv4& fake_ip);

    bool has_mac(const MacAddress& mac) const;
    bool has_ip(const IPv4& fake_ip) const;

    std::optional<IPv4> ip_for_mac(const MacAddress& mac) const;
    std::optional<MacAddress> mac_for_ip(const IPv4& fake_ip) const;
    std::optional<IdentityEntry> entry_for_mac(const MacAddress& mac) const;
    std::optional<IdentityEntry> entry_for_ip(const IPv4& fake_ip) const;

    std::size_t size() const noexcept { return entries_.size(); }
    bool empty() const noexcept { return entries_.empty(); }
    const std::vector<IdentityEntry>& entries() const noexcept { return entries_; }
    void clear() noexcept { entries_.clear(); }

    // First unused 192.168.<pool_second_octet>.<1..254> in ascending order.
    std::optional<IPv4> next_free_fake_ip() const;

    // Deterministic unique 00:1F:32:xx:xx:xx, never a sentinel.
    std::optional<MacAddress> generate_mac() const;

private:
    std::vector<IdentityEntry> entries_;
};

} // namespace citra_gateway
