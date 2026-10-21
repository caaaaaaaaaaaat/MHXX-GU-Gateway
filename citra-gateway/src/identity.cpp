// SPDX-License-Identifier: GPL-2.0-or-later
#include "citra_gateway/identity.hpp"

#include <algorithm>
#include <cstdio>
#include <utility>

namespace citra_gateway {

bool is_sentinel_mac(const MacAddress& mac) noexcept {
    return std::all_of(mac.begin(), mac.end(), [](std::uint8_t byte) { return byte == 0xFF; });
}

bool is_sentinel_ip(const IPv4& ip) noexcept {
    return std::all_of(ip.begin(), ip.end(), [](std::uint8_t byte) { return byte == 0xFF; });
}

// Nintendo OUI 00:1F:32 prefix. Citra's own IsValidMacAddress is a uniqueness
// test only (citra-master/src/network/room.cpp:578-583), so this predicate must
// not be used to reject a preferred MAC.
bool is_valid_mac_address(const MacAddress& mac) noexcept {
    return mac[0] == 0x00 && mac[1] == 0x1F && mac[2] == 0x32;
}

MacAddress make_generated_mac(std::uint32_t counter) noexcept {
    return MacAddress{0x00, 0x1F, 0x32,
                      static_cast<std::uint8_t>((counter >> 16) & 0xFF),
                      static_cast<std::uint8_t>((counter >> 8) & 0xFF),
                      static_cast<std::uint8_t>(counter & 0xFF)};
}

std::uint32_t crc32_iso_hdlc(const std::uint8_t* data, std::size_t size) noexcept {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ ((crc & 1u) != 0u ? 0xEDB88320u : 0u);
        }
    }
    return ~crc;
}

std::array<std::uint8_t, 4> mhxx_identity_word_from_seed(std::uint64_t seed) noexcept {
    std::array<std::uint8_t, 8> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>((seed >> (8 * index)) & 0xFFu);
    }
    const std::uint32_t word = crc32_iso_hdlc(bytes.data(), bytes.size());
    return {static_cast<std::uint8_t>((word >> 24) & 0xFFu),
            static_cast<std::uint8_t>((word >> 16) & 0xFFu),
            static_cast<std::uint8_t>((word >> 8) & 0xFFu),
            static_cast<std::uint8_t>(word & 0xFFu)};
}

std::string mac_to_string(const MacAddress& mac) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}

std::string ip_to_string(const IPv4& ip) {
    char buffer[20];
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return std::string(buffer);
}

bool IdentityTable::insert(const MacAddress& mac, const IPv4& fake_ip, std::string nickname) {
    if (is_sentinel_mac(mac) || is_sentinel_ip(fake_ip)) return false;
    if (entries_.size() >= capacity) return false;
    if (has_mac(mac) || has_ip(fake_ip)) return false;
    IdentityEntry entry;
    entry.mac = mac;
    entry.fake_ip = fake_ip;
    entry.nickname = std::move(nickname);
    entries_.push_back(std::move(entry));
    return true;
}

void IdentityTable::erase_mac(const MacAddress& mac) {
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                  [&](const IdentityEntry& e) { return e.mac == mac; }),
                   entries_.end());
}

void IdentityTable::erase_ip(const IPv4& fake_ip) {
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                  [&](const IdentityEntry& e) { return e.fake_ip == fake_ip; }),
                   entries_.end());
}

bool IdentityTable::has_mac(const MacAddress& mac) const {
    return std::any_of(entries_.begin(), entries_.end(),
                       [&](const IdentityEntry& e) { return e.mac == mac; });
}

bool IdentityTable::has_ip(const IPv4& fake_ip) const {
    return std::any_of(entries_.begin(), entries_.end(),
                       [&](const IdentityEntry& e) { return e.fake_ip == fake_ip; });
}

std::optional<IPv4> IdentityTable::ip_for_mac(const MacAddress& mac) const {
    for (const auto& entry : entries_)
        if (entry.mac == mac) return entry.fake_ip;
    return std::nullopt;
}

std::optional<MacAddress> IdentityTable::mac_for_ip(const IPv4& fake_ip) const {
    for (const auto& entry : entries_)
        if (entry.fake_ip == fake_ip) return entry.mac;
    return std::nullopt;
}

std::optional<IdentityEntry> IdentityTable::entry_for_mac(const MacAddress& mac) const {
    for (const auto& entry : entries_)
        if (entry.mac == mac) return entry;
    return std::nullopt;
}

std::optional<IdentityEntry> IdentityTable::entry_for_ip(const IPv4& fake_ip) const {
    for (const auto& entry : entries_)
        if (entry.fake_ip == fake_ip) return entry;
    return std::nullopt;
}

std::optional<IPv4> IdentityTable::next_free_fake_ip() const {
    for (std::uint32_t host = 1; host <= 254; ++host) {
        const IPv4 candidate{192, pool_second_octet, pool_third_octet,
                             static_cast<std::uint8_t>(host)};
        if (!has_ip(candidate)) return candidate;
    }
    return std::nullopt;
}

std::optional<MacAddress> IdentityTable::generate_mac() const {
    for (std::uint32_t counter = 1; counter <= 0x00FFFFFFu; ++counter) {
        const MacAddress candidate = make_generated_mac(counter);
        if (!has_mac(candidate)) return candidate;
    }
    return std::nullopt;
}

} // namespace citra_gateway
