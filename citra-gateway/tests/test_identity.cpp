// SPDX-License-Identifier: GPL-2.0-or-later
// Offline unit tests for the G-b identity map. No sockets, no ENet.
#include "citra_gateway/identity.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

int checks = 0;
int failures = 0;

void check(bool condition, const std::string& name) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cout << "FAIL " << checks << " " << name << "\n";
    } else {
        std::cout << "PASS " << checks << " " << name << "\n";
    }
}

const citra_gateway::MacAddress kMacA{0x00, 0x1F, 0x32, 0x11, 0x22, 0x33};
const citra_gateway::MacAddress kMacB{0x00, 0x1F, 0x32, 0x44, 0x55, 0x66};

} // namespace

int main() {
    using namespace citra_gateway;

    check(is_sentinel_mac(citra_room::no_preferred_mac), "citra NoPreferredMac is a sentinel");
    check(is_sentinel_mac(citra_room::broadcast_mac), "citra BroadcastMac is a sentinel");
    check(!is_sentinel_mac(kMacA), "ordinary MAC is not a sentinel");
    check(is_sentinel_ip(room_client::no_preferred_ip), "yuzu NoPreferredIP is a sentinel");
    check(!is_sentinel_ip(IPv4{192, 168, 1, 7}), "ordinary IPv4 is not a sentinel");

    check(mac_to_string(kMacA) == "00:1f:32:11:22:33", "MAC string form");
    check(ip_to_string(IPv4{192, 168, 1, 7}) == "192.168.1.7", "IPv4 string form");
    check(make_generated_mac(0x0A0B0C) == MacAddress({0x00, 0x1F, 0x32, 0x0A, 0x0B, 0x0C}),
          "generated MAC carries Nintendo OUI 00:1F:32");

    IdentityTable table;
    check(table.empty(), "table starts empty");
    check(table.insert(kMacA, IPv4{192, 168, 1, 1}, "Nick"), "insert first entry");
    check(table.insert(kMacB, IPv4{192, 168, 1, 2}, "Other"), "insert second entry");
    check(table.size() == 2, "table size 2");
    check(!table.insert(kMacA, IPv4{192, 168, 1, 3}, "DupMac"), "duplicate MAC rejected");
    check(!table.insert(MacAddress{0x00, 0x1F, 0x32, 9, 9, 9}, IPv4{192, 168, 1, 2}, "DupIp"),
          "duplicate IP rejected");
    check(!table.insert(citra_room::no_preferred_mac, IPv4{192, 168, 1, 4}, "SentinelMac"),
          "sentinel MAC never inserted");
    check(!table.insert(citra_room::broadcast_mac, IPv4{192, 168, 1, 4}, "SentinelMac2"),
          "broadcast MAC never inserted");
    check(!table.insert(MacAddress{0x00, 0x1F, 0x32, 5, 5, 5}, room_client::no_preferred_ip, "SentinelIp"),
          "sentinel IP never inserted");
    check(table.size() == 2, "rejected inserts left the table unchanged");

    check(table.ip_for_mac(kMacA).value() == IPv4({192, 168, 1, 1}), "MAC -> IP forward lookup");
    check(table.mac_for_ip(IPv4{192, 168, 1, 2}).value() == kMacB, "IP -> MAC reverse lookup");
    check(!table.ip_for_mac(MacAddress{9, 9, 9, 9, 9, 9}).has_value(), "unknown MAC has no IP");
    check(!table.mac_for_ip(IPv4{10, 0, 0, 1}).has_value(), "unknown IP has no MAC");
    check(!table.mac_for_ip(room_client::no_preferred_ip).has_value(), "sentinel IP lookup is empty");

    const auto next = table.next_free_fake_ip();
    check(next.has_value() && next.value() == IPv4({192, 168, 1, 3}), "next free fake IP skips used ones");

    const auto generated = table.generate_mac();
    check(generated.has_value(), "generator produced a MAC");
    check(!table.has_mac(generated.value()), "generated MAC is unused");
    check(is_sentinel_mac(generated.value()) == false, "generated MAC is not a sentinel");

    table.erase_mac(kMacA);
    check(!table.has_mac(kMacA), "erase_mac removed the entry");
    check(!table.has_ip(IPv4{192, 168, 1, 1}), "erase_mac removed the IP side too");
    check(table.size() == 1, "size after erase");
    table.erase_ip(IPv4{192, 168, 1, 2});
    check(table.empty(), "erase_ip emptied the table");

    // Capacity boundary.
    IdentityTable full;
    for (std::uint32_t i = 1; i <= IdentityTable::capacity; ++i) {
        const MacAddress mac{0x02, 0x00, static_cast<std::uint8_t>((i >> 8) & 0xFF),
                             static_cast<std::uint8_t>(i & 0xFF), 0x00, 0x01};
        const IPv4 ip{192, 168, static_cast<std::uint8_t>((i / 254) + 1),
                      static_cast<std::uint8_t>((i % 254) + 1)};
        if (!full.insert(mac, ip, "n")) { std::cout << "capacity fill failed at " << i << "\n"; break; }
    }
    check(full.size() == IdentityTable::capacity, "capacity reached exactly 254");
    check(!full.insert(MacAddress{7, 7, 7, 7, 7, 7}, IPv4{10, 0, 0, 1}, "overflow"),
          "insert beyond capacity rejected");
    full.clear();
    check(full.empty(), "clear empties the table");

    std::cout << "RESULT checks=" << checks << " failures=" << failures << "\n";
    return failures == 0 ? 0 : 1;
}
