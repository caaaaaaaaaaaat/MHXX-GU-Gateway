// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
// Read-only view of the local UDP endpoint table (IP Helper API). Used to prove
// which address a room server actually bound and that the port is gone after exit.
#include <cstdint>
#include <string>
#include <vector>

namespace rri {

struct UdpEndpoint {
    std::string address; // dotted quad, e.g. 127.0.0.1 or 0.0.0.0
    std::uint16_t port = 0;
    std::uint32_t pid = 0;
    bool wildcard = false; // address == 0.0.0.0
};

std::vector<UdpEndpoint> udp_endpoints_for_pid(std::uint32_t pid);
std::vector<UdpEndpoint> udp_endpoints_by_port(std::uint16_t port);
// "127.0.0.1:39572(pid=1234) 0.0.0.0:39572(pid=1234)" or "<none>"
std::string describe_endpoints(const std::vector<UdpEndpoint>& endpoints);
bool endpoints_loopback_only(const std::vector<UdpEndpoint>& endpoints);

} // namespace rri
