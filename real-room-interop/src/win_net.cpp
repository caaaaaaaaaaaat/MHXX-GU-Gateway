// SPDX-License-Identifier: GPL-2.0-or-later
#include "win_net.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>
#include <windows.h>

#include <cstring>

namespace rri {

namespace {
void ensure_wsa() {
    static bool ready = false;
    if (!ready) {
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
        ready = true;
    }
}

std::vector<UdpEndpoint> udp_table() {
    ensure_wsa();
    std::vector<UdpEndpoint> out;
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0) return out;
    std::vector<unsigned char> buffer(static_cast<std::size_t>(size) + 64);
    auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
    DWORD used = static_cast<DWORD>(buffer.size());
    if (GetExtendedUdpTable(table, &used, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
        return out;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        in_addr addr{};
        addr.s_addr = row.dwLocalAddr;
        char text[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &addr, text, sizeof(text)) == nullptr) continue;
        UdpEndpoint endpoint;
        endpoint.address = text;
        endpoint.port = ntohs(static_cast<u_short>(row.dwLocalPort));
        endpoint.pid = row.dwOwningPid;
        endpoint.wildcard = endpoint.address == "0.0.0.0";
        out.push_back(endpoint);
    }
    return out;
}
} // namespace

std::vector<UdpEndpoint> udp_endpoints_for_pid(std::uint32_t pid) {
    std::vector<UdpEndpoint> out;
    for (const auto& endpoint : udp_table())
        if (endpoint.pid == pid) out.push_back(endpoint);
    return out;
}

std::vector<UdpEndpoint> udp_endpoints_by_port(std::uint16_t port) {
    std::vector<UdpEndpoint> out;
    for (const auto& endpoint : udp_table())
        if (endpoint.port == port) out.push_back(endpoint);
    return out;
}

std::string describe_endpoints(const std::vector<UdpEndpoint>& endpoints) {
    if (endpoints.empty()) return "<none>";
    std::string out;
    for (const auto& endpoint : endpoints) {
        if (!out.empty()) out.push_back(' ');
        out += endpoint.address + ":" + std::to_string(endpoint.port) + "(pid=" +
               std::to_string(endpoint.pid) + ")";
    }
    return out;
}

bool endpoints_loopback_only(const std::vector<UdpEndpoint>& endpoints) {
    if (endpoints.empty()) return false;
    for (const auto& endpoint : endpoints)
        if (endpoint.wildcard || endpoint.address != "127.0.0.1") return false;
    return true;
}

} // namespace rri
