// SPDX-FileCopyrightText: Copyright 2026 LAN codec contributors
// SPDX-License-Identifier: GPL-3.0-or-later
#include "lan_codecs.h"
#include "hex_io.h"
#include <charconv>
#include <iostream>
#include <stdexcept>
#include <string_view>
using namespace lan_codec;
namespace {
void help() {
    std::cout << "Offline synthetic codec only; NOT a game translator, relay or game-compatibility proof.\n"
        "Input HEX is whitespace-separated hex, or @path to an owned offline hex fixture.\n"
        "lan-codecs uds-decode HEX\n"
        "lan-codecs uds-encode CHANNEL DESTINATION SOURCE SEQUENCE HEX\n"
        "lan-codecs node-decode HEX\n"
        "lan-codecs network-decode HEX\n"
        "lan-codecs ldn-decode TYPE HEX   (0 Scan,1 ScanResp,2 Connect,3 Sync,4 Disconnect,5 Destroy)\n"
        "lan-codecs zstd-decode HEX\n"
        "lan-codecs zstd-encode HEX\n"
        "Numeric arguments: unsigned decimal. No sockets, keys, title IDs or patches.\n";
}
unsigned number(std::string_view text, unsigned limit) {
    unsigned v = 0; auto [p, e] = std::from_chars(text.data(), text.data() + text.size(), v);
    if (e != std::errc{} || p != text.data() + text.size() || v > limit) throw std::runtime_error("numeric argument outside range");
    return v;
}
template<class T> bool check(const Result<T>& r) {
    if (r) return true;
    std::cerr << "error=" << error_name(r.error) << " offset=" << r.offset << '\n'; return false;
}
void print_node(const NodeInfo& n) {
    const auto room = node_ipv4_from_room_bytes(n.node_ipv4);
    std::cout << "node_id=" << int(n.node_id) << " connected=" << unsigned(n.is_connected)
        << " node_ipv4_bytes=" << hex_io::format(n.node_ipv4) << " room_ipv4_bytes=" << hex_io::format(room)
        << " communication_version=" << n.communication_version << " user_name_bytes=" << hex_io::format(n.user_name) << '\n';
}
void print_network(const NetworkInfo& n) {
    std::cout << "profile=yuzu-raw-body-le created-network-subset nodes=" << unsigned(n.node_count)
        << " max_nodes=" << unsigned(n.node_count_max) << " local_communication_id=0x" << std::hex
        << n.local_communication_id << std::dec << " advertise_size=" << n.advertise_size << '\n';
}
int bytes_result(const Result<Bytes>& r) { if (!check(r)) return 2; std::cout << hex_io::format(r.value) << '\n'; return 0; }
}
int main(int argc, char** argv) {
    try {
        if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) { help(); return 0; }
        const std::string_view mode(argv[1]);
        if (mode == "uds-encode" && argc == 7) {
            UdsData d; d.channel = static_cast<Byte>(number(argv[2], 255)); d.destination = static_cast<std::uint16_t>(number(argv[3], 65535));
            d.source = static_cast<std::uint16_t>(number(argv[4], 65535)); d.sequence = static_cast<std::uint16_t>(number(argv[5], 65535));
            d.application = hex_io::load(argv[6], uds_application_max); return bytes_result(encode_uds(d));
        }
        if (mode == "ldn-decode" && argc == 4) {
            auto data = hex_io::load(argv[3], network_info_size + 1);
            auto r = decode_ldn(static_cast<Byte>(number(argv[2], 255)), data); if (!check(r)) return 2;
            std::cout << "ldn_type=" << unsigned(static_cast<Byte>(r.value.type)) << " body_size=" << data.size() << '\n';
            if (r.value.type == LdnType::connect || r.value.type == LdnType::disconnect) print_node(r.value.node);
            else if (r.value.type == LdnType::scan_response || r.value.type == LdnType::sync_network) print_network(r.value.network);
            return 0;
        }
        if (argc != 3) { help(); return 1; }
        auto data = hex_io::load(argv[2]);
        if (mode == "uds-decode") {
            auto r = decode_uds(data); if (!check(r)) return 2;
            std::cout << "channel=" << unsigned(r.value.channel) << " destination=" << r.value.destination << " source=" << r.value.source
                << " sequence=" << r.value.sequence << " opaque_application=" << hex_io::format(r.value.application) << '\n'; return 0;
        }
        if (mode == "node-decode") { auto r = decode_node(data); if (!check(r)) return 2; print_node(r.value); return 0; }
        if (mode == "network-decode") { auto r = decode_network(data); if (!check(r)) return 2; print_network(r.value); return 0; }
        if (mode == "zstd-decode") return bytes_result(decode_zstd_single(data));
        if (mode == "zstd-encode") return bytes_result(encode_zstd_default(data));
        help(); return 1;
    } catch (const std::exception& e) { std::cerr << "input_error=" << e.what() << '\n'; return 1; }
}
