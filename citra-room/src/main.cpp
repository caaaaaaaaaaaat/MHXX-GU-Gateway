// SPDX-License-Identifier: GPL-2.0-or-later
// Offline replay CLI for the Citra room codec.
//
// OFFLINE ONLY: no ENet, socket, UDS conversion, or room connection.
#include "citra_room/protocol.hpp"
#include "citra_room/session.hpp"

#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace citra_room;

constexpr std::size_t max_line_bytes = 3U * 65536U + 64U;

void usage() {
    std::cout
        << "usage:\n"
        << "  citra-room emit-join NICKNAME\n"
        << "  citra-room decode c2s|s2c HEX\n"
        << "  citra-room replay NICKNAME [HEX-LINES-FILE]\n"
        << "\n"
        << "OFFLINE ONLY: no ENet, socket, UDS conversion, or room connection.\n";
}

std::optional<Direction> parse_direction(const std::string& name) {
    if (name == "c2s" || name == "client-to-server") return Direction::ClientToServer;
    if (name == "s2c" || name == "server-to-client") return Direction::ServerToClient;
    return std::nullopt;
}

int emit_join(const std::string& nickname) {
    if (!is_valid_nickname(nickname)) {
        std::cerr << "invalid nickname (room.cpp:566-576 requires ^[ a-zA-Z0-9._-]{4,20}$): "
                  << nickname << "\n";
        return 2;
    }
    // Mirror the real client (room_member.cpp:280-294): the preferred MAC is
    // NoPreferredMac (room.h:46) unless the user pinned one, and the console id
    // hash, password and token are the caller's strings (empty here).
    const JoinRequest request{nickname, {}, no_preferred_mac, network_version, {}, {}};
    const Bytes bytes = encode(Message{request}, Direction::ClientToServer);
    std::cout << to_hex(bytes) << "\n";
    return 0;
}

int decode_command(const std::string& direction_name, const std::string& hex) {
    const std::optional<Direction> direction = parse_direction(direction_name);
    if (!direction) {
        std::cerr << "unknown direction: " << direction_name << "\n";
        return 2;
    }
    const Message message = decode(parse_hex(hex), *direction);
    std::cout << message_name(message_id(message)) << "\n";
    if (const auto* error = std::get_if<ServerError>(&message)) {
        std::cout << "server_version=" << error->server_version << "\n";
    }
    return 0;
}

std::string trim(const std::string& line) {
    const std::size_t first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const std::size_t last = line.find_last_not_of(" \t\r\n");
    return line.substr(first, last - first + 1);
}

int replay(const std::string& nickname, std::istream& input, bool from_file) {
    Session session;
    std::uint64_t now_ms = 0;
    (void)session.begin_join(JoinRequest{nickname, {}, no_preferred_mac, network_version, {}, {}},
                             now_ms);
    std::cout << "JOIN-REQUEST state=" << state_name(session.state()) << "\n";

    std::string line;
    std::size_t index = 0;
    while (std::getline(input, line)) {
        const std::string hex = trim(line);
        if (hex.empty() || hex[0] == '#') continue;
        if (hex.size() > max_line_bytes) {
            std::cerr << "line " << index << " exceeds the offline line bound\n";
            return 1;
        }
        ++now_ms; // one synthetic millisecond per fixture line
        const Message message = session.receive(parse_hex(hex), now_ms);
        std::cout << message_name(message_id(message)) << " state=" << state_name(session.state())
                  << "\n";
        ++index;
    }
    if (from_file && input.bad()) {
        std::cerr << "error reading the fixture file\n";
        return 1;
    }
    std::cout << "final state=" << state_name(session.state())
              << " joined=" << (session.joined() ? "yes" : "no") << "\n";
    return session.joined() ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            usage();
            return 2;
        }
        const std::string command = argv[1];
        if (command == "emit-join") {
            if (argc != 3) {
                usage();
                return 2;
            }
            return emit_join(argv[2]);
        }
        if (command == "decode") {
            if (argc != 4) {
                usage();
                return 2;
            }
            return decode_command(argv[2], argv[3]);
        }
        if (command == "replay") {
            if (argc < 3 || argc > 4) {
                usage();
                return 2;
            }
            if (argc == 4) {
                std::ifstream file(argv[3]);
                if (!file) {
                    std::cerr << "cannot open fixture file: " << argv[3] << "\n";
                    return 1;
                }
                return replay(argv[2], file, true);
            }
            return replay(argv[2], std::cin, false);
        }
        usage();
        return 2;
    } catch (const ProtocolError& error) {
        std::cerr << "protocol error code=" << error_code_name(error.code())
                  << " offset=" << error.offset() << ": " << error.what() << "\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    }
}
