// SPDX-License-Identifier: GPL-2.0-or-later
#include "room_client/session.hpp"
#include <fstream>
#include <iostream>
#include <string>

namespace {
using namespace room_client;
bool bounded_line(std::istream& input, std::string& line) {
    line.clear(); char c;
    while (input.get(c)) {
        if (c == '\n') return true;
        if (line.size() >= Limits{}.packet_bytes * 3)
            throw ProtocolError(ErrorCode::LimitExceeded, line.size(), "fixture line size limit");
        line += c;
    }
    return !line.empty();
}
int usage() {
    std::cerr << "OFFLINE ONLY: no ENet, socket, UDS conversion, or room connection.\n"
                 "room-fixture emit-join NICKNAME\n"
                 "room-fixture decode c2s|s2c HEX\n"
                 "room-fixture replay NICKNAME [HEX-LINES-FILE] (otherwise stdin)\n"
                 "replay starts Joining and consumes server packets, 1 synthetic ms per line.\n";
    return 2;
}
}
int main(int argc, char** argv) {
    using namespace room_client;
    try {
        if (argc == 3 && std::string(argv[1]) == "emit-join") {
            JoinRequest request; request.nickname = argv[2];
            Session session;
            std::cout << to_hex(session.begin_join(request, 0)) << '\n'; return 0;
        }
        if (argc == 4 && std::string(argv[1]) == "decode") {
            const std::string dir = argv[2];
            if (dir != "c2s" && dir != "s2c") return usage();
            auto bytes = parse_hex(argv[3]);
            auto message = decode(bytes, dir == "c2s" ? Direction::ClientToServer : Direction::ServerToClient);
            std::cout << message_name(message_id(message)) << " bytes=" << bytes.size() << '\n'; return 0;
        }
        if ((argc == 3 || argc == 4) && std::string(argv[1]) == "replay") {
            Session session; JoinRequest request; request.nickname = argv[2];
            (void)session.begin_join(request, 0);
            std::ifstream file;
            if (argc == 4) { file.open(argv[3]); if (!file) throw std::runtime_error("cannot open fixture file"); }
            auto& input = argc == 4 ? static_cast<std::istream&>(file) : std::cin;
            std::string line; std::uint64_t time = 0;
            std::cout << "OFFLINE state=Joining\n";
            while (bounded_line(input, line)) {
                if (line.find_first_not_of(" \t\r") == std::string::npos) continue;
                auto message = session.receive(parse_hex(line), ++time);
                std::cout << message_name(message_id(message)) << " state=" << state_name(session.state()) << '\n';
            }
            if (session.state() != SessionState::Joined && session.state() != SessionState::Moderator) {
                std::cerr << "fixture ended without offline membership success\n"; return 1;
            }
            return 0;
        }
        return usage();
    } catch (const ProtocolError& error) {
        std::cerr << "protocol error code=" << static_cast<int>(error.code()) << ": " << error.what() << '\n'; return 1;
    } catch (const std::exception& error) {
        std::cerr << "fixture error: " << error.what() << '\n'; return 1;
    }
}
