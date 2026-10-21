// SPDX-License-Identifier: GPL-2.0-or-later
// Offline replay / decode CLI for the Yuzu room v1 codec and session.
//
// OFFLINE ONLY: this program opens no sockets, speaks no ENet, runs no threads,
// and never talks to a room server or a game.
#include "yuzu_room/protocol.hpp"
#include "yuzu_room/session.hpp"

#include <exception>
#include <fstream>
#include <iostream>
#include <istream>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace yuzu_room;

constexpr const char* offline_banner =
    "OFFLINE ONLY: no ENet, socket, LAN proxy, or room connection.";

void usage() {
    std::cerr << "usage:\n"
              << "  yuzu-room emit-join NICKNAME [PASSWORD] [TOKEN]\n"
              << "  yuzu-room decode c2s|s2c HEX\n"
              << "  yuzu-room replay NICKNAME [HEX-FILE]\n"
              << offline_banner << "\n";
}

std::string ip_text(const IPv4Address& ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." +
           std::to_string(ip[3]);
}

std::optional<Direction> parse_direction(const std::string& text) {
    if (text == "c2s" || text == "client-to-server") return Direction::ClientToServer;
    if (text == "s2c" || text == "server-to-client") return Direction::ServerToClient;
    return std::nullopt;
}

void print_join_request(const JoinRequest& request) {
    std::cout << "nickname=" << request.nickname << " preferred_fake_ip="
              << ip_text(request.preferred_fake_ip) << " version=" << request.version
              << " password_bytes=" << request.password.size() << " token_bytes=" << request.token.size()
              << "\n";
}

void print_room_information(const RoomInformation& info) {
    std::cout << "name=" << info.name << " description_bytes=" << info.description.size()
              << " member_slots=" << info.member_slots << " port=" << info.port
              << " preferred_game=" << info.preferred_game_name << " host_username_bytes="
              << info.host_username.size() << " members=" << info.members.size() << "\n";
    for (const auto& member : info.members) {
        std::cout << "  member nickname=" << member.nickname << " fake_ip=" << ip_text(member.fake_ip)
                  << " game_name=" << member.game_name << " game_id=" << member.game_id
                  << " game_version=" << member.game_version << " username_bytes="
                  << member.username.size() << " display_name_bytes=" << member.display_name.size()
                  << " avatar_url_bytes=" << member.avatar_url.size() << "\n";
    }
}

void print_message(const Message& message) {
    std::cout << "message=" << message_name(message_id(message));
    if (const auto* request = std::get_if<JoinRequest>(&message)) {
        std::cout << " "; print_join_request(*request);
    } else if (const auto* success = std::get_if<JoinSuccess>(&message)) {
        std::cout << " assigned_fake_ip=" << ip_text(success->assigned_fake_ip)
                  << " moderator=" << (success->moderator ? "yes" : "no") << "\n";
    } else if (const auto* info = std::get_if<RoomInformation>(&message)) {
        std::cout << " "; print_room_information(*info);
    } else if (const auto* game = std::get_if<GameInfo>(&message)) {
        std::cout << " name=" << game->name << " id=" << game->id << " version=" << game->version << "\n";
    } else if (const auto* proxy = std::get_if<ProxyPacket>(&message)) {
        std::cout << " local=" << ip_text(proxy->local_endpoint.ip) << ":" << proxy->local_endpoint.port
                  << " remote=" << ip_text(proxy->remote_endpoint.ip) << ":" << proxy->remote_endpoint.port
                  << " family=" << static_cast<unsigned>(proxy->local_endpoint.family)
                  << " protocol=" << static_cast<unsigned>(proxy->protocol)
                  << " (" << protocol_name(proxy->protocol) << ")"
                  << " broadcast=" << (proxy->broadcast ? "yes" : "no")
                  << " data_bytes=" << proxy->data.size() << "\n";
    } else if (const auto* ldn = std::get_if<LdnPacket>(&message)) {
        std::cout << " type=" << ldn_type_name(ldn->type) << " local_ip=" << ip_text(ldn->local_ip)
                  << " remote_ip=" << ip_text(ldn->remote_ip)
                  << " broadcast=" << (ldn->broadcast ? "yes" : "no")
                  << " data_bytes=" << ldn->data.size() << "\n";
    } else if (const auto* chat = std::get_if<ChatRequest>(&message)) {
        std::cout << " message_bytes=" << chat->message.size() << "\n";
    } else if (const auto* chat = std::get_if<ChatMessage>(&message)) {
        std::cout << " nickname=" << chat->nickname << " username_bytes=" << chat->username.size()
                  << " message_bytes=" << chat->message.size() << "\n";
    } else if (const auto* status = std::get_if<StatusMessage>(&message)) {
        std::cout << " type=" << status_type_name(status->type) << " nickname=" << status->nickname
                  << " username_bytes=" << status->username.size() << "\n";
    } else if (const auto* error = std::get_if<ServerError>(&message)) {
        std::cout << " server_version=" << error->server_version << "\n";
    }
}

int command_emit_join(const std::vector<std::string>& args) {
    if (args.empty()) { usage(); return 2; }
    if (!is_valid_nickname(args[0])) {
        std::cerr << "invalid nickname: room.cpp:550-560 requires ^[ a-zA-Z0-9._-]{4,20}$\n";
        return 2;
    }
    JoinRequest request;
    request.nickname = args[0];
    if (args.size() > 1) request.password = args[1];
    if (args.size() > 2) request.token = args[2];
    std::cout << to_hex(encode(Message{request}, Direction::ClientToServer)) << "\n";
    return 0;
}

int command_decode(const std::vector<std::string>& args) {
    if (args.size() != 2) { usage(); return 2; }
    const auto direction = parse_direction(args[0]);
    if (!direction) { usage(); return 2; }
    const auto message = decode(parse_hex(args[1]), *direction);
    print_message(message);
    return 0;
}

int command_replay(const std::vector<std::string>& args) {
    if (args.empty()) { usage(); return 2; }
    if (!is_valid_nickname(args[0])) {
        std::cerr << "invalid nickname: room.cpp:550-560 requires ^[ a-zA-Z0-9._-]{4,20}$\n";
        return 2;
    }
    std::ifstream file;
    std::istream* input = &std::cin;
    if (args.size() > 1) {
        file.open(args[1]);
        if (!file) { std::cerr << "cannot open " << args[1] << "\n"; return 2; }
        input = &file;
    }
    Session session;
    JoinRequest request;
    request.nickname = args[0];
    (void)session.begin_join(request, 0);
    std::uint64_t now_ms = 0;
    std::string line;
    while (std::getline(*input, line)) {
        std::size_t begin = line.find_first_not_of(" \t\r");
        if (begin == std::string::npos) continue;
        if (line[begin] == '#') continue;
        ++now_ms;
        (void)session.receive(parse_hex(line), now_ms);
        std::cout << "t=" << now_ms << " state=" << state_name(session.state()) << "\n";
    }
    std::cout << "final state=" << state_name(session.state())
              << " joined=" << (session.joined() ? "yes" : "no") << "\n";
    return session.joined() ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) { usage(); return 2; }
    const std::string command = args.front();
    args.erase(args.begin());
    try {
        if (command == "emit-join") return command_emit_join(args);
        if (command == "decode") return command_decode(args);
        if (command == "replay") return command_replay(args);
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
