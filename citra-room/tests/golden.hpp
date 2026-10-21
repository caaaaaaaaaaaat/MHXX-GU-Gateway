// SPDX-License-Identifier: GPL-2.0-or-later
// Hand-computed golden hex for the Citra room wire format.
//
// Every hex string below was derived by hand from the Citra source layout and
// from the field-order tables in docs/citra-room-report.md; none of them was
// produced by this project's own encoder. Source anchors:
//   citra-master/src/network/packet.cpp      (primitive byte order, u32 lengths)
//   citra-master/src/network/room_member.cpp (SendJoinRequest :280-294,
//                                             SendWifiPacket :589-598,
//                                             SendChatMessage :600-605,
//                                             SendGameInfo :607-617)
//   citra-master/src/network/room.cpp        (BroadcastRoomInformation :806-834,
//                                             SendStatusMessage :767-804,
//                                             SendJoinSuccess :675-693,
//                                             error senders :614-713,750-765)
#ifndef CITRA_ROOM_GOLDEN_HPP
#define CITRA_ROOM_GOLDEN_HPP

#include "citra_room/protocol.hpp"

#include <initializer_list>
#include <string>
#include <vector>

namespace citra_room {
namespace golden {

inline MacAddress mac_of(std::initializer_list<std::uint8_t> bytes) {
    MacAddress mac{};
    std::size_t i = 0;
    for (const auto byte : bytes) {
        if (i >= mac.size()) break;
        mac[i++] = byte;
    }
    return mac;
}

// --- Message goldens (spaced hex, whitespace ignored by parse_hex) ----------

// id 01 | u32-len "Nick" | u32-len "cid0" | 6-byte NoPreferredMac |
// u32 4 | u32-len "pw" | u32-len "tk"
inline constexpr const char* join_request_hex =
    "01 00000004 4e69636b 00000004 63696430 ffffffffffff 00000004 "
    "00000002 7077 00000002 746b";

// id 02 | 6-byte MAC (NintendoOUI 00:1F:32 prefix, room.cpp:54-55)
inline constexpr const char* join_success_hex = "02 001f32112233";
// id 18 (=24) | 6-byte MAC
inline constexpr const char* join_success_as_mod_hex = "18 001f32112233";

// id 03 | name | description | u32 slots | u16 port | preferred_game |
// host_username | u32 count | member{ nickname, mac, game_name, u64 game_id,
// username, display_name, avatar_url }
inline constexpr const char* room_information_hex =
    "03 00000004 526f6f6d 00000004 44657363 00000004 6128 00000004 47616d65 "
    "00000004 486f7374 00000001 00000004 4e69636b 001f32112233 00000004 47616d65 "
    "1122334455667788 00000004 686f7374 00000005 486f737479 00000001 75";

// id 04 | u32-len "Game" | u64 0xff
inline constexpr const char* set_game_info_hex = "04 00000004 47616d65 00000000000000ff";

// id 05 | u8 type=1 (Data) | u8 channel=6 | 6-byte transmitter |
// 6-byte destination | u32-len blob 0xdeadbeef
inline constexpr const char* wifi_packet_hex =
    "05 01 06 001f32000002 ffffffffffff 00000004 deadbeef";

// id 06 | u32-len "hi!"   (client -> server chat request)
inline constexpr const char* chat_request_hex = "06 00000003 686921";
// id 06 | nickname | username | u32-len "hi!"   (server -> client echo)
inline constexpr const char* chat_message_hex =
    "06 00000004 486f7374 00000004 686f7374 00000003 686921";

// id 0e (=14) | u8 type=1 (MemberJoin) | nickname | username
inline constexpr const char* status_message_hex =
    "0e 01 00000004 4e69636b 00000004 6e69636b";

inline constexpr const char* name_collision_hex = "07";
inline constexpr const char* mac_collision_hex = "08";
inline constexpr const char* version_mismatch_hex = "09 00000004";
inline constexpr const char* wrong_password_hex = "0a";
inline constexpr const char* close_room_hex = "0b";
inline constexpr const char* room_is_full_hex = "0c";
inline constexpr const char* console_id_collision_hex = "0d";
inline constexpr const char* host_kicked_hex = "0f";
inline constexpr const char* host_banned_hex = "10";

// --- Expected messages ------------------------------------------------------

inline JoinRequest join_request() {
    return JoinRequest{"Nick", "cid0", no_preferred_mac, 4, "pw", "tk"};
}
inline JoinSuccess join_success() {
    return JoinSuccess{mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x33}), false};
}
inline JoinSuccess join_success_as_mod() {
    return JoinSuccess{mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x33}), true};
}
inline RoomInformation room_information() {
    RoomInformation info;
    info.name = "Room";
    info.description = "Desc";
    info.member_slots = 4;
    info.port = 24872;
    info.preferred_game = "Game";
    info.host_username = "Host";
    Member member;
    member.nickname = "Nick";
    member.mac = mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x33});
    member.game_name = "Game";
    member.game_id = 0x1122334455667788ULL;
    member.username = "host";
    member.display_name = "Hosty";
    member.avatar_url = "u";
    info.members.push_back(member);
    return info;
}
inline GameInfo set_game_info() { return GameInfo{"Game", 0x00000000000000ffULL}; }
inline WifiPacket wifi_packet() {
    return WifiPacket{FrameType::Data, 6, mac_of({0x00, 0x1f, 0x32, 0x00, 0x00, 0x02}),
                      broadcast_mac, Bytes{0xde, 0xad, 0xbe, 0xef}};
}
inline ChatRequest chat_request() { return ChatRequest{"hi!"}; }
inline ChatMessage chat_message() { return ChatMessage{"Host", "host", "hi!"}; }
inline StatusMessage status_message() { return StatusMessage{StatusType::MemberJoin, "Nick", "nick"}; }

struct Fixture {
    std::string name;
    std::string hex;
    Direction direction;
    Message expected;
};

inline std::vector<Fixture> fixtures() {
    return {
        {"join_request", join_request_hex, Direction::ClientToServer, join_request()},
        {"join_success", join_success_hex, Direction::ServerToClient, join_success()},
        {"join_success_as_mod", join_success_as_mod_hex, Direction::ServerToClient, join_success_as_mod()},
        {"room_information", room_information_hex, Direction::ServerToClient, room_information()},
        {"set_game_info", set_game_info_hex, Direction::ClientToServer, set_game_info()},
        {"wifi_packet_c2s", wifi_packet_hex, Direction::ClientToServer, wifi_packet()},
        {"wifi_packet_s2c", wifi_packet_hex, Direction::ServerToClient, wifi_packet()},
        {"chat_request", chat_request_hex, Direction::ClientToServer, chat_request()},
        {"chat_message", chat_message_hex, Direction::ServerToClient, chat_message()},
        {"status_message", status_message_hex, Direction::ServerToClient, status_message()},
        {"name_collision", name_collision_hex, Direction::ServerToClient, ServerError{MessageId::NameCollision, 0}},
        {"mac_collision", mac_collision_hex, Direction::ServerToClient, ServerError{MessageId::MacCollision, 0}},
        {"version_mismatch", version_mismatch_hex, Direction::ServerToClient, ServerError{MessageId::VersionMismatch, 4}},
        {"wrong_password", wrong_password_hex, Direction::ServerToClient, ServerError{MessageId::WrongPassword, 0}},
        {"close_room", close_room_hex, Direction::ServerToClient, ServerError{MessageId::CloseRoom, 0}},
        {"room_is_full", room_is_full_hex, Direction::ServerToClient, ServerError{MessageId::RoomIsFull, 0}},
        {"console_id_collision", console_id_collision_hex, Direction::ServerToClient, ServerError{MessageId::ConsoleIdCollision, 0}},
        {"host_kicked", host_kicked_hex, Direction::ServerToClient, ServerError{MessageId::HostKicked, 0}},
        {"host_banned", host_banned_hex, Direction::ServerToClient, ServerError{MessageId::HostBanned, 0}},
    };
}

// --- Primitive goldens (packet.cpp) ----------------------------------------

inline constexpr const char* primitives_all_hex = "121234123456780102030405060708";
inline constexpr const char* primitives_string_hex = "000000024142";
inline constexpr const char* primitives_blob_hex = "000000020102";
inline constexpr const char* primitives_bool_hex = "0001";

} // namespace golden
} // namespace citra_room

#endif // CITRA_ROOM_GOLDEN_HPP
