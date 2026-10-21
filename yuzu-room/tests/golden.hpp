// SPDX-License-Identifier: GPL-2.0-or-later
// Hand-computed wire goldens for the Yuzu / Nintendo-LDN room protocol v1.
//
// Every byte string here was assembled by hand from the reference senders and
// readers in the yuzu tree (paths in protocol.hpp). None of them was produced by
// the encoder under test; each carries a comment stating how the bytes were
// computed. Frames marked "captured" are copied byte-for-byte from
// crossplay/real-room-interop/evidence/real/yuzu-ea-2024/cases/*.s2c.hex, where
// the label is a real yuzu-room.exe reply; frames marked "hand" are synthetic
// but laid out exactly like the source sender.
#pragma once

#include "yuzu_room/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace yuzu_room::golden {

inline IPv4Address ip_of(std::initializer_list<std::uint8_t> parts) {
    IPv4Address ip{};
    std::size_t i = 0;
    for (const auto part : parts) {
        if (i < ip.size()) ip[i++] = part;
    }
    return ip;
}

inline Bytes bytes_of(std::initializer_list<std::uint8_t> parts) {
    Bytes bytes;
    for (const auto part : parts) bytes.push_back(part);
    return bytes;
}

inline std::string repeat(const std::string& unit, std::size_t count) {
    std::string out;
    out.reserve(unit.size() * count);
    for (std::size_t i = 0; i < count; ++i) out += unit;
    return out;
}

// ---------------------------------------------------------------------------
// Primitives (network/packet.cpp): big-endian widths, u32 length prefixes.
// u8 0x12; u16 0x1234; u32 0x12345678; u64 0x0102030405060708.
inline constexpr const char* primitives_all_hex = "121234123456780102030405060708";
// string "AB" -> u32 length 2 then 0x41 0x42.
inline constexpr const char* primitives_string_hex = "000000024142";
// blob {01,02} -> u32 length 2 then the two bytes.
inline constexpr const char* primitives_blob_hex = "000000020102";
// boolean false,true -> 0x00 0x01.
inline constexpr const char* primitives_bool_hex = "0001";

// ---------------------------------------------------------------------------
// Message goldens. Layout citations are in protocol.hpp and README.md.
// ---------------------------------------------------------------------------
// hand: id 01 | nickname "Test" (00000004 54657374) | preferred 192.168.1.2
//   -- actually no_preferred_ip ff ff ff ff | version 1 (00000001) |
//   password "pw1" (00000003 707731) | token "" (00000000)
inline constexpr const char* join_request_hex =
    "010000000454657374ffffffff000000010000000370773100000000";
// captured prefix: same layout with nickname "rri-a1" (room_member.cpp:284-296;
// the bytes are evidence .../cases/proxy_route.wire.txt line "A C2S").
inline constexpr const char* real_join_request_hex =
    "01000000067272692d6131ffffffff000000010000000370773100000000";
// hand: id 02 | fake IP 192.168.1.2 (room.cpp:641-649).
inline constexpr const char* join_success_hex = "02c0a80102";
// captured: id 02 | fake IP 192.168.124.145 (evidence .../cases/join.s2c.hex).
inline constexpr const char* real_join_success_hex = "02c0a87c91";
// hand: id 24 (JoinSuccessAsMod) | fake IP 192.168.1.2 (room.cpp:651-659).
inline constexpr const char* join_success_mod_hex = "18c0a80102";
// hand: id 03 | name "R" | description "" | slots 4 | port 0x6128 (24872) |
//   preferred game name "GU" | host username "" | count 1 |
//   member: nickname "Test", fake IP 192.168.1.2, game name "GU",
//   game id 0x0102030405060708, game version "1", username "u",
//   display name "D", avatar "" (room.cpp:772-801; byte-identical to
//   crossplay/room-client/fixtures/join-success.hex line 1).
inline constexpr const char* room_information_hex =
    "0300000001520000000000000004612800000002475500000000000000010000000454657374c0a80102000000024755010203040506070800000001310000000175000000014400000000";
// captured: id 03 | name "rri-real-join" | description "real-room-interop" |
//   slots 8 | port 0x9a95 (39573) | preferred "RealRoomInterop" | host "" |
//   count 1 | member "rri-a1" 192.168.124.145 with all five trailing strings
//   empty (room.cpp:772-801; evidence .../cases/join.s2c.hex, client A).
inline constexpr const char* real_room_information_hex =
    "030000000d7272692d7265616c2d6a6f696e000000117265616c2d726f6f6d2d696e7465726f70000000089a950000000f5265616c526f6f6d496e7465726f700000000000000001000000067272692d6131c0a87c9100000000000000000000000000000000000000000000000000000000";
// captured: same shape, room "rri-real-proxy_route", port 0x9a9f (39583),
//   member "rri-a1" 192.168.41.33 (evidence .../cases/proxy_route.s2c.hex).
inline constexpr const char* proxy_room_information_hex =
    "03000000147272692d7265616c2d70726f78795f726f757465000000117265616c2d726f6f6d2d696e7465726f7000"
    "0000089a9f0000000f5265616c526f6f6d496e7465726f700000000000000001000000067272692d6131c0a82921"
    "00000000000000000000000000000000000000000000000000000000";
// hand: id 04 | name "GU" | id 0x0102030405060708 | version "1"
//   (room_member.cpp:668-679; room.cpp:977-985 reads name, id, version).
inline constexpr const char* set_game_info_hex = "0400000002475501020304050607080000000131";
// captured: id 05 | local family 01, ip 192.168.41.33, port 0x1388 | remote
//   family 01, ip 192.168.32.13, port 0x1389 | protocol 03 | broadcast 00 |
//   16 data bytes (room_member.cpp:627-644; evidence .../cases/proxy_route).
inline constexpr const char* proxy_packet_hex =
    "0501c0a82921138801c0a8200d1389030000000010444b525960676e757c838a91989fa6ad";
// hand, projected from the captured 1215-byte dataplane frame
// (evidence .../cases/dataplane_size.s2c.hex: id 06 | type 00 | local
//   192.168.29.100 | remote 192.168.13.52 | broadcast 00 | length 1200). This
//   golden keeps the same header and the first four payload bytes with the
//   declared length rewritten to 4, so the structure test stays small.
inline constexpr const char* ldn_packet_hex = "0600c0a81d64c0a80d340000000004b0141b22";
// hand: id 07 | "hi" (room_member.cpp:661-666).
inline constexpr const char* chat_request_hex = "07000000026869";
// hand: id 07 | nickname "Test" | username "u" | message "hi"
//   (room.cpp:733-748 analogue for chat: nickname, username, message).
inline constexpr const char* chat_message_hex = "0700000004546573740000000175000000026869";
// captured prefix: id 07 | nickname "rri-a1" | username "" | message length
//   0x000001f4 = 500 (room.cpp:944-945 truncates to MaxMessageSize).
inline constexpr const char* real_chat_message_hex_prefix =
    "07000000067272692d613100000000000001f4";
inline std::string real_chat_message_hex() {
    return std::string(real_chat_message_hex_prefix) + repeat("78", 500);
}
// captured: id 0e | type 01 (IdMemberJoin) | nickname "rri-b1" | username ""
//   (room.cpp:733-748; evidence .../cases/chat_limit.s2c.hex).
inline constexpr const char* status_message_hex = "0e01000000067272692d623100000000";

// Single-frame server errors (room.cpp:590-699). Captured exact bytes:
// NameCollision 08, IpCollision 09, VersionMismatch 0a 00000001,
// WrongPassword 0b, CloseRoom 0c (source-only), RoomIsFull 0d,
// HostKicked 0f, HostBanned 10.
inline constexpr const char* name_collision_hex = "08";
inline constexpr const char* ip_collision_hex = "09";
inline constexpr const char* version_mismatch_hex = "0a00000001";
inline constexpr const char* wrong_password_hex = "0b";
inline constexpr const char* close_room_hex = "0c";
inline constexpr const char* room_full_hex = "0d";
inline constexpr const char* host_kicked_hex = "0f";
inline constexpr const char* host_banned_hex = "10";

// ---------------------------------------------------------------------------
// Expected structures for the golden byte strings.
// ---------------------------------------------------------------------------
inline JoinRequest join_request() {
    JoinRequest request;
    request.nickname = "Test";
    request.preferred_fake_ip = no_preferred_ip;
    request.version = network_version;
    request.password = "pw1";
    return request;
}

inline JoinRequest real_join_request() {
    auto request = join_request();
    request.nickname = "rri-a1";
    return request;
}

inline JoinSuccess join_success() { return JoinSuccess{ip_of({192, 168, 1, 2}), false}; }
inline JoinSuccess real_join_success() { return JoinSuccess{ip_of({192, 168, 124, 145}), false}; }
inline JoinSuccess join_success_mod() { return JoinSuccess{ip_of({192, 168, 1, 2}), true}; }

inline Member member_rri_a1(const IPv4Address& ip) {
    Member member;
    member.nickname = "rri-a1";
    member.fake_ip = ip;
    return member;
}

inline RoomInformation room_information() {
    RoomInformation info;
    info.name = "R";
    info.member_slots = 4;
    info.port = default_room_port;
    info.preferred_game_name = "GU";
    Member member;
    member.nickname = "Test";
    member.fake_ip = ip_of({192, 168, 1, 2});
    member.game_name = "GU";
    member.game_id = 0x0102030405060708ULL;
    member.game_version = "1";
    member.username = "u";
    member.display_name = "D";
    info.members.push_back(member);
    return info;
}

inline RoomInformation real_room_information() {
    RoomInformation info;
    info.name = "rri-real-join";
    info.description = "real-room-interop";
    info.member_slots = 8;
    info.port = 0x9a95;
    info.preferred_game_name = "RealRoomInterop";
    info.members.push_back(member_rri_a1(ip_of({192, 168, 124, 145})));
    return info;
}

inline RoomInformation proxy_room_information() {
    RoomInformation info;
    info.name = "rri-real-proxy_route";
    info.description = "real-room-interop";
    info.member_slots = 8;
    info.port = 0x9a9f;
    info.preferred_game_name = "RealRoomInterop";
    info.members.push_back(member_rri_a1(ip_of({192, 168, 41, 33})));
    return info;
}

inline GameInfo set_game_info() { return GameInfo{"GU", 0x0102030405060708ULL, "1"}; }

inline ProxyPacket proxy_packet() {
    ProxyPacket packet;
    packet.local_endpoint = SockAddrIn{0x01, ip_of({192, 168, 41, 33}), 0x1388};
    packet.remote_endpoint = SockAddrIn{0x01, ip_of({192, 168, 32, 13}), 0x1389};
    packet.protocol = 0x03;
    packet.broadcast = false;
    packet.data = bytes_of({0x44, 0x4b, 0x52, 0x59, 0x60, 0x67, 0x6e, 0x75,
                            0x7c, 0x83, 0x8a, 0x91, 0x98, 0x9f, 0xa6, 0xad});
    return packet;
}

inline LdnPacket ldn_packet() {
    LdnPacket packet;
    packet.type = LdnPacketType::Scan;
    packet.local_ip = ip_of({192, 168, 29, 100});
    packet.remote_ip = ip_of({192, 168, 13, 52});
    packet.broadcast = false;
    packet.data = bytes_of({0xb0, 0x14, 0x1b, 0x22});
    return packet;
}

inline ChatRequest chat_request() { return ChatRequest{"hi"}; }
inline ChatMessage chat_message() { return ChatMessage{"Test", "u", "hi"}; }
inline ChatMessage real_chat_message() { return ChatMessage{"rri-a1", "", std::string(500, 'x')}; }
inline StatusMessage status_message() { return StatusMessage{StatusType::MemberJoin, "rri-b1", ""}; }

struct Fixture {
    std::string name;
    std::string hex;
    Direction direction;
    Message expected;
};

inline std::vector<Fixture> fixtures() {
    const auto error = [](MessageId id, std::uint32_t version) {
        return Message{ServerError{id, version}};
    };
    return {
        {"join_request", join_request_hex, Direction::ClientToServer, join_request()},
        {"real_join_request", real_join_request_hex, Direction::ClientToServer, real_join_request()},
        {"join_success", join_success_hex, Direction::ServerToClient, join_success()},
        {"real_join_success", real_join_success_hex, Direction::ServerToClient, real_join_success()},
        {"join_success_as_mod", join_success_mod_hex, Direction::ServerToClient, join_success_mod()},
        {"room_information", room_information_hex, Direction::ServerToClient, room_information()},
        {"real_room_information", real_room_information_hex, Direction::ServerToClient, real_room_information()},
        {"proxy_room_information", proxy_room_information_hex, Direction::ServerToClient, proxy_room_information()},
        {"set_game_info", set_game_info_hex, Direction::ClientToServer, set_game_info()},
        {"proxy_packet", proxy_packet_hex, Direction::ClientToServer, proxy_packet()},
        {"ldn_packet", ldn_packet_hex, Direction::ClientToServer, ldn_packet()},
        {"chat_request", chat_request_hex, Direction::ClientToServer, chat_request()},
        {"chat_message", chat_message_hex, Direction::ServerToClient, chat_message()},
        {"real_chat_message", real_chat_message_hex(), Direction::ServerToClient, real_chat_message()},
        {"status_message", status_message_hex, Direction::ServerToClient, status_message()},
        {"name_collision", name_collision_hex, Direction::ServerToClient, error(MessageId::NameCollision, 0)},
        {"ip_collision", ip_collision_hex, Direction::ServerToClient, error(MessageId::IpCollision, 0)},
        {"version_mismatch", version_mismatch_hex, Direction::ServerToClient, error(MessageId::VersionMismatch, 1)},
        {"wrong_password", wrong_password_hex, Direction::ServerToClient, error(MessageId::WrongPassword, 0)},
        {"close_room", close_room_hex, Direction::ServerToClient, error(MessageId::CloseRoom, 0)},
        {"room_is_full", room_full_hex, Direction::ServerToClient, error(MessageId::RoomIsFull, 0)},
        {"host_kicked", host_kicked_hex, Direction::ServerToClient, error(MessageId::HostKicked, 0)},
        {"host_banned", host_banned_hex, Direction::ServerToClient, error(MessageId::HostBanned, 0)},
    };
}

} // namespace yuzu_room::golden
