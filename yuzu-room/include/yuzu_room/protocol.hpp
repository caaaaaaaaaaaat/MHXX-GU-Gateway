// SPDX-License-Identifier: GPL-2.0-or-later
// Bounded, offline codec for the Yuzu / Nintendo-LDN room wire protocol,
// network_version 1. Derived (not copied) from the read-only yuzu reference
// tree at
//   crossplay/reference/yuzu-src-20220923/
//     yuzu-windows-msvc-source-20220923-7edc31be2/src/
//       network/room.h, network/room.cpp, network/room_member.h,
//       network/room_member.cpp, network/packet.h, network/packet.cpp,
//       common/socket_types.h, common/announce_multiplayer_room.h,
//       network/verify_user.h
// Every wire fact below carries a file:line citation into that tree.
//
// OFFLINE ONLY: no sockets, no ENet, no threads, no timers, no emulator code.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu_room {

using Bytes = std::vector<std::uint8_t>;
using IPv4Address = std::array<std::uint8_t, 4>;

// ---------------------------------------------------------------------------
// Constants (yuzu src/network/room.h)
// ---------------------------------------------------------------------------
constexpr std::uint32_t network_version = 1;            // room.h:21
constexpr std::uint16_t default_room_port = 24872;      // room.h:23
constexpr std::size_t max_message_size = 500;           // room.h:25
constexpr std::size_t max_concurrent_connections = 254; // room.h:28
constexpr std::size_t num_channels = 1;                 // room.h:30

// room.h:34  "constexpr IPv4Address NoPreferredIP{0xFF, 0xFF, 0xFF, 0xFF};"
inline constexpr IPv4Address no_preferred_ip{0xff, 0xff, 0xff, 0xff};
inline constexpr IPv4Address broadcast_ip{0xff, 0xff, 0xff, 0xff};

// common/socket_types.h:11-13  "enum class Domain : u8 { INET };"
// common/socket_types.h:24-28  "enum class Protocol : u8 { ICMP, TCP, UDP };"
//
// DOCUMENTED DISAGREEMENT (see README "Open questions"): the 2022 reference
// source gives INET == 0 and UDP == 2, but every captured ProxyPacket in
// crossplay/real-room-interop/evidence/real/yuzu-ea-2024 carries family 0x01
// and protocol 0x03. The room itself never reads either byte
// (room.cpp:815-871 ignores them and relays the frame verbatim), so this codec
// preserves both as opaque u8 and refuses to range-check them. The names below
// are the reference-source names only.
constexpr std::uint8_t domain_inet = 0;
constexpr std::uint8_t protocol_icmp = 0;
constexpr std::uint8_t protocol_tcp = 1;
constexpr std::uint8_t protocol_udp = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
enum class ErrorCode {
    Truncated,
    LimitExceeded,
    InvalidBoolean,
    InvalidEnum,
    UnknownMessage,
    UnsupportedMessage,
    TrailingBytes,
    WrongDirection,
    InvalidState,
    InvalidArgument,
    Timeout,
};

std::string error_code_name(ErrorCode code);

class ProtocolError final : public std::runtime_error {
public:
    ProtocolError(ErrorCode code, std::size_t offset, const std::string& detail);
    ErrorCode code() const noexcept { return code_; }
    std::size_t offset() const noexcept { return offset_; }

private:
    ErrorCode code_;
    std::size_t offset_;
};

// ---------------------------------------------------------------------------
// Direction and message ids (network/room.h:37-73)
// ---------------------------------------------------------------------------
enum class Direction { ClientToServer, ServerToClient };
std::string direction_name(Direction direction);

enum class MessageId : std::uint8_t {
    JoinRequest = 1,        // room.h:38
    JoinSuccess = 2,        // room.h:39
    RoomInformation = 3,    // room.h:40
    SetGameInfo = 4,        // room.h:41
    ProxyPacket = 5,        // room.h:42
    LdnPacket = 6,          // room.h:43
    ChatMessage = 7,        // room.h:44
    NameCollision = 8,      // room.h:45
    IpCollision = 9,        // room.h:46
    VersionMismatch = 10,   // room.h:47
    WrongPassword = 11,     // room.h:48
    CloseRoom = 12,         // room.h:49
    RoomIsFull = 13,        // room.h:50
    StatusMessage = 14,     // room.h:51
    HostKicked = 15,        // room.h:52
    HostBanned = 16,        // room.h:53
    ModKick = 17,           // room.h:54
    ModBan = 18,            // room.h:55
    ModUnban = 19,          // room.h:56
    ModGetBanList = 20,     // room.h:57
    ModBanListResponse = 21,// room.h:58
    ModPermissionDenied = 22,// room.h:59
    ModNoSuchUser = 23,     // room.h:60
    JoinSuccessAsMod = 24,  // room.h:61
};

// network/room_member.h:20-27  "enum class LDNPacketType : u8 { Scan, ScanResp,
// Connect, SyncNetwork, Disconnect, DestroyNetwork };"
enum class LdnPacketType : std::uint8_t {
    Scan = 0,
    ScanResp = 1,
    Connect = 2,
    SyncNetwork = 3,
    Disconnect = 4,
    DestroyNetwork = 5,
};

// network/room.h:67-73  "enum StatusMessageTypes : u8 { IdMemberJoin = 1,
// IdMemberLeave, IdMemberKicked, IdMemberBanned, IdAddressUnbanned };"
enum class StatusType : std::uint8_t {
    MemberJoin = 1,
    MemberLeave = 2,
    MemberKicked = 3,
    MemberBanned = 4,
    AddressUnbanned = 5,
};

// ---------------------------------------------------------------------------
// Limits: hard ceilings. A caller may tighten them, never widen them.
// ---------------------------------------------------------------------------
struct Limits {
    std::size_t packet_bytes = 65536;                 // whole frame
    std::size_t string_bytes = 4096;                  // DecodeString / EncodeString
    std::size_t members = max_concurrent_connections; // room.h:28
    std::size_t data_bytes = 60000;                   // ProxyPacket/LdnPacket blob
    std::size_t chat_bytes = max_message_size;        // room.h:25, room.cpp:944-945
};

// ---------------------------------------------------------------------------
// Wire structs (field order is the sender order from the reference sources)
// ---------------------------------------------------------------------------
// common/socket_types.h:41-45  "struct SockAddrIn { Domain family; IPv4Address
// ip; u16 portno; };"
struct SockAddrIn {
    std::uint8_t family = domain_inet;
    IPv4Address ip{};
    std::uint16_t port = 0;
    bool operator==(const SockAddrIn&) const = default;
};

// room_member.cpp:284-296 (sender) and room.cpp:304-318 (reader):
//   u8 id, string nickname, ipv4 preferred_fake_ip, u32 version, string
//   password, string token.
struct JoinRequest {
    std::string nickname;
    IPv4Address preferred_fake_ip = no_preferred_ip;
    std::uint32_t version = network_version;
    std::string password;
    std::string token;
    bool operator==(const JoinRequest&) const = default;
};

// room.cpp:641-659 / room_member.cpp:343-352: u8 id, ipv4 fake_ip.
// moderator distinguishes IdJoinSuccess(2) from IdJoinSuccessAsMod(24).
struct JoinSuccess {
    IPv4Address assigned_fake_ip{};
    bool moderator = false;
    bool operator==(const JoinSuccess&) const = default;
};

// room.cpp:772-801 (BroadcastRoomInformation) and room_member.cpp:298-341
// (reader). A member carries six strings, one IPv4 address and one u64.
struct Member {
    std::string nickname;
    IPv4Address fake_ip{};
    std::string game_name;
    std::uint64_t game_id = 0;
    std::string game_version;
    std::string username;
    std::string display_name;
    std::string avatar_url;
    bool operator==(const Member&) const = default;
};

struct RoomInformation {
    std::string name;
    std::string description;
    std::uint32_t member_slots = 0;
    std::uint16_t port = 0;
    std::string preferred_game_name; // GameInfo::name, room.cpp:783
    std::string host_username;
    std::vector<Member> members;
    bool operator==(const RoomInformation&) const = default;
};

// room_member.cpp:668-679 (sender) and room.cpp:977-985 (reader):
//   u8 id, string name, u64 id, string version.
struct GameInfo {
    std::string name;
    std::uint64_t id = 0;
    std::string version;
    bool operator==(const GameInfo&) const = default;
};

// room_member.cpp:627-644 (sender) and :354-383 (reader):
//   u8 id, u8 local family, ipv4 local ip, u16 local port, u8 remote family,
//   ipv4 remote ip, u16 remote port, u8 protocol, bool broadcast, blob data.
// The room relays this frame byte-for-byte (room.cpp:815-871).
struct ProxyPacket {
    SockAddrIn local_endpoint;
    SockAddrIn remote_endpoint;
    std::uint8_t protocol = protocol_udp;
    bool broadcast = false;
    Bytes data;
    bool operator==(const ProxyPacket&) const = default;
};

// room_member.cpp:646-659 (sender) and :385-404 (reader):
//   u8 id, u8 type, ipv4 local_ip, ipv4 remote_ip, bool broadcast, blob data.
struct LdnPacket {
    LdnPacketType type = LdnPacketType::Scan;
    IPv4Address local_ip{};
    IPv4Address remote_ip{};
    bool broadcast = false;
    Bytes data;
    bool operator==(const LdnPacket&) const = default;
};

// room_member.cpp:661-666: u8 id, string message (client -> server).
struct ChatRequest {
    std::string message;
    bool operator==(const ChatRequest&) const = default;
};

// room.cpp:927-975: u8 id, nickname, username, message (server -> client).
struct ChatMessage {
    std::string nickname;
    std::string username;
    std::string message;
    bool operator==(const ChatMessage&) const = default;
};

// room.cpp:733-748: u8 id, u8 type, nickname, username (server -> client).
struct StatusMessage {
    StatusType type = StatusType::MemberJoin;
    std::string nickname;
    std::string username;
    bool operator==(const StatusMessage&) const = default;
};

// The eight server-error frames defined by the reference source. The id must be
// one of them; only VersionMismatch carries a payload (room.cpp:630-639).
struct ServerError {
    MessageId id = MessageId::CloseRoom;
    std::uint32_t server_version = 0;
    bool operator==(const ServerError&) const = default;
};

using Message = std::variant<JoinRequest, JoinSuccess, RoomInformation, GameInfo, ProxyPacket,
                             LdnPacket, ChatRequest, ChatMessage, StatusMessage, ServerError>;

// ---------------------------------------------------------------------------
// Message classification
// ---------------------------------------------------------------------------
MessageId message_id(const Message& message);
bool is_server_error(MessageId id);
bool is_known_message_id(std::uint8_t raw);
bool is_unsupported_message_id(MessageId id);
std::string message_name(MessageId id);
std::string ldn_type_name(LdnPacketType type);
std::string status_type_name(StatusType type);
std::string domain_name(std::uint8_t family);
std::string protocol_name(std::uint8_t protocol);

// ---------------------------------------------------------------------------
// Primitives (network/packet.cpp: big-endian, u32-length-prefixed strings)
// ---------------------------------------------------------------------------
class PrimitiveWriter {
public:
    explicit PrimitiveWriter(const Limits& limits = {});

    void u8(std::uint8_t value);
    void u16(std::uint16_t value);
    void u32(std::uint32_t value);
    void u64(std::uint64_t value);
    void boolean(bool value);
    void enumeration(std::uint8_t value, std::uint8_t lo, std::uint8_t hi);
    void ipv4(const IPv4Address& value);
    void string(const std::string& value, std::size_t maximum);
    void string(const std::string& value);
    void data(const Bytes& value, std::size_t maximum);
    void data(const Bytes& value);

    std::size_t size() const noexcept { return bytes_.size(); }
    Bytes finish() { return std::move(bytes_); }

private:
    void need(std::size_t count) const;
    const Limits& limits_;
    Bytes bytes_;
};

class PrimitiveReader {
public:
    explicit PrimitiveReader(const Bytes& bytes, const Limits& limits = {});

    std::uint8_t u8();
    std::uint16_t u16();
    std::uint32_t u32();
    std::uint64_t u64();
    bool boolean();
    std::uint8_t enumeration(std::uint8_t lo, std::uint8_t hi);
    IPv4Address ipv4();
    std::string string(std::size_t maximum);
    std::string string();
    Bytes data(std::size_t maximum);
    Bytes data();

    std::size_t offset() const noexcept { return pos_; }
    std::size_t remaining() const noexcept { return bytes_.size() - pos_; }
    void require_end();

private:
    std::uint64_t integer(unsigned count);
    std::size_t length(std::size_t maximum);
    void need(std::size_t count) const;

    const Bytes& bytes_;
    const Limits& limits_;
    std::size_t pos_ = 0;
};

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------
Bytes encode(const Message& message, Direction direction, const Limits& limits = {});
Message decode(const Bytes& bytes, Direction direction, const Limits& limits = {});
Bytes parse_hex(std::string_view text, const Limits& limits = {});
std::string to_hex(const Bytes& bytes);

} // namespace yuzu_room
