// SPDX-License-Identifier: GPL-2.0-or-later
// Offline bounded codec for the Citra room protocol (network_version 4).
//
// Wire layout and message identifiers are derived from the Citra sources
// (GPL-2.0-or-later):
//   citra-master/src/network/packet.h, packet.cpp
//   citra-master/src/network/room.h, room.cpp
//   citra-master/src/network/room_member.h, room_member.cpp
// See NOTICE.md in this directory for provenance.
//
// OFFLINE ONLY: this header performs no I/O, opens no sockets, does not link or
// speak ENet, and never touches an emulator or game.
#ifndef CITRA_ROOM_PROTOCOL_HPP
#define CITRA_ROOM_PROTOCOL_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace citra_room {

// Raw byte string, as stored by Citra Network::Packet.
using Bytes = std::vector<std::uint8_t>;
// room.h:43  using MacAddress = std::array<u8, 6>;
using MacAddress = std::array<std::uint8_t, 6>;

// room.h:16  constexpr u32 network_version = 4;
inline constexpr std::uint32_t network_version = 4;
// room.h:18  constexpr u16 DefaultRoomPort = 24872;
inline constexpr std::uint16_t default_room_port = 24872;
// room.h:20  constexpr u32 MaxMessageSize = 500;  (chat payload cap)
inline constexpr std::size_t max_message_size = 500;
// room.h:23  constexpr u32 MaxConcurrentConnections = 254;
inline constexpr std::size_t max_concurrent_connections = 254;
// room.h:25  constexpr u32 NumChannels = 1;
inline constexpr std::size_t num_channels = 1;

// room.h:46  constexpr MacAddress NoPreferredMac = {0xFF, ...};
inline constexpr MacAddress no_preferred_mac{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// room.h:49  constexpr MacAddress BroadcastMac = {0xFF, ...};
inline constexpr MacAddress broadcast_mac{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

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

// Same shape as the M1 core (crossplay/room-client/include/room_client/protocol.hpp).
class ProtocolError final : public std::runtime_error {
public:
    ProtocolError(ErrorCode code, std::size_t offset, const std::string& detail);
    ErrorCode code() const noexcept { return code_; }
    std::size_t offset() const noexcept { return offset_; }

private:
    ErrorCode code_;
    std::size_t offset_;
};

enum class Direction { ClientToServer, ServerToClient };

std::string direction_name(Direction direction);

// room.h:52-79  enum RoomMessageTypes : u8  (explicit numeric values).
enum class MessageId : std::uint8_t {
    JoinRequest = 1,
    JoinSuccess = 2,
    RoomInformation = 3,
    SetGameInfo = 4,
    WifiPacket = 5,
    ChatMessage = 6,          // client->server: chat request; server->client: chat echo
    NameCollision = 7,
    MacCollision = 8,
    VersionMismatch = 9,
    WrongPassword = 10,
    CloseRoom = 11,
    RoomIsFull = 12,
    ConsoleIdCollision = 13,
    StatusMessage = 14,
    HostKicked = 15,
    HostBanned = 16,
    ModKick = 17,             // known in source, deliberately unsupported here
    ModBan = 18,
    ModUnban = 19,
    ModGetBanList = 20,
    ModBanListResponse = 21,
    ModPermissionDenied = 22,
    ModNoSuchUser = 23,
    JoinSuccessAsMod = 24,
};

// room_member.h:19-45  WifiPacket::PacketType : u8
enum class FrameType : std::uint8_t {
    Beacon = 0,
    Data = 1,
    Authentication = 2,
    AssociationResponse = 3,
    Deauthentication = 4,
    NodeMap = 5,
};

// room.h:82-88  enum StatusMessageTypes : u8
enum class StatusType : std::uint8_t {
    MemberJoin = 1,
    MemberLeave = 2,
    MemberKicked = 3,
    MemberBanned = 4,
    AddressUnbanned = 5,
};

// Caller-tunable hard bounds. Defaults are the hard ceilings; every field is
// additionally capped by the ceiling of the same name (see validate_limits).
struct Limits {
    std::size_t packet_bytes = 65536;
    std::size_t string_bytes = 4096;
    std::size_t members = max_concurrent_connections;  // room.h:23
    std::size_t data_bytes = 60000;
    std::size_t chat_bytes = max_message_size;         // room.h:20
};

// room_member.cpp:280-294  SendJoinRequest
struct JoinRequest {
    std::string nickname;
    std::string console_id_hash;
    MacAddress preferred_mac{};
    std::uint32_t version = network_version;
    std::string password;
    std::string token;
    bool operator==(const JoinRequest&) const = default;
};

// room.cpp:675-693  SendJoinSuccess / SendJoinSuccessAsMod
struct JoinSuccess {
    MacAddress assigned_mac{};
    bool moderator = false;
    bool operator==(const JoinSuccess&) const = default;
};

// room.cpp:806-834  BroadcastRoomInformation (per-member wire order)
struct Member {
    std::string nickname;
    MacAddress mac{};
    std::string game_name;
    std::uint64_t game_id = 0;
    std::string username;
    std::string display_name;
    std::string avatar_url;
    bool operator==(const Member&) const = default;
};

// IMPORTANT (room.cpp:806-834): RoomInformation::preferred_game_id (room.h:33)
// and RoomInformation::enable_citra_mods (room.h:35) exist in the struct but are
// NOT serialized anywhere on the wire. They are intentionally absent here.
struct RoomInformation {
    std::string name;
    std::string description;
    std::uint32_t member_slots = 0;
    std::uint16_t port = 0;
    std::string preferred_game;
    std::string host_username;
    std::vector<Member> members;
    bool operator==(const RoomInformation&) const = default;
};

// room.h:38-41  GameInfo; room_member.cpp:607-617  SendGameInfo
struct GameInfo {
    std::string name;
    std::uint64_t id = 0;
    bool operator==(const GameInfo&) const = default;
};

// room_member.cpp:589-598 / room.cpp:848-894. The data blob is opaque: this
// codec never inspects UDS, 802.11 or game bytes.
struct WifiPacket {
    FrameType type = FrameType::Beacon;
    std::uint8_t channel = 0;
    MacAddress transmitter{};
    MacAddress destination{};
    Bytes data;
    bool operator==(const WifiPacket&) const = default;
};

// Client -> server chat (room_member.cpp:600-605).
struct ChatRequest {
    std::string message;
    bool operator==(const ChatRequest&) const = default;
};

// Server -> client chat echo (room.cpp:896-922).
struct ChatMessage {
    std::string nickname;
    std::string username;
    std::string message;
    bool operator==(const ChatMessage&) const = default;
};

// room.cpp:767-804  SendStatusMessage
struct StatusMessage {
    StatusType type = StatusType::MemberJoin;
    std::string nickname;
    std::string username;
    bool operator==(const StatusMessage&) const = default;
};

// The server error family (room.cpp:614-713,750-765). server_version is only
// meaningful for VersionMismatch.
struct ServerError {
    MessageId id = MessageId::CloseRoom;
    std::uint32_t server_version = 0;
    bool operator==(const ServerError&) const = default;
};

using Message = std::variant<JoinRequest, JoinSuccess, RoomInformation, GameInfo,
                             WifiPacket, ChatRequest, ChatMessage, StatusMessage,
                             ServerError>;

MessageId message_id(const Message& message);
bool is_server_error(MessageId id);
bool is_known_message_id(std::uint8_t raw);
bool is_unsupported_message_id(MessageId id);

std::string message_name(MessageId id);
std::string frame_type_name(FrameType type);
std::string status_type_name(StatusType type);

// Citra Network::Packet primitives (packet.cpp). Big-endian for u16/u32/u64;
// strings and blobs are u32-length-prefixed raw bytes with no NUL terminator.
//
// Exposed so the offline harness can test the primitives directly (no room
// message in the Citra room layer carries a boolean field).
class PrimitiveWriter {
public:
    explicit PrimitiveWriter(const Limits& limits = {});
    void u8(std::uint8_t value);
    void u16(std::uint16_t value);
    void u32(std::uint32_t value);
    void u64(std::uint64_t value);
    void boolean(bool value);
    void enumeration(std::uint8_t value, std::uint8_t lo, std::uint8_t hi);
    void mac(const MacAddress& value);
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
    MacAddress mac();
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

Bytes encode(const Message& message, Direction direction, const Limits& limits = {});
Message decode(const Bytes& bytes, Direction direction, const Limits& limits = {});
Bytes parse_hex(std::string_view text, const Limits& limits = {});
std::string to_hex(const Bytes& bytes);

} // namespace citra_room

#endif // CITRA_ROOM_PROTOCOL_HPP
