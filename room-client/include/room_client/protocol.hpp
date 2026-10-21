// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace room_client {
using Bytes = std::vector<std::uint8_t>;
using IPv4 = std::array<std::uint8_t, 4>; // Raw wire octets, never an integer.
constexpr std::uint32_t network_version = 1;
constexpr std::uint8_t enet_channel = 0; // M1 has no ENet transport implementation.
constexpr IPv4 no_preferred_ip{255, 255, 255, 255};

struct Limits {
    std::size_t packet_bytes = 65536;
    std::size_t string_bytes = 4096;
    std::size_t members = 254;
    std::size_t data_bytes = 60000;
    std::size_t chat_bytes = 500;
};

enum class ErrorCode { Truncated, LimitExceeded, InvalidBoolean, InvalidEnum,
                       UnknownMessage, UnsupportedMessage, TrailingBytes,
                       WrongDirection, InvalidState, InvalidArgument, Timeout };
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
enum class MessageId : std::uint8_t {
    JoinRequest = 1, JoinSuccess = 2, RoomInformation = 3, SetGameInfo = 4,
    Proxy = 5, Ldn = 6, Chat = 7, NameCollision = 8, IpCollision = 9,
    VersionMismatch = 10, WrongPassword = 11, CloseRoom = 12, RoomFull = 13,
    Status = 14, HostKicked = 15, HostBanned = 16, PermissionDenied = 22,
    NoSuchUser = 23, JoinSuccessAsModerator = 24
};
enum class LdnType : std::uint8_t { Scan = 0, ScanResponse = 1, Connect = 2,
                                  SyncNetwork = 3, Disconnect = 4, DestroyNetwork = 5 };
enum class Domain : std::uint8_t { Unspecified = 0, Inet = 1 };
enum class SocketProtocol : std::uint8_t { Unspecified = 0, Icmp = 1, Tcp = 2, Udp = 3 };
enum class StatusType : std::uint8_t { MemberJoin = 1, MemberLeave = 2, MemberKicked = 3,
                                     MemberBanned = 4, AddressUnbanned = 5 };
struct JoinRequest {
    std::string nickname;
    IPv4 preferred_ip = no_preferred_ip;
    std::uint32_t version = network_version;
    std::string password;
    std::string token;
 bool operator==(const JoinRequest&) const = default; };
struct JoinSuccess { IPv4 assigned_ip{}; bool moderator = false; bool operator==(const JoinSuccess&) const = default; };
struct GameInfo { std::string name; std::uint64_t id = 0; std::string version;  bool operator==(const GameInfo&) const = default; };
struct Member {
    std::string nickname;
    IPv4 fake_ip{};
    GameInfo game;
    std::string username, display_name, avatar_url;
    bool operator==(const Member&) const = default;
};
struct RoomInformation {
    std::string name, description;
    std::uint32_t member_slots = 0;
    std::uint16_t port = 0;
    std::string preferred_game_name, host_username;
    std::vector<Member> members;
 bool operator==(const RoomInformation&) const = default; };
struct Endpoint { Domain family = Domain::Inet; IPv4 ip{}; std::uint16_t port = 0; bool operator==(const Endpoint&) const = default; };
struct ProxyPacket {
    Endpoint local, remote;
    SocketProtocol protocol = SocketProtocol::Udp;
    bool broadcast = false;
    Bytes data; // Opaque source bytes: source socket_proxy uses ZSTD, NOT raw UDP.
 bool operator==(const ProxyPacket&) const = default; };
struct LdnPacket {
    LdnType type = LdnType::Scan;
    IPv4 local_ip{}, remote_ip{};
    bool broadcast = false;
    Bytes data; // Opaque LDN control bytes; NOT a UDS conversion.
    bool operator==(const LdnPacket&) const = default;
};
struct ChatRequest { std::string message;  bool operator==(const ChatRequest&) const = default; };
struct ChatMessage { std::string nickname, username, message;  bool operator==(const ChatMessage&) const = default; };
struct StatusMessage { StatusType type = StatusType::MemberJoin; std::string nickname, username;  bool operator==(const StatusMessage&) const = default; };
struct ServerError { MessageId id = MessageId::WrongPassword; std::uint32_t server_version = 0;  bool operator==(const ServerError&) const = default; };
using Message = std::variant<JoinRequest, JoinSuccess, RoomInformation, GameInfo,
                             ProxyPacket, LdnPacket, ChatRequest, ChatMessage,
                             StatusMessage, ServerError>;
MessageId message_id(const Message& message);
Bytes encode(const Message& message, Direction direction, const Limits& limits = {});
Message decode(const Bytes& bytes, Direction direction, const Limits& limits = {});
Bytes parse_hex(std::string_view text, const Limits& limits = {});
std::string to_hex(const Bytes& bytes);
std::string message_name(MessageId id);
} // namespace room_client
