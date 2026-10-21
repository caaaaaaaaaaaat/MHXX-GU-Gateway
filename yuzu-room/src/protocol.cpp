// SPDX-License-Identifier: GPL-2.0-or-later
// Bounded, fail-closed implementation of the Yuzu / Nintendo-LDN room wire
// format (network_version 1). Derived from the read-only yuzu reference tree
// (network/room.{h,cpp}, network/room_member.{h,cpp}, network/packet.{h,cpp}).
//
// OFFLINE ONLY: no sockets, no ENet, no emulator, no game data.
#include "yuzu_room/protocol.hpp"

#include <algorithm>
#include <type_traits>
#include <utility>

namespace yuzu_room {

ProtocolError::ProtocolError(ErrorCode code, std::size_t offset, const std::string& detail)
    : std::runtime_error(detail + " at byte " + std::to_string(offset)), code_(code), offset_(offset) {}

std::string error_code_name(ErrorCode code) {
    switch (code) {
    case ErrorCode::Truncated: return "Truncated";
    case ErrorCode::LimitExceeded: return "LimitExceeded";
    case ErrorCode::InvalidBoolean: return "InvalidBoolean";
    case ErrorCode::InvalidEnum: return "InvalidEnum";
    case ErrorCode::UnknownMessage: return "UnknownMessage";
    case ErrorCode::UnsupportedMessage: return "UnsupportedMessage";
    case ErrorCode::TrailingBytes: return "TrailingBytes";
    case ErrorCode::WrongDirection: return "WrongDirection";
    case ErrorCode::InvalidState: return "InvalidState";
    case ErrorCode::InvalidArgument: return "InvalidArgument";
    case ErrorCode::Timeout: return "Timeout";
    }
    return "Unknown";
}

std::string direction_name(Direction direction) {
    switch (direction) {
    case Direction::ClientToServer: return "c2s";
    case Direction::ServerToClient: return "s2c";
    }
    return "unknown";
}

namespace {

[[noreturn]] void fail(ErrorCode code, std::size_t offset, const std::string& detail) {
    throw ProtocolError(code, offset, detail);
}

void validate_limits(const Limits& l) {
    const Limits hard{};
    if (!l.packet_bytes || l.packet_bytes > hard.packet_bytes || !l.string_bytes ||
        l.string_bytes > hard.string_bytes || !l.members || l.members > hard.members ||
        !l.data_bytes || l.data_bytes > hard.data_bytes || !l.chat_bytes ||
        l.chat_bytes > hard.chat_bytes)
        fail(ErrorCode::InvalidArgument, 0, "limits must be positive and no larger than hard ceilings");
}

void validate_direction(Direction d) {
    if (d != Direction::ClientToServer && d != Direction::ServerToClient)
        fail(ErrorCode::InvalidEnum, 0, "invalid codec direction");
}

void check_enum(std::uint8_t n, std::uint8_t lo, std::uint8_t hi, std::size_t offset) {
    if (n < lo || n > hi) fail(ErrorCode::InvalidEnum, offset, "invalid enum value");
}

// room.cpp:240-289 (server dispatch) and room_member.cpp:164-273 (client
// dispatch) constrain who may send which message. IdProxyPacket and IdLdnPacket
// are symmetric: the room relays them verbatim, so a client both sends and
// receives them (room.cpp:815-925).
void check_direction(MessageId id, Direction direction) {
    validate_direction(direction);
    if ((id == MessageId::JoinRequest || id == MessageId::SetGameInfo) &&
        direction != Direction::ClientToServer)
        fail(ErrorCode::WrongDirection, 0, "client-only message");
    if ((id == MessageId::JoinSuccess || id == MessageId::JoinSuccessAsMod ||
         id == MessageId::RoomInformation || id == MessageId::StatusMessage ||
         is_server_error(id)) &&
        direction != Direction::ServerToClient)
        fail(ErrorCode::WrongDirection, 0, "server-only message");
}

// room.cpp:772-801: member_slots is a u32 count of slots, members.size() the
// current membership; the room never sends more members than slots.
void check_members(std::uint32_t slots, std::size_t count, const Limits& l, std::size_t offset) {
    if (slots == 0 || slots > l.members || count > l.members || count > slots)
        fail(ErrorCode::LimitExceeded, offset, "member count/slots limit");
}

} // namespace

// room.cpp:590-699: the eight single-frame error replies. IdRoomIsFull is 13 in
// the v1 source (Yuzu has no IdConsoleIdCollision, which Citra numbers 13).
bool is_server_error(MessageId id) {
    switch (id) {
    case MessageId::NameCollision: case MessageId::IpCollision:
    case MessageId::VersionMismatch: case MessageId::WrongPassword:
    case MessageId::CloseRoom: case MessageId::RoomIsFull:
    case MessageId::HostKicked: case MessageId::HostBanned: return true;
    default: return false;
    }
}

bool is_known_message_id(std::uint8_t raw) { return raw >= 1 && raw <= 24; }

// room.h:54-60: defined ids that this bounded codec deliberately refuses to
// parse (moderation and ban-list requests need moderator privileges and are
// outside the audited client scope).
bool is_unsupported_message_id(MessageId id) {
    return id == MessageId::ModKick || id == MessageId::ModBan || id == MessageId::ModUnban ||
           id == MessageId::ModGetBanList || id == MessageId::ModBanListResponse ||
           id == MessageId::ModPermissionDenied || id == MessageId::ModNoSuchUser;
}

std::string message_name(MessageId id) {
    switch (id) {
    case MessageId::JoinRequest: return "JoinRequest";
    case MessageId::JoinSuccess: return "JoinSuccess";
    case MessageId::RoomInformation: return "RoomInformation";
    case MessageId::SetGameInfo: return "SetGameInfo";
    case MessageId::ProxyPacket: return "ProxyPacket";
    case MessageId::LdnPacket: return "LdnPacket";
    case MessageId::ChatMessage: return "ChatMessage";
    case MessageId::NameCollision: return "NameCollision";
    case MessageId::IpCollision: return "IpCollision";
    case MessageId::VersionMismatch: return "VersionMismatch";
    case MessageId::WrongPassword: return "WrongPassword";
    case MessageId::CloseRoom: return "CloseRoom";
    case MessageId::RoomIsFull: return "RoomIsFull";
    case MessageId::StatusMessage: return "StatusMessage";
    case MessageId::HostKicked: return "HostKicked";
    case MessageId::HostBanned: return "HostBanned";
    case MessageId::ModKick: return "ModKick";
    case MessageId::ModBan: return "ModBan";
    case MessageId::ModUnban: return "ModUnban";
    case MessageId::ModGetBanList: return "ModGetBanList";
    case MessageId::ModBanListResponse: return "ModBanListResponse";
    case MessageId::ModPermissionDenied: return "ModPermissionDenied";
    case MessageId::ModNoSuchUser: return "ModNoSuchUser";
    case MessageId::JoinSuccessAsMod: return "JoinSuccessAsMod";
    }
    return "Unknown";
}

std::string ldn_type_name(LdnPacketType type) {
    switch (type) {
    case LdnPacketType::Scan: return "Scan";
    case LdnPacketType::ScanResp: return "ScanResp";
    case LdnPacketType::Connect: return "Connect";
    case LdnPacketType::SyncNetwork: return "SyncNetwork";
    case LdnPacketType::Disconnect: return "Disconnect";
    case LdnPacketType::DestroyNetwork: return "DestroyNetwork";
    }
    return "Unknown";
}

std::string status_type_name(StatusType type) {
    switch (type) {
    case StatusType::MemberJoin: return "MemberJoin";
    case StatusType::MemberLeave: return "MemberLeave";
    case StatusType::MemberKicked: return "MemberKicked";
    case StatusType::MemberBanned: return "MemberBanned";
    case StatusType::AddressUnbanned: return "AddressUnbanned";
    }
    return "Unknown";
}

// source-only names (common/socket_types.h:11-28); see the disagreement note in
// protocol.hpp: captured frames carry 0x01 / 0x03, which this codec preserves.
std::string domain_name(std::uint8_t family) {
    switch (family) {
    case domain_inet: return "INET";
    default: return "Unknown";
    }
}

std::string protocol_name(std::uint8_t protocol) {
    switch (protocol) {
    case protocol_icmp: return "ICMP";
    case protocol_tcp: return "TCP";
    case protocol_udp: return "UDP";
    default: return "Unknown";
    }
}

// ---------------------------------------------------------------------------
// Packet primitives (network/packet.cpp: big-endian, u32-length-prefixed)
// ---------------------------------------------------------------------------

PrimitiveWriter::PrimitiveWriter(const Limits& limits) : limits_(limits) { validate_limits(limits_); }

void PrimitiveWriter::need(std::size_t count) const {
    if (count > limits_.packet_bytes - bytes_.size())
        fail(ErrorCode::LimitExceeded, bytes_.size(), "packet size limit");
}

void PrimitiveWriter::u8(std::uint8_t value) { need(1); bytes_.push_back(value); }

void PrimitiveWriter::u16(std::uint16_t value) {
    need(2);
    for (unsigned i = 2; i-- > 0;) bytes_.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}

void PrimitiveWriter::u32(std::uint32_t value) {
    need(4);
    for (unsigned i = 4; i-- > 0;) bytes_.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}

void PrimitiveWriter::u64(std::uint64_t value) {
    need(8);
    for (unsigned i = 8; i-- > 0;) bytes_.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}

void PrimitiveWriter::boolean(bool value) { u8(value ? 1 : 0); }

void PrimitiveWriter::enumeration(std::uint8_t value, std::uint8_t lo, std::uint8_t hi) {
    check_enum(value, lo, hi, bytes_.size());
    u8(value);
}

void PrimitiveWriter::ipv4(const IPv4Address& value) {
    need(value.size());
    bytes_.insert(bytes_.end(), value.begin(), value.end());
}

void PrimitiveWriter::string(const std::string& value, std::size_t maximum) {
    if (value.size() > std::min(maximum, limits_.string_bytes))
        fail(ErrorCode::LimitExceeded, bytes_.size(), "string size limit");
    need(4 + value.size());
    u32(static_cast<std::uint32_t>(value.size()));
    bytes_.insert(bytes_.end(), value.begin(), value.end());
}

void PrimitiveWriter::string(const std::string& value) { string(value, limits_.string_bytes); }

void PrimitiveWriter::data(const Bytes& value, std::size_t maximum) {
    if (value.size() > std::min(maximum, limits_.data_bytes))
        fail(ErrorCode::LimitExceeded, bytes_.size(), "blob size limit");
    need(4 + value.size());
    u32(static_cast<std::uint32_t>(value.size()));
    bytes_.insert(bytes_.end(), value.begin(), value.end());
}

void PrimitiveWriter::data(const Bytes& value) { data(value, limits_.data_bytes); }

PrimitiveReader::PrimitiveReader(const Bytes& bytes, const Limits& limits)
    : bytes_(bytes), limits_(limits) {
    validate_limits(limits_);
    if (bytes_.size() > limits_.packet_bytes)
        fail(ErrorCode::LimitExceeded, 0, "packet size limit");
}

void PrimitiveReader::need(std::size_t count) const {
    if (count > remaining()) fail(ErrorCode::Truncated, pos_, "truncated packet");
}

std::uint64_t PrimitiveReader::integer(unsigned count) {
    need(count);
    std::uint64_t value = 0;
    for (unsigned i = 0; i < count; ++i) value = (value << 8) | bytes_[pos_++];
    return value;
}

std::uint8_t PrimitiveReader::u8() { need(1); return bytes_[pos_++]; }
std::uint16_t PrimitiveReader::u16() { return static_cast<std::uint16_t>(integer(2)); }
std::uint32_t PrimitiveReader::u32() { return static_cast<std::uint32_t>(integer(4)); }
std::uint64_t PrimitiveReader::u64() { return integer(8); }

bool PrimitiveReader::boolean() {
    const auto value = u8();
    // Strict: the reference reader (packet.cpp:69-75) treats any nonzero byte as
    // true; this codec refuses everything above 1 instead.
    if (value > 1) fail(ErrorCode::InvalidBoolean, pos_ - 1, "bool must be 0 or 1");
    return value == 1;
}

std::uint8_t PrimitiveReader::enumeration(std::uint8_t lo, std::uint8_t hi) {
    const auto value = u8();
    check_enum(value, lo, hi, pos_ - 1);
    return value;
}

IPv4Address PrimitiveReader::ipv4() {
    need(4);
    IPv4Address value{};
    for (auto& byte : value) byte = bytes_[pos_++];
    return value;
}

std::size_t PrimitiveReader::length(std::size_t maximum) {
    const auto n = u32();
    if (n > maximum) fail(ErrorCode::LimitExceeded, pos_ - 4, "declared length limit");
    need(n); // Check remaining bytes BEFORE any allocation.
    return n;
}

std::string PrimitiveReader::string(std::size_t maximum) {
    const auto n = length(std::min(maximum, limits_.string_bytes));
    if (!n) return {};
    std::string value(reinterpret_cast<const char*>(bytes_.data() + pos_), n);
    pos_ += n;
    return value;
}

std::string PrimitiveReader::string() { return string(limits_.string_bytes); }

Bytes PrimitiveReader::data(std::size_t maximum) {
    const auto n = length(std::min(maximum, limits_.data_bytes));
    Bytes value(bytes_.begin() + static_cast<Bytes::difference_type>(pos_),
                bytes_.begin() + static_cast<Bytes::difference_type>(pos_ + n));
    pos_ += n;
    return value;
}

Bytes PrimitiveReader::data() { return data(limits_.data_bytes); }

void PrimitiveReader::require_end() {
    if (remaining()) fail(ErrorCode::TrailingBytes, pos_, "trailing bytes");
}

// ---------------------------------------------------------------------------
// Message layer
// ---------------------------------------------------------------------------

MessageId message_id(const Message& message) {
    return std::visit([](const auto& m) -> MessageId {
        using T = std::decay_t<decltype(m)>;
        if constexpr (std::is_same_v<T, JoinRequest>) return MessageId::JoinRequest;
        else if constexpr (std::is_same_v<T, JoinSuccess>) return m.moderator ? MessageId::JoinSuccessAsMod : MessageId::JoinSuccess;
        else if constexpr (std::is_same_v<T, RoomInformation>) return MessageId::RoomInformation;
        else if constexpr (std::is_same_v<T, GameInfo>) return MessageId::SetGameInfo;
        else if constexpr (std::is_same_v<T, ProxyPacket>) return MessageId::ProxyPacket;
        else if constexpr (std::is_same_v<T, LdnPacket>) return MessageId::LdnPacket;
        else if constexpr (std::is_same_v<T, ChatRequest> || std::is_same_v<T, ChatMessage>) return MessageId::ChatMessage;
        else if constexpr (std::is_same_v<T, StatusMessage>) return MessageId::StatusMessage;
        else return m.id;
    }, message);
}

Bytes encode(const Message& message, Direction direction, const Limits& limits) {
    validate_limits(limits);
    const auto id = message_id(message);
    // A ServerError alternative whose id is not one of the eight server-error
    // ids is structurally invalid; report InvalidEnum before the direction
    // test, which would otherwise misreport a client-only id as WrongDirection.
    if (std::holds_alternative<ServerError>(message) && !is_server_error(id))
        fail(ErrorCode::InvalidEnum, 0, "invalid server error id");
    check_direction(id, direction);
    PrimitiveWriter w(limits);
    w.u8(static_cast<std::uint8_t>(id));
    std::visit([&](const auto& m) {
        using T = std::decay_t<decltype(m)>;
        if constexpr (std::is_same_v<T, JoinRequest>) {
            w.string(m.nickname); w.ipv4(m.preferred_fake_ip); w.u32(m.version);
            w.string(m.password); w.string(m.token);
        } else if constexpr (std::is_same_v<T, JoinSuccess>) {
            w.ipv4(m.assigned_fake_ip);
        } else if constexpr (std::is_same_v<T, RoomInformation>) {
            check_members(m.member_slots, m.members.size(), limits, 0);
            w.string(m.name); w.string(m.description); w.u32(m.member_slots); w.u16(m.port);
            w.string(m.preferred_game_name); w.string(m.host_username);
            w.u32(static_cast<std::uint32_t>(m.members.size()));
            for (const auto& member : m.members) {
                w.string(member.nickname); w.ipv4(member.fake_ip); w.string(member.game_name);
                w.u64(member.game_id); w.string(member.game_version); w.string(member.username);
                w.string(member.display_name); w.string(member.avatar_url);
            }
        } else if constexpr (std::is_same_v<T, GameInfo>) {
            w.string(m.name); w.u64(m.id); w.string(m.version);
        } else if constexpr (std::is_same_v<T, ProxyPacket>) {
            w.u8(m.local_endpoint.family); w.ipv4(m.local_endpoint.ip); w.u16(m.local_endpoint.port);
            w.u8(m.remote_endpoint.family); w.ipv4(m.remote_endpoint.ip); w.u16(m.remote_endpoint.port);
            w.u8(m.protocol); w.boolean(m.broadcast); w.data(m.data);
        } else if constexpr (std::is_same_v<T, LdnPacket>) {
            w.enumeration(static_cast<std::uint8_t>(m.type), 0, 5);
            w.ipv4(m.local_ip); w.ipv4(m.remote_ip); w.boolean(m.broadcast); w.data(m.data);
        } else if constexpr (std::is_same_v<T, ChatRequest>) {
            if (direction != Direction::ClientToServer) fail(ErrorCode::WrongDirection, 0, "chat request direction");
            w.string(m.message, limits.chat_bytes);
        } else if constexpr (std::is_same_v<T, ChatMessage>) {
            if (direction != Direction::ServerToClient) fail(ErrorCode::WrongDirection, 0, "chat response direction");
            w.string(m.nickname); w.string(m.username); w.string(m.message, limits.chat_bytes);
        } else if constexpr (std::is_same_v<T, StatusMessage>) {
            w.enumeration(static_cast<std::uint8_t>(m.type), 1, 5);
            w.string(m.nickname); w.string(m.username);
        } else if constexpr (std::is_same_v<T, ServerError>) {
            if (!is_server_error(m.id)) fail(ErrorCode::InvalidEnum, 0, "invalid server error id");
            if (m.id == MessageId::VersionMismatch) w.u32(m.server_version);
            else if (m.server_version != 0) fail(ErrorCode::InvalidArgument, 0, "version only belongs to VersionMismatch");
        }
    }, message);
    return w.finish();
}

Message decode(const Bytes& bytes, Direction direction, const Limits& limits) {
    validate_limits(limits);
    validate_direction(direction);
    PrimitiveReader r(bytes, limits);
    const auto raw = r.u8();
    if (!is_known_message_id(raw)) fail(ErrorCode::UnknownMessage, 0, "unknown message id");
    const auto id = static_cast<MessageId>(raw);
    if (is_unsupported_message_id(id)) fail(ErrorCode::UnsupportedMessage, 0, "moderation/ban-list codec outside this project");
    check_direction(id, direction);
    Message result;
    switch (id) {
    case MessageId::JoinRequest: {
        JoinRequest m;
        m.nickname = r.string(); m.preferred_fake_ip = r.ipv4(); m.version = r.u32();
        m.password = r.string(); m.token = r.string();
        result = std::move(m); break;
    }
    case MessageId::JoinSuccess:
    case MessageId::JoinSuccessAsMod:
        result = JoinSuccess{r.ipv4(), id == MessageId::JoinSuccessAsMod}; break;
    case MessageId::RoomInformation: {
        RoomInformation m;
        m.name = r.string(); m.description = r.string(); m.member_slots = r.u32(); m.port = r.u16();
        m.preferred_game_name = r.string(); m.host_username = r.string();
        const auto count = r.u32();
        check_members(m.member_slots, count, limits, r.offset() - 4);
        // Each member costs at least six string prefixes + 4-byte IPv4 + u64 = 36 bytes.
        if (static_cast<std::size_t>(count) > r.remaining() / 36)
            fail(ErrorCode::Truncated, r.offset(), "truncated members");
        m.members.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            Member member;
            member.nickname = r.string(); member.fake_ip = r.ipv4(); member.game_name = r.string();
            member.game_id = r.u64(); member.game_version = r.string(); member.username = r.string();
            member.display_name = r.string(); member.avatar_url = r.string();
            m.members.push_back(std::move(member));
        }
        result = std::move(m); break;
    }
    case MessageId::SetGameInfo: {
        GameInfo m; m.name = r.string(); m.id = r.u64(); m.version = r.string();
        result = std::move(m); break;
    }
    case MessageId::ProxyPacket: {
        ProxyPacket m;
        m.local_endpoint.family = r.u8(); m.local_endpoint.ip = r.ipv4(); m.local_endpoint.port = r.u16();
        m.remote_endpoint.family = r.u8(); m.remote_endpoint.ip = r.ipv4(); m.remote_endpoint.port = r.u16();
        m.protocol = r.u8(); m.broadcast = r.boolean(); m.data = r.data();
        result = std::move(m); break;
    }
    case MessageId::LdnPacket: {
        LdnPacket m;
        m.type = static_cast<LdnPacketType>(r.enumeration(0, 5));
        m.local_ip = r.ipv4(); m.remote_ip = r.ipv4(); m.broadcast = r.boolean(); m.data = r.data();
        result = std::move(m); break;
    }
    case MessageId::ChatMessage:
        if (direction == Direction::ClientToServer) result = ChatRequest{r.string(limits.chat_bytes)};
        else result = ChatMessage{r.string(), r.string(), r.string(limits.chat_bytes)};
        break;
    case MessageId::StatusMessage:
        result = StatusMessage{static_cast<StatusType>(r.enumeration(1, 5)), r.string(), r.string()};
        break;
    default:
        if (!is_server_error(id)) fail(ErrorCode::UnknownMessage, 0, "unknown message id");
        result = ServerError{id, id == MessageId::VersionMismatch ? r.u32() : 0};
        break;
    }
    r.require_end();
    return result;
}

Bytes parse_hex(std::string_view text, const Limits& limits) {
    validate_limits(limits);
    if (text.size() > limits.packet_bytes * 3) fail(ErrorCode::LimitExceeded, 0, "hex text size limit");
    Bytes bytes;
    int high = -1;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int n = -1;
        if (c >= '0' && c <= '9') n = c - '0';
        else if (c >= 'a' && c <= 'f') n = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') n = c - 'A' + 10;
        if (n < 0) fail(ErrorCode::InvalidArgument, i, "invalid hex character");
        if (high < 0) high = n;
        else {
            if (bytes.size() == limits.packet_bytes) fail(ErrorCode::LimitExceeded, i, "hex packet size limit");
            bytes.push_back(static_cast<std::uint8_t>((high << 4) | n));
            high = -1;
        }
    }
    if (high >= 0) fail(ErrorCode::InvalidArgument, text.size(), "odd hex digit count");
    return bytes;
}

std::string to_hex(const Bytes& bytes) {
    if (bytes.size() > Limits{}.packet_bytes) fail(ErrorCode::LimitExceeded, 0, "hex packet size limit");
    constexpr char hex[] = "0123456789abcdef";
    std::string text;
    text.reserve(bytes.size() * 2);
    for (const auto byte : bytes) { text += hex[byte >> 4]; text += hex[byte & 15]; }
    return text;
}

} // namespace yuzu_room
