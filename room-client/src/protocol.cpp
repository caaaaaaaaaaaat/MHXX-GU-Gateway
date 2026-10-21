// SPDX-License-Identifier: GPL-2.0-or-later
// Independent bounded implementation of the audited Yuzu room wire format.
#include "room_client/protocol.hpp"
#include <algorithm>
#include <type_traits>
#include <utility>

namespace room_client {
ProtocolError::ProtocolError(ErrorCode code, std::size_t offset, const std::string& detail)
    : std::runtime_error(detail + " at byte " + std::to_string(offset)), code_(code), offset_(offset) {}
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
bool is_server_error(MessageId id) {
    switch (id) {
    case MessageId::NameCollision: case MessageId::IpCollision:
    case MessageId::VersionMismatch: case MessageId::WrongPassword:
    case MessageId::CloseRoom: case MessageId::RoomFull:
    case MessageId::HostKicked: case MessageId::HostBanned:
    case MessageId::PermissionDenied: case MessageId::NoSuchUser: return true;
    default: return false;
    }
}
void check_direction(MessageId id, Direction direction) {
    validate_direction(direction);
    if ((id == MessageId::JoinRequest || id == MessageId::SetGameInfo) &&
        direction != Direction::ClientToServer)
        fail(ErrorCode::WrongDirection, 0, "client-only message");
    if ((id == MessageId::JoinSuccess || id == MessageId::JoinSuccessAsModerator ||
         id == MessageId::RoomInformation || id == MessageId::Status || is_server_error(id)) &&
        direction != Direction::ServerToClient)
        fail(ErrorCode::WrongDirection, 0, "server-only message");
}
void check_enum(std::uint8_t n, std::uint8_t lo, std::uint8_t hi, std::size_t offset) {
    if (n < lo || n > hi) fail(ErrorCode::InvalidEnum, offset, "invalid enum value");
}
class Reader {
public:
    Reader(const Bytes& bytes, const Limits& limits) : b(bytes), l(limits) {
        if (b.size() > l.packet_bytes) fail(ErrorCode::LimitExceeded, 0, "packet size limit");
    }
    std::size_t offset() const { return pos; }
    std::size_t remaining() const { return b.size() - pos; }
    void need(std::size_t n) const {
        if (n > remaining()) fail(ErrorCode::Truncated, pos, "truncated packet");
    }
    std::uint8_t u8() { need(1); return b[pos++]; }
    std::uint64_t integer(unsigned n) {
        need(n);
        std::uint64_t value = 0;
        for (unsigned i = 0; i < n; ++i) value = (value << 8) | b[pos++];
        return value;
    }
    std::uint16_t u16() { return static_cast<std::uint16_t>(integer(2)); }
    std::uint32_t u32() { return static_cast<std::uint32_t>(integer(4)); }
    std::uint64_t u64() { return integer(8); }
    bool boolean() {
        auto value = u8();
        if (value > 1) fail(ErrorCode::InvalidBoolean, pos - 1, "bool must be 0 or 1");
        return value == 1;
    }
    std::uint8_t enumeration(std::uint8_t lo, std::uint8_t hi) {
        auto value = u8(); check_enum(value, lo, hi, pos - 1); return value;
    }
    IPv4 ip() {
        need(4); IPv4 value{};
        for (auto& octet : value) octet = b[pos++];
        return value;
    }
    std::size_t length(std::size_t maximum) {
        auto n = u32();
        if (n > maximum) fail(ErrorCode::LimitExceeded, pos - 4, "declared length limit");
        need(n); return n; // Check remaining bytes BEFORE any allocation.
    }
    std::string string(std::size_t maximum) {
        auto n = length(std::min(maximum, l.string_bytes));
        if (!n) return {};
        std::string value(reinterpret_cast<const char*>(b.data() + pos), n);
        pos += n; return value;
    }
    std::string string() { return string(l.string_bytes); }
    Bytes data() {
        auto n = length(l.data_bytes);
        Bytes value(b.begin() + static_cast<Bytes::difference_type>(pos),
                    b.begin() + static_cast<Bytes::difference_type>(pos + n));
        pos += n; return value;
    }
    void end() const {
        if (remaining()) fail(ErrorCode::TrailingBytes, pos, "trailing bytes");
    }
private:
    const Bytes& b; const Limits& l; std::size_t pos = 0;
};
class Writer {
public:
    explicit Writer(const Limits& limits) : l(limits) {}
    void need(std::size_t n) const {
        if (n > l.packet_bytes - b.size()) fail(ErrorCode::LimitExceeded, b.size(), "packet size limit");
    }
    void u8(std::uint8_t n) { need(1); b.push_back(n); }
    void integer(std::uint64_t value, unsigned n) {
        need(n);
        for (unsigned i = n; i > 0; --i) b.push_back(static_cast<std::uint8_t>(value >> ((i - 1) * 8)));
    }
    void u16(std::uint16_t n) { integer(n, 2); }
    void u32(std::uint32_t n) { integer(n, 4); }
    void u64(std::uint64_t n) { integer(n, 8); }
    void boolean(bool n) { u8(n ? 1 : 0); }
    void enumeration(std::uint8_t n, std::uint8_t lo, std::uint8_t hi) {
        check_enum(n, lo, hi, b.size()); u8(n);
    }
    void ip(const IPv4& value) { need(4); b.insert(b.end(), value.begin(), value.end()); }
    void string(const std::string& s, std::size_t maximum) {
        if (s.size() > std::min(maximum, l.string_bytes)) fail(ErrorCode::LimitExceeded, b.size(), "string size limit");
        need(4 + s.size()); u32(static_cast<std::uint32_t>(s.size()));
        b.insert(b.end(), s.begin(), s.end());
    }
    void string(const std::string& s) { string(s, l.string_bytes); }
    void data(const Bytes& value) {
        if (value.size() > l.data_bytes) fail(ErrorCode::LimitExceeded, b.size(), "data size limit");
        need(4 + value.size()); u32(static_cast<std::uint32_t>(value.size()));
        b.insert(b.end(), value.begin(), value.end());
    }
    Bytes finish() { return std::move(b); }
private:
    const Limits& l; Bytes b;
};
GameInfo read_game(Reader& r) { return {r.string(), r.u64(), r.string()}; }
void write_game(Writer& w, const GameInfo& g) { w.string(g.name); w.u64(g.id); w.string(g.version); }
Endpoint read_endpoint(Reader& r) {
    return {static_cast<Domain>(r.enumeration(0, 1)), r.ip(), r.u16()};
}
void write_endpoint(Writer& w, const Endpoint& e) {
    w.enumeration(static_cast<std::uint8_t>(e.family), 0, 1); w.ip(e.ip); w.u16(e.port);
}
void check_members(std::uint32_t slots, std::size_t count, const Limits& l, std::size_t pos) {
    if (!slots || slots > l.members || count > l.members || count > slots)
        fail(ErrorCode::LimitExceeded, pos, "member count/slots limit");
}
} // namespace

MessageId message_id(const Message& message) {
    return std::visit([](const auto& m) -> MessageId {
        using T = std::decay_t<decltype(m)>;
        if constexpr (std::is_same_v<T, JoinRequest>) return MessageId::JoinRequest;
        else if constexpr (std::is_same_v<T, JoinSuccess>) return m.moderator ? MessageId::JoinSuccessAsModerator : MessageId::JoinSuccess;
        else if constexpr (std::is_same_v<T, RoomInformation>) return MessageId::RoomInformation;
        else if constexpr (std::is_same_v<T, GameInfo>) return MessageId::SetGameInfo;
        else if constexpr (std::is_same_v<T, ProxyPacket>) return MessageId::Proxy;
        else if constexpr (std::is_same_v<T, LdnPacket>) return MessageId::Ldn;
        else if constexpr (std::is_same_v<T, ChatRequest> || std::is_same_v<T, ChatMessage>) return MessageId::Chat;
        else if constexpr (std::is_same_v<T, StatusMessage>) return MessageId::Status;
        else return m.id;
    }, message);
}
Bytes encode(const Message& message, Direction direction, const Limits& limits) {
    validate_limits(limits);
    const auto id = message_id(message); check_direction(id, direction);
    Writer w(limits); w.u8(static_cast<std::uint8_t>(id));
    std::visit([&](const auto& m) {
        using T = std::decay_t<decltype(m)>;
        if constexpr (std::is_same_v<T, JoinRequest>) {
            w.string(m.nickname); w.ip(m.preferred_ip); w.u32(m.version); w.string(m.password); w.string(m.token);
        } else if constexpr (std::is_same_v<T, JoinSuccess>) w.ip(m.assigned_ip);
        else if constexpr (std::is_same_v<T, RoomInformation>) {
            check_members(m.member_slots, m.members.size(), limits, 0);
            w.string(m.name); w.string(m.description); w.u32(m.member_slots); w.u16(m.port);
            w.string(m.preferred_game_name); w.string(m.host_username); w.u32(static_cast<std::uint32_t>(m.members.size()));
            for (const auto& member : m.members) {
                w.string(member.nickname); w.ip(member.fake_ip); write_game(w, member.game);
                w.string(member.username); w.string(member.display_name); w.string(member.avatar_url);
            }
        } else if constexpr (std::is_same_v<T, GameInfo>) write_game(w, m);
        else if constexpr (std::is_same_v<T, ProxyPacket>) {
            write_endpoint(w, m.local); write_endpoint(w, m.remote);
            w.enumeration(static_cast<std::uint8_t>(m.protocol), 0, 3); w.boolean(m.broadcast); w.data(m.data);
        } else if constexpr (std::is_same_v<T, LdnPacket>) {
            w.enumeration(static_cast<std::uint8_t>(m.type), 0, 5); w.ip(m.local_ip); w.ip(m.remote_ip);
            w.boolean(m.broadcast); w.data(m.data);
        } else if constexpr (std::is_same_v<T, ChatRequest>) {
            if (direction != Direction::ClientToServer) fail(ErrorCode::WrongDirection, 0, "chat request direction");
            w.string(m.message, limits.chat_bytes);
        } else if constexpr (std::is_same_v<T, ChatMessage>) {
            if (direction != Direction::ServerToClient) fail(ErrorCode::WrongDirection, 0, "chat response direction");
            w.string(m.nickname); w.string(m.username); w.string(m.message, limits.chat_bytes);
        } else if constexpr (std::is_same_v<T, StatusMessage>) {
            w.enumeration(static_cast<std::uint8_t>(m.type), 1, 5); w.string(m.nickname); w.string(m.username);
        } else {
            if (!is_server_error(m.id)) fail(ErrorCode::InvalidEnum, 0, "invalid server error id");
            if (m.id == MessageId::VersionMismatch) w.u32(m.server_version);
            else if (m.server_version != 0) fail(ErrorCode::InvalidArgument, 0, "version only belongs to VersionMismatch");
        }
    }, message);
    return w.finish();
}
Message decode(const Bytes& bytes, Direction direction, const Limits& limits) {
    validate_limits(limits); validate_direction(direction); Reader r(bytes, limits);
    auto raw = r.u8();
    if (raw == 0 || raw > 24) fail(ErrorCode::UnknownMessage, 0, "unknown message id");
    if (raw >= 17 && raw <= 21) fail(ErrorCode::UnsupportedMessage, 0, "moderation request/ban list codec outside M1");
    auto id = static_cast<MessageId>(raw); check_direction(id, direction);
    Message result;
    switch (id) {
    case MessageId::JoinRequest: {
        JoinRequest m; m.nickname = r.string(); m.preferred_ip = r.ip(); m.version = r.u32();
        m.password = r.string(); m.token = r.string(); result = std::move(m); break;
    }
    case MessageId::JoinSuccess: case MessageId::JoinSuccessAsModerator:
        result = JoinSuccess{r.ip(), id == MessageId::JoinSuccessAsModerator}; break;
    case MessageId::RoomInformation: {
        RoomInformation m; m.name = r.string(); m.description = r.string();
        m.member_slots = r.u32(); m.port = r.u16(); m.preferred_game_name = r.string(); m.host_username = r.string();
        auto count = r.u32(); check_members(m.member_slots, count, limits, r.offset() - 4);
        // Each member needs at least six string prefixes, raw IPv4, and u64 = 36 bytes.
        if (count > r.remaining() / 36) fail(ErrorCode::Truncated, r.offset(), "truncated members");
        m.members.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            Member member; member.nickname = r.string(); member.fake_ip = r.ip(); member.game = read_game(r);
            member.username = r.string(); member.display_name = r.string(); member.avatar_url = r.string();
            m.members.push_back(std::move(member));
        }
        result = std::move(m); break;
    }
    case MessageId::SetGameInfo: result = read_game(r); break;
    case MessageId::Proxy: {
        ProxyPacket m; m.local = read_endpoint(r); m.remote = read_endpoint(r);
        m.protocol = static_cast<SocketProtocol>(r.enumeration(0, 3)); m.broadcast = r.boolean(); m.data = r.data();
        result = std::move(m); break;
    }
    case MessageId::Ldn: {
        LdnPacket m; m.type = static_cast<LdnType>(r.enumeration(0, 5)); m.local_ip = r.ip(); m.remote_ip = r.ip();
        m.broadcast = r.boolean(); m.data = r.data(); result = std::move(m); break;
    }
    case MessageId::Chat:
        if (direction == Direction::ClientToServer) result = ChatRequest{r.string(limits.chat_bytes)};
        else result = ChatMessage{r.string(), r.string(), r.string(limits.chat_bytes)};
        break;
    case MessageId::Status:
        result = StatusMessage{static_cast<StatusType>(r.enumeration(1, 5)), r.string(), r.string()}; break;
    default:
        if (!is_server_error(id)) fail(ErrorCode::UnknownMessage, 0, "unknown message id");
        result = ServerError{id, id == MessageId::VersionMismatch ? r.u32() : 0}; break;
    }
    r.end(); return result;
}
Bytes parse_hex(std::string_view text, const Limits& limits) {
    validate_limits(limits);
    if (text.size() > limits.packet_bytes * 3) fail(ErrorCode::LimitExceeded, 0, "hex text size limit");
    Bytes bytes; int high = -1;
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
            bytes.push_back(static_cast<std::uint8_t>((high << 4) | n)); high = -1;
        }
    }
    if (high >= 0) fail(ErrorCode::InvalidArgument, text.size(), "odd hex digit count");
    return bytes;
}
std::string to_hex(const Bytes& bytes) {
    if (bytes.size() > Limits{}.packet_bytes) fail(ErrorCode::LimitExceeded, 0, "hex packet size limit");
    constexpr char hex[] = "0123456789abcdef"; std::string text; text.reserve(bytes.size() * 2);
    for (auto b : bytes) { text += hex[b >> 4]; text += hex[b & 15]; }
    return text;
}
std::string message_name(MessageId id) {
    switch (id) {
    case MessageId::JoinRequest: return "JoinRequest";
    case MessageId::JoinSuccess: return "JoinSuccess";
    case MessageId::JoinSuccessAsModerator: return "JoinSuccessAsModerator";
    case MessageId::RoomInformation: return "RoomInformation";
    case MessageId::SetGameInfo: return "SetGameInfo";
    case MessageId::Proxy: return "Proxy";
    case MessageId::Ldn: return "LDN";
    case MessageId::Chat: return "Chat";
    case MessageId::Status: return "Status";
    case MessageId::NameCollision: return "NameCollision";
    case MessageId::IpCollision: return "IpCollision";
    case MessageId::VersionMismatch: return "VersionMismatch";
    case MessageId::WrongPassword: return "WrongPassword";
    case MessageId::CloseRoom: return "CloseRoom";
    case MessageId::RoomFull: return "RoomFull";
    case MessageId::HostKicked: return "HostKicked";
    case MessageId::HostBanned: return "HostBanned";
    case MessageId::PermissionDenied: return "PermissionDenied";
    case MessageId::NoSuchUser: return "NoSuchUser";
    }
    return "Unknown";
}
} // namespace room_client
