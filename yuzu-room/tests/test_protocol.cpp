// SPDX-License-Identifier: GPL-2.0-or-later
// Offline protocol tests: primitives, hex, golden frames, message ids, declared
// lengths, limits and names. Every rejection is a ProtocolError; no test may
// crash, over-allocate or accept a malformed frame.
#include "golden.hpp"
#include "yuzu_room/protocol.hpp"

#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace yuzu_room;

int g_checks = 0;
int g_prefix = 0;
int g_boundary = 0;

struct Stat {
    std::string name;
    int checks = 0;
    int prefix = 0;
    int boundary = 0;
};
std::vector<Stat> g_stats;

void check(bool condition, const std::string& what) {
    ++g_checks;
    if (!condition) throw std::runtime_error("check failed: " + what);
}

void check_code(const ProtocolError& error, const std::optional<ErrorCode>& expected, const std::string& what) {
    if (expected) check(error.code() == *expected, what + " code=" + error_code_name(error.code()));
}

template <typename Fn>
void rejects(const Fn& fn, const std::string& what, std::optional<ErrorCode> expected = std::nullopt) {
    ++g_checks;
    try {
        fn();
    } catch (const ProtocolError& error) {
        check_code(error, expected, what);
        return;
    } catch (const std::exception& error) {
        throw std::runtime_error(what + ": non-protocol exception: " + error.what());
    }
    throw std::runtime_error(what + ": did not throw");
}

void section(const std::string& name, const std::function<void()>& run) {
    Stat stat;
    stat.name = name;
    const int checks = g_checks;
    const int prefix = g_prefix;
    const int boundary = g_boundary;
    run();
    stat.checks = g_checks - checks;
    stat.prefix = g_prefix - prefix;
    stat.boundary = g_boundary - boundary;
    g_stats.push_back(stat);
}

Bytes H(const std::string& text) { return parse_hex(text); }

void set_u8(Bytes& bytes, std::size_t offset, std::uint8_t value) {
    if (offset >= bytes.size()) throw std::runtime_error("patch offset out of range");
    bytes[offset] = value;
}

void set_u16(Bytes& bytes, std::size_t offset, std::uint16_t value) {
    if (offset + 2 > bytes.size()) throw std::runtime_error("patch offset out of range");
    bytes[offset] = static_cast<std::uint8_t>(value >> 8);
    bytes[offset + 1] = static_cast<std::uint8_t>(value & 0xff);
}

void set_u32(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    if (offset + 4 > bytes.size()) throw std::runtime_error("patch offset out of range");
    for (unsigned i = 0; i < 4; ++i)
        bytes[offset + i] = static_cast<std::uint8_t>(value >> ((3 - i) * 8));
}

// ---------------------------------------------------------------------------
void test_primitives() {
    {
        PrimitiveWriter w;
        w.u8(0x12);
        w.u16(0x1234);
        w.u32(0x12345678);
        w.u64(0x0102030405060708ULL);
        check(to_hex(w.finish()) == golden::primitives_all_hex, "fixed-width integers are big-endian");
    }
    {
        PrimitiveWriter w;
        w.boolean(false);
        w.boolean(true);
        check(to_hex(w.finish()) == golden::primitives_bool_hex, "bool writes 00/01");
    }
    {
        PrimitiveWriter w;
        w.string("AB");
        check(to_hex(w.finish()) == golden::primitives_string_hex, "string is u32 length prefixed");
    }
    {
        PrimitiveWriter w;
        w.data(golden::bytes_of({0x01, 0x02}));
        check(to_hex(w.finish()) == golden::primitives_blob_hex, "blob is u32 length prefixed");
    }
    {
        PrimitiveWriter w;
        w.ipv4(golden::ip_of({192, 168, 1, 2}));
        check(to_hex(w.finish()) == "c0a80102", "ipv4 is four verbatim bytes");
    }
    {
        const auto bytes = H(golden::primitives_all_hex);
        PrimitiveReader r(bytes);
        check(r.u8() == 0x12, "u8 read");
        check(r.u16() == 0x1234, "u16 read");
        check(r.u32() == 0x12345678, "u32 read");
        check(r.u64() == 0x0102030405060708ULL, "u64 read");
        check(r.remaining() == 0, "reader consumed exactly");
        r.require_end();
    }
    {
        const auto bytes = H(golden::primitives_all_hex);
        for (std::size_t n = 0; n < 8; ++n) {
            ++g_prefix;
            rejects(
                [&] {
                    const Bytes cut(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(n));
                    PrimitiveReader r(cut);
                    (void)r.u64();
                },
                "u64 truncation at " + std::to_string(n), ErrorCode::Truncated);
        }
        for (std::size_t n = 0; n < 2; ++n) {
            ++g_prefix;
            rejects(
                [&] {
                    const Bytes cut(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(n));
                    PrimitiveReader r(cut);
                    (void)r.u16();
                },
                "u16 truncation at " + std::to_string(n), ErrorCode::Truncated);
        }
    }
    {
        const Bytes zero{0x00};
        PrimitiveReader r(zero);
        check(!r.boolean(), "bool false reads false");
    }
    {
        const Bytes one{0x01};
        PrimitiveReader r(one);
        check(r.boolean(), "bool true reads true");
    }
    {
        Bytes two{0x02};
        ++g_boundary;
        rejects([&] { PrimitiveReader r(two); (void)r.boolean(); }, "boolean is strict 0/1",
                ErrorCode::InvalidBoolean);
    }
    {
        Bytes five{0x05};
        PrimitiveReader r(five);
        check(r.enumeration(0, 5) == 5, "enumeration upper bound is inclusive");
    }
    {
        Bytes six{0x06};
        ++g_boundary;
        rejects([&] { PrimitiveReader r(six); (void)r.enumeration(0, 5); }, "enumeration out of range",
                ErrorCode::InvalidEnum);
    }
    {
        ++g_boundary;
        rejects([] { PrimitiveWriter w(Limits{.packet_bytes = 1}); w.u16(0); }, "writer packet cap",
                ErrorCode::LimitExceeded);
    }
    {
        ++g_boundary;
        rejects([] { PrimitiveWriter w; w.string(std::string(4097, 'a')); }, "writer string cap",
                ErrorCode::LimitExceeded);
    }
    {
        ++g_boundary;
        rejects([] { PrimitiveWriter w; w.data(Bytes(60001, 0)); }, "writer blob cap",
                ErrorCode::LimitExceeded);
    }
}

// ---------------------------------------------------------------------------
void test_hex() {
    check(H("").empty(), "empty hex is empty bytes");
    check(H("01 02\n03\t04") == golden::bytes_of({0x01, 0x02, 0x03, 0x04}), "hex skips whitespace");
    check(H("AB") == golden::bytes_of({0xab}), "uppercase hex accepted");
    check(to_hex(golden::bytes_of({0x00, 0xa5, 0xff})) == "00a5ff", "to_hex is lowercase");
    check(to_hex(H(golden::join_request_hex)) == golden::join_request_hex, "hex round-trip");
    ++g_boundary;
    rejects([] { (void)parse_hex("0"); }, "odd hex digits", ErrorCode::InvalidArgument);
    ++g_boundary;
    rejects([] { (void)parse_hex("zz"); }, "invalid hex character", ErrorCode::InvalidArgument);
    ++g_boundary;
    rejects([] { (void)parse_hex(std::string(Limits{}.packet_bytes * 3 + 1, '0')); }, "hex text cap",
            ErrorCode::LimitExceeded);
}

// ---------------------------------------------------------------------------
void test_fixtures() {
    for (const auto& fixture : golden::fixtures()) {
        const auto bytes = H(fixture.hex);
        check(!bytes.empty(), "fixture non-empty: " + fixture.name);
        check(bytes[0] == static_cast<std::uint8_t>(message_id(fixture.expected)),
              "fixture id byte: " + fixture.name);
        check(encode(fixture.expected, fixture.direction) == bytes, "fixture encode: " + fixture.name);
        check(decode(bytes, fixture.direction) == fixture.expected, "fixture decode: " + fixture.name);
        check(message_id(decode(bytes, fixture.direction)) == message_id(fixture.expected),
              "fixture message_id: " + fixture.name);
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            ++g_prefix;
            rejects(
                [&] {
                    const Bytes cut(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(n));
                    (void)decode(cut, fixture.direction);
                },
                "prefix truncation " + fixture.name + " at " + std::to_string(n));
        }
        Bytes extended = bytes;
        extended.push_back(0x00);
        ++g_boundary;
        rejects([&] { (void)decode(extended, fixture.direction); }, "trailing byte " + fixture.name,
                ErrorCode::TrailingBytes);
        const bool client_only = std::holds_alternative<JoinRequest>(fixture.expected) ||
                                 std::holds_alternative<GameInfo>(fixture.expected);
        const bool server_only = std::holds_alternative<JoinSuccess>(fixture.expected) ||
                                 std::holds_alternative<RoomInformation>(fixture.expected) ||
                                 std::holds_alternative<StatusMessage>(fixture.expected) ||
                                 std::holds_alternative<ServerError>(fixture.expected);
        if (client_only) {
            ++g_boundary;
            rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                    "client-only decode s2c: " + fixture.name, ErrorCode::WrongDirection);
            ++g_boundary;
            rejects([&] { (void)encode(fixture.expected, Direction::ServerToClient); },
                    "client-only encode s2c: " + fixture.name, ErrorCode::WrongDirection);
        }
        if (server_only) {
            ++g_boundary;
            rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                    "server-only decode c2s: " + fixture.name, ErrorCode::WrongDirection);
            ++g_boundary;
            rejects([&] { (void)encode(fixture.expected, Direction::ClientToServer); },
                    "server-only encode c2s: " + fixture.name, ErrorCode::WrongDirection);
        }
        if (std::holds_alternative<ChatRequest>(fixture.expected)) {
            // Id 7 is overloaded: c2s it carries one string, s2c it carries
            // nickname/username/message. A client frame re-read as a server
            // frame therefore fails structurally, not by a direction tag.
            ++g_boundary;
            rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                    "chat request decode s2c: " + fixture.name, ErrorCode::Truncated);
            ++g_boundary;
            rejects([&] { (void)encode(fixture.expected, Direction::ServerToClient); },
                    "chat request encode s2c: " + fixture.name, ErrorCode::WrongDirection);
        }
        if (std::holds_alternative<ChatMessage>(fixture.expected)) {
            ++g_boundary;
            rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                    "chat response decode c2s: " + fixture.name, ErrorCode::TrailingBytes);
            ++g_boundary;
            rejects([&] { (void)encode(fixture.expected, Direction::ClientToServer); },
                    "chat response encode c2s: " + fixture.name, ErrorCode::WrongDirection);
        }
        if (std::holds_alternative<ProxyPacket>(fixture.expected) ||
            std::holds_alternative<LdnPacket>(fixture.expected)) {
            const auto other = fixture.direction == Direction::ClientToServer ? Direction::ServerToClient
                                                                             : Direction::ClientToServer;
            check(decode(bytes, other) == fixture.expected, "symmetric decode: " + fixture.name);
            check(encode(fixture.expected, other) == bytes, "symmetric encode: " + fixture.name);
        }
    }
}

// ---------------------------------------------------------------------------
void test_message_ids() {
    const std::vector<std::uint8_t> unknown_ids{0x00, 0x19, 0x7f, 0xff};
    for (const std::uint8_t raw : unknown_ids) {
        ++g_boundary;
        rejects([&] { (void)decode(Bytes{raw}, Direction::ClientToServer); }, "unknown id " + std::to_string(raw),
                ErrorCode::UnknownMessage);
        check(!is_known_message_id(raw), "unknown id is not known: " + std::to_string(raw));
    }
    for (std::uint8_t raw = 1; raw <= 24; ++raw)
        check(is_known_message_id(raw), "known id " + std::to_string(raw));
    for (std::uint8_t raw = 17; raw <= 23; ++raw) {
        const auto id = static_cast<MessageId>(raw);
        check(is_known_message_id(raw) && is_unsupported_message_id(id), "unsupported id " + std::to_string(raw));
        ++g_boundary;
        rejects([&] { (void)decode(Bytes{raw}, Direction::ClientToServer); },
                "unsupported c2s " + std::to_string(raw), ErrorCode::UnsupportedMessage);
        ++g_boundary;
        rejects([&] { (void)decode(Bytes{raw}, Direction::ServerToClient); },
                "unsupported s2c " + std::to_string(raw), ErrorCode::UnsupportedMessage);
    }
    for (const auto id : {MessageId::NameCollision, MessageId::IpCollision, MessageId::VersionMismatch,
                          MessageId::WrongPassword, MessageId::CloseRoom, MessageId::RoomIsFull,
                          MessageId::HostKicked, MessageId::HostBanned})
        check(is_server_error(id), "server error id " + message_name(id));
    check(!is_server_error(MessageId::StatusMessage), "status message is not an error");
    {
        auto bytes = H(golden::ldn_packet_hex);
        set_u8(bytes, 1, 6);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); }, "ldn type 6 is invalid",
                ErrorCode::InvalidEnum);
    }
    {
        auto bytes = H(golden::status_message_hex);
        set_u8(bytes, 1, 0);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "status type 0 is invalid",
                ErrorCode::InvalidEnum);
        set_u8(bytes, 1, 6);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "status type 6 is invalid",
                ErrorCode::InvalidEnum);
    }
    {
        auto expected = golden::proxy_packet();
        expected.local_endpoint.family = 0xff;
        expected.remote_endpoint.family = 0xff;
        expected.protocol = 0xff;
        const auto bytes = encode(expected, Direction::ClientToServer);
        ++g_boundary;
        check(decode(bytes, Direction::ClientToServer) == Message{expected}, "opaque family/protocol round-trip");
        check(bytes[1] == 0xff && bytes[8] == 0xff && bytes[15] == 0xff,
              "captured family/protocol bytes are preserved verbatim");
    }
    {
        ++g_boundary;
        rejects([] { (void)encode(Message{ServerError{MessageId::JoinRequest, 0}}, Direction::ServerToClient); },
                "server error id must be one of the eight", ErrorCode::InvalidEnum);
        ++g_boundary;
        rejects([] { (void)encode(Message{ServerError{MessageId::NameCollision, 5}}, Direction::ServerToClient); },
                "bare error carries no payload", ErrorCode::InvalidArgument);
        const auto bytes = encode(Message{ServerError{MessageId::VersionMismatch, 7}}, Direction::ServerToClient);
        check(to_hex(bytes) == "0a00000007", "VersionMismatch carries the u32 server version");
        check(decode(bytes, Direction::ServerToClient) == Message{ServerError{MessageId::VersionMismatch, 7}},
              "VersionMismatch version round-trips");
    }
    for (const char* hex : {golden::name_collision_hex, golden::ip_collision_hex, golden::version_mismatch_hex,
                            golden::wrong_password_hex, golden::close_room_hex, golden::room_full_hex,
                            golden::host_kicked_hex, golden::host_banned_hex}) {
        auto bytes = H(hex);
        bytes.push_back(0x00);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "error frame does not carry extra bytes",
                ErrorCode::TrailingBytes);
    }
}

// ---------------------------------------------------------------------------
void test_declared_lengths() {
    {
        auto bytes = H(golden::join_request_hex);
        set_u32(bytes, 1, 0xff);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); }, "nickname length beyond the frame",
                ErrorCode::Truncated);
        set_u32(bytes, 1, 0x2000);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); }, "nickname length above string cap",
                ErrorCode::LimitExceeded);
        set_u32(bytes, 1, 0xffffffffu);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                "hostile nickname length must not allocate", ErrorCode::LimitExceeded);
    }
    {
        auto bytes = H(golden::room_information_hex);
        set_u32(bytes, 1, 0xffffffffu);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "hostile room name length",
                ErrorCode::LimitExceeded);
        set_u32(bytes, 1, 0x2000);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "room name above string cap",
                ErrorCode::LimitExceeded);
    }
    {
        auto bytes = H(golden::room_information_hex);
        set_u32(bytes, 26, 2);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "member count beyond the frame",
                ErrorCode::Truncated);
        set_u32(bytes, 26, 0xffffffffu);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "hostile member count",
                ErrorCode::LimitExceeded);
    }
    {
        auto bytes = H(golden::room_information_hex);
        set_u32(bytes, 10, 0);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "zero member slots",
                ErrorCode::LimitExceeded);
        set_u32(bytes, 10, 0xffffffffu);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); }, "hostile member slots",
                ErrorCode::LimitExceeded);
    }
    {
        auto bytes = H(golden::room_information_hex);
        set_u16(bytes, 14, 0xffff);
        const auto message = decode(bytes, Direction::ServerToClient);
        check(std::get<RoomInformation>(message).port == 0xffff, "u16 port is verbatim");
    }
    {
        auto bytes = H(golden::proxy_packet_hex);
        set_u32(bytes, 17, 0xffffffffu);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); }, "hostile blob length",
                ErrorCode::LimitExceeded);
        set_u32(bytes, 17, 0x00010000u);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); }, "blob length above cap",
                ErrorCode::LimitExceeded);
        set_u32(bytes, 17, 0x40);
        ++g_boundary;
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); }, "blob length beyond the frame",
                ErrorCode::Truncated);
    }
    {
        RoomInformation two = golden::room_information();
        two.member_slots = 8;
        Member guest;
        guest.nickname = "Guest";
        guest.fake_ip = golden::ip_of({192, 168, 1, 3});
        guest.game_name = "GU";
        guest.game_id = 0x0102030405060708ULL;
        guest.game_version = "1";
        guest.username = "v";
        guest.display_name = "W";
        two.members.push_back(guest);
        const auto full = encode(two, Direction::ServerToClient);
        check(decode(full, Direction::ServerToClient) == Message{two}, "two-member room round-trips");
        for (std::size_t n = 0; n < full.size(); ++n) {
            ++g_prefix;
            rejects(
                [&] {
                    const Bytes cut(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(n));
                    (void)decode(cut, Direction::ServerToClient);
                },
                "two-member truncation at " + std::to_string(n));
        }
    }
}

// ---------------------------------------------------------------------------
void test_limits() {
    ++g_boundary;
    rejects([] { (void)decode(Bytes{}, Direction::ClientToServer); }, "empty packet", ErrorCode::Truncated);
    ++g_boundary;
    rejects([] { (void)decode(golden::bytes_of({0x08}), Direction::ServerToClient, Limits{.packet_bytes = 0}); },
            "zero packet limit is rejected before parsing", ErrorCode::InvalidArgument);
    ++g_boundary;
    rejects([] {
        const Bytes big(Limits{}.packet_bytes + 1, 0x00);
        (void)decode(big, Direction::ClientToServer);
    }, "packet larger than the cap", ErrorCode::LimitExceeded);
    {
        Limits tightened;
        tightened.members = 2;
        RoomInformation info = golden::room_information();
        info.member_slots = 3;
        ++g_boundary;
        rejects([&] { (void)encode(info, Direction::ServerToClient, tightened); }, "member slots above the limit",
                ErrorCode::LimitExceeded);
        info.member_slots = 2;
        check(!encode(info, Direction::ServerToClient, tightened).empty(), "member slots at the limit are accepted");
    }
    {
        Limits tightened;
        tightened.string_bytes = 2;
        JoinRequest request = golden::join_request();
        ++g_boundary;
        rejects([&] { (void)encode(request, Direction::ClientToServer, tightened); },
                "string above the tightened limit", ErrorCode::LimitExceeded);
    }
    {
        Limits widened;
        widened.packet_bytes = Limits{}.packet_bytes + 1;
        ++g_boundary;
        rejects([&] { (void)encode(golden::chat_request(), Direction::ClientToServer, widened); },
                "limits may not be widened", ErrorCode::InvalidArgument);
    }
}

// ---------------------------------------------------------------------------
void test_names() {
    for (std::uint8_t raw = 1; raw <= 24; ++raw)
        check(!message_name(static_cast<MessageId>(raw)).empty(), "message name " + std::to_string(raw));
    for (int type = 0; type <= 5; ++type)
        check(!ldn_type_name(static_cast<LdnPacketType>(type)).empty(), "ldn type name " + std::to_string(type));
    for (int type = 1; type <= 5; ++type)
        check(!status_type_name(static_cast<StatusType>(type)).empty(), "status type name " + std::to_string(type));
    for (const auto code : {ErrorCode::Truncated, ErrorCode::LimitExceeded, ErrorCode::InvalidBoolean,
                            ErrorCode::InvalidEnum, ErrorCode::UnknownMessage, ErrorCode::UnsupportedMessage,
                            ErrorCode::TrailingBytes, ErrorCode::WrongDirection, ErrorCode::InvalidState,
                            ErrorCode::InvalidArgument, ErrorCode::Timeout})
        check(!error_code_name(code).empty(), "error code name");
    check(direction_name(Direction::ClientToServer) != direction_name(Direction::ServerToClient),
          "direction names are distinct");
    check(domain_name(domain_inet) == "INET", "source Domain::INET name");
    check(protocol_name(protocol_udp) == "UDP", "source Protocol::UDP name");
    ++g_boundary;
    check(protocol_name(0x03) == "Unknown", "captured protocol byte 0x03 has no source enum name");
}

} // namespace

int main() {
    try {
        section("primitives", test_primitives);
        section("hex", test_hex);
        section("fixtures", test_fixtures);
        section("message_ids", test_message_ids);
        section("declared_lengths", test_declared_lengths);
        section("limits", test_limits);
        section("names", test_names);
    } catch (const std::exception& error) {
        std::cout << "protocol tests FAILED: " << error.what() << "\n";
        std::cout << "checks_before_failure=" << g_checks << "\n";
        return 1;
    }
    std::cout << "section breakdown:\n";
    for (const auto& stat : g_stats)
        std::cout << "  " << stat.name << ": checks=" << stat.checks
                  << " prefix_truncations=" << stat.prefix << " boundary_cases=" << stat.boundary << "\n";
    std::cout << "protocol tests passed checks=" << g_checks << " prefix_truncations=" << g_prefix
              << " boundary_cases=" << g_boundary << "\n";
    return 0;
}
