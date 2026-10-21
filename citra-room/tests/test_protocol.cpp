// SPDX-License-Identifier: GPL-2.0-or-later
// Offline, bounded decode/encode tests for the Citra room wire codec.
//
// Every golden byte string lives in tests/golden.hpp and was computed by hand
// from the Citra source layout; this file never derives an expectation from
// the encoder under test.
#include "citra_room/protocol.hpp"

#include "golden.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace {

using namespace citra_room;

std::size_t g_checks = 0;
std::size_t g_prefix = 0;
std::size_t g_boundary = 0;

void check(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) {
        throw std::runtime_error("check failed: " + what);
    }
}

void check_code(const ProtocolError& error, const std::optional<ErrorCode>& expected,
                const std::string& what) {
    if (expected && error.code() != *expected) {
        throw std::runtime_error("check failed: " + what + " (got code " +
                                 error_code_name(error.code()) + " at offset " +
                                 std::to_string(error.offset()) + ", want " +
                                 error_code_name(*expected) + ")");
    }
}

template <class F>
void rejects(F&& fn, const std::string& what, const std::optional<ErrorCode>& expected = {}) {
    ++g_checks;
    try {
        fn();
    } catch (const ProtocolError& error) {
        check_code(error, expected, what);
        return;
    } catch (const std::exception& error) {
        throw std::runtime_error("check failed: " + what + " threw a non-protocol exception: " +
                                 error.what());
    }
    throw std::runtime_error("check failed: " + what + " did not throw");
}

Bytes H(const std::string& hex) { return parse_hex(hex); }

void set_u32(Bytes& bytes, std::size_t pos, std::uint32_t value) {
    bytes[pos + 0] = static_cast<std::uint8_t>((value >> 24) & 0xffU);
    bytes[pos + 1] = static_cast<std::uint8_t>((value >> 16) & 0xffU);
    bytes[pos + 2] = static_cast<std::uint8_t>((value >> 8) & 0xffU);
    bytes[pos + 3] = static_cast<std::uint8_t>(value & 0xffU);
}

void set_u16(Bytes& bytes, std::size_t pos, std::uint16_t value) {
    bytes[pos + 0] = static_cast<std::uint8_t>((value >> 8) & 0xffU);
    bytes[pos + 1] = static_cast<std::uint8_t>(value & 0xffU);
}

void set_u8(Bytes& bytes, std::size_t pos, std::uint8_t value) { bytes[pos] = value; }

// --------------------------------------------------------------------------
// 1. Primitive codec (citra-master/src/network/packet.cpp)
// --------------------------------------------------------------------------
void test_primitives() {
    {
        PrimitiveWriter writer;
        writer.u8(0x12);
        writer.u16(0x1234);
        writer.u32(0x12345678U);
        writer.u64(0x0102030405060708ULL);
        const std::string prim_hex = to_hex(writer.finish());
        check(prim_hex == golden::primitives_all_hex,
              "primitive big-endian widths (got " + prim_hex + " want " +
                  std::string(golden::primitives_all_hex) + ")");
        ++g_boundary;
    }
    {
        PrimitiveWriter writer;
        writer.string("AB");
        check(to_hex(writer.finish()) == golden::primitives_string_hex,
              "u32-length-prefixed string");
        PrimitiveWriter blob;
        blob.data(Bytes{0x01, 0x02});
        check(to_hex(blob.finish()) == golden::primitives_blob_hex, "u32-length-prefixed blob");
        PrimitiveWriter flag;
        flag.boolean(false);
        flag.boolean(true);
        check(to_hex(flag.finish()) == golden::primitives_bool_hex, "boolean 0/1 encoding");
    }
    {
        Bytes all = H(golden::primitives_all_hex);
        PrimitiveReader reader(all);
        check(reader.u8() == 0x12, "u8 read");
        check(reader.u16() == 0x1234, "u16 read");
        check(reader.u32() == 0x12345678U, "u32 read");
        check(reader.u64() == 0x0102030405060708ULL, "u64 read");
        check(reader.remaining() == 0, "primitive reader consumed exactly");
        reader.require_end();
    }
    {
        Bytes text = H(golden::primitives_string_hex);
        PrimitiveReader reader(text);
        check(reader.string() == "AB", "string read");
    }
    {
        Bytes empty = H("00000000");
        PrimitiveReader reader(empty);
        check(reader.string().empty(), "zero-length string");
        PrimitiveReader blob_reader(empty);
        check(blob_reader.data().empty(), "zero-length blob");
    }
    {
        // String length prefixes are unsigned and independent of the byte content.
        PrimitiveWriter writer;
        writer.string(std::string("\0A", 2));
        Bytes encoded = writer.finish();
        check(to_hex(encoded) == "000000020041", "NUL byte inside a string is preserved");
    }
    // Strict boolean: values above 1 are rejected (declared divergence from
    // packet.cpp:69-75, which treats any nonzero byte as true).
    for (const char* raw : {"02", "80", "ff"}) {
        rejects(
            [&] {
                Bytes bytes = H(raw);
                PrimitiveReader reader(bytes);
                (void)reader.boolean();
            },
            std::string("strict boolean rejects ") + raw, ErrorCode::InvalidBoolean);
        ++g_boundary;
    }
    {
        Bytes yes = H("01");
        PrimitiveReader reader(yes);
        check(reader.boolean(), "boolean 1 is true");
    }
    // Fixed-width truncation.
    rejects([] {
        Bytes bytes = H("010203");
        PrimitiveReader reader(bytes);
        (void)reader.u32();
    }, "u32 needs four bytes", ErrorCode::Truncated);
    rejects([] {
        Bytes bytes;
        PrimitiveReader reader(bytes);
        (void)reader.u8();
    }, "u8 on empty input", ErrorCode::Truncated);
    rejects([] {
        Bytes bytes = H("001f32");
        PrimitiveReader reader(bytes);
        (void)reader.mac();
    }, "mac needs six bytes", ErrorCode::Truncated);
    // Declared length larger than the remaining bytes.
    rejects([] {
        Bytes bytes = H("000000054142");
        PrimitiveReader reader(bytes);
        (void)reader.string();
    }, "string declared length overruns input", ErrorCode::Truncated);
    rejects([] {
        Bytes bytes = H("000000030102");
        PrimitiveReader reader(bytes);
        (void)reader.data();
    }, "blob declared length overruns input", ErrorCode::Truncated);
    // Declared length above the configured limit fails before allocation.
    rejects([] {
        Bytes bytes = H("000020004142");
        PrimitiveReader reader(bytes);
        (void)reader.string();
    }, "string declared length above string_bytes", ErrorCode::LimitExceeded);
    rejects([] {
        Bytes bytes = H("000100000102");
        PrimitiveReader reader(bytes);
        (void)reader.data();
    }, "blob declared length above data_bytes", ErrorCode::LimitExceeded);
    // Trailing bytes.
    rejects([] {
        Bytes bytes = H("00");
        PrimitiveReader reader(bytes);
        reader.require_end();
    }, "require_end rejects trailing byte", ErrorCode::TrailingBytes);
    {
        Bytes bytes = H("00");
        PrimitiveReader reader(bytes);
        (void)reader.u8();
        reader.require_end(); // consume exactly: no throw
    }
    // Enumeration range checks.
    rejects([] {
        Bytes bytes = H("06");
        PrimitiveReader reader(bytes);
        (void)reader.enumeration(0, 5);
    }, "enumeration above top bound", ErrorCode::InvalidEnum);
    rejects([] {
        Bytes bytes = H("ff");
        PrimitiveReader reader(bytes);
        (void)reader.enumeration(0, 5);
    }, "enumeration 0xff", ErrorCode::InvalidEnum);
    {
        for (std::uint8_t value = 0; value <= 5; ++value) {
            Bytes bytes{value};
            PrimitiveReader reader(bytes);
            check(reader.enumeration(0, 5) == value, "enumeration legal value");
        }
    }
    // Writer limits.
    rejects([] {
        Limits limits;
        limits.string_bytes = 2;
        PrimitiveWriter writer(limits);
        writer.string("abc");
    }, "writer string cap", ErrorCode::LimitExceeded);
    rejects([] {
        Limits limits;
        limits.data_bytes = 2;
        PrimitiveWriter writer(limits);
        writer.data(Bytes{1, 2, 3});
    }, "writer blob cap", ErrorCode::LimitExceeded);
    rejects([] {
        Limits limits;
        limits.packet_bytes = 2;
        PrimitiveWriter writer(limits);
        writer.u32(0);
    }, "writer packet cap", ErrorCode::LimitExceeded);
    // Global limit validation.
    rejects([] {
        Limits limits;
        limits.packet_bytes = 0;
        (void)parse_hex("", limits);
    }, "zero packet_bytes limit", ErrorCode::InvalidArgument);
    rejects([] {
        Limits limits;
        limits.string_bytes = 1U << 20U;
        (void)parse_hex("", limits);
    }, "string_bytes above hard ceiling", ErrorCode::InvalidArgument);
    rejects([] {
        Limits limits;
        limits.members = 0;
        (void)parse_hex("", limits);
    }, "zero member limit", ErrorCode::InvalidArgument);
}

// --------------------------------------------------------------------------
// 2. Hex helpers
// --------------------------------------------------------------------------
void test_hex() {
    check(to_hex(H("01 02")) == "0102", "to_hex is lowercase and unpadded");
    check(to_hex(H("01\t02\r\n03")) == "010203", "parse_hex skips whitespace");
    check(H("").empty(), "empty hex is empty bytes");
    rejects([] { (void)parse_hex("zz"); }, "non-hex digit", ErrorCode::InvalidArgument);
    rejects([] { (void)parse_hex("abc"); }, "odd digit count", ErrorCode::InvalidArgument);
    rejects([] { (void)parse_hex("0g"); }, "half-valid pair", ErrorCode::InvalidArgument);
    const std::string tiny_cap = "010203";
    rejects([&] {
        Limits limits;
        limits.packet_bytes = 2;
        (void)parse_hex(tiny_cap, limits);
    }, "hex text above packet cap", ErrorCode::LimitExceeded);
}

// --------------------------------------------------------------------------
// 3. Golden fixtures: encode, decode, every proper prefix, trailing bytes,
//    wrong direction.
// --------------------------------------------------------------------------
void test_fixtures() {
    for (const auto& fixture : golden::fixtures()) {
        const Bytes bytes = H(fixture.hex);
        check(!bytes.empty(), "fixture " + fixture.name + " is non-empty");
        check(bytes[0] == static_cast<std::uint8_t>(message_id(fixture.expected)),
              "fixture " + fixture.name + " leading byte is the message id");

        const Bytes encoded = encode(fixture.expected, fixture.direction);
        check(encoded == bytes, "encode matches hand golden: " + fixture.name);

        const Message decoded = decode(bytes, fixture.direction);
        check(decoded == fixture.expected, "decode matches hand golden: " + fixture.name);
        check(message_id(decoded) == message_id(fixture.expected),
              "decoded id matches: " + fixture.name);

        // Every proper prefix must be rejected, never silently accepted.
        for (std::size_t length = 0; length < bytes.size(); ++length) {
            Bytes prefix(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length));
            ++g_prefix;
            rejects([&] { (void)decode(prefix, fixture.direction); },
                    "prefix of " + fixture.name + " at length " + std::to_string(length));
        }

        // One extra trailing byte must be rejected.
        Bytes extended = bytes;
        extended.push_back(0x00);
        rejects([&] { (void)decode(extended, fixture.direction); },
                "trailing byte after " + fixture.name, ErrorCode::TrailingBytes);

        const MessageId id = message_id(fixture.expected);
        const bool client_only = id == MessageId::JoinRequest || id == MessageId::SetGameInfo;
        const bool server_only = id == MessageId::JoinSuccess || id == MessageId::JoinSuccessAsMod ||
                                 id == MessageId::RoomInformation || id == MessageId::StatusMessage ||
                                 is_server_error(id);
        if (client_only) {
            rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                    "server->client " + fixture.name + " is the wrong direction",
                    ErrorCode::WrongDirection);
            rejects([&] { (void)encode(fixture.expected, Direction::ServerToClient); },
                    "encoding " + fixture.name + " as server->client", ErrorCode::WrongDirection);
        } else if (server_only) {
            rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                    "client->server " + fixture.name + " is the wrong direction",
                    ErrorCode::WrongDirection);
            rejects([&] { (void)encode(fixture.expected, Direction::ClientToServer); },
                    "encoding " + fixture.name + " as client->server", ErrorCode::WrongDirection);
        }

        // Chat has two shapes behind one id and is resolved by direction only.
        if (std::holds_alternative<ChatRequest>(fixture.expected)) {
            rejects([&] { (void)encode(fixture.expected, Direction::ServerToClient); },
                    "ChatRequest is client->server only", ErrorCode::WrongDirection);
        }
        if (std::holds_alternative<ChatMessage>(fixture.expected)) {
            rejects([&] { (void)encode(fixture.expected, Direction::ClientToServer); },
                    "ChatMessage is server->client only", ErrorCode::WrongDirection);
        }
        if (id == MessageId::WifiPacket) {
            // WifiPacket is symmetric on the wire; both directions must round-trip.
            check(decode(bytes, Direction::ServerToClient) == fixture.expected,
                  "wifi packet is direction-symmetric: " + fixture.name);
        }
    }
}

// --------------------------------------------------------------------------
// 4. Unknown / unsupported ids, illegal enum values.
// --------------------------------------------------------------------------
void test_message_ids() {
    for (std::uint8_t raw : {std::uint8_t{0x00}, std::uint8_t{0x19}, std::uint8_t{0x7f},
                             std::uint8_t{0xff}}) {
        rejects([&] {
            Bytes bytes{raw};
            (void)decode(bytes, Direction::ServerToClient);
        }, "unknown message id " + std::to_string(raw), ErrorCode::UnknownMessage);
        ++g_boundary;
    }
    for (std::uint8_t raw = 17; raw <= 23; ++raw) {
        // IdModKick(17)..IdModNoSuchUser(23) ARE defined in room.h:74-76, so they are
        // known ids that this bounded codec deliberately refuses to parse.
        check(is_known_message_id(raw) && is_unsupported_message_id(static_cast<MessageId>(raw)),
              "moderation id " + std::to_string(raw) + " is defined but unsupported");
        rejects([&] {
            Bytes bytes{raw};
            (void)decode(bytes, Direction::ServerToClient);
        }, "unsupported message id " + std::to_string(raw), ErrorCode::UnsupportedMessage);
        rejects([&] {
            Bytes bytes{raw};
            (void)decode(bytes, Direction::ClientToServer);
        }, "unsupported message id " + std::to_string(raw) + " client->server",
        ErrorCode::UnsupportedMessage);
        ++g_boundary;
    }
    for (std::uint8_t raw = 1; raw <= 24; ++raw) {
        check(is_known_message_id(raw), "id 1..24 is a known message id");
    }

    // Illegal frame type in an otherwise well-formed WifiPacket.
    {
        Bytes bytes = H(golden::wifi_packet_hex);
        set_u8(bytes, 1, 6);
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                "frame type 6 is not in PacketType", ErrorCode::InvalidEnum);
        set_u8(bytes, 1, 0xff);
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                "frame type 0xff", ErrorCode::InvalidEnum);
        // Every declared frame type is accepted.
        for (std::uint8_t type = 0; type <= 5; ++type) {
            Bytes legal = H(golden::wifi_packet_hex);
            set_u8(legal, 1, type);
            const Message decoded = decode(legal, Direction::ClientToServer);
            check(std::get<WifiPacket>(decoded).type == static_cast<FrameType>(type),
                  "legal frame type " + std::to_string(type));
        }
        // Channel is a full u8, not an enum: 0xff must round-trip unchanged.
        Bytes channel = H(golden::wifi_packet_hex);
        set_u8(channel, 2, 0xff);
        check(std::get<WifiPacket>(decode(channel, Direction::ClientToServer)).channel == 0xff,
              "channel is an opaque u8");
    }
    // Illegal status type.
    {
        Bytes bytes = H(golden::status_message_hex);
        for (std::uint8_t raw : {std::uint8_t{0x00}, std::uint8_t{0x06}, std::uint8_t{0xff}}) {
            Bytes broken = bytes;
            set_u8(broken, 1, raw);
            rejects([&] { (void)decode(broken, Direction::ServerToClient); },
                    "status type " + std::to_string(raw), ErrorCode::InvalidEnum);
            ++g_boundary;
        }
        for (std::uint8_t raw = 1; raw <= 5; ++raw) {
            Bytes legal = bytes;
            set_u8(legal, 1, raw);
            check(std::get<StatusMessage>(decode(legal, Direction::ServerToClient)).type ==
                      static_cast<StatusType>(raw),
                  "legal status type " + std::to_string(raw));
        }
    }
    // ServerError encoding rules.
    rejects([] {
        (void)encode(Message{ServerError{MessageId::JoinRequest, 0}}, Direction::ServerToClient);
    }, "ServerError carrying a non-error id", ErrorCode::InvalidEnum);
    rejects([] {
        (void)encode(Message{ServerError{MessageId::NameCollision, 4}}, Direction::ServerToClient);
    }, "bare server error with a payload", ErrorCode::InvalidArgument);
    {
        const Bytes version = encode(Message{ServerError{MessageId::VersionMismatch, 7}},
                                     Direction::ServerToClient);
        check(to_hex(version) == "0900000007", "VersionMismatch carries the server version");
        check(std::get<ServerError>(decode(version, Direction::ServerToClient)).server_version == 7,
              "VersionMismatch version round-trips");
    }
    // VersionMismatch with no payload is truncated.
    rejects([] {
        Bytes bytes = H("09");
        (void)decode(bytes, Direction::ServerToClient);
    }, "VersionMismatch needs a u32 version", ErrorCode::Truncated);
    // Bare error family must not accept a payload.
    for (std::uint8_t raw : {std::uint8_t{0x07}, std::uint8_t{0x08}, std::uint8_t{0x0a},
                             std::uint8_t{0x0b}, std::uint8_t{0x0c}, std::uint8_t{0x0d},
                             std::uint8_t{0x0f}, std::uint8_t{0x10}}) {
        Bytes bytes{raw, 0x00};
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                "bare error " + std::to_string(raw) + " rejects trailing payload",
                ErrorCode::TrailingBytes);
        ++g_boundary;
    }
}

// --------------------------------------------------------------------------
// 5. Declared-length mismatch, overrun, and member-count bounds.
// --------------------------------------------------------------------------
void test_declared_lengths() {
    // Nickname length field patched past the end of the buffer.
    {
        Bytes bytes = H(golden::join_request_hex);
        set_u32(bytes, 1, 0x000000ffU);
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                "nickname length overruns buffer", ErrorCode::Truncated);
    }
    {
        Bytes bytes = H(golden::join_request_hex);
        set_u32(bytes, 1, 0x00002000U);
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                "nickname length above string_bytes", ErrorCode::LimitExceeded);
    }
    {
        Bytes bytes = H(golden::join_request_hex);
        set_u32(bytes, 1, 0xffffffffU);
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                "nickname length 0xffffffff must not allocate", ErrorCode::LimitExceeded);
    }
    // WifiPacket data length patched.
    {
        Bytes bytes = H(golden::wifi_packet_hex);
        set_u32(bytes, 15, 0x000000ffU);
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                "wifi data length overruns buffer", ErrorCode::Truncated);
    }
    {
        Bytes bytes = H(golden::wifi_packet_hex);
        set_u32(bytes, 15, 0xffffffffU);
        rejects([&] { (void)decode(bytes, Direction::ClientToServer); },
                "wifi data length 0xffffffff must not allocate", ErrorCode::LimitExceeded);
    }
    // RoomInformation member count patched (count @39, slots @17).
    {
        Bytes bytes = H(golden::room_information_hex);
        set_u32(bytes, 39, 2);
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                "declared member count above remaining members", ErrorCode::Truncated);
    }
    {
        Bytes bytes = H(golden::room_information_hex);
        set_u32(bytes, 39, 5);
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                "member count above member_slots", ErrorCode::LimitExceeded);
    }
    {
        Bytes bytes = H(golden::room_information_hex);
        set_u32(bytes, 17, 0);
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                "zero member_slots", ErrorCode::LimitExceeded);
    }
    {
        Bytes bytes = H(golden::room_information_hex);
        set_u32(bytes, 17, 0xffffffffU);
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                "member_slots above the member limit", ErrorCode::LimitExceeded);
    }
    {
        Bytes bytes = H(golden::room_information_hex);
        set_u32(bytes, 39, 0xffffffffU);
        rejects([&] { (void)decode(bytes, Direction::ServerToClient); },
                "member count 0xffffffff must not allocate", ErrorCode::LimitExceeded);
    }
    // A well-formed two-member room information round-trips, and the last
    // member truncated is still rejected.
    {
        RoomInformation info = golden::room_information();
        Member second = info.members.front();
        second.nickname = "Nico";
        second.mac = golden::mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x34});
        second.username = "nico";
        second.display_name = "Nico";
        info.members.push_back(second);
        info.member_slots = 2;
        Bytes full = encode(Message{info}, Direction::ServerToClient);
        check(decode(full, Direction::ServerToClient) == Message{info},
              "two-member room information round-trips");
        for (std::size_t cut = 1; cut <= 40; ++cut) {
            Bytes truncated(full.begin(), full.end() - static_cast<std::ptrdiff_t>(cut));
            ++g_prefix;
            rejects([&] { (void)decode(truncated, Direction::ServerToClient); },
                    "truncated two-member room information by " + std::to_string(cut));
        }
    }
    // Port is a u16 read verbatim.
    {
        Bytes bytes = H(golden::room_information_hex);
        set_u16(bytes, 21, 1);
        check(std::get<RoomInformation>(decode(bytes, Direction::ServerToClient)).port == 1,
              "port is a u16");
    }
}

// --------------------------------------------------------------------------
// 6. Size and limit boundaries.
// --------------------------------------------------------------------------
void test_limits() {
    const Bytes join = H(golden::join_request_hex);
    {
        Limits limits;
        limits.packet_bytes = join.size();
        check(decode(join, Direction::ClientToServer, limits) == Message{golden::join_request()},
              "packet_bytes equal to the frame size decodes");
        ++g_boundary;
    }
    rejects([&] {
        Limits limits;
        limits.packet_bytes = join.size() - 1;
        (void)decode(join, Direction::ClientToServer, limits);
    }, "packet_bytes one below the frame size", ErrorCode::LimitExceeded);
    {
        // string_bytes exactly the nickname length still decodes.
        Limits limits;
        limits.string_bytes = 4;
        check(decode(join, Direction::ClientToServer, limits) == Message{golden::join_request()},
              "string_bytes equal to the longest string decodes");
        ++g_boundary;
    }
    rejects([&] {
        Limits limits;
        limits.string_bytes = 3;
        (void)decode(join, Direction::ClientToServer, limits);
    }, "string_bytes one below the nickname length", ErrorCode::LimitExceeded);
    {
        // data_bytes exactly the opaque payload length still decodes.
        Limits limits;
        limits.data_bytes = 4;
        check(decode(H(golden::wifi_packet_hex), Direction::ClientToServer, limits) ==
                  Message{golden::wifi_packet()},
              "data_bytes equal to the payload decodes");
        ++g_boundary;
    }
    rejects([&] {
        Limits limits;
        limits.data_bytes = 3;
        (void)decode(H(golden::wifi_packet_hex), Direction::ClientToServer, limits);
    }, "data_bytes one below the payload length", ErrorCode::LimitExceeded);
    {
        // chat_bytes is enforced on encode and decode alike.
        Limits limits;
        limits.chat_bytes = 4;
        const Bytes four = encode(Message{ChatRequest{"abcd"}}, Direction::ClientToServer, limits);
        check(decode(four, Direction::ClientToServer, limits) == Message{ChatRequest{"abcd"}},
              "chat_bytes equal to the message length");
        ++g_boundary;
        rejects([&] {
            (void)encode(Message{ChatRequest{"abcde"}}, Direction::ClientToServer, limits);
        }, "chat longer than chat_bytes on encode", ErrorCode::LimitExceeded);
        rejects([&] { (void)decode(H("06 00000005 6162636465"), Direction::ClientToServer, limits); },
                "chat longer than chat_bytes on decode", ErrorCode::LimitExceeded);
    }
    // A legal payload exactly at max_message_size is still limited by the
    // caller's packet_bytes; the hard ceiling is enforced too.
    {
        Limits strict;
        strict.packet_bytes = max_message_size;
        const Bytes ok = encode(Message{ChatRequest{std::string(400, 'a')}},
                                Direction::ClientToServer, strict);
        check(ok.size() == 405, "chat frame size accounting");
        rejects([&] {
            Limits tight;
            tight.packet_bytes = 404;
            tight.chat_bytes = 500;
            (void)encode(Message{ChatRequest{std::string(400, 'a')}}, Direction::ClientToServer,
                         tight);
        }, "frame above packet_bytes", ErrorCode::LimitExceeded);
    }
    // The hard ceilings are exactly the Limits{} defaults: the defaults themselves
    // are accepted, one byte above any of them is rejected outright as an argument
    // error (the caller may tighten limits, never widen them past the audited bound).
    check(decode(join, Direction::ClientToServer, Limits{}) == Message{golden::join_request()},
          "the default (hard ceiling) limits decode a legal frame");
    ++g_boundary;
    rejects([] {
        Limits limits;
        limits.packet_bytes = Limits{}.packet_bytes + 1;
        (void)encode(Message{ChatRequest{"hi!"}}, Direction::ClientToServer, limits);
    }, "packet_bytes above the hard ceiling", ErrorCode::InvalidArgument);
    rejects([] {
        Limits limits;
        limits.chat_bytes = max_message_size + 1;
        (void)encode(Message{ChatRequest{"hi!"}}, Direction::ClientToServer, limits);
    }, "chat_bytes above max_message_size", ErrorCode::InvalidArgument);
    rejects([] {
        Limits limits;
        limits.members = max_concurrent_connections + 1;
        (void)encode(Message{golden::room_information()}, Direction::ServerToClient, limits);
    }, "members above max_concurrent_connections", ErrorCode::InvalidArgument);
    rejects([] {
        Limits limits;
        limits.packet_bytes = 0;
        (void)encode(Message{ChatRequest{"hi!"}}, Direction::ClientToServer, limits);
    }, "zero packet_bytes", ErrorCode::InvalidArgument);
    // Member limit honoured on both sides of the boundary.
    {
        RoomInformation info = golden::room_information();
        info.member_slots = 2;
        info.members.push_back(info.members.front());
        Limits limits;
        limits.members = 2;
        Bytes encoded = encode(Message{info}, Direction::ServerToClient, limits);
        check(decode(encoded, Direction::ServerToClient, limits) == Message{info},
              "member limit equal to the count");
        ++g_boundary;
        info.members.push_back(info.members.front());
        info.member_slots = 3;
        rejects([&] { (void)encode(Message{info}, Direction::ServerToClient, limits); },
                "member count above the member limit", ErrorCode::LimitExceeded);
    }
}

// --------------------------------------------------------------------------
// 7. Names and enum coverage.
// --------------------------------------------------------------------------
void test_names() {
    for (std::uint8_t raw = 0; raw <= 24; ++raw) {
        if (raw == 0) continue;
        check(!message_name(static_cast<MessageId>(raw)).empty(), "message_name is non-empty");
    }
    check(message_name(MessageId::JoinRequest) == "JoinRequest", "ID1 name");
    check(message_name(MessageId::HostBanned) == "HostBanned", "ID16 name");
    check(message_name(MessageId::JoinSuccessAsMod) == "JoinSuccessAsMod", "ID24 name");
    check(message_name(MessageId::StatusMessage) == "StatusMessage", "ID14 name");
    for (std::uint8_t raw = 0; raw <= 5; ++raw) {
        check(!frame_type_name(static_cast<FrameType>(raw)).empty(), "frame_type_name");
    }
    for (std::uint8_t raw = 1; raw <= 5; ++raw) {
        check(!status_type_name(static_cast<StatusType>(raw)).empty(), "status_type_name");
    }
    for (const ErrorCode code :
         {ErrorCode::Truncated, ErrorCode::LimitExceeded, ErrorCode::InvalidBoolean,
          ErrorCode::InvalidEnum, ErrorCode::UnknownMessage, ErrorCode::UnsupportedMessage,
          ErrorCode::TrailingBytes, ErrorCode::WrongDirection, ErrorCode::InvalidState,
          ErrorCode::InvalidArgument, ErrorCode::Timeout}) {
        check(!error_code_name(code).empty(), "error_code_name");
    }
    check(direction_name(Direction::ClientToServer) != direction_name(Direction::ServerToClient),
          "directions have distinct names");
}

} // namespace

int main() {
    const struct {
        const char* name;
        void (*fn)();
    } sections[] = {
        {"primitives", test_primitives},
        {"hex", test_hex},
        {"fixtures", test_fixtures},
        {"message_ids", test_message_ids},
        {"declared_lengths", test_declared_lengths},
        {"limits", test_limits},
        {"names", test_names},
    };
    try {
        std::cout << "section breakdown:\n";
        for (const auto& section : sections) {
            const std::size_t checks_before = g_checks;
            const std::size_t prefix_before = g_prefix;
            const std::size_t boundary_before = g_boundary;
            section.fn();
            std::cout << "  " << section.name << ": checks=" << (g_checks - checks_before)
                      << " prefix_truncations=" << (g_prefix - prefix_before)
                      << " boundary_cases=" << (g_boundary - boundary_before) << "\n";
        }
    } catch (const std::exception& error) {
        std::cout << "protocol tests FAILED: " << error.what() << "\n";
        std::cout << "checks_before_failure=" << g_checks << "\n";
        return 1;
    }
    std::cout << "protocol tests passed"
              << " checks=" << g_checks
              << " prefix_truncations=" << g_prefix
              << " boundary_cases=" << g_boundary << "\n";
    return 0;
}
