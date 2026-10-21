// SPDX-License-Identifier: GPL-2.0-or-later
#include "golden.hpp"
#include "room_client/session.hpp"
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <utility>

using namespace room_client;
namespace {
std::size_t checks = 0, prefixes = 0, length_cases = 0;
void check(bool value, const std::string& detail) {
    ++checks;
    if (!value) throw std::runtime_error(detail);
}
template<class F> void rejects(F&& f, const std::string& detail,
                              std::optional<ErrorCode> expected = {}) {
    ++checks;
    try { f(); }
    catch (const ProtocolError& e) {
        if (expected && e.code() != *expected) throw std::runtime_error(detail + ": unexpected error: " + e.what());
        return;
    }
    throw std::runtime_error(detail + ": did not reject");
}
void set_u32(Bytes& b, std::size_t p, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) b.at(p + i) = static_cast<std::uint8_t>(value >> ((3 - i) * 8));
}
void golden_and_prefixes() {
    auto fixtures = golden::fixtures();
    check(fixtures.size() == 24, "golden fixture inventory");
    for (const auto& f : fixtures) {
        const auto bytes = parse_hex(f.hex);
        check(encode(f.expected, f.direction) == bytes, f.name + " fixed encode golden");
        check(decode(bytes, f.direction) == f.expected, f.name + " independent decoded values");
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            Bytes prefix(bytes.begin(), bytes.begin() + static_cast<Bytes::difference_type>(n));
            rejects([&] { (void)decode(prefix, f.direction); }, f.name + " prefix " + std::to_string(n));
            ++prefixes;
        }
        auto trailing = bytes; trailing.push_back(0);
        rejects([&] { (void)decode(trailing, f.direction); }, f.name + " trailing garbage", ErrorCode::TrailingBytes);
        Limits tight; tight.packet_bytes = bytes.size();
        check(decode(bytes, f.direction, tight) == f.expected, f.name + " exact packet cap");
        if (bytes.size() > 1) {
            --tight.packet_bytes;
            rejects([&] { (void)decode(bytes, f.direction, tight); }, f.name + " decode packet cap", ErrorCode::LimitExceeded);
            rejects([&] { (void)encode(f.expected, f.direction, tight); }, f.name + " encode packet cap", ErrorCode::LimitExceeded);
        }
    }
    // Envelope codecs support both directions; upstream/downstream chat differs.
    for (const auto* hex : {golden::ldn, golden::proxy}) {
        auto bytes = parse_hex(hex);
        auto m = decode(bytes, Direction::ServerToClient);
        check(encode(m, Direction::ServerToClient) == bytes, "bidirectional envelope");
    }
}
void exceptional_lengths() {
    struct Row { const char* hex; Direction direction; std::vector<std::size_t> strings; };
    const auto c = Direction::ClientToServer, s = Direction::ServerToClient;
    const std::vector<Row> rows{
        {golden::join,c,{1,17,21}}, {golden::join_utf8,c,{1,16,20}},
        {golden::join_secret,c,{1,17,23}}, {golden::empty_room,s,{1,6,16,22}},
        {golden::room,s,{1,6,16,22,30,42,56,61,66,71}},
        {golden::two_members,s,{1,6,16,22,30,42,56,61,66,71,75,87,99,103,107,111}},
        {golden::game,c,{1,15}}, {golden::chat_request,c,{1}},
        {golden::chat_message,s,{1,9,14}}, {golden::status,s,{2,10}}
    };
    for (const auto& row : rows) for (auto p : row.strings) {
        for (auto value : {4097U, 0xffffffffU}) {
            auto b = parse_hex(row.hex); set_u32(b,p,value);
            rejects([&] { (void)decode(b,row.direction); }, "oversized declared string", ErrorCode::LimitExceeded);
            ++length_cases;
        }
    }
    for (const auto* hex : {golden::ldn,golden::proxy}) for (auto value : {60001U,0xffffffffU}) {
        auto b = parse_hex(hex); set_u32(b,b[0] == 6 ? 11 : 17,value);
        rejects([&] { (void)decode(b,c); }, "oversized declared data", ErrorCode::LimitExceeded); ++length_cases;
    }
    for (auto p : {10U,26U}) for (auto value : {255U,0xffffffffU}) {
        auto b = parse_hex(golden::room); set_u32(b,p,value);
        rejects([&] { (void)decode(b,s); }, "oversized slots/member count", ErrorCode::LimitExceeded); ++length_cases;
    }
    auto b = parse_hex(golden::room); set_u32(b,26,5);
    rejects([&] { (void)decode(b,s); }, "member count exceeds slots", ErrorCode::LimitExceeded); ++length_cases;
    b = parse_hex(golden::empty_room); set_u32(b,26,1);
    rejects([&] { (void)decode(b,s); }, "member count exceeds remaining minimum bytes", ErrorCode::Truncated); ++length_cases;
    b = parse_hex(golden::ldn); set_u32(b,11,4);
    rejects([&] { (void)decode(b,c); }, "declared data one byte missing", ErrorCode::Truncated); ++length_cases;
    b = parse_hex(golden::join); set_u32(b,21,1);
    rejects([&] { (void)decode(b,c); }, "declared token byte missing", ErrorCode::Truncated); ++length_cases;
}
void illegal_values_and_directions() {
    const auto c = Direction::ClientToServer, s = Direction::ServerToClient;
    for (auto value : {0,25,255}) rejects([&] { (void)decode(Bytes{static_cast<std::uint8_t>(value)},s); }, "unknown ID", ErrorCode::UnknownMessage);
    for (int value = 17; value <= 21; ++value) rejects([&] { (void)decode(Bytes{static_cast<std::uint8_t>(value)},s); }, "explicitly unsupported moderation", ErrorCode::UnsupportedMessage);
    for (auto value : {2,255}) for (const auto* hex : {golden::ldn,golden::proxy}) {
        auto b = parse_hex(hex); b.at(b[0] == 6 ? 10 : 16) = static_cast<std::uint8_t>(value);
        rejects([&] { (void)decode(b,c); }, "illegal bool", ErrorCode::InvalidBoolean);
    }
    for (auto value : {6,255}) {
        auto b = parse_hex(golden::ldn); b[1] = static_cast<std::uint8_t>(value);
        rejects([&] { (void)decode(b,c); }, "illegal LDN type", ErrorCode::InvalidEnum);
    }
    for (auto p : {1U,8U,15U}) {
        auto b = parse_hex(golden::proxy); b[p] = 255;
        rejects([&] { (void)decode(b,c); }, "illegal proxy enum", ErrorCode::InvalidEnum);
    }
    for (auto value : {0,6,255}) {
        auto b = parse_hex(golden::status); b[1] = static_cast<std::uint8_t>(value);
        rejects([&] { (void)decode(b,s); }, "illegal status enum", ErrorCode::InvalidEnum);
    }
    for (const auto& f : golden::fixtures()) {
        if (std::holds_alternative<ProxyPacket>(f.expected) || std::holds_alternative<LdnPacket>(f.expected)) continue;
        const auto opposite = f.direction == c ? s : c;
        rejects([&] { (void)decode(parse_hex(f.hex),opposite); }, "wrong incoming direction");
        rejects([&] { (void)encode(f.expected,opposite); }, "wrong outgoing direction", ErrorCode::WrongDirection);
    }
    for (unsigned value = 0; value <= 5; ++value) {
        auto b = parse_hex(golden::ldn); b[1] = static_cast<std::uint8_t>(value);
        check(encode(decode(b,c),c) == b, "all valid LDN enum values");
    }
    for (unsigned family = 0; family <= 1; ++family) for (unsigned protocol = 0; protocol <= 3; ++protocol) {
        auto b = parse_hex(golden::proxy); b[1] = b[8] = static_cast<std::uint8_t>(family); b[15] = static_cast<std::uint8_t>(protocol);
        check(encode(decode(b,c),c) == b, "all valid proxy enum values");
    }
    for (unsigned value = 1; value <= 5; ++value) {
        auto b = parse_hex(golden::status); b[1] = static_cast<std::uint8_t>(value);
        check(encode(decode(b,s),s) == b, "all valid status enum values");
    }
    LdnPacket ldn; ldn.type = static_cast<LdnType>(6);
    rejects([&] { (void)encode(ldn,c); }, "encode illegal LDN type", ErrorCode::InvalidEnum);
    ProxyPacket proxy; proxy.local.family = static_cast<Domain>(2);
    rejects([&] { (void)encode(proxy,c); }, "encode illegal family", ErrorCode::InvalidEnum);
    proxy.local.family = Domain::Inet; proxy.protocol = static_cast<SocketProtocol>(4);
    rejects([&] { (void)encode(proxy,c); }, "encode illegal socket protocol", ErrorCode::InvalidEnum);
    rejects([&] { (void)encode(StatusMessage{static_cast<StatusType>(0),"",""},s); }, "encode illegal status", ErrorCode::InvalidEnum);
    rejects([&] { (void)encode(ServerError{MessageId::JoinRequest,0},s); }, "encode invalid error variant");
    rejects([&] { (void)encode(ServerError{MessageId::WrongPassword,1},s); }, "error version field not applicable", ErrorCode::InvalidArgument);
    rejects([&] { (void)decode(parse_hex(golden::success),static_cast<Direction>(7)); }, "illegal direction enum", ErrorCode::InvalidEnum);
    rejects([&] { (void)parse_hex("0"); }, "odd hex", ErrorCode::InvalidArgument);
    rejects([&] { (void)parse_hex("zz"); }, "non-hex", ErrorCode::InvalidArgument);
    check(parse_hex(" aA \n BB\t00\r") == Bytes({0xaa,0xbb,0}), "hex whitespace and case");
    check(to_hex(Bytes{0,255}) == "00ff", "canonical hex output");
}
void boundary_resources() {
    const auto c = Direction::ClientToServer, s = Direction::ServerToClient;
    JoinRequest j; j.nickname.assign(4096,'x');
    auto b = encode(j,c); check(std::get<JoinRequest>(decode(b,c)).nickname == j.nickname, "exact string limit");
    j.nickname += 'x'; rejects([&] { (void)encode(j,c); }, "string over limit", ErrorCode::LimitExceeded);
    LdnPacket l; l.data.assign(60000,0xaa); b = encode(l,c);
    check(std::get<LdnPacket>(decode(b,c)).data == l.data, "exact data limit");
    l.data.push_back(0); rejects([&] { (void)encode(l,c); }, "data over limit", ErrorCode::LimitExceeded);
    RoomInformation room; room.member_slots = 254; room.members.resize(254);
    b = encode(room,s); check(std::get<RoomInformation>(decode(b,s)).members.size() == 254, "exact member cap");
    room.members.resize(255); rejects([&] { (void)encode(room,s); }, "member cap exceeded", ErrorCode::LimitExceeded);
    room.members.clear(); room.member_slots = 0;
    rejects([&] { (void)encode(room,s); }, "zero slots", ErrorCode::LimitExceeded);
    room.member_slots = 254; room.members.resize(254); for (auto& m : room.members) m.nickname.assign(4096,'x');
    rejects([&] { (void)encode(room,s); }, "aggregate total packet limit", ErrorCode::LimitExceeded);
    rejects([&] { (void)decode(Bytes(65537,0),s); }, "input total packet limit", ErrorCode::LimitExceeded);
    rejects([&] { (void)parse_hex(std::string(131074,'a')); }, "hex decoded packet limit", ErrorCode::LimitExceeded);
    rejects([&] { (void)to_hex(Bytes(65537,0)); }, "output hex packet limit", ErrorCode::LimitExceeded);
    rejects([&] { (void)parse_hex(std::string(196609,' ')); }, "raw hex text limit including whitespace", ErrorCode::LimitExceeded);
    ChatRequest chat{std::string(500,'h')}; b = encode(chat,c);
    check(std::get<ChatRequest>(decode(b,c)).message.size() == 500,"exact chat cap");
    chat.message += 'h'; rejects([&] { (void)encode(chat,c); }, "chat cap exceeded", ErrorCode::LimitExceeded);
    b = {7,0,0,1,0xf5}; b.resize(506,'h');
    rejects([&] { (void)decode(b,c); }, "declared chat cap", ErrorCode::LimitExceeded);
    for (int field = 0; field < 5; ++field) for (bool oversized : {false,true}) {
        Limits cap; auto set = [&](std::size_t& n) { n = oversized ? n + 1 : 0; };
        switch(field) { case 0: set(cap.packet_bytes); break; case 1: set(cap.string_bytes); break;
        case 2: set(cap.members); break; case 3: set(cap.data_bytes); break; default: set(cap.chat_bytes); }
        rejects([&] { (void)decode(parse_hex(golden::success),s,cap); }, "invalid limits", ErrorCode::InvalidArgument);
    }
    Limits small; small.string_bytes = 2;
    rejects([&] { (void)decode(parse_hex(golden::join),c,small); }, "smaller string cap", ErrorCode::LimitExceeded);
    small = {}; small.data_bytes = 2;
    rejects([&] { (void)decode(parse_hex(golden::ldn),c,small); }, "smaller data cap", ErrorCode::LimitExceeded);
    small = {}; small.members = 1;
    rejects([&] { (void)decode(parse_hex(golden::room),s,small); }, "smaller member cap", ErrorCode::LimitExceeded);
}
void joined_session(Session& session, bool moderator = false) {
    (void)session.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},0);
    (void)session.receive(parse_hex(golden::room),1);
    (void)session.receive(parse_hex(moderator ? golden::moderator : golden::success),2);
}
void session_order_and_failure_safety() {
    Session session; const auto ldn = decode(parse_hex(golden::ldn),Direction::ClientToServer);
    rejects([&] { (void)session.send(ldn,0); }, "idle send rejected", ErrorCode::InvalidState);
    rejects([&] { (void)session.receive(parse_hex(golden::success),0); }, "idle success rejected", ErrorCode::InvalidState);
    check(session.state() == SessionState::Idle && !session.room() && !session.assigned_ip(), "idle identity unchanged");
    rejects([&] { (void)session.begin_join(JoinRequest{"bad",no_preferred_ip,1,"",""},0); }, "short nickname", ErrorCode::InvalidArgument);
    rejects([&] { (void)session.begin_join(JoinRequest{"Test",no_preferred_ip,2,"",""},0); }, "unsupported join version", ErrorCode::InvalidArgument);
    check(session.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},0) == parse_hex(golden::join), "state produces fixed join golden");
    rejects([&] { (void)session.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},0); }, "duplicate join", ErrorCode::InvalidState);
    rejects([&] { (void)session.receive(parse_hex(golden::success),1); }, "success before info", ErrorCode::InvalidState);
    (void)session.receive(parse_hex(golden::empty_room),1);
    rejects([&] { (void)session.receive(parse_hex(golden::success),1); }, "success without self", ErrorCode::InvalidState);
    (void)session.receive(parse_hex(golden::status),1); // Status may occur while Joining.
    (void)session.receive(parse_hex(golden::room),1);
    check(session.state() == SessionState::Joining && session.room() == golden::room_value() && !session.assigned_ip(), "RoomInformation before success accepted");
    rejects([&] { (void)session.send(ldn,1); }, "joining application send", ErrorCode::InvalidState);
    rejects([&] { (void)session.receive(parse_hex(golden::ldn),1); }, "joining inbound data", ErrorCode::InvalidState);
    auto wrong_ip = parse_hex(golden::success); wrong_ip[4] = 3;
    rejects([&] { (void)session.receive(wrong_ip,1); }, "assigned IP mismatch", ErrorCode::InvalidState);
    for (const auto& f : golden::fixtures()) {
        if (f.direction != Direction::ServerToClient) continue;
        auto bytes = parse_hex(f.hex);
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            const auto retained = session.room(); const auto state = session.state();
            rejects([&] { (void)session.receive(Bytes(bytes.begin(),bytes.begin()+static_cast<Bytes::difference_type>(n)),1); }, "invalid receive prefix");
            check(session.state() == state && session.room() == retained && !session.assigned_ip(), "malformed receive leaves identity/state unchanged");
        }
    }
    rejects([&] { (void)session.receive(parse_hex(golden::success),1,1); }, "channel 1 rejected", ErrorCode::InvalidArgument);
    (void)session.receive(parse_hex(golden::success),2);
    check(session.state() == SessionState::Joined && session.assigned_ip() == IPv4({192,168,1,2}), "normal ordered join");
    rejects([&] { (void)session.receive(parse_hex(golden::success),2); }, "duplicate success", ErrorCode::InvalidState);
    rejects([&] { (void)session.receive(parse_hex(golden::moderator),2); }, "duplicate moderator success", ErrorCode::InvalidState);
    // Codec goldens intentionally use a distinct IP (1.2.3.4) to test raw ordering.
    // The state-level positive send must instead use this session's assigned identity.
    auto valid_ldn = std::get<LdnPacket>(ldn); valid_ldn.local_ip = *session.assigned_ip();
    check(session.send(valid_ldn,2) == parse_hex("06 02 c0a80102 fedcba98 01 00000003 aabbcc"), "joined control send independent wire");
    auto valid_proxy = std::get<ProxyPacket>(decode(parse_hex(golden::proxy),Direction::ClientToServer)); valid_proxy.local.ip = *session.assigned_ip();
    check(session.send(valid_proxy,2) == parse_hex("05 01 c0a80102 1234 01 fedcba98 abcd 03 00 00000009 28b52ffd2000010000"), "joined opaque proxy send independent wire");
    auto spoofed_ldn = valid_ldn; spoofed_ldn.local_ip[3] = 3;
    rejects([&] { (void)session.send(spoofed_ldn,2); }, "spoofed LDN sender IP", ErrorCode::InvalidState);
    auto spoofed_proxy = valid_proxy; spoofed_proxy.local.ip[3] = 3;
    rejects([&] { (void)session.send(spoofed_proxy,2); }, "spoofed Proxy sender IP", ErrorCode::InvalidState);
    const auto valid_room = session.room(); const auto valid_ip = session.assigned_ip();
    auto bad_bool = parse_hex(golden::ldn); bad_bool[10] = 2;
    rejects([&] { (void)session.receive(bad_bool,2); }, "joined malformed boolean", ErrorCode::InvalidBoolean);
    check(session.state() == SessionState::Joined && session.room() == valid_room && session.assigned_ip() == valid_ip, "joined malformed input retains full identity");
    (void)session.receive(parse_hex(golden::two_members),2);
    auto duplicate = golden::room_value(); duplicate.members.push_back(duplicate.members.front());
    auto prior = session.room();
    rejects([&] { (void)session.receive(encode(duplicate,Direction::ServerToClient),2); }, "duplicate member identity", ErrorCode::InvalidState);
    check(session.room() == prior && session.state() == SessionState::Joined, "duplicate table retained state");
    duplicate.members[1].nickname = "Else";
    rejects([&] { (void)session.receive(encode(duplicate,Direction::ServerToClient),2); }, "duplicate member IP only", ErrorCode::InvalidState);
    duplicate.members[1].nickname = "Test"; duplicate.members[1].fake_ip[3] = 3;
    rejects([&] { (void)session.receive(encode(duplicate,Direction::ServerToClient),2); }, "duplicate member nickname only", ErrorCode::InvalidState);
    rejects([&] { (void)session.receive(parse_hex(golden::empty_room),2); }, "joined update loses identity", ErrorCode::InvalidState);
    rejects([&] { (void)session.send(JoinSuccess{},2); }, "cannot send server message", ErrorCode::InvalidState);
    rejects([&] { session.reset(2); }, "active reset forbidden", ErrorCode::InvalidState);
    (void)session.receive(Bytes{22},2); check(session.state() == SessionState::Joined, "moderation error preserves membership");
    rejects([&] { (void)session.receive(Bytes{11},2); }, "join failure outside joining", ErrorCode::InvalidState);
    session.begin_leave(3); check(session.state() == SessionState::Leaving && !session.room() && !session.assigned_ip(), "leave immediately clears cached identity");
    rejects([&] { (void)session.send(ldn,3); }, "leaving send rejected", ErrorCode::InvalidState);
    session.disconnected(4); check(session.state() == SessionState::Idle && !session.room(), "disconnect clean idle");
    Session mod; joined_session(mod,true); check(mod.state() == SessionState::Moderator, "moderator join");
    rejects([&] { (void)mod.receive(parse_hex(golden::moderator),2); }, "moderator duplicate", ErrorCode::InvalidState);
}
void session_rejections_timeouts() {
    for (auto id : {8,9,10,11,12,13,15,16}) {
        Session session; (void)session.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},10);
        (void)session.receive(parse_hex(golden::room),11);
        Bytes failure = id == 10 ? parse_hex(golden::mismatch) : Bytes{static_cast<std::uint8_t>(id)};
        (void)session.receive(failure,12);
        check(session.state() == SessionState::Failed && !session.room() && !session.assigned_ip(), "server rejection clears identity");
        check(session.last_server_error() == static_cast<MessageId>(id), "retains rejection reason");
        rejects([&] { (void)session.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},13); }, "no automatic retry");
        session.reset(13); check(session.state() == SessionState::Idle && !session.last_server_error(), "explicit failure reset");
    }
    for (auto id : {12,15,16}) {
        Session session; joined_session(session); (void)session.receive(Bytes{static_cast<std::uint8_t>(id)},3);
        check(session.state() == SessionState::Failed && !session.room() && !session.assigned_ip(), "joined closure cleans cache");
    }
    Session timeout; (void)timeout.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},10);
    (void)timeout.receive(parse_hex(golden::room),11);
    check(!timeout.advance(5009) && timeout.state() == SessionState::Joining, "join timeout before boundary");
    check(timeout.advance(5010) && timeout.state() == SessionState::Failed && timeout.timed_out() && !timeout.room(), "exact join deadline and cleanup");
    timeout.reset(5011); check(!timeout.timed_out(), "timeout reset");
    Session late; (void)late.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},0);
    rejects([&] { (void)late.receive(parse_hex(golden::room),5000); }, "late input timeout", ErrorCode::Timeout);
    check(late.state() == SessionState::Failed && !late.room(), "late packet not cached");
    Session leave; joined_session(leave); leave.begin_leave(3);
    check(!leave.advance(5002), "leave timeout before boundary");
    check(leave.advance(5003) && leave.state() == SessionState::Idle && leave.timed_out(), "leave exact timeout");
    rejects([&] { leave.advance(5002); }, "backwards clock", ErrorCode::InvalidArgument);
    for (auto value : {0ULL,60001ULL}) {
        SessionOptions options; options.join_timeout_ms = value;
        rejects([&] { Session invalid(options); }, "join timeout cap", ErrorCode::InvalidArgument);
        options.join_timeout_ms = 5000; options.leave_timeout_ms = value;
        rejects([&] { Session invalid(options); }, "leave timeout cap", ErrorCode::InvalidArgument);
    }
    const auto start = std::numeric_limits<std::uint64_t>::max() - 5000;
    Session overflow; (void)overflow.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},start);
    check(overflow.advance(std::numeric_limits<std::uint64_t>::max()), "deadline subtraction avoids overflow");
    Session disconnect; joined_session(disconnect); disconnect.disconnected(3);
    check(disconnect.state() == SessionState::Idle && !disconnect.assigned_ip() && !disconnect.room(), "unexpected disconnect cleanup");
}
}
int main() {
    const std::vector<std::pair<const char*,std::function<void()>>> groups{
        {"source golden + all prefix truncations",golden_and_prefixes},
        {"exceptional declared lengths",exceptional_lengths},
        {"illegal values + directions",illegal_values_and_directions},
        {"resource boundaries",boundary_resources},
        {"state ordering + invalid input safety",session_order_and_failure_safety},
        {"state rejection + bounded timeouts",session_rejections_timeouts}
    };
    std::size_t passed = 0;
    for (const auto& [name,run] : groups) {
        try { run(); ++passed; std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) { std::cerr << "FAIL " << name << ": " << e.what() << '\n'; return 1; }
    }
    std::cout << "PASS " << passed << "/" << groups.size() << " groups; " << checks
              << " checks; " << golden::fixtures().size() << " fixed golden fixtures; " << prefixes
              << " codec truncation prefixes; " << length_cases << " exceptional length cases\n";
    return 0;
}
