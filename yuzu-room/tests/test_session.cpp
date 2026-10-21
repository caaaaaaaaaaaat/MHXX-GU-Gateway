// SPDX-License-Identifier: GPL-2.0-or-later
// Offline session tests. Every rejected packet must leave the observable
// session state byte-identical; the timeout transition is the only documented
// state change that a failed receive may cause.
#include "golden.hpp"
#include "yuzu_room/session.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace {

using namespace yuzu_room;
using Direction = yuzu_room::Direction;

int g_checks = 0;
int g_invariants = 0;
int g_boundary = 0;
int g_prefix = 0;

struct Stat {
    std::string name;
    int checks = 0;
    int invariants = 0;
    int boundary = 0;
    int prefix = 0;
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

struct Snapshot {
    SessionState state = SessionState::Idle;
    bool has_room = false;
    bool has_assigned = false;
    bool has_error = false;
    bool timed_out = false;
    bool moderator = false;
    std::string nickname;
    std::string room_name;
    bool operator==(const Snapshot&) const = default;
};

Snapshot snap(const Session& session) {
    Snapshot out;
    out.state = session.state();
    out.has_room = session.room().has_value();
    out.has_assigned = session.assigned_fake_ip().has_value();
    out.has_error = session.last_server_error().has_value();
    out.timed_out = session.timed_out();
    out.moderator = session.moderator();
    out.nickname = session.nickname();
    if (session.room()) out.room_name = session.room()->name;
    return out;
}

template <typename Fn>
void rejects_without_mutation(Session& session, const Fn& fn, const std::string& what,
                              std::optional<ErrorCode> expected = std::nullopt) {
    const Snapshot before = snap(session);
    ++g_checks;
    try {
        fn();
    } catch (const ProtocolError& error) {
        check_code(error, expected, what);
        const Snapshot after = snap(session);
        if (!(before == after)) throw std::runtime_error("state mutated on rejection: " + what);
        ++g_invariants;
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
    const int invariants = g_invariants;
    const int boundary = g_boundary;
    const int prefix = g_prefix;
    run();
    stat.checks = g_checks - checks;
    stat.invariants = g_invariants - invariants;
    stat.boundary = g_boundary - boundary;
    stat.prefix = g_prefix - prefix;
    g_stats.push_back(stat);
}

Bytes H(const std::string& text) { return parse_hex(text); }

Bytes frame(const Message& message, Direction direction) { return encode(message, direction); }

Session& join_test_member(Session& session, std::uint64_t& now) {
    (void)session.begin_join(golden::join_request(), now);
    (void)session.receive(frame(golden::room_information(), Direction::ServerToClient), ++now);
    (void)session.receive(frame(golden::join_success(), Direction::ServerToClient), ++now);
    return session;
}

// ---------------------------------------------------------------------------
void test_construction() {
    Session session;
    check(session.state() == SessionState::Idle, "a new session is Idle");
    check(!session.joined(), "a new session is not joined");
    check(!session.room().has_value(), "a new session has no room");
    check(!session.assigned_fake_ip().has_value(), "a new session has no fake IP");
    check(!session.last_server_error().has_value(), "a new session has no server error");
    check(!session.timed_out(), "a new session has not timed out");
    check(!session.moderator(), "a new session is not a moderator");
    check(session.nickname().empty(), "a new session has no nickname");
    ++g_boundary;
    rejects([] { Session bad(SessionOptions{.limits = Limits{}, .join_timeout_ms = 0}); }, "zero join timeout",
            ErrorCode::InvalidArgument);
    ++g_boundary;
    rejects([] { Session bad(SessionOptions{.limits = Limits{}, .leave_timeout_ms = 60001}); }, "leave timeout above the cap",
            ErrorCode::InvalidArgument);
    check(Session(SessionOptions{.limits = Limits{}, .join_timeout_ms = 1, .leave_timeout_ms = 1}).state() == SessionState::Idle,
          "minimum timeouts are accepted");
}

// ---------------------------------------------------------------------------
void test_begin_join() {
    Session session;
    const auto bytes = session.begin_join(golden::join_request(), 10);
    check(bytes == H(golden::join_request_hex), "begin_join emits the golden JoinRequest");
    check(session.state() == SessionState::Joining, "begin_join moves to Joining");
    check(session.nickname() == "Test", "begin_join remembers the nickname");
    check(!session.joined(), "begin_join does not join directly");
    Session other;
    auto request = golden::join_request();
    ++g_boundary;
    request.nickname = "abc";
    rejects_without_mutation(other, [&] { (void)other.begin_join(request, 0); }, "nickname too short",
                             ErrorCode::InvalidArgument);
    ++g_boundary;
    request.nickname = std::string(21, 'a');
    rejects_without_mutation(other, [&] { (void)other.begin_join(request, 0); }, "nickname too long",
                             ErrorCode::InvalidArgument);
    ++g_boundary;
    request.nickname = "Test!";
    rejects_without_mutation(other, [&] { (void)other.begin_join(request, 0); }, "nickname has an invalid character",
                             ErrorCode::InvalidArgument);
    ++g_boundary;
    request.nickname = "Test";
    request.version = 2;
    rejects_without_mutation(other, [&] { (void)other.begin_join(request, 0); }, "version is pinned to 1",
                             ErrorCode::InvalidArgument);
    ++g_boundary;
    rejects_without_mutation(session, [&] { (void)session.begin_join(golden::join_request(), 20); },
                             "a second join needs an explicit reset", ErrorCode::InvalidState);
    ++g_boundary;
    rejects_without_mutation(session, [&] { (void)session.begin_join(golden::join_request(), 5); },
                             "time cannot move backwards", ErrorCode::InvalidArgument);
}

// ---------------------------------------------------------------------------
void test_join_flow() {
    Session session;
    std::uint64_t now = 0;
    (void)session.begin_join(golden::join_request(), now);
    ++now;
    const auto status = session.receive(frame(golden::status_message(), Direction::ServerToClient), now);
    check(std::holds_alternative<StatusMessage>(status), "status message decodes");
    check(session.state() == SessionState::Joining, "status keeps the session Joining");
    check(!session.room().has_value(), "status does not create a room");
    ++now;
    (void)session.receive(frame(golden::room_information(), Direction::ServerToClient), now);
    check(session.state() == SessionState::Joining, "room information keeps the session Joining");
    check(session.room().has_value() && session.room()->name == "R", "room information is cached");
    ++now;
    const auto success = session.receive(frame(golden::join_success(), Direction::ServerToClient), now);
    check(std::holds_alternative<JoinSuccess>(success), "join success decodes");
    check(session.joined(), "join success moves to Joined");
    check(session.assigned_fake_ip().has_value() &&
              *session.assigned_fake_ip() == golden::ip_of({192, 168, 1, 2}),
          "assigned fake IP is cached");
    check(!session.moderator(), "plain join success is not a moderator");
    {
        const auto expected = session.room().value();
        check(decode(frame(expected, Direction::ServerToClient), Direction::ServerToClient) ==
                  Message{expected},
              "cached room information still encodes");
    }
    {
        Session real;
        std::uint64_t t = 0;
        (void)real.begin_join(golden::real_join_request(), t);
        ++t;
        (void)real.receive(H(golden::real_room_information_hex), t);
        ++t;
        (void)real.receive(H(golden::real_join_success_hex), t);
        check(real.joined(), "captured join flow reaches Joined");
        check(real.assigned_fake_ip().has_value() &&
                  *real.assigned_fake_ip() == golden::ip_of({192, 168, 124, 145}),
              "captured assigned fake IP");
        check(real.room().has_value() && real.room()->name == "rri-real-join", "captured room name");
    }
    {
        Session moderator;
        std::uint64_t t = 0;
        (void)moderator.begin_join(golden::join_request(), t);
        ++t;
        (void)moderator.receive(frame(golden::room_information(), Direction::ServerToClient), t);
        ++t;
        (void)moderator.receive(H(golden::join_success_mod_hex), t);
        check(moderator.joined() && moderator.moderator(), "JoinSuccessAsMod sets the moderator flag");
    }
}

// ---------------------------------------------------------------------------
void test_room_validation() {
    Session session;
    std::uint64_t now = 0;
    (void)session.begin_join(golden::join_request(), now);
    {
        auto info = golden::room_information();
        info.members.clear();
        ++g_boundary;
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(frame(info, Direction::ServerToClient), ++now); },
                                 "room without our nickname", ErrorCode::InvalidState);
    }
    {
        auto info = golden::room_information();
        info.members.push_back(info.members.front());
        ++g_boundary;
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(frame(info, Direction::ServerToClient), ++now); },
                                 "duplicate member identity", ErrorCode::InvalidState);
    }
    (void)session.receive(frame(golden::room_information(), Direction::ServerToClient), ++now);
    check(session.room().has_value(), "valid room information is cached");
    {
        auto success = golden::join_success();
        success.assigned_fake_ip = golden::ip_of({192, 168, 1, 9});
        ++g_boundary;
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(frame(success, Direction::ServerToClient), ++now); },
                                 "assigned fake IP is not in the room", ErrorCode::InvalidState);
    }
    {
        Session early;
        std::uint64_t t = 0;
        (void)early.begin_join(golden::join_request(), t);
        ++g_boundary;
        rejects_without_mutation(early,
                                 [&] { (void)early.receive(frame(golden::join_success(), Direction::ServerToClient), 1); },
                                 "join success before room information", ErrorCode::InvalidState);
    }
    {
        Session duplicate;
        std::uint64_t t = 0;
        join_test_member(duplicate, t);
        ++g_boundary;
        rejects_without_mutation(duplicate,
                                 [&] { (void)duplicate.receive(frame(golden::join_success(), Direction::ServerToClient), ++t); },
                                 "duplicate join success", ErrorCode::InvalidState);
    }
    {
        Session pre;
        std::uint64_t t = 0;
        (void)pre.begin_join(golden::join_request(), t);
        ++g_boundary;
        rejects_without_mutation(pre,
                                 [&] { (void)pre.receive(frame(golden::chat_message(), Direction::ServerToClient), ++t); },
                                 "chat before membership", ErrorCode::InvalidState);
    }
}

// ---------------------------------------------------------------------------
void test_send_gates() {
    Session session;
    std::uint64_t now = 0;
    (void)session.begin_join(golden::join_request(), now);
    ++g_boundary;
    rejects_without_mutation(session, [&] { (void)session.send(golden::chat_request(), ++now); },
                             "send before membership", ErrorCode::InvalidState);
    ++g_boundary;
    rejects_without_mutation(session, [&] { (void)session.send(golden::set_game_info(), ++now); },
                             "game info before membership", ErrorCode::InvalidState);
    (void)session.receive(frame(golden::room_information(), Direction::ServerToClient), ++now);
    (void)session.receive(frame(golden::join_success(), Direction::ServerToClient), ++now);
    check(session.joined(), "joined before send gates");
    check(session.send(golden::chat_request(), ++now) == H(golden::chat_request_hex), "chat send");
    check(session.send(golden::set_game_info(), ++now) == H(golden::set_game_info_hex), "game info send");
    {
        auto proxy = golden::proxy_packet();
        proxy.local_endpoint.ip = golden::ip_of({192, 168, 1, 2});
        proxy.remote_endpoint.ip = golden::ip_of({192, 168, 1, 2});
        const auto bytes = session.send(proxy, ++now);
        check(decode(bytes, Direction::ClientToServer) == Message{proxy}, "proxy send round-trips");
    }
    {
        auto proxy = golden::proxy_packet();
        proxy.local_endpoint.ip = golden::ip_of({192, 168, 1, 9});
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.send(proxy, ++now); },
                                 "proxy local IP must be the assigned one", ErrorCode::InvalidState);
    }
    {
        auto proxy = golden::proxy_packet();
        proxy.local_endpoint.ip = golden::ip_of({192, 168, 1, 2});
        proxy.remote_endpoint.ip = golden::ip_of({10, 0, 0, 1});
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.send(proxy, ++now); },
                                 "proxy remote must be a member when not broadcast", ErrorCode::InvalidState);
    }
    {
        auto proxy = golden::proxy_packet();
        proxy.local_endpoint.ip = golden::ip_of({192, 168, 1, 2});
        proxy.remote_endpoint.ip = golden::ip_of({10, 0, 0, 1});
        proxy.broadcast = true;
        check(!session.send(proxy, ++now).empty(), "proxy broadcast to an unknown remote is allowed");
    }
    {
        auto packet = golden::ldn_packet();
        packet.local_ip = golden::ip_of({192, 168, 1, 2});
        packet.remote_ip = golden::ip_of({192, 168, 1, 2});
        check(!session.send(packet, ++now).empty(), "ldn send");
    }
    {
        auto packet = golden::ldn_packet();
        packet.local_ip = golden::ip_of({192, 168, 1, 9});
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.send(packet, ++now); },
                                 "ldn local IP must be the assigned one", ErrorCode::InvalidState);
    }
    {
        auto packet = golden::ldn_packet();
        packet.local_ip = golden::ip_of({192, 168, 1, 2});
        packet.remote_ip = golden::ip_of({10, 0, 0, 1});
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.send(packet, ++now); },
                                 "ldn remote must be a member when not broadcast", ErrorCode::InvalidState);
    }
    ++g_boundary;
    rejects_without_mutation(session, [&] { (void)session.send(golden::status_message(), ++now); },
                             "status messages are server-only", ErrorCode::InvalidState);
    ++g_boundary;
    rejects_without_mutation(session, [&] { (void)session.send(golden::join_success(), ++now); },
                             "join success is server-only", ErrorCode::InvalidState);
    ++g_boundary;
    rejects_without_mutation(session, [&] { (void)session.send(golden::join_request(), ++now); },
                             "join requests use begin_join", ErrorCode::InvalidState);
    ++g_boundary;
    rejects_without_mutation(session, [&] { (void)session.send(golden::chat_message(), ++now); },
                             "chat responses are server-only", ErrorCode::InvalidState);
}

// ---------------------------------------------------------------------------
void test_leave_and_disconnect() {
    {
        Session session;
        std::uint64_t now = 0;
        (void)session.begin_join(golden::join_request(), now);
        ++g_boundary;
        rejects_without_mutation(session, [&] { session.begin_leave(++now); }, "leave before membership",
                                 ErrorCode::InvalidState);
        (void)session.receive(frame(golden::room_information(), Direction::ServerToClient), ++now);
        (void)session.receive(frame(golden::join_success(), Direction::ServerToClient), ++now);
        check(session.joined(), "the join completes after the rejected leave");
        session.begin_leave(++now);
        check(session.state() == SessionState::Leaving, "leave moves to Leaving");
        check(!session.joined(), "leaving is not joined");
        check(!session.room().has_value(), "leave clears the cached room");
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.send(golden::chat_request(), ++now); },
                                 "no sends while leaving", ErrorCode::InvalidState);
        ++g_boundary;
        rejects_without_mutation(
            session, [&] { (void)session.receive(frame(golden::chat_message(), Direction::ServerToClient), ++now); },
            "no receives while leaving", ErrorCode::InvalidState);
    }
    {
        SessionOptions options;
        options.leave_timeout_ms = 100;
        Session session(options);
        std::uint64_t now = 0;
        join_test_member(session, now);
        session.begin_leave(++now);
        check(!session.advance(now), "leave deadline not yet reached");
        check(session.advance(now + 100), "leave deadline reached");
        check(session.state() == SessionState::Idle, "leave timeout returns to Idle");
        check(session.timed_out(), "leave timeout is flagged");
    }
    {
        Session session;
        std::uint64_t now = 0;
        (void)session.begin_join(golden::join_request(), now);
        session.disconnected(++now);
        check(session.state() == SessionState::Idle && !session.timed_out(), "disconnect returns to Idle");
        session.reset(++now);
        check(session.state() == SessionState::Idle, "reset from Idle is allowed");
    }
    {
        Session session;
        std::uint64_t now = 0;
        join_test_member(session, now);
        ++g_boundary;
        rejects_without_mutation(session, [&] { session.reset(++now); }, "reset from Joined", ErrorCode::InvalidState);
    }
}

// ---------------------------------------------------------------------------
void test_receive_timeouts() {
    SessionOptions options;
    options.join_timeout_ms = 1000;
    Session session(options);
    const std::uint64_t start = 500;
    (void)session.begin_join(golden::join_request(), start);
    check(!session.advance(start), "join deadline not yet reached");
    check(!session.advance(start + 999), "join deadline not reached early");
    check(session.advance(start + 1000), "join deadline reached");
    check(session.state() == SessionState::Failed, "join timeout fails the session");
    check(session.timed_out(), "join timeout is flagged");
    check(!session.room().has_value() && session.nickname().empty(), "identity is cleared on timeout");
    ++g_boundary;
    rejects_without_mutation(session,
                             [&] { (void)session.receive(frame(golden::room_information(), Direction::ServerToClient), start + 1000); },
                             "receive after failure", ErrorCode::InvalidState);
    {
        Session expiring(options);
        std::uint64_t now = 0;
        (void)expiring.begin_join(golden::join_request(), now);
        ++g_boundary;
        rejects([&] { (void)expiring.receive(H(golden::real_room_information_hex), now + 1000); },
                "receive exactly at the join deadline", ErrorCode::Timeout);
        check(expiring.state() == SessionState::Failed && expiring.timed_out(),
              "deadline receive fails closed");
    }
    {
        Session session2;
        std::uint64_t now = 100;
        (void)session2.begin_join(golden::join_request(), now);
        ++g_boundary;
        rejects_without_mutation(session2,
                                 [&] { (void)session2.receive(frame(golden::room_information(), Direction::ServerToClient), now - 1); },
                                 "receive time moved backwards", ErrorCode::InvalidArgument);
        ++g_boundary;
        rejects_without_mutation(session2, [&] { (void)session2.advance(now - 1); }, "advance time moved backwards",
                                 ErrorCode::InvalidArgument);
        (void)session2.receive(frame(golden::status_message(), Direction::ServerToClient), now + 1);
        ++g_boundary;
        rejects_without_mutation(
            session2,
            [&] { (void)session2.receive(frame(golden::status_message(), Direction::ServerToClient), now + 2, 1); },
            "only ENet channel 0 is audited", ErrorCode::InvalidArgument);
    }
}

// ---------------------------------------------------------------------------
void test_session_termination_and_failclosed() {
    for (const auto id : {MessageId::NameCollision, MessageId::IpCollision, MessageId::VersionMismatch,
                          MessageId::WrongPassword, MessageId::RoomIsFull}) {
        Session session;
        std::uint64_t now = 0;
        (void)session.begin_join(golden::join_request(), now);
        const auto payload = id == MessageId::VersionMismatch ? 1u : 0u;
        (void)session.receive(frame(Message{ServerError{id, payload}}, Direction::ServerToClient), ++now);
        check(session.state() == SessionState::Failed, "join rejection fails the session: " + message_name(id));
        check(session.last_server_error().has_value() && *session.last_server_error() == id,
              "join rejection is recorded: " + message_name(id));
        check(!session.room().has_value() && !session.assigned_fake_ip().has_value(),
              "join rejection clears identity: " + message_name(id));
    }
    for (const auto id : {MessageId::CloseRoom, MessageId::HostKicked, MessageId::HostBanned}) {
        Session session;
        std::uint64_t now = 0;
        join_test_member(session, now);
        (void)session.receive(frame(Message{ServerError{id, 0}}, Direction::ServerToClient), ++now);
        check(session.state() == SessionState::Failed, "termination fails the session: " + message_name(id));
        check(session.last_server_error().has_value() && *session.last_server_error() == id,
              "termination is recorded: " + message_name(id));
    }
    {
        Session session;
        std::uint64_t now = 0;
        join_test_member(session, now);
        ++g_boundary;
        rejects_without_mutation(
            session, [&] { (void)session.receive(H(golden::wrong_password_hex), ++now); },
            "join rejection after membership", ErrorCode::InvalidState);
    }
    {
        Session session;
        std::uint64_t now = 0;
        (void)session.begin_join(golden::join_request(), now);
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.receive(H(golden::set_game_info_hex), ++now); },
                                 "client frame received as a server frame", ErrorCode::WrongDirection);
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.receive(H(golden::join_request_hex), ++now); },
                                 "join request received", ErrorCode::WrongDirection);
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.receive(golden::bytes_of({0x00}), ++now); },
                                 "unknown message id", ErrorCode::UnknownMessage);
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.receive(golden::bytes_of({0x11}), ++now); },
                                 "unsupported message id", ErrorCode::UnsupportedMessage);
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.receive(golden::bytes_of({0xff}), ++now); },
                                 "unknown message id 0xff", ErrorCode::UnknownMessage);
        ++g_boundary;
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(Bytes(Limits{}.packet_bytes + 1, 0), ++now); },
                                 "packet above the size cap", ErrorCode::LimitExceeded);
        ++g_boundary;
        auto trailing = H(golden::real_room_information_hex);
        trailing.push_back(0x00);
        rejects_without_mutation(session, [&] { (void)session.receive(trailing, ++now); },
                                 "room information with a trailing byte", ErrorCode::TrailingBytes);
    }
    {
        Session session;
        std::uint64_t now = 0;
        join_test_member(session, now);
        auto proxy = H(golden::proxy_packet_hex);
        proxy[16] = 0x02;
        ++g_boundary;
        rejects_without_mutation(session, [&] { (void)session.receive(proxy, ++now); },
                                 "relayed proxy with an invalid bool", ErrorCode::InvalidBoolean);
    }
    {
        Session session;
        std::uint64_t now = 0;
        (void)session.begin_join(golden::real_join_request(), now);
        const auto info = H(golden::real_room_information_hex);
        for (std::size_t n = 0; n < info.size(); ++n) {
            ++g_prefix;
            rejects_without_mutation(
                session,
                [&] {
                    const Bytes cut(info.begin(), info.begin() + static_cast<std::ptrdiff_t>(n));
                    (void)session.receive(cut, ++now);
                },
                "truncated room information at " + std::to_string(n));
        }
        const auto success = H(golden::real_join_success_hex);
        for (std::size_t n = 0; n < success.size(); ++n) {
            ++g_prefix;
            rejects_without_mutation(
                session,
                [&] {
                    const Bytes cut(success.begin(), success.begin() + static_cast<std::ptrdiff_t>(n));
                    (void)session.receive(cut, ++now);
                },
                "truncated join success at " + std::to_string(n));
        }
        (void)session.receive(info, ++now);
        (void)session.receive(success, ++now);
        check(session.joined(), "the captured flow still joins after every rejection");
    }
}

// ---------------------------------------------------------------------------
void test_nickname_rule() {
    check(is_valid_nickname("Test"), "four characters are valid");
    check(is_valid_nickname("a b_c-d.e"), "space, dot, underscore and dash are valid");
    check(is_valid_nickname(std::string(20, 'a')), "twenty characters are valid");
    ++g_boundary;
    check(!is_valid_nickname(std::string(3, 'a')), "three characters are invalid");
    ++g_boundary;
    check(!is_valid_nickname(std::string(21, 'a')), "twenty-one characters are invalid");
    ++g_boundary;
    check(!is_valid_nickname("Test!"), "exclamation mark is invalid");
    ++g_boundary;
    check(!is_valid_nickname(""), "the empty nickname is invalid");
    ++g_boundary;
    check(!is_valid_nickname("T" "\xc3\xab" "st"), "non-ASCII bytes are invalid");
}

// ---------------------------------------------------------------------------
void test_state_names() {
    const std::vector<SessionState> states{SessionState::Idle, SessionState::Joining, SessionState::Joined,
                                           SessionState::Leaving, SessionState::Failed};
    for (std::size_t i = 0; i < states.size(); ++i) {
        check(!state_name(states[i]).empty(), "state name is not empty " + std::to_string(i));
        for (std::size_t j = i + 1; j < states.size(); ++j)
            check(state_name(states[i]) != state_name(states[j]), "state names are distinct");
    }
}

} // namespace

int main() {
    try {
        section("construction", test_construction);
        section("begin_join", test_begin_join);
        section("join_flow", test_join_flow);
        section("room_validation", test_room_validation);
        section("send_gates", test_send_gates);
        section("leave_and_disconnect", test_leave_and_disconnect);
        section("receive_timeouts", test_receive_timeouts);
        section("session_termination_and_failclosed", test_session_termination_and_failclosed);
        section("nickname_rule", test_nickname_rule);
        section("state_names", test_state_names);
    } catch (const std::exception& error) {
        std::cout << "session tests FAILED: " << error.what() << "\n";
        std::cout << "checks_before_failure=" << g_checks << "\n";
        return 1;
    }
    std::cout << "section breakdown:\n";
    for (const auto& stat : g_stats)
        std::cout << "  " << stat.name << ": checks=" << stat.checks
                  << " state_invariants=" << stat.invariants << " prefix_truncations=" << stat.prefix
                  << " boundary_cases=" << stat.boundary << "\n";
    std::cout << "session tests passed checks=" << g_checks << " state_invariants=" << g_invariants
              << " prefix_truncations=" << g_prefix << " boundary_cases=" << g_boundary << "\n";
    return 0;
}
