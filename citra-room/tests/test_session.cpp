// SPDX-License-Identifier: GPL-2.0-or-later
// Offline tests for the synchronous Citra room session state machine.
//
// The important property here is fail-closed behaviour: no malformed or
// out-of-order server frame may move the state machine, the identity, or the
// room cache. Every rejection below re-checks the observable snapshot.
#include "citra_room/protocol.hpp"
#include "citra_room/session.hpp"

#include "golden.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace citra_room;

std::size_t g_checks = 0;
std::size_t g_invariants = 0;

void check(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) {
        throw std::runtime_error("check failed: " + what);
    }
}

template <class F>
void rejects(F&& fn, const std::string& what,
             const std::optional<ErrorCode>& expected = {}) {
    ++g_checks;
    try {
        fn();
    } catch (const ProtocolError& error) {
        if (expected && error.code() != *expected) {
            throw std::runtime_error("check failed: " + what + " (got code " +
                                     error_code_name(error.code()) + ", want " +
                                     error_code_name(*expected) + ")");
        }
        return;
    } catch (const std::exception& error) {
        throw std::runtime_error("check failed: " + what + " threw a non-protocol exception: " +
                                 error.what());
    }
    throw std::runtime_error("check failed: " + what + " did not throw");
}

Bytes H(const std::string& hex) { return parse_hex(hex); }

struct Snapshot {
    SessionState state = SessionState::Idle;
    bool has_room = false;
    bool has_mac = false;
    bool has_error = false;
    bool timed_out = false;
    std::string nickname;
    std::string room_name;

    bool operator==(const Snapshot&) const = default;
};

Snapshot snap(const Session& session) {
    Snapshot s;
    s.state = session.state();
    s.has_room = session.room().has_value();
    s.has_mac = session.assigned_mac().has_value();
    s.has_error = session.last_server_error().has_value();
    s.timed_out = session.timed_out();
    s.nickname = session.nickname();
    s.room_name = session.room() ? session.room()->name : std::string{};
    return s;
}

JoinRequest request_for(const std::string& nickname) {
    JoinRequest request = golden::join_request();
    request.nickname = nickname;
    return request;
}

// Runs fn, requires it to throw, and requires the observable session state to
// be byte-for-byte identical before and after.
template <class F>
void rejects_without_mutation(Session& session, F&& fn, const std::string& what,
                              const std::optional<ErrorCode>& expected = {}) {
    const Snapshot before = snap(session);
    rejects(std::forward<F>(fn), what, expected);
    const Snapshot after = snap(session);
    ++g_invariants;
    if (!(before == after)) {
        throw std::runtime_error("state invariant violated: " + what);
    }
}

void test_construction() {
    {
        Session session;
        check(session.state() == SessionState::Idle, "default state is Idle");
        check(!session.room().has_value(), "no room cache initially");
        check(!session.assigned_mac().has_value(), "no assigned MAC initially");
        check(!session.last_server_error().has_value(), "no error initially");
        check(!session.timed_out(), "not timed out initially");
        check(session.nickname().empty(), "no nickname initially");
    }
    rejects([] {
        SessionOptions options;
        options.limits.packet_bytes = 0;
        Session session(options);
    }, "invalid limits rejected by the constructor", ErrorCode::InvalidArgument);
    for (const std::uint64_t timeout : {std::uint64_t{0}, std::uint64_t{60001}, std::uint64_t{999999}}) {
        rejects([&] {
            SessionOptions options;
            options.join_timeout_ms = timeout;
            Session session(options);
        }, "join timeout out of range", ErrorCode::InvalidArgument);
        rejects([&] {
            SessionOptions options;
            options.leave_timeout_ms = timeout;
            Session session(options);
        }, "leave timeout out of range", ErrorCode::InvalidArgument);
    }
    {
        SessionOptions options;
        options.join_timeout_ms = 1;
        options.leave_timeout_ms = 60000;
        Session session(options);
        check(session.state() == SessionState::Idle, "boundary timeouts accepted");
        ++g_checks;
    }
}

void test_begin_join() {
    {
        Session session;
        const Bytes bytes = session.begin_join(golden::join_request(), 100);
        check(to_hex(bytes) == to_hex(H(golden::join_request_hex)), "begin_join emits golden bytes");
        check(session.state() == SessionState::Joining, "begin_join enters Joining");
        check(session.nickname() == "Nick", "begin_join records the nickname");
    }
    // A second join without a reset is refused, and changes nothing.
    {
        Session session;
        (void)session.begin_join(golden::join_request(), 0);
        rejects_without_mutation(session, [&] { (void)session.begin_join(golden::join_request(), 1); },
                                 "join while Joining", ErrorCode::InvalidState);
    }
    // Wrong nickname shapes.
    for (const std::string& bad : std::vector<std::string>{"ab", "abc", std::string(21, 'a'), "nick!", "nick\n",
                                              std::string("\xff\xff\xff\xff", 4)}) {
        Session session;
        rejects_without_mutation(session,
                                 [&] { (void)session.begin_join(request_for(bad), 0); },
                                 "illegal nickname", ErrorCode::InvalidArgument);
    }
    // Legal nickname alphabet and lengths.
    for (const std::string& good : std::vector<std::string>{"Nick", "a b c", "AB.CD-ef_12", "0123",
                                               std::string(20, 'z')}) {
        Session session;
        const JoinRequest request = request_for(good);
        check(!session.begin_join(request, 0).empty(), "legal nickname accepted");
        check(session.nickname() == good, "legal nickname recorded");
    }
    // Version is pinned to network_version 4.
    for (const std::uint32_t version : {std::uint32_t{0}, std::uint32_t{1}, std::uint32_t{3},
                                        std::uint32_t{5}, std::uint32_t{0xffffffffU}}) {
        Session session;
        JoinRequest request = golden::join_request();
        request.version = version;
        rejects_without_mutation(session, [&] { (void)session.begin_join(request, 0); },
                                 "version must be 4", ErrorCode::InvalidArgument);
    }
    // Monotonic clock.
    {
        Session session;
        (void)session.begin_join(golden::join_request(), 100);
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(H(golden::status_message_hex), 99); },
                                 "clock moved backwards", ErrorCode::InvalidArgument);
        rejects_without_mutation(session, [&] { session.advance(50); },
                                 "advance with a backwards clock", ErrorCode::InvalidArgument);
        // Equal timestamps are allowed (non-decreasing, not strictly increasing).
        (void)session.receive(H(golden::status_message_hex), 100);
    }
    // Reset requires Idle or Failed.
    {
        Session session;
        (void)session.begin_join(golden::join_request(), 0);
        rejects_without_mutation(session, [&] { session.reset(1); }, "reset while Joining",
                                 ErrorCode::InvalidState);
    }
    // After a reset the same nickname can join again.
    {
        SessionOptions options;
        options.join_timeout_ms = 100;
        Session session(options);
        (void)session.begin_join(golden::join_request(), 0);
        check(session.advance(100), "join timeout transitions");
        check(session.state() == SessionState::Failed, "join timeout leads to Failed");
        check(session.timed_out(), "join timeout is recorded");
        session.reset(101);
        check(session.state() == SessionState::Idle, "reset returns to Idle");
        check(!session.timed_out(), "reset clears the timeout flag");
        check(!session.begin_join(golden::join_request(), 102).empty(), "rejoin after reset");
    }
}

void test_join_flow() {
    SessionOptions options;
    options.join_timeout_ms = 1000;
    Session session(options);
    (void)session.begin_join(golden::join_request(), 0);

    // A server rejection moves to Failed with the error recorded, and clears
    // any identity.
    (void)session.receive(H(golden::room_is_full_hex), 10);
    check(session.state() == SessionState::Failed, "RoomIsFull leads to Failed");
    check(session.last_server_error() == MessageId::RoomIsFull, "error id recorded");
    check(!session.room().has_value(), "no room cache after rejection");
    check(!session.timed_out(), "rejection is not a timeout");

    session.reset(11);
    check(!session.last_server_error().has_value(), "reset clears the error");
    (void)session.begin_join(golden::join_request(), 12);

    // Status messages are legal during Joining and change nothing.
    (void)session.receive(H(golden::status_message_hex), 13);
    check(session.state() == SessionState::Joining, "status keeps Joining");

    // Application data during Joining is refused.
    rejects_without_mutation(session, [&] { (void)session.receive(H(golden::wifi_packet_hex), 14); },
                             "wifi data before membership", ErrorCode::InvalidState);

    // Success before room information is refused.
    rejects_without_mutation(session, [&] { (void)session.receive(H(golden::join_success_hex), 15); },
                             "JoinSuccess before RoomInformation", ErrorCode::InvalidState);

    // Room information.
    (void)session.receive(H(golden::room_information_hex), 16);
    check(session.state() == SessionState::Joining, "RoomInformation keeps Joining");
    check(session.room().has_value(), "room cache populated");
    check(session.room()->name == "Room", "room cache content");
    check(session.room()->members.size() == 1, "room cache member count");
    check(!session.assigned_mac().has_value(), "no MAC before success");

    // A second room information is still fine during Joining.
    (void)session.receive(H(golden::room_information_hex), 17);

    // Success.
    const Message success = session.receive(H(golden::join_success_hex), 18);
    check(std::get<JoinSuccess>(success).assigned_mac ==
              golden::mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x33}),
          "JoinSuccess carries the assigned MAC");
    check(session.state() == SessionState::Joined, "JoinSuccess enters Joined");
    check(session.joined(), "joined() is true");
    check(session.assigned_mac().has_value(), "assigned MAC recorded");

    // A second success is refused.
    rejects_without_mutation(session, [&] { (void)session.receive(H(golden::join_success_hex), 19); },
                             "duplicate JoinSuccess", ErrorCode::InvalidState);

    // Moderator success is recognised as a success, but only while Joining.
    {
        Session moderator(options);
        (void)moderator.begin_join(golden::join_request(), 0);
        (void)moderator.receive(H(golden::room_information_hex), 1);
        (void)moderator.receive(H(golden::join_success_as_mod_hex), 2);
        check(moderator.state() == SessionState::Joined, "moderator success enters Joined");
    }
    // Success carrying a MAC that is not in the cached room is refused.
    {
        Session bad(options);
        (void)bad.begin_join(golden::join_request(), 0);
        (void)bad.receive(H(golden::room_information_hex), 1);
        JoinSuccess foreign = golden::join_success();
        foreign.assigned_mac = golden::mac_of({0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
        rejects_without_mutation(bad, [&] { (void)bad.receive(encode(Message{foreign}, Direction::ServerToClient), 2); },
                                 "success MAC absent from the room", ErrorCode::InvalidState);
    }
}

void test_room_validation() {
    SessionOptions options;
    Session session(options);
    (void)session.begin_join(golden::join_request(), 0);

    RoomInformation info = golden::room_information();
    // Duplicate nickname.
    {
        RoomInformation dup = info;
        dup.members.push_back(info.members.front());
        dup.member_slots = 2;
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(encode(Message{dup}, Direction::ServerToClient), 1); },
                                 "duplicate member nickname", ErrorCode::InvalidState);
    }
    // Duplicate MAC.
    {
        RoomInformation dup = info;
        Member other = info.members.front();
        other.nickname = "Other";
        dup.members.push_back(other);
        dup.member_slots = 2;
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(encode(Message{dup}, Direction::ServerToClient), 1); },
                                 "duplicate member MAC", ErrorCode::InvalidState);
    }
    // Missing joining nickname.
    {
        RoomInformation other = info;
        other.members.front().nickname = "Other";
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(encode(Message{other}, Direction::ServerToClient), 1); },
                                 "room without the joining nickname", ErrorCode::InvalidState);
    }
    // Empty room.
    {
        RoomInformation empty = info;
        empty.members.clear();
        rejects_without_mutation(session,
                                 [&] { (void)session.receive(encode(Message{empty}, Direction::ServerToClient), 1); },
                                 "room without the joining nickname (empty)", ErrorCode::InvalidState);
    }
    // After joining, a broadcast that drops the assigned MAC is refused.
    {
        (void)session.receive(H(golden::room_information_hex), 2);
        (void)session.receive(H(golden::join_success_hex), 3);
        const Snapshot before = snap(session);
        RoomInformation foreign = info;
        foreign.members.front().mac = golden::mac_of({0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
        rejects([&] { (void)session.receive(encode(Message{foreign}, Direction::ServerToClient), 4); },
                "broadcast dropping the assigned MAC", ErrorCode::InvalidState);
        check(snap(session) == before, "identity and cache survive a rejected broadcast");
        ++g_invariants;
        // A fresh valid broadcast is accepted.
        (void)session.receive(H(golden::room_information_hex), 5);
        check(session.state() == SessionState::Joined, "valid broadcast keeps Joined");
    }
}

void test_send_gates() {
    SessionOptions options;
    Session session(options);
    // Sends before joining are refused.
    rejects_without_mutation(session, [&] { (void)session.send(Message{golden::set_game_info()}, 0); },
                             "send from Idle", ErrorCode::InvalidState);
    (void)session.begin_join(golden::join_request(), 0);
    rejects_without_mutation(session, [&] { (void)session.send(Message{golden::set_game_info()}, 1); },
                             "send from Joining", ErrorCode::InvalidState);
    (void)session.receive(H(golden::room_information_hex), 2);
    (void)session.receive(H(golden::join_success_hex), 3);

    // Legal application sends.
    check(to_hex(session.send(Message{golden::set_game_info()}, 4)) ==
              to_hex(H(golden::set_game_info_hex)),
          "SetGameInfo send");
    check(to_hex(session.send(Message{WifiPacket{FrameType::Data, 6,
                                                golden::mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x33}),
                                                broadcast_mac, Bytes{0xde, 0xad, 0xbe, 0xef}}}, 5)) ==
              to_hex(H("05 01 06 001f32112233 ffffffffffff 00000004 deadbeef")),
          "WifiPacket send with the assigned transmitter");
    check(to_hex(session.send(Message{ChatRequest{"hi!"}}, 6)) == to_hex(H(golden::chat_request_hex)),
          "ChatRequest send");

    // WifiPacket identity rules.
    {
        WifiPacket spoofed = golden::wifi_packet();
        rejects_without_mutation(session, [&] { (void)session.send(Message{spoofed}, 7); },
                                 "spoofed transmitter address", ErrorCode::InvalidState);
    }
    {
        WifiPacket wrong_destination = golden::wifi_packet();
        wrong_destination.destination = golden::mac_of({0x02, 0x00, 0x00, 0x00, 0x00, 0x09});
        wrong_destination.transmitter = golden::mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x33});
        rejects_without_mutation(session, [&] { (void)session.send(Message{wrong_destination}, 8); },
                                 "destination outside the room", ErrorCode::InvalidState);
    }
    {
        WifiPacket to_member = golden::wifi_packet();
        to_member.transmitter = golden::mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x33});
        to_member.destination = golden::mac_of({0x00, 0x1f, 0x32, 0x11, 0x22, 0x33});
        check(!session.send(Message{to_member}, 9).empty(), "destination may be a room member");
    }
    // Messages that are not application sends.
    rejects_without_mutation(session, [&] { (void)session.send(Message{golden::room_information()}, 10); },
                             "RoomInformation is not an application send", ErrorCode::InvalidState);
    rejects_without_mutation(session, [&] { (void)session.send(Message{golden::status_message()}, 11); },
                             "StatusMessage is not an application send", ErrorCode::InvalidState);
    rejects_without_mutation(session, [&] { (void)session.send(Message{golden::join_request()}, 12); },
                             "JoinRequest is not an application send", ErrorCode::InvalidState);
}

void test_leave_and_disconnect() {
    SessionOptions options;
    options.join_timeout_ms = 100;
    options.leave_timeout_ms = 50;
    Session session(options);
    rejects_without_mutation(session, [&] { session.begin_leave(0); }, "leave from Idle",
                             ErrorCode::InvalidState);
    (void)session.begin_join(golden::join_request(), 0);
    session.begin_leave(10);
    check(session.state() == SessionState::Leaving, "leave enters Leaving");
    check(!session.advance(59), "leave timeout not yet reached");
    check(session.advance(60), "leave timeout transitions");
    check(session.state() == SessionState::Idle, "leave timeout returns to Idle");
    check(session.timed_out(), "leave timeout is recorded");

    // Disconnect from Joined clears everything.
    (void)session.begin_join(golden::join_request(), 100);
    (void)session.receive(H(golden::room_information_hex), 101);
    (void)session.receive(H(golden::join_success_hex), 102);
    session.disconnected(103);
    check(session.state() == SessionState::Idle, "disconnect returns to Idle");
    check(!session.room().has_value(), "disconnect clears the room cache");
    check(!session.assigned_mac().has_value(), "disconnect clears the MAC");
    check(!session.last_server_error().has_value(), "disconnect clears the error");
    check(!session.timed_out(), "disconnect clears the timeout flag");
    check(session.nickname().empty(), "disconnect clears the nickname");

    // A receive after a disconnect needs a fresh join.
    rejects_without_mutation(session,
                             [&] { (void)session.receive(H(golden::status_message_hex), 104); },
                             "receive while Idle", ErrorCode::InvalidState);
}

void test_receive_timeouts() {
    SessionOptions options;
    options.join_timeout_ms = 100;
    Session session(options);
    (void)session.begin_join(golden::join_request(), 0);
    rejects([&] { (void)session.receive(H(golden::room_information_hex), 250); },
            "receive past the join deadline", ErrorCode::Timeout);
    check(session.state() == SessionState::Failed, "deadline moves to Failed");
    check(session.timed_out(), "deadline records the timeout");
    check(!session.room().has_value(), "deadline clears identity");

    // Sending past the deadline is a Timeout as well.
    Session joined(options);
    (void)joined.begin_join(golden::join_request(), 0);
    (void)joined.receive(H(golden::room_information_hex), 10);
    (void)joined.receive(H(golden::join_success_hex), 20);
    // Joined is not subject to the join timeout.
    check(!joined.advance(1000), "no timeout while Joined");
    check(joined.state() == SessionState::Joined, "still Joined");
}

void test_session_termination_and_failclosed() {
    SessionOptions options;
    Session session(options);
    (void)session.begin_join(golden::join_request(), 0);
    (void)session.receive(H(golden::room_information_hex), 1);
    (void)session.receive(H(golden::join_success_hex), 2);

    // Session termination while Joined.
    (void)session.receive(H(golden::close_room_hex), 3);
    check(session.state() == SessionState::Failed, "CloseRoom terminates the session");
    check(session.last_server_error() == MessageId::CloseRoom, "CloseRoom recorded");
    check(!session.room().has_value(), "termination clears the room cache");

    // Termination frames outside membership are refused.
    session.reset(4);
    rejects_without_mutation(session, [&] { (void)session.receive(H(golden::close_room_hex), 5); },
                             "CloseRoom while Idle", ErrorCode::InvalidState);
    (void)session.begin_join(golden::join_request(), 6);
    // HostKicked during Joining is legal (the server may reject late).
    (void)session.receive(H(golden::host_kicked_hex), 7);
    check(session.last_server_error() == MessageId::HostKicked, "HostKicked during Joining");
    check(session.state() == SessionState::Failed, "HostKicked terminates");

    // Fail-closed sweep: a batch of malformed frames, each of which must leave
    // the whole observable snapshot untouched.
    session.reset(8);
    (void)session.begin_join(golden::join_request(), 9);
    (void)session.receive(H(golden::room_information_hex), 10);
    (void)session.receive(H(golden::join_success_hex), 11);
    const std::vector<std::pair<std::string, std::optional<ErrorCode>>> malformed = {
        {"", ErrorCode::Truncated},
        {"00", ErrorCode::UnknownMessage},
        {"ff", ErrorCode::UnknownMessage},
        {"11", ErrorCode::UnsupportedMessage},
        {"17", ErrorCode::UnsupportedMessage},
        {"02", ErrorCode::Truncated},
        {"02 001f32112233 00", ErrorCode::TrailingBytes},
        {"0e 00 00000000 00000000", ErrorCode::InvalidEnum},
        {"05 06 00 001f32112233 001f32112233 00000000", ErrorCode::InvalidEnum},
        {"03", ErrorCode::Truncated},
        {"0e 06 00000004 4e69636b 00000004 6e69636b", ErrorCode::InvalidEnum},
    };
    for (const auto& entry : malformed) {
        rejects_without_mutation(session, [&] { (void)session.receive(H(entry.first), 20); },
                                 "malformed frame " + entry.first, entry.second);
    }
    // Channel other than 0 is refused.
    rejects_without_mutation(session,
                             [&] { (void)session.receive(H(golden::status_message_hex), 21, 1); },
                             "channel 1", ErrorCode::InvalidArgument);
    // A valid status frame still works after the sweep.
    (void)session.receive(H(golden::status_message_hex), 22);
    check(session.state() == SessionState::Joined, "session survived the malformed sweep");
}

// room.cpp:566-576: the server's nickname syntax, reproduced offline. This is a
// pure predicate; it must agree with begin_join's own gate.
void test_nickname_rule() {
    for (const std::string bad : {"", "abc", "abcde1234567890123456", "Nick!", "Ni ck\t"}) {
        check(!is_valid_nickname(bad), "nickname rejected: " + bad);
    }
    check(!is_valid_nickname(std::string(21, 'a')), "nickname of 21 chars rejected");
    check(is_valid_nickname(std::string(20, 'a')), "nickname of 20 chars accepted");
    check(!is_valid_nickname(std::string(3, 'a')), "nickname of 3 chars rejected");
    for (const std::string good : {"Nick", "abcd", "Ab_1-2 .", "Nico"}) {
        check(is_valid_nickname(good), "nickname accepted: " + good);
    }
    // The predicate and begin_join agree: an invalid nickname is InvalidArgument.
    Session session;
    rejects([&] {
        (void)session.begin_join(JoinRequest{"bad!", {}, no_preferred_mac, network_version, {}, {}}, 0);
    }, "begin_join invalid nickname", ErrorCode::InvalidArgument);
    check(session.state() == SessionState::Idle, "invalid nickname left the session Idle");
}

void test_state_names() {
    check(state_name(SessionState::Idle) == "Idle", "Idle name");
    check(state_name(SessionState::Joining) == "Joining", "Joining name");
    check(state_name(SessionState::Joined) == "Joined", "Joined name");
    check(state_name(SessionState::Leaving) == "Leaving", "Leaving name");
    check(state_name(SessionState::Failed) == "Failed", "Failed name");
}

} // namespace

int main() {
    const struct {
        const char* name;
        void (*fn)();
    } sections[] = {
        {"construction", test_construction},
        {"begin_join", test_begin_join},
        {"join_flow", test_join_flow},
        {"room_validation", test_room_validation},
        {"send_gates", test_send_gates},
        {"leave_and_disconnect", test_leave_and_disconnect},
        {"receive_timeouts", test_receive_timeouts},
        {"session_termination_and_failclosed", test_session_termination_and_failclosed},
        {"nickname_rule", test_nickname_rule},
        {"state_names", test_state_names},
    };
    try {
        std::cout << "section breakdown:\n";
        for (const auto& section : sections) {
            const std::size_t checks_before = g_checks;
            const std::size_t invariants_before = g_invariants;
            section.fn();
            std::cout << "  " << section.name << ": checks=" << (g_checks - checks_before)
                      << " state_invariants=" << (g_invariants - invariants_before) << "\n";
        }
    } catch (const std::exception& error) {
        std::cout << "session tests FAILED: " << error.what() << "\n";
        std::cout << "checks_before_failure=" << g_checks << "\n";
        return 1;
    }
    std::cout << "session tests passed"
              << " checks=" << g_checks
              << " state_invariants=" << g_invariants << "\n";
    return 0;
}
