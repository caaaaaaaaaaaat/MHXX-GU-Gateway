// SPDX-License-Identifier: GPL-2.0-or-later
// Offline synchronous session state machine for the Citra room client side.
// Mirrors the conventions of the M1 core at crossplay/room-client (which is
// read-only for this project).
//
// OFFLINE ONLY: no timers, no threads, no sockets. The caller supplies a
// non-decreasing monotonic millisecond clock.
#ifndef CITRA_ROOM_SESSION_HPP
#define CITRA_ROOM_SESSION_HPP

#include "citra_room/protocol.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace citra_room {

enum class SessionState { Idle, Joining, Joined, Leaving, Failed };

std::string state_name(SessionState state);

// room.cpp:566-576: IsValidNickname = "^[ a-zA-Z0-9._-]{4,20}$" and not already
// taken in the room. Uniqueness is a server-side property (room.cpp:585-591 is a
// different check), so only the syntax is reproducible offline.
bool is_valid_nickname(const std::string& nickname);

struct SessionOptions {
    Limits limits;
    std::uint64_t join_timeout_ms = 5000;
    std::uint64_t leave_timeout_ms = 5000;
};

class Session {
public:
    explicit Session(SessionOptions options = {});

    // Emits the IdJoinRequest bytes and enters Joining. Only legal from Idle;
    // after a failure an explicit reset() is required (no implicit retry).
    Bytes begin_join(const JoinRequest& request, std::uint64_t now_ms);

    // Decodes one server->client frame. Any malformed input throws and leaves
    // state, identity and room cache unchanged.
    Message receive(const Bytes& bytes, std::uint64_t now_ms, std::uint8_t channel = 0);

    // Encodes one client->server application frame. Only legal from Joined.
    Bytes send(const Message& message, std::uint64_t now_ms);

    void begin_leave(std::uint64_t now_ms);
    // Returns true only when this call performed a timeout transition.
    bool advance(std::uint64_t now_ms);
    void disconnected(std::uint64_t now_ms);
    void reset(std::uint64_t now_ms);

    SessionState state() const noexcept { return state_; }
    bool joined() const noexcept { return state_ == SessionState::Joined; }
    const std::optional<RoomInformation>& room() const noexcept { return room_; }
    const std::optional<MacAddress>& assigned_mac() const noexcept { return assigned_mac_; }
    const std::optional<MessageId>& last_server_error() const noexcept { return last_server_error_; }
    bool timed_out() const noexcept { return timed_out_; }
    const std::string& nickname() const noexcept { return nickname_; }

private:
    void validate_time(std::uint64_t now_ms) const;
    void clear_identity();
    void validate_room(const RoomInformation& room) const;

    SessionOptions options_;
    SessionState state_ = SessionState::Idle;
    std::string nickname_;
    std::optional<RoomInformation> room_;
    std::optional<MacAddress> assigned_mac_;
    std::optional<MessageId> last_server_error_;
    std::uint64_t started_ms_ = 0;
    std::uint64_t last_ms_ = 0;
    bool has_time_ = false;
    bool timed_out_ = false;
};

} // namespace citra_room

#endif // CITRA_ROOM_SESSION_HPP
