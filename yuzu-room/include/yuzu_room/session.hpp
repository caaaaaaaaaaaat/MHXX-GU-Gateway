// SPDX-License-Identifier: GPL-2.0-or-later
// Offline synchronous state machine for the Yuzu room client side
// (RoomMember::State, room_member.h:69-75).
#pragma once

#include "yuzu_room/protocol.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu_room {

enum class SessionState { Idle, Joining, Joined, Leaving, Failed };
std::string state_name(SessionState state);

// room.cpp:550-560  bool Room::RoomImpl::IsValidNickname(std::string_view name)
// requires the regex "^[ a-zA-Z0-9._-]{4,20}$" and that the name is not taken.
bool is_valid_nickname(const std::string& nickname);

struct SessionOptions {
    Limits limits;
    // room_member.cpp:17  "constexpr u32 ConnectionTimeoutMs = 5000;"
    std::uint64_t join_timeout_ms = 5000;
    // The v1 client disconnects immediately on leave (no leave frame exists);
    // this mirrors the local cleanup deadline only.
    std::uint64_t leave_timeout_ms = 5000;
};

class Session {
public:
    explicit Session(SessionOptions options = {});

    Bytes begin_join(const JoinRequest& request, std::uint64_t now_ms);
    Message receive(const Bytes& bytes, std::uint64_t now_ms, std::uint8_t channel = 0);
    Bytes send(const Message& message, std::uint64_t now_ms);
    void begin_leave(std::uint64_t now_ms);
    bool advance(std::uint64_t now_ms);
    void disconnected(std::uint64_t now_ms);
    void reset(std::uint64_t now_ms);

    SessionState state() const noexcept { return state_; }
    bool joined() const noexcept { return state_ == SessionState::Joined; }
    const std::optional<RoomInformation>& room() const noexcept { return room_; }
    const std::optional<IPv4Address>& assigned_fake_ip() const noexcept { return assigned_fake_ip_; }
    const std::optional<MessageId>& last_server_error() const noexcept { return last_server_error_; }
    bool timed_out() const noexcept { return timed_out_; }
    bool moderator() const noexcept { return moderator_; }
    const std::string& nickname() const noexcept { return nickname_; }

private:
    void validate_time(std::uint64_t now_ms) const;
    void clear_identity();
    void validate_room(const RoomInformation& room) const;

    SessionOptions options_;
    SessionState state_ = SessionState::Idle;
    std::string nickname_;
    std::optional<RoomInformation> room_;
    std::optional<IPv4Address> assigned_fake_ip_;
    std::optional<MessageId> last_server_error_;
    std::uint64_t started_ms_ = 0;
    std::uint64_t last_ms_ = 0;
    bool has_time_ = false;
    bool timed_out_ = false;
    bool moderator_ = false;
};

} // namespace yuzu_room
