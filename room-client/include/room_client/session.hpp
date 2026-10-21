// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "room_client/protocol.hpp"
#include <optional>

namespace room_client {
enum class SessionState { Idle, Joining, Joined, Moderator, Leaving, Failed };
struct SessionOptions {
    Limits limits;
    std::uint64_t join_timeout_ms = 5000;
    std::uint64_t leave_timeout_ms = 5000;
};
// Synchronous offline state machine. No socket, thread, retry, or packet queue.
// Caller serializes access and provides nondecreasing monotonic milliseconds.
class Session final {
public:
    explicit Session(SessionOptions options = {});
    Bytes begin_join(const JoinRequest& request, std::uint64_t now_ms);
    Message receive(const Bytes& bytes, std::uint64_t now_ms, std::uint8_t channel = enet_channel);
    Bytes send(const Message& message, std::uint64_t now_ms);
    void begin_leave(std::uint64_t now_ms); // M2 must map to actual ENet disconnect.
    bool advance(std::uint64_t now_ms); // True only when a timeout changes state.
    void disconnected(std::uint64_t now_ms);
    void reset(std::uint64_t now_ms);
    SessionState state() const noexcept { return state_; }
    const std::optional<RoomInformation>& room() const noexcept { return room_; }
    const std::optional<IPv4>& assigned_ip() const noexcept { return assigned_ip_; }
    const std::optional<MessageId>& last_server_error() const noexcept { return last_server_error_; }
    bool timed_out() const noexcept { return timed_out_; }
private:
    bool joined() const noexcept;
    void validate_time(std::uint64_t now_ms) const;
    void clear_identity();
    void validate_room(const RoomInformation& room, const std::optional<IPv4>& assigned) const;
    SessionOptions options_;
    SessionState state_ = SessionState::Idle;
    std::optional<RoomInformation> room_;
    std::optional<IPv4> assigned_ip_;
    std::optional<MessageId> last_server_error_;
    std::string nickname_;
    std::uint64_t started_ms_ = 0, last_ms_ = 0;
    bool has_time_ = false, timed_out_ = false;
};
std::string state_name(SessionState state);
} // namespace room_client
