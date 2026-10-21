// SPDX-License-Identifier: GPL-2.0-or-later
#include "room_client/session.hpp"
#include <utility>

namespace room_client {
namespace {
[[noreturn]] void invalid_state(const std::string& message) {
    throw ProtocolError(ErrorCode::InvalidState, 0, message);
}
bool valid_nickname(const std::string& n) {
    if (n.size() < 4 || n.size() > 20) return false;
    for (const char c : n) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == ' ' || c == '.' || c == '_' || c == '-')) return false;
    }
    return true;
}
}
Session::Session(SessionOptions options) : options_(options) {
    (void)parse_hex("", options_.limits); // Validate configurable hard limits.
    if (!options_.join_timeout_ms || options_.join_timeout_ms > 60000 ||
        !options_.leave_timeout_ms || options_.leave_timeout_ms > 60000)
        throw ProtocolError(ErrorCode::InvalidArgument, 0, "timeout must be 1..60000 milliseconds");
}
bool Session::joined() const noexcept {
    return state_ == SessionState::Joined || state_ == SessionState::Moderator;
}
void Session::validate_time(std::uint64_t now_ms) const {
    if (has_time_ && now_ms < last_ms_)
        throw ProtocolError(ErrorCode::InvalidArgument, 0, "monotonic time moved backwards");
}
void Session::clear_identity() {
    room_.reset(); assigned_ip_.reset(); nickname_.clear();
}
void Session::validate_room(const RoomInformation& room, const std::optional<IPv4>& assigned) const {
    const Member* self = nullptr;
    for (std::size_t i = 0; i < room.members.size(); ++i) {
        const auto& member = room.members[i];
        for (std::size_t j = 0; j < i; ++j)
            if (member.nickname == room.members[j].nickname || member.fake_ip == room.members[j].fake_ip)
                invalid_state("duplicate room member identity");
        if (member.nickname == nickname_) self = &member;
    }
    if (assigned && (!self || self->fake_ip != *assigned))
        invalid_state("room information does not contain the assigned local identity");
}
Bytes Session::begin_join(const JoinRequest& request, std::uint64_t now_ms) {
    validate_time(now_ms);
    if (state_ != SessionState::Idle) invalid_state("join only allowed from Idle; explicit reset required after failure");
    if (request.version != network_version || !valid_nickname(request.nickname))
        throw ProtocolError(ErrorCode::InvalidArgument, 0, "join requires version 1 and source-valid ASCII nickname (4..20 bytes)");
    auto bytes = encode(request, Direction::ClientToServer, options_.limits);
    auto nickname = request.nickname; // Complete allocations before mutating state.
    clear_identity(); nickname_ = std::move(nickname); last_server_error_.reset(); timed_out_ = false;
    state_ = SessionState::Joining; started_ms_ = last_ms_ = now_ms; has_time_ = true;
    return bytes;
}
bool Session::advance(std::uint64_t now_ms) {
    validate_time(now_ms); last_ms_ = now_ms; has_time_ = true;
    if (state_ == SessionState::Joining && now_ms - started_ms_ >= options_.join_timeout_ms) {
        clear_identity(); state_ = SessionState::Failed; timed_out_ = true; return true;
    }
    if (state_ == SessionState::Leaving && now_ms - started_ms_ >= options_.leave_timeout_ms) {
        clear_identity(); state_ = SessionState::Idle; timed_out_ = true; return true;
    }
    return false;
}
Message Session::receive(const Bytes& bytes, std::uint64_t now_ms, std::uint8_t channel) {
    validate_time(now_ms);
    if (channel != enet_channel) throw ProtocolError(ErrorCode::InvalidArgument, 0, "only ENet channel 0 is audited");
    if (advance(now_ms)) throw ProtocolError(ErrorCode::Timeout, 0, "session deadline expired");
    if (state_ != SessionState::Joining && !joined()) invalid_state("receive requires Joining/Joined/Moderator");
    auto message = decode(bytes, Direction::ServerToClient, options_.limits);
    if (const auto* info = std::get_if<RoomInformation>(&message)) {
        validate_room(*info, assigned_ip_);
        auto retained = *info; room_ = std::move(retained);
    } else if (const auto* success = std::get_if<JoinSuccess>(&message)) {
        if (state_ != SessionState::Joining || !room_) invalid_state("success requires Joining after RoomInformation (no duplicate success)");
        validate_room(*room_, success->assigned_ip);
        assigned_ip_ = success->assigned_ip;
        state_ = success->moderator ? SessionState::Moderator : SessionState::Joined;
    } else if (const auto* error = std::get_if<ServerError>(&message)) {
        if (error->id == MessageId::PermissionDenied || error->id == MessageId::NoSuchUser) {
            if (!joined()) invalid_state("moderation error requires membership");
            last_server_error_ = error->id;
        } else {
            const bool join_rejection = error->id == MessageId::NameCollision || error->id == MessageId::IpCollision ||
                error->id == MessageId::VersionMismatch || error->id == MessageId::WrongPassword || error->id == MessageId::RoomFull;
            if (join_rejection && state_ != SessionState::Joining) invalid_state("join rejection outside Joining");
            last_server_error_ = error->id; clear_identity(); state_ = SessionState::Failed;
        }
    } else if (!std::holds_alternative<StatusMessage>(message) && !joined()) {
        invalid_state("non-status data received before membership");
    }
    return message;
}
Bytes Session::send(const Message& message, std::uint64_t now_ms) {
    validate_time(now_ms);
    if (advance(now_ms)) throw ProtocolError(ErrorCode::Timeout, 0, "session deadline expired");
    if (!joined()) invalid_state("application send requires membership");
    if (!std::holds_alternative<GameInfo>(message) && !std::holds_alternative<ProxyPacket>(message) &&
        !std::holds_alternative<LdnPacket>(message) && !std::holds_alternative<ChatRequest>(message))
        invalid_state("message not supported for application send");
    if (const auto* ldn = std::get_if<LdnPacket>(&message); ldn && ldn->local_ip != *assigned_ip_)
        invalid_state("LDN sender IP must equal assigned local identity");
    if (const auto* proxy = std::get_if<ProxyPacket>(&message); proxy && proxy->local.ip != *assigned_ip_)
        invalid_state("Proxy sender IP must equal assigned local identity");
    return encode(message, Direction::ClientToServer, options_.limits);
}
void Session::begin_leave(std::uint64_t now_ms) {
    validate_time(now_ms);
    if (advance(now_ms)) throw ProtocolError(ErrorCode::Timeout, 0, "session deadline expired");
    if (state_ != SessionState::Joining && !joined()) invalid_state("leave requires active membership or Joining");
    clear_identity(); state_ = SessionState::Leaving; started_ms_ = now_ms;
}
void Session::disconnected(std::uint64_t now_ms) {
    validate_time(now_ms); clear_identity(); last_ms_ = now_ms; has_time_ = true;
    state_ = SessionState::Idle; last_server_error_.reset(); timed_out_ = false;
}
void Session::reset(std::uint64_t now_ms) {
    validate_time(now_ms);
    if (state_ != SessionState::Idle && state_ != SessionState::Failed) invalid_state("reset requires Idle or Failed");
    disconnected(now_ms);
}
std::string state_name(SessionState state) {
    switch (state) {
    case SessionState::Idle: return "Idle";
    case SessionState::Joining: return "Joining";
    case SessionState::Joined: return "Joined";
    case SessionState::Moderator: return "Moderator";
    case SessionState::Leaving: return "Leaving";
    case SessionState::Failed: return "Failed";
    }
    return "Unknown";
}
} // namespace room_client
