// SPDX-License-Identifier: GPL-2.0-or-later
// Offline synchronous session state machine for the Yuzu room client side.
#include "yuzu_room/session.hpp"

#include <algorithm>
#include <utility>

namespace yuzu_room {
namespace {

[[noreturn]] void invalid_state(const std::string& message) {
    throw ProtocolError(ErrorCode::InvalidState, 0, message);
}

// room.cpp:550-560  IsValidNickname uses the regex "^[ a-zA-Z0-9._-]{4,20}$".
bool valid_nickname(const std::string& n) {
    if (n.size() < 4 || n.size() > 20) return false;
    for (const char c : n) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == ' ' || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

// room.cpp:321-345 and error_order evidence: rejections that can only answer a
// pending IdJoinRequest. Yuzu v1 has no IdConsoleIdCollision.
bool is_join_rejection(MessageId id) {
    switch (id) {
    case MessageId::NameCollision:
    case MessageId::IpCollision:
    case MessageId::VersionMismatch:
    case MessageId::WrongPassword:
    case MessageId::RoomIsFull: return true;
    default: return false;
    }
}

// room_member.cpp:164-273: room teardown that may arrive before or after Join.
bool is_session_termination(MessageId id) {
    return id == MessageId::CloseRoom || id == MessageId::HostKicked || id == MessageId::HostBanned;
}

bool same_ip(const IPv4Address& a, const IPv4Address& b) { return a == b; }

} // namespace

bool is_valid_nickname(const std::string& nickname) { return valid_nickname(nickname); }

Session::Session(SessionOptions options) : options_(options) {
    (void)parse_hex("", options_.limits); // Validate configurable hard limits.
    if (!options_.join_timeout_ms || options_.join_timeout_ms > 60000 ||
        !options_.leave_timeout_ms || options_.leave_timeout_ms > 60000)
        throw ProtocolError(ErrorCode::InvalidArgument, 0, "timeout must be 1..60000 milliseconds");
}

void Session::validate_time(std::uint64_t now_ms) const {
    if (has_time_ && now_ms < last_ms_)
        throw ProtocolError(ErrorCode::InvalidArgument, 0, "monotonic time moved backwards");
}

void Session::clear_identity() {
    room_.reset();
    assigned_fake_ip_.reset();
    nickname_.clear();
    moderator_ = false;
}

void Session::validate_room(const RoomInformation& room) const {
    bool nickname_present = false;
    const Member* self = nullptr;
    for (std::size_t i = 0; i < room.members.size(); ++i) {
        const auto& member = room.members[i];
        for (std::size_t j = 0; j < i; ++j)
            if (member.nickname == room.members[j].nickname || same_ip(member.fake_ip, room.members[j].fake_ip))
                invalid_state("duplicate room member identity");
        if (member.nickname == nickname_) nickname_present = true;
        if (assigned_fake_ip_ && same_ip(member.fake_ip, *assigned_fake_ip_)) self = &member;
    }
    if (!nickname_present) invalid_state("room information does not contain the joining nickname");
    if (assigned_fake_ip_ && !self) invalid_state("room information does not contain the assigned fake IP");
}

Bytes Session::begin_join(const JoinRequest& request, std::uint64_t now_ms) {
    validate_time(now_ms);
    if (state_ != SessionState::Idle) invalid_state("join only allowed from Idle; explicit reset required after failure");
    if (request.version != network_version || !valid_nickname(request.nickname))
        throw ProtocolError(ErrorCode::InvalidArgument, 0,
                            "join requires network_version 1 and a source-valid ASCII nickname (4..20 bytes)");
    auto bytes = encode(request, Direction::ClientToServer, options_.limits);
    auto nickname = request.nickname; // Complete allocations before mutating state.
    clear_identity();
    nickname_ = std::move(nickname);
    last_server_error_.reset();
    timed_out_ = false;
    state_ = SessionState::Joining;
    started_ms_ = last_ms_ = now_ms;
    has_time_ = true;
    return bytes;
}

bool Session::advance(std::uint64_t now_ms) {
    validate_time(now_ms);
    last_ms_ = now_ms;
    has_time_ = true;
    if (state_ == SessionState::Joining && now_ms - started_ms_ >= options_.join_timeout_ms) {
        clear_identity();
        state_ = SessionState::Failed;
        timed_out_ = true;
        return true;
    }
    if (state_ == SessionState::Leaving && now_ms - started_ms_ >= options_.leave_timeout_ms) {
        clear_identity();
        state_ = SessionState::Idle;
        timed_out_ = true;
        return true;
    }
    return false;
}

Message Session::receive(const Bytes& bytes, std::uint64_t now_ms, std::uint8_t channel) {
    validate_time(now_ms);
    if (channel != 0) throw ProtocolError(ErrorCode::InvalidArgument, 0, "only ENet channel 0 is audited");
    if (advance(now_ms)) throw ProtocolError(ErrorCode::Timeout, 0, "session deadline expired");
    if (state_ != SessionState::Joining && !joined()) invalid_state("receive requires Joining/Joined");
    auto message = decode(bytes, Direction::ServerToClient, options_.limits);
    if (const auto* info = std::get_if<RoomInformation>(&message)) {
        validate_room(*info);
        auto retained = *info;
        room_ = std::move(retained);
    } else if (const auto* success = std::get_if<JoinSuccess>(&message)) {
        if (state_ != SessionState::Joining || !room_ || assigned_fake_ip_)
            invalid_state("success requires Joining after RoomInformation (no duplicate success)");
        const bool present = std::any_of(room_->members.begin(), room_->members.end(),
                                         [&](const Member& m) { return same_ip(m.fake_ip, success->assigned_fake_ip); });
        if (!present) invalid_state("assigned fake IP is not present in the cached room information");
        assigned_fake_ip_ = success->assigned_fake_ip;
        moderator_ = success->moderator;
        state_ = SessionState::Joined;
    } else if (const auto* error = std::get_if<ServerError>(&message)) {
        if (is_join_rejection(error->id)) {
            if (state_ != SessionState::Joining) invalid_state("join rejection outside Joining");
        } else if (is_session_termination(error->id)) {
            if (state_ != SessionState::Joining && !joined()) invalid_state("session termination outside membership");
        } else {
            invalid_state("unsupported server error");
        }
        last_server_error_ = error->id;
        clear_identity();
        state_ = SessionState::Failed;
    } else if (!std::holds_alternative<StatusMessage>(message) && !joined()) {
        invalid_state("application data received before membership");
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
    const auto known_member = [&](const IPv4Address& ip) {
        if (!room_) return false;
        return std::any_of(room_->members.begin(), room_->members.end(),
                           [&](const Member& m) { return same_ip(m.fake_ip, ip); });
    };
    // Client-side identity gate. The room does not validate the sender
    // (room.cpp:815-925, VERIFIED FACT V-016 in the evidence), so this codec
    // refuses to emit a data-plane frame that claims a foreign source.
    if (const auto* proxy = std::get_if<ProxyPacket>(&message)) {
        if (!assigned_fake_ip_ || !same_ip(proxy->local_endpoint.ip, *assigned_fake_ip_))
            invalid_state("ProxyPacket local endpoint must equal the assigned fake IP");
        if (!proxy->broadcast && !known_member(proxy->remote_endpoint.ip))
            invalid_state("ProxyPacket remote endpoint must be a registered member when not broadcast");
    }
    if (const auto* ldn = std::get_if<LdnPacket>(&message)) {
        if (!assigned_fake_ip_ || !same_ip(ldn->local_ip, *assigned_fake_ip_))
            invalid_state("LdnPacket local IP must equal the assigned fake IP");
        if (!ldn->broadcast && !known_member(ldn->remote_ip))
            invalid_state("LdnPacket remote IP must be a registered member when not broadcast");
    }
    return encode(message, Direction::ClientToServer, options_.limits);
}

void Session::begin_leave(std::uint64_t now_ms) {
    validate_time(now_ms);
    if (advance(now_ms)) throw ProtocolError(ErrorCode::Timeout, 0, "session deadline expired");
    if (!joined()) invalid_state("leave requires the session to be Joined");
    clear_identity();
    state_ = SessionState::Leaving;
    started_ms_ = now_ms;
}

void Session::disconnected(std::uint64_t now_ms) {
    validate_time(now_ms);
    clear_identity();
    last_ms_ = now_ms;
    has_time_ = true;
    state_ = SessionState::Idle;
    last_server_error_.reset();
    timed_out_ = false;
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
    case SessionState::Leaving: return "Leaving";
    case SessionState::Failed: return "Failed";
    }
    return "Unknown";
}

} // namespace yuzu_room
