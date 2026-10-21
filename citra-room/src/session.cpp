// SPDX-License-Identifier: GPL-2.0-or-later
// Offline synchronous session state machine for the Citra room client side.
#include "citra_room/session.hpp"

#include <algorithm>
#include <utility>

namespace citra_room {
namespace {

[[noreturn]] void invalid_state(const std::string& message) {
    throw ProtocolError(ErrorCode::InvalidState, 0, message);
}

// room.cpp:566-576  IsValidNickname uses the regex "^[ a-zA-Z0-9._-]{4,20}$".
bool valid_nickname(const std::string& n) {
    if (n.size() < 4 || n.size() > 20) return false;
    for (const char c : n) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == ' ' || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

// room_member.cpp:158-237 / room.cpp:614-672: rejections that can only answer a
// pending IdJoinRequest.
bool is_join_rejection(MessageId id) {
    switch (id) {
    case MessageId::NameCollision:
    case MessageId::MacCollision:
    case MessageId::VersionMismatch:
    case MessageId::WrongPassword:
    case MessageId::RoomIsFull:
    case MessageId::ConsoleIdCollision: return true;
    default: return false;
    }
}

// room_member.cpp:158-237: room teardown that may arrive before or after Join.
bool is_session_termination(MessageId id) {
    return id == MessageId::CloseRoom || id == MessageId::HostKicked || id == MessageId::HostBanned;
}

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
    assigned_mac_.reset();
    nickname_.clear();
}

void Session::validate_room(const RoomInformation& room) const {
    bool nickname_present = false;
    const Member* self = nullptr;
    for (std::size_t i = 0; i < room.members.size(); ++i) {
        const auto& member = room.members[i];
        for (std::size_t j = 0; j < i; ++j)
            if (member.nickname == room.members[j].nickname || member.mac == room.members[j].mac)
                invalid_state("duplicate room member identity");
        if (member.nickname == nickname_) nickname_present = true;
        if (assigned_mac_ && member.mac == *assigned_mac_) self = &member;
    }
    if (!nickname_present) invalid_state("room information does not contain the joining nickname");
    if (assigned_mac_ && !self) invalid_state("room information does not contain the assigned MAC");
}

Bytes Session::begin_join(const JoinRequest& request, std::uint64_t now_ms) {
    validate_time(now_ms);
    if (state_ != SessionState::Idle) invalid_state("join only allowed from Idle; explicit reset required after failure");
    if (request.version != network_version || !valid_nickname(request.nickname))
        throw ProtocolError(ErrorCode::InvalidArgument, 0,
                            "join requires network_version 4 and a source-valid ASCII nickname (4..20 bytes)");
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
        if (state_ != SessionState::Joining || !room_ || assigned_mac_)
            invalid_state("success requires Joining after RoomInformation (no duplicate success)");
        const bool present = std::any_of(room_->members.begin(), room_->members.end(),
                                         [&](const Member& m) { return m.mac == success->assigned_mac; });
        if (!present) invalid_state("assigned MAC is not present in the cached room information");
        assigned_mac_ = success->assigned_mac;
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
    if (!std::holds_alternative<GameInfo>(message) && !std::holds_alternative<WifiPacket>(message) &&
        !std::holds_alternative<ChatRequest>(message))
        invalid_state("message not supported for application send");
    if (const auto* wifi = std::get_if<WifiPacket>(&message)) {
        if (!assigned_mac_ || wifi->transmitter != *assigned_mac_)
            invalid_state("WifiPacket transmitter must equal the assigned local MAC");
        bool to_member = false;
        if (room_)
            for (const auto& member : room_->members)
                if (member.mac == wifi->destination) to_member = true;
        if (wifi->destination != broadcast_mac && !to_member)
            invalid_state("WifiPacket destination must be the broadcast MAC or a registered member");
    }
    return encode(message, Direction::ClientToServer, options_.limits);
}

void Session::begin_leave(std::uint64_t now_ms) {
    validate_time(now_ms);
    if (advance(now_ms)) throw ProtocolError(ErrorCode::Timeout, 0, "session deadline expired");
    if (state_ != SessionState::Joining && !joined()) invalid_state("leave requires active membership or Joining");
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

} // namespace citra_room
