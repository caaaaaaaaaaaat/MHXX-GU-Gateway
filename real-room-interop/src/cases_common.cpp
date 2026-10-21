// SPDX-License-Identifier: GPL-2.0-or-later
#include "cases.hpp"

namespace rri {

CaseResult begin_case(const RunConfig& cfg, const ServerSpec& spec, const std::string& id) {
    CaseResult result;
    result.id = id;
    result.protocol = spec.protocol;
    result.server_tag = cfg.server_tag;
    return result;
}

void end_case(CaseResult& result, std::uint64_t t0_ms) { result.ms = now_ms() - t0_ms; }

room_client::Bytes v1_join_bytes(const std::string& nickname,
                                 const room_client::IPv4& preferred_ip,
                                 const std::string& password, std::uint32_t version) {
    room_client::JoinRequest request;
    request.nickname = nickname;
    request.preferred_ip = preferred_ip;
    request.version = version;
    request.password = password;
    request.token.clear();
    return room_client::encode(room_client::Message{request},
                               room_client::Direction::ClientToServer);
}

room_client::Bytes v1_expected_error(room_client::MessageId id, std::uint32_t server_version) {
    room_client::ServerError error;
    error.id = id;
    error.server_version = server_version;
    return room_client::encode(room_client::Message{error},
                               room_client::Direction::ServerToClient);
}

citra_room::Bytes v4_join_bytes(const std::string& nickname, const std::string& console_id_hash,
                                const citra_room::MacAddress& preferred_mac,
                                const std::string& password, std::uint32_t version) {
    citra_room::JoinRequest request;
    request.nickname = nickname;
    request.console_id_hash = console_id_hash;
    request.preferred_mac = preferred_mac;
    request.version = version;
    request.password = password;
    request.token.clear();
    return citra_room::encode(citra_room::Message{request},
                              citra_room::Direction::ClientToServer);
}

citra_room::Bytes v4_expected_error(citra_room::MessageId id, std::uint32_t server_version) {
    citra_room::ServerError error;
    error.id = id;
    error.server_version = server_version;
    return citra_room::encode(citra_room::Message{error},
                              citra_room::Direction::ServerToClient);
}

bool decode_v1_s2c(const Bytes& bytes, room_client::Message& out, std::string& error) {
    try {
        out = room_client::decode(bytes, room_client::Direction::ServerToClient);
        return true;
    } catch (const room_client::ProtocolError& e) {
        error = std::string("ProtocolError: ") + e.what();
        return false;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

bool decode_v4_s2c(const Bytes& bytes, citra_room::Message& out, std::string& error) {
    try {
        out = citra_room::decode(bytes, citra_room::Direction::ServerToClient);
        return true;
    } catch (const citra_room::ProtocolError& e) {
        error = std::string("ProtocolError: ") + e.what();
        return false;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

std::string v1_name(const room_client::Message& message) {
    try {
        return room_client::message_name(room_client::message_id(message));
    } catch (const std::exception&) {
        return "?";
    }
}

std::string v4_name(const citra_room::Message& message) {
    try {
        return citra_room::message_name(citra_room::message_id(message));
    } catch (const std::exception&) {
        return "?";
    }
}

bool frame_is_join_success(const Bytes& frame) {
    if (frame.empty()) return false;
    return frame[0] == 0x02 || frame[0] == 0x18;
}

std::vector<Bytes> wait_server_frames_until(
    RawClient& client, const std::function<bool(const std::vector<Bytes>&)>& predicate,
    std::uint64_t timeout_ms) {
    const std::uint64_t deadline = now_ms() + timeout_ms;
    for (;;) {
        client.service(20);
        auto frames = client.server_frames();
        if (predicate(frames)) return frames;
        if (now_ms() >= deadline) return frames;
    }
}

std::vector<Bytes> wait_server_frames(RawClient& client, std::size_t min_count,
                                      std::uint64_t timeout_ms) {
    return wait_server_frames_until(
        client, [min_count](const std::vector<Bytes>& f) { return f.size() >= min_count; },
        timeout_ms);
}

void expect_single_error_frame(CaseResult& result, RawClient& client, const Bytes& expected,
                               const std::string& label) {
    const auto frames = wait_server_frames(client, 1, 3000);
    result.check(label + "_server_frame_count",
                 frames.size() == 1,
                 "count=" + format_uint64(static_cast<std::uint64_t>(frames.size())));
    bool any_join = false;
    for (const auto& f : frames)
        if (frame_is_join_success(f)) any_join = true;
    result.check(label + "_no_join_success", !any_join);
    if (frames.empty()) {
        result.check(label + "_bytes_exact", false, "no server response");
        return;
    }
    result.check(label + "_bytes_exact", frames[0] == expected,
                 "actual=" + hex_spaced(frames[0]) + " expected=" + hex_spaced(expected));
}

void check_v1_server_error(CaseResult& result, const Bytes& frame, room_client::MessageId id,
                           std::uint32_t server_version, const std::string& label) {
    room_client::Message message;
    std::string error;
    if (!decode_v1_s2c(frame, message, error)) {
        result.check(label + "_decodes", false, error);
        return;
    }
    result.check(label + "_decodes", true);
    const auto* server_error = std::get_if<room_client::ServerError>(&message);
    if (server_error == nullptr) {
        result.check(label + "_is_server_error", false, "got " + v1_name(message));
        return;
    }
    result.check(label + "_is_server_error", true);
    result.check(label + "_id", server_error->id == id,
                 "got " + room_client::message_name(server_error->id));
    result.check(label + "_server_version", server_error->server_version == server_version,
                 "got " + format_uint64(server_error->server_version));
}

void check_v4_server_error(CaseResult& result, const Bytes& frame, citra_room::MessageId id,
                           std::uint32_t server_version, const std::string& label) {
    citra_room::Message message;
    std::string error;
    if (!decode_v4_s2c(frame, message, error)) {
        result.check(label + "_decodes", false, error);
        return;
    }
    result.check(label + "_decodes", true);
    const auto* server_error = std::get_if<citra_room::ServerError>(&message);
    if (server_error == nullptr) {
        result.check(label + "_is_server_error", false, "got " + v4_name(message));
        return;
    }
    result.check(label + "_is_server_error", true);
    result.check(label + "_id", server_error->id == id,
                 "got " + citra_room::message_name(server_error->id));
    result.check(label + "_server_version", server_error->server_version == server_version,
                 "got " + format_uint64(server_error->server_version));
}

int v1_find(const std::vector<Bytes>& frames, room_client::MessageId id) {
    for (std::size_t i = 0; i < frames.size(); ++i) {
        room_client::Message message;
        std::string error;
        if (!decode_v1_s2c(frames[i], message, error)) continue;
        if (room_client::message_id(message) == id) return static_cast<int>(i);
    }
    return -1;
}

int v4_find(const std::vector<Bytes>& frames, citra_room::MessageId id) {
    for (std::size_t i = 0; i < frames.size(); ++i) {
        citra_room::Message message;
        std::string error;
        if (!decode_v4_s2c(frames[i], message, error)) continue;
        if (citra_room::message_id(message) == id) return static_cast<int>(i);
    }
    return -1;
}

bool v1_room_info(const std::vector<Bytes>& frames, room_client::RoomInformation& out) {
    for (const auto& frame : frames) {
        room_client::Message message;
        std::string error;
        if (!decode_v1_s2c(frame, message, error)) continue;
        if (const auto* info = std::get_if<room_client::RoomInformation>(&message)) {
            out = *info;
            return true;
        }
    }
    return false;
}

bool v1_join_success(const std::vector<Bytes>& frames, room_client::JoinSuccess& out) {
    for (const auto& frame : frames) {
        room_client::Message message;
        std::string error;
        if (!decode_v1_s2c(frame, message, error)) continue;
        if (const auto* success = std::get_if<room_client::JoinSuccess>(&message)) {
            out = *success;
            return true;
        }
    }
    return false;
}

bool v4_room_info(const std::vector<Bytes>& frames, citra_room::RoomInformation& out) {
    for (const auto& frame : frames) {
        citra_room::Message message;
        std::string error;
        if (!decode_v4_s2c(frame, message, error)) continue;
        if (const auto* info = std::get_if<citra_room::RoomInformation>(&message)) {
            out = *info;
            return true;
        }
    }
    return false;
}

bool v4_join_success(const std::vector<Bytes>& frames, citra_room::JoinSuccess& out) {
    for (const auto& frame : frames) {
        citra_room::Message message;
        std::string error;
        if (!decode_v4_s2c(frame, message, error)) continue;
        if (const auto* success = std::get_if<citra_room::JoinSuccess>(&message)) {
            out = *success;
            return true;
        }
    }
    return false;
}

bool v1_member_named(const room_client::RoomInformation& info, const std::string& nickname) {
    for (const auto& member : info.members)
        if (member.nickname == nickname) return true;
    return false;
}

bool v4_member_named(const citra_room::RoomInformation& info, const std::string& nickname) {
    for (const auto& member : info.members)
        if (member.nickname == nickname) return true;
    return false;
}

bool v1_join_and_wait(RawClient& client, const std::string& nickname, const std::string& password,
                      std::uint16_t port, CaseResult& result, const std::string& role,
                      room_client::IPv4& out_ip) {
    std::string error;
    if (!client.connect("127.0.0.1", port, 1500, error)) {
        result.check("connect_" + role, false, error);
        return false;
    }
    result.check("connect_" + role, true);
    client.send(v1_join_bytes(nickname, room_client::no_preferred_ip, password,
                              room_client::network_version));
    const auto frames = wait_server_frames_until(
        client, [](const std::vector<Bytes>& f) { return v1_find(f, room_client::MessageId::JoinSuccess) >= 0; },
        3000);
    room_client::JoinSuccess success;
    if (!v1_join_success(frames, success)) {
        result.check("join_success_" + role, false,
                     "nickname=" + nickname + " frames=" + format_uint64(static_cast<std::uint64_t>(frames.size())));
        return false;
    }
    result.check("join_success_" + role, true);
    out_ip = success.assigned_ip;
    return true;
}

bool v4_join_and_wait(RawClient& client, const std::string& nickname, const std::string& console_id,
                      const std::string& password, std::uint16_t port, CaseResult& result,
                      const std::string& role, citra_room::MacAddress& out_mac) {
    std::string error;
    if (!client.connect("127.0.0.1", port, 1500, error)) {
        result.check("connect_" + role, false, error);
        return false;
    }
    result.check("connect_" + role, true);
    client.send(v4_join_bytes(nickname, console_id, citra_room::no_preferred_mac, password,
                              citra_room::network_version));
    const auto frames = wait_server_frames_until(
        client, [](const std::vector<Bytes>& f) { return v4_find(f, citra_room::MessageId::JoinSuccess) >= 0; },
        3000);
    citra_room::JoinSuccess success;
    if (!v4_join_success(frames, success)) {
        result.check("join_success_" + role, false,
                     "nickname=" + nickname + " frames=" + format_uint64(static_cast<std::uint64_t>(frames.size())));
        return false;
    }
    result.check("join_success_" + role, true);
    out_mac = success.assigned_mac;
    return true;
}

} // namespace rri
