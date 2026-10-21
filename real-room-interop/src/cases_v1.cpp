// SPDX-License-Identifier: GPL-2.0-or-later
// v1 (yuzu / 01052024-yuzu-mirror-master) room-interop cases.
#include "cases.hpp"

#include <room_transport/transport.hpp>

#include <algorithm>
#include <initializer_list>

namespace rri {
namespace {

Bytes make_payload(std::size_t size, unsigned char seed) {
    Bytes out(size);
    for (std::size_t i = 0; i < size; ++i)
        out[i] = static_cast<unsigned char>((seed + i * 7 + 3) & 0xFF);
    return out;
}

std::vector<Bytes> tail_from(const std::vector<Bytes>& all, std::size_t base) {
    if (base >= all.size()) return {};
    return std::vector<Bytes>(all.begin() + static_cast<std::ptrdiff_t>(base), all.end());
}

void drain(std::initializer_list<RawClient*> clients, int rounds, std::uint32_t wait_ms) {
    for (int i = 0; i < rounds; ++i)
        for (RawClient* client : clients) client->service(wait_ms);
}

std::string count_str(std::size_t n) {
    return format_uint64(static_cast<std::uint64_t>(n));
}

Bytes proxy_bytes(const room_client::IPv4& local_ip, std::uint16_t local_port,
                  const room_client::IPv4& remote_ip, std::uint16_t remote_port, bool broadcast,
                  const Bytes& data) {
    room_client::ProxyPacket packet;
    packet.local.family = room_client::Domain::Inet;
    packet.local.ip = local_ip;
    packet.local.port = local_port;
    packet.remote.family = room_client::Domain::Inet;
    packet.remote.ip = remote_ip;
    packet.remote.port = remote_port;
    packet.protocol = room_client::SocketProtocol::Udp;
    packet.broadcast = broadcast;
    packet.data = data;
    return room_client::encode(room_client::Message{packet},
                               room_client::Direction::ClientToServer);
}

// The frozen codec caps chat at Limits::chat_bytes (500 == room.h MaxMessageSize), so an
// over-long chat frame is built by hand: the room's truncation is what is under test here.
Bytes v1_chat_frame(std::size_t length) {
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(room_client::MessageId::Chat));
    const std::uint32_t n = static_cast<std::uint32_t>(length);
    out.push_back(static_cast<std::uint8_t>((n >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((n >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((n >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(n & 0xFF));
    out.insert(out.end(), length, static_cast<std::uint8_t>('x'));
    return out;
}

Bytes ldn_bytes(const room_client::IPv4& local_ip, const room_client::IPv4& remote_ip,
                bool broadcast, const Bytes& data) {
    room_client::LdnPacket packet;
    packet.type = room_client::LdnType::Scan;
    packet.local_ip = local_ip;
    packet.remote_ip = remote_ip;
    packet.broadcast = broadcast;
    packet.data = data;
    return room_client::encode(room_client::Message{packet},
                               room_client::Direction::ClientToServer);
}

} // namespace

CaseResult case_join(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "join");
    RawClient a;
    room_client::IPv4 ip_a{};
    if (!v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a)) {
        result.capture("A", a);
        end_case(result, t0);
        return result;
    }
    const auto frames = wait_server_frames(a, 3, 1500);
    room_client::RoomInformation info;
    const bool have_info = v1_room_info(frames, info);
    const int info_at = v1_find(frames, room_client::MessageId::RoomInformation);
    const int success_at = v1_find(frames, room_client::MessageId::JoinSuccess);
    result.check("room_information_received", have_info);
    result.check("room_information_before_join_success", info_at >= 0 && success_at > info_at,
                 "room_information_at=" + format_uint64(static_cast<std::uint64_t>(info_at)) +
                     " join_success_at=" + format_uint64(static_cast<std::uint64_t>(success_at)));
    if (have_info) {
        if (spec.check_room_name)
            result.check("room_name", info.name == spec.room_name, "got=" + info.name);
        else
            result.note("room_name check skipped (attach mode without -RoomName; got=" + info.name +
                        ")");
        if (spec.check_capacity)
            result.check("member_slots",
                         info.member_slots == static_cast<std::uint32_t>(spec.capacity),
                         "got=" + format_uint64(info.member_slots));
        else
            result.note("member_slots check skipped (attach mode without -Slots; got=" +
                        format_uint64(info.member_slots) + ")");
        result.check("room_port", info.port == spec.port, "got=" + format_uint64(info.port));
        result.check("member_list_contains_a", v1_member_named(info, "rri-a1"));
    }
    result.check("assigned_fake_ip_not_no_preferred_ip",
                 ip_a != room_client::no_preferred_ip, "ip=" + hex_spaced(Bytes(ip_a.begin(), ip_a.end())));
    result.note("assigned_fake_ip=" + hex_spaced(Bytes(ip_a.begin(), ip_a.end())));
    result.capture("A", a);

    // A second joiner must see the first member: that is the room's own continuation
    // behaviour and does not depend on how the server routes its log output.
    RawClient b;
    room_client::IPv4 ip_b{};
    if (v1_join_and_wait(b, "rri-b1", spec.password, spec.port, result, "b", ip_b)) {
        // v1_join_and_wait already waited for JoinSuccess, and the room broadcasts
        // RoomInformation before JoinSuccess, so b.server_frames() already holds it.
        room_client::RoomInformation info_b;
        const bool have_info_b = v1_room_info(b.server_frames(), info_b);
        result.check("second_joiner_room_information", have_info_b);
        if (have_info_b) {
            result.check("second_joiner_sees_first_member", v1_member_named(info_b, "rri-a1"),
                         "members=" + count_str(info_b.members.size()));
            result.check("second_joiner_list_includes_self", v1_member_named(info_b, "rri-b1"));
        }
        // The first joiner only receives Status(MemberJoin) once somebody else joins.
        const auto a_status_frames = wait_server_frames_until(
            a,
            [](const std::vector<Bytes>& f) {
                return v1_find(f, room_client::MessageId::Status) >= 0;
            },
            2000);
        const int status_at = v1_find(a_status_frames, room_client::MessageId::Status);
        bool status_for_b = false;
        std::string status_nickname;
        if (status_at >= 0) {
            room_client::Message message;
            std::string decode_error;
            if (decode_v1_s2c(a_status_frames[static_cast<std::size_t>(status_at)], message,
                              decode_error)) {
                if (const auto* status = std::get_if<room_client::StatusMessage>(&message)) {
                    status_nickname = status->nickname;
                    status_for_b = status->nickname == "rri-b1";
                }
            }
        }
        result.check("status_member_join_seen", status_for_b,
                     "status_nickname=" +
                         (status_nickname.empty() ? std::string("<none>") : status_nickname));
        result.capture("B", b);
        b.disconnect(400);
    }
    a.disconnect(400);
    drain({&a, &b}, 4, 10);
    result.note("release_ms=" + format_uint64(result.ms));
    end_case(result, t0);
    return result;
}

CaseResult case_version_mismatch(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "version_mismatch");
    RawClient a;
    std::string error;
    result.check("connect", a.connect("127.0.0.1", spec.port, 1500, error), error);
    a.send(v1_join_bytes("rri-a1", room_client::no_preferred_ip, spec.password, 2));
    expect_single_error_frame(result, a, v1_expected_error(room_client::MessageId::VersionMismatch, 1),
                              "version_mismatch");
    const auto frames = a.server_frames();
    if (!frames.empty())
        check_v1_server_error(result, frames[0], room_client::MessageId::VersionMismatch, 1,
                              "version_mismatch_observed");
    result.capture("A", a);
    a.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_wrong_password(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "wrong_password");
    RawClient a;
    std::string error;
    result.check("connect", a.connect("127.0.0.1", spec.port, 1500, error), error);
    a.send(v1_join_bytes("rri-a1", room_client::no_preferred_ip, "not-the-password",
                         room_client::network_version));
    expect_single_error_frame(result, a, v1_expected_error(room_client::MessageId::WrongPassword),
                              "wrong_password");
    const auto frames = a.server_frames();
    if (!frames.empty())
        check_v1_server_error(result, frames[0], room_client::MessageId::WrongPassword, 0,
                              "wrong_password_observed");
    result.capture("A", a);
    a.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_name_collision(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "name_collision");
    RawClient a;
    room_client::IPv4 ip_a{};
    if (!v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a)) {
        result.capture("A", a);
        end_case(result, t0);
        return result;
    }
    RawClient b;
    std::string error;
    result.check("connect_b", b.connect("127.0.0.1", spec.port, 1500, error), error);
    b.send(v1_join_bytes("rri-a1", room_client::no_preferred_ip, spec.password,
                         room_client::network_version));
    expect_single_error_frame(result, b, v1_expected_error(room_client::MessageId::NameCollision),
                              "name_collision");
    const auto frames = b.server_frames();
    if (!frames.empty())
        check_v1_server_error(result, frames[0], room_client::MessageId::NameCollision, 0,
                              "name_collision_observed");
    result.capture("A", a);
    result.capture("B", b);
    a.disconnect(200);
    b.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_ip_collision(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "ip_collision");
    const room_client::IPv4 preferred{192, 168, 7, 7};
    RawClient a;
    std::string error;
    result.check("connect_a", a.connect("127.0.0.1", spec.port, 1500, error), error);
    a.send(v1_join_bytes("rri-a1", preferred, spec.password, room_client::network_version));
    const auto frames_a = wait_server_frames_until(
        a, [](const std::vector<Bytes>& f) { return v1_find(f, room_client::MessageId::JoinSuccess) >= 0; },
        3000);
    room_client::JoinSuccess success_a;
    const bool joined_a = v1_join_success(frames_a, success_a);
    result.check("first_client_joined_with_preferred_ip", joined_a);
    if (joined_a)
        result.check("preferred_ip_honoured", success_a.assigned_ip == preferred,
                     "assigned=" + hex_spaced(Bytes(success_a.assigned_ip.begin(), success_a.assigned_ip.end())));

    RawClient b;
    result.check("connect_b", b.connect("127.0.0.1", spec.port, 1500, error), error);
    b.send(v1_join_bytes("rri-b1", preferred, spec.password, room_client::network_version));
    expect_single_error_frame(result, b, v1_expected_error(room_client::MessageId::IpCollision),
                              "ip_collision");
    const auto frames_b = b.server_frames();
    if (!frames_b.empty())
        check_v1_server_error(result, frames_b[0], room_client::MessageId::IpCollision, 0,
                              "ip_collision_observed");
    result.capture("A", a);
    result.capture("B", b);
    a.disconnect(200);
    b.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_room_full(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "room_full");
    RawClient a;
    RawClient b;
    room_client::IPv4 ip_a{};
    room_client::IPv4 ip_b{};
    const bool joined_a = v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a);
    const bool joined_b = joined_a && v1_join_and_wait(b, "rri-b1", spec.password, spec.port, result, "b", ip_b);
    RawClient c;
    if (joined_a && joined_b) {
        std::string error;
        result.check("connect_c", c.connect("127.0.0.1", spec.port, 1500, error), error);
        c.send(v1_join_bytes("rri-c1", room_client::no_preferred_ip, spec.password,
                             room_client::network_version));
        expect_single_error_frame(result, c, v1_expected_error(room_client::MessageId::RoomFull),
                                  "room_full");
        const auto frames = c.server_frames();
        if (!frames.empty())
            check_v1_server_error(result, frames[0], room_client::MessageId::RoomFull, 0,
                                  "room_full_observed");
    }
    result.capture("A", a);
    result.capture("B", b);
    result.capture("C", c);
    result.note("capacity=" + format_uint64(spec.capacity));
    a.disconnect(200);
    b.disconnect(200);
    c.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_release(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "release");
    RawClient a;
    RawClient b;
    room_client::IPv4 ip_a{};
    room_client::IPv4 ip_b{};
    const bool joined_a = v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a);
    const bool joined_b = joined_a && v1_join_and_wait(b, "rri-b1", spec.password, spec.port, result, "b", ip_b);
    RawClient c;
    if (joined_a && joined_b) {
        std::string error;
        result.check("connect_c", c.connect("127.0.0.1", spec.port, 1500, error), error);
        c.send(v1_join_bytes("rri-c1", room_client::no_preferred_ip, spec.password,
                             room_client::network_version));
        expect_single_error_frame(result, c, v1_expected_error(room_client::MessageId::RoomFull),
                                  "third_client_rejected");
        const std::uint64_t leave_start = now_ms();
        a.disconnect(400);
        RawClient d;
        room_client::IPv4 ip_d{};
        const bool joined_d = v1_join_and_wait(d, "rri-d1", spec.password, spec.port, result, "d", ip_d);
        const std::uint64_t elapsed = now_ms() - leave_start;
        result.check("rejected_and_disconnected_slot_reclaimed_within_bound",
                     joined_d && elapsed <= 5000,
                     "joined=" + std::string(joined_d ? "1" : "0") +
                         " elapsed_ms=" + format_uint64(elapsed));
        result.note("release_elapsed_ms=" + format_uint64(elapsed));
        result.capture("D", d);
        d.disconnect(200);
    }
    result.capture("A", a);
    result.capture("B", b);
    result.capture("C", c);
    b.disconnect(200);
    c.disconnect(200);
    result.note("capacity=" + format_uint64(spec.capacity));
    end_case(result, t0);
    return result;
}

CaseResult case_m2_parity(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "m2_parity");
    room_transport::Options options;
    options.port = spec.port;
    options.connect_timeout_ms = 2000;
    {
        room_transport::Transport transport(options);
        room_client::JoinRequest request;
        request.nickname = "rri-m2";
        request.version = room_client::network_version;
        request.password = spec.password;
        transport.start(request);
        const std::uint64_t deadline = now_ms() + 4000;
        while (now_ms() < deadline) {
            for (int i = 0; i < 4; ++i) transport.poll(5);
            const auto snapshot = transport.snapshot();
            if (snapshot.state == room_transport::State::Joined ||
                snapshot.state == room_transport::State::Failed)
                break;
        }
        const auto snapshot = transport.snapshot();
        result.check("transport_state_joined", snapshot.state == room_transport::State::Joined,
                     "state=" + room_transport::state_name(snapshot.state) +
                         " failure=" + snapshot.failure);
        result.check("transport_room_information_present", snapshot.room.has_value());
        result.check("transport_assigned_ip_present", snapshot.assigned_ip.has_value());
        result.check("transport_no_server_error", !snapshot.server_error.has_value());
        if (snapshot.room.has_value())
            result.check("transport_room_name_matches", snapshot.room->name == spec.room_name,
                         "got=" + snapshot.room->name);
        result.check("transport_host_live", snapshot.host_live);
        transport.leave();
        const std::uint64_t leave_deadline = now_ms() + 3000;
        while (now_ms() < leave_deadline) {
            for (int i = 0; i < 4; ++i) transport.poll(5);
            if (transport.snapshot().state != room_transport::State::Joined) break;
        }
        result.check("transport_left", transport.snapshot().state != room_transport::State::Joined,
                     "state=" + room_transport::state_name(transport.snapshot().state));
    }
    {
        room_transport::Transport transport(options);
        room_client::JoinRequest request;
        request.nickname = "rri-m2b";
        request.version = room_client::network_version;
        request.password = "not-the-password";
        transport.start(request);
        const std::uint64_t deadline = now_ms() + 4000;
        while (now_ms() < deadline) {
            for (int i = 0; i < 4; ++i) transport.poll(5);
            const auto snapshot = transport.snapshot();
            if (snapshot.server_error.has_value() || snapshot.state == room_transport::State::Failed)
                break;
        }
        const auto snapshot = transport.snapshot();
        const bool mismatched =
            snapshot.server_error.has_value() &&
            *snapshot.server_error == room_client::MessageId::WrongPassword;
        result.check("transport_observes_wrong_password", mismatched,
                     "server_error=" +
                         std::string(snapshot.server_error.has_value()
                                         ? room_client::message_name(*snapshot.server_error)
                                         : "none"));
        result.note("m2_transport_does_not_expose_raw_wire_bytes; raw capture comes from the "
                    "dedicated raw client in this harness");
    }
    end_case(result, t0);
    return result;
}

CaseResult case_port_conflict(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "port_conflict");
    std::string reason;
    const bool free_now = port_available(spec.port, reason);
    result.check("port_reported_busy_while_room_runs", !free_now,
                 free_now ? "probe could still bind " + format_uint64(spec.port) : reason);
    ServerLaunch second = to_launch(spec);
    second.tag = spec.scenario + "-portconflict";
    second.workdir = spec.workdir + "-portconflict";
    second.out_file = second.workdir + "/stdout.txt";
    second.err_file = second.workdir + "/stderr.txt";
    ServerSession session;
    std::string error;
    const bool became_ready = session.start(second, 5000, error);
    result.check("second_server_refused_on_busy_port", !became_ready,
                 became_ready ? "second room server reported ready on a taken port" : error);
    result.note("second_launch_outcome=" +
                std::string(became_ready ? "ready(UNEXPECTED)" : "refused") + " error=" + error);
    if (!became_ready) {
        const std::string tail = session.stdout_tail(400);
        if (!tail.empty()) result.note("second_launch_stdout_tail=" + trim(tail));
    }
    // Primary room must still be usable after the failed duplicate launch.
    RawClient a;
    room_client::IPv4 ip_a{};
    const bool still_serving = v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a);
    result.check("primary_room_still_serves_after_conflict", still_serving);
    result.capture("A", a);
    a.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_family_isolation(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "family_isolation");
    // The citra (v4) network version must not be accepted by a v1 room: the response has to
    // carry the v1 server_version (1), proving the two families do not share a version space.
    RawClient a;
    std::string error;
    result.check("connect", a.connect("127.0.0.1", spec.port, 1500, error), error);
    a.send(v1_join_bytes("rri-a1", room_client::no_preferred_ip, spec.password, 4));
    expect_single_error_frame(result, a, v1_expected_error(room_client::MessageId::VersionMismatch, 1),
                              "cross_family_version");
    const auto frames = a.server_frames();
    if (!frames.empty())
        check_v1_server_error(result, frames[0], room_client::MessageId::VersionMismatch, 1,
                              "cross_family_version_observed");
    result.note("sent v1 JoinRequest with citra network_version=4; server_version in response must "
                "be the v1 value 1");
    result.capture("A", a);
    a.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_proxy_route(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "proxy_route");
    RawClient a;
    RawClient b;
    RawClient c;
    room_client::IPv4 ip_a{};
    room_client::IPv4 ip_b{};
    room_client::IPv4 ip_c{};
    const bool ja = v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a);
    const bool jb = ja && v1_join_and_wait(b, "rri-b1", spec.password, spec.port, result, "b", ip_b);
    const bool jc = jb && v1_join_and_wait(c, "rri-c1", spec.password, spec.port, result, "c", ip_c);
    if (jc) {
        drain({&a, &b, &c}, 6, 10);
        const std::size_t base_a = a.server_frames().size();
        const std::size_t base_b = b.server_frames().size();
        const std::size_t base_c = c.server_frames().size();
        const Bytes payload = make_payload(16, 0x41);
        const Bytes sent = proxy_bytes(ip_a, 5000, ip_b, 5001, false, payload);
        a.send(sent);
        for (int i = 0; i < 60; ++i) {
            a.service(10);
            b.service(10);
            c.service(10);
            if (b.server_frames().size() > base_b) break;
        }
        drain({&a, &b, &c}, 6, 10);
        const auto new_b = tail_from(b.server_frames(), base_b);
        const auto new_c = tail_from(c.server_frames(), base_c);
        const auto new_a = tail_from(a.server_frames(), base_a);
        result.check("destination_member_received_exactly_one_frame", new_b.size() == 1,
                     "count=" + count_str(new_b.size()));
        if (new_b.size() == 1)
            result.check("destination_member_bytes_exact", new_b[0] == sent,
                         "actual=" + hex_spaced(new_b[0]));
        result.check("other_member_received_nothing", new_c.empty(),
                     "count=" + count_str(new_c.size()));
        result.check("sender_received_nothing", new_a.empty(),
                     "count=" + count_str(new_a.size()));
        result.note("routing is by destination IPv4 only (room.cpp:853-868)");
        result.note("dest_ip=" + hex_spaced(Bytes(ip_b.begin(), ip_b.end())));
    }
    result.capture("A", a);
    result.capture("B", b);
    result.capture("C", c);
    a.disconnect(150);
    b.disconnect(150);
    c.disconnect(150);
    end_case(result, t0);
    return result;
}

CaseResult case_proxy_broadcast(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "proxy_broadcast");
    RawClient a;
    RawClient b;
    RawClient c;
    room_client::IPv4 ip_a{};
    room_client::IPv4 ip_b{};
    room_client::IPv4 ip_c{};
    const bool ja = v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a);
    const bool jb = ja && v1_join_and_wait(b, "rri-b1", spec.password, spec.port, result, "b", ip_b);
    const bool jc = jb && v1_join_and_wait(c, "rri-c1", spec.password, spec.port, result, "c", ip_c);
    if (jc) {
        drain({&a, &b, &c}, 6, 10);
        const std::size_t base_a = a.server_frames().size();
        const std::size_t base_b = b.server_frames().size();
        const std::size_t base_c = c.server_frames().size();
        const Bytes payload = make_payload(24, 0x77);
        const room_client::IPv4 ignored{192, 168, 99, 99};
        const Bytes sent = proxy_bytes(ip_a, 5000, ignored, 5001, true, payload);
        a.send(sent);
        for (int i = 0; i < 60; ++i) {
            a.service(10);
            b.service(10);
            c.service(10);
            if (b.server_frames().size() > base_b && c.server_frames().size() > base_c) break;
        }
        drain({&a, &b, &c}, 6, 10);
        const auto new_b = tail_from(b.server_frames(), base_b);
        const auto new_c = tail_from(c.server_frames(), base_c);
        const auto new_a = tail_from(a.server_frames(), base_a);
        result.check("broadcast_reached_member_b", new_b.size() == 1 && new_b[0] == sent,
                     "count=" + count_str(new_b.size()) +
                         (new_b.empty() ? "" : " hex=" + hex_spaced(new_b[0])));
        result.check("broadcast_reached_member_c", new_c.size() == 1 && new_c[0] == sent,
                     "count=" + count_str(new_c.size()));
        result.check("broadcast_not_echoed_to_sender", new_a.empty(),
                     "count=" + count_str(new_a.size()));
        result.note("broadcast = every member except the sender (room.cpp:840-852)");
    }
    result.capture("A", a);
    result.capture("B", b);
    result.capture("C", c);
    a.disconnect(150);
    b.disconnect(150);
    c.disconnect(150);
    end_case(result, t0);
    return result;
}

CaseResult case_dataplane_size(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "dataplane_size");
    RawClient a;
    RawClient b;
    room_client::IPv4 ip_a{};
    room_client::IPv4 ip_b{};
    const bool ja = v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a);
    const bool jb = ja && v1_join_and_wait(b, "rri-b1", spec.password, spec.port, result, "b", ip_b);
    if (jb) {
        drain({&a, &b}, 6, 10);
        const std::size_t base_b = b.server_frames().size();
        const Bytes payload = make_payload(1200, 0x11);
        const Bytes sent = ldn_bytes(ip_a, ip_b, false, payload);
        a.send(sent);
        for (int i = 0; i < 60; ++i) {
            a.service(10);
            b.service(10);
            if (b.server_frames().size() > base_b) break;
        }
        drain({&a, &b}, 6, 10);
        const auto new_b = tail_from(b.server_frames(), base_b);
        result.check("ldn_frame_forwarded", new_b.size() == 1, "count=" + count_str(new_b.size()));
        if (new_b.size() == 1)
            result.check("ldn_frame_bytes_exact_1200_payload", new_b[0] == sent,
                         "actual_len=" + count_str(new_b[0].size()) +
                             " expected_len=" + count_str(sent.size()));
        result.note("MaxMessageSize=500 applies to chat only (room.cpp:944-945); the data plane "
                    "forwards a 1200-byte LDN payload intact");
    }
    result.capture("A", a);
    result.capture("B", b);
    a.disconnect(150);
    b.disconnect(150);
    end_case(result, t0);
    return result;
}

CaseResult case_chat_limit(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "chat_limit");
    RawClient a;
    RawClient b;
    room_client::IPv4 ip_a{};
    room_client::IPv4 ip_b{};
    const bool ja = v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a);
    const bool jb = ja && v1_join_and_wait(b, "rri-b1", spec.password, spec.port, result, "b", ip_b);
    if (jb) {
        drain({&a, &b}, 6, 10);
        const std::size_t base_a = a.server_frames().size();
        const std::size_t base_b = b.server_frames().size();
        a.send(v1_chat_frame(600));
        for (int i = 0; i < 60; ++i) {
            a.service(10);
            b.service(10);
            if (b.server_frames().size() > base_b) break;
        }
        drain({&a, &b}, 6, 10);
        const auto new_b = tail_from(b.server_frames(), base_b);
        const auto new_a = tail_from(a.server_frames(), base_a);
        room_client::ChatMessage message;
        bool have_chat = false;
        for (const auto& frame : new_b) {
            room_client::Message decoded;
            std::string error;
            if (!decode_v1_s2c(frame, decoded, error)) continue;
            if (const auto* chat = std::get_if<room_client::ChatMessage>(&decoded)) {
                message = *chat;
                have_chat = true;
            }
        }
        result.check("chat_received_by_other_member", have_chat,
                     "count=" + count_str(new_b.size()));
        if (have_chat) {
            result.check("chat_nickname", message.nickname == "rri-a1", "got=" + message.nickname);
            result.check("chat_truncated_to_max_message_size_500", message.message.size() == 500,
                         "got=" + count_str(message.message.size()));
        }
        result.check("chat_not_echoed_to_sender", new_a.empty(), "count=" + count_str(new_a.size()));
    }
    result.capture("A", a);
    result.capture("B", b);
    a.disconnect(150);
    b.disconnect(150);
    end_case(result, t0);
    return result;
}

CaseResult case_unjoined_source(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "unjoined_source");
    RawClient a;
    RawClient b;
    room_client::IPv4 ip_a{};
    room_client::IPv4 ip_b{};
    const bool ja = v1_join_and_wait(a, "rri-a1", spec.password, spec.port, result, "a", ip_a);
    const bool jb = ja && v1_join_and_wait(b, "rri-b1", spec.password, spec.port, result, "b", ip_b);
    RawClient u;
    if (jb) {
        std::string error;
        const bool connected = u.connect("127.0.0.1", spec.port, 1500, error);
        result.check("connect_unjoined_peer", connected, error);
        if (connected) {
            drain({&a, &b, &u}, 6, 10);
            const std::size_t base_b = b.server_frames().size();
            const Bytes payload = make_payload(8, 0x5A);
            const room_client::IPv4 fake_local{192, 168, 50, 50};
            const Bytes sent = proxy_bytes(fake_local, 4000, ip_b, 4001, false, payload);
            u.send(sent);
            for (int i = 0; i < 60; ++i) {
                a.service(10);
                b.service(10);
                u.service(10);
                if (b.server_frames().size() > base_b) break;
            }
            drain({&a, &b, &u}, 6, 10);
            const auto new_b = tail_from(b.server_frames(), base_b);
            if (!new_b.empty()) {
                result.note("VERIFIED FACT (V-016): the room forwarded data from a peer that never "
                            "joined (no sender validation); frame_bytes_exact=" +
                            std::string(new_b[0] == sent ? "yes" : "no"));
            } else {
                result.note("VERIFIED FACT (V-016): the room dropped data from a peer that never "
                            "joined");
            }
            result.note("record-only case: the room neither validates sender membership nor that "
                        "local_ip equals the sender's fake IP (room.cpp:815-871)");
            result.capture("U", u);
        }
    }
    result.capture("A", a);
    result.capture("B", b);
    a.disconnect(150);
    b.disconnect(150);
    u.disconnect(150);
    end_case(result, t0);
    return result;
}

CaseResult case_error_order(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "error_order");
    // room.cpp:295-345 validates in this order:
    //   room full -> password -> nickname -> preferred IP -> network version.
    // Every client below breaks two rules at once, so the single response byte
    // proves which check ran first (V-016m).
    std::string error;

    RawClient a;
    result.check("connect_password", a.connect("127.0.0.1", spec.port, 1500, error), error);
    a.send(v1_join_bytes("rri-a1", room_client::no_preferred_ip, spec.password + "-wrong", 2));
    expect_single_error_frame(result, a, v1_expected_error(room_client::MessageId::WrongPassword),
                              "password_before_version");
    {
        const auto frames = a.server_frames();
        if (!frames.empty())
            check_v1_server_error(result, frames[0], room_client::MessageId::WrongPassword, 0,
                                  "password_before_version_observed");
    }
    result.capture("A", a);
    a.disconnect(200);

    RawClient b;
    result.check("connect_nickname", b.connect("127.0.0.1", spec.port, 1500, error), error);
    // "rr" is shorter than the ^[ a-zA-Z0-9._-]{4,20}$ minimum (room.cpp:550).
    b.send(v1_join_bytes("rr", room_client::no_preferred_ip, spec.password, 2));
    expect_single_error_frame(result, b, v1_expected_error(room_client::MessageId::NameCollision),
                              "nickname_before_version");
    {
        const auto frames = b.server_frames();
        if (!frames.empty())
            check_v1_server_error(result, frames[0], room_client::MessageId::NameCollision, 0,
                                  "nickname_before_version_observed");
    }
    result.capture("B", b);
    b.disconnect(200);

    // The preferred-IP check precedes the version check, so a member keeps an IP in
    // the room and the next client asks for that same IP with the wrong version.
    RawClient c;
    room_client::IPv4 ip_c{};
    if (v1_join_and_wait(c, "rri-c1", spec.password, spec.port, result, "c", ip_c)) {
        RawClient d;
        result.check("connect_ip", d.connect("127.0.0.1", spec.port, 1500, error), error);
        d.send(v1_join_bytes("rri-d1", ip_c, spec.password, 2));
        expect_single_error_frame(result, d, v1_expected_error(room_client::MessageId::IpCollision),
                                  "ip_before_version");
        const auto frames = d.server_frames();
        if (!frames.empty())
            check_v1_server_error(result, frames[0], room_client::MessageId::IpCollision, 0,
                                  "ip_before_version_observed");
        result.note("contested_ip=" +
                    hex_spaced(Bytes(ip_c.begin(), ip_c.end())));
        result.capture("D", d);
        d.disconnect(200);
    }
    result.capture("C", c);
    c.disconnect(200);
    result.note("each client above breaks two rules at once; the observed byte is the "
                "highest-priority failing check, not the last one");
    end_case(result, t0);
    return result;
}

CaseResult case_fixture_bytes(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "fixture_bytes");

    // The M2 golden fixture is produced by the frozen codec's own fixture CLI
    // (crossplay/room-client), never by re-encoding bytes captured here. This case therefore
    // compares frames that really crossed the wire with those golden bytes directly -- no
    // decode -> encode round trip -- as docs/ACCEPTANCE.md M2b demands.
    const char* candidates[] = {"../room-client/fixtures/join-success.hex",
                                "../../crossplay/room-client/fixtures/join-success.hex",
                                "crossplay/room-client/fixtures/join-success.hex"};
    std::string fixture_path;
    std::string fixture_text;
    for (const char* candidate : candidates) {
        fixture_text = read_file(candidate);
        if (!fixture_text.empty()) {
            fixture_path = candidate;
            break;
        }
    }
    result.check("m2_fixture_loaded", !fixture_path.empty(),
                 fixture_path.empty() ? "none of the candidate paths held the M2 fixture"
                                      : "path=" + fixture_path);
    result.note("m2_fixture_path=" + (fixture_path.empty() ? std::string("<none>") : fixture_path));
    if (fixture_path.empty()) {
        end_case(result, t0);
        return result;
    }

    // Split the fixture into per-frame lines and parse each line with the frozen codec's own
    // hex reader; the file holds one RoomInformation line and one JoinSuccess line.
    std::vector<Bytes> fixture_frames;
    std::string pending;
    for (std::size_t i = 0; i <= fixture_text.size(); ++i) {
        const char c = i < fixture_text.size() ? fixture_text[i] : '\n';
        if (c == '\n' || c == '\r') {
            const std::string line = trim(pending);
            pending.clear();
            if (line.empty()) continue;
            try {
                fixture_frames.push_back(room_client::parse_hex(line));
            } catch (const std::exception& e) {
                result.note(std::string("m2_fixture_line_parse_error=") + e.what());
            }
        } else {
            pending.push_back(c);
        }
    }
    result.note("m2_fixture_frames=" + count_str(fixture_frames.size()));

    Bytes fixture_join_success;
    Bytes fixture_room_information;
    for (const Bytes& frame : fixture_frames) {
        if (frame.empty()) continue;
        if (frame[0] == static_cast<std::uint8_t>(room_client::MessageId::JoinSuccess) &&
            fixture_join_success.empty())
            fixture_join_success = frame;
        if (frame[0] == static_cast<std::uint8_t>(room_client::MessageId::RoomInformation) &&
            fixture_room_information.empty())
            fixture_room_information = frame;
    }
    result.check("m2_fixture_join_success_frame", fixture_join_success.size() == 5,
                 "bytes=" + hex_spaced(fixture_join_success));
    result.check("m2_fixture_room_information_frame", !fixture_room_information.empty(),
                 "bytes=" + count_str(fixture_room_information.size()));

    room_client::RoomInformation fixture_info;
    bool have_fixture_info = false;
    if (!fixture_room_information.empty()) {
        room_client::Message message;
        std::string decode_error;
        if (decode_v1_s2c(fixture_room_information, message, decode_error)) {
            if (const auto* info = std::get_if<room_client::RoomInformation>(&message)) {
                fixture_info = *info;
                have_fixture_info = true;
            }
        }
        result.check("m2_fixture_room_information_decodes", have_fixture_info, decode_error);
    }
    if (have_fixture_info) {
        result.check("m2_fixture_room_information_fields",
                     fixture_info.member_slots == 4 && fixture_info.port == 24872 &&
                         fixture_info.preferred_game_name == "GU" && fixture_info.members.size() == 1 &&
                         v1_member_named(fixture_info, "Test"),
                     "slots=" + format_uint64(fixture_info.member_slots) +
                         " port=" + format_uint64(fixture_info.port) +
                         " preferred_game=" + fixture_info.preferred_game_name +
                         " members=" + count_str(fixture_info.members.size()));
        result.note("m2_fixture_room_information_fields=name=" + fixture_info.name +
                    " slots=4 port=24872 preferred_game=GU members=1 nickname=Test "
                    "fake_ip=c0a80102");
    }

    // The golden JoinSuccess frame fixes the fake IP the fixture room used. Asking the real
    // room for that same preferred IP makes the two frames directly comparable byte for byte.
    room_client::IPv4 preferred_ip = room_client::no_preferred_ip;
    if (fixture_join_success.size() == 5) {
        for (std::size_t i = 0; i < 4; ++i)
            preferred_ip[i] = fixture_join_success[i + 1];
        result.note("m2_fixture_fake_ip=" +
                    hex_spaced(Bytes(preferred_ip.begin(), preferred_ip.end())));
    }

    RawClient a;
    std::string error;
    if (!a.connect("127.0.0.1", spec.port, 1500, error)) {
        result.check("connect", false, error);
        result.capture("A", a);
        end_case(result, t0);
        return result;
    }
    result.check("connect", true);
    a.send(v1_join_bytes("rri-t1", preferred_ip, spec.password, 1));
    const auto frames = wait_server_frames_until(
        a,
        [](const std::vector<Bytes>& f) {
            return v1_find(f, room_client::MessageId::JoinSuccess) >= 0;
        },
        2500);

    const int success_at = v1_find(frames, room_client::MessageId::JoinSuccess);
    result.check("join_success_frame_captured", success_at >= 0,
                 "server_frames=" + count_str(frames.size()));
    if (success_at >= 0) {
        const Bytes observed = frames[static_cast<std::size_t>(success_at)];
        result.note("observed_join_success=" + hex_spaced(observed));
        result.check("join_success_bytes_equal_m2_fixture", observed == fixture_join_success,
                     "observed=" + hex_spaced(observed) +
                         " m2_fixture=" + hex_spaced(fixture_join_success));
        result.check("join_success_assigned_ip_honours_preferred_ip",
                     observed.size() == 5 &&
                         Bytes(observed.begin() + 1, observed.end()) ==
                             Bytes(preferred_ip.begin(), preferred_ip.end()),
                     "observed=" + hex_spaced(observed));
    }

    room_client::RoomInformation info;
    const bool have_info = v1_room_info(frames, info);
    const int info_at = v1_find(frames, room_client::MessageId::RoomInformation);
    result.check("room_information_frame_captured", have_info);
    if (have_info) {
        result.check("room_information_member_slots_matches_capacity",
                     info.member_slots == static_cast<std::uint32_t>(spec.capacity),
                     "got=" + format_uint64(info.member_slots) +
                         " capacity=" + format_uint64(spec.capacity));
        result.check("room_information_has_self_with_preferred_ip",
                     v1_member_named(info, "rri-t1") && info.port == spec.port,
                     "port=" + format_uint64(info.port));
        result.note("observed_room_information=" +
                    hex_spaced(frames[static_cast<std::size_t>(info_at)]));

        // The two RoomInformation frames cannot be equal: the fixture room has a different
        // name, port and member identity, and the room broadcasts RoomInformation before any
        // SetGameInfo can run. Record exactly where they diverge and why.
        const Bytes& observed_info = frames[static_cast<std::size_t>(info_at)];
        std::size_t first_diff = 0;
        while (first_diff < observed_info.size() && first_diff < fixture_room_information.size() &&
               observed_info[first_diff] == fixture_room_information[first_diff])
            ++first_diff;
        result.note("room_information_first_difference_offset=" + count_str(first_diff));
        result.note("room_information_first_difference_reason=the M2 fixture room is named \"R\" "
                    "(port 24872) and holds one synthetic member whose game info is already set, "
                    "while this real room carries its own name (first differing byte is the room "
                    "name length) and broadcasts RoomInformation before JoinSuccess, so no "
                    "SetGameInfo can be reflected yet; JoinSuccess is pinned to the fixture "
                    "instead by requesting the fixture's fake IP as the preferred IP");
    }

    result.capture("A", a);
    a.disconnect(200);
    result.note("comparison uses the bytes that crossed the wire and the bytes stored in the M2 "
                "fixture file; no frame is decoded and re-encoded before comparing");
    end_case(result, t0);
    return result;
}

} // namespace rri
