// SPDX-License-Identifier: GPL-2.0-or-later
// v4 (citra) room-interop cases. The synthetic client speaks the frozen offline codec
// (crossplay/citra-room), which is derived from the citra sources; no emulator and no game
// code is involved, and the only peer is the room server on 127.0.0.1.
#include "cases.hpp"

#include <initializer_list>

namespace rri {
namespace {

Bytes make_payload(std::size_t size, unsigned char seed) {
    Bytes out(size);
    for (std::size_t i = 0; i < size; ++i)
        out[i] = static_cast<unsigned char>((seed + i * 11 + 5) & 0xFF);
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

std::string mac_str(const citra_room::MacAddress& mac) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < mac.size(); ++i) {
        if (i) s.push_back(':');
        s.push_back(d[(mac[i] >> 4) & 0xF]);
        s.push_back(d[mac[i] & 0xF]);
    }
    return s;
}

Bytes wifi_bytes(citra_room::FrameType type, std::uint8_t channel,
                 const citra_room::MacAddress& transmitter,
                 const citra_room::MacAddress& destination, const Bytes& data) {
    citra_room::WifiPacket packet;
    packet.type = type;
    packet.channel = channel;
    packet.transmitter = transmitter;
    packet.destination = destination;
    packet.data = data;
    return citra_room::encode(citra_room::Message{packet},
                              citra_room::Direction::ClientToServer);
}

// Same reason as the v1 harness: Limits::chat_bytes is the 500-byte wire cap, so an
// over-long chat frame is assembled by hand and the room's truncation is what is tested.
Bytes v4_chat_frame(std::size_t length) {
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(citra_room::MessageId::ChatMessage));
    const std::uint32_t n = static_cast<std::uint32_t>(length);
    out.push_back(static_cast<std::uint8_t>((n >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((n >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((n >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(n & 0xFF));
    out.insert(out.end(), length, static_cast<std::uint8_t>('x'));
    return out;
}

} // namespace

CaseResult case_join_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "join");
    RawClient a;
    citra_room::MacAddress mac_a{};
    if (!v4_join_and_wait(a, "rri-a1", "console-a1", spec.password, spec.port, result, "a", mac_a)) {
        result.capture("A", a);
        end_case(result, t0);
        return result;
    }
    const auto frames = wait_server_frames(a, 3, 1500);
    citra_room::RoomInformation info;
    const bool have_info = v4_room_info(frames, info);
    const int info_at = v4_find(frames, citra_room::MessageId::RoomInformation);
    const int success_at = v4_find(frames, citra_room::MessageId::JoinSuccess);
    result.check("room_information_received", have_info);
    // G-a2 asks for the citra ordering: room information is broadcast before join success
    // (citra room.cpp:409 BroadcastRoomInformation, then :413 SendJoinSuccess).
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
        result.check("member_list_contains_a", v4_member_named(info, "rri-a1"));
    }
    result.check("assigned_mac_not_no_preferred_mac", mac_a != citra_room::no_preferred_mac);
    result.note("assigned_mac=" + mac_str(mac_a));
    result.capture("A", a);

    RawClient b;
    citra_room::MacAddress mac_b{};
    if (v4_join_and_wait(b, "rri-b1", "console-b1", spec.password, spec.port, result, "b", mac_b)) {
        citra_room::RoomInformation info_b;
        const bool have_info_b = v4_room_info(b.server_frames(), info_b);
        result.check("second_joiner_room_information", have_info_b);
        if (have_info_b) {
            result.check("second_joiner_sees_first_member", v4_member_named(info_b, "rri-a1"),
                         "members=" + count_str(info_b.members.size()));
            result.check("second_joiner_list_includes_self", v4_member_named(info_b, "rri-b1"));
        }
        // The first joiner only receives StatusMessage(MemberJoin) once somebody else joins.
        const auto a_status_frames = wait_server_frames_until(
            a,
            [](const std::vector<Bytes>& f) {
                return v4_find(f, citra_room::MessageId::StatusMessage) >= 0;
            },
            2000);
        const int status_at = v4_find(a_status_frames, citra_room::MessageId::StatusMessage);
        bool status_for_b = false;
        std::string status_nickname;
        if (status_at >= 0) {
            citra_room::Message message;
            std::string decode_error;
            if (decode_v4_s2c(a_status_frames[static_cast<std::size_t>(status_at)], message,
                              decode_error)) {
                if (const auto* status = std::get_if<citra_room::StatusMessage>(&message)) {
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
    end_case(result, t0);
    return result;
}

CaseResult case_version_mismatch_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "version_mismatch");
    RawClient a;
    std::string error;
    result.check("connect", a.connect("127.0.0.1", spec.port, 1500, error), error);
    // A v1 network version sent to a v4 room: the answer must carry the v4 server version.
    a.send(v4_join_bytes("rri-a1", "console-a1", citra_room::no_preferred_mac, spec.password, 1));
    expect_single_error_frame(result, a,
                              v4_expected_error(citra_room::MessageId::VersionMismatch, 4),
                              "version_mismatch");
    const auto frames = a.server_frames();
    if (!frames.empty())
        check_v4_server_error(result, frames[0], citra_room::MessageId::VersionMismatch, 4,
                              "version_mismatch_observed");
    result.note("sent v1 network_version=1 to the v4 room; the response carries server_version=4, "
                "so the two families do not share a version space");
    result.capture("A", a);
    a.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_wrong_password_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "wrong_password");
    RawClient a;
    std::string error;
    result.check("connect", a.connect("127.0.0.1", spec.port, 1500, error), error);
    a.send(v4_join_bytes("rri-a1", "console-a1", citra_room::no_preferred_mac, "not-the-password",
                         citra_room::network_version));
    expect_single_error_frame(result, a, v4_expected_error(citra_room::MessageId::WrongPassword),
                              "wrong_password");
    const auto frames = a.server_frames();
    if (!frames.empty())
        check_v4_server_error(result, frames[0], citra_room::MessageId::WrongPassword, 0,
                              "wrong_password_observed");
    result.capture("A", a);
    a.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_name_collision_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "name_collision");
    RawClient a;
    citra_room::MacAddress mac_a{};
    if (!v4_join_and_wait(a, "rri-a1", "console-a1", spec.password, spec.port, result, "a", mac_a)) {
        result.capture("A", a);
        end_case(result, t0);
        return result;
    }
    RawClient b;
    std::string error;
    result.check("connect_b", b.connect("127.0.0.1", spec.port, 1500, error), error);
    b.send(v4_join_bytes("rri-a1", "console-b1", citra_room::no_preferred_mac, spec.password,
                         citra_room::network_version));
    expect_single_error_frame(result, b, v4_expected_error(citra_room::MessageId::NameCollision),
                              "name_collision");
    const auto frames = b.server_frames();
    if (!frames.empty())
        check_v4_server_error(result, frames[0], citra_room::MessageId::NameCollision, 0,
                              "name_collision_observed");
    result.capture("A", a);
    result.capture("B", b);
    a.disconnect(200);
    b.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_room_full_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "room_full");
    RawClient a;
    RawClient b;
    citra_room::MacAddress mac_a{};
    citra_room::MacAddress mac_b{};
    const bool joined_a = v4_join_and_wait(a, "rri-a1", "console-a1", spec.password, spec.port,
                                           result, "a", mac_a);
    const bool joined_b = joined_a && v4_join_and_wait(b, "rri-b1", "console-b1", spec.password,
                                                       spec.port, result, "b", mac_b);
    RawClient c;
    if (joined_a && joined_b) {
        std::string error;
        result.check("connect_c", c.connect("127.0.0.1", spec.port, 1500, error), error);
        c.send(v4_join_bytes("rri-c1", "console-c1", citra_room::no_preferred_mac, spec.password,
                             citra_room::network_version));
        expect_single_error_frame(result, c, v4_expected_error(citra_room::MessageId::RoomIsFull),
                                  "room_full");
        const auto frames = c.server_frames();
        if (!frames.empty())
            check_v4_server_error(result, frames[0], citra_room::MessageId::RoomIsFull, 0,
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

CaseResult case_chat_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "chat");
    RawClient a;
    RawClient b;
    citra_room::MacAddress mac_a{};
    citra_room::MacAddress mac_b{};
    const bool joined_a = v4_join_and_wait(a, "rri-a1", "console-a1", spec.password, spec.port,
                                           result, "a", mac_a);
    const bool joined_b = joined_a && v4_join_and_wait(b, "rri-b1", "console-b1", spec.password,
                                                       spec.port, result, "b", mac_b);
    if (joined_b) {
        drain({&a, &b}, 6, 10);
        const std::size_t base_a = a.server_frames().size();
        const std::size_t base_b = b.server_frames().size();
        a.send(v4_chat_frame(600));
        for (int i = 0; i < 60; ++i) {
            a.service(10);
            b.service(10);
            if (b.server_frames().size() > base_b) break;
        }
        drain({&a, &b}, 6, 10);
        const auto new_b = tail_from(b.server_frames(), base_b);
        const auto new_a = tail_from(a.server_frames(), base_a);
        citra_room::ChatMessage message;
        bool have_chat = false;
        for (const auto& frame : new_b) {
            citra_room::Message decoded;
            std::string error;
            if (!decode_v4_s2c(frame, decoded, error)) continue;
            if (const auto* chat = std::get_if<citra_room::ChatMessage>(&decoded)) {
                message = *chat;
                have_chat = true;
            }
        }
        result.check("chat_received_by_other_member", have_chat, "count=" + count_str(new_b.size()));
        if (have_chat) {
            result.check("chat_nickname", message.nickname == "rri-a1", "got=" + message.nickname);
            result.check("chat_truncated_to_max_message_size_500", message.message.size() == 500,
                         "got=" + count_str(message.message.size()));
        }
        result.check("chat_not_echoed_to_sender", new_a.empty(), "count=" + count_str(new_a.size()));
        result.note("citra truncates chat at room.cpp:913-914 (MaxMessageSize=500)");
    }
    result.capture("A", a);
    result.capture("B", b);
    a.disconnect(150);
    b.disconnect(150);
    end_case(result, t0);
    return result;
}

CaseResult case_wifi_route_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "wifi_route");
    RawClient a;
    RawClient b;
    RawClient c;
    citra_room::MacAddress mac_a{};
    citra_room::MacAddress mac_b{};
    citra_room::MacAddress mac_c{};
    const bool ja = v4_join_and_wait(a, "rri-a1", "console-a1", spec.password, spec.port, result,
                                     "a", mac_a);
    const bool jb = ja && v4_join_and_wait(b, "rri-b1", "console-b1", spec.password, spec.port,
                                           result, "b", mac_b);
    const bool jc = jb && v4_join_and_wait(c, "rri-c1", "console-c1", spec.password, spec.port,
                                           result, "c", mac_c);
    if (jc) {
        drain({&a, &b, &c}, 6, 10);
        const std::size_t base_a = a.server_frames().size();
        const std::size_t base_b = b.server_frames().size();
        const std::size_t base_c = c.server_frames().size();
        const Bytes payload = make_payload(20, 0x41);
        const Bytes sent = wifi_bytes(citra_room::FrameType::Data, 6, mac_a, mac_b, payload);
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
        result.check("sender_received_nothing", new_a.empty(), "count=" + count_str(new_a.size()));
        result.note("routing is by destination MAC only (citra room.cpp:876-892)");
        result.note("dest_mac=" + mac_str(mac_b));
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

CaseResult case_wifi_broadcast_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "wifi_broadcast");
    RawClient a;
    RawClient b;
    RawClient c;
    citra_room::MacAddress mac_a{};
    citra_room::MacAddress mac_b{};
    citra_room::MacAddress mac_c{};
    const bool ja = v4_join_and_wait(a, "rri-a1", "console-a1", spec.password, spec.port, result,
                                     "a", mac_a);
    const bool jb = ja && v4_join_and_wait(b, "rri-b1", "console-b1", spec.password, spec.port,
                                           result, "b", mac_b);
    const bool jc = jb && v4_join_and_wait(c, "rri-c1", "console-c1", spec.password, spec.port,
                                           result, "c", mac_c);
    if (jc) {
        drain({&a, &b, &c}, 6, 10);
        const std::size_t base_a = a.server_frames().size();
        const std::size_t base_b = b.server_frames().size();
        const std::size_t base_c = c.server_frames().size();
        const Bytes payload = make_payload(32, 0x77);
        const Bytes sent =
            wifi_bytes(citra_room::FrameType::Beacon, 6, mac_a, citra_room::broadcast_mac, payload);
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
        result.note("broadcast = every member except the sender (citra room.cpp:863-875)");
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

CaseResult case_console_id_collision_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "console_id_collision_v4");
    RawClient a;
    citra_room::MacAddress mac_a{};
    if (!v4_join_and_wait(a, "rri-a1", "console-a1", spec.password, spec.port, result, "a", mac_a)) {
        result.capture("A", a);
        end_case(result, t0);
        return result;
    }
    // A fresh nickname and a fresh MAC: those checks pass, so the answer must be the
    // console-id check (citra room.cpp:352 IsValidConsoleId -> ConsoleIdCollision 13).
    RawClient b;
    std::string error;
    result.check("connect_b", b.connect("127.0.0.1", spec.port, 1500, error), error);
    b.send(v4_join_bytes("rri-b1", "console-a1", citra_room::no_preferred_mac, spec.password,
                         citra_room::network_version));
    expect_single_error_frame(result, b,
                              v4_expected_error(citra_room::MessageId::ConsoleIdCollision),
                              "console_id_collision");
    {
        const auto frames = b.server_frames();
        if (!frames.empty())
            check_v4_server_error(result, frames[0], citra_room::MessageId::ConsoleIdCollision, 0,
                                  "console_id_collision_observed");
    }
    result.note("same console_id_hash console-a1, different nickname/MAC -> exactly 13");
    result.capture("A", a);
    result.capture("B", b);
    a.disconnect(200);
    b.disconnect(200);
    end_case(result, t0);
    return result;
}

CaseResult case_error_order_v4(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = now_ms();
    CaseResult result = begin_case(cfg, spec, "error_order_v4");
    // citra room.cpp:302-360 validates in this order:
    //   room full(12) -> password(10) -> nickname(7) -> MAC(8) -> console id(13) -> version(9).
    // Each client below breaks two rules at once (V-016m).
    std::string error;

    RawClient a;
    result.check("connect_password", a.connect("127.0.0.1", spec.port, 1500, error), error);
    a.send(v4_join_bytes("rri-a1", "console-a1", citra_room::no_preferred_mac,
                         spec.password + "-wrong", 1));
    expect_single_error_frame(result, a, v4_expected_error(citra_room::MessageId::WrongPassword),
                              "password_before_version");
    {
        const auto frames = a.server_frames();
        if (!frames.empty())
            check_v4_server_error(result, frames[0], citra_room::MessageId::WrongPassword, 0,
                                  "password_before_version_observed");
    }
    result.capture("A", a);
    a.disconnect(200);

    RawClient b;
    result.check("connect_nickname", b.connect("127.0.0.1", spec.port, 1500, error), error);
    // "rr" is shorter than the ^[ a-zA-Z0-9._-]{4,20}$ minimum (citra room.cpp:566).
    b.send(v4_join_bytes("rr", "console-b1", citra_room::no_preferred_mac, spec.password, 1));
    expect_single_error_frame(result, b, v4_expected_error(citra_room::MessageId::NameCollision),
                              "nickname_before_version");
    {
        const auto frames = b.server_frames();
        if (!frames.empty())
            check_v4_server_error(result, frames[0], citra_room::MessageId::NameCollision, 0,
                                  "nickname_before_version_observed");
    }
    result.capture("B", b);
    b.disconnect(200);

    // A joined member holds a MAC and a console id; the next client reuses each of them
    // while also sending a wrong version, so the response proves the earlier check won.
    RawClient c;
    citra_room::MacAddress mac_c{};
    if (v4_join_and_wait(c, "rri-c1", "console-c1", spec.password, spec.port, result, "c", mac_c)) {
        RawClient d;
        result.check("connect_mac", d.connect("127.0.0.1", spec.port, 1500, error), error);
        d.send(v4_join_bytes("rri-d1", "console-d1", mac_c, spec.password, 1));
        expect_single_error_frame(result, d, v4_expected_error(citra_room::MessageId::MacCollision),
                                  "mac_before_version");
        const auto frames = d.server_frames();
        if (!frames.empty())
            check_v4_server_error(result, frames[0], citra_room::MessageId::MacCollision, 0,
                                  "mac_before_version_observed");
        result.note("contested_mac=" + mac_str(mac_c));
        result.capture("D", d);
        d.disconnect(200);

        RawClient e;
        result.check("connect_console_id", e.connect("127.0.0.1", spec.port, 1500, error), error);
        e.send(v4_join_bytes("rri-e1", "console-c1", citra_room::no_preferred_mac, spec.password, 1));
        expect_single_error_frame(result, e,
                                  v4_expected_error(citra_room::MessageId::ConsoleIdCollision),
                                  "console_id_before_version");
        const auto frames_e = e.server_frames();
        if (!frames_e.empty())
            check_v4_server_error(result, frames_e[0], citra_room::MessageId::ConsoleIdCollision, 0,
                                  "console_id_before_version_observed");
        result.capture("E", e);
        e.disconnect(200);
    }
    result.capture("C", c);
    c.disconnect(200);
    result.note("each client above breaks two rules at once; the observed byte is the "
                "highest-priority failing check, not the last one");
    end_case(result, t0);
    return result;
}

} // namespace rri
