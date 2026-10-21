// SPDX-License-Identifier: GPL-2.0-or-later
// real-room-interop: 'observe' mode -- an independent v1 room member.
//
// Why this exists (G-c): the claim under test is "a real Citra client reaches the
// gateway, and the gateway then appears as one v1 peer in the member list of an
// original Yuzu room".  The original room broadcasts IdRoomInformation to every
// member on each membership change (01052024-yuzu-mirror-master/src/network/room.cpp:
// 772-799), so a plain v1 member is enough to read the member table -- it is an
// oracle that never touches the gateway itself.
//
// Two observation paths:
//   --via raw        (default) ENet capture + the frozen room_client::Session codec.
//                    Every server->client frame is kept, SHA-256 hashed, and decoded;
//                    a frame that fails to decode is recorded fail-closed as
//                    kind=unknown with its raw hash (fields are never guessed).
//   --via transport  the frozen room_transport::Transport envelope client.  It does
//                    not expose raw frame bytes, so its events carry raw_sha256:null;
//                    structural rejections and the server error surface through
//                    snapshot().  Used as a second, independent reading of the same
//                    member table.
//
// Only loopback rooms are accepted unless --allow-non-loopback is given explicitly; the
// refusal happens before any socket is created.

#include "observe.hpp"

#include "harness.hpp"
#include "raw_client.hpp"
#include "sha256.hpp"
#include "util.hpp"

#include <room_transport/transport.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <variant>
#include <vector>

namespace rri {
namespace {

constexpr std::uint64_t kDefaultSeconds = 5;
constexpr std::uint64_t kMaxSeconds = 3600;
constexpr std::uint32_t kConnectTimeoutMs = 3000;

struct ObserveConfig {
    std::string room = "127.0.0.1";
    std::uint16_t room_port = 0;
    std::string password;
    std::string nickname;
    std::uint64_t seconds = kDefaultSeconds;
    std::string out;
    std::string via = "raw";
    bool allow_non_loopback = false;
    bool with_help = false;
};

std::string ju(std::uint64_t value) { return format_uint64(value); }
std::string jstr(const std::string& value) { return "\"" + json_escape(value) + "\""; }

std::string ip_text(const room_client::IPv4& ip) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", static_cast<unsigned>(ip[0]),
                  static_cast<unsigned>(ip[1]), static_cast<unsigned>(ip[2]),
                  static_cast<unsigned>(ip[3]));
    return buf;
}

std::string bytes_to_string(const Bytes& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

bool parse_ipv4(const std::string& text, room_client::IPv4& out) {
    unsigned parts[4] = {0, 0, 0, 0};
    std::size_t index = 0;
    std::size_t value = 0;
    bool digits = false;
    for (std::size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == '.') {
            if (!digits || index >= 4) return false;
            parts[index++] = static_cast<unsigned>(value);
            value = 0;
            digits = false;
            continue;
        }
        const char c = text[i];
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<std::size_t>(c - '0');
        if (value > 255) return false;
        digits = true;
    }
    if (index != 4) return false;
    for (std::size_t i = 0; i < 4; ++i) out[i] = static_cast<std::uint8_t>(parts[i]);
    return true;
}

bool is_loopback(const room_client::IPv4& ip) { return ip[0] == 127; }

// Matches the room's own nickname grammar: ^[ a-zA-Z0-9._-]{4,20}$
bool valid_nickname(const std::string& nickname) {
    if (nickname.size() < 4 || nickname.size() > 20) return false;
    for (char c : nickname) {
        const bool ok = c == ' ' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

struct UtcStamp {
    std::string iso;
    std::string compact;
};

UtcStamp utc_stamp() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char iso[48];
    char compact[32];
    std::snprintf(iso, sizeof(iso), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
                  static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
                  static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond),
                  static_cast<unsigned>(st.wMilliseconds));
    std::snprintf(compact, sizeof(compact), "%04u%02u%02uT%02u%02u%02uZ",
                  static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
                  static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
                  static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond));
    return {iso, compact};
}

std::string own_exe_path() {
    std::vector<wchar_t> buffer(1024);
    for (;;) {
        const DWORD length =
            GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (static_cast<std::size_t>(length) < buffer.size())
            return wide_to_utf8(std::wstring(buffer.data(), length));
        buffer.resize(buffer.size() * 2);
    }
}

void ensure_parent_dir(const std::string& path) {
    const std::size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos || slash == 0) return;
    const std::wstring dir = utf8_to_wide(path.substr(0, slash));
    for (std::size_t i = 0; i < dir.size(); ++i) {
        if (dir[i] != L'/' && dir[i] != L'\\') continue;
        if (i == 0) continue;
        if (i == 2 && dir[1] == L':') continue; // never create "C:"
        CreateDirectoryW(dir.substr(0, i).c_str(), nullptr);
    }
    CreateDirectoryW(dir.c_str(), nullptr);
}

bool write_text_utf8(const std::string& path, const std::string& text, std::string& error) {
    ensure_parent_dir(path);
    const std::wstring wide_path = utf8_to_wide(path);
    std::FILE* file = _wfopen(wide_path.c_str(), L"wb");
    if (!file) {
        error = "cannot open for write: " + path;
        return false;
    }
    const std::size_t written =
        text.empty() ? 0 : std::fwrite(text.data(), 1, text.size(), file);
    std::fclose(file);
    if (written != text.size()) {
        error = "short write: " + path;
        return false;
    }
    return true;
}

const char* status_type_name(room_client::StatusType type) {
    switch (type) {
    case room_client::StatusType::MemberJoin: return "MemberJoin";
    case room_client::StatusType::MemberLeave: return "MemberLeave";
    case room_client::StatusType::MemberKicked: return "MemberKicked";
    case room_client::StatusType::MemberBanned: return "MemberBanned";
    case room_client::StatusType::AddressUnbanned: return "AddressUnbanned";
    }
    return "Unknown";
}

const char* ldn_type_name(room_client::LdnType type) {
    switch (type) {
    case room_client::LdnType::Scan: return "Scan";
    case room_client::LdnType::ScanResponse: return "ScanResponse";
    case room_client::LdnType::Connect: return "Connect";
    case room_client::LdnType::SyncNetwork: return "SyncNetwork";
    case room_client::LdnType::Disconnect: return "Disconnect";
    case room_client::LdnType::DestroyNetwork: return "DestroyNetwork";
    }
    return "Unknown";
}

const char* socket_protocol_name(room_client::SocketProtocol protocol) {
    switch (protocol) {
    case room_client::SocketProtocol::Unspecified: return "Unspecified";
    case room_client::SocketProtocol::Icmp: return "Icmp";
    case room_client::SocketProtocol::Tcp: return "Tcp";
    case room_client::SocketProtocol::Udp: return "Udp";
    }
    return "Unknown";
}

struct EventLog {
    std::string events; // comma separated JSON objects, no surrounding brackets
    std::size_t events_count = 0;
    std::size_t join_success = 0;
    std::size_t room_information = 0;
    std::size_t errors = 0;
    std::size_t unknown = 0;
    std::size_t decode_failures = 0;
    std::size_t status = 0;
    std::size_t chat = 0;
    std::size_t proxy = 0;
    std::size_t ldn = 0;
    std::size_t other = 0;
    std::size_t max_member_count = 0;
    bool saw_self = false;
    bool joined = false;
    std::string self_nickname;
    std::string fake_ip;
    std::string room_name;
    std::uint32_t member_slots = 0;
    std::uint16_t room_port = 0;
    std::vector<std::string> members_seen;
};

void add_event(EventLog& log, const std::string& object) {
    if (!log.events.empty()) log.events += ",";
    log.events += "\n    ";
    log.events += object;
    ++log.events_count;
}

void remember_member(EventLog& log, const std::string& nickname, const room_client::IPv4& fake_ip) {
    if (nickname == log.self_nickname) {
        log.saw_self = true;
        if (log.fake_ip.empty()) log.fake_ip = ip_text(fake_ip);
    }
    if (nickname.empty()) return;
    for (const std::string& seen : log.members_seen)
        if (seen == nickname) return;
    log.members_seen.push_back(nickname);
}

std::string raw_sha_field(const std::string& raw_sha) {
    return raw_sha.empty() ? std::string("null") : ("\"" + raw_sha + "\"");
}

std::string member_object(const room_client::Member& member) {
    std::string json = "{";
    json += "\"nickname\":" + jstr(member.nickname);
    json += ",\"fake_ip\":\"" + ip_text(member.fake_ip) + "\"";
    json += ",\"game_info_name\":" + jstr(member.game.name);
    json += ",\"game_info_id\":" + ju(member.game.id);
    json += ",\"game_info_version\":" + jstr(member.game.version);
    json += ",\"username\":" + jstr(member.username);
    json += ",\"display_name\":" + jstr(member.display_name);
    json += ",\"avatar_url\":" + jstr(member.avatar_url);
    json += "}";
    return json;
}

void print_member_table(const room_client::RoomInformation& info) {
    std::printf("OBSERVE   member_table member_count=%llu room=%s\n",
                static_cast<unsigned long long>(info.members.size()), info.name.c_str());
    for (const room_client::Member& member : info.members) {
        std::printf(
            "OBSERVE     member nickname=%s fake_ip=%s game=%s game_id=%llu game_version=%s "
            "username=%s display_name=%s\n",
            member.nickname.c_str(), ip_text(member.fake_ip).c_str(), member.game.name.c_str(),
            static_cast<unsigned long long>(member.game.id), member.game.version.c_str(),
            member.username.c_str(), member.display_name.c_str());
    }
}

void emit_v1_message(EventLog& log, const room_client::Message& message, std::uint64_t t_ms,
                     const std::string& raw_sha, const std::string& via) {
    const std::string prefix =
        "{\"t_ms\":" + ju(t_ms) + ",\"via\":" + jstr(via) + ",\"raw_sha256\":" +
        raw_sha_field(raw_sha);

    if (const auto* success = std::get_if<room_client::JoinSuccess>(&message)) {
        ++log.join_success;
        log.joined = true;
        std::string json = prefix + ",\"kind\":\"join_success\"";
        json += ",\"fake_ip\":\"" + ip_text(success->assigned_ip) + "\"";
        json += std::string(",\"moderator\":") + (success->moderator ? "true" : "false");
        json += ",\"room_name\":" + jstr(log.room_name);
        json += ",\"member_slots\":" + ju(log.member_slots);
        json += ",\"room_port\":" + ju(log.room_port);
        json += "}";
        add_event(log, json);
        std::printf("OBSERVE join_success t_ms=%llu fake_ip=%s moderator=%s room=%s slots=%llu\n",
                    static_cast<unsigned long long>(t_ms), ip_text(success->assigned_ip).c_str(),
                    success->moderator ? "true" : "false", log.room_name.c_str(),
                    static_cast<unsigned long long>(log.member_slots));
        return;
    }
    if (const auto* info = std::get_if<room_client::RoomInformation>(&message)) {
        ++log.room_information;
        log.room_name = info->name;
        log.member_slots = info->member_slots;
        log.room_port = info->port;
        if (info->members.size() > log.max_member_count) log.max_member_count = info->members.size();
        std::string json = prefix + ",\"kind\":\"room_information\"";
        json += ",\"room_name\":" + jstr(info->name);
        json += ",\"description\":" + jstr(info->description);
        json += ",\"member_slots\":" + ju(info->member_slots);
        json += ",\"room_port\":" + ju(info->port);
        json += ",\"preferred_game_name\":" + jstr(info->preferred_game_name);
        json += ",\"host_username\":" + jstr(info->host_username);
        json += ",\"member_count\":" + ju(info->members.size());
        json += ",\"members\":[";
        for (std::size_t i = 0; i < info->members.size(); ++i) {
            if (i) json += ",";
            json += member_object(info->members[i]);
        }
        json += "]}";
        for (const room_client::Member& member : info->members)
            remember_member(log, member.nickname, member.fake_ip);
        add_event(log, json);
        std::printf(
            "OBSERVE room_information t_ms=%llu member_count=%llu room=%s slots=%llu port=%llu\n",
            static_cast<unsigned long long>(t_ms),
            static_cast<unsigned long long>(info->members.size()), info->name.c_str(),
            static_cast<unsigned long long>(info->member_slots),
            static_cast<unsigned long long>(info->port));
        print_member_table(*info);
        return;
    }
    if (const auto* error = std::get_if<room_client::ServerError>(&message)) {
        ++log.errors;
        std::string json = prefix + ",\"kind\":\"error\"";
        json += ",\"code\":" + ju(static_cast<std::uint64_t>(error->id));
        json += ",\"name\":" + jstr(room_client::message_name(error->id));
        json += ",\"server_version\":" + ju(error->server_version);
        json += "}";
        add_event(log, json);
        std::printf("OBSERVE error t_ms=%llu code=%llu name=%s server_version=%llu\n",
                    static_cast<unsigned long long>(t_ms),
                    static_cast<unsigned long long>(error->id),
                    room_client::message_name(error->id).c_str(),
                    static_cast<unsigned long long>(error->server_version));
        return;
    }
    if (const auto* status = std::get_if<room_client::StatusMessage>(&message)) {
        ++log.status;
        std::string json = prefix + ",\"kind\":\"status\"";
        json += ",\"type\":" + ju(static_cast<std::uint64_t>(status->type));
        json += ",\"type_name\":" + jstr(status_type_name(status->type));
        json += ",\"nickname\":" + jstr(status->nickname);
        json += ",\"username\":" + jstr(status->username);
        json += "}";
        add_event(log, json);
        std::printf("OBSERVE status t_ms=%llu type=%s nickname=%s\n",
                    static_cast<unsigned long long>(t_ms), status_type_name(status->type),
                    status->nickname.c_str());
        return;
    }
    if (const auto* chat = std::get_if<room_client::ChatMessage>(&message)) {
        ++log.chat;
        std::string json = prefix + ",\"kind\":\"chat\"";
        json += ",\"nickname\":" + jstr(chat->nickname);
        json += ",\"username\":" + jstr(chat->username);
        json += ",\"message\":" + jstr(chat->message);
        json += "}";
        add_event(log, json);
        std::printf("OBSERVE chat t_ms=%llu nickname=%s bytes=%llu\n",
                    static_cast<unsigned long long>(t_ms), chat->nickname.c_str(),
                    static_cast<unsigned long long>(chat->message.size()));
        return;
    }
    if (const auto* proxy = std::get_if<room_client::ProxyPacket>(&message)) {
        ++log.proxy;
        const std::string data_sha = sha256_hex_of(bytes_to_string(proxy->data));
        std::string json = prefix + ",\"kind\":\"proxy\"";
        json += std::string(",\"broadcast\":") + (proxy->broadcast ? "true" : "false");
        json += ",\"local_ip\":\"" + ip_text(proxy->local.ip) + "\"";
        json += ",\"local_port\":" + ju(proxy->local.port);
        json += ",\"remote_ip\":\"" + ip_text(proxy->remote.ip) + "\"";
        json += ",\"remote_port\":" + ju(proxy->remote.port);
        json += ",\"protocol\":" + jstr(socket_protocol_name(proxy->protocol));
        json += ",\"data_bytes\":" + ju(proxy->data.size());
        json += ",\"data_sha256\":\"" + data_sha + "\"";
        json += "}";
        add_event(log, json);
        std::printf("OBSERVE proxy t_ms=%llu broadcast=%s remote=%s:%llu data_bytes=%llu\n",
                    static_cast<unsigned long long>(t_ms), proxy->broadcast ? "true" : "false",
                    ip_text(proxy->remote.ip).c_str(),
                    static_cast<unsigned long long>(proxy->remote.port),
                    static_cast<unsigned long long>(proxy->data.size()));
        return;
    }
    if (const auto* ldn = std::get_if<room_client::LdnPacket>(&message)) {
        ++log.ldn;
        const std::string data_sha = sha256_hex_of(bytes_to_string(ldn->data));
        std::string json = prefix + ",\"kind\":\"ldn\"";
        json += ",\"type\":" + ju(static_cast<std::uint64_t>(ldn->type));
        json += ",\"type_name\":" + jstr(ldn_type_name(ldn->type));
        json += ",\"local_ip\":\"" + ip_text(ldn->local_ip) + "\"";
        json += ",\"remote_ip\":\"" + ip_text(ldn->remote_ip) + "\"";
        json += std::string(",\"broadcast\":") + (ldn->broadcast ? "true" : "false");
        json += ",\"data_bytes\":" + ju(ldn->data.size());
        json += ",\"data_sha256\":\"" + data_sha + "\"";
        json += "}";
        add_event(log, json);
        std::printf("OBSERVE ldn t_ms=%llu type=%s remote=%s data_bytes=%llu\n",
                    static_cast<unsigned long long>(t_ms), ldn_type_name(ldn->type),
                    ip_text(ldn->remote_ip).c_str(),
                    static_cast<unsigned long long>(ldn->data.size()));
        return;
    }

    ++log.other;
    std::string json = prefix + ",\"kind\":\"other\"";
    json += ",\"name\":" + jstr(room_client::message_name(room_client::message_id(message)));
    json += "}";
    add_event(log, json);
    std::printf("OBSERVE other t_ms=%llu name=%s\n", static_cast<unsigned long long>(t_ms),
                room_client::message_name(room_client::message_id(message)).c_str());
}

void record_unknown(EventLog& log, std::uint64_t t_ms, const std::string& via,
                    const std::string& raw_sha, std::size_t raw_bytes, const std::string& reason,
                    bool decode_failure) {
    ++log.unknown;
    if (decode_failure) ++log.decode_failures;
    std::string json = "{\"t_ms\":" + ju(t_ms) + ",\"via\":" + jstr(via) +
                       ",\"kind\":\"unknown\"";
    if (raw_bytes != 0) json += ",\"raw_bytes\":" + ju(raw_bytes);
    json += ",\"raw_sha256\":" + raw_sha_field(raw_sha);
    json += ",\"reason\":" + jstr(reason) + "}";
    add_event(log, json);
    std::printf("OBSERVE unknown t_ms=%llu via=%s raw_bytes=%llu reason=%s\n",
                static_cast<unsigned long long>(t_ms), via.c_str(),
                static_cast<unsigned long long>(raw_bytes), reason.c_str());
}

struct ObserveOutcome {
    bool connected = false;
    bool server_rejected = false;
    std::string failure;
};

ObserveOutcome observe_raw(const ObserveConfig& cfg, const room_client::JoinRequest& request,
                           EventLog& log, std::string& error) {
    ObserveOutcome outcome;
    RawClient client;
    std::string connect_error;
    if (!client.connect(cfg.room, cfg.room_port, kConnectTimeoutMs, connect_error)) {
        error = "connect to " + cfg.room + ":" + ju(cfg.room_port) + " failed: " + connect_error;
        return outcome;
    }
    outcome.connected = true;
    // The frozen codec caps its session timeouts at 60000 ms; a join completes in milliseconds,
    // and the observation window (--seconds, up to 3600) is bounded by this loop, not by the
    // session deadline.
    room_client::SessionOptions session_options;
    session_options.join_timeout_ms = 60000;
    session_options.leave_timeout_ms = 1000;
    room_client::Session session(session_options);
    try {
        client.send(session.begin_join(request, now_ms()));
    } catch (const std::exception& e) {
        error = std::string("begin_join failed: ") + e.what();
        client.abort();
        return outcome;
    }
    const std::uint64_t deadline = now_ms() + cfg.seconds * 1000;
    std::size_t cursor = 0;
    bool stop = false;
    while (!stop && now_ms() < deadline) {
        client.service(5);
        const std::vector<WireFrame>& frames = client.frames();
        for (; cursor < frames.size(); ++cursor) {
            const WireFrame& frame = frames[cursor];
            if (!frame.from_server) continue;
            const std::string raw_sha =
                sha256_hex_of(bytes_to_string(frame.bytes));
            try {
                const room_client::Message message =
                    session.receive(frame.bytes, now_ms(), room_client::enet_channel);
                emit_v1_message(log, message, frame.t_ms, raw_sha, "raw");
                if (session.state() == room_client::SessionState::Joined ||
                    session.state() == room_client::SessionState::Moderator)
                    log.joined = true;
                if (std::holds_alternative<room_client::ServerError>(message)) {
                    outcome.server_rejected = true;
                    outcome.failure =
                        "server rejected the join: " +
                        room_client::message_name(*session.last_server_error());
                    stop = true;
                    break;
                }
            } catch (const room_client::ProtocolError& e) {
                record_unknown(log, frame.t_ms, "raw", raw_sha, frame.bytes.size(),
                               std::string("ProtocolError: ") + e.what(), true);
                outcome.failure = std::string("decode failed (fail-closed): ") + e.what();
                stop = true;
                break;
            } catch (const std::exception& e) {
                record_unknown(log, frame.t_ms, "raw", raw_sha, frame.bytes.size(),
                               std::string("session error: ") + e.what(), true);
                outcome.failure = std::string("session error (fail-closed): ") + e.what();
                stop = true;
                break;
            }
        }
        if (!stop && client.disconnected()) {
            if (outcome.failure.empty()) outcome.failure = "server disconnected";
            stop = true;
        }
    }
    client.disconnect();
    return outcome;
}

ObserveOutcome observe_transport(const ObserveConfig& cfg, const room_client::JoinRequest& request,
                                 EventLog& log, std::string& error) {
    ObserveOutcome outcome;
    room_transport::Options options;
    options.address = cfg.room;
    options.port = cfg.room_port;
    options.connect_timeout_ms = kConnectTimeoutMs;
    options.session = room_client::SessionOptions{{}, 60000, 1000};
    options.queue_packets = 4096;
    options.queue_bytes = 16u * 1024u * 1024u;
    room_transport::Transport transport(options);
    const std::uint64_t started = now_ms();
    try {
        transport.start(request);
    } catch (const std::exception& e) {
        error = std::string("transport start failed: ") + e.what();
        return outcome;
    }
    outcome.connected = true;
    const std::uint64_t deadline = started + cfg.seconds * 1000;
    std::size_t last_boundary = 0;
    bool stop = false;
    while (!stop && now_ms() < deadline) {
        transport.poll(5);
        while (auto message = transport.pop()) {
            emit_v1_message(log, *message, now_ms() - started, std::string(), "transport");
        }
        const room_transport::Snapshot snapshot = transport.snapshot();
        if (snapshot.state == room_transport::State::Joined) log.joined = true;
        if (snapshot.boundary_rejections > last_boundary) {
            last_boundary = snapshot.boundary_rejections;
            record_unknown(log, now_ms() - started, "transport", std::string(), 0,
                           std::string("boundary guard: ") + snapshot.boundary_reason, false);
            outcome.failure = "boundary guard rejected a frame: " + snapshot.boundary_reason;
            stop = true;
        }
        if (snapshot.state == room_transport::State::Failed) {
            if (snapshot.server_error) {
                ++log.errors;
                add_event(log,
                          "{\"t_ms\":" + ju(now_ms() - started) +
                              ",\"via\":\"transport\",\"kind\":\"error\",\"raw_sha256\":null"
                              ",\"code\":" +
                              ju(static_cast<std::uint64_t>(*snapshot.server_error)) +
                              ",\"name\":" +
                              jstr(room_client::message_name(*snapshot.server_error)) +
                              ",\"server_version\":null}");
                std::printf("OBSERVE error t_ms=%llu via=transport code=%llu name=%s\n",
                            static_cast<unsigned long long>(now_ms() - started),
                            static_cast<unsigned long long>(*snapshot.server_error),
                            room_client::message_name(*snapshot.server_error).c_str());
                outcome.server_rejected = true;
            } else {
                record_unknown(log, now_ms() - started, "transport", std::string(), 0,
                               snapshot.failure, false);
            }
            outcome.failure = snapshot.failure;
            stop = true;
        }
    }
    transport.stop();
    return outcome;
}

std::string usage_text() {
    return std::string(
        "real-room-interop observe: independent v1 room member / member-table oracle\n"
        "usage: real_room_interop.exe observe --room <ipv4> --room-port <n> [options]\n"
        "  --room <ipv4>          room server address (loopback only by default)\n"
        "  --room-port <n>        room server UDP port (1..65535)\n"
        "  --password <text>      room password (may be empty for an open room)\n"
        "  --nickname <name>      ^[ a-zA-Z0-9._-]{4,20}$ (same grammar as the room)\n"
        "  --seconds <n>          observation window, 1..3600 (default 5)\n"
        "  --out <path>           JSON evidence file (UTF-8 path)\n"
        "  --via raw|transport    observation path (default raw; transport has no raw bytes)\n"
        "  --allow-non-loopback   permit a non-loopback --room (records the full command line)\n"
        "                         (never used by this project: only loopback is authorized)\n"
        "  --help                 print this text\n"
        "exit: 0 observed, 2 usage, 3 non-loopback refused, 4 no join, 5 server rejected\n");
}

bool parse_observe(const std::vector<std::string>& args, ObserveConfig& cfg, std::string& error) {
    for (std::size_t i = 2; i < args.size(); ++i) {
        const std::string& a = args[i];
        auto value = [&](std::string& slot) {
            if (i + 1 >= args.size()) {
                error = a + " needs a value";
                return false;
            }
            slot = args[++i];
            return true;
        };
        std::string text;
        if (a == "--help" || a == "-h") {
            cfg.with_help = true;
        } else if (a == "--room") {
            if (!value(cfg.room)) return false;
        } else if (a == "--room-port") {
            if (!value(text)) return false;
            const unsigned long parsed = std::strtoul(text.c_str(), nullptr, 10);
            if (parsed == 0 || parsed > 65535) {
                error = "--room-port out of range: " + text;
                return false;
            }
            cfg.room_port = static_cast<std::uint16_t>(parsed);
        } else if (a == "--password") {
            if (!value(cfg.password)) return false;
        } else if (a == "--nickname") {
            if (!value(cfg.nickname)) return false;
        } else if (a == "--seconds") {
            if (!value(text)) return false;
            const unsigned long long parsed = std::strtoull(text.c_str(), nullptr, 10);
            if (parsed == 0 || parsed > kMaxSeconds) {
                error = "--seconds out of range (1..3600): " + text;
                return false;
            }
            cfg.seconds = static_cast<std::uint64_t>(parsed);
        } else if (a == "--out") {
            if (!value(cfg.out)) return false;
        } else if (a == "--via") {
            if (!value(cfg.via)) return false;
        } else if (a == "--allow-non-loopback") {
            cfg.allow_non_loopback = true;
        } else {
            error = "unknown option '" + a + "'";
            return false;
        }
    }
    if (cfg.with_help) return true;
    if (cfg.room_port == 0) {
        error = "--room-port is required";
        return false;
    }
    if (cfg.nickname.empty()) {
        error = "--nickname is required";
        return false;
    }
    if (!valid_nickname(cfg.nickname)) {
        error = "--nickname must match ^[ a-zA-Z0-9._-]{4,20}$: " + cfg.nickname;
        return false;
    }
    if (cfg.out.empty()) {
        error = "--out is required";
        return false;
    }
    if (cfg.via != "raw" && cfg.via != "transport") {
        error = "--via must be raw or transport";
        return false;
    }
    return true;
}

} // namespace

int run_observe(const std::vector<std::string>& args) {
    ObserveConfig cfg;
    std::string error;
    if (!parse_observe(args, cfg, error)) {
        std::fprintf(stderr, "observe: %s\n\n%s", error.c_str(), usage_text().c_str());
        return 2;
    }
    if (cfg.with_help) {
        std::fputs(usage_text().c_str(), stdout);
        return 0;
    }

    room_client::IPv4 room_ip{};
    if (!parse_ipv4(cfg.room, room_ip)) {
        std::fprintf(stderr, "observe: --room must be a numeric IPv4 address: %s\n",
                     cfg.room.c_str());
        return 2;
    }
    if (!is_loopback(room_ip) && !cfg.allow_non_loopback) {
        std::fprintf(stderr,
                     "observe: refusing non-loopback room %s: this project is only authorized to "
                     "talk to 127.0.0.0/8 (pass --allow-non-loopback to override explicitly)\n",
                     cfg.room.c_str());
        return 3;
    }

    const std::string exe_path = own_exe_path();
    const std::string command_line = wide_to_utf8(GetCommandLineW());
    const UtcStamp start_stamp = utc_stamp();
    const std::string run_id = start_stamp.compact + "-" + ju(GetCurrentProcessId());

    EventLog log;
    log.self_nickname = cfg.nickname;

    room_client::JoinRequest request;
    request.nickname = cfg.nickname;
    request.version = room_client::network_version;
    request.password = cfg.password;

    std::printf("OBSERVE start run_id=%s nickname=%s room=%s:%llu via=%s seconds=%llu\n",
                run_id.c_str(), cfg.nickname.c_str(), cfg.room.c_str(),
                static_cast<unsigned long long>(cfg.room_port), cfg.via.c_str(),
                static_cast<unsigned long long>(cfg.seconds));

    std::string run_error;
    ObserveOutcome outcome;
    try {
        outcome = (cfg.via == "transport") ? observe_transport(cfg, request, log, run_error)
                                           : observe_raw(cfg, request, log, run_error);
    } catch (const std::exception& e) {
        // Nothing may escape: an uncaught exception would abort the process and lose the
        // evidence file, so it is recorded fail-closed like any other decode failure.
        run_error = std::string("unhandled failure (fail-closed): ") + e.what();
        record_unknown(log, 0, cfg.via, std::string(), 0, run_error, true);
    }
    if (!run_error.empty()) std::fprintf(stderr, "observe: %s\n", run_error.c_str());

    const std::string end_stamp = utc_stamp().iso;

    int exit_code = 0;
    if (!run_error.empty() || !outcome.connected) exit_code = 4;
    else if (outcome.server_rejected) exit_code = 5;
    else if (!log.joined) exit_code = 4;

    std::string json = "{\n";
    json += "  \"tool\": \"real-room-interop\",\n";
    json += "  \"mode\": \"observe\",\n";
    json += "  \"run_id\": \"" + run_id + "\",\n";
    json += "  \"start_utc\": \"" + start_stamp.iso + "\",\n";
    json += "  \"end_utc\": \"" + end_stamp + "\",\n";
    json += "  \"exe\": {\"path\": " + jstr(exe_path) + ", \"bytes\": " + ju(file_size(exe_path)) +
            ", \"sha256\": \"" + file_sha256_hex(exe_path) + "\"},\n";
    json += "  \"command_line\": " + jstr(command_line) + ",\n";
    json += "  \"protocol\": \"v1\",\n";
    json += "  \"via\": " + jstr(cfg.via) + ",\n";
    json += "  \"room\": {\"address\": " + jstr(cfg.room) + ", \"port\": " + ju(cfg.room_port) +
            ", \"nickname\": " + jstr(cfg.nickname) + ", \"password_set\": " +
            (cfg.password.empty() ? "false" : "true") + ", \"loopback_only\": " +
            (is_loopback(room_ip) ? "true" : "false") + ", \"local_socket\": " +
            jstr(cfg.via == "transport"
                     ? "0.0.0.0:ephemeral (frozen room_transport::Transport host default)"
                     : "127.0.0.1:ephemeral (RawClient binds loopback)") +
            "},\n";
    json += "  \"decode_failures\": " + ju(log.decode_failures) + ",\n";
    if (!run_error.empty()) json += "  \"failure\": " + jstr(run_error) + ",\n";
    else if (!outcome.failure.empty()) json += "  \"failure\": " + jstr(outcome.failure) + ",\n";
    json += "  \"events\": [" + log.events + "\n  ],\n";
    json += "  \"summary\": {\"exit\": " + ju(static_cast<std::uint64_t>(exit_code)) +
            ", \"seconds\": " + ju(cfg.seconds) + ", \"events\": " + ju(log.events_count) +
            ", \"join_success\": " + ju(log.join_success) +
            ", \"room_information\": " + ju(log.room_information) +
            ", \"errors\": " + ju(log.errors) + ", \"unknown\": " + ju(log.unknown) +
            ", \"decode_failures\": " + ju(log.decode_failures) + ", \"status\": " + ju(log.status) +
            ", \"chat\": " + ju(log.chat) + ", \"proxy\": " + ju(log.proxy) + ", \"ldn\": " +
            ju(log.ldn) + ", \"other\": " + ju(log.other) +
            ", \"joined\": " + (log.joined ? "true" : "false") +
            ", \"saw_self\": " + (log.saw_self ? "true" : "false") +
            ", \"self_fake_ip\": " + jstr(log.fake_ip) +
            ", \"max_member_count\": " + ju(log.max_member_count) + ", \"members_seen\": [";
    for (std::size_t i = 0; i < log.members_seen.size(); ++i) {
        if (i) json += ", ";
        json += jstr(log.members_seen[i]);
    }
    json += "]}\n";
    json += "}\n";

    std::string write_error;
    if (!write_text_utf8(cfg.out, json, write_error))
        std::fprintf(stderr, "observe: %s\n", write_error.c_str());

    std::string members;
    for (std::size_t i = 0; i < log.members_seen.size(); ++i) {
        if (i) members += ",";
        members += log.members_seen[i];
    }
    if (members.empty()) members = "-";
    std::printf(
        "OBSERVE_RESULT exit=%d seconds=%llu events=%llu join_success=%llu room_information=%llu "
        "errors=%llu unknown=%llu decode_failures=%llu status=%llu chat=%llu proxy=%llu ldn=%llu "
        "other=%llu max_member_count=%llu saw_self=%d joined=%d members=%s\n",
        exit_code, static_cast<unsigned long long>(cfg.seconds),
        static_cast<unsigned long long>(log.events_count),
        static_cast<unsigned long long>(log.join_success),
        static_cast<unsigned long long>(log.room_information),
        static_cast<unsigned long long>(log.errors),
        static_cast<unsigned long long>(log.unknown),
        static_cast<unsigned long long>(log.decode_failures),
        static_cast<unsigned long long>(log.status), static_cast<unsigned long long>(log.chat),
        static_cast<unsigned long long>(log.proxy), static_cast<unsigned long long>(log.ldn),
        static_cast<unsigned long long>(log.other),
        static_cast<unsigned long long>(log.max_member_count), log.saw_self ? 1 : 0,
        log.joined ? 1 : 0, members.c_str());
    std::fflush(stdout);
    return exit_code;
}

} // namespace rri
