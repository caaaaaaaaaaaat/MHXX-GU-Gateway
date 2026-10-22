// SPDX-License-Identifier: GPL-2.0-or-later
// G-b loopback gateway implementation. Single threaded, non blocking, no worker
// threads. See gateway.hpp and README.md.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <zstd.h>

#include "citra_gateway/gateway.hpp"

#include <enet/enet.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace citra_gateway {
namespace {

std::uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

// G-c / V-027: the deliverable Citra-side transport is an ENet/UDP server, the
// transport a real Citra room member speaks. ENet's enet_initialize /
// enet_deinitialize are a WSAStartup/WSACleanup pair rather than a reference
// count, and room_transport::Transport already owns its own balanced pair
// (crossplay/room-transport/src/transport.cpp:107), so this process initializes
// ENet once and never tears it down (the same choice
// crossplay/real-room-interop/src/raw_client.cpp:9-15 makes).
void ensure_enet_runtime() {
    static const bool ready = []() { return enet_initialize() == 0; }();
    (void)ready;
}

// V-047/V-048 peer relay wrapper. The Yuzu ProxyPacket has no frame-type field,
// so a relayed WifiPacket would arrive as Data/channel-placeholder. The gateway
// therefore prepends a 7 byte wrapper to the plain payload before Zstd:
//   magic[4] = "CRLY" (0x43 0x52 0x4C 0x59), version 0x01, type, channel.
// The receiver only strips it when the magic matches, so an unwrapped frame from
// a non-relay peer (or the ordinary Data path) still decodes exactly as before.
constexpr std::uint8_t kPeerRelayMagic[4] = {0x43, 0x52, 0x4C, 0x59};
constexpr std::uint8_t kPeerRelayVersion = 0x01;
constexpr std::size_t kPeerRelayHeaderBytes = 7;
// citra_room::FrameType is Beacon=0..NodeMap=5 (protocol.hpp:110-117).
constexpr std::uint8_t kPeerRelayMaxType = 5;

bool peer_relay_wrapper(const citra_room::Bytes& plain) {
    return plain.size() >= kPeerRelayHeaderBytes &&
           plain[0] == kPeerRelayMagic[0] && plain[1] == kPeerRelayMagic[1] &&
           plain[2] == kPeerRelayMagic[2] && plain[3] == kPeerRelayMagic[3];
}

std::string json_escape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (const char ch : text) {
        const unsigned char byte = static_cast<unsigned char>(ch);
        switch (byte) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (byte < 0x20) {
                static const char* digits = "0123456789abcdef";
                out += "\\u00";
                out += digits[(byte >> 4) & 0xF];
                out += digits[byte & 0xF];
            } else {
                out += ch;
            }
            break;
        }
    }
    return out;
}

std::string hex_of(const citra_room::Bytes& data, std::size_t max_bytes) {
    static const char* digits = "0123456789abcdef";
    const std::size_t count = std::min(data.size(), max_bytes);
    std::string out;
    out.reserve(count * 2);
    for (std::size_t i = 0; i < count; ++i) {
        out += digits[(data[i] >> 4) & 0xF];
        out += digits[data[i] & 0xF];
    }
    return out;
}

// V-262: one bounded inbound Wi-Fi frame sample, kept per frame type so a real
// run can be diagnosed without a packet capture.  For beacons the parsed
// NetworkInfo is recorded too: its 200-byte application data is exactly the
// hall advertisement a cross-game bridge has to carry.
struct InboundWifiSample {
    std::string transmitter;
    std::string destination;
    std::uint8_t channel = 0;
    std::size_t bytes = 0;
    std::string data_hex;
    std::string extra_json;  // "" or a leading-comma object fragment
};

std::string join_fields(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::ostringstream out;
    out << "{";
    bool first = true;
    for (const auto& [key, value] : fields) {
        if (!first) {
            out << ",";
        }
        first = false;
        out << "\"" << json_escape(key) << "\":" << value;
    }
    out << "}";
    return out.str();
}

template <typename T>
std::string json_array(const std::vector<T>& items, std::string (*render)(const T&)) {
    std::ostringstream out;
    out << "[";
    bool first = true;
    for (const auto& item : items) {
        if (!first) {
            out << ",";
        }
        first = false;
        out << render(item);
    }
    out << "]";
    return out.str();
}

std::string quote(const std::string& text) { return "\"" + json_escape(text) + "\""; }

} // namespace

std::string phase_name(ClientPhase phase) {
    switch (phase) {
    case ClientPhase::Framing: return "Framing";
    case ClientPhase::Joining: return "Joining";
    case ClientPhase::Joined: return "Joined";
    case ClientPhase::Closing: return "Closing";
    case ClientPhase::Closed: return "Closed";
    }
    return "Unknown";
}

bool valid_proxy_frame(const room_client::Bytes& frame, std::size_t compressed_cap,
                       std::size_t decompressed_cap, std::string* why) {
    const auto fail = [&](const char* text) {
        if (why != nullptr) {
            *why = text;
        }
        return false;
    };
    if (frame.size() > compressed_cap) {
        return fail("proxy frame over compressed cap");
    }
    if (frame.size() < 4) {
        return fail("proxy frame too short");
    }
    if (!(frame[0] == 0x28 && frame[1] == 0xB5 && frame[2] == 0x2F && frame[3] == 0xFD)) {
        return fail("proxy frame is not a standard zstd frame");
    }
    const unsigned long long content = ZSTD_getFrameContentSize(frame.data(), frame.size());
    if (content == ZSTD_CONTENTSIZE_ERROR) {
        return fail("proxy frame content size error");
    }
    if (content == ZSTD_CONTENTSIZE_UNKNOWN) {
        return fail("proxy frame unknown content size");
    }
    if (content > decompressed_cap) {
        return fail("proxy frame over decompressed cap");
    }
    const std::size_t frame_size = ZSTD_findFrameCompressedSize(frame.data(), frame.size());
    if (ZSTD_isError(frame_size)) {
        return fail("proxy frame malformed or incomplete");
    }
    if (frame_size != frame.size()) {
        return fail("proxy frame has trailing or concatenated bytes");
    }
    return true;
}

bool compress_proxy_frame(const citra_room::Bytes& plain, std::size_t compressed_cap,
                          int level, room_client::Bytes& out, std::string* why) {
    if (plain.empty()) {
        if (why != nullptr) {
            *why = "empty payload";
        }
        return false;
    }
    const std::size_t bound = ZSTD_compressBound(plain.size());
    if (bound > compressed_cap) {
        if (why != nullptr) {
            *why = "payload compression bound over compressed cap";
        }
        return false;
    }
    out.assign(bound, 0);
    const std::size_t written =
        ZSTD_compress(out.data(), out.size(), plain.data(), plain.size(), level);
    if (ZSTD_isError(written)) {
        if (why != nullptr) {
            *why = std::string("zstd compress failed: ") + ZSTD_getErrorName(written);
        }
        return false;
    }
    out.resize(written);
    if (!valid_proxy_frame(out, compressed_cap, plain.size(), why)) {
        return false;
    }
    return true;
}

bool decompress_proxy_frame(const room_client::Bytes& frame, std::size_t decompressed_cap,
                            citra_room::Bytes& out, std::string* why) {
    if (!valid_proxy_frame(frame, frame.size(), decompressed_cap, why)) {
        return false;
    }
    const unsigned long long content = ZSTD_getFrameContentSize(frame.data(), frame.size());
    out.assign(static_cast<std::size_t>(content), 0);
    // Even FCS=0 must reach the decoder: frame-size checks alone cannot
    // validate content or an optional checksum. Use a valid zero-capacity
    // destination without relying on empty vector::data() being non-null.
    std::uint8_t empty_destination = 0;
    const std::size_t written =
        ZSTD_decompress(out.empty() ? &empty_destination : out.data(), out.size(),
                        frame.data(), frame.size());
    if (ZSTD_isError(written)) {
        if (why != nullptr) {
            *why = std::string("zstd decompress failed: ") + ZSTD_getErrorName(written);
        }
        return false;
    }
    if (written != content) {
        if (why != nullptr) {
            *why = "zstd decompressed size mismatch";
        }
        return false;
    }
    out.resize(written);
    return true;
}

bool is_valid_nickname(const std::string& nickname) {
    if (nickname.size() < 4 || nickname.size() > 20) {
        return false;
    }
    for (const char raw : nickname) {
        const unsigned char ch = static_cast<unsigned char>(raw);
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == ' ' || ch == '.' || ch == '_' ||
                        ch == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

class Gateway::Impl {
public:
    explicit Impl(Options options) : options_(std::move(options)), start_ms_(now_ms()) {
        if (options_.ldn_dual_host) {
            options_.ldn_gu_host_discovery = options_.ldn_gu_host_admission = true;
            options_.ldn_require_live_hall = options_.ldn_announce_forward = true;
            options_.ldn_guest_inject = options_.ldn_game_return = true;
        }
    }
    ~Impl() { close(); }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    void open() {
        if (const char* error = gateway_capability_error(options_.application_mode, options_.proxy_wire_profile)) {
            throw std::runtime_error(error);
        }
        if (open_) {
            throw std::runtime_error("gateway is already open");
        }
        in_addr parsed{};
        if (::inet_pton(AF_INET, options_.listen_address.c_str(), &parsed) != 1) {
            throw std::runtime_error("listen address is not a numeric IPv4 literal: " +
                                     options_.listen_address);
        }
        const std::uint32_t host_order = ntohl(parsed.s_addr);
        if ((host_order >> 24) != 127U && !options_.allow_remote_listen) {
            throw std::runtime_error("refusing to listen on a non loopback address: " +
                                     options_.listen_address);
        }
        if (!options_.trace_path.empty()) {
            std::string trace_why;
            if (!trace_.open(options_.trace_path, options_.trace_raw, &trace_why)) {
                throw std::runtime_error(trace_why);
            }
            add_event("trace.open", 0, options_.trace_path);
        }
        if (options_.citra_tcp_test_transport) {
            open_tcp_test_listener(parsed);
        } else {
            open_enet_listener();
        }
        open_ = true;
        add_event("gateway.open", 0,
                  options_.listen_address + ":" + std::to_string(bound_port_) + " (" +
                      std::string(citra_transport_name()) + ")");
        if (trace_.enabled()) {
            // A run with zero frames must still identify itself: pick up the
            // initial stage (if a stage file was supplied) and write exactly one
            // run.begin marker before any frame can be traced.
            trace_refresh_stage(false);
            trace_write_marker("run.begin");
        }
    }

    // Deliverable Citra-side listener (G-c / V-027). A real Citra is an ENet/UDP
    // client (citra-master/src/network/room_member.cpp:553-563) and the real room
    // server is an ENet/UDP server with citra_room::num_channels channels
    // (citra-master/src/network/room.cpp:1026), so the gateway binds an ENet host
    // on --listen/--listen-port and gives every session exactly one peer. The
    // payloads are raw citra_room v4 frames: no length prefix, one reliable
    // packet per frame.
    void open_enet_listener() {
        ensure_enet_runtime();
        ENetAddress address{};
        if (enet_address_set_host_ip(&address, options_.listen_address.c_str()) != 0) {
            throw std::runtime_error("cannot resolve listen address " + options_.listen_address);
        }
        address.port = options_.listen_port;
        enet_host_ = enet_host_create(&address, options_.max_clients + 1,
                                      static_cast<std::size_t>(citra_room::num_channels), 0, 0);
        if (enet_host_ == nullptr) {
            ++counters_.port_conflicts;
            throw std::runtime_error("ENet/UDP bind failed on " + options_.listen_address + ":" +
                                     std::to_string(options_.listen_port) +
                                     " (port conflict, no silent fallback)");
        }
        enet_host_->maximumPacketSize =
            static_cast<enet_uint32>(options_.max_frame_bytes + 4096);
        enet_host_->maximumWaitingData =
            static_cast<enet_uint32>(options_.per_client_inbox_bytes);
        bound_port_ = enet_host_->address.port;
    }

    // HARNESS ONLY (Options::citra_tcp_test_transport): the legacy TCP listener
    // with 4-byte big-endian length-prefix framing. No CLI flag reaches it; it
    // exists so the deterministic A1..A10 / B1 / B2 groups keep their exact
    // evidence while the deliverable path is the ENet server above.
    void open_tcp_test_listener(const in_addr& parsed) {
        WSADATA wsa{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
        wsa_started_ = true;

        SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            const int error = ::WSAGetLastError();
            throw std::runtime_error("socket() failed with WSA error " + std::to_string(error));
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(options_.listen_port);
        address.sin_addr = parsed;
        if (::bind(sock, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ==
            SOCKET_ERROR) {
            const int error = ::WSAGetLastError();
            ::closesocket(sock);
            ++counters_.port_conflicts;
            throw std::runtime_error("bind failed on " + options_.listen_address + ":" +
                                     std::to_string(options_.listen_port) +
                                     " (port conflict, no silent fallback), WSA error " +
                                     std::to_string(error));
        }
        if (::listen(sock, SOMAXCONN) == SOCKET_ERROR) {
            const int error = ::WSAGetLastError();
            ::closesocket(sock);
            throw std::runtime_error("listen() failed with WSA error " + std::to_string(error));
        }
        sockaddr_in bound{};
        int bound_len = sizeof(bound);
        if (::getsockname(sock, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0) {
            bound_port_ = ntohs(bound.sin_port);
        } else {
            bound_port_ = options_.listen_port;
        }
        u_long non_blocking = 1;
        ::ioctlsocket(sock, FIONBIO, &non_blocking);
        listener_ = sock;
    }

    void tick(std::uint32_t wait_ms) {
        if (!open_) {
            return;
        }
        trace_refresh_stage(true);
        accept_ready();
        service_citra_enet();
        for (std::size_t i = 0; i < clients_.size(); ++i) {
            Client& client = *clients_[i];
            if (client.phase == ClientPhase::Closed) {
                continue;
            }
            if (options_.ldn_dual_host && client.phase == ClientPhase::Joined && client.dual_citra_host &&
                now_ms() - client.dual_last_beacon_ms > kCitraAppdataMaxAgeMs) reset_dual_role(client);
            if (client.control && client.phase == ClientPhase::Joined) {
                // Beacons are rate limited inside the bridge; emitting before
                // pump_client lets the same tick flush them to the Citra socket.
                emit_control(client, client.control->tick(now_ms()));
                // V-112: after the bridge's own emissions so a script step that
                // fires on the join tick lands in the same pump_client flush.
                run_game_script(client, now_ms());
            }
            pump_client(client);
        }
        reap();
        if (wait_ms > 0) {
            Sleep(1);
        }
    }

    void close() noexcept {
        for (auto& client : clients_) {
            if (client->phase != ClientPhase::Closed) {
                release_room_peer(*client);
                release_citra_transport(*client);
                if (client->sock != INVALID_SOCKET) {
                    ::closesocket(client->sock);
                    client->sock = INVALID_SOCKET;
                }
                client->phase = ClientPhase::Closed;
            }
        }
        clients_.clear();
        if (listener_ != INVALID_SOCKET) {
            ::closesocket(listener_);
            listener_ = INVALID_SOCKET;
        }
        if (enet_host_ != nullptr) {
            enet_host_destroy(enet_host_);
            enet_host_ = nullptr;
        }
        open_ = false;
        if (wsa_started_) {
            ::WSACleanup();
            wsa_started_ = false;
        }
        identities_.clear();
        trace_.close();
    }

    void begin_shutdown() noexcept {
        if (!closing_) {
            closing_ = true;
            add_event("gateway.shutdown", 0, "closing flag set");
        }
    }

    bool is_open() const noexcept { return open_; }
    std::uint16_t port() const noexcept { return bound_port_; }
    bool trace_enabled() const noexcept { return trace_.enabled(); }

    // Effective G2 run identity, as one JSON object. Used by the CLI identity
    // line and the optional trace.json dump.
    std::string trace_json() const {
        std::string json = "{";
        json += "\"enabled\":";
        json += trace_.enabled() ? "true" : "false";
        json += ",\"raw_enabled\":";
        json += trace_.raw_enabled() ? "true" : "false";
        json += ",\"path\":" + quote(trace_.path());
        json += ",\"manifest_id\":" + quote(options_.trace_context.manifest_id);
        json += ",\"run_id\":" + quote(options_.trace_context.run_id);
        json += ",\"channel\":" + quote(options_.trace_context.channel);
        json += ",\"platform\":" + quote(options_.trace_context.platform);
        json += ",\"build_id\":" + quote(options_.trace_context.build_id);
        json += ",\"role\":" + quote(options_.trace_context.role);
        json += ",\"stage\":" + quote(options_.trace_context.stage);
        json += "}";
        return json;
    }

    std::size_t client_count() const noexcept { return clients_.size(); }

    Counters counters() const { return counters_; }

    std::vector<ClientSnapshot> clients() const {
        std::vector<ClientSnapshot> out;
        out.reserve(clients_.size());
        for (const auto& client : clients_) {
            ClientSnapshot snapshot;
            snapshot.id = client->id;
            snapshot.nickname = client->nickname;
            snapshot.phase = phase_name(client->phase);
            snapshot.transport = client->enet ? "enet" : "tcp";
            snapshot.mac_known = client->mac_known;
            snapshot.mac = client->mac_known ? mac_to_string(client->mac) : std::string();
            snapshot.ip_known = client->ip_known;
            snapshot.fake_ip = client->ip_known ? ip_to_string(client->fake_ip) : std::string();
            snapshot.failure = client->failure;
            snapshot.frames_in = client->frames_in;
            snapshot.frames_out = client->frames_out;
            snapshot.frames_rejected = client->frames_rejected;
            snapshot.room_frames_rejected = client->room_frames_rejected;
            snapshot.transport_boundary_rejections = client->last_boundary;
            snapshot.queued_out_bytes = client->outbox_bytes;
            if (client->transport) {
                const auto room_snapshot = client->transport->snapshot();
                snapshot.room_state = room_transport::state_name(room_snapshot.state);
            } else {
                snapshot.room_state = "None";
            }
            out.push_back(std::move(snapshot));
        }
        return out;
    }

    std::vector<IdentityEntry> identities() const { return identities_.entries(); }

    std::vector<DataPlaneCapture> captures() const {
        return std::vector<DataPlaneCapture>(captures_.begin(), captures_.end());
    }
    void clear_captures() { captures_.clear(); }

    std::vector<Event> events() const {
        return std::vector<Event>(events_.begin(), events_.end());
    }

    bool inject_room_message_for_test(std::uint64_t client_id,
                                      const room_client::Message& message) {
        room_client::Bytes frame;
        try {
            frame = room_client::encode(message, room_client::Direction::ServerToClient);
        } catch (const std::exception& error) {
            add_event("inject.encode.failed", client_id, error.what());
            return false;
        }
        return inject_room_raw_for_test(client_id, frame);
    }

    bool inject_room_raw_for_test(std::uint64_t client_id, const room_client::Bytes& raw_frame) {
        Client* client = find_client(client_id);
        if (client == nullptr || !client->transport) {
            return false;
        }
        bool accepted = true;
        try {
            accepted = client->transport->inject_inbound_for_test(raw_frame);
        } catch (const std::exception& error) {
            // A malformed injected room frame must never terminate the gateway.
            add_event("inject.room.rejected", client->id, error.what());
            accepted = false;
        }
        absorb_transport_boundary(*client);
        drain_room(*client);
        if (client->transport &&
            client->transport->snapshot().state == room_transport::State::Failed) {
            handle_room_failure(*client, client->transport->snapshot());
        }
        return accepted;
    }

    const std::vector<EmittedFrame>& emitted_frames() const { return emitted_; }

    std::string emitted_json() const {
        const auto render = [](const EmittedFrame& frame) {
            return join_fields({
                {"seq", std::to_string(frame.seq)},
                {"time_ms", std::to_string(frame.time_ms)},
                {"client_id", std::to_string(frame.client_id)},
                {"direction", quote(frame.direction)},
                {"kind", quote(frame.kind)},
                {"bytes", std::to_string(frame.bytes)},
                {"hex", quote(frame.hex)},
            });
        };
        return json_array<EmittedFrame>(emitted_frames(), render);
    }

    void clear_emitted_for_test() { emitted_.clear(); }

    bool inject_citra_frame_for_test(std::uint64_t client_id, const citra_room::Bytes& frame) {
        Client* client = find_client(client_id);
        if (client == nullptr) {
            return false;
        }
        handle_citra_frame(*client, frame);
        return true;
    }

    bool inject_ldn_message_for_test(std::uint64_t client_id, const room_client::LdnPacket& packet) {
        Client* client = find_client(client_id);
        if (client == nullptr) {
            return false;
        }
        const room_client::Message message = packet;
        handle_room_message(*client, message);
        return true;
    }

    // V-262: per-frame-type census and bounded raw samples of the Citra wire.
    std::string inbound_json() const {
        std::ostringstream out;
        out << "{\"by_type\":{";
        bool first = true;
        for (const auto& [type, count] : inbound_by_type_) {
            if (!first) {
                out << ",";
            }
            first = false;
            out << quote(type) << ":" << count;
        }
        out << "},\"samples\":{";
        first = true;
        for (const auto& [type, list] : inbound_samples_) {
            if (!first) {
                out << ",";
            }
            first = false;
            out << quote(type) << ":[";
            bool first_sample = true;
            for (const auto& sample : list) {
                if (!first_sample) {
                    out << ",";
                }
                first_sample = false;
                out << "{\"transmitter\":" << quote(sample.transmitter)
                    << ",\"destination\":" << quote(sample.destination)
                    << ",\"channel\":" << static_cast<int>(sample.channel)
                    << ",\"bytes\":" << sample.bytes
                    << ",\"data_hex\":" << quote(sample.data_hex) << sample.extra_json << "}";
            }
            out << "]";
        }
        out << "}}";
        return out.str();
    }

    void note_inbound_wifi(const citra_room::WifiPacket& wifi) {
        const std::string type = citra_room::frame_type_name(wifi.type);
        ++inbound_by_type_[type];
        auto& list = inbound_samples_[type];
        if (list.size() >= 3) {
            return;
        }
        InboundWifiSample sample;
        sample.transmitter = mac_to_string(wifi.transmitter);
        sample.destination = mac_to_string(wifi.destination);
        sample.channel = wifi.channel;
        sample.bytes = wifi.data.size();
        sample.data_hex = hex_of(wifi.data, 1200);
        if (wifi.type == citra_room::FrameType::Beacon) {
            const auto beacon = citra_control::parse_beacon_frame(
                wifi.data.data(), wifi.data.size(), wifi.transmitter, nullptr);
            if (beacon.ok()) {
                const auto& info = beacon.value.network_info;
                const std::size_t app_bytes = std::min<std::size_t>(
                    info.application_data_size, info.application_data.size());
                const citra_room::Bytes app(info.application_data.begin(),
                                            info.application_data.begin() + app_bytes);
                sample.extra_json =
                    ",\"beacon\":{\"network_id\":" + std::to_string(info.network_id) +
                    ",\"wlan_comm_id\":" + std::to_string(info.wlan_comm_id) +
                    ",\"channel\":" + std::to_string(info.channel) +
                    ",\"total_nodes\":" + std::to_string(info.total_nodes) +
                    ",\"max_nodes\":" + std::to_string(info.max_nodes) +
                    ",\"host_mac\":" + quote(mac_to_string(info.host_mac_address)) +
                    ",\"appdata_size\":" + std::to_string(info.application_data_size) +
                    ",\"appdata_hex\":" + quote(hex_of(app, 200)) + "}";
            } else {
                sample.extra_json = ",\"beacon\":{\"parse\":\"failed\"}";
            }
        }
        list.push_back(std::move(sample));
    }

    std::string counters_json() const {
        std::vector<std::pair<std::string, std::string>> fields;
        const auto add = [&](const char* name, std::uint64_t value) {
            fields.emplace_back(name, std::to_string(value));
        };
        add("clients_accepted", counters_.clients_accepted);
        add("clients_rejected_full", counters_.clients_rejected_full);
        add("clients_rejected_local", counters_.clients_rejected_local);
        add("clients_joined", counters_.clients_joined);
        add("clients_left", counters_.clients_left);
        add("clients_closed_by_gateway", counters_.clients_closed_by_gateway);
        add("frames_in", counters_.frames_in);
        add("frames_out", counters_.frames_out);
        add("frames_rejected", counters_.frames_rejected);
        add("game_script_frames_sent", counters_.game_script_frames_sent);
        add("game_script_nonce_learned", counters_.game_script_nonce_learned);
        add("game_script_frames_patched", counters_.game_script_frames_patched);
        add("game_script_nonce_waits", counters_.game_script_nonce_waits);
        add("game_script_tokens_learned", counters_.game_script_tokens_learned);
        add("game_script_token_frames_patched", counters_.game_script_token_frames_patched);
        add("game_script_token_waits", counters_.game_script_token_waits);
        add("prefix_truncation_rejections", counters_.prefix_truncation_rejections);
        add("wrong_direction_rejections", counters_.wrong_direction_rejections);
        add("unknown_id_rejections", counters_.unknown_id_rejections);
        add("unknown_enum_rejections", counters_.unknown_enum_rejections);
        add("trailing_byte_rejections", counters_.trailing_byte_rejections);
        add("malformed_frame_rejections", counters_.malformed_frame_rejections);
        add("limit_exceeded_rejections", counters_.limit_exceeded_rejections);
        add("oversize_rejections", counters_.oversize_rejections);
        add("sentinel_mac_rejections", counters_.sentinel_mac_rejections);
        add("unsupported_in_phase_rejections", counters_.unsupported_in_phase_rejections);
        add("local_version_rejections", counters_.local_version_rejections);
        add("local_mac_collision_rejections", counters_.local_mac_collision_rejections);
        add("local_console_id_collision_rejections",
            counters_.local_console_id_collision_rejections);
        add("no_correspondence_rejections", counters_.no_correspondence_rejections);
        add("local_closing_rejections", counters_.local_closing_rejections);
        add("local_join_rejections", counters_.local_join_rejections);
        add("local_room_full_rejections", counters_.local_room_full_rejections);
        add("local_wrong_password_rejections", counters_.local_wrong_password_rejections);
        add("local_name_collision_rejections", counters_.local_name_collision_rejections);
        add("room_join_attempts", counters_.room_join_attempts);
        add("room_join_successes", counters_.room_join_successes);
        add("room_join_failures", counters_.room_join_failures);
        add("room_errors_mapped", counters_.room_errors_mapped);
        add("room_errors_unmapped", counters_.room_errors_unmapped);
        add("room_transport_failures", counters_.room_transport_failures);
        add("room_frames_rejected", counters_.room_frames_rejected);
        add("join_watchdog_timeouts", counters_.join_watchdog_timeouts);
        add("transport_boundary_rejections", counters_.transport_boundary_rejections);
        add("proxy_frames_emitted", counters_.proxy_frames_emitted);
        add("proxy_frames_consumed", counters_.proxy_frames_consumed);
        add("payload_forwarded", counters_.payload_forwarded);
        add("payload_rejected_unknown_category", counters_.payload_rejected_unknown_category);
        add("payload_rejected_boundary", counters_.payload_rejected_boundary);
        add("payload_rejected_source", counters_.payload_rejected_source);
        add("payload_rejected_destination", counters_.payload_rejected_destination);
        add("channel_normalized", counters_.channel_normalized);
        add("peer_relay_frames_emitted", counters_.peer_relay_frames_emitted);
        add("peer_relay_frames_consumed", counters_.peer_relay_frames_consumed);
        add("peer_relay_bad_wrapper", counters_.peer_relay_bad_wrapper);
        add("set_game_info_accepted", counters_.set_game_info_accepted);
        add("set_game_info_deferred", counters_.set_game_info_deferred);
        add("set_game_info_replaced", counters_.set_game_info_replaced);
        add("set_game_info_discarded", counters_.set_game_info_discarded);
        add("set_game_info_rejected", counters_.set_game_info_rejected);
        add("set_game_info_version_placeholder", counters_.set_game_info_version_placeholder);
        add("destination_unmapped_rejections", counters_.destination_unmapped_rejections);
        add("self_echo_rejections", counters_.self_echo_rejections);
        add("unknown_source_rejections", counters_.unknown_source_rejections);
        add("queue_overflows", counters_.queue_overflows);
        add("outbox_overflows", counters_.outbox_overflows);
        add("inbox_overflows", counters_.inbox_overflows);
        add("mac_generated", counters_.mac_generated);
        add("ip_reassigned", counters_.ip_reassigned);
        add("unmappable_room_members", counters_.unmappable_room_members);
        add("projection_missing_self", counters_.projection_missing_self);
        add("port_conflicts", counters_.port_conflicts);
        add("events_dropped", counters_.events_dropped);
        add("citra_enet_connects", counters_.citra_enet_connects);
        add("citra_enet_disconnects", counters_.citra_enet_disconnects);
        add("citra_enet_receives", counters_.citra_enet_receives);
        add("citra_enet_rejected_full", counters_.citra_enet_rejected_full);
        add("citra_tcp_accepts", counters_.citra_tcp_accepts);
        add("members_in_room", counters_.members_in_room);
        add("max_members_in_room", counters_.max_members_in_room);
        add("room_version_forwarded", counters_.room_version_forwarded);
        add("citra_version_served", counters_.citra_version_served);

        std::ostringstream errors;
        errors << "{";
        bool first = true;
        for (const auto& [key, value] : counters_.decode_error_codes) {
            if (!first) {
                errors << ",";
            }
            first = false;
            errors << quote(key) << ":" << value;
        }
        errors << "}";
        fields.emplace_back("decode_error_codes", errors.str());

        std::ostringstream mapped;
        mapped << "{";
        first = true;
        for (const auto& [key, value] : counters_.error_map_hits) {
            if (!first) {
                mapped << ",";
            }
            first = false;
            mapped << quote(key) << ":" << value;
        }
        mapped << "}";
        fields.emplace_back("error_map_hits", mapped.str());

        // Control-plane counters are cumulative: the counters of a session that has
        // already been torn down are folded into control_cumulative_ when the session
        // closes, so a dump taken after a client left still reports what the bridge did.
        std::map<std::string, std::uint64_t> control = control_cumulative_;
        std::size_t live_control_sessions = 0;
        for (const std::string& key : control_counter_keys()) {
            if (control.find(key) == control.end()) {
                control[key] = 0;
            }
        }
        for (const auto& client : clients_) {
            if (!client || !client->control) {
                continue;
            }
            ++live_control_sessions;
            for (const auto& [key, value] : client->control->counters()) {
                control[key] += value;
            }
        }
        fields.emplace_back("control", control_counters_json(control));
        // V-261: the announce forward's reasons live in the control bridge, which
        // counters.json never carried.  A live session's samples are enough for a
        // run diagnosis; cumulative sessions are not merged.
        std::string samples_json = "{}";
        for (const auto& client : clients_) {
            if (client && client->control) {
                samples_json = client->control->data_frame_samples_json();
                break;
            }
        }
        fields.emplace_back("data_frame_samples", samples_json);
        fields.emplace_back("control_scope", quote("cumulative"));
        fields.emplace_back("control_sessions_live", std::to_string(live_control_sessions));
        fields.emplace_back("control_sessions_departed", std::to_string(control_departed_sessions_));

        fields.emplace_back("citra_transport", quote(citra_transport_name()));
        fields.emplace_back("listen_address", quote(options_.listen_address));
        fields.emplace_back("listen_port", std::to_string(bound_port_));
        fields.emplace_back("room_address", quote(options_.room_address));
        fields.emplace_back("room_port", std::to_string(options_.room_port));
        return join_fields(fields);
    }

    // V-261: the diagnostic document is the counters document -- it already
    // carries the merged control counters and the Data frame samples.  It is
    // written separately (diag.json) so counters.json keeps its frozen key set.
    std::string diag_text() const { return counters_json(); }

    std::string clients_json() const {
        const auto render = [](const ClientSnapshot& snapshot) {
            return join_fields({
                {"id", std::to_string(snapshot.id)},
                {"nickname", quote(snapshot.nickname)},
                {"phase", quote(snapshot.phase)},
                {"transport", quote(snapshot.transport)},
                {"mac_known", snapshot.mac_known ? "true" : "false"},
                {"mac", quote(snapshot.mac)},
                {"ip_known", snapshot.ip_known ? "true" : "false"},
                {"fake_ip", quote(snapshot.fake_ip)},
                {"room_state", quote(snapshot.room_state)},
                {"failure", quote(snapshot.failure)},
                {"frames_in", std::to_string(snapshot.frames_in)},
                {"frames_out", std::to_string(snapshot.frames_out)},
                {"frames_rejected", std::to_string(snapshot.frames_rejected)},
                {"room_frames_rejected", std::to_string(snapshot.room_frames_rejected)},
                {"transport_boundary_rejections",
                 std::to_string(snapshot.transport_boundary_rejections)},
                {"queued_out_bytes", std::to_string(snapshot.queued_out_bytes)},
            });
        };
        // Departed sessions are appended (phase "Departed", departed true) so a
        // dump taken after a client left still carries its nickname, MAC and fake
        // IPv4. Live entries always come first.
        std::string departed;
        for (const SessionRecord& record : session_ledger_) {
            if (!departed.empty()) {
                departed += ",";
            }
            departed += session_record_json(record);
        }
        return append_departed(json_array<ClientSnapshot>(clients(), render), departed);
    }

    std::string identities_json() const {
        const auto render = [](const IdentityEntry& entry) {
            return join_fields({
                {"mac", quote(mac_to_string(entry.mac))},
                {"fake_ip", quote(ip_to_string(entry.fake_ip))},
                {"nickname", quote(entry.nickname)},
            });
        };
        std::string departed;
        for (const SessionRecord& record : session_ledger_) {
            if (!record.mac_known && !record.ip_known) {
                continue;
            }
            if (!departed.empty()) {
                departed += ",";
            }
            departed += join_fields({
                    {"mac", quote(record.mac_known ? mac_to_string(record.mac) : std::string())},
                    {"fake_ip",
                     quote(record.ip_known ? ip_to_string(record.fake_ip) : std::string())},
                    {"assigned_fake_ip",
                     quote(record.ip_known ? ip_to_string(record.fake_ip) : std::string())},
                    {"ipv4_address",
                     quote(record.ip_known ? ip_to_string(record.fake_ip) : std::string())},
                    {"nickname", quote(record.nickname)},
                    {"departed", "true"},
                    {"live", "false"},
                    {"joined_room", record.joined_room ? "true" : "false"},
                    {"departed_at_ms", std::to_string(record.departed_at_ms)},
            });
        }
        return append_departed(json_array<IdentityEntry>(identities(), render), departed);
    }

    std::string captures_json() const {
        const auto render = [](const DataPlaneCapture& capture) {
            return join_fields({
                {"direction", quote(capture.direction)},
                {"client_id", std::to_string(capture.client_id)},
                {"broadcast", capture.broadcast ? "true" : "false"},
                {"source_mac", quote(capture.source_mac)},
                {"destination_mac", quote(capture.destination_mac)},
                {"source_ip", quote(capture.source_ip)},
                {"destination_ip", quote(capture.destination_ip)},
                {"wire_bytes", std::to_string(capture.wire_bytes)},
                {"content_bytes", std::to_string(capture.content_bytes)},
                {"opaque_bytes", std::to_string(capture.opaque_bytes)},
                {"opaque_hex", quote(capture.opaque_hex)},
            });
        };
        return json_array<DataPlaneCapture>(captures(), render);
    }

    std::string events_json() const {
        const auto render = [](const Event& event) {
            return join_fields({
                {"seq", std::to_string(event.seq)},
                {"time_ms", std::to_string(event.time_ms)},
                {"kind", quote(event.kind)},
                {"client_id", std::to_string(event.client_id)},
                {"detail", quote(event.detail)},
            });
        };
        return json_array<Event>(events(), render);
    }

    std::string snapshot_json() const {
        // V-243: surface the cross-game session phase of the first live control
        // bridge (ApStandby until a Yuzu client connects).
        std::string session_phase;
        for (const auto& client : clients_) {
            if (client && client->control && client->phase != ClientPhase::Closed) {
                session_phase = client->control->session_phase();
                break;
            }
        }
        if (session_phase.empty()) {
            session_phase = "None";
        }
        return "{\"counters\":" + counters_json() + ",\"clients\":" + clients_json() +
               ",\"identities\":" + identities_json() + ",\"captures\":" + captures_json() +
               ",\"events\":" + events_json() + ",\"session_phase\":\"" + session_phase + "\"}";
    }

    std::optional<room_client::ProxyPacket> last_forwarded_proxy() const {
        return last_forwarded_proxy_;
    }
    std::optional<room_client::ProxyPacket> last_inbound_proxy() const {
        return last_inbound_proxy_;
    }

private:
    struct Client {
        std::uint64_t id = 0;
        SOCKET sock = INVALID_SOCKET;
        // Citra-side transport of this session: true = ENet/UDP (the deliverable
        // path), false = the test-only TCP length-prefix framing.
        bool enet = false;
        ENetPeer* peer = nullptr;
        std::size_t inbox_bytes = 0;
        std::deque<citra_room::Bytes> enet_frames;
        ClientPhase phase = ClientPhase::Framing;
        std::vector<std::uint8_t> inbox;
        std::deque<room_client::Bytes> outbox;
        std::size_t outbox_bytes = 0;
        std::string nickname;
        std::string console_id_hash; // local only; never forwarded or logged
        MacAddress mac{};
        bool mac_known = false;
        IPv4 fake_ip{};
        bool ip_known = false;
        std::unique_ptr<room_transport::Transport> transport;
        // Native Citra sends this immediately after JoinRequest, before the
        // asynchronous upstream join can finish. Keep only the latest value.
        std::optional<citra_room::GameInfo> pending_game_info;
        // G-b' per-session control-plane bridge. Null unless
        // Options::control_plane_enabled and this session has joined.
        std::unique_ptr<ControlBridge> control;
        bool dual_citra_host = false;
        std::optional<MacAddress> dual_local_host;
        std::optional<citra_control::EapolNodeInfo> dual_local_identity;
        std::uint16_t dual_local_node_id = 0;
        std::uint64_t dual_last_beacon_ms = 0, dual_host_seed = 0;
        std::uint32_t dual_host_network = 0;
        std::uint8_t dual_host_channel = 6;
        // V-274: separate RF and UDS data channels learned from a validated
        // host game frame. Never infer these from ProxyPacket port or CRLY.
        bool return_profile_known = false;
        std::uint8_t return_data_channel = 0;
        std::uint8_t return_wifi_channel = 0;
        std::optional<std::uint32_t> return_network_id;
        std::size_t last_boundary = 0;
        std::string failure;
        std::uint64_t close_deadline = 0;
        std::uint64_t join_started = 0;
        std::uint64_t frames_in = 0;
        std::uint64_t frames_out = 0;
        std::uint64_t frames_rejected = 0;
        std::uint64_t room_frames_rejected = 0;
        bool counted_leave = false;
        // Session ledger bookkeeping (relative to start_ms_).
        std::uint64_t accepted_at = 0;
        std::uint64_t joined_at = 0;
        bool joined_room = false;
        bool departed_recorded = false;
        // V-112 synthetic-host game-layer script state (Options::game_script).
        // script_join_ms is when the control plane reported the guest Connected
        // (its EAPoL-Start); script_guest_ms keeps the arrival times of the
        // guest's own game-layer frames so a step can be anchored to the N-th
        // one. All of it stays unused while the script is empty.
        bool script_join_known = false;
        std::uint64_t script_join_ms = 0;
        std::size_t script_pos = 0;
        bool script_due_known = false;
        std::uint64_t script_due_ms = 0;
        std::size_t script_sent = 0;
        std::vector<std::uint64_t> script_guest_ms;
        // V-132: the guest's own nonce family value (Options::game_nonce_ref).
        // script_nonce is the most recent value the guest announced and the
        // replay echoes it back; script_wait_logged keeps the "held for the
        // guest's nonce" event to one per step.
        bool script_nonce_known = false;
        std::uint32_t script_nonce = 0;
        bool script_wait_logged = false;
        // V-133: live values of Options::game_token_refs, indexed in the same
        // order; script_token_known marks the ones the guest announced.
        std::vector<std::uint32_t> script_tokens;
        std::vector<bool> script_token_known;
    };

    // Cumulative session ledger (G-c defect 1): a --dump written after a client
    // left must still report that client's identity, its fake IPv4 and what its
    // control-plane bridge did. One record per session that reached the v4 join
    // stage, filled in when the session closes. The control counters of a
    // departed session are folded into control_cumulative_ at the same time.
    struct SessionRecord {
        std::uint64_t id = 0;
        std::string nickname;
        std::string transport;
        bool mac_known = false;
        MacAddress mac{};
        bool ip_known = false;
        IPv4 fake_ip{};
        std::string room_state;
        std::string failure;
        bool joined_room = false;
        std::uint64_t accepted_at_ms = 0;
        std::uint64_t joined_at_ms = 0;
        std::uint64_t departed_at_ms = 0;
        std::uint64_t frames_in = 0;
        std::uint64_t frames_out = 0;
        std::uint64_t frames_rejected = 0;
        std::uint64_t room_frames_rejected = 0;
        std::uint64_t transport_boundary_rejections = 0;
        bool console_id_hash_present = false;
        std::map<std::string, std::uint64_t> control;
    };

    std::string session_record_json(const SessionRecord& record) const {
        return join_fields({
            {"id", std::to_string(record.id)},
            {"nickname", quote(record.nickname)},
            {"phase", quote("Departed")},
            {"departed", "true"},
            {"live", "false"},
            {"transport", quote(record.transport)},
            {"mac_known", record.mac_known ? "true" : "false"},
            {"mac", quote(record.mac_known ? mac_to_string(record.mac) : std::string())},
            {"ip_known", record.ip_known ? "true" : "false"},
            {"fake_ip", quote(record.ip_known ? ip_to_string(record.fake_ip) : std::string())},
            {"assigned_fake_ip",
             quote(record.ip_known ? ip_to_string(record.fake_ip) : std::string())},
            {"ipv4_address", quote(record.ip_known ? ip_to_string(record.fake_ip) : std::string())},
            {"room_state", quote(record.room_state)},
            {"failure", quote(record.failure)},
            {"joined_room", record.joined_room ? "true" : "false"},
            {"accepted_at_ms", std::to_string(record.accepted_at_ms)},
            {"joined_at_ms", std::to_string(record.joined_at_ms)},
            {"departed_at_ms", std::to_string(record.departed_at_ms)},
            {"frames_in", std::to_string(record.frames_in)},
            {"frames_out", std::to_string(record.frames_out)},
            {"frames_rejected", std::to_string(record.frames_rejected)},
            {"room_frames_rejected", std::to_string(record.room_frames_rejected)},
            {"transport_boundary_rejections",
             std::to_string(record.transport_boundary_rejections)},
            {"queued_out_bytes", "0"},
            // console_id_hash is a local admission control value: the room
            // protocol has no counterpart, so only its presence is reported.
            {"console_id_hash_local_only", "true"},
            {"console_id_hash_present", record.console_id_hash_present ? "true" : "false"},
            {"control", control_counters_json(record.control)},
        });
    }

    // Appends ledger entries to a live JSON array, keeping the document a valid
    // JSON array even when every session has already gone.
    static std::string append_departed(const std::string& live_array, const std::string& entries) {
        if (entries.empty()) {
            return live_array;
        }
        if (live_array.size() <= 2) {
            return "[" + entries + "]";
        }
        std::string text = live_array;
        text.insert(text.size() - 1, "," + entries);
        return text;
    }

    // Departure funnel: runs while the session's identity, transport and control
    // bridge still exist, and exactly once per session.
    void record_departure(Client& client) {
        if (client.departed_recorded) {
            return;
        }
        client.departed_recorded = true;
        if (client.nickname.empty() && !client.mac_known && !client.ip_known) {
            // A socket that never spoke v4 carries no identity worth keeping.
            return;
        }
        SessionRecord record;
        record.id = client.id;
        record.nickname = client.nickname;
        record.transport = client.enet ? "enet" : "tcp";
        record.mac_known = client.mac_known;
        record.mac = client.mac;
        record.ip_known = client.ip_known;
        record.fake_ip = client.fake_ip;
        record.room_state = "None";
        if (client.transport) {
            try {
                record.room_state = room_transport::state_name(client.transport->snapshot().state);
            } catch (...) {
                record.room_state = "Unknown";
            }
        }
        record.failure = client.failure;
        record.joined_room = client.joined_room;
        record.accepted_at_ms = client.accepted_at;
        record.joined_at_ms = client.joined_at;
        record.departed_at_ms = now_ms() - start_ms_;
        record.frames_in = client.frames_in;
        record.frames_out = client.frames_out;
        record.frames_rejected = client.frames_rejected;
        record.room_frames_rejected = client.room_frames_rejected;
        record.transport_boundary_rejections = client.last_boundary;
        record.console_id_hash_present = !client.console_id_hash.empty();
        if (client.control) {
            record.control = client.control->counters();
            for (const std::string& key : control_counter_keys()) {
                if (control_cumulative_.find(key) == control_cumulative_.end()) {
                    control_cumulative_[key] = 0;
                }
                const auto found = record.control.find(key);
                control_cumulative_[key] += (found == record.control.end()) ? 0 : found->second;
            }
            ++control_departed_sessions_;
            // The bridge of a closed session is dropped: its counters live on in
            // control_cumulative_ so a later dump never reports zero.
            client.control.reset();
        }
        session_ledger_.push_back(std::move(record));
    }

    Client* find_client(std::uint64_t id) {
        for (auto& client : clients_) {
            if (client->id == id) {
                return client.get();
            }
        }
        return nullptr;
    }

    // ENet hands back peers, not ids. Scanning (instead of trusting peer->data)
    // keeps a recycled peer from resolving to a freed session.
    Client* find_client_by_peer(const ENetPeer* peer) {
        for (auto& client : clients_) {
            if (client->enet && client->peer == peer) {
                return client.get();
            }
        }
        return nullptr;
    }

    void release_citra_transport(Client& client) {
        if (client.enet && client.peer != nullptr) {
            enet_peer_disconnect_now(client.peer, 0);
            client.peer = nullptr;
        }
        client.inbox_bytes = 0;
        client.enet_frames.clear();
    }

    const char* citra_transport_name() const noexcept {
        return options_.citra_tcp_test_transport ? "tcp-test" : "enet";
    }

    void add_event(const std::string& kind, std::uint64_t client_id, const std::string& detail) {
        if (events_.size() >= options_.event_limit) {
            events_.pop_front();
            ++counters_.events_dropped;
        }
        Event event;
        event.seq = ++event_seq_;
        event.time_ms = now_ms() - start_ms_;
        event.kind = kind;
        event.client_id = client_id;
        event.detail = detail;
        events_.push_back(std::move(event));
    }

    void record_emitted(std::uint64_t client_id, const std::string& direction,
                        const std::string& kind, const std::vector<std::uint8_t>& bytes) {
        if (options_.emitted_limit > 0 && emitted_.size() >= options_.emitted_limit) {
            emitted_.erase(emitted_.begin());
        }
        EmittedFrame frame;
        frame.seq = ++emitted_seq_;
        frame.time_ms = now_ms() - start_ms_;
        frame.client_id = client_id;
        frame.direction = direction;
        frame.kind = kind;
        frame.bytes = bytes.size();
        frame.hex = hex_of(bytes, bytes.size());
        emitted_.push_back(std::move(frame));
    }

    // G-b' (docs/M4-CONTROL-PLANE.md 7.1): exactly one session owns the LDN
    // control plane of this gateway; the lowest joined client id wins, and every
    // other joined session mirrors membership changes without emitting.
    Client* control_owner() {
        Client* owner = nullptr;
        for (auto& client : clients_) {
            if (client->phase != ClientPhase::Joined || !client->control) {
                continue;
            }
            if (owner == nullptr || client->id < owner->id) {
                owner = client.get();
            }
        }
        return owner;
    }

    // V-112: the synthetic host's game-layer dialogue.  A real MHXX host
    // answers a guest's EAPoL-Start with SecureData (EtherType 0x876d) frames
    // (083801: 217 B broadcast ~31 ms after the 672 B EAPoL-Logoff, then a
    // request/response exchange), and the guest waits for that traffic before
    // it enters the gathering hall.  The gateway replays captured host frames
    // from Options::game_script; each step fires delay_ms after either the
    // guest's Citra association completed (after_guest_frames == 0; V-131: the
    // gateway-only room has no Yuzu peer, so the room side never reports
    // Connected and keying to it left the script permanently inert) or after
    // the N-th game-layer frame arrived from the guest.  An empty script
    // (the default) keeps the gateway byte-for-byte unchanged.
    static std::uint32_t read_be32(const std::uint8_t* data) {
        return (static_cast<std::uint32_t>(data[0]) << 24) |
               (static_cast<std::uint32_t>(data[1]) << 16) |
               (static_cast<std::uint32_t>(data[2]) << 8) |
               static_cast<std::uint32_t>(data[3]);
    }

    static std::string hex_u32(const std::uint32_t value) {
        constexpr char kDigits[] = "0123456789abcdef";
        std::string out(8, '0');
        for (int i = 7; i >= 0; --i) {
            out[static_cast<std::size_t>(i)] = kDigits[(value >> (4 * i)) & 0xFu];
        }
        return out;
    }

    // V-132: the guest announces its own nonce family value (A) in its own
    // 0x876d frames at a per-length offset.  Measured on both real MHXX
    // sessions (083801, 085518) and on gc8, whose guest announced the
    // successive values c9c93d03/c65d8ffc/9409deb8 at UDS payload offsets 128
    // (134 B frame), 285 (290 B) and 64 (70 B); the guest's frames are
    // LLC(8) + SecureDataHeader(14) + game data, so those are game data
    // offsets 106 (112 B), 263 (268 B) and 42 (48 B).  This table is indexed
    // by the *game data* length, which is what SecureDataFrame::payload holds.
    static bool guest_nonce_offset(const std::size_t length, std::size_t* offset) {
        switch (length) {
        case 112:
            *offset = 106;
            return true;
        case 268:
            *offset = 263;
            return true;
        case 48:
            *offset = 42;
            return true;
        default:
            return false;
        }
    }

    // True when the payload carries a value from the captured nonce family
    // [ref, ref + 31].
    static bool payload_has_nonce_family(const std::vector<std::uint8_t>& payload,
                                         const std::uint32_t ref) {
        if (payload.size() < 4) {
            return false;
        }
        for (std::size_t i = 0; i + 4 <= payload.size(); ++i) {
            const std::uint32_t value = read_be32(payload.data() + i);
            if (value >= ref && static_cast<std::uint64_t>(value) - ref < 32) {
                return true;
            }
        }
        return false;
    }

    // Rewrite every occurrence of the captured family in place and report how
    // many were replaced (the captured script carries exactly one per frame).
    static std::size_t patch_nonce_family(std::vector<std::uint8_t>& payload,
                                          const std::uint32_t ref,
                                          const std::uint32_t live) {
        std::size_t patched = 0;
        if (payload.size() < 4) {
            return 0;
        }
        for (std::size_t i = 0; i + 4 <= payload.size(); ++i) {
            const std::uint32_t value = read_be32(payload.data() + i);
            if (value >= ref && static_cast<std::uint64_t>(value) - ref < 32) {
                payload[i] = static_cast<std::uint8_t>((live >> 24) & 0xFFu);
                payload[i + 1] = static_cast<std::uint8_t>((live >> 16) & 0xFFu);
                payload[i + 2] = static_cast<std::uint8_t>((live >> 8) & 0xFFu);
                payload[i + 3] = static_cast<std::uint8_t>(live & 0xFFu);
                ++patched;
            }
        }
        return patched;
    }

    // V-133: true when the payload carries a captured token value verbatim.
    static bool payload_has_token_ref(const std::vector<std::uint8_t>& payload,
                                      const std::uint32_t ref) {
        if (payload.size() < 4) {
            return false;
        }
        for (std::size_t i = 0; i + 4 <= payload.size(); ++i) {
            if (read_be32(payload.data() + i) == ref) {
                return true;
            }
        }
        return false;
    }

    // V-133: rewrite every verbatim occurrence of a captured token with the live
    // value and keep the captured <value><value >> 16> suffix encoding
    // consistent.  The suffix is only touched when it really follows the value.
    static std::size_t patch_token_ref(std::vector<std::uint8_t>& payload,
                                       const std::uint32_t ref,
                                       const std::uint32_t live) {
        std::size_t patched = 0;
        if (payload.size() < 4) {
            return 0;
        }
        const std::uint16_t ref_suffix = static_cast<std::uint16_t>(ref >> 16);
        const std::uint16_t live_suffix = static_cast<std::uint16_t>(live >> 16);
        for (std::size_t i = 0; i + 4 <= payload.size(); ++i) {
            if (read_be32(payload.data() + i) != ref) {
                continue;
            }
            payload[i] = static_cast<std::uint8_t>((live >> 24) & 0xFFu);
            payload[i + 1] = static_cast<std::uint8_t>((live >> 16) & 0xFFu);
            payload[i + 2] = static_cast<std::uint8_t>((live >> 8) & 0xFFu);
            payload[i + 3] = static_cast<std::uint8_t>(live & 0xFFu);
            if (i + 6 <= payload.size()) {
                const std::uint16_t suffix =
                    static_cast<std::uint16_t>((static_cast<std::uint16_t>(payload[i + 4]) << 8) |
                                               static_cast<std::uint16_t>(payload[i + 5]));
                if (suffix == ref_suffix) {
                    payload[i + 4] = static_cast<std::uint8_t>((live_suffix >> 8) & 0xFFu);
                    payload[i + 5] = static_cast<std::uint8_t>(live_suffix & 0xFFu);
                }
            }
            ++patched;
            i += 3;
        }
        return patched;
    }

    // V-133: the site (game data length -> offset) at which a guest frame
    // announces a token family's live value.
    static bool token_learn_offset(const Options::GameTokenRef& token,
                                   const std::size_t length,
                                   std::size_t* offset) {
        for (const auto& site : token.learn_sites) {
            if (site.first == length) {
                *offset = site.second;
                return true;
            }
        }
        return false;
    }

    void note_guest_game_frame(Client& client, std::uint64_t now,
                               const std::vector<std::uint8_t>& payload) {
        if (options_.game_script.empty()) {
            return;
        }
        // V-132: remember the guest's own nonce value.  The live value, not the
        // captured one, is what a real host echoes back.
        std::size_t nonce_offset = 0;
        if (guest_nonce_offset(payload.size(), &nonce_offset)) {
            const std::uint32_t value = read_be32(payload.data() + nonce_offset);
            if (!client.script_nonce_known || client.script_nonce != value) {
                client.script_nonce = value;
                client.script_nonce_known = true;
                ++counters_.game_script_nonce_learned;
                add_event("game.script.nonce", client.id, hex_u32(value));
            }
        }
        // V-133: the guest announces the other session tokens (C, D) in its own
        // frames too; remember every live value so a replayed host frame echoes
        // the value this guest chose instead of the captured session's.
        if (client.script_tokens.size() != options_.game_token_refs.size()) {
            client.script_tokens.assign(options_.game_token_refs.size(), 0);
            client.script_token_known.assign(options_.game_token_refs.size(), false);
        }
        for (std::size_t t = 0; t < options_.game_token_refs.size(); ++t) {
            std::size_t token_offset = 0;
            if (!token_learn_offset(options_.game_token_refs[t], payload.size(),
                                    &token_offset) ||
                token_offset + 4 > payload.size()) {
                continue;
            }
            const std::uint32_t value = read_be32(payload.data() + token_offset);
            if (!client.script_token_known[t] || client.script_tokens[t] != value) {
                client.script_tokens[t] = value;
                client.script_token_known[t] = true;
                ++counters_.game_script_tokens_learned;
                add_event("game.script.token", client.id,
                          std::to_string(t) + " " + hex_u32(value));
            }
        }
        constexpr std::size_t kHistory = 512;
        if (client.script_guest_ms.size() >= kHistory) {
            client.script_guest_ms.erase(client.script_guest_ms.begin());
        }
        client.script_guest_ms.push_back(now);
        add_event("game.script.guest_frame", client.id,
                  std::to_string(client.script_guest_ms.size()));
    }

    void run_game_script(Client& client, std::uint64_t now) {
        if (options_.game_script.empty() || !client.control) {
            return;
        }
        if (!client.script_join_known) {
            if (!client.control->citra_association_complete()) {
                return;
            }
            client.script_join_known = true;
            client.script_join_ms = now;
            add_event("game.script.armed", client.id, std::to_string(now));
        }
        while (client.script_pos < options_.game_script.size()) {
            const Options::GameScriptStep& step = options_.game_script[client.script_pos];
            if (!client.script_due_known) {
                std::uint64_t base = client.script_join_ms;
                if (step.after_guest_frames > 0) {
                    if (client.script_guest_ms.size() < step.after_guest_frames) {
                        return;  // that many guest frames have not arrived yet
                    }
                    base = client.script_guest_ms[step.after_guest_frames - 1];
                }
                client.script_due_ms = base + static_cast<std::uint64_t>(step.delay_ms);
                client.script_due_known = true;
            }
            if (now < client.script_due_ms) {
                return;
            }
            // V-132: echo the guest's own nonce family.  A step that carries the
            // captured family is held until the guest has announced its value: a
            // real host only echoes what it just received, so waiting is
            // causally correct and in the captured timing costs a few ms.
            const bool needs_nonce =
                options_.have_game_nonce_ref &&
                payload_has_nonce_family(step.payload, options_.game_nonce_ref);
            if (needs_nonce && !client.script_nonce_known) {
                if (!client.script_wait_logged) {
                    client.script_wait_logged = true;
                    ++counters_.game_script_nonce_waits;
                    add_event("game.script.nonce_wait", client.id, step.label);
                }
                return;
            }
            // V-133: the same rule for the other guest-chosen session tokens (C
            // and D in the MHXX join dialogue).  A step that still carries a
            // captured value is held until the guest announces its live value;
            // the patch then rewrites the value and its suffix together.
            if (client.script_tokens.size() != options_.game_token_refs.size()) {
                client.script_tokens.assign(options_.game_token_refs.size(), 0);
                client.script_token_known.assign(options_.game_token_refs.size(), false);
            }
            std::vector<std::size_t> token_hits;
            for (std::size_t t = 0; t < options_.game_token_refs.size(); ++t) {
                if (!payload_has_token_ref(step.payload, options_.game_token_refs[t].ref)) {
                    continue;
                }
                token_hits.push_back(t);
                if (!client.script_token_known[t]) {
                    if (!client.script_wait_logged) {
                        client.script_wait_logged = true;
                        ++counters_.game_script_token_waits;
                        add_event("game.script.token_wait", client.id,
                                  step.label + " token" + std::to_string(t));
                    }
                    return;
                }
            }
            const bool rewrite = needs_nonce || !token_hits.empty();
            std::vector<std::uint8_t> patched;
            if (rewrite) {
                patched = step.payload;
                std::size_t replaced = 0;
                if (needs_nonce) {
                    replaced += patch_nonce_family(patched, options_.game_nonce_ref,
                                                   client.script_nonce);
                }
                for (const std::size_t t : token_hits) {
                    replaced += patch_token_ref(patched, options_.game_token_refs[t].ref,
                                                client.script_tokens[t]);
                }
                if (replaced > 0) {
                    ++counters_.game_script_frames_patched;
                }
                if (!token_hits.empty()) {
                    ++counters_.game_script_token_frames_patched;
                }
            }
            ControlEmission emission;
            emission.to_citra = true;
            emission.kind = "citra.game_script";
            emission.citra_type = citra_room::FrameType::Data;
            emission.citra_broadcast = step.broadcast;
            emission.citra_data = rewrite ? patched : step.payload;
            emit_control(client, {emission});
            ++client.script_sent;
            ++counters_.game_script_frames_sent;
            client.script_wait_logged = false;
            add_event("game.script.sent", client.id,
                      step.label.empty()
                          ? std::to_string(step.payload.size())
                          : (rewrite ? step.label + (needs_nonce ? "|nonce" : "|token")
                                     : step.label));
            ++client.script_pos;
            client.script_due_known = false;
        }
    }

    void emit_control(Client& client, const std::vector<ControlEmission>& emissions) {
        for (const ControlEmission& emission : emissions) {
            if (options_.ldn_dual_host && client.dual_citra_host && emission.kind == "citra.beacon") continue;
            if (emission.to_citra) {
                citra_room::WifiPacket wifi;
                wifi.type = emission.citra_type;
                // V-111: real MHXX beacons are seen on channel 11 and the
                // profile can say so; without it the gateway keeps channel 6.
                wifi.channel = options_.have_uds_wifi_channel
                                   ? static_cast<std::uint8_t>(options_.uds_wifi_channel)
                                   : static_cast<std::uint8_t>(kControlChannel);
                // V-266: an injected association frame carries the Yuzu station's
                // own addresses (source = station MAC, destination = the host
                // bssid); every other emission keeps the gateway's identity.
                if (options_.ldn_dual_host && client.dual_citra_host) wifi.channel = client.dual_host_channel;
                if (options_.ldn_dual_host && client.dual_local_host) {
                    for (const auto& host : clients_)
                        if (host->phase == ClientPhase::Joined && host->dual_citra_host &&
                            host->mac == *client.dual_local_host) wifi.channel = host->dual_host_channel;
                }
                wifi.transmitter = emission.have_citra_addresses
                                       ? emission.citra_transmitter
                                       : (client.control ? client.control->bssid() : MacAddress{});
                wifi.destination = emission.have_citra_addresses
                                       ? emission.citra_destination
                                       : (emission.citra_broadcast ? citra_room::broadcast_mac
                                                                   : client.mac);
                wifi.data = emission.citra_data;
                send_citra(client, wifi);
                record_emitted(client.id, "citra", emission.kind, wifi.data);
                add_event("control.emit.citra", client.id, emission.kind);
                continue;
            }
            if (emission.room_proxy) {
                // V-259: translated game announce -> ProxyPacket to the Yuzu
                // members.  Same wire shape as every other gateway proxy: the
                // sender's fake IPv4 as local, the port placeholder on both
                // ends, and -- for a broadcast -- the sender's own fake IPv4 as
                // the remote (exactly how the relay path marks bidirectionality,
                // gateway.cpp broadcast destination above).
                room_client::ProxyPacket proxy;
                // V-272: the Yuzu ProxySocket filters on the remote port
                // (socket_proxy.cpp HandleProxyPacket compares it with the
                // socket's local port), so a translated frame must carry the
                // game's UDP port rather than the 0 placeholder.
                const std::uint16_t proxy_port = options_.proxy_udp_port != 0
                                                     ? options_.proxy_udp_port
                                                     : options_.proxy_port_placeholder;
                proxy.local.family = room_client::Domain::Inet;
                proxy.local.ip = client.fake_ip;
                proxy.local.port = proxy_port;
                proxy.remote.family = room_client::Domain::Inet;
                proxy.remote.ip = emission.proxy_broadcast ? client.fake_ip
                                                          : emission.proxy_remote_ip;
                proxy.remote.port = proxy_port;
                proxy.protocol = room_client::SocketProtocol::Udp;
                proxy.broadcast = emission.proxy_broadcast;
                std::string compress_why;
                if (!compress_proxy_frame(emission.proxy_data,
                                          options_.proxy_compressed_bytes,
                                          3, proxy.data, &compress_why)) {
                    ++counters_.payload_rejected_boundary;
                    add_event("proxy.compress.failed", client.id, compress_why);
                    continue;
                }
                bool sent = false;
                try {
                    sent = client.transport->send(proxy);
                } catch (const std::exception& error) {
                    ++counters_.room_frames_rejected;
                    add_event("proxy.send.failed", client.id, error.what());
                    continue;
                }
                if (sent) {
                    ++counters_.proxy_frames_emitted;
                    record_emitted(client.id, "proxy", emission.kind, proxy.data);
                    add_event("control.emit.proxy", client.id, emission.kind);
                }
                continue;
            }
            if (!client.transport) {
                ++counters_.room_frames_rejected;
                continue;
            }
            room_client::LdnPacket packet;
            packet.type = emission.ldn_type;
            packet.local_ip = client.fake_ip;
            packet.remote_ip = emission.ldn_remote_ip;
            packet.broadcast = emission.ldn_broadcast;
            packet.data = emission.ldn_body;
            bool sent = false;
            try {
                sent = client.transport->send(packet);
            } catch (const std::exception& error) {
                ++counters_.room_frames_rejected;
                add_event("control.send.failed", client.id, error.what());
                continue;
            }
            if (!sent) {
                ++counters_.room_frames_rejected;
                add_event("control.send.backpressure", client.id, emission.kind);
                continue;
            }
            record_emitted(client.id, "room", emission.kind, packet.data);
            add_event("control.emit.room", client.id,
                      emission.kind + " -> " + ip_to_string(packet.remote_ip));
        }
    }

    // G-b' section 7.2: one decoded room-side LDN packet. Only the control owner
    // processes it; every other joined session counts and mirrors the resulting
    // membership change without emitting anything.
    void refresh_gu_guest_identities() {
        std::vector<GuHostGuestIdentity> peers;
        for (const auto& session : clients_) {
            if (session->phase == ClientPhase::Joined && session->control) {
                if (auto peer = session->control->gu_host_guest_identity()) peers.push_back(*peer);
            }
        }
        for (const auto& session : clients_) {
            if (session->phase == ClientPhase::Joined && session->control)
            {
                session->control->set_gu_host_guest_identities(peers);
                std::vector<room_client::IPv4> native_members;
                if (session->transport) {
                    const auto snapshot = session->transport->snapshot();
                    if (snapshot.room) for (const auto& member : snapshot.room->members)
                        if (!identities_.mac_for_ip(member.fake_ip)) native_members.push_back(member.fake_ip);
                }
                session->control->set_gu_host_native_members(native_members);
            }
        }
    }

    void on_ldn_message(Client& client, const room_client::LdnPacket& packet) {
        if (client.phase != ClientPhase::Joined || !client.control) return;
        if (options_.ldn_dual_host && gu_guest_role(client) && identities_.mac_for_ip(packet.local_ip))
            return; // Native Citra halls are delivered directly, not rediscovered through GU conversion.
        // GU-host discovery/admission belongs to each upstream guest transport.
        // The single owner below is for the synthetic Citra-host AP only.
        if (gu_guest_role(client)) {
            if (client.phase != ClientPhase::Joined || !client.control) return;
            refresh_gu_guest_identities();
            const auto handling = client.control->on_ldn(packet, {});
            if (!handling.accepted) {
                add_event("control.ldn.rejected", client.id,
                          "guest-session ldn " + std::to_string(static_cast<int>(packet.type)));
                return;
            }
            emit_control(client, handling.emissions);
            return;
        }
        Client* owner = options_.ldn_dual_host ? &client : control_owner();
        if (owner == nullptr) {
            ++counters_.payload_rejected_unknown_category;
            add_event("payload.rejected.unknown", client.id, "room IdLdnPacket");
            return;
        }
        if (client.id != owner->id) {
            client.control->note_non_owner_ignored();
            return;
        }
        citra_room::MacAddress station_mac{};
        bool have_station_mac = false;
        std::array<std::uint8_t, 4> declared_ipv4{};
        bool have_declared_ipv4 = false;
        citra_control::LdnNodeInfo declared_node;
        if (packet.type == room_client::LdnType::Connect) {
            const auto parsed = citra_control::parse_ldn_node_info(packet.data.data(),
                                                                 packet.data.size(), nullptr);
            if (parsed.ok()) {
                declared_node = parsed.value;
                declared_ipv4 = parsed.value.ipv4_address;
                have_declared_ipv4 = !(declared_ipv4 == std::array<std::uint8_t, 4>{});
            }
            if (parsed.ok() && !is_sentinel_mac(parsed.value.mac_address) &&
                !(parsed.value.mac_address == citra_room::MacAddress{})) {
                station_mac = parsed.value.mac_address;
                have_station_mac = true;
            } else if (const auto mapped = identities_.mac_for_ip(packet.local_ip)) {
                station_mac = *mapped;
                have_station_mac = true;
            }
        }
        LdnContext context;
        context.mapped_mac = station_mac;
        context.have_mapped_mac = have_station_mac;

        const LdnHandling handling = owner->control->on_ldn(packet, context);
        if (!handling.accepted) {
            add_event("control.ldn.rejected", owner->id,
                      std::string("ldn ") + std::to_string(static_cast<int>(packet.type)) + " body " +
                          std::to_string(packet.data.size()));
            return;
        }
        for (auto& other : clients_) {
            if (options_.ldn_dual_host || other.get() == owner || other->phase != ClientPhase::Joined || !other->control) {
                continue;
            }
            switch (packet.type) {
            case room_client::LdnType::Connect:
                other->control->mirror_connect(packet.local_ip, station_mac, declared_ipv4,
                                                have_declared_ipv4, declared_node.user_name,
                                                declared_node.local_communication_version);
                break;
            case room_client::LdnType::Disconnect:
                other->control->mirror_disconnect(packet.local_ip);
                break;
            case room_client::LdnType::DestroyNetwork:
                other->control->mirror_destroy();
                break;
            default:
                break;
            }
        }
        emit_control(*owner, handling.emissions);
    }

    void accept_ready() {
        if (listener_ == INVALID_SOCKET) {
            return;
        }
        for (;;) {
            SOCKET accepted = ::accept(listener_, nullptr, nullptr);
            if (accepted == INVALID_SOCKET) {
                break;
            }
            if (clients_.size() >= options_.max_clients) {
                ++counters_.clients_rejected_full;
                ::closesocket(accepted);
                continue;
            }
            u_long non_blocking = 1;
            ::ioctlsocket(accepted, FIONBIO, &non_blocking);
            int nodelay = 1;
            ::setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY,
                         reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
            auto client = std::make_unique<Client>();
            client->id = ++next_client_id_;
            client->sock = accepted;
            client->enet = false;
            client->phase = ClientPhase::Framing;
            client->accepted_at = now_ms() - start_ms_;
            ++counters_.clients_accepted;
            ++counters_.citra_tcp_accepts;
            add_event("client.accepted", client->id, "tcp");
            clients_.push_back(std::move(client));
        }
    }

    // G-c / V-027: pump the ENet/UDP listener. CONNECT opens one session,
    // RECEIVE queues one complete citra_room frame, DISCONNECT closes the
    // session. timeout 0 drains every pending event without blocking the tick,
    // and each call also drives retransmits of queued outgoing packets.
    void service_citra_enet() {
        if (enet_host_ == nullptr) {
            return;
        }
        for (;;) {
            ENetEvent event{};
            const int result = enet_host_service(enet_host_, &event, 0);
            if (result <= 0) {
                break;
            }
            if (event.type == ENET_EVENT_TYPE_CONNECT) {
                ++counters_.citra_enet_connects;
                if (clients_.size() >= options_.max_clients) {
                    ++counters_.clients_rejected_full;
                    ++counters_.citra_enet_rejected_full;
                    enet_peer_disconnect_now(event.peer, 0);
                    continue;
                }
                auto client = std::make_unique<Client>();
                client->id = ++next_client_id_;
                client->enet = true;
                client->peer = event.peer;
                client->phase = ClientPhase::Framing;
                client->accepted_at = now_ms() - start_ms_;
                ++counters_.clients_accepted;
                add_event("client.accepted", client->id, "enet");
                clients_.push_back(std::move(client));
                continue;
            }
            if (event.type == ENET_EVENT_TYPE_RECEIVE) {
                Client* client = find_client_by_peer(event.peer);
                const std::size_t size = event.packet->dataLength;
                if (client == nullptr || client->phase == ClientPhase::Closed ||
                    client->phase == ClientPhase::Closing) {
                    enet_packet_destroy(event.packet);
                    continue;
                }
                ++counters_.citra_enet_receives;
                if (client->inbox_bytes + size > options_.per_client_inbox_bytes) {
                    ++counters_.inbox_overflows;
                    ++counters_.queue_overflows;
                    add_event("queue.overflow", client->id, "inbound");
                    close_after_flush(*client, "inbound queue limit");
                } else {
                    citra_room::Bytes frame(event.packet->data,
                                            event.packet->data + event.packet->dataLength);
                    client->inbox_bytes += frame.size();
                    client->enet_frames.push_back(std::move(frame));
                }
                enet_packet_destroy(event.packet);
                continue;
            }
            if (event.type == ENET_EVENT_TYPE_DISCONNECT) {
                ++counters_.citra_enet_disconnects;
                Client* client = find_client_by_peer(event.peer);
                if (client != nullptr && client->phase != ClientPhase::Closed) {
                    client->peer = nullptr;
                    leave_client(*client, "citra peer closed");
                }
            }
        }
    }

    void reap() {
        clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
                                      [](const std::unique_ptr<Client>& client) {
                                          return client->phase == ClientPhase::Closed;
                                      }),
                       clients_.end());
    }

    void mark_release(Client& client) {
        if (client.counted_leave) {
            return;
        }
        client.counted_leave = true;
        if (client.phase == ClientPhase::Joined) {
            ++counters_.clients_left;
        } else if (client.phase == ClientPhase::Joining) {
            ++counters_.room_join_failures;
        }
    }

    void release_room_peer(Client& client) {
        if (client.pending_game_info) {
            ++counters_.set_game_info_discarded;
            client.pending_game_info.reset();
        }
        if (client.transport) {
            try {
                if (options_.ldn_dual_host) forget_dual_local_peer(client);
                if (options_.ldn_dual_host && client.dual_citra_host) retire_dual_host(client);
                if (client.control) {
                    emit_control(client, client.control->on_transport_departure());
                }
                client.transport->stop();
            } catch (...) {
            }
            client.transport.reset();
        }
        if (client.mac_known) {
            identities_.erase_mac(client.mac);
        }
    }

    void hard_close(Client& client) {
        // The session ledger must be filled while the identity, the timestamps and
        // the control bridge of this session still exist: release_room_peer erases
        // the identity and release_citra_transport drops the ENet peer.
        record_departure(client);
        release_room_peer(client);
        release_citra_transport(client);
        if (client.sock != INVALID_SOCKET) {
            ::closesocket(client.sock);
            client.sock = INVALID_SOCKET;
        }
        client.inbox.clear();
        client.outbox.clear();
        client.outbox_bytes = 0;
        client.phase = ClientPhase::Closed;
    }

    void close_after_flush(Client& client, const std::string& why) {
        if (client.phase == ClientPhase::Closed) {
            return;
        }
        if (client.failure.empty()) {
            client.failure = why;
        }
        mark_release(client);
        client.phase = ClientPhase::Closing;
        client.close_deadline = now_ms() + options_.close_grace_ms;
        ++counters_.clients_closed_by_gateway;
        release_room_peer(client);
        if (client.outbox.empty()) {
            hard_close(client);
        }
    }

    void leave_client(Client& client, const std::string& why) {
        if (client.phase == ClientPhase::Closed) {
            return;
        }
        if (client.failure.empty()) {
            client.failure = why;
        }
        mark_release(client);
        add_event("client.closed", client.id, why);
        hard_close(client);
    }

    bool read_client(Client& client) {
        if (client.enet) {
            // ENet delivers whole frames as events; there is no byte stream to
            // drain here.
            return true;
        }
        for (;;) {
            if (client.inbox.size() >= options_.per_client_inbox_bytes) {
                ++counters_.inbox_overflows;
                ++counters_.queue_overflows;
                close_after_flush(client, "inbound queue limit");
                return true;
            }
            std::uint8_t buffer[8192];
            const int received = ::recv(client.sock, reinterpret_cast<char*>(buffer),
                                        static_cast<int>(sizeof(buffer)), 0);
            if (received > 0) {
                client.inbox.insert(client.inbox.end(), buffer, buffer + received);
                if (client.inbox.size() > options_.per_client_inbox_bytes) {
                    ++counters_.inbox_overflows;
                    ++counters_.queue_overflows;
                    close_after_flush(client, "inbound queue limit");
                    return true;
                }
                continue;
            }
            if (received == 0) {
                return false;
            }
            const int error = ::WSAGetLastError();
            if (error == WSAEWOULDBLOCK) {
                return true;
            }
            if (error == WSAEINTR) {
                continue;
            }
            return false;
        }
    }

    bool flush_client(Client& client) {
        if (client.enet) {
            return flush_client_enet(client);
        }
        while (!client.outbox.empty()) {
            room_client::Bytes& frame = client.outbox.front();
            const int sent = ::send(client.sock, reinterpret_cast<const char*>(frame.data()),
                                    static_cast<int>(frame.size()), 0);
            if (sent > 0) {
                const std::size_t sent_size = static_cast<std::size_t>(sent);
                if (sent_size < frame.size()) {
                    room_client::Bytes rest(frame.begin() + static_cast<std::ptrdiff_t>(sent_size),
                                            frame.end());
                    client.outbox_bytes -= rest.size();
                    client.outbox.front() = std::move(rest);
                    return true;
                }
                client.outbox_bytes -= frame.size();
                client.outbox.pop_front();
                continue;
            }
            if (sent == SOCKET_ERROR) {
                const int error = ::WSAGetLastError();
                if (error == WSAEWOULDBLOCK) {
                    return true;
                }
                return false;
            }
            return false;
        }
        return true;
    }

    // ENet owns reliability and ordering; enet_peer_send copies the bytes and a
    // trailing enet_host_flush pushes everything queued by this tick.
    bool flush_client_enet(Client& client) {
        if (enet_host_ == nullptr || client.peer == nullptr) {
            return false;
        }
        while (!client.outbox.empty()) {
            room_client::Bytes& frame = client.outbox.front();
            ENetPacket* packet = enet_packet_create(frame.data(), frame.size(),
                                                    ENET_PACKET_FLAG_RELIABLE);
            if (packet == nullptr) {
                return false;
            }
            if (enet_peer_send(client.peer, 0, packet) != 0) {
                enet_packet_destroy(packet);
                return false;
            }
            client.outbox_bytes -= frame.size();
            client.outbox.pop_front();
        }
        enet_host_flush(enet_host_);
        return true;
    }

    void process_inbound(Client& client) {
        if (client.enet) {
            process_inbound_enet(client);
            return;
        }
        for (;;) {
            if (client.phase == ClientPhase::Closed || client.phase == ClientPhase::Closing) {
                return;
            }
            if (client.inbox.size() < 4) {
                return;
            }
            const std::uint32_t length = (static_cast<std::uint32_t>(client.inbox[0]) << 24) |
                                         (static_cast<std::uint32_t>(client.inbox[1]) << 16) |
                                         (static_cast<std::uint32_t>(client.inbox[2]) << 8) |
                                         static_cast<std::uint32_t>(client.inbox[3]);
            if (length > options_.max_frame_bytes) {
                // Framing level oversize: the declared length cannot be trusted
                // to resync, so the connection is closed (declared policy).
                ++counters_.oversize_rejections;
                ++counters_.frames_rejected;
                ++client.frames_rejected;
                add_event("frame.oversize.framing", client.id, std::to_string(length));
                close_after_flush(client, "framing oversize");
                return;
            }
            if (client.inbox.size() < 4 + length) {
                return;
            }
            citra_room::Bytes frame(client.inbox.begin() + 4,
                                    client.inbox.begin() + 4 + length);
            client.inbox.erase(client.inbox.begin(),
                               client.inbox.begin() + 4 + static_cast<std::ptrdiff_t>(length));
            ++client.frames_in;
            ++counters_.frames_in;
            handle_citra_frame(client, frame);
        }
    }

    void process_inbound_enet(Client& client) {
        while (!client.enet_frames.empty()) {
            if (client.phase == ClientPhase::Closed || client.phase == ClientPhase::Closing) {
                return;
            }
            citra_room::Bytes frame = std::move(client.enet_frames.front());
            client.enet_frames.pop_front();
            if (client.inbox_bytes >= frame.size()) {
                client.inbox_bytes -= frame.size();
            } else {
                client.inbox_bytes = 0;
            }
            ++client.frames_in;
            ++counters_.frames_in;
            handle_citra_frame(client, frame);
        }
    }

    void note_decode_error(citra_room::ErrorCode code) {
        counters_.decode_error_codes[citra_room::error_code_name(code)]++;
    }

    // v4 SetGameInfo (room.h:52-79 MessageId 4; room_member.cpp:607-617 SendGameInfo)
    // carries the game name and id; the room side logs/publishes it
    // (room.cpp HandleGameInfoPacket). ADR-009 pins one Citra client to exactly one
    // v1 room peer, so the info is written to THIS session's own room transport and
    // never to another session's peer. The v1 GameInfo.version field has no v4
    // source: it is the gateway placeholder and every use of it is counted.
    void note_set_game_info(Client& client, const citra_room::GameInfo& game) {
        bool mappable = game.name.size() <= 4096;
        for (const char raw : game.name) {
            const unsigned char ch = static_cast<unsigned char>(raw);
            if (ch < 0x20 || ch == 0x7F) {
                // Control characters (including an embedded NUL) have no room-side
                // representation: fail closed instead of sanitising the name.
                mappable = false;
                break;
            }
        }
        if ((client.phase != ClientPhase::Joined && client.phase != ClientPhase::Joining) ||
            !client.transport || !mappable) {
            ++counters_.set_game_info_rejected;
            ++counters_.frames_rejected;
            ++client.frames_rejected;
            add_event("payload.rejected.set_game_info", client.id,
                      client.phase == ClientPhase::Joined ? "unmappable game name"
                                                          : "session is not joined");
            return;
        }
        if (client.phase == ClientPhase::Joining) {
            if (client.pending_game_info) ++counters_.set_game_info_replaced;
            client.pending_game_info = game;
            ++counters_.set_game_info_deferred;
            add_event("payload.deferred.set_game_info", client.id, "waiting for upstream join");
            return;
        }
        room_client::GameInfo info;
        info.name = game.name;
        info.id = game.id;
        info.version = options_.peer_game_version;
        try {
            if (!client.transport->send(room_client::Message{info})) {
                ++counters_.set_game_info_rejected;
                ++counters_.queue_overflows;
                add_event("payload.rejected.set_game_info", client.id, "upstream send budget full");
                return;
            }
        } catch (const std::exception& error) {
            ++counters_.set_game_info_rejected;
            add_event("payload.rejected.set_game_info", client.id, error.what());
            return;
        }
        ++counters_.set_game_info_version_placeholder;
        ++counters_.set_game_info_accepted;
        add_event("payload.set_game_info", client.id, info.name);
    }

    void handle_citra_frame(Client& client, const citra_room::Bytes& frame) {
        // V-023: defense in depth only. The default equals the frozen codec frame
        // limit (65536), so every legal Citra frame reaches the decoder; the data
        // plane limit (60000) is enforced by citra_room::decode itself.
        if (frame.size() > options_.max_inbound_citra_bytes) {
            ++counters_.oversize_rejections;
            ++counters_.frames_rejected;
            ++client.frames_rejected;
            add_event("frame.citra.oversize", client.id, std::to_string(frame.size()));
            return;
        }
        citra_room::Message message;
        try {
            message = citra_room::decode(frame, citra_room::Direction::ClientToServer,
                                         citra_limits_);
        } catch (const citra_room::ProtocolError& error) {
            note_decode_error(error.code());
            switch (error.code()) {
            case citra_room::ErrorCode::Truncated:
                ++counters_.prefix_truncation_rejections;
                break;
            case citra_room::ErrorCode::WrongDirection:
                ++counters_.wrong_direction_rejections;
                break;
            case citra_room::ErrorCode::UnknownMessage:
                ++counters_.unknown_id_rejections;
                break;
            case citra_room::ErrorCode::UnsupportedMessage:
                ++counters_.unknown_id_rejections;
                break;
            case citra_room::ErrorCode::InvalidEnum:
                ++counters_.unknown_enum_rejections;
                break;
            case citra_room::ErrorCode::TrailingBytes:
                ++counters_.trailing_byte_rejections;
                break;
            case citra_room::ErrorCode::LimitExceeded:
                // V-023: a genuine frozen codec limit, not a pre decode policy cap.
                ++counters_.limit_exceeded_rejections;
                break;
            default:
                ++counters_.malformed_frame_rejections;
                break;
            }
            ++counters_.frames_rejected;
            ++client.frames_rejected;
            add_event("frame.citra.decode_error", client.id,
                      std::string(citra_room::error_code_name(error.code())) + " @" +
                          std::to_string(error.offset()));
            trace_citra_frame("citra.in", "citra->gateway", frame, nullptr,
                              std::string(citra_room::error_code_name(error.code())) + " @" +
                                  std::to_string(error.offset()));
            return;
        }
        trace_citra_frame("citra.in", "citra->gateway", frame, &message);
        if (const auto* request = std::get_if<citra_room::JoinRequest>(&message)) {
            if (client.phase != ClientPhase::Framing) {
                ++counters_.unsupported_in_phase_rejections;
                ++counters_.frames_rejected;
                ++client.frames_rejected;
                add_event("frame.citra.duplicate_join", client.id, "");
                return;
            }
            begin_join(client, *request);
            return;
        }
        if (const auto* wifi = std::get_if<citra_room::WifiPacket>(&message)) {
            forward_wifi(client, *wifi);
            return;
        }
        if (const auto* game = std::get_if<citra_room::GameInfo>(&message)) {
            note_set_game_info(client, *game);
            return;
        }
        if (const auto* chat = std::get_if<citra_room::ChatRequest>(&message)) {
            if (client.phase == ClientPhase::Joined && client.transport) {
                try {
                    if (client.transport->send(room_client::ChatRequest{chat->message})) {
                        add_event("chat.sent", client.id, "upstream");
                        return;
                    }
                } catch (const std::exception& error) {
                    add_event("chat.send_failed", client.id, error.what());
                }
            }
            ++counters_.frames_rejected;
            ++client.frames_rejected;
            add_event("chat.rejected", client.id, "not joined or upstream queue unavailable");
            return;
        }
        ++counters_.payload_rejected_unknown_category;
        ++counters_.frames_rejected;
        ++client.frames_rejected;
        add_event("payload.rejected.unknown", client.id,
                  "citra " + citra_room::message_name(citra_room::message_id(message)));
    }

    std::size_t joined_or_joining_clients() const {
        std::size_t count = 0;
        for (const auto& other : clients_) {
            if (other->phase == ClientPhase::Joining || other->phase == ClientPhase::Joined) {
                ++count;
            }
        }
        return count;
    }

    void begin_join(Client& client, const citra_room::JoinRequest& request) {
        ++counters_.room_join_attempts;
        add_event("join.request", client.id, request.nickname);
        if (closing_) {
            reject_local(client, citra_room::MessageId::CloseRoom, "gateway is closing");
            return;
        }
        // V-016l: the local checks now run in exactly the order the real Citra
        // server runs them (citra-master/src/network/room.cpp:302-360, mirrored by
        // the identical Yuzu twin at
        // 01052024-yuzu-mirror-master/src/network/room.cpp:295-399):
        //   room full -> password -> nickname -> MAC -> console id -> version.
        // Every step below is a LOCAL decision; the Yuzu room is only asked once
        // all of them passed. When two faults are present the answer is the code
        // of the earliest failing step, which is what the multi-fault goldens pin.
        if (options_.room_capacity != 0 &&
            joined_or_joining_clients() >= options_.room_capacity) {
            // citra-master/src/network/room.cpp:305-308: the real Citra server
            // checks members.size() >= member_slots before parsing the request.
            reject_local(client, citra_room::MessageId::RoomIsFull, "room is full");
            return;
        }
        if (request.password != options_.room_password) {
            // citra-master/src/network/room.cpp:331-334. The room is not asked:
            // ordering must not depend on a remote rejection. The request password
            // is still forwarded below because the Yuzu room checks it too.
            reject_local(client, citra_room::MessageId::WrongPassword,
                         "room password mismatch");
            return;
        }
        if (!is_valid_nickname(request.nickname)) {
            // citra-master/src/network/room.cpp:336-339 first half: the regex.
            reject_local(client, citra_room::MessageId::NameCollision,
                         "nickname does not match the room rule");
            return;
        }
        for (const auto& other : clients_) {
            if (other.get() == &client) {
                continue;
            }
            if (other->phase != ClientPhase::Joining && other->phase != ClientPhase::Joined) {
                continue;
            }
            if (other->nickname == request.nickname) {
                // citra-master/src/network/room.cpp:336-339 second half: uniqueness.
                reject_local(client, citra_room::MessageId::NameCollision,
                             "nickname already in the room");
                return;
            }
        }
        MacAddress mac = request.preferred_mac;
        if (is_sentinel_mac(mac)) {
            // Citra NoPreferredMac == BroadcastMac == FF:FF:FF:FF:FF:FF means
            // "assign one"; sentinels never enter the identity table.
            const auto generated = identities_.generate_mac();
            if (!generated) {
                reject_local(client, citra_room::MessageId::MacCollision, "no free MAC");
                return;
            }
            mac = *generated;
            ++counters_.mac_generated;
        } else if (identities_.has_mac(mac)) {
            // citra-master/src/network/room.cpp:341-346 + :578-583: a non-sentinel
            // preferred MAC is rejected with IdMacCollision (8) exactly when it is
            // already taken. There is no OUI validity test on the wire value.
            // Gateway-local policy (ADR-009 / M4 spec section 3): a MAC already in
            // the session map is a collision; the room is never asked.
            reject_local(client, citra_room::MessageId::MacCollision,
                         "preferred MAC already mapped");
            return;
        }
        // citra-master/src/network/room.cpp:585-591 IsValidConsoleId: the console
        // hash is compared against the members already known locally. The hash is
        // never forwarded to the room and never logged (ADR-009).
        if (!request.console_id_hash.empty()) {
            for (const auto& other : clients_) {
                if (other.get() == &client) {
                    continue;
                }
                if (other->phase != ClientPhase::Joining &&
                    other->phase != ClientPhase::Joined) {
                    continue;
                }
                if (other->console_id_hash == request.console_id_hash) {
                    reject_local(client, citra_room::MessageId::ConsoleIdCollision,
                                 "console id already in the room");
                    return;
                }
            }
        }
        // ADR-009: the Citra v4 version terminates on this side; the room only
        // ever sees the Yuzu v1 version. Neither value is forwarded across. The
        // version is checked LAST because that is where the real Citra server
        // checks it (citra-master/src/network/room.cpp:357-360).
        if (request.version != citra_room::network_version) {
            reject_local(client, citra_room::MessageId::VersionMismatch,
                         "citra network version mismatch");
            return;
        }
        const auto fake_ip = identities_.next_free_fake_ip();
        if (!fake_ip) {
            reject_local(client, citra_room::MessageId::RoomIsFull, "no free fake IPv4");
            return;
        }
        if (!identities_.insert(mac, *fake_ip, request.nickname)) {
            reject_local(client, citra_room::MessageId::MacCollision,
                         "identity table rejected the mapping");
            return;
        }
        client.nickname = request.nickname;
        client.console_id_hash = request.console_id_hash; // local only
        client.mac = mac;
        client.mac_known = true;
        client.fake_ip = *fake_ip;
        client.ip_known = true;
        client.join_started = now_ms();
        client.phase = ClientPhase::Joining;

        room_transport::Options options;
        options.address = options_.room_address;
        options.allow_remote = options_.allow_remote_room;
        options.port = options_.room_port;
        options.connect_timeout_ms = options_.connect_timeout_ms;
        options.session.join_timeout_ms = options_.join_timeout_ms;
        options.session.leave_timeout_ms = options_.leave_timeout_ms;
        options.queue_packets = options_.room_queue_packets;
        options.queue_bytes = options_.room_queue_bytes;
        options.outgoing_packets = options_.room_outgoing_packets;
        options.outgoing_bytes = options_.room_outgoing_bytes;
        options.proxy_compressed_bytes = options_.proxy_compressed_bytes;
        options.proxy_decompressed_bytes = options_.proxy_decompressed_bytes;
        client.transport = std::make_unique<room_transport::Transport>(options);

        room_client::JoinRequest join;
        join.nickname = request.nickname;
        join.preferred_ip = *fake_ip;
        join.version = room_client::network_version; // v1 is synthesised here
        join.password = request.password;
        join.token = request.token;
        try {
            client.transport->start(join);
        } catch (const std::exception& error) {
            ++counters_.room_transport_failures;
            identities_.erase_mac(client.mac);
            const std::string detail = std::string("transport start failed: ") + error.what();
            add_event("room.start.failed", client.id, detail);
            close_after_flush(client, detail);
        }
    }

    void reject_local(Client& client, citra_room::MessageId id, const std::string& why) {
        ++counters_.clients_rejected_local;
        ++counters_.local_join_rejections;
        switch (id) {
        case citra_room::MessageId::VersionMismatch:
            ++counters_.local_version_rejections;
            break;
        case citra_room::MessageId::MacCollision:
            ++counters_.local_mac_collision_rejections;
            break;
        case citra_room::MessageId::ConsoleIdCollision:
            ++counters_.local_console_id_collision_rejections;
            // V-016g: Citra IdConsoleIdCollision (13) has no Yuzu counterpart. It is
            // only ever produced by this side's own console_id_hash uniqueness check,
            // never by a room error mapping, so it is counted separately.
            ++counters_.no_correspondence_rejections;
            break;
        case citra_room::MessageId::CloseRoom:
            ++counters_.local_closing_rejections;
            break;
        case citra_room::MessageId::RoomIsFull:
            ++counters_.local_room_full_rejections;
            break;
        case citra_room::MessageId::WrongPassword:
            ++counters_.local_wrong_password_rejections;
            break;
        case citra_room::MessageId::NameCollision:
            ++counters_.local_name_collision_rejections;
            break;
        default:
            break;
        }
        counters_.error_map_hits[citra_room::message_name(id)]++;
        add_event("join.rejected.local", client.id,
                  std::string(citra_room::message_name(id)) + ": " + why);
        send_error_frame(client, id);
        close_after_flush(client, why);
    }

    void send_error_frame(Client& client, citra_room::MessageId id) {
        citra_room::ServerError error;
        error.id = id;
        error.server_version =
            (id == citra_room::MessageId::VersionMismatch) ? citra_room::network_version : 0;
        send_citra(client, error);
    }

    bool send_citra(Client& client, const citra_room::Message& message) {
        citra_room::Bytes payload;
        try {
            payload =
                citra_room::encode(message, citra_room::Direction::ServerToClient, citra_limits_);
        } catch (const std::exception& error) {
            ++counters_.frames_rejected;
            ++client.frames_rejected;
            add_event("frame.citra.encode_error", client.id, error.what());
            return false;
        }
        const bool queued = queue_frame(client, payload);
        if (queued) {
            trace_citra_frame("citra.out", "gateway->citra", payload, &message);
        }
        return queued;
    }

    bool queue_frame(Client& client, const citra_room::Bytes& payload) {
        if (payload.size() > options_.max_frame_bytes) {
            ++counters_.oversize_rejections;
            ++counters_.frames_rejected;
            return false;
        }
        room_client::Bytes framed;
        if (client.enet) {
            // One ENet packet per citra_room v4 message: the wire carries no
            // length prefix, and a real Citra dispatches on data[0], the message
            // id (citra-master/src/network/room_member.cpp:166).
            framed = payload;
        } else {
            framed.reserve(payload.size() + 4);
            const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
            framed.push_back(static_cast<std::uint8_t>((length >> 24) & 0xFF));
            framed.push_back(static_cast<std::uint8_t>((length >> 16) & 0xFF));
            framed.push_back(static_cast<std::uint8_t>((length >> 8) & 0xFF));
            framed.push_back(static_cast<std::uint8_t>(length & 0xFF));
            framed.insert(framed.end(), payload.begin(), payload.end());
        }
        if (client.outbox.size() >= options_.per_client_outbox_frames ||
            client.outbox_bytes + framed.size() > options_.per_client_outbox_bytes) {
            ++counters_.outbox_overflows;
            ++counters_.queue_overflows;
            add_event("queue.overflow", client.id, "outbound");
            close_after_flush(client, "outbound queue limit");
            return false;
        }
        client.outbox_bytes += framed.size();
        client.outbox.push_back(std::move(framed));
        ++counters_.frames_out;
        ++client.frames_out;
        return true;
    }

    bool gu_guest_role(const Client& client) const {
        return options_.ldn_gu_host_discovery &&
               (!options_.ldn_dual_host || (!client.dual_citra_host && !client.dual_local_host));
    }

    bool game_return_role(const Client& client) const {
        return options_.ldn_game_return && (!options_.ldn_dual_host || client.dual_citra_host);
    }

    void retire_dual_host(Client& host) {
        if (host.control) {
            for (const auto& station : host.control->stations()) {
                ControlEmission e;e.kind="room.dual_host.destroy";
                e.ldn_type=room_client::LdnType::DestroyNetwork;e.ldn_remote_ip=station.fake_ip;
                emit_control(host,{e});
            }
        }
        for (auto& other : clients_) {
            if (other.get()==&host || other->phase!=ClientPhase::Joined ||
                other->dual_local_host!=host.mac) continue;
            citra_room::WifiPacket deauth;deauth.type=citra_room::FrameType::Deauthentication;
            deauth.channel=host.dual_host_channel;deauth.transmitter=host.mac;deauth.destination=other->mac;
            deauth.data=citra_control::build_deauthentication_frame().value;
            send_citra(*other,deauth);
            other->dual_local_host.reset();initialize_control(*other);
        }
        add_event("dual.host.retired",host.id,"native guests and local associations cleared");
    }

    void forget_dual_local_peer(Client& client) {
        if (!client.dual_local_host) return;
        for (const auto& host : clients_)
            if (host->dual_citra_host && host->mac == *client.dual_local_host && host->control)
                emit_control(*host, host->control->forget_citra_host_peer(client.mac));
    }

    void reset_dual_role(Client& client) {
        forget_dual_local_peer(client);
        if (client.dual_citra_host) retire_dual_host(client);
        else if (client.control) emit_control(client,client.control->on_transport_departure());
        client.dual_citra_host=false;client.dual_local_host.reset();
        client.dual_local_identity.reset();client.dual_local_node_id=0;
        client.return_profile_known=false;client.return_network_id.reset();
        initialize_control(client);
        add_event("dual.role",client.id,"GU discovery");
    }

    bool handle_dual_wifi(Client& client,const citra_room::WifiPacket& wifi) {
        const auto stamp=now_ms();
        if (wifi.type==citra_room::FrameType::Beacon) {
            const auto beacon=citra_control::parse_beacon_frame(wifi.data.data(),wifi.data.size(),wifi.transmitter);
            // Beacon tags omit host_mac_address; source-bound decryption authenticates that field.
            if (!beacon.ok() || beacon.value.network_info.wlan_comm_id!=options_.uds_wlan_comm_id ||
                beacon.value.appdata_size!=200 || beacon.value.nodes.empty() ||
                beacon.value.nodes[0].network_node_id!=1) return true;
            const auto seed=beacon.value.nodes[0].friend_code_seed;
            const auto network=beacon.value.network_info.network_id;
            if (!client.dual_citra_host || client.dual_host_seed!=seed || client.dual_host_network!=network) {
                if (client.dual_local_host) forget_dual_local_peer(client);
                if (client.dual_citra_host) retire_dual_host(client);
                else if (client.control) emit_control(client,client.control->on_transport_departure());
                client.dual_citra_host=true;client.dual_local_host.reset();
                client.dual_host_seed=seed;client.dual_host_network=network;
                client.return_profile_known=false;client.return_network_id.reset();
                initialize_control(client);
                add_event("dual.role",client.id,"Citra host");
            }
            client.dual_host_channel=wifi.channel;client.dual_last_beacon_ms=stamp;
            for (auto& other:clients_) {
                if (other.get()==&client || other->phase!=ClientPhase::Joined || other->dual_citra_host) continue;
                const bool same_local=other->dual_local_host==client.mac;
                const bool idle=!other->dual_local_host && other->control && !other->control->gu_host_guest_identity();
                if (same_local || idle) send_citra(*other,wifi);
            }
            return false; // The real host beacon also updates its forward LDN advertisement.
        }
        if (!client.dual_citra_host && wifi.type==citra_room::FrameType::Authentication) {
            for (auto& host:clients_) {
                if (host->phase!=ClientPhase::Joined || !host->dual_citra_host || host->mac!=wifi.destination) continue;
                if (client.control) emit_control(client,client.control->on_transport_departure());
                forget_dual_local_peer(client);
                client.control.reset();client.dual_local_host=host->mac;
                client.dual_local_identity.reset();client.dual_local_node_id=0;
                add_event("dual.role",client.id,"local Citra guest");break;
            }
        }
        if (client.dual_local_host) {
            if (wifi.type == citra_room::FrameType::Data) {
                const auto start = citra_control::parse_eapol_start_frame(wifi.data.data(), wifi.data.size());
                if (start.ok() && wifi.destination == *client.dual_local_host && !client.dual_local_node_id)
                    client.dual_local_identity = start.value.node;
            }
            bool host_alive=false;
            for (auto& other:clients_) {
                if (other->phase!=ClientPhase::Joined)continue;
                const bool host=other->dual_citra_host && other->mac==*client.dual_local_host;
                host_alive |= host;
                if (host && other->control && client.dual_local_identity && client.dual_local_node_id) {
                    CitraHostPeerIdentity identity{client.mac, client.fake_ip,
                        *client.dual_local_identity, client.dual_local_node_id};
                    const auto emissions = other->control->on_citra_host_peer_game(wifi, identity, stamp);
                    if (!emissions.empty()) {
                        emit_control(client, emissions);
                        add_event("dual.peer.to_gu", client.id, mac_to_string(wifi.destination));
                    }
                }
                const bool sibling=other->dual_local_host==client.dual_local_host;
                if (other.get()!=&client && (host || sibling) &&
                    (wifi.destination==citra_room::broadcast_mac || wifi.destination==other->mac)) {
                    if(send_citra(*other,wifi))++counters_.payload_forwarded;
                }
            }
            if(!host_alive || wifi.type==citra_room::FrameType::Deauthentication)reset_dual_role(client);
            return true;
        }
        if (client.dual_citra_host) {
            bool local_destination=false;
            for(auto& other:clients_) {
                if(other->phase!=ClientPhase::Joined || other->dual_local_host!=client.mac)continue;
                if(wifi.destination==citra_room::broadcast_mac || wifi.destination==other->mac) {
                    if (wifi.type == citra_room::FrameType::Data && other->dual_local_identity) {
                        const auto logoff = citra_control::parse_eapol_logoff_frame(wifi.data.data(), wifi.data.size());
                        if (logoff.ok() && logoff.value.assigned_node_id >= 2 &&
                            logoff.value.assigned_node_id <= 4) {
                            const auto id = logoff.value.assigned_node_id;
                            const auto& node = logoff.value.nodes[id - 1];
                            if (node.network_node_id == id &&
                                node.friend_code_seed == other->dual_local_identity->friend_code_seed &&
                                node.username == other->dual_local_identity->username) {
                                other->dual_local_node_id = id;
                                if (client.control) emit_control(client, client.control->register_citra_host_peer(
                                    CitraHostPeerIdentity{other->mac, other->fake_ip, node, id}));
                            }
                        }
                    }
                    if(send_citra(*other,wifi))++counters_.payload_forwarded;
                    if(wifi.destination==other->mac)local_destination=true;
                    if(wifi.type==citra_room::FrameType::Deauthentication) {
                        if (client.control) emit_control(client, client.control->forget_citra_host_peer(other->mac));
                        other->dual_local_host.reset();initialize_control(*other);
                    }
                }
            }
            if(wifi.type==citra_room::FrameType::Deauthentication && wifi.destination==citra_room::broadcast_mac) {
                reset_dual_role(client);return true;
            }
            if(local_destination)return true;
        }
        return false;
    }

    void forward_wifi(Client& client, const citra_room::WifiPacket& wifi) {
        if (client.phase != ClientPhase::Joined || !client.transport) {
            ++counters_.unsupported_in_phase_rejections;
            return;
        }
        // Bind every frame to its registered peer before any control-plane
        // handler can mutate the association or cached identity.
        if (is_sentinel_mac(wifi.transmitter)) {
            ++counters_.sentinel_mac_rejections;
            ++counters_.payload_rejected_source;
            add_event("payload.rejected.sentinel_mac", client.id, mac_to_string(wifi.transmitter));
            return;
        }
        if (!(wifi.transmitter == client.mac)) {
            ++counters_.payload_rejected_source;
            add_event("payload.rejected.transmitter", client.id, mac_to_string(wifi.transmitter));
            return;
        }
        // V-262: census every accepted inbound Wi-Fi frame before any handler can
        // consume it, so inbound.json explains which side is the UDS host.
        note_inbound_wifi(wifi);
        if (options_.ldn_dual_host && handle_dual_wifi(client, wifi)) return;
        // V-047/V-048: peer relay wins over a control bridge if both are somehow
        // set in-process (the CLI refuses that combination).
        const bool relay = options_.citra_peer_relay;
        if (client.control && !relay) {
            // G-b' section 7.2: non Data frame types are control-plane frames.
            if (wifi.type != citra_room::FrameType::Data) {
                if (game_return_role(client)) {
                    if (wifi.type == citra_room::FrameType::Beacon) {
                        const auto beacon = citra_control::parse_beacon_frame(
                            wifi.data.data(), wifi.data.size(), wifi.transmitter, nullptr);
                        if (beacon.ok()) {
                            const auto network = beacon.value.network_info.network_id;
                            if (client.return_network_id && *client.return_network_id != network) {
                                client.return_profile_known = false;
                                client.control->invalidate_game_return_admission();
                                add_event("game.return.reset", client.id, "host network changed");
                            }
                            client.return_network_id = network;
                        }
                    } else if (wifi.type == citra_room::FrameType::Deauthentication) {
                        client.return_profile_known = false;
                        client.return_network_id.reset();
                        client.control->invalidate_game_return_admission();
                    }
                }
                emit_control(client, client.control->on_citra_wifi(wifi, now_ms()));
                return;
            }
            const auto ether =
                citra_control::llc_ether_type(wifi.data.data(), wifi.data.size(), nullptr);
            if (ether.ok() && ether.value == citra_control::EtherType::Eapol) {
                if (gu_guest_role(client)) {
                    emit_control(client, client.control->on_citra_wifi(wifi, now_ms()));
                    return;
                }
                emit_control(client, client.control->on_citra_eapol(wifi.data, now_ms()));
                return;
            }
            if (ether.ok() && ether.value == citra_control::EtherType::SecureData) {
                const auto secure = citra_control::parse_secure_data_frame(
                    wifi.data.data(), wifi.data.size(), nullptr);
                if (!secure.ok()) {
                    ++counters_.payload_rejected_boundary;
                    add_event("payload.rejected.secure_data", client.id, "invalid frame");
                    return;
                }
                if (options_.ldn_gu_host_admission && gu_guest_role(client)) {
                    refresh_gu_guest_identities();
                    for (const auto& recipient : clients_) {
                        if (recipient.get() == &client || recipient->phase != ClientPhase::Joined ||
                            !recipient->control || !recipient->control->accepts_gu_host_peer_wifi(wifi)) continue;
                        if (send_citra(*recipient, wifi)) {
                            ++counters_.payload_forwarded;
                            record_emitted(recipient->id, "citra", "citra.gu_host.peer", wifi.data);
                            add_event("gu.peer.forwarded", client.id, std::to_string(recipient->id));
                        }
                    }
                    emit_control(client, client.control->on_gu_native_peer_game(wifi));
                    emit_control(client, client.control->on_gu_host_guest_game(wifi));
                    return;
                }
                // V-263: when the Citra side is the UDS *host* (measured:
                // MHXX creates the hall, src_node_id 1) its game traffic never
                // passes the guest-side source rule below.  A payload carrying
                // the 32AB9864 game magic is the cross-game packet the control
                // plane translates and hands to the Yuzu members.
                // V-265: hand over the whole UDS frame (LLC + UDS header +
                // payload).  The room proxy channel carries frames, not bare
                // payloads; the bridge substitutes only the identity words.
                if (secure.value.payload.size() >= 32 && secure.value.payload[0] == 0x32
                    && secure.value.payload[1] == 0xab && secure.value.payload[2] == 0x98
                    && secure.value.payload[3] == 0x64) {
                    if (game_return_role(client) && client.return_network_id &&
                        secure.value.header.src_node_id == 1 &&
                        secure.value.header.data_channel != 0 && wifi.channel >= 1 && wifi.channel <= 14) {
                        client.return_data_channel = secure.value.header.data_channel;
                        client.return_wifi_channel = wifi.channel;
                        client.return_profile_known = true;
                    }
                    emit_control(client, client.control->on_citra_game_payload(wifi.data));
                    return;
                }
                // This control bridge serves a directly associated guest, not
                // a host forwarding traffic on behalf of other UDS nodes.
                if (secure.value.header.src_node_id != kControlCitraPeerNodeId) {
                    ++counters_.payload_rejected_source;
                    add_event("payload.rejected.secure_source", client.id,
                              std::to_string(secure.value.header.src_node_id));
                    return;
                }
                // Declared: UDS payload traffic needs an established UDS session.
                if (!client.control->on_citra_secure_data()) {
                    return;
                }
                // V-112: a real guest answers the host's game-layer traffic with
                // its own; script steps can be anchored to those arrivals.
                note_guest_game_frame(client, now_ms(), secure.value.payload);
            } else {
                // Not an LLC frame at all: this is G-b opaque payload, forwarded
                // unchanged (section 7.2 event 10 covers only decoded UDS frames).
                client.control->note_opaque_data();
            }
        }
        if (!relay && wifi.type != citra_room::FrameType::Data) {
            ++counters_.payload_rejected_unknown_category;
            add_event("payload.rejected.unknown", client.id,
                      std::string("citra frame ") + citra_room::frame_type_name(wifi.type));
            return;
        }
        bool broadcast = false;
        IPv4 destination_ip{};
        if (wifi.destination == citra_room::broadcast_mac) {
            broadcast = true;
            destination_ip = client.fake_ip;
        } else if (wifi.destination == client.mac) {
            ++counters_.self_echo_rejections;
            ++counters_.payload_rejected_destination;
            add_event("payload.rejected.self_echo", client.id, mac_to_string(wifi.destination));
            return;
        } else {
            const auto destination = identities_.ip_for_mac(wifi.destination);
            if (!destination) {
                // Fail closed: a non-broadcast destination that is not a mapped
                // session member is rejected, never widened into a broadcast.
                ++counters_.destination_unmapped_rejections;
                ++counters_.payload_rejected_destination;
                add_event("payload.rejected.destination", client.id,
                          mac_to_string(wifi.destination));
                return;
            }
            destination_ip = *destination;
        }
        // V-047/V-048: in relay mode every WifiPacket type travels the same path
        // as Data. The Yuzu ProxyPacket cannot express the frame type or channel,
        // so a 7 byte CRLY wrapper is prepended to the plain payload before Zstd;
        // the receiver restores both fields from it.
        citra_room::Bytes relay_plain;
        const citra_room::Bytes* plain_payload = &wifi.data;
        if (relay) {
            relay_plain.reserve(kPeerRelayHeaderBytes + wifi.data.size());
            relay_plain.push_back(kPeerRelayMagic[0]);
            relay_plain.push_back(kPeerRelayMagic[1]);
            relay_plain.push_back(kPeerRelayMagic[2]);
            relay_plain.push_back(kPeerRelayMagic[3]);
            relay_plain.push_back(kPeerRelayVersion);
            relay_plain.push_back(static_cast<std::uint8_t>(wifi.type));
            relay_plain.push_back(wifi.channel);
            relay_plain.insert(relay_plain.end(), wifi.data.begin(), wifi.data.end());
            plain_payload = &relay_plain;
        }
        room_client::Bytes compressed;
        std::string why;
        if (!compress_proxy_frame(*plain_payload, options_.proxy_compressed_bytes,
                                  options_.zstd_level, compressed, &why)) {
            ++counters_.payload_rejected_boundary;
            add_event("payload.rejected.boundary", client.id, why);
            return;
        }
        room_client::ProxyPacket proxy;
        proxy.local.family = room_client::Domain::Inet;
        proxy.local.ip = client.fake_ip;
        proxy.local.port = options_.proxy_port_placeholder;
        proxy.remote.family = room_client::Domain::Inet;
        proxy.remote.ip = destination_ip;
        proxy.remote.port = options_.proxy_port_placeholder;
        proxy.protocol = room_client::SocketProtocol::Udp;
        proxy.broadcast = broadcast;
        proxy.data = std::move(compressed);
        bool sent = false;
        try {
            sent = client.transport->send(proxy);
        } catch (const std::exception& error) {
            ++counters_.room_frames_rejected;
            ++counters_.payload_rejected_boundary;
            add_event("payload.send.failed", client.id, error.what());
            return;
        }
        if (!sent) {
            ++counters_.outbox_overflows;
            ++counters_.payload_rejected_boundary;
            add_event("payload.send.backpressure", client.id, "");
            return;
        }
        const std::uint64_t content =
            ZSTD_getFrameContentSize(proxy.data.data(), proxy.data.size());
        ++counters_.proxy_frames_emitted;
        ++counters_.payload_forwarded;
        if (relay) {
            // The wrapper carries the original channel, so no placeholder was
            // substituted and this frame is not a channel normalisation.
            ++counters_.peer_relay_frames_emitted;
        } else {
            ++counters_.channel_normalized;
        }
        last_forwarded_proxy_ = proxy;
        trace_write("proxy.out", "gateway->room", proxy.data.data(), proxy.data.size(),
                    trace_decode_yuzu_proxy(proxy.data.data(), proxy.data.size(),
                                            plain_payload->data(), plain_payload->size(), true));
        record_capture("citra_to_room", client, proxy.broadcast, mac_to_string(client.mac),
                       broadcast ? mac_to_string(citra_room::broadcast_mac)
                                 : mac_to_string(wifi.destination),
                       ip_to_string(client.fake_ip), ip_to_string(destination_ip),
                       proxy.data.size(), static_cast<std::size_t>(content), *plain_payload);
    }

    void on_inbound_proxy(Client& client, const room_client::ProxyPacket& proxy) {
        if (client.phase != ClientPhase::Joined || !client.transport) {
            ++counters_.unsupported_in_phase_rejections;
            return;
        }
        const auto room_snapshot = client.transport->snapshot();
        if (!room_snapshot.room) {
            ++counters_.unknown_source_rejections;
            ++counters_.payload_rejected_source;
            add_event("payload.rejected.source", client.id, "no cached room information");
            return;
        }
        // Gateway-owned member table check: the original relay validates neither
        // membership nor local_ip == the sender's assigned fake IPv4.
        bool member_known = false;
        for (const auto& member : room_snapshot.room->members) {
            if (member.fake_ip == proxy.local.ip) {
                member_known = true;
                break;
            }
        }
        if (options_.ldn_dual_host && client.dual_local_host) {
            if (!member_known || !client.dual_local_identity || !client.dual_local_node_id ||
                proxy.broadcast || proxy.remote.ip != client.fake_ip ||
                proxy.protocol != room_client::SocketProtocol::Udp ||
                proxy.local.family != room_client::Domain::Inet || proxy.remote.family != room_client::Domain::Inet ||
                !options_.proxy_udp_port || proxy.local.port != options_.proxy_udp_port ||
                proxy.remote.port != options_.proxy_udp_port) return;
            for (const auto& host : clients_) {
                if (host->phase != ClientPhase::Joined || !host->dual_citra_host ||
                    host->mac != *client.dual_local_host || !host->control) continue;
                citra_room::Bytes plain;
                if (!decompress_proxy_frame(proxy.data, options_.proxy_decompressed_bytes, plain, nullptr)) return;
                const CitraHostPeerIdentity identity{client.mac, client.fake_ip,
                    *client.dual_local_identity, client.dual_local_node_id};
                trace_write("proxy.peer.in", "room->gateway", proxy.data.data(), proxy.data.size(),
                    trace_decode_yuzu_proxy(proxy.data.data(), proxy.data.size(), plain.data(), plain.size(), true));
                const auto emissions = host->control->on_citra_host_peer_proxy(proxy.local.ip, plain, identity, now_ms());
                if (emissions.empty()) {
                    add_event("dual.peer.rejected", client.id,
                        ip_to_string(proxy.local.ip) + " length=" + std::to_string(plain.size()) +
                        " kind=" + (plain.size() > 5 ? std::to_string(plain[5]) : "short"));
                }
                if (!emissions.empty()) {
                    ++counters_.proxy_frames_consumed;
                    trace_write("proxy.in", "room->gateway", proxy.data.data(), proxy.data.size(),
                        trace_decode_yuzu_proxy(proxy.data.data(), proxy.data.size(), plain.data(), plain.size(), true));
                    emit_control(client, emissions);
                    add_event("dual.peer.from_gu", client.id, ip_to_string(proxy.local.ip));
                }
                return;
            }
            return;
        }
        if (member_known && gu_guest_role(client) && client.control &&
            client.control->gu_native_peer_source(proxy.local.ip)) {
            if (proxy.broadcast || proxy.remote.ip != client.fake_ip ||
                proxy.protocol != room_client::SocketProtocol::Udp ||
                proxy.local.family != room_client::Domain::Inet || proxy.remote.family != room_client::Domain::Inet ||
                proxy.local.port != 12345 || proxy.remote.port != 12345) return;
            citra_room::Bytes plain;
            if (!decompress_proxy_frame(proxy.data, options_.proxy_decompressed_bytes, plain, nullptr)) return;
            const auto emissions = client.control->on_gu_native_peer_proxy(proxy.local.ip, plain);
            trace_write("proxy.native_peer.in", "room->gateway", proxy.data.data(), proxy.data.size(),
                trace_decode_yuzu_proxy(proxy.data.data(), proxy.data.size(), plain.data(), plain.size(), true));
            if (emissions.empty()) add_event("gu.native_peer.rejected", client.id, ip_to_string(proxy.local.ip));
            else { ++counters_.proxy_frames_consumed; emit_control(client, emissions); }
            return;
        }
        auto source_mac = identities_.mac_for_ip(proxy.local.ip);
        const bool gu_host_source = member_known && options_.ldn_gu_host_admission &&
            client.control && client.control->gu_host_source(proxy.local.ip);
        std::optional<ControlStation> return_station;
        if (!source_mac && member_known && game_return_role(client) && client.control &&
            !options_.citra_peer_relay) {
            return_station = client.control->game_return_station(proxy.local.ip);
            if (return_station) {
                source_mac = return_station->mac;
            }
        }
        if (!member_known || (!source_mac && !gu_host_source)) {
            ++counters_.unknown_source_rejections;
            ++counters_.payload_rejected_source;
            add_event("payload.rejected.source", client.id, ip_to_string(proxy.local.ip));
            return;
        }
        if (!proxy.broadcast) {
            if (proxy.local.ip == proxy.remote.ip) {
                ++counters_.self_echo_rejections;
                ++counters_.payload_rejected_destination;
                add_event("payload.rejected.self_echo", client.id, ip_to_string(proxy.remote.ip));
                return;
            }
            if (!(proxy.remote.ip == client.fake_ip)) {
                ++counters_.payload_rejected_destination;
                add_event("payload.rejected.destination", client.id,
                          ip_to_string(proxy.remote.ip));
                return;
            }
        }
        if (return_station &&
            (!client.return_profile_known || !client.return_network_id ||
             proxy.protocol != room_client::SocketProtocol::Udp ||
             proxy.local.family != room_client::Domain::Inet ||
             proxy.remote.family != room_client::Domain::Inet ||
             options_.proxy_udp_port == 0 || proxy.local.port != options_.proxy_udp_port ||
             proxy.remote.port != options_.proxy_udp_port)) {
            ++counters_.payload_rejected_boundary;
            add_event("game.return.rejected", client.id, "channel profile or UDP endpoints");
            return;
        }
        citra_room::Bytes plain;
        std::string why;
        if (gu_host_source &&
            (proxy.protocol != room_client::SocketProtocol::Udp ||
             proxy.local.family != room_client::Domain::Inet ||
             proxy.remote.family != room_client::Domain::Inet ||
             proxy.local.port != 12345 || proxy.remote.port != 12345)) {
            ++counters_.payload_rejected_boundary;
            add_event("gu.host.rejected", client.id, "announcement UDP boundary");
            return;
        }
        if (!decompress_proxy_frame(proxy.data, options_.proxy_decompressed_bytes, plain, &why)) {
            ++counters_.payload_rejected_boundary;
            add_event("payload.rejected.boundary", client.id, why);
            return;
        }
        if (gu_host_source) {
            refresh_gu_guest_identities();
            const auto emissions = client.control->on_gu_host_proxy(proxy.local.ip, plain);
            if (emissions.empty()) {
                ++counters_.payload_rejected_boundary;
                add_event("gu.host.rejected", client.id, "unsupported announcement or identity map");
                return;
            }
            ++counters_.proxy_frames_consumed;
            trace_write("proxy.in", "room->gateway", proxy.data.data(), proxy.data.size(),
                        trace_decode_yuzu_proxy(proxy.data.data(), proxy.data.size(),
                                                plain.data(), plain.size(), true));
            emit_control(client, emissions);
            return;
        }
        if (return_station) {
            const auto translated = client.control->translate_game_return(proxy.local.ip, plain);
            if (!translated) {
                ++counters_.payload_rejected_boundary;
                add_event("game.return.rejected", client.id, "unsupported MH control frame or identity map");
                return;
            }
            citra_control::SecureDataFrame frame;
            frame.header.data_channel = client.return_data_channel;
            frame.header.sequence_number = 0; // Citra SendDataPacket also uses 0.
            frame.header.src_node_id = return_station->uds_node_id;
            frame.header.dest_node_id = proxy.broadcast ? 0xffff : 1;
            frame.payload = *translated;
            const auto encoded = citra_control::build_secure_data_frame(frame, nullptr);
            if (!encoded.ok()) {
                ++counters_.payload_rejected_boundary;
                add_event("game.return.rejected", client.id, "UDS encode failed");
                return;
            }
            citra_room::WifiPacket wifi;
            wifi.type = citra_room::FrameType::Data;
            wifi.channel = client.return_wifi_channel;
            wifi.transmitter = return_station->mac;
            wifi.destination = proxy.broadcast ? citra_room::broadcast_mac : client.mac;
            wifi.data = encoded.value;
            ++counters_.proxy_frames_consumed;
            trace_write("proxy.in", "room->gateway", proxy.data.data(), proxy.data.size(),
                        trace_decode_yuzu_proxy(proxy.data.data(), proxy.data.size(),
                                                plain.data(), plain.size(), true));
            if (send_citra(client, wifi)) {
                ++counters_.payload_forwarded;
                record_emitted(client.id, "citra", "citra.game.return", wifi.data);
                add_event("game.return.forwarded", client.id, ip_to_string(proxy.local.ip));
            }
            return;
        }
        // V-245: feed the heartbeat learner before any boundary decision.  This
        // is metadata-only (kind/sender/time words) -- the frame itself stays
        // gated exactly as before.
        if (client.control) {
            const std::array<std::uint8_t, 4> sender_bytes = {proxy.local.ip[0], proxy.local.ip[1],
                                                              proxy.local.ip[2], proxy.local.ip[3]};
            for (std::size_t scan = 0; scan + 12 <= plain.size(); ++scan) {
                if (plain[scan] == 0x32 && plain[scan + 1] == 0xab && plain[scan + 2] == 0x98
                    && plain[scan + 3] == 0x64) {
                    const std::uint16_t seq =
                        static_cast<std::uint16_t>((plain[scan + 6] << 8) | plain[scan + 7]);
                    const std::uint16_t rel_time =
                        static_cast<std::uint16_t>((plain[scan + 8] << 8) | plain[scan + 9]);
                    const std::uint16_t time_echo =
                        static_cast<std::uint16_t>((plain[scan + 10] << 8) | plain[scan + 11]);
                    client.control->observe_heartbeat(sender_bytes, plain[scan + 5], seq, rel_time,
                                                      time_echo);
                    break;
                }
            }
        }
        ++counters_.proxy_frames_consumed;
        last_inbound_proxy_ = proxy;
        trace_write("proxy.in", "room->gateway", proxy.data.data(), proxy.data.size(),
                    trace_decode_yuzu_proxy(proxy.data.data(), proxy.data.size(), plain.data(),
                                            plain.size(), true));
        // V-047/V-048: a relay peer wraps the WifiPacket type and channel in a
        // 7 byte CRLY header. Only a matching magic is unwrapped; anything else
        // keeps the frozen Data/placeholder defaults, so a non-relay peer (or a
        // plain Data frame) is decoded exactly as before.
        citra_room::FrameType wifi_type = citra_room::FrameType::Data;
        std::uint8_t wifi_channel = options_.wifi_channel_placeholder;
        bool wrapped = false;
        if (options_.citra_peer_relay && peer_relay_wrapper(plain)) {
            const std::uint8_t version = plain[4];
            const std::uint8_t wrapped_type = plain[5];
            if (version != kPeerRelayVersion || wrapped_type > kPeerRelayMaxType) {
                ++counters_.peer_relay_bad_wrapper;
                add_event("payload.rejected.peer_relay_wrapper", client.id,
                          std::string("citra relay wrapper version ") +
                              std::to_string(version) + " type " +
                              std::to_string(wrapped_type));
                return;
            }
            wrapped = true;
            wifi_type = static_cast<citra_room::FrameType>(wrapped_type);
            wifi_channel = plain[6];
            plain.erase(plain.begin(),
                        plain.begin() + static_cast<std::ptrdiff_t>(kPeerRelayHeaderBytes));
        }
        const std::uint64_t content =
            wrapped ? static_cast<std::uint64_t>(plain.size())
                    : ZSTD_getFrameContentSize(proxy.data.data(), proxy.data.size());
        citra_room::WifiPacket wifi;
        wifi.type = wifi_type;
        wifi.channel = wifi_channel;
        wifi.transmitter = *source_mac;
        wifi.destination =
            proxy.broadcast ? citra_room::broadcast_mac : client.mac;
        wifi.data = std::move(plain);
        if (!send_citra(client, wifi)) {
            return;
        }
        ++counters_.payload_forwarded;
        if (wrapped) {
            ++counters_.peer_relay_frames_consumed;
        } else {
            ++counters_.channel_normalized;
        }
        record_capture("room_to_citra", client, proxy.broadcast, mac_to_string(*source_mac),
                       mac_to_string(wifi.destination), ip_to_string(proxy.local.ip),
                       ip_to_string(proxy.remote.ip), proxy.data.size(),
                       static_cast<std::size_t>(content), wifi.data);
    }

    void record_capture(const std::string& direction, const Client& client, bool broadcast,
                        const std::string& source_mac, const std::string& destination_mac,
                        const std::string& source_ip, const std::string& destination_ip,
                        std::size_t wire_bytes, std::size_t content_bytes,
                        const citra_room::Bytes& opaque) {
        if (captures_.size() >= options_.capture_limit) {
            captures_.pop_front();
        }
        DataPlaneCapture capture;
        capture.direction = direction;
        capture.client_id = client.id;
        capture.broadcast = broadcast;
        capture.source_mac = source_mac;
        capture.destination_mac = destination_mac;
        capture.source_ip = source_ip;
        capture.destination_ip = destination_ip;
        capture.wire_bytes = wire_bytes;
        capture.content_bytes = content_bytes;
        capture.opaque_bytes = opaque.size();
        capture.opaque_hex = hex_of(opaque, 512);
        captures_.push_back(std::move(capture));
    }

    // G2 trace helpers. trace_write is the only place that touches the trace
    // file; a runtime write failure disables tracing and records an event but
    // never changes cross-plane protocol behaviour.
    TraceStamp trace_stamp() const {
        if (options_.trace_clock) {
            return options_.trace_clock();
        }
        TraceStamp stamp;
        stamp.utc = trace_utc_now();
        stamp.monotonic_ms = trace_monotonic_ms();
        return stamp;
    }

    void trace_write(const std::string& event_label, const std::string& direction,
                     const std::uint8_t* data, std::size_t size, TraceStructure structure) {
        if (!trace_.enabled()) {
            return;
        }
        TraceRecord record = trace_make_record(options_.trace_context, event_label, direction,
                                               trace_stamp(), data, size, structure,
                                               trace_.raw_enabled());
        std::string why;
        if (!trace_.write(record, &why)) {
            add_event("trace.write.failed", 0, why);
            trace_.close();
        }
    }

    // Writes one self-describing marker (run.begin / stage.begin). Markers carry
    // no frame bytes, so raw tracing never embeds them.
    void trace_write_marker(const std::string& event_label) {
        if (!trace_.enabled()) {
            return;
        }
        TraceRecord record = trace_make_marker(options_.trace_context, event_label, trace_stamp());
        std::string why;
        if (!trace_.write(record, &why)) {
            add_event("trace.write.failed", 0, why);
            trace_.close();
        }
    }

    // Reads Options::trace_stage_file. Returns true when the content changed and
    // updates the run stage; an unreadable file is ignored (tracing must never
    // change cross-plane protocol behaviour). With announce, a change also
    // appends one stage.begin marker.
    bool trace_refresh_stage(bool announce) {
        if (!trace_.enabled() || options_.trace_stage_file.empty()) {
            return false;
        }
        std::ifstream in;
        try {
            in.open(trace_path_from_narrow(options_.trace_stage_file), std::ios::binary);
        } catch (...) {
            return false;
        }
        if (!in) {
            return false;
        }
        std::string stage((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        while (!stage.empty() && (stage.back() == '\n' || stage.back() == '\r')) {
            stage.pop_back();
        }
        if (stage == options_.trace_context.stage) {
            return false;
        }
        options_.trace_context.stage = stage;
        if (announce) {
            trace_write_marker("stage.begin");
        }
        return true;
    }

    // Citra channel: a WifiPacket body decodes to LLC/SecureData fields; every
    // other category has no LLC structure and is recorded under its own name.
    void trace_citra_frame(const std::string& event_label, const std::string& direction,
                           const citra_room::Bytes& frame, const citra_room::Message* message,
                           const std::string& undecoded_reason = std::string()) {
        TraceStructure structure;
        if (message == nullptr) {
            structure.name = "citra_message";
            structure.decoded = false;
            structure.reason = undecoded_reason;
            structure.fields.push_back(trace_field_undecoded("citra_message"));
        } else if (const auto* wifi = std::get_if<citra_room::WifiPacket>(message)) {
            // trace_decode_citra_secure_data always runs the LLC/SecureData parser,
            // which reports a bogus secure_data:BadTag for every non-Data frame
            // (a Beacon is not an LLC frame at all). Only Data bodies are LLC
            // frames, so any other type is recorded under its own type name. The
            // Data path is byte-for-byte unchanged.
            if (wifi->type == citra_room::FrameType::Data) {
                structure = trace_decode_citra_secure_data(wifi->data.data(), wifi->data.size());
            } else {
                structure.name = citra_room::frame_type_name(wifi->type);
                structure.decoded = true;
                structure.fields.push_back(trace_field_string(
                    "citra_frame_type", citra_room::frame_type_name(wifi->type)));
                structure.fields.push_back(
                    trace_field_u64("wifi_channel", static_cast<std::uint64_t>(wifi->channel)));
            }
        } else {
            structure.name = "citra_message";
            structure.decoded = true;
            structure.fields.push_back(trace_field_string(
                "citra_message", citra_room::message_name(citra_room::message_id(*message))));
        }
        trace_write(event_label, direction, frame.data(), frame.size(), std::move(structure));
    }

    std::size_t drain_room(Client& client) {
        std::size_t handled = 0;
        for (;;) {
            if (!client.transport) {
                break;
            }
            std::optional<room_client::Message> message;
            try {
                message = client.transport->pop();
            } catch (const std::exception& error) {
                add_event("room.pop.failed", client.id, error.what());
                break;
            }
            if (!message) {
                break;
            }
            ++handled;
            handle_room_message(client, *message);
            if (client.phase == ClientPhase::Closed || client.phase == ClientPhase::Closing) {
                break;
            }
        }
        return handled;
    }

    void handle_room_message(Client& client, const room_client::Message& message) {
        if (const auto* room = std::get_if<room_client::RoomInformation>(&message)) {
            on_room_information(client, *room);
            return;
        }
        if (std::holds_alternative<room_client::JoinSuccess>(message)) {
            on_join_success(client);
            return;
        }
        if (const auto* proxy = std::get_if<room_client::ProxyPacket>(&message)) {
            on_inbound_proxy(client, *proxy);
            return;
        }
        if (const auto* ldn = std::get_if<room_client::LdnPacket>(&message)) {
            trace_write("ldn.in", "room->gateway", ldn->data.data(), ldn->data.size(),
                        trace_decode_yuzu_ldn(static_cast<std::uint8_t>(ldn->type),
                                              ldn->data.data(), ldn->data.size()));
            if (options_.control_plane_enabled) {
                on_ldn_message(client, *ldn);
                return;
            }
            ++counters_.payload_rejected_unknown_category;
            add_event("payload.rejected.unknown", client.id, "room IdLdnPacket");
            return;
        }
        if (std::holds_alternative<room_client::StatusMessage>(message)) {
            // Native room membership notification: no v1 Citra projection.
            add_event("room.status", client.id, "native status ignored");
            return;
        }
        if (const auto* chat = std::get_if<room_client::ChatMessage>(&message)) {
            if (client.phase == ClientPhase::Joined) {
                send_citra(client, citra_room::ChatMessage{chat->nickname, chat->username,
                                                         chat->message});
                add_event("chat.received", client.id, "upstream");
            }
            return;
        }
        ++counters_.payload_rejected_unknown_category;
        add_event("payload.rejected.unknown", client.id, "room category not declared in v1");
    }

    void on_room_information(Client& client, const room_client::RoomInformation& room) {
        room_name_ = room.name;
        counters_.members_in_room = room.members.size();
        counters_.max_members_in_room =
            std::max(counters_.max_members_in_room,
                     static_cast<std::uint64_t>(room.members.size()));
        if (client.phase != ClientPhase::Joining && client.phase != ClientPhase::Joined) {
            return;
        }
        citra_room::RoomInformation projected;
        projected.name = room.name;
        projected.description = room.description;
        projected.member_slots = room.member_slots;
        projected.port = room.port;
        projected.preferred_game = room.preferred_game_name;
        projected.host_username = room.host_username;
        bool self_found = false;
        for (const auto& member : room.members) {
            auto mac = identities_.mac_for_ip(member.fake_ip);
            if (!mac) {
                // Room-list identity only: never insert an upstream-only member
                // into identities_, which authorizes game packet routing.
                MacAddress display{0x02, 0x00, member.fake_ip[0], member.fake_ip[1],
                                   member.fake_ip[2], member.fake_ip[3]};
                while (identities_.has_mac(display)) {
                    ++display[1];
                }
                mac = display;
            }
            citra_room::Member out;
            out.nickname = member.nickname;
            out.mac = *mac;
            out.game_name = member.game.name;
            out.game_id = member.game.id;
            out.username = member.username;
            out.display_name = member.display_name;
            out.avatar_url = member.avatar_url;
            if (member.fake_ip == client.fake_ip) {
                self_found = true;
            }
            projected.members.push_back(std::move(out));
        }
        if (!self_found) {
            ++counters_.projection_missing_self;
            close_after_flush(client, "room information does not contain this member");
            return;
        }
        send_citra(client, projected);
    }

    void initialize_control(Client& client) {
            ControlOptions control_options;
            control_options.room_name = room_name_.empty() ? std::string(kControlFallbackSsid) : room_name_;
            control_options.room_seed =
                control_fnv1a32(control_options.room_name + ":" + std::to_string(options_.room_port));
            control_options.beacon_interval_ms = kControlBeaconIntervalMs;
            control_options.channel = kControlChannel;
            control_options.scene_id = 0;
            // V-111: the beacon identity profile reaches the bridge through the
            // same struct the CLI filled in.  Only the Citra Beacon reads these
            // fields, so the LDN side keeps its derived values.
            control_options.uds_wlan_comm_id = options_.uds_wlan_comm_id;
            control_options.have_uds_wlan_comm_id = options_.have_uds_wlan_comm_id;
            // V-239: the LDN-side identity override is control-plane only.
            control_options.ldn_comm_id_override = options_.ldn_comm_id_override;
            control_options.ldn_session_id = options_.ldn_session_id;
            control_options.ldn_advertise_data = options_.ldn_advertise_data;
            // V-267: live Citra beacon appdata wins over the CLI template.
            control_options.ldn_live_advertise = options_.ldn_live_advertise;
            control_options.ldn_require_live_hall = options_.ldn_require_live_hall;
            control_options.ldn_gu_host_discovery = options_.ldn_gu_host_discovery;
        control_options.ldn_gu_host_admission = options_.ldn_gu_host_admission;
            // V-259: cross-game announce forward gate + identity pairs.
            control_options.ldn_announce_forward = options_.ldn_announce_forward;
            // V-266: reverse UDS association injection gate.
            control_options.ldn_guest_inject = options_.ldn_guest_inject;
            control_options.ldn_game_return = options_.ldn_game_return;
            for (const auto& pair : options_.ldn_identity_pairs) {
                control_options.ldn_identity_pairs.push_back(
                    {pair.xx_word, pair.gu_word});
            }
            control_options.uds_beacon_id = options_.uds_beacon_id;
            control_options.have_uds_beacon_id = options_.have_uds_beacon_id;
            control_options.uds_attributes = options_.uds_attributes;
            control_options.have_uds_attributes = options_.have_uds_attributes;
            control_options.uds_network_id = options_.uds_network_id;
            control_options.have_uds_network_id = options_.have_uds_network_id;
            control_options.uds_tag_word = options_.uds_tag_word;
            control_options.have_uds_tag_word = options_.have_uds_tag_word;
            control_options.uds_appdata = options_.uds_appdata;
            control_options.have_uds_appdata = options_.have_uds_appdata;
            control_options.uds_host_seed = options_.uds_host_seed;
            control_options.have_uds_host_seed = options_.have_uds_host_seed;
            control_options.uds_host_username = options_.uds_host_username;
            control_options.have_uds_host_username = options_.have_uds_host_username;
            if (options_.ldn_dual_host) {
                const bool host = client.dual_citra_host;
                control_options.ldn_gu_host_discovery = control_options.ldn_gu_host_admission = !host;
                control_options.ldn_require_live_hall = control_options.ldn_announce_forward = host;
                control_options.ldn_guest_inject = control_options.ldn_game_return = host;
                control_options.ldn_identity_pairs.clear();
                if (host) {
                    control_options.room_seed = control_fnv1a32(control_options.room_name + ":" +
                        mac_to_string(client.mac) + ":" + std::to_string(client.dual_host_network));
                    control_options.ldn_identity_pairs.push_back(
                        {mhxx_identity_word_from_seed(client.dual_host_seed), client.fake_ip});
                }
            }
            client.control =
                std::make_unique<ControlBridge>(control_options, client.fake_ip, client.mac);
            add_event("control.start", client.id,
                      "bssid=" + mac_to_string(client.control->bssid()));
            emit_control(client, client.control->start());
    }

    void on_join_success(Client& client) {
        if (client.phase != ClientPhase::Joining || !client.transport) {
            ++counters_.unsupported_in_phase_rejections;
            return;
        }
        const auto room_snapshot = client.transport->snapshot();
        if (!room_snapshot.assigned_ip) {
            close_after_flush(client, "join success without a fake IPv4");
            return;
        }
        if (!(*room_snapshot.assigned_ip == client.fake_ip)) {
            identities_.erase_mac(client.mac);
            if (!identities_.insert(client.mac, *room_snapshot.assigned_ip, client.nickname)) {
                close_after_flush(client, "room assigned an unrepresentable fake IPv4");
                return;
            }
            client.fake_ip = *room_snapshot.assigned_ip;
            ++counters_.ip_reassigned;
        }
        citra_room::JoinSuccess success;
        success.assigned_mac = client.mac;
        success.moderator = false;
        send_citra(client, success);
        client.phase = ClientPhase::Joined;
        client.joined_room = true;
        client.joined_at = now_ms() - start_ms_;
        ++counters_.clients_joined;
        ++counters_.room_join_successes;
        add_event("join.success", client.id, client.nickname);

        if (options_.control_plane_enabled) {
            initialize_control(client);
        }

        if (client.pending_game_info) {
            const auto pending = std::move(*client.pending_game_info);
            client.pending_game_info.reset();
            note_set_game_info(client, pending);
            return;
        }
        room_client::GameInfo game;
        game.name = options_.peer_game_name;
        game.id = options_.peer_game_id;
        game.version = options_.peer_game_version;
        try {
            client.transport->send(game);
        } catch (const std::exception& error) {
            ++counters_.room_frames_rejected;
            add_event("room.send.failed", client.id, error.what());
        }
    }

    std::optional<citra_room::MessageId> map_room_error(room_client::MessageId id) const {
        switch (id) {
        case room_client::MessageId::WrongPassword:
            return citra_room::MessageId::WrongPassword;
        case room_client::MessageId::NameCollision:
            return citra_room::MessageId::NameCollision;
        case room_client::MessageId::IpCollision:
            return citra_room::MessageId::MacCollision;
        case room_client::MessageId::VersionMismatch:
            return citra_room::MessageId::VersionMismatch;
        case room_client::MessageId::CloseRoom:
            return citra_room::MessageId::CloseRoom;
        case room_client::MessageId::RoomFull:
            return citra_room::MessageId::RoomIsFull;
        case room_client::MessageId::HostKicked:
            return citra_room::MessageId::HostKicked;
        case room_client::MessageId::HostBanned:
            return citra_room::MessageId::HostBanned;
        default:
            return std::nullopt;
        }
    }

    void handle_room_failure(Client& client, const room_transport::Snapshot& room_snapshot) {
        std::string detail;
        if (room_snapshot.server_error) {
            const auto mapped = map_room_error(*room_snapshot.server_error);
            if (mapped) {
                ++counters_.room_errors_mapped;
                counters_.error_map_hits[citra_room::message_name(*mapped)]++;
                add_event("room.error.mapped", client.id,
                          std::string(room_client::message_name(*room_snapshot.server_error)) +
                              " -> " + citra_room::message_name(*mapped));
                send_error_frame(client, *mapped);
                detail = std::string("room error ") +
                         room_client::message_name(*room_snapshot.server_error) + " mapped to " +
                         citra_room::message_name(*mapped);
            } else {
                ++counters_.room_errors_unmapped;
                add_event("room.error.unmapped", client.id,
                          room_client::message_name(*room_snapshot.server_error));
                detail = std::string("unmapped room error ") +
                         room_client::message_name(*room_snapshot.server_error);
            }
        } else {
            ++counters_.room_transport_failures;
            detail = room_snapshot.failure.empty() ? std::string("room transport failure")
                                                   : room_snapshot.failure;
            add_event("room.transport.failure", client.id, detail);
        }
        close_after_flush(client, detail);
    }

    void absorb_transport_boundary(Client& client) {
        if (!client.transport) {
            return;
        }
        const auto room_snapshot = client.transport->snapshot();
        if (room_snapshot.boundary_rejections > client.last_boundary) {
            counters_.transport_boundary_rejections +=
                room_snapshot.boundary_rejections - client.last_boundary;
            client.last_boundary = room_snapshot.boundary_rejections;
        }
    }

    void pump_room(Client& client) {
        for (std::size_t i = 0; i < 16; ++i) {
            if (!client.transport) {
                return;
            }
            const auto before = client.transport->snapshot();
            try {
                client.transport->poll(0);
            } catch (const std::exception& error) {
                ++counters_.room_transport_failures;
                add_event("room.poll.failed", client.id, error.what());
                close_after_flush(client, std::string("room poll failed: ") + error.what());
                return;
            }
            const std::size_t handled = drain_room(client);
            if (!client.transport) {
                return;
            }
            if (client.phase == ClientPhase::Closed || client.phase == ClientPhase::Closing) {
                return;
            }
            absorb_transport_boundary(client);
            const auto after = client.transport->snapshot();
            if (after.state == room_transport::State::Failed) {
                handle_room_failure(client, after);
                return;
            }
            if (handled == 0 && after.queued_packets == before.queued_packets &&
                after.state == before.state) {
                return;
            }
        }
    }

    // A Citra peer is torn down only once ENet has acknowledged every queued
    // reliable frame. enet_peer_disconnect_now() resets the peer and discards
    // data the remote has received but not yet dispatched, so an immediate
    // close would lose the last frame (a real Citra client would lose the
    // version-rejection ServerError the same way). Either the last frame is
    // acknowledged, or the grace deadline expires first.
    bool close_drained(const Client& client) const {
        if (!client.outbox.empty()) {
            return false;
        }
        if (!client.enet || client.peer == nullptr) {
            return true;
        }
        return client.peer->reliableDataInTransit == 0 &&
               enet_list_empty(&client.peer->sentReliableCommands);
    }

    void pump_client(Client& client) {
        if (client.phase == ClientPhase::Closed) {
            return;
        }
        if (client.phase == ClientPhase::Closing) {
            const bool ok = flush_client(client);
            if (!ok || close_drained(client) || now_ms() >= client.close_deadline) {
                hard_close(client);
            }
            return;
        }
        if (!read_client(client)) {
            leave_client(client, "citra peer closed");
            return;
        }
        if (client.phase == ClientPhase::Closed) {
            return;
        }
        process_inbound(client);
        if (client.phase == ClientPhase::Closed || client.phase == ClientPhase::Closing) {
            if (!client.outbox.empty()) {
                flush_client(client);
            }
            if (close_drained(client) || now_ms() >= client.close_deadline) {
                hard_close(client);
            }
            return;
        }
        if (client.transport) {
            pump_room(client);
        }
        if (client.phase == ClientPhase::Closed || client.phase == ClientPhase::Closing) {
            if (!client.outbox.empty()) {
                flush_client(client);
            }
            if (close_drained(client) || now_ms() >= client.close_deadline) {
                hard_close(client);
            }
            return;
        }
        if (!flush_client(client)) {
            leave_client(client, "citra socket write failed");
            return;
        }
        if (client.phase == ClientPhase::Joining && client.transport &&
            now_ms() - client.join_started > options_.join_watchdog_ms) {
            ++counters_.join_watchdog_timeouts;
            leave_client(client, "join watchdog timeout");
        }
    }

    Options options_;
    std::uint64_t start_ms_ = 0;
    std::uint64_t event_seq_ = 0;
    std::uint64_t next_client_id_ = 0;
    bool open_ = false;
    bool closing_ = false;
    bool wsa_started_ = false;
    SOCKET listener_ = INVALID_SOCKET;
    ENetHost* enet_host_ = nullptr;
    std::uint16_t bound_port_ = 0;
    std::vector<std::unique_ptr<Client>> clients_;
    std::deque<room_client::Bytes> captures_queue_unused_;
    mutable Counters counters_;
    IdentityTable identities_;
    std::deque<DataPlaneCapture> captures_;
    std::deque<Event> events_;
    std::vector<EmittedFrame> emitted_;
    std::uint64_t emitted_seq_ = 0;
    std::string room_name_;
    // Cumulative session ledger and cumulative control-plane counters: both survive
    // the destruction of the sessions they describe.
    std::vector<SessionRecord> session_ledger_;
    std::map<std::string, std::uint64_t> control_cumulative_;
    std::uint64_t control_departed_sessions_ = 0;
    // V-262 inbound Wi-Fi frame census (bounded; feeds inbound.json).
    std::map<std::string, std::uint64_t> inbound_by_type_;
    std::map<std::string, std::vector<InboundWifiSample>> inbound_samples_;
    std::optional<room_client::ProxyPacket> last_forwarded_proxy_;
    std::optional<room_client::ProxyPacket> last_inbound_proxy_;
    citra_room::Limits citra_limits_{};
    TraceSink trace_;
};

Gateway::Gateway(Options options) : impl_(std::make_unique<Impl>(std::move(options))) {}
Gateway::~Gateway() = default;

void Gateway::open() { impl_->open(); }
void Gateway::tick(std::uint32_t wait_ms) { impl_->tick(wait_ms); }
void Gateway::close() noexcept { impl_->close(); }
void Gateway::begin_shutdown() noexcept { impl_->begin_shutdown(); }
bool Gateway::is_open() const noexcept { return impl_->is_open(); }
std::uint16_t Gateway::port() const noexcept { return impl_->port(); }
bool Gateway::trace_enabled() const noexcept { return impl_->trace_enabled(); }
std::string Gateway::trace_json() const { return impl_->trace_json(); }
Counters Gateway::counters() const { return impl_->counters(); }
std::vector<ClientSnapshot> Gateway::clients() const { return impl_->clients(); }
std::vector<IdentityEntry> Gateway::identities() const { return impl_->identities(); }
std::vector<DataPlaneCapture> Gateway::data_plane_captures() const { return impl_->captures(); }
std::vector<Event> Gateway::events() const { return impl_->events(); }
std::size_t Gateway::client_count() const { return impl_->client_count(); }
std::string Gateway::counters_json() const { return impl_->counters_json(); }
std::string Gateway::diag_text() const { return impl_->diag_text(); }
std::string Gateway::inbound_json() const { return impl_->inbound_json(); }
std::string Gateway::clients_json() const { return impl_->clients_json(); }
std::string Gateway::identities_json() const { return impl_->identities_json(); }
std::string Gateway::captures_json() const { return impl_->captures_json(); }
std::string Gateway::events_json() const { return impl_->events_json(); }
std::string Gateway::snapshot_json() const { return impl_->snapshot_json(); }
bool Gateway::inject_room_message_for_test(std::uint64_t client_id,
                                          const room_client::Message& message) {
    return impl_->inject_room_message_for_test(client_id, message);
}
bool Gateway::inject_room_raw_for_test(std::uint64_t client_id,
                                       const room_client::Bytes& raw_frame) {
    return impl_->inject_room_raw_for_test(client_id, raw_frame);
}
const std::vector<EmittedFrame>& Gateway::emitted_frames() const { return impl_->emitted_frames(); }
std::string Gateway::emitted_json() const { return impl_->emitted_json(); }
void Gateway::clear_emitted_for_test() { impl_->clear_emitted_for_test(); }
bool Gateway::inject_citra_frame_for_test(std::uint64_t client_id, const citra_room::Bytes& frame) {
    return impl_->inject_citra_frame_for_test(client_id, frame);
}
bool Gateway::inject_ldn_message_for_test(std::uint64_t client_id,
                                          const room_client::LdnPacket& packet) {
    return impl_->inject_ldn_message_for_test(client_id, packet);
}

} // namespace citra_gateway
