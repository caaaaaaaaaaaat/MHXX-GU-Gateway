// SPDX-License-Identifier: GPL-2.0-or-later
#include "room_transport/transport.hpp"
#include <enet/enet.h>
#include <zstd.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace room_transport {
namespace {
std::mutex runtime_mutex;
std::size_t runtime_refs = 0;
std::atomic_size_t hosts{0};
// Bounded grace period for a flushed graceful disconnect before the host is destroyed.
constexpr std::uint64_t disconnect_flush_ms = 200;
// Hard resource cap mirroring crossplay/lan-codecs/include/lan_codecs.h:99.
constexpr std::size_t boundary_hard_cap = 1024 * 1024;
constexpr std::size_t ldn_body_unknown = static_cast<std::size_t>(-1);
std::uint64_t now() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
struct Budget { std::size_t packets = 0, bytes = 0; };
struct Ticket { std::shared_ptr<Budget> budget; std::size_t bytes; };
void ENET_CALLBACK released(ENetPacket* packet) {
    auto* ticket = static_cast<Ticket*>(packet->userData);
    --ticket->budget->packets;
    ticket->budget->bytes -= ticket->bytes;
    delete ticket;
}
struct PacketDeleter { void operator()(ENetPacket* p) const { enet_packet_destroy(p); } };
using PacketPtr = std::unique_ptr<ENetPacket, PacketDeleter>;

// Exact LDN body length implied by the type discriminator. Lengths verified
// against 01052024-yuzu-mirror-master/src/core/hle/service/ldn/lan_discovery.cpp:
// Scan :115 SendBroadcast(Scan) -> empty; ScanResp :485 network_info 0x480;
// Connect :300 node_info 0x40; Disconnect :311 node_info 0x40;
// SyncNetwork :381 network_info 0x480; DestroyNetwork :274 -> empty.
std::size_t ldn_body_size(room_client::LdnType type) {
    using T = room_client::LdnType;
    switch (type) {
    case T::Scan: return 0;
    case T::ScanResponse: return 0x480;
    case T::Connect: return 0x40;
    case T::SyncNetwork: return 0x480;
    case T::Disconnect: return 0x40;
    case T::DestroyNetwork: return 0;
    }
    return ldn_body_unknown; // out-of-range wire discriminator: fail closed
}
bool valid_ldn_body(const room_client::LdnPacket& packet, std::string& why) {
    const auto expected = ldn_body_size(packet.type);
    if (expected == ldn_body_unknown) { why = "unknown LDN type"; return false; }
    if (packet.data.size() != expected) { why = "LDN body length"; return false; }
    return true;
}
// Exactly one complete standard Zstd frame with a known content size. Structural
// model: crossplay/lan-codecs/src/zstd_codec.cpp:17-35 (read-only). No payload is
// decoded here; semantic decoding belongs to G3/M5.
bool valid_proxy_frame(const room_client::Bytes& frame, std::size_t compressed_cap,
                       std::size_t decompressed_cap, std::string& why) {
    if (frame.size() > compressed_cap) { why = "proxy frame over compressed cap"; return false; }
    if (frame.size() < 4) { why = "proxy frame too short"; return false; }
    if (!(frame[0] == 0x28 && frame[1] == 0xB5 && frame[2] == 0x2F && frame[3] == 0xFD)) {
        why = "proxy frame is not a standard zstd frame"; return false;
    }
    const auto content = ZSTD_getFrameContentSize(frame.data(), frame.size());
    if (content == ZSTD_CONTENTSIZE_ERROR) { why = "proxy frame content size error"; return false; }
    if (content == ZSTD_CONTENTSIZE_UNKNOWN) { why = "proxy frame unknown content size"; return false; }
    if (content > decompressed_cap) { why = "proxy frame over decompressed cap"; return false; }
    const auto frame_size = ZSTD_findFrameCompressedSize(frame.data(), frame.size());
    if (ZSTD_isError(frame_size)) { why = "proxy frame malformed or incomplete"; return false; }
    if (frame_size != frame.size()) { why = "proxy frame trailing or concatenated bytes"; return false; }
    return true;
}
// After joining, inbound data must come from a known room member, must not be a
// self-echo, and if unicast must be addressed to this client. A broadcast packet
// ignores its target field. Identity/state is never mutated by this predicate.
bool valid_inbound_source(const room_client::Message& message,
                          const std::optional<room_client::RoomInformation>& room,
                          const std::optional<room_client::IPv4>& self, std::string& why) {
    room_client::IPv4 local{}, remote{};
    bool broadcast = false;
    if (const auto* ldn = std::get_if<room_client::LdnPacket>(&message)) {
        local = ldn->local_ip; remote = ldn->remote_ip; broadcast = ldn->broadcast;
    } else if (const auto* proxy = std::get_if<room_client::ProxyPacket>(&message)) {
        local = proxy->local.ip; remote = proxy->remote.ip; broadcast = proxy->broadcast;
    } else {
        return true; // control traffic (RoomInformation/Status/ServerError) is validated by M1
    }
    if (!room || !self) { why = "inbound data without room identity"; return false; }
    if (local == *self) { why = "self echo"; return false; }
    const bool member = std::any_of(room->members.begin(), room->members.end(),
        [&](const room_client::Member& m) { return m.fake_ip == local; });
    if (!member) { why = "source is not a known room member"; return false; }
    if (!broadcast && remote != *self) { why = "unicast destination is not self"; return false; }
    return true;
}
} // namespace

Runtime::Runtime() {
    const std::lock_guard lock(runtime_mutex);
    if (runtime_refs == 0 && enet_initialize() != 0) throw std::runtime_error("enet_initialize failed");
    ++runtime_refs;
}
Runtime::~Runtime() {
    const std::lock_guard lock(runtime_mutex);
    if (--runtime_refs == 0) enet_deinitialize();
}
class Transport::Impl {
public:
    Runtime runtime; // Outlives every ENet host in this object.
    const Options options;
    mutable std::mutex mutex;
    room_client::Session session;
    State state = State::Idle;
    ENetHost* host = nullptr;
    ENetPeer* peer = nullptr;
    room_client::JoinRequest request;
    std::uint64_t connecting_since = 0, leaving_since = 0;
    std::optional<room_client::MessageId> server_error;
    std::string failure;
    std::shared_ptr<Budget> budget = std::make_shared<Budget>();
    struct Event { room_client::Message message; std::size_t bytes; };
    std::deque<Event> events;
    std::size_t event_bytes = 0;
    std::size_t boundary_rejections = 0;
    std::string boundary_reason;
    explicit Impl(Options o) : options(std::move(o)), session(options.session) {
        if ((!options.allow_remote && options.address != "127.0.0.1") || options.port == 0 ||
            options.connect_timeout_ms == 0 || options.connect_timeout_ms > 60000 ||
            options.queue_packets == 0 || options.queue_packets > 1024 ||
            options.outgoing_packets == 0 || options.outgoing_packets > 1024 ||
            options.queue_bytes < options.session.limits.packet_bytes || options.queue_bytes > 4194304 ||
            options.outgoing_bytes < options.session.limits.packet_bytes || options.outgoing_bytes > 4194304 ||
            options.proxy_compressed_bytes < 4 || options.proxy_compressed_bytes > boundary_hard_cap ||
            options.proxy_decompressed_bytes == 0 || options.proxy_decompressed_bytes > boundary_hard_cap)
            throw std::invalid_argument("M2 requires numeric loopback, nonzero port, bounded time/queues/caps");
    }
    ~Impl() { close_host(); }
    // Bounded, actually-flushed graceful disconnect before the ENet host is
    // destroyed: enet_peer_disconnect + flush (first attempt on the wire now) and
    // a short service loop (retransmission / server reclamation) with a deadline.
    void close_host() noexcept {
        if (peer && host && peer->state == ENET_PEER_STATE_CONNECTED) {
            enet_peer_disconnect(peer, 0);
            enet_host_flush(host);
            const auto deadline = now() + disconnect_flush_ms;
            while (now() < deadline) {
                ENetEvent event{};
                const auto result = enet_host_service(host, &event, 2);
                if (result > 0 && event.type == ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(event.packet);
                if (result > 0 && event.type == ENET_EVENT_TYPE_DISCONNECT) break;
                if (result < 0) break;
            }
        }
        if (peer) enet_peer_disconnect_now(peer, 0); // reset even if the graceful handshake did not finish
        peer = nullptr;
        if (host) { enet_host_destroy(host); host = nullptr; --hosts; }
    }
    void clear_events() { events.clear(); event_bytes = 0; }
    void fail(const std::string& why) {
        failure = why;
        state = State::Failed;
        close_host();
        clear_events(); // no stale application data after loss of identity
        // Session failure/server error is retained for diagnostics; identity already
        // cleared by core on rejection, otherwise reset on transport failure.
        if (session.state() != room_client::SessionState::Failed) session.disconnected(now());
    }
    bool enqueue(const room_client::Bytes& bytes) {
        if (!peer || bytes.empty() || bytes.size() > options.session.limits.packet_bytes)
            throw std::runtime_error("invalid outbound packet size or peer");
        if (budget->packets >= options.outgoing_packets || bytes.size() > options.outgoing_bytes - budget->bytes)
            return false;
        auto ticket = std::make_unique<Ticket>(budget, bytes.size());
        PacketPtr packet(enet_packet_create(bytes.data(), bytes.size(), ENET_PACKET_FLAG_RELIABLE));
        if (!packet) throw std::bad_alloc();
        packet->userData = ticket.release(); packet->freeCallback = released;
        ++budget->packets; budget->bytes += bytes.size();
        if (enet_peer_send(peer, room_client::enet_channel, packet.get()) != 0)
            throw std::runtime_error("enet_peer_send failed");
        (void)packet.release(); // ENet owns until ACK/reset; callback returns budget.
        enet_host_flush(host);
        return true;
    }
    // Structural boundary gate for one decoded server->client message.
    bool boundary_ok(const room_client::Message& message, std::string& why) {
        if (const auto* ldn = std::get_if<room_client::LdnPacket>(&message)) {
            if (!valid_ldn_body(*ldn, why)) return false;
        } else if (const auto* proxy = std::get_if<room_client::ProxyPacket>(&message)) {
            if (!valid_proxy_frame(proxy->data, options.proxy_compressed_bytes,
                                   options.proxy_decompressed_bytes, why)) return false;
        } else {
            return true;
        }
        return valid_inbound_source(message, session.room(), session.assigned_ip(), why);
    }
    // Decode + boundary guard + publish. Returns false when a structural guard
    // rejected the frame (fail closed: never delivered, identity/state untouched).
    bool ingest_locked(const room_client::Bytes& bytes) {
        auto message = session.receive(bytes, now(), room_client::enet_channel);
        if (const auto* error = std::get_if<room_client::ServerError>(&message)) server_error = error->id;
        if (session.state() == room_client::SessionState::Failed) {
            // Error observable in snapshot even after native peer is reset.
            fail("server rejected/closed: " + room_client::message_name(*server_error)); return false;
        }
        std::string why;
        if (!boundary_ok(message, why)) {
            boundary_reason = why; ++boundary_rejections; return false;
        }
        events.push_back({std::move(message), bytes.size()}); event_bytes += bytes.size();
        if (session.state() == room_client::SessionState::Joined || session.state() == room_client::SessionState::Moderator)
            state = State::Joined;
        return true;
    }
    void poll_locked(std::uint32_t wait) {
        if (!host) return;
        const auto time = now();
        if (state == State::Connecting && time - connecting_since >= options.connect_timeout_ms) {
            fail("connect timeout"); return;
        }
        if (state == State::Leaving && time - leaving_since >= options.session.leave_timeout_ms) {
            close_host(); session.disconnected(time); state = State::Idle; return;
        }
        if ((state == State::Joining || state == State::Joined) && session.advance(time)) {
            fail("join timeout"); return;
        }
        ENetEvent event{};
        // Exactly one ENet event per poll; caller cannot be trapped by traffic.
        const auto result = enet_host_service(host, &event, wait);
        if (result < 0) { fail("enet_host_service failed"); return; }
        if (result == 0) return;
        if (event.type == ENET_EVENT_TYPE_CONNECT) {
            if (state != State::Connecting) { fail("unexpected connect event"); return; }
            auto bytes = session.begin_join(request, now());
            state = State::Joining;
            if (!enqueue(bytes)) fail("join backpressure");
        } else if (event.type == ENET_EVENT_TYPE_RECEIVE) {
            PacketPtr packet(event.packet);
            if (state == State::Leaving) return; // drain/free, never publish while leaving
            if (event.channelID != 0 || packet->dataLength == 0 || packet->dataLength > options.session.limits.packet_bytes ||
                !(packet->flags & ENET_PACKET_FLAG_RELIABLE)) {
                fail("invalid inbound channel/size/reliability"); return;
            }
            if (events.size() >= options.queue_packets || packet->dataLength > options.queue_bytes - event_bytes) {
                fail("inbound queue limit"); return;
            }
            room_client::Bytes bytes(packet->data, packet->data + packet->dataLength);
            (void)ingest_locked(bytes);
        } else if (event.type == ENET_EVENT_TYPE_DISCONNECT) {
            if (state == State::Leaving) { close_host(); session.disconnected(now()); state = State::Idle; }
            else fail("remote disconnected");
        }
    }
    void leave_locked() {
        if (state == State::Idle || state == State::Leaving) return;
        clear_events();
        if (state == State::Failed || state == State::Connecting) {
            close_host(); session.disconnected(now()); state = State::Idle; return;
        }
        session.begin_leave(now()); state = State::Leaving; leaving_since = now();
        enet_peer_disconnect(peer, 0); enet_host_flush(host);
    }
};
Transport::Transport(Options options) : impl_(std::make_unique<Impl>(std::move(options))) {}
Transport::~Transport() { stop(); }
void Transport::start(const room_client::JoinRequest& request) {
    const std::lock_guard lock(impl_->mutex);
    if (impl_->state != State::Idle) throw std::logic_error("start requires Idle; explicit stop after failure");
    // Validate before creating sockets (local temporary core does not send).
    room_client::Session validation(impl_->options.session); (void)validation.begin_join(request, now());
    impl_->session.reset(now()); impl_->clear_events(); impl_->server_error.reset(); impl_->failure.clear();
    impl_->boundary_rejections = 0; impl_->boundary_reason.clear();
    impl_->request = request;
    impl_->host = enet_host_create(nullptr, 1, 1, 0, 0);
    if (!impl_->host) { impl_->fail("enet_host_create failed"); return; }
    ++hosts;
    impl_->host->maximumPacketSize = impl_->options.session.limits.packet_bytes;
    impl_->host->maximumWaitingData = impl_->options.queue_bytes;
    ENetAddress address{}; address.port = impl_->options.port;
    if (enet_address_set_host_ip(&address, impl_->options.address.c_str()) != 0) {
        impl_->fail("numeric address invalid"); return;
    }
    impl_->peer = enet_host_connect(impl_->host, &address, 1, 0);
    if (!impl_->peer) { impl_->fail("enet_host_connect failed"); return; }
    enet_peer_timeout(impl_->peer, 8, 500, 1500);
    impl_->state = State::Connecting; impl_->connecting_since = now();
}
void Transport::poll(std::uint32_t wait_ms) {
    if (wait_ms > 5) throw std::invalid_argument("poll wait must be 0..5 ms");
    const std::lock_guard lock(impl_->mutex);
    try { impl_->poll_locked(wait_ms); }
    catch (const std::exception& e) { impl_->fail(e.what()); }
}
bool Transport::send(const room_client::Message& message) {
    const std::lock_guard lock(impl_->mutex);
    if (impl_->state != State::Joined) throw std::logic_error("send requires Joined");
    // Outbound fail-closed structural gate: reject before any state or wire change.
    std::string why;
    if (const auto* ldn = std::get_if<room_client::LdnPacket>(&message)) {
        if (!valid_ldn_body(*ldn, why)) throw std::invalid_argument("outbound LDN boundary: " + why);
    } else if (const auto* proxy = std::get_if<room_client::ProxyPacket>(&message)) {
        if (!valid_proxy_frame(proxy->data, impl_->options.proxy_compressed_bytes,
                               impl_->options.proxy_decompressed_bytes, why))
            throw std::invalid_argument("outbound proxy boundary: " + why);
    }
    const auto bytes = impl_->session.send(message, now());
    return impl_->enqueue(bytes);
}
std::optional<room_client::Message> Transport::pop() {
    const std::lock_guard lock(impl_->mutex);
    if (impl_->events.empty()) return {};
    auto entry = std::move(impl_->events.front()); impl_->events.pop_front(); impl_->event_bytes -= entry.bytes;
    return std::move(entry.message);
}
void Transport::leave() {
    const std::lock_guard lock(impl_->mutex);
    try { impl_->leave_locked(); }
    catch (const std::exception& e) { impl_->fail(e.what()); }
}
void Transport::stop() noexcept {
    const std::lock_guard lock(impl_->mutex);
    try {
        impl_->leave_locked();
        const auto deadline = now() + impl_->options.session.leave_timeout_ms + 10;
        while (impl_->host && impl_->state == State::Leaving && now() < deadline) impl_->poll_locked(5);
    } catch (...) { /* host reset below releases every queued packet */ }
    impl_->close_host(); impl_->clear_events();
    impl_->session.disconnected(now()); impl_->state = State::Idle;
}
bool Transport::inject_inbound_for_test(const room_client::Bytes& frame) {
    const std::lock_guard lock(impl_->mutex);
    if (impl_->state != State::Joined) throw std::logic_error("inject requires Joined");
    return impl_->ingest_locked(frame);
}
Snapshot Transport::snapshot() const {
    const std::lock_guard lock(impl_->mutex);
    return {impl_->state, impl_->session.state(), impl_->session.room(), impl_->session.assigned_ip(),
            impl_->server_error, impl_->failure, impl_->events.size(), impl_->event_bytes,
            impl_->budget->packets, impl_->budget->bytes, impl_->host != nullptr,
            impl_->boundary_rejections, impl_->boundary_reason};
}
std::size_t Transport::live_hosts() noexcept { return hosts.load(); }
std::string state_name(State state) {
    switch (state) {
    case State::Idle: return "Idle"; case State::Connecting: return "Connecting";
    case State::Joining: return "Joining"; case State::Joined: return "Joined";
    case State::Leaving: return "Leaving"; case State::Failed: return "Failed";
    }
    return "Unknown";
}
} // namespace room_transport
