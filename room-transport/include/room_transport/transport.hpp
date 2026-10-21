// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "room_client/session.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace room_transport {
// Reference-counted process ENet initialization, shared by Room and transports.
class Runtime final {
public:
    Runtime();
    ~Runtime();
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
};
enum class State { Idle, Connecting, Joining, Joined, Leaving, Failed };
struct Options {
    std::string address = "127.0.0.1"; // Deliberately numeric loopback only in M2.
    std::uint16_t port = 24872;
    std::uint32_t connect_timeout_ms = 1500;
    room_client::SessionOptions session{{}, 1500, 500};
    std::size_t queue_packets = 128;
    std::size_t queue_bytes = 262144;
    std::size_t outgoing_packets = 64;
    std::size_t outgoing_bytes = 262144;
    // Structural Proxy caps: one complete standard Zstd frame, compressed and
    // decompressed. Defaults match crossplay/lan-codecs ZstdLimits (64 KiB each).
    std::size_t proxy_compressed_bytes = 65536;
    std::size_t proxy_decompressed_bytes = 65536;
    // Explicit opt-in for numeric remote IPv4 servers. DNS is resolved by the
    // application outside this synchronous transport; legacy loopback is default.
    bool allow_remote = false;
};
struct Snapshot {
    State state = State::Idle;
    room_client::SessionState core_state = room_client::SessionState::Idle;
    std::optional<room_client::RoomInformation> room;
    std::optional<room_client::IPv4> assigned_ip;
    std::optional<room_client::MessageId> server_error;
    std::string failure;
    std::size_t queued_packets = 0, queued_bytes = 0;
    std::size_t outstanding_packets = 0, outstanding_bytes = 0;
    bool host_live = false;
    // Inbound frames discarded by a structural boundary guard; identity/state untouched.
    std::size_t boundary_rejections = 0;
    std::string boundary_reason;
};
// No worker thread. All methods serialize internally; poll services ENet <=5ms.
// Owner must not destroy this object while another caller uses it.
// Application pumps regularly; no implicit reconnect, DNS, or public rooms.
class Transport final {
public:
    explicit Transport(Options options = {});
    ~Transport();
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;
    void start(const room_client::JoinRequest& request);
    void poll(std::uint32_t wait_ms = 0);
    bool send(const room_client::Message& message); // false = bounded backpressure
    std::optional<room_client::Message> pop();
    void leave(); // asynchronous, deadline enforced by poll
    void stop() noexcept; // services graceful disconnect, then forcibly frees host
    Snapshot snapshot() const;
    static std::size_t live_hosts() noexcept;
    // Test-only: feed one server->client frame through the identical decode +
    // boundary-guard + publish path used by poll(), without ENet. Returns true
    // when the frame was accepted and published; false when a guard rejected it.
    bool inject_inbound_for_test(const room_client::Bytes& frame);
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
std::string state_name(State state);
} // namespace room_transport
