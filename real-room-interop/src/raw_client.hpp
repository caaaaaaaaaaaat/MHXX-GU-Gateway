// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
// Raw ENet capture client: the actual bytes on the wire, both directions.
// Message generation/parsing is done by the frozen codecs the caller chooses.
#include "util.hpp"

#include <enet/enet.h>

#include <optional>
#include <string>
#include <vector>

namespace rri {

struct WireFrame {
    bool from_server = false;
    std::uint8_t channel = 0;
    bool reliable = false;
    std::uint64_t t_ms = 0;
    Bytes bytes;
};

class RawClient {
public:
    RawClient();
    ~RawClient();
    RawClient(const RawClient&) = delete;
    RawClient& operator=(const RawClient&) = delete;

    bool connect(const std::string& ip, std::uint16_t port, std::uint32_t timeout_ms, std::string& err);
    bool connected() const { return peer_ != nullptr && peer_->state == ENET_PEER_STATE_CONNECTED; }

    void send(const Bytes& bytes, bool reliable = true);
    // Service ENet for wait_ms; every received frame is appended to frames().
    void service(std::uint32_t wait_ms);
    // Service until frames() grows past 'from', or timeout. Returns true if it grew.
    bool wait_frames(std::size_t from, std::uint32_t timeout_ms);

    const std::vector<WireFrame>& frames() const { return frames_; }
    // Bytes of every frame received from the server, in arrival order.
    std::vector<Bytes> server_frames() const;
    bool disconnected() const { return disconnected_; }

    // Graceful ENet disconnect, bounded by flush_ms.
    void disconnect(std::uint32_t flush_ms = 400);
    // Hard teardown, always safe to call twice.
    void abort();
    std::uint16_t peer_port() const { return port_; }

private:
    void handle_event(ENetEvent& event);
    ENetHost* host_ = nullptr;
    ENetPeer* peer_ = nullptr;
    std::vector<WireFrame> frames_;
    bool disconnected_ = false;
    std::uint16_t port_ = 0;
    std::uint64_t t0_ = 0;
};

} // namespace rri
