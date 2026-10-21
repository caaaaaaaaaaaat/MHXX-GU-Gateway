// SPDX-License-Identifier: GPL-2.0-or-later
#include "raw_client.hpp"

#include <cstring>

namespace rri {

namespace {
void ensure_enet() {
    static bool inited = false;
    if (!inited) {
        if (enet_initialize() != 0) std::fprintf(stderr, "enet_initialize failed\n");
        inited = true;
    }
}
} // namespace

RawClient::RawClient() {
    ensure_enet();
    t0_ = now_ms();
}

RawClient::~RawClient() { abort(); }

bool RawClient::connect(const std::string& ip, std::uint16_t port, std::uint32_t timeout_ms,
                        std::string& err) {
    // The client's own socket is bound to 127.0.0.1 explicitly: the harness must never
    // source traffic from a routable interface.
    ENetAddress local{};
    if (enet_address_set_host_ip(&local, "127.0.0.1") != 0) {
        err = "enet_address_set_host_ip(127.0.0.1) failed for the local socket";
        return false;
    }
    local.port = 0;
    host_ = enet_host_create(&local, 1, 1, 0, 0);
    if (!host_) {
        err = "enet_host_create failed";
        return false;
    }
    host_->maximumPacketSize = 65536;
    host_->maximumWaitingData = 262144;
    ENetAddress address{};
    if (enet_address_set_host_ip(&address, ip.c_str()) != 0) {
        err = "enet_address_set_host_ip failed for " + ip;
        return false;
    }
    address.port = port;
    port_ = port;
    peer_ = enet_host_connect(host_, &address, 1, 0);
    if (!peer_) {
        err = "enet_host_connect failed";
        return false;
    }
    const std::uint64_t deadline = now_ms() + timeout_ms;
    ENetEvent event;
    while (now_ms() < deadline) {
        const int rc = enet_host_service(host_, &event, 5);
        if (rc > 0) {
            if (event.type == ENET_EVENT_TYPE_CONNECT) return true;
            handle_event(event);
        }
    }
    err = "connect timeout after " + format_uint64(timeout_ms) + " ms";
    return false;
}

void RawClient::handle_event(ENetEvent& event) {
    switch (event.type) {
    case ENET_EVENT_TYPE_RECEIVE: {
        WireFrame f;
        f.from_server = true;
        f.channel = event.channelID;
        f.reliable = (event.packet->flags & ENET_PACKET_FLAG_RELIABLE) != 0;
        f.t_ms = now_ms() - t0_;
        f.bytes.assign(event.packet->data, event.packet->data + event.packet->dataLength);
        frames_.push_back(std::move(f));
        enet_packet_destroy(event.packet);
        break;
    }
    case ENET_EVENT_TYPE_DISCONNECT:
        disconnected_ = true;
        peer_ = nullptr;
        break;
    default:
        break;
    }
}

void RawClient::send(const Bytes& bytes, bool reliable) {
    if (!peer_) return;
    ENetPacket* packet = enet_packet_create(bytes.data(), bytes.size(),
                                            reliable ? ENET_PACKET_FLAG_RELIABLE : 0);
    enet_peer_send(peer_, 0, packet);
    enet_host_flush(host_);
    WireFrame f;
    f.from_server = false;
    f.channel = 0;
    f.reliable = reliable;
    f.t_ms = now_ms() - t0_;
    f.bytes = bytes;
    frames_.push_back(std::move(f));
}

void RawClient::service(std::uint32_t wait_ms) {
    if (!host_) return;
    ENetEvent event;
    std::uint32_t first = wait_ms;
    for (;;) {
        const int rc = enet_host_service(host_, &event, first);
        first = 0;
        if (rc <= 0) break;
        handle_event(event);
    }
}

bool RawClient::wait_frames(std::size_t from, std::uint32_t timeout_ms) {
    const std::uint64_t deadline = now_ms() + timeout_ms;
    while (frames_.size() <= from) {
        if (now_ms() >= deadline) return false;
        service(10);
    }
    return true;
}

std::vector<Bytes> RawClient::server_frames() const {
    std::vector<Bytes> out;
    for (const auto& f : frames_)
        if (f.from_server) out.push_back(f.bytes);
    return out;
}

void RawClient::disconnect(std::uint32_t flush_ms) {
    if (!host_ || !peer_) return;
    enet_peer_disconnect(peer_, 0);
    const std::uint64_t deadline = now_ms() + flush_ms;
    ENetEvent event;
    while (now_ms() < deadline && peer_ != nullptr) {
        const int rc = enet_host_service(host_, &event, 5);
        if (rc > 0) handle_event(event);
    }
}

void RawClient::abort() {
    if (peer_) {
        enet_peer_reset(peer_);
        peer_ = nullptr;
    }
    if (host_) {
        enet_host_destroy(host_);
        host_ = nullptr;
    }
    disconnected_ = true;
}

} // namespace rri
