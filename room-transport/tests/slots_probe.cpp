// SPDX-License-Identifier: GPL-2.0-or-later
// M2 diagnosis probe (side artifact): peer-slot exhaustion vs. teardown flush.
// Own synthetic clients only; unchanged original Room; localhost only.
#include "room_transport/transport.hpp"
#include "network/room.h"
#include <enet/enet.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace rc = room_client;
namespace rt = room_transport;
using Clock = std::chrono::steady_clock;

struct HostDeleter { void operator()(ENetHost* h) const { if (h) enet_host_destroy(h); } };

void check(bool yes, const std::string& what) {
    if (!yes) throw std::runtime_error(what);
}

struct Room {
    Network::Room room; bool open = false;
    Room(std::uint16_t port, std::uint32_t capacity, std::string password = {}) {
        open = room.Create("M2-slot-probe", "diagnosis only", "127.0.0.1", port,
            password, capacity, "", Network::GameInfo{"probe", 0, ""},
            std::make_unique<Network::VerifyUser::NullBackend>(), {}, false);
        if (!open) throw std::runtime_error("original Room::Create failed");
    }
    ~Room() { if (open) room.Destroy(); }
};

// --- one raw peer: connect, optionally join with version 1/2, teardown in a chosen way ---
struct RawPeer {
    std::unique_ptr<ENetHost, HostDeleter> host;
    ENetPeer* peer = nullptr;
    bool connected = false;
    long long connect_ms = -1;

    static RawPeer connect(std::uint16_t port, int timeout_ms) {
        RawPeer r;
        r.host.reset(enet_host_create(nullptr, 1, 1, 0, 0));
        if (!r.host) throw std::runtime_error("raw host create");
        r.host->maximumPacketSize = 65536; r.host->maximumWaitingData = 262144;
        ENetAddress a{}; enet_address_set_host_ip(&a, "127.0.0.1"); a.port = port;
        r.peer = enet_host_connect(r.host.get(), &a, 1, 0);
        if (!r.peer) throw std::runtime_error("raw connect");
        const auto t0 = Clock::now();
        const auto dl = t0 + std::chrono::milliseconds(timeout_ms);
        while (Clock::now() < dl) {
            ENetEvent e{};
            const int n = enet_host_service(r.host.get(), &e, 2);
            if (n <= 0) continue;
            if (e.type == ENET_EVENT_TYPE_CONNECT) {
                r.connected = true;
                r.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
                return r;
            }
            if (e.type == ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(e.packet);
        }
        return r;
    }
    void send_join(std::uint32_t version, const std::string& nick);
    void service_until_error(int timeout_ms); // pumps until ServerError or deadline
    // Teardown modes.
    void drop_no_flush() {   // the datagram is never sent: enet_peer_reset discards queued commands
        if (peer) { enet_peer_reset(peer); peer = nullptr; }
    }
    void drop_disconnect_now() { // EXACT behaviour of the current transport.cpp close_host()
        if (peer) { enet_peer_disconnect_now(peer, 0); peer = nullptr; }
    }
    void drop_graceful(std::uint32_t ms) {
        if (!peer) return;
        if (peer->state == ENET_PEER_STATE_CONNECTED) {
            enet_peer_disconnect(peer, 0);
            enet_host_flush(host.get());
            const auto dl = Clock::now() + std::chrono::milliseconds(ms);
            while (Clock::now() < dl) {
                ENetEvent e{};
                const int n = enet_host_service(host.get(), &e, 2);
                if (n > 0 && e.type == ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(e.packet);
                if (n > 0 && e.type == ENET_EVENT_TYPE_DISCONNECT) break;
            }
            enet_peer_disconnect_now(peer, 0);
        }
        peer = nullptr;
    }
    RawPeer() = default;
    RawPeer(RawPeer&&) = default;
    RawPeer& operator=(RawPeer&&) = default;
    ~RawPeer() { if (peer) enet_peer_disconnect_now(peer, 0); }
};

void RawPeer::send_join(std::uint32_t version, const std::string& nick) {
    rc::JoinRequest jr{nick, rc::no_preferred_ip, version, "", ""};
    const auto bytes = rc::encode(jr, rc::Direction::ClientToServer);
    ENetPacket* p = enet_packet_create(bytes.data(), bytes.size(), ENET_PACKET_FLAG_RELIABLE);
    if (!p) throw std::bad_alloc();
    if (enet_peer_send(peer, 0, p) != 0) { enet_packet_destroy(p); throw std::runtime_error("raw join send"); }
    enet_host_flush(host.get());
}

void RawPeer::service_until_error(int timeout_ms) {
    const auto dl = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Clock::now() < dl) {
        ENetEvent e{};
        const int n = enet_host_service(host.get(), &e, 2);
        if (n <= 0) continue;
        if (e.type == ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(e.packet);
    }
}

// A fresh raw version-2 client: measure whether CONNECT arrives and the VersionMismatch reply arrives.
struct V2 { bool connected = false; bool mismatch = false; long long connect_ms = -1; long long reply_ms = -1; };
V2 probe_version2(std::uint16_t port, int timeout_ms) {
    V2 out;
    auto r = RawPeer::connect(port, timeout_ms);
    out.connected = r.connected; out.connect_ms = r.connect_ms;
    if (!r.connected) return out;
    const auto t0 = Clock::now();
    r.send_join(2, "VersionProbe");
    const auto dl = t0 + std::chrono::milliseconds(timeout_ms);
    while (Clock::now() < dl) {
        ENetEvent e{};
        const int n = enet_host_service(r.host.get(), &e, 2);
        if (n <= 0) continue;
        if (e.type == ENET_EVENT_TYPE_RECEIVE) {
            rc::Bytes bytes(e.packet->data, e.packet->data + e.packet->dataLength);
            enet_packet_destroy(e.packet);
            auto m = rc::decode(bytes, rc::Direction::ServerToClient);
            if (std::holds_alternative<rc::ServerError>(m)) {
                out.mismatch = true;
                out.reply_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
                break;
            }
        }
    }
    return out;
}

// Full harness replay using the real Transport clients, capacity 3, two rejections.
struct Client {
    rt::Transport transport;
    explicit Client(rt::Options o) : transport(o) {}
    void tick(std::uint32_t w = 1) { transport.poll(w); while (transport.pop()) {} }
};
rt::Options options(std::uint16_t port) { rt::Options o; o.port = port; return o; }
rc::JoinRequest join_request(const std::string& n, rc::IPv4 ip = rc::no_preferred_ip, std::string pw = {}) {
    return {n, ip, 1, std::move(pw), ""};
}
void pump_until(const std::function<bool()>& done, const std::vector<Client*>& cs, std::uint32_t bound = 2500) {
    const auto dl = Clock::now() + std::chrono::milliseconds(bound);
    while (!done() && Clock::now() < dl) for (auto* c : cs) c->tick(2);
}
// Reproduce the harness order: two joined members, then two rejected pre-join clients.
V2 replay(std::uint16_t port, std::uint32_t capacity, int rejects, int wait_before_v2_ms) {
    Room room(port, capacity);
    Client a(options(port)), b(options(port));
    a.transport.start(join_request("AlphaClient"));
    pump_until([&] { return a.transport.snapshot().state == rt::State::Joined; }, {&a});
    b.transport.start(join_request("BravoClient", rc::IPv4{192,168,42,99}));
    pump_until([&] { return b.transport.snapshot().state == rt::State::Joined; }, {&a, &b});
    check(a.transport.snapshot().state == rt::State::Joined && b.transport.snapshot().state == rt::State::Joined, "members joined");
    std::vector<Client*> pump{&a, &b, nullptr};
    for (int i = 0; i < rejects; ++i) {
        Client r(options(port));
        pump.back() = &r;
        r.transport.start(i == 0 ? join_request("AlphaClient") : join_request("IpCollision", rc::IPv4{192,168,42,99}));
        pump_until([&] { return r.transport.snapshot().state == rt::State::Failed; }, pump);
        check(r.transport.snapshot().state == rt::State::Failed, "rejected client reached Failed");
        r.transport.stop();
        const auto dl = Clock::now() + std::chrono::milliseconds(25);
        while (Clock::now() < dl) for (auto* c : {&a, &b}) c->tick(2);
    }
    if (wait_before_v2_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(wait_before_v2_ms));
    auto out = probe_version2(port, 2500);
    a.transport.stop(); b.transport.stop();
    return out;
}

int main() {
    std::cout << "M2 slot/teardown diagnosis probe (localhost only, original Room, synthetic clients)" << std::endl;
    try {
        rt::Runtime runtime;
        constexpr std::uint16_t port = 39572;
        struct Case { const char* name; V2 v2; };
        std::vector<Case> cases;

        // Sanity: the raw version-2 client and the unchanged Room work when nothing leaked.
        cases.push_back({"capacity3, 0 rejects", replay(port, 3, 0, 0)});
        // The exact harness shape: capacity 3, 2 rejects, immediate version-2 attempt.
        cases.push_back({"capacity3, 2 rejects", replay(port, 3, 2, 0)});
        // Free slots: capacity 5 leaves two server peer slots for the version-2 client.
        cases.push_back({"capacity5, 2 rejects", replay(port, 5, 2, 0)});
        // Wait longer than ENet's minimum reclamation window (5s) before the version-2 attempt.
        cases.push_back({"capacity3, 2 rejects, wait 6000ms", replay(port, 3, 2, 6000)});

        for (const auto& c : cases)
            std::cout << "CASE " << c.name << " connected=" << c.v2.connected << " connect_ms=" << c.v2.connect_ms
                      << " mismatch=" << c.v2.mismatch << " reply_ms=" << c.v2.reply_ms << std::endl;

        // Stress the exact failing sequence many times in one process.
        int stress_fail = 0;
        for (int i = 0; i < 30; ++i) {
            auto v = replay(port, 3, 2, 0);
            if (!v.connected || !v.mismatch) ++stress_fail;
        }
        std::cout << "STRESS replay(cap3,2rejects) runs=30 failures=" << stress_fail << std::endl;

        // Teardown matrix: capacity 1 => exactly two server peer slots. Fill both,
        // tear the first down in the chosen way, then a fresh peer needs the freed slot.
        for (const char* mode : {"no_flush", "disconnect_now", "graceful"}) {
            {
                Room room(port, 1);
                auto occupant1 = RawPeer::connect(port, 1000);
                auto occupant2 = RawPeer::connect(port, 1000);
                check(occupant1.connected && occupant2.connected, "two occupants fill both slots");
                auto overflow = RawPeer::connect(port, 400);
                std::cout << "TEARDOWN " << mode << " full_room_overflow_connected=" << overflow.connected << std::endl;
                if (std::string(mode) == "no_flush") occupant1.drop_no_flush();
                else if (std::string(mode) == "disconnect_now") occupant1.drop_disconnect_now();
                else occupant1.drop_graceful(150);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                auto fresh = RawPeer::connect(port, 1200);
                std::cout << "TEARDOWN " << mode << " fresh_connected=" << fresh.connected
                          << " fresh_connect_ms=" << fresh.connect_ms << std::endl;
                if (fresh.peer) fresh.drop_graceful(50);
                if (occupant2.peer) occupant2.drop_graceful(50);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        std::cout << "PROBE DONE" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "PROBE FAIL " << e.what() << std::endl;
        return 1;
    }
}
