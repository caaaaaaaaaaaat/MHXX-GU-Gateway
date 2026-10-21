// SPDX-License-Identifier: GPL-2.0-or-later
#include "gateway_gui/backend.hpp"
#include "citra_room/protocol.hpp"
#include "network/room.h"
#include <enet/enet.h>
#include <chrono>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
int cases = 0;
void check(bool ok, const char* label) {
    ++cases;
    if (!ok) throw std::runtime_error(label);
    std::cout << "PASS " << label << std::endl;
}
bool wait(const std::function<bool()>& condition, unsigned milliseconds = 6000) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
    while (std::chrono::steady_clock::now() < end) {
        if (condition()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return condition();
}
ENetHost* listener(unsigned port = 0) {
    ENetAddress address{};
    enet_address_set_host_ip(&address, "127.0.0.1");
    address.port = static_cast<enet_uint16>(port);
    return enet_host_create(&address, 4, 1, 0, 0);
}
unsigned free_port() {
    auto* host = listener();
    if (!host) throw std::runtime_error("cannot allocate temporary loopback port");
    ENetAddress address{};
    enet_socket_get_address(host->socket, &address);
    enet_host_destroy(host);
    return address.port;
}
struct Client {
    ENetHost* host = nullptr;
    ENetPeer* peer = nullptr;
    bool joined = false;
    Client(unsigned port, const std::string& name, unsigned id) {
        host = enet_host_create(nullptr, 1, 1, 0, 0);
        if (!host) throw std::runtime_error("client host failed");
        ENetAddress address{};
        enet_address_set_host_ip(&address, "127.0.0.1"); address.port = static_cast<enet_uint16>(port);
        peer = enet_host_connect(host, &address, 1, 0);
        if (!peer) throw std::runtime_error("client connect failed");
        if (!wait([&] {
            ENetEvent event{};
            while (enet_host_service(host, &event, 0) > 0) {
                if (event.type == ENET_EVENT_TYPE_CONNECT) return true;
                if (event.type == ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(event.packet);
            }
            return false;
        })) {
            enet_host_destroy(host); host = nullptr;
            throw std::runtime_error("synthetic Citra ENet connection timed out");
        }
        citra_room::JoinRequest join;
        join.nickname = name;
        join.console_id_hash = "gui-test-console-" + std::to_string(id);
        join.preferred_mac = {2, 11, 22, 33, 44, static_cast<std::uint8_t>(id)};
        join.password = "desktop-password";
        const auto bytes = citra_room::encode(join, citra_room::Direction::ClientToServer);
        auto* packet = enet_packet_create(bytes.data(), bytes.size(), ENET_PACKET_FLAG_RELIABLE);
        if (enet_peer_send(peer, 0, packet) != 0) { enet_packet_destroy(packet); throw std::runtime_error("client send failed"); }
        enet_host_flush(host);
    }
    void pump() {
        ENetEvent event{};
        while (enet_host_service(host, &event, 0) > 0) {
            if (event.type == ENET_EVENT_TYPE_RECEIVE) {
                if (event.packet->dataLength && (event.packet->data[0] == static_cast<unsigned>(citra_room::MessageId::JoinSuccess) ||
                    event.packet->data[0] == static_cast<unsigned>(citra_room::MessageId::JoinSuccessAsMod))) joined = true;
                enet_packet_destroy(event.packet);
            }
        }
    }
    void leave() { enet_peer_disconnect(peer, 0); enet_host_flush(host); }
    ~Client() { if (host) enet_host_destroy(host); }
};
}
int main() {
    try {
        room_transport::Runtime runtime;
        gateway_gui::Config config;
        check(gateway_gui::validate(config).empty(), "default configuration valid");
        config.server = "http://localhost:1234";
        check(!gateway_gui::validate(config).empty(), "URL rejected instead of misconnecting");
        config.server = "localhost"; config.local_port = 65536;
        check(!gateway_gui::validate(config).empty(), "out of range port rejected");
        config.local_port = 0;
        check(!gateway_gui::validate(config).empty(), "zero local port rejected");
        config.local_port = free_port(); config.server_port = free_port();
        config.password = "desktop-password";
        bool denied = false;
        try { room_transport::Options o; o.address = "127.0.0.2"; room_transport::Transport transport(o); }
        catch (const std::invalid_argument&) { denied = true; }
        check(denied, "legacy remote guard retained");
        struct RoomGuard { Network::Room value; bool active = false; ~RoomGuard() { if (active) value.Destroy(); } } guard;
        auto& room = guard.value;
        check(room.Create("Desktop-test", "synthetic", "127.0.0.2", static_cast<std::uint16_t>(config.server_port),
            config.password, 8, "", Network::GameInfo{"Test", 0, ""},
            std::make_unique<Network::VerifyUser::NullBackend>(), {}, false), "isolated original room started");
        guard.active = true;
        room_transport::Options remote;
        remote.address = "127.0.0.2"; remote.allow_remote = true;
        { room_transport::Transport allowed(remote); }
        check(true, "explicit remote numeric opt-in accepted");
        config.server = "127.0.0.2"; // Exercise opt-in with a real numeric non-default endpoint.
        gateway_gui::Backend backend;
        backend.start(config);
        check(wait([&] { return backend.view().phase == gateway_gui::Phase::Listening; }), "gateway ready before any Citra");
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        check(room.GetRoomMemberList().empty(), "idle GUI creates NO room member");
        check(backend.view().citra_count == 0 && backend.view().upstream_count == 0, "initial counts zero");
        Client first(config.local_port, "GuiCitraA", 1);
        const bool first_ok = wait([&] { first.pump(); return first.joined && backend.view().citra_count == 1 && backend.view().upstream_count == 1; });
        if (!first_ok) std::cerr << "Diagnostic: " << backend.view().detail << " local=" << backend.view().citra_count << " upstream=" << backend.view().upstream_count << " room=" << room.GetRoomMemberList().size() << " client_joined=" << first.joined << '\n';
        check(first_ok, "first Citra counts one and upstream joined");
        Client second(config.local_port, "GuiCitraB", 2);
        check(wait([&] { first.pump(); second.pump(); return second.joined && backend.view().citra_count == 2 && backend.view().upstream_count == 2; }), "second Citra counts two and upstream joined");
        check(room.GetRoomMemberList().size() == 2, "two Citra produce exactly two room members");
        first.leave();
        check(wait([&] { first.pump(); second.pump(); return backend.view().citra_count == 1 && backend.view().upstream_count == 1 && room.GetRoomMemberList().size() == 1; }), "first leave updates count to one");
        second.leave();
        check(wait([&] { second.pump(); return backend.view().citra_count == 0 && room.GetRoomMemberList().empty(); }), "last leave updates count to zero");
        backend.stop();
        check(wait([&] { return !backend.running(); }), "stop completes");
        check(backend.view().phase == gateway_gui::Phase::Disconnected, "stop state disconnected");
        auto* occupied = listener(config.local_port);
        check(occupied != nullptr, "stop releases local UDP port");
        backend.start(config);
        check(wait([&] { return !backend.running(); }) && backend.view().phase == gateway_gui::Phase::Failed, "port conflict reported without false success");
        enet_host_destroy(occupied);
        room.Destroy(); guard.active = false;
        check(room.Create("Desktop-hostname", "synthetic", "127.0.0.1", static_cast<std::uint16_t>(config.server_port),
            config.password, 8, "", Network::GameInfo{"Test", 0, ""},
            std::make_unique<Network::VerifyUser::NullBackend>(), {}, false), "hostname target room started");
        guard.active = true;
        config.server = "localhost";
        backend.start(config);
        check(wait([&] { return backend.view().phase == gateway_gui::Phase::Listening; }), "restart and hostname resolution work");
        Client third(config.local_port, "GuiCitraC", 3);
        check(wait([&] { third.pump(); return third.joined && backend.view().upstream_count == 1; }), "hostname connection joins original server");
        room.Destroy();
        guard.active = false;
        check(wait([&] { third.pump(); return backend.view().upstream_count == 0; }), "server close clears connected status");
        backend.stop();
        check(wait([&] { return !backend.running(); }), "final stop completes");
        check(room_transport::Transport::live_hosts() == 0, "upstream hosts cleaned up");
        std::cout << "RESULT cases=" << cases << " failed=0\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
