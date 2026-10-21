// SPDX-License-Identifier: GPL-2.0-or-later
// real_room_self_server: a room server built from the UNMODIFIED original sources
// (01052024-yuzu-mirror-master/src/network/{room,packet,verify_user}.cpp) so the interop
// harness can be exercised before any real distribution binary is involved.
//
// It only binds 127.0.0.1 and it never loads a game or an emulator.
#include "util.hpp"

#include "network/room.h"
#include "network/verify_user.h"

#include <enet/enet.h>

#include <chrono>
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace {

const char* kReadyMarker = "SELF_SERVER_READY";

void usage() {
    std::fprintf(stderr,
                 "real_room_self_server --name <room> --port <port> [--password <pw>]\n"
                 "                     [--slots <2..254>] [--preferred-game <name>]\n"
                 "                     [--description <text>]\n");
}

std::string value_of(const std::vector<std::string>& argv, const std::string& key,
                     const std::string& fallback) {
    for (std::size_t i = 0; i + 1 < argv.size(); ++i)
        if (argv[i] == key) return argv[i + 1];
    return fallback;
}

} // namespace

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    const std::vector<std::string> args = rri::utf8_argv();
    const std::string name = value_of(args, "--name", std::string());
    const std::string port_text = value_of(args, "--port", std::string());
    const std::string password = value_of(args, "--password", std::string());
    const std::string slots_text = value_of(args, "--slots", "8");
    const std::string preferred_game = value_of(args, "--preferred-game", "real-room-interop");
    const std::string description = value_of(args, "--description", "real-room-interop self server");
    if (name.empty() || port_text.empty()) {
        usage();
        return 2;
    }
    unsigned long port_value = 0;
    unsigned long slots_value = 0;
    try {
        port_value = std::stoul(port_text);
        slots_value = std::stoul(slots_text);
    } catch (const std::exception&) {
        std::fprintf(stderr, "SELF_SERVER_ERROR invalid --port/--slots\n");
        return 2;
    }
    if (port_value == 0 || port_value > 65535 || slots_value < 2 || slots_value > 254) {
        std::fprintf(stderr, "SELF_SERVER_ERROR port must be 1..65535 and slots 2..254\n");
        return 2;
    }

    // The original dedicated-room main() initializes ENet through Network::Init();
    // this harness does the equivalent directly so the unmodified room sources need no change.
    if (enet_initialize() != 0) {
        std::fprintf(stderr, "SELF_SERVER_ERROR enet_initialize failed\n");
        return 1;
    }

    Network::Room room;
    Network::GameInfo game_info;
    game_info.name = preferred_game;
    game_info.id = 0;
    game_info.version = std::string();
    const bool created = room.Create(
        name, description, "127.0.0.1", static_cast<u16>(port_value), password,
        static_cast<u32>(slots_value), std::string(), game_info,
        std::make_unique<Network::VerifyUser::NullBackend>(), Network::Room::BanList{}, false);
    if (!created) {
        std::fprintf(stderr, "SELF_SERVER_ERROR Room::Create failed for 127.0.0.1:%lu\n", port_value);
        std::fflush(stderr);
        return 1;
    }
    if (room.GetState() != Network::Room::State::Open) {
        std::fprintf(stderr, "SELF_SERVER_ERROR room state is not Open\n");
        std::fflush(stderr);
        return 1;
    }

    std::printf("%s room=%s bind=127.0.0.1 port=%lu slots=%lu password=%s\n", kReadyMarker,
                name.c_str(), port_value, slots_value, password.empty() ? "(none)" : "(set)");
    std::fflush(stdout);

    // One non-empty stdin line (or a closing stdin) ends the room cleanly.
    for (;;) {
        std::string line;
        if (std::getline(std::cin, line)) {
            if (!line.empty()) break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    room.Destroy();
    std::printf("SELF_SERVER_STOPPED\n");
    std::fflush(stdout);
    return 0;
}
