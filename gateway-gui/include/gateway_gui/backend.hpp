// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "citra_gateway/gateway.hpp"
#include <atomic>
#include <mutex>
#include <thread>

namespace gateway_gui {
struct Config {
    std::string server = "127.0.0.1";
    unsigned server_port = 24872;
    unsigned local_port = 24875;
    std::string password;
    std::string listen_address = "127.0.0.1";
};
enum class Phase { Disconnected, Starting, Listening, Connecting, Connected, Stopping, Failed };
struct View {
    Phase phase = Phase::Disconnected;
    std::string detail;
    std::string endpoint;
    unsigned citra_count = 0;
    unsigned upstream_count = 0;
};
std::string validate(const Config& config);
citra_gateway::Options bridge_options(const Config& config, const std::string& ipv4);
class Backend {
public:
    ~Backend();
    void start(Config config);
    void stop();
    View view() const;
    bool running() const { return running_.load(); }
private:
    void run(Config config);
    mutable std::mutex mutex_;
    View view_;
    std::thread worker_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
};
} // namespace gateway_gui
