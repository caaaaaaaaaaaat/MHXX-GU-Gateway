// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include "citra_gateway/trace.hpp"

namespace yuzu_capture {
struct Options {
    std::uint16_t listen_port = 24940; // numeric loopback only
    std::uint16_t room_port = 24930;
    std::size_t max_peers = 4;
    std::uint64_t connect_timeout_ms = 2000;
    std::uint64_t join_timeout_ms = 15000;
    std::uint64_t drain_timeout_ms = 1000;
    std::size_t queue_packets = 64;
    std::size_t queue_bytes = 262144;
    std::string trace_path;
    std::string stage_file;
    bool trace_raw = false;
    citra_gateway::TraceContext identity;
    // Optional synthetic fault-injection hook. False simulates a failed write;
    // no CLI flag exposes this hook and successful records still use TraceSink.
    std::function<bool()> trace_write_gate;
};
struct Stats {
    std::uint64_t connected = 0, disconnected = 0, forwarded_up = 0, forwarded_down = 0;
    std::uint64_t rejected = 0, decode_failures = 0, timeouts = 0, trace_failures = 0;
    std::size_t active = 0;
};
// Caller owns ENet initialization. Single-threaded: tick services both legs.
class Relay {
public:
    explicit Relay(Options options);
    ~Relay();
    Relay(const Relay&) = delete;
    Relay& operator=(const Relay&) = delete;
    void open();
    void tick();
    void close() noexcept;
    std::uint16_t port() const;
    Stats stats() const;
    bool failed() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace yuzu_capture
