// SPDX-License-Identifier: GPL-2.0-or-later
#include <winsock2.h>
#include <ws2tcpip.h>
#include "gateway_gui/backend.hpp"
#include <algorithm>
#include <chrono>

namespace gateway_gui {
std::string validate(const Config& c) {
    in_addr address{};
    if (inet_pton(AF_INET, c.listen_address.c_str(), &address) != 1 ||
        (ntohl(address.s_addr) >> 24) >= 224U)
        return "请输入有效的监听 IPv4 地址，例如 127.0.0.1 或 0.0.0.0。";
    if (c.server.empty() || c.server.size() > 253 ||
        c.server.find_first_of(" /\\\t\r\n:") != std::string::npos)
        return "请输入 IPv4 地址或域名，不要包含协议、端口或路径。";
    if (!c.server_port || c.server_port > 65535 || !c.local_port || c.local_port > 65535)
        return "端口范围为 1–65535。";
    if (c.password.size() > 4096) return "密码过长。";
    return {};
}
citra_gateway::Options bridge_options(const Config& c, const std::string& ipv4) {
    citra_gateway::Options o;
    o.listen_address = c.listen_address;
    o.allow_remote_listen = true;
    o.listen_port = static_cast<std::uint16_t>(c.local_port);
    o.room_address = ipv4;
    o.room_port = static_cast<std::uint16_t>(c.server_port);
    o.allow_remote_room = true;
    o.room_password = c.password;
    o.connect_timeout_ms = 10000;
    o.join_timeout_ms = 10000;
    o.join_watchdog_ms = 25000;
    o.control_plane_enabled = true;
    o.ldn_dual_host = true;
    o.ldn_gu_host_discovery = true;
    o.ldn_gu_host_admission = true;
    o.proxy_udp_port = 12345;
    o.ldn_comm_id_override = 0x0100770008dd8000ULL;
    o.have_uds_wlan_comm_id = true; o.uds_wlan_comm_id = 0x00197110;
    o.have_uds_beacon_id = true; o.uds_beacon_id = 0;
    o.have_uds_attributes = true; o.uds_attributes = 0x8000;
    o.have_uds_network_id = true; o.uds_network_id = 0;
    o.have_uds_tag_word = true; o.uds_tag_word = 1;
    o.have_uds_wifi_channel = true; o.uds_wifi_channel = 6;
    // Keep diagnostic samples bounded in memory; never write raw traces.
    o.capture_limit = 1;
    o.emitted_limit = 1;
    o.event_limit = 128;
    return o;
}
namespace {
std::string resolve(const std::string& server) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* found = nullptr;
    if (getaddrinfo(server.c_str(), nullptr, &hints, &found) != 0 || !found)
        throw std::runtime_error("无法解析服务器地址，请检查域名和网络。 ");
    char ip[INET_ADDRSTRLEN]{};
    const auto* sa = reinterpret_cast<const sockaddr_in*>(found->ai_addr);
    const bool ok = inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)) != nullptr;
    freeaddrinfo(found);
    if (!ok) throw std::runtime_error("服务器未提供可用的 IPv4 地址。");
    const unsigned first = static_cast<unsigned>(std::stoul(ip));
    if (first == 0 || first >= 224) throw std::runtime_error("服务器地址不是可连接的单播 IPv4 地址。");
    return ip;
}
}
Backend::~Backend() { stop(); if (worker_.joinable()) worker_.join(); }
void Backend::start(Config config) {
    if (running_) throw std::logic_error("连接尚未结束。");
    if (worker_.joinable()) worker_.join();
    const auto error = validate(config);
    if (!error.empty()) throw std::invalid_argument(error);
    stop_ = false;
    {
        std::lock_guard lock(mutex_);
        view_ = {};
        view_.phase = Phase::Starting;
        view_.detail = "正在解析服务器地址并启动网关…";
    }
    running_ = true;
    try { worker_ = std::thread(&Backend::run, this, std::move(config)); }
    catch (...) { running_ = false; throw; }
}
void Backend::stop() {
    stop_ = true;
    std::lock_guard lock(mutex_);
    if (running_) { view_.phase = Phase::Stopping; view_.detail = "正在断开连接…"; }
}
View Backend::view() const { std::lock_guard lock(mutex_); return view_; }
void Backend::run(Config config) {
    try {
        room_transport::Runtime runtime;
        const auto ip = resolve(config.server);
        if (!stop_) {
            auto options = bridge_options(config, ip);
            citra_gateway::Gateway gateway(options);
            // Detect port conflicts before advertising a successful connection.
            try { gateway.open(); }
            catch (const std::exception&) {
                throw std::runtime_error("本机 Citra 接入端口无法绑定，请更换端口或关闭占用它的程序。");
            }
            {
                std::lock_guard lock(mutex_);
                view_.endpoint = (config.listen_address == "0.0.0.0" ? "127.0.0.1" : config.listen_address)
                    + ":" + std::to_string(config.local_port);
            }
            auto last_update = std::chrono::steady_clock::time_point{};
            std::uint64_t last_event = 0;
            std::string last_error;
            while (!stop_) {
                gateway.tick(1);
                const auto now = std::chrono::steady_clock::now();
                if (now - last_update >= std::chrono::milliseconds(100)) {
                    const auto clients = gateway.clients();
                    unsigned joined = 0, joining = 0, attached = 0;
                    for (const auto& event : gateway.events()) {
                        if (event.seq <= last_event) continue;
                        last_event = event.seq;
                        if (event.kind == "room.error.mapped" || event.kind == "room.error.unmapped" ||
                            event.kind == "room.transport.failure") {
                            if (event.detail.find("WrongPassword") != std::string::npos) last_error = "房间密码错误";
                            else if (event.detail.find("RoomFull") != std::string::npos) last_error = "服务器房间已满";
                            else if (event.detail.find("NameCollision") != std::string::npos) last_error = "Citra 昵称重复";
                            else if (event.detail.find("VersionMismatch") != std::string::npos) last_error = "服务器协议版本不兼容";
                            else last_error = "服务器连接中断或加入失败，请在 Citra 中重新加入";
                        }
                    }
                    for (const auto& client : clients) {
                        if (client.phase != "Closing" && client.phase != "Closed") ++attached;
                        if (client.room_state == "Joined" && client.phase == "Joined") ++joined;
                        else if (client.phase == "Joining" || client.phase == "Framing") ++joining;
                    }
                    std::lock_guard lock(mutex_);
                    view_.phase = joined ? Phase::Connected : joining ? Phase::Connecting : Phase::Listening;
                    view_.citra_count = attached;
                    view_.upstream_count = joined;
                    view_.detail = joined ? "已连接 Yuzu 服务器（" + std::to_string(joined) + "/" + std::to_string(attached) + "）" :
                        joining ? "Citra 已接入，正在连接 Yuzu 服务器…" :
                        "等待 Citra 接入 · 尚未连接 Yuzu 服务器";
                    if (joined && joined == attached) last_error.clear();
                    if (!last_error.empty()) view_.detail += "；最近连接错误：" + last_error;
                    last_update = now;
                }
            }
            gateway.close();
        }
        std::lock_guard lock(mutex_);
        view_.phase = Phase::Disconnected;
        view_.detail = "已断开连接";
        view_.citra_count = view_.upstream_count = 0;
    } catch (const std::exception& e) {
        std::lock_guard lock(mutex_);
        view_.phase = stop_ ? Phase::Disconnected : Phase::Failed;
        view_.detail = stop_ ? "已断开连接" : e.what();
        view_.citra_count = view_.upstream_count = 0;
    }
    running_ = false;
}
} // namespace gateway_gui
