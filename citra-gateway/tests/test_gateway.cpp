// SPDX-License-Identifier: GPL-2.0-or-later
// G-b acceptance harness: synthetic Citra v4 clients over bounded TCP framing
// <-> this gateway <-> the UNMODIFIED Yuzu v1 room implementation, in process.
//
// Every assertion below is structural (tier A). Nothing here shows that a real
// Yuzu client receives data (tier B, needs G2) or that a game is playable
// (tier C, needs M5). See docs/citra-gateway-report.md.
#include "citra_gateway/gateway.hpp"
#include "citra_gateway/control.hpp"
#include "citra_gateway/trace.hpp"
#include "citra_control/heartbeat.hpp"
#include "citra_room/session.hpp"
#include "network/room.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>

#include <zstd.h>
#include <enet/enet.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

int g_cases = 0;
int g_failed = 0;
int g_groups = 0;
std::vector<std::string> g_failures;
std::map<std::string, std::string> g_notes;

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch())
            .count());
}

template <typename ByteContainer>
std::string hex_of(const ByteContainer& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::uint8_t byte : bytes) {
        out.push_back(digits[(byte >> 4) & 0x0F]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

void check(bool ok, const std::string& name) {
    ++g_cases;
    if (ok) {
        std::cout << "PASS " << g_cases << " " << name << "\n";
    } else {
        ++g_failed;
        g_failures.push_back(name);
        std::cout << "FAIL " << g_cases << " " << name << "\n";
    }
}

void verify(bool ok, const std::string& name) {
    check(ok, name);
    if (!ok) {
        throw std::runtime_error("prerequisite failed: " + name);
    }
}

void run_group(const std::string& label, const std::function<void()>& body) {
    ++g_groups;
    std::cout << "--- group " << label << "\n";
    const int before = g_failed;
    try {
        body();
    } catch (const std::exception& error) {
        if (g_failed == before) {
            ++g_failed;
            ++g_cases;
            g_failures.push_back(label + " aborted: " + error.what());
            std::cout << "FAIL " << g_cases << " " << label << " aborted: " << error.what()
                      << "\n";
        }
    }
}

void note(const std::string& key, const std::string& value) {
    g_notes[key] = value;
}

std::size_t thread_count() {
    std::size_t count = 0;
    const DWORD self = ::GetCurrentProcessId();
    const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (::Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == self) {
                ++count;
            }
        } while (::Thread32Next(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return count;
}

// ---------------------------------------------------------------------------
// Citra side: one bounded 4 byte big endian length prefixed TCP connection.
// DECLARED LIMITATION: the real Citra client speaks ENet. This framing is a
// harness transport substitute for the offline G-b topology only.
// ---------------------------------------------------------------------------
class CitraClient {
public:
    CitraClient() = default;
    ~CitraClient() { close_now(); }
    CitraClient(const CitraClient&) = delete;
    CitraClient& operator=(const CitraClient&) = delete;

    void connect_to(std::uint16_t port) {
        sock_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_ == INVALID_SOCKET) {
            throw std::runtime_error("citra client socket() failed");
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        if (::connect(sock_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ==
            SOCKET_ERROR) {
            ::closesocket(sock_);
            sock_ = INVALID_SOCKET;
            throw std::runtime_error("citra client connect failed, WSA " +
                                     std::to_string(::WSAGetLastError()));
        }
        u_long non_blocking = 1;
        ::ioctlsocket(sock_, FIONBIO, &non_blocking);
    }

    bool peer_closed() const { return peer_closed_; }

    void close_now() {
        if (sock_ != INVALID_SOCKET) {
            ::closesocket(sock_);
            sock_ = INVALID_SOCKET;
        }
    }

    void send_frame(const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> framed;
        const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
        framed.push_back(static_cast<std::uint8_t>((length >> 24) & 0xFF));
        framed.push_back(static_cast<std::uint8_t>((length >> 16) & 0xFF));
        framed.push_back(static_cast<std::uint8_t>((length >> 8) & 0xFF));
        framed.push_back(static_cast<std::uint8_t>(length & 0xFF));
        framed.insert(framed.end(), payload.begin(), payload.end());
        send_all(framed);
    }

    void send_prefix_only(std::uint32_t length) {
        std::vector<std::uint8_t> framed;
        framed.push_back(static_cast<std::uint8_t>((length >> 24) & 0xFF));
        framed.push_back(static_cast<std::uint8_t>((length >> 16) & 0xFF));
        framed.push_back(static_cast<std::uint8_t>((length >> 8) & 0xFF));
        framed.push_back(static_cast<std::uint8_t>(length & 0xFF));
        send_all(framed);
    }

    void send_all(const std::vector<std::uint8_t>& bytes) {
        if (sock_ == INVALID_SOCKET) {
            throw std::runtime_error("send on a closed citra client");
        }
        std::size_t sent = 0;
        while (sent < bytes.size()) {
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(sock_, &writable);
            timeval timeout{2, 0};
            const int ready = ::select(0, nullptr, &writable, nullptr, &timeout);
            if (ready <= 0) {
                throw std::runtime_error("citra send timed out");
            }
            const int written =
                ::send(sock_, reinterpret_cast<const char*>(bytes.data() + sent),
                       static_cast<int>(bytes.size() - sent), 0);
            if (written <= 0) {
                peer_closed_ = true;
                throw std::runtime_error("citra send failed, WSA " +
                                         std::to_string(::WSAGetLastError()));
            }
            sent += static_cast<std::size_t>(written);
        }
    }

    std::optional<std::vector<std::uint8_t>> recv_frame(int timeout_ms) {
        const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
        for (;;) {
            if (sock_ == INVALID_SOCKET) {
                return std::nullopt;
            }
            if (buffer_.size() >= 4) {
                const std::uint32_t length = (static_cast<std::uint32_t>(buffer_[0]) << 24) |
                                             (static_cast<std::uint32_t>(buffer_[1]) << 16) |
                                             (static_cast<std::uint32_t>(buffer_[2]) << 8) |
                                             static_cast<std::uint32_t>(buffer_[3]);
                if (length > (1U << 20)) {
                    peer_closed_ = true;
                    return std::nullopt;
                }
                if (buffer_.size() >= 4 + length) {
                    std::vector<std::uint8_t> frame(buffer_.begin() + 4,
                                                    buffer_.begin() + 4 + length);
                    buffer_.erase(buffer_.begin(), buffer_.begin() + 4 + length);
                    raw_frames_.push_back(frame);
                    return frame;
                }
            }
            if (Clock::now() >= deadline) {
                return std::nullopt;
            }
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(sock_, &readable);
            timeval timeout{0, 2000};
            const int ready = ::select(0, &readable, nullptr, nullptr, &timeout);
            if (ready < 0) {
                peer_closed_ = true;
                return std::nullopt;
            }
            if (ready == 0) {
                continue;
            }
            char chunk[8192];
            const int got = ::recv(sock_, chunk, sizeof(chunk), 0);
            if (got <= 0) {
                peer_closed_ = true;
                return std::nullopt;
            }
            buffer_.insert(buffer_.end(), chunk, chunk + got);
        }
    }

    std::vector<std::vector<std::uint8_t>> drain(int timeout_ms) {
        const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
        while (Clock::now() < deadline) {
            if (!recv_frame(20) && peer_closed_) {
                break;
            }
        }
        return raw_frames_;
    }

    const std::vector<std::vector<std::uint8_t>>& raw_frames() const { return raw_frames_; }
    void clear_frames() { raw_frames_.clear(); }

    std::optional<citra_room::Message> next_message(int timeout_ms) {
        const auto frame = recv_frame(timeout_ms);
        if (!frame) {
            return std::nullopt;
        }
        return citra_room::decode(*frame, citra_room::Direction::ServerToClient);
    }

private:
    SOCKET sock_ = INVALID_SOCKET;
    bool peer_closed_ = false;
    std::vector<std::uint8_t> buffer_;
    std::vector<std::vector<std::uint8_t>> raw_frames_;
};

// ---------------------------------------------------------------------------
// Yuzu side: the unmodified upstream room, in process.
// ---------------------------------------------------------------------------
class RoomGuard {
public:
    RoomGuard(std::uint16_t port, std::uint32_t capacity, const std::string& password = "")
        : port_(port), capacity_(capacity) {
        open_ = room_.Create("G-b-loopback", "synthetic only", "127.0.0.1", port, password,
                             capacity, "", Network::GameInfo{"Envelope test", 0, ""},
                             std::make_unique<Network::VerifyUser::NullBackend>(), {}, false);
        if (!open_) {
            throw std::runtime_error("room Create failed on port " + std::to_string(port));
        }
    }
    ~RoomGuard() { close(); }
    RoomGuard(const RoomGuard&) = delete;
    RoomGuard& operator=(const RoomGuard&) = delete;

    void close() {
        if (open_) {
            room_.Destroy();
            open_ = false;
        }
    }

    std::vector<Network::Member> members() { return room_.GetRoomMemberList(); }
    const Network::RoomInformation& information() { return room_.GetRoomInformation(); }
    std::uint16_t port() const { return port_; }
    std::uint32_t capacity() const { return capacity_; }

private:
    Network::Room room_;
    bool open_ = false;
    std::uint16_t port_ = 0;
    std::uint32_t capacity_ = 0;
};

class RawRoomPeer {
public:
    RawRoomPeer(std::uint16_t port, const std::string& nickname, std::uint32_t version,
                const room_client::IPv4& preferred_ip = room_client::no_preferred_ip,
                const std::string& password = std::string()) {
        host_ = enet_host_create(nullptr, 1, 1, 0, 0);
        if (host_ == nullptr) {
            throw std::runtime_error("raw peer enet_host_create failed");
        }
        ENetAddress address{};
        enet_address_set_host(&address, "127.0.0.1");
        address.port = port;
        peer_ = enet_host_connect(host_, &address, 1, 0);
        if (peer_ == nullptr) {
            throw std::runtime_error("raw peer enet_host_connect failed");
        }
        ENetEvent event;
        if (enet_host_service(host_, &event, 2000) <= 0 || event.type != ENET_EVENT_TYPE_CONNECT) {
            throw std::runtime_error("raw peer could not connect to the room");
        }
        room_client::JoinRequest request;
        request.nickname = nickname;
        request.preferred_ip = preferred_ip;
        request.version = version;
        request.password = password;
        const auto bytes = room_client::encode(request, room_client::Direction::ClientToServer);
        ENetPacket* packet =
            enet_packet_create(bytes.data(), bytes.size(), ENET_PACKET_FLAG_RELIABLE);
        enet_peer_send(peer_, room_client::enet_channel, packet);
        enet_host_flush(host_);
    }

    ~RawRoomPeer() {
        if (host_ != nullptr) {
            if (peer_ != nullptr) {
                enet_peer_reset(peer_);
            }
            enet_host_destroy(host_);
        }
    }
    RawRoomPeer(const RawRoomPeer&) = delete;
    RawRoomPeer& operator=(const RawRoomPeer&) = delete;

    bool pump(int timeout_ms) {
        ENetEvent event;
        const int served = enet_host_service(host_, &event, static_cast<std::uint32_t>(timeout_ms));
        if (served <= 0) {
            return false;
        }
        if (event.type == ENET_EVENT_TYPE_RECEIVE) {
            room_client::Bytes frame(event.packet->data,
                                     event.packet->data + event.packet->dataLength);
            enet_packet_destroy(event.packet);
            raw_frames_.push_back(frame);
            try {
                messages_.push_back(
                    room_client::decode(frame, room_client::Direction::ServerToClient));
            } catch (const std::exception&) {
                malformed_.push_back(frame);
            }
            return true;
        }
        return false;
    }

    // B2: send one room message straight down the ENet connection, exactly the
    // way the unmodified room client would.  Used to drive the LDN control path.
    void send(const room_client::Message& message) {
        const auto bytes =
            room_client::encode(message, room_client::Direction::ClientToServer);
        ENetPacket* packet =
            enet_packet_create(bytes.data(), bytes.size(), ENET_PACKET_FLAG_RELIABLE);
        enet_peer_send(peer_, room_client::enet_channel, packet);
        enet_host_flush(host_);
    }

    void leave() {
        enet_peer_disconnect(peer_, 0);
        enet_host_flush(host_);
    }

    std::optional<room_client::Message> message_of(room_client::MessageId id) const {
        for (const auto& message : messages_) {
            if (room_client::message_id(message) == id) {
                return message;
            }
        }
        return std::nullopt;
    }

    const std::vector<room_client::Message>& messages() const { return messages_; }
    const std::vector<room_client::Bytes>& raw_frames() const { return raw_frames_; }

private:
    ENetHost* host_ = nullptr;
    ENetPeer* peer_ = nullptr;
    std::vector<room_client::Message> messages_;
    std::vector<room_client::Bytes> malformed_;
    std::vector<room_client::Bytes> raw_frames_;
};

std::optional<room_client::ServerError> probe_room_version(std::uint16_t port,
                                                           std::uint32_t version) {
    RawRoomPeer peer(port, "ProbeUser", version);
    for (int i = 0; i < 60; ++i) {
        peer.pump(50);
        for (const auto& message : peer.messages()) {
            if (const auto* error = std::get_if<room_client::ServerError>(&message)) {
                return *error;
            }
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Gateway drivers.
// ---------------------------------------------------------------------------
citra_gateway::Options gateway_options(std::uint16_t listen_port, std::uint16_t room_port,
                                       std::uint32_t room_capacity = 0,
                                       const std::string& room_password = std::string()) {
    citra_gateway::Options options;
    options.listen_address = "127.0.0.1";
    options.listen_port = listen_port;
    options.room_address = "127.0.0.1";
    options.room_port = room_port;
    options.connect_timeout_ms = 1500;
    options.join_timeout_ms = 1500;
    options.leave_timeout_ms = 500;
    options.join_watchdog_ms = 3000;
    // V-016l: the host of the in-process mode reads the room's own member_slots
    // and hands it to the gateway, exactly like Network::Room reports it.
    options.room_capacity = room_capacity;
    options.room_password = room_password;
    // G-c / V-027: the A1..A10 / B1 / B2 groups drive the deterministic TCP +
    // 4-byte length-prefix listener, which is a test-only transport. The
    // deliverable Citra transport (ENet/UDP) is exercised by B3_citra_enet,
    // which builds its own Options. citra-gateway.exe can never set this.
    options.citra_tcp_test_transport = true;
    return options;
}

// In-process host helper: read the live member_slots straight out of the room.
citra_gateway::Options gateway_options(std::uint16_t listen_port, RoomGuard& room,
                                       const std::string& room_password = std::string()) {
    return gateway_options(listen_port, room.port(), room.information().member_slots,
                           room_password);
}

template <typename Predicate>
bool until(citra_gateway::Gateway& gateway, Predicate done, int bound_ms = 3000) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(bound_ms);
    while (Clock::now() < deadline) {
        gateway.tick(0);
        if (done()) {
            return true;
        }
        ::Sleep(1);
    }
    gateway.tick(0);
    return done();
}

citra_room::Bytes citra_join_bytes(const std::string& nickname,
                                   const std::string& console_id_hash,
                                   const citra_room::MacAddress& preferred_mac,
                                   std::uint32_t version = citra_room::network_version,
                                   const std::string& password = std::string()) {
    citra_room::JoinRequest request;
    request.nickname = nickname;
    request.console_id_hash = console_id_hash;
    request.preferred_mac = preferred_mac;
    request.version = version;
    request.password = password;
    return citra_room::encode(request, citra_room::Direction::ClientToServer);
}

citra_room::Bytes citra_wifi_bytes(const citra_room::MacAddress& transmitter,
                                   const citra_room::MacAddress& destination,
                                   const std::vector<std::uint8_t>& data,
                                   citra_room::FrameType type = citra_room::FrameType::Data,
                                   std::uint8_t channel = 0) {
    citra_room::WifiPacket wifi;
    wifi.type = type;
    wifi.channel = channel;
    wifi.transmitter = transmitter;
    wifi.destination = destination;
    wifi.data = data;
    return citra_room::encode(wifi, citra_room::Direction::ClientToServer);
}

// V-023: hand written Citra IdWifiPacket golden. It is assembled byte by byte
// here so the large frame assertions never depend on a decode -> encode round
// trip, and so it also works for bodies the frozen encoder itself refuses.
citra_room::Bytes citra_wifi_frame_manual(const citra_room::MacAddress& transmitter,
                                          const citra_room::MacAddress& destination,
                                          const std::vector<std::uint8_t>& data,
                                          std::uint8_t type = 1, std::uint8_t channel = 0) {
    citra_room::Bytes out;
    out.push_back(0x05);
    out.push_back(type);
    out.push_back(channel);
    out.insert(out.end(), transmitter.begin(), transmitter.end());
    out.insert(out.end(), destination.begin(), destination.end());
    const std::uint32_t size = static_cast<std::uint32_t>(data.size());
    out.push_back(static_cast<std::uint8_t>((size >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((size >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((size >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(size & 0xFF));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

// V-023: hand written Citra ChatRequest (id 6) golden with a body longer than
// chat_bytes, so the frozen codec limit is what rejects it.
citra_room::Bytes citra_chat_frame_manual(const std::string& body) {
    citra_room::Bytes out;
    out.push_back(0x06);
    const std::uint32_t size = static_cast<std::uint32_t>(body.size());
    out.push_back(static_cast<std::uint8_t>((size >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((size >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((size >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(size & 0xFF));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// Deterministic synthetic payload: never a capture, never game data.
std::vector<std::uint8_t> synthetic_payload(std::size_t size, std::uint8_t seed) {
    std::vector<std::uint8_t> out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = static_cast<std::uint8_t>((seed + i * 37U + (i >> 3)) & 0xFF);
    }
    return out;
}

std::vector<std::uint8_t> zstd_frame(const std::vector<std::uint8_t>& plain, int level) {
    std::vector<std::uint8_t> out(ZSTD_compressBound(plain.size()));
    const std::size_t written = ZSTD_compress(out.data(), out.size(), plain.data(), plain.size(),
                                              level);
    if (ZSTD_isError(written)) {
        throw std::runtime_error(std::string("zstd compress failed: ") +
                                 ZSTD_getErrorName(written));
    }
    out.resize(written);
    return out;
}

std::vector<std::uint8_t> zstd_frame_unknown_size(const std::vector<std::uint8_t>& plain) {
    ZSTD_CCtx* context = ZSTD_createCCtx();
    if (context == nullptr) {
        throw std::runtime_error("ZSTD_createCCtx failed");
    }
    ZSTD_CCtx_setParameter(context, ZSTD_c_contentSizeFlag, 0);
    std::vector<std::uint8_t> out(ZSTD_compressBound(plain.size()));
    const std::size_t written =
        ZSTD_compress2(context, out.data(), out.size(), plain.data(), plain.size());
    const std::size_t frame_size = ZSTD_findFrameCompressedSize(out.data(), written);
    ZSTD_freeCCtx(context);
    if (ZSTD_isError(written) || ZSTD_isError(frame_size)) {
        throw std::runtime_error("unknown-size zstd frame failed");
    }
    out.resize(frame_size);
    return out;
}

std::uint16_t g_next_port = 39572;
std::uint16_t take_port() {
    const std::uint16_t port = g_next_port;
    g_next_port = static_cast<std::uint16_t>(g_next_port + 2);
    return port;
}

// ---------------------------------------------------------------------------
// Part B: helper drivers, the ten acceptance groups and main.
//
// Golden provenance (the parent session's V-016g requirement). Every error
// golden below is a HAND WRITTEN hex literal; none of them is produced by
// running this project's own encoder and reading the result back.
//
// Citra side (the bytes the synthetic client must observe):
//   "07"         IdNameCollision      citra-master/src/network/room.h enum block (:52-70)
//   "08"         IdMacCollision       same enum block; sender writes a bare u8
//   "09 00000004" IdVersionMismatch   same enum block + network_version = 4 (room.h:16)
//   "0a"         IdWrongPassword      same enum block, bare u8
//   "0b"         IdCloseRoom          same enum block, bare u8
//   "0c"         IdRoomIsFull         same enum block, bare u8
//   "0d"         IdConsoleIdCollision same enum block, bare u8
// Yuzu side (the bytes the unmodified room source really puts on the wire):
//   "08"       IdNameCollision       01052024-yuzu-mirror-master/src/network/room.h enum block (:37-64)
//   "09"       IdIpCollision         same enum block, bare u8
//   "0a 00000001" IdVersionMismatch   same enum block + network_version = 1 (room.h:21)
//   "0b"       IdWrongPassword       same enum block, bare u8
//   "0c"       IdCloseRoom           same enum block, bare u8
//   "0d"       IdRoomIsFull          same enum block, bare u8
// ---------------------------------------------------------------------------

std::string g_evidence_dir = ".build-direct/evidence";

bool same_ip(const Network::IPv4Address& a, const citra_gateway::IPv4& b) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

std::optional<citra_gateway::IdentityEntry> identity_for(const citra_gateway::Gateway& gateway,
                                                         const std::string& nickname) {
    for (const auto& entry : gateway.identities()) {
        if (entry.nickname == nickname) {
            return entry;
        }
    }
    return std::nullopt;
}

std::optional<Network::Member> member_for(RoomGuard& room, const std::string& nickname) {
    for (const auto& member : room.members()) {
        if (member.nickname == nickname) {
            return member;
        }
    }
    return std::nullopt;
}

std::size_t room_size(RoomGuard& room) {
    return room.members().size();
}

std::uint64_t client_id_for(const citra_gateway::Gateway& gateway, const std::string& nickname) {
    for (const auto& snapshot : gateway.clients()) {
        if (snapshot.nickname == nickname) {
            return snapshot.id;
        }
    }
    return 0;
}

bool has_single_hit(const std::map<std::string, std::uint64_t>& hits, const std::string& name,
                    std::uint64_t value) {
    return hits.size() == 1 && hits.count(name) == 1 && hits.at(name) == value;
}

std::optional<room_client::Bytes> wait_raw_frame(RawRoomPeer& peer, std::uint8_t id,
                                                 int bound_ms = 3000) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(bound_ms);
    for (;;) {
        for (const auto& frame : peer.raw_frames()) {
            if (!frame.empty() && frame[0] == id) {
                return frame;
            }
        }
        if (Clock::now() >= deadline) {
            return std::nullopt;
        }
        peer.pump(10);
    }
}

std::optional<room_client::IPv4> wait_assigned_ip(RawRoomPeer& peer, int bound_ms = 3000) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(bound_ms);
    for (;;) {
        const auto message = peer.message_of(room_client::MessageId::JoinSuccess);
        if (message) {
            if (const auto* success = std::get_if<room_client::JoinSuccess>(&*message)) {
                return success->assigned_ip;
            }
        }
        if (Clock::now() >= deadline) {
            return std::nullopt;
        }
        peer.pump(10);
    }
}

void dump_documents(const citra_gateway::Gateway& gateway, const std::string& tag) {
    std::error_code ignored;
    std::filesystem::create_directories(g_evidence_dir, ignored);
    const std::pair<const char*, std::string> documents[] = {
        {"counters", gateway.counters_json()}, {"clients", gateway.clients_json()},
        {"identities", gateway.identities_json()}, {"captures", gateway.captures_json()},
        {"events", gateway.events_json()},         {"snapshot", gateway.snapshot_json()},
        {"emitted", gateway.emitted_json()},
    };
    for (const auto& [name, text] : documents) {
        const std::string path = g_evidence_dir + "/" + tag + "." + name + ".json";
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            check(false, "A9 evidence file written: " + path);
            continue;
        }
        out << text << "\n";
    }
    check(true, "A9 machine readable evidence exported: " + tag + ".*.json (7 documents)");
}

class CitraPeer {
public:
    void connect(std::uint16_t port) { client_.connect_to(port); }
    void send(const citra_room::Bytes& frame) { client_.send_frame(frame); }
    void send_prefix_only(std::uint32_t length) { client_.send_prefix_only(length); }
    void close_now() { client_.close_now(); }
    bool peer_closed() const { return client_.peer_closed(); }
    std::size_t raw_count() const { return client_.raw_frames().size(); }
    const std::vector<std::vector<std::uint8_t>>& raw_frames() const { return client_.raw_frames(); }
    const std::vector<citra_room::Message>& messages() const { return messages_; }
    const std::vector<std::string>& undecodable() const { return undecodable_; }

    std::size_t absorb() {
        for (int i = 0; i < 32; ++i) {
            if (!client_.recv_frame(1).has_value()) {
                break;
            }
        }
        const auto& raw = client_.raw_frames();
        std::size_t added = 0;
        while (decoded_ < raw.size()) {
            const auto frame = raw[decoded_++];
            try {
                messages_.push_back(citra_room::decode(frame, citra_room::Direction::ServerToClient));
            } catch (const std::exception& error) {
                undecodable_.push_back(std::string(error.what()) + " frame=" + hex_of(frame));
            }
            ++added;
        }
        return added;
    }

    std::size_t wifi_frames() const {
        std::size_t count = 0;
        for (const auto& message : messages_) {
            if (std::holds_alternative<citra_room::WifiPacket>(message)) {
                ++count;
            }
        }
        return count;
    }

    std::optional<citra_room::MacAddress> assigned_mac() const {
        for (const auto& message : messages_) {
            if (const auto* success = std::get_if<citra_room::JoinSuccess>(&message)) {
                return success->assigned_mac;
            }
        }
        return std::nullopt;
    }

private:
    CitraClient client_;
    std::vector<citra_room::Message> messages_;
    std::vector<std::string> undecodable_;
    std::size_t decoded_ = 0;
};

// ---------------------------------------------------------------------------
// B3 (G-c / V-027): a real ENet/UDP Citra-side peer.  This is the transport an
// unmodified Citra uses (citra-master/src/network/room_member.cpp): one ENet
// host with NumChannels=1, one bare citra_room v4 message per reliable packet
// and no length prefix.  Unlike RawRoomPeer there is no background server, so
// the peer only progresses while the caller ticks the gateway and services the
// host; connect() therefore reports completion asynchronously.
// ---------------------------------------------------------------------------
class EnetCitraPeer {
public:
    explicit EnetCitraPeer(std::uint16_t port) {
        host_ = enet_host_create(nullptr, 1, citra_room::num_channels, 0, 0);
        if (host_ == nullptr) {
            throw std::runtime_error("enet citra peer enet_host_create failed");
        }
        host_->maximumPacketSize = 65536;
        host_->maximumWaitingData = 262144;
        ENetAddress address{};
        enet_address_set_host(&address, "127.0.0.1");
        address.port = port;
        peer_ = enet_host_connect(host_, &address, citra_room::num_channels, 0);
        if (peer_ == nullptr) {
            throw std::runtime_error("enet citra peer enet_host_connect failed");
        }
    }

    ~EnetCitraPeer() {
        if (host_ != nullptr) {
            if (peer_ != nullptr) {
                enet_peer_reset(peer_);
            }
            enet_host_destroy(host_);
        }
    }
    EnetCitraPeer(const EnetCitraPeer&) = delete;
    EnetCitraPeer& operator=(const EnetCitraPeer&) = delete;

    // One bare citra_room v4 message, exactly as the real client sends it.
    void send(const citra_room::Bytes& message) {
        if (peer_ == nullptr) {
            // The peer was closed or reset (for example by a rejected join that
            // ended in a DISCONNECT event).
            return;
        }
        ENetPacket* packet =
            enet_packet_create(message.data(), message.size(), ENET_PACKET_FLAG_RELIABLE);
        enet_peer_send(peer_, 0, packet);
        enet_host_flush(host_);
    }

    void send_message(const citra_room::Message& message) {
        send(citra_room::encode(message, citra_room::Direction::ClientToServer));
    }

    void close_now() {
        if (peer_ != nullptr) {
            enet_peer_disconnect_now(peer_, 0);
            peer_ = nullptr;
        }
    }

    // Drains every queued ENet event without blocking.
    std::size_t service() {
        std::size_t added = 0;
        for (;;) {
            ENetEvent event{};
            const int served = enet_host_service(host_, &event, 0);
            if (served <= 0) {
                break;
            }
            if (event.type == ENET_EVENT_TYPE_CONNECT) {
                connected_ = true;
            } else if (event.type == ENET_EVENT_TYPE_RECEIVE) {
                raw_frames_.emplace_back(event.packet->data,
                                         event.packet->data + event.packet->dataLength);
                enet_packet_destroy(event.packet);
                ++added;
            } else if (event.type == ENET_EVENT_TYPE_DISCONNECT) {
                peer_closed_ = true;
                peer_ = nullptr;
            }
        }
        return added;
    }

    bool connected() const { return connected_; }
    bool peer_closed() const { return peer_closed_; }
    std::size_t raw_count() const { return raw_frames_.size(); }
    const std::vector<citra_room::Bytes>& raw_frames() const { return raw_frames_; }

    // Every received frame must be exactly one whole citra_room v4 message; a
    // 4 byte length prefix (the old TCP framing) would fail here.
    bool every_frame_decodes() const {
        for (const auto& frame : raw_frames_) {
            try {
                (void)citra_room::decode(frame, citra_room::Direction::ServerToClient);
            } catch (const std::exception&) {
                return false;
            }
        }
        return true;
    }

private:
    ENetHost* host_ = nullptr;
    ENetPeer* peer_ = nullptr;
    bool connected_ = false;
    bool peer_closed_ = false;
    std::vector<citra_room::Bytes> raw_frames_;
};

bool drive(citra_gateway::Gateway& gateway, const std::vector<CitraPeer*>& peers,
           const std::function<bool()>& done, int bound_ms = 3000) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(bound_ms);
    for (;;) {
        gateway.tick(0);
        for (CitraPeer* peer : peers) {
            peer->absorb();
        }
        if (done()) {
            return true;
        }
        if (Clock::now() >= deadline) {
            return false;
        }
        ::Sleep(1);
    }
}

// B3: pump the gateway and every ENet peer in lockstep (the gateway's ENet
// host only advances inside Gateway::tick).
bool until_enet(citra_gateway::Gateway& gateway, const std::vector<EnetCitraPeer*>& peers,
                const std::function<bool()>& done, int bound_ms = 4000) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(bound_ms);
    for (;;) {
        gateway.tick(0);
        for (EnetCitraPeer* peer : peers) {
            peer->service();
        }
        if (done()) {
            return true;
        }
        if (Clock::now() >= deadline) {
            return false;
        }
        ::Sleep(1);
    }
}

bool connect_enet_peer(citra_gateway::Gateway& gateway, EnetCitraPeer& peer, int bound_ms = 4000) {
    return until_enet(gateway, {&peer}, [&] { return peer.connected(); }, bound_ms);
}

bool wait_room_member(citra_gateway::Gateway& gateway, RoomGuard& room, const std::string& nickname,
                      bool present, int bound_ms = 3000) {
    return drive(gateway, {},
                 [&] { return member_for(room, nickname).has_value() == present; }, bound_ms);
}

bool join_peer(citra_gateway::Gateway& gateway, CitraPeer& peer, const std::string& nickname,
               const std::string& console_id_hash,
               const citra_room::MacAddress& preferred_mac = citra_room::no_preferred_mac,
               std::uint32_t version = citra_room::network_version,
               const std::string& password = std::string(),
               const std::vector<CitraPeer*>& peers = {}) {
    peer.send(citra_join_bytes(nickname, console_id_hash, preferred_mac, version, password));
    std::vector<CitraPeer*> watched = peers;
    if (watched.empty()) {
        watched.push_back(&peer);
    }
    return drive(gateway, watched, [&] {
        if (!peer.assigned_mac()) return false;
        // Game metadata is a separate upstream broadcast. Wait for it on
        // every watched peer before taking payload-only frame baselines.
        for (const auto* observer : watched) {
            bool found = false;
            for (const auto& message : observer->messages()) {
                if (const auto* info = std::get_if<citra_room::RoomInformation>(&message)) {
                    for (const auto& member : info->members) {
                        if (member.nickname == nickname && member.game_name == "CitraGateway") found = true;
                    }
                }
            }
            if (!found) return false;
        }
        return true;
    }, 4000);
}

bool wait_error_frame(citra_gateway::Gateway& gateway, CitraPeer& peer,
                      const std::vector<CitraPeer*>& peers = {}) {
    std::vector<CitraPeer*> watched = peers;
    if (watched.empty()) {
        watched.push_back(&peer);
    }
    return drive(gateway, watched, [&] { return peer.raw_count() >= 1; }, 4000);
}

room_client::Bytes compress_payload(const std::vector<std::uint8_t>& plain) {
    return zstd_frame(plain, 1);
}

// ===========================================================================
// A1: the gateway appears in the original room member table.
// ===========================================================================
void group_a1_members() {
    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 3);
    citra_gateway::Gateway gateway(gateway_options(gw_port, room));
    gateway.open();

    CitraPeer alpha;
    alpha.connect(gateway.port());
    verify(join_peer(gateway, alpha, "alpha-1", "console-alpha"), "A1 alpha joins through the gateway");
    verify(alpha.messages().size() >= 2, "A1 alpha received two Citra frames");

    const auto& alpha_raw = alpha.raw_frames();
    check(alpha_raw[0].size() >= 1 && alpha_raw[0][0] == 0x03,
          "A1 alpha raw frame 0 is Citra IdRoomInformation (03)");
    check(alpha_raw[1].size() >= 1 && alpha_raw[1][0] == 0x02,
          "A1 alpha raw frame 1 is Citra IdJoinSuccess (02)");
    check(std::holds_alternative<citra_room::RoomInformation>(alpha.messages()[0]) &&
              std::holds_alternative<citra_room::JoinSuccess>(alpha.messages()[1]),
          "A1 decoded order is RoomInformation then JoinSuccess");
    const auto* projected = std::get_if<citra_room::RoomInformation>(&alpha.messages()[0]);
    verify(projected != nullptr, "A1 first frame decodes as RoomInformation");
    check(projected->member_slots == 3, "A1 projected Citra member_slots equals room capacity 3");
    check(projected->members.size() == 1 && projected->members[0].nickname == "alpha-1",
          "A1 projected Citra member list holds alpha-1");

    const auto alpha_identity = identity_for(gateway, "alpha-1");
    verify(alpha_identity.has_value(), "A1 gateway identity table holds alpha-1");
    check(!citra_gateway::is_sentinel_mac(alpha_identity->mac),
          "A1 sentinel preferred MAC never enters the identity table");
    check(!citra_gateway::is_sentinel_ip(alpha_identity->fake_ip),
          "A1 assigned fake IPv4 is not the NoPreferredIP sentinel");
    check(gateway.counters().mac_generated == 1,
          "A1 sentinel preferred MAC was generated once by the gateway");
    check(alpha.assigned_mac().has_value() && *alpha.assigned_mac() == alpha_identity->mac,
          "A1 JoinSuccess carries the mapped MAC");

    verify(wait_room_member(gateway, room, "alpha-1", true), "A1 alpha appears in room member table");
    const auto alpha_member = member_for(room, "alpha-1");
    verify(alpha_member.has_value(), "A1 room member alpha-1 readable");
    check(same_ip(alpha_member->fake_ip, alpha_identity->fake_ip),
          "A1 room member fake IPv4 equals the mapped fake IPv4");
    check(room.information().member_slots == 3,
          "A1 original room member_slots mirrors the configured capacity");
    check(room_size(room) == 1, "A1 original room member count is 1");

    const bool game_set = drive(gateway, {&alpha},
                                [&] {
                                    const auto member = member_for(room, "alpha-1");
                                    return member.has_value() && member->game.name == "CitraGateway";
                                },
                                3000);
    const auto with_game = member_for(room, "alpha-1");
    check(game_set && with_game.has_value() && with_game->game.name == "CitraGateway",
          "A1 room member game name is the declared gateway peer game name");
    check(with_game.has_value() && with_game->game.version == "gw-v1",
          "A1 room member game version is the declared gateway peer game version");
    check(with_game.has_value() && with_game->game.id == 0,
          "A1 room member game id is the declared gateway peer game id");

    CitraPeer beta;
    beta.connect(gateway.port());
    verify(join_peer(gateway, beta, "beta-2", "console-beta", citra_room::no_preferred_mac,
                     citra_room::network_version, "", {&alpha, &beta}),
           "A1 beta joins through the gateway");
    verify(wait_room_member(gateway, room, "beta-2", true), "A1 beta appears in room member table");
    check(room_size(room) == 2, "A1 original room member count is 2");
    const auto beta_identity = identity_for(gateway, "beta-2");
    verify(beta_identity.has_value(), "A1 gateway identity table holds beta-2");
    check(beta_identity->fake_ip != alpha_identity->fake_ip,
          "A1 two peers receive distinct fake IPv4 values");
    check(beta_identity->mac != alpha_identity->mac, "A1 two peers receive distinct MACs");
    check(gateway.counters().members_in_room >= 2,
          "A1 gateway observed at least two room members");

    const auto counters_before = gateway.counters();
    beta.close_now();
    const bool left = drive(gateway, {},
                            [&] {
                                return gateway.counters().clients_left >=
                                           counters_before.clients_left + 1 &&
                                       !member_for(room, "beta-2").has_value();
                            },
                            4000);
    check(left, "A1 room member table updates after the client disconnects");
    check(!identity_for(gateway, "beta-2").has_value(),
          "A1 identity mapping is deleted on disconnect");
    check(room_size(room) == 1, "A1 room member count returns to 1 after disconnect");
    check(gateway.client_count() == 1, "A1 gateway retains only the live client");

    dump_documents(gateway, "a1_members");
}

// ===========================================================================
// A2: handshake order and strict per-side version termination.
// ===========================================================================
void group_a2_handshake() {
    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 4);
    citra_gateway::Gateway gateway(gateway_options(gw_port, room));
    gateway.open();

    CitraPeer wrong_version;
    wrong_version.connect(gateway.port());
    wrong_version.send(citra_join_bytes("zeta-9", "console-zeta", citra_room::no_preferred_mac, 3, ""));
    verify(wait_error_frame(gateway, wrong_version), "A2 version 3 client receives one frame");
    check(hex_of(wrong_version.raw_frames()[0]) == "0900000004",
          "A2 Citra side version mismatch is exactly 09 00000004");
    check(room_size(room) == 0, "A2 rejected client never reaches the room member table");
    check(gateway.counters().local_version_rejections == 1,
          "A2 local version rejection counted once");
    check(gateway.counters().room_join_successes == 0, "A2 no room join success recorded");
    check(gateway.counters().room_join_attempts == 1, "A2 one join attempt recorded");

    CitraPeer good;
    good.connect(gateway.port());
    verify(join_peer(gateway, good, "alpha-1", "console-alpha"), "A2 version 4 client joins");
    check(good.raw_frames()[0][0] == 0x03 && good.raw_frames()[1][0] == 0x02,
          "A2 RoomInformation precedes JoinSuccess for the accepted client");
    verify(wait_room_member(gateway, room, "alpha-1", true), "A2 accepted client in room table");

    const auto room_probe = probe_room_version(room_port, 4);
    verify(room_probe.has_value(), "A2 raw v4 probe against the original room is rejected");
    check(room_probe->id == room_client::MessageId::VersionMismatch,
          "A2 the original room answers a v4 join with IdVersionMismatch");
    check(room_probe->server_version == 1, "A2 the original room announces server version 1");

    RawRoomPeer raw_probe(room_port, "ProbeUser", 4);
    const auto raw_error = wait_raw_frame(raw_probe, 0x0A);
    verify(raw_error.has_value(), "A2 the room answers the v4 probe with an IdVersionMismatch frame");
    check(room_client::to_hex(*raw_error) == "0a00000001",
          "A2 room side version mismatch wire golden is the hand written 0a 00000001");
    const auto decoded_error = room_client::decode(*raw_error, room_client::Direction::ServerToClient);
    const auto* server_error = std::get_if<room_client::ServerError>(&decoded_error);
    check(server_error != nullptr && server_error->id == room_client::MessageId::VersionMismatch &&
              server_error->server_version == 1,
          "A2 the hand written room golden decodes to IdVersionMismatch with server version 1");

    check(gateway.counters().room_version_forwarded == 1,
          "A2 the gateway only ever forwards room version 1");
    check(gateway.counters().citra_version_served == 4,
          "A2 the gateway only ever serves Citra version 4");
    check(good.undecodable().empty(), "A2 every gateway frame decodes as Citra v4");

    dump_documents(gateway, "a2_handshake");
}

// ===========================================================================
// A3: one independent hex golden per error mapping.
// ===========================================================================
void group_a3_mappings() {
    const std::string golden_password = "0a";
    const std::string golden_citra_version = "0900000004";
    const std::string golden_name = "07";
    const std::string golden_mac = "08";
    const std::string golden_full = "0c";
    const std::string golden_close = "0b";
    const std::string golden_console = "0d";
    const std::vector<std::pair<std::string, std::string>> goldens = {
        {"password", golden_password}, {"citra_version", golden_citra_version},
        {"name", golden_name},         {"mac", golden_mac},
        {"full", golden_full},         {"close", golden_close},
        {"console_id", golden_console},
    };
    for (std::size_t i = 0; i < goldens.size(); ++i) {
        for (std::size_t j = i + 1; j < goldens.size(); ++j) {
            check(goldens[i].second != goldens[j].second,
                  "A3 golden " + goldens[i].first + " differs from golden " + goldens[j].first);
        }
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4, "local-secret");
        citra_gateway::Gateway gateway(gateway_options(gw_port, room, "local-secret"));
        gateway.open();
        CitraPeer peer;
        peer.connect(gateway.port());
        peer.send(citra_join_bytes("alpha-1", "console-alpha", citra_room::no_preferred_mac,
                                   citra_room::network_version, "wrong-one"));
        verify(wait_error_frame(gateway, peer), "A3 password case receives a rejection frame");
        check(hex_of(peer.raw_frames()[0]) == golden_password,
              "A3 wrong password maps to Citra 0a");
        check(has_single_hit(gateway.counters().error_map_hits, "WrongPassword", 1),
              "A3 wrong password counter is exactly WrongPassword=1");
        // V-016l: the password is now compared locally in Citra's own order, so
        // the rejection no longer travels through the room error mapping.
        check(gateway.counters().room_errors_mapped == 0,
              "A3 wrong password was rejected locally, not by the room");
        check(gateway.counters().local_wrong_password_rejections == 1,
              "A3 wrong password local counter is exactly 1");
        dump_documents(gateway, "a3_password");
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();
        CitraPeer peer;
        peer.connect(gateway.port());
        peer.send(citra_join_bytes("alpha-1", "console-alpha", citra_room::no_preferred_mac, 2, ""));
        verify(wait_error_frame(gateway, peer), "A3 version case receives a rejection frame");
        check(hex_of(peer.raw_frames()[0]) == golden_citra_version,
              "A3 Citra version mismatch maps to Citra 09 00000004");
        check(has_single_hit(gateway.counters().error_map_hits, "VersionMismatch", 1),
              "A3 version counter is exactly VersionMismatch=1");
        dump_documents(gateway, "a3_version");
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();
        CitraPeer alpha;
        alpha.connect(gateway.port());
        verify(join_peer(gateway, alpha, "alpha-1", "console-alpha"), "A3 name case alpha joins");
        CitraPeer twin;
        twin.connect(gateway.port());
        twin.send(citra_join_bytes("alpha-1", "console-twin", citra_room::no_preferred_mac));
        verify(wait_error_frame(gateway, twin, {&alpha, &twin}),
               "A3 name case twin receives a rejection frame");
        check(hex_of(twin.raw_frames()[0]) == golden_name,
              "A3 nickname collision maps to Citra 07");
        check(has_single_hit(gateway.counters().error_map_hits, "NameCollision", 1),
              "A3 name collision counter is exactly NameCollision=1");
        // V-016l: the nickname rule and its uniqueness are checked locally, in
        // Citra's own order, before the room is asked.
        check(gateway.counters().room_errors_mapped == 0,
              "A3 name collision was rejected locally, not by the room");
        check(gateway.counters().local_name_collision_rejections == 1,
              "A3 name collision local counter is exactly 1");
        check(room_size(room) == 1, "A3 name collision leaves the room member table at 1");
        dump_documents(gateway, "a3_name");
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();
        citra_room::MacAddress preferred{0x00, 0x1F, 0x32, 0x01, 0x02, 0x03};
        CitraPeer alpha;
        alpha.connect(gateway.port());
        verify(join_peer(gateway, alpha, "alpha-1", "console-alpha", preferred),
               "A3 MAC case alpha joins with a preferred MAC");
        const auto alpha_identity = identity_for(gateway, "alpha-1");
        check(alpha_identity.has_value() && alpha_identity->mac == preferred,
              "A3 gateway honours a valid non sentinel preferred MAC");
        CitraPeer twin;
        twin.connect(gateway.port());
        twin.send(citra_join_bytes("beta-2", "console-twin", preferred));
        verify(wait_error_frame(gateway, twin, {&alpha, &twin}),
               "A3 MAC case twin receives a rejection frame");
        check(hex_of(twin.raw_frames()[0]) == golden_mac, "A3 MAC collision maps to Citra 08");
        check(has_single_hit(gateway.counters().error_map_hits, "MacCollision", 1),
              "A3 MAC collision counter is exactly MacCollision=1");
        check(gateway.counters().local_mac_collision_rejections == 1,
              "A3 MAC collision was rejected locally without asking the room");
        check(gateway.counters().room_join_attempts == 2, "A3 both MAC case joins were attempted");
        dump_documents(gateway, "a3_mac");
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 1);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();
        CitraPeer alpha;
        alpha.connect(gateway.port());
        verify(join_peer(gateway, alpha, "alpha-1", "console-alpha"), "A3 full case alpha joins");
        CitraPeer beta;
        beta.connect(gateway.port());
        beta.send(citra_join_bytes("beta-2", "console-beta", citra_room::no_preferred_mac));
        verify(wait_error_frame(gateway, beta, {&alpha, &beta}),
               "A3 full case beta receives a rejection frame");
        check(hex_of(beta.raw_frames()[0]) == golden_full, "A3 room full maps to Citra 0c");
        check(has_single_hit(gateway.counters().error_map_hits, "RoomIsFull", 1),
              "A3 room full counter is exactly RoomIsFull=1");
        // V-016l: with the room capacity known in-process the full check is local
        // too (Citra checks it before parsing the rest of the request).
        check(gateway.counters().room_errors_mapped == 0,
              "A3 room full was rejected locally, not by the room");
        check(gateway.counters().local_room_full_rejections == 1,
              "A3 room full local counter is exactly 1");
        dump_documents(gateway, "a3_full");
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();
        CitraPeer alpha;
        alpha.connect(gateway.port());
        verify(join_peer(gateway, alpha, "alpha-1", "console-alpha"), "A3 close case alpha joins");
        const std::size_t baseline = alpha.raw_count();
        room.close();
        const bool closed = drive(gateway, {&alpha}, [&] { return alpha.raw_count() > baseline; }, 4000);
        check(closed, "A3 close case alpha receives a final frame after Room::Destroy");
        check(alpha.raw_count() == baseline + 1 &&
                  hex_of(alpha.raw_frames()[baseline]) == golden_close,
              "A3 room closed maps to Citra 0b");
        check(has_single_hit(gateway.counters().error_map_hits, "CloseRoom", 1),
              "A3 close room counter is exactly CloseRoom=1");
        check(gateway.counters().room_errors_mapped == 1,
              "A3 close room travelled through the room error mapping");
        dump_documents(gateway, "a3_close");
    }

    // V-016g: Citra IdConsoleIdCollision (13) has no Yuzu counterpart. It must
    // stay a local, explicitly counted no-correspondence rejection and must never
    // be produced by a room error mapping (in particular never from IpCollision).
    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();
        CitraPeer alpha;
        alpha.connect(gateway.port());
        verify(join_peer(gateway, alpha, "alpha-1", "shared-console-id"),
               "A3 console id case alpha joins");
        CitraPeer twin;
        twin.connect(gateway.port());
        twin.send(citra_join_bytes("beta-2", "shared-console-id", citra_room::no_preferred_mac));
        verify(wait_error_frame(gateway, twin, {&alpha, &twin}),
               "A3 console id case twin receives a rejection frame");
        check(hex_of(twin.raw_frames()[0]) == golden_console,
              "A3 console id collision maps to Citra 0d");
        check(has_single_hit(gateway.counters().error_map_hits, "ConsoleIdCollision", 1),
              "A3 console id counter is exactly ConsoleIdCollision=1");
        check(gateway.counters().room_errors_mapped == 0,
              "A3 console id collision was never produced by a room error mapping");
        check(gateway.counters().local_console_id_collision_rejections == 1 &&
                  gateway.counters().no_correspondence_rejections == 1,
              "A3 console id collision is counted as a no-correspondence rejection");
        check(gateway.counters().local_mac_collision_rejections == 0,
              "A3 console id collision is never silently mapped to a MAC collision");
        dump_documents(gateway, "a3_console_id");
    }
}

// ===========================================================================
// A3b: the same mapping evidence, but read from the room's own wire bytes.
// ===========================================================================
void group_a3_room_goldens() {
    {
        const auto port = take_port();
        RoomGuard room(port, 2);
        RawRoomPeer peer(port, "ProbeUser", 4);
        const auto frame = wait_raw_frame(peer, 0x0A);
        check(frame.has_value() && room_client::to_hex(*frame) == "0a00000001",
              "A3b room IdVersionMismatch wire golden is exactly 0a 00000001");
    }
    {
        const auto port = take_port();
        RoomGuard room(port, 2, "local-secret");
        RawRoomPeer peer(port, "WrongPass-1", room_client::network_version);
        const auto frame = wait_raw_frame(peer, 0x0B);
        check(frame.has_value() && room_client::to_hex(*frame) == "0b",
              "A3b room IdWrongPassword wire golden is exactly 0b");
    }
    {
        const auto port = take_port();
        RoomGuard room(port, 2);
        RawRoomPeer first(port, "collide-1", room_client::network_version);
        verify(wait_raw_frame(first, 0x02).has_value(), "A3b the first raw peer joins the room");
        RawRoomPeer second(port, "collide-1", room_client::network_version);
        const auto frame = wait_raw_frame(second, 0x08);
        check(frame.has_value() && room_client::to_hex(*frame) == "08",
              "A3b room IdNameCollision wire golden is exactly 08");
    }
    {
        const auto port = take_port();
        RoomGuard room(port, 2);
        RawRoomPeer first(port, "ipfirst-1", room_client::network_version);
        const auto ip = wait_assigned_ip(first);
        verify(ip.has_value(), "A3b the first raw peer received an assigned fake IPv4");
        RawRoomPeer second(port, "ipsecond-2", room_client::network_version, *ip);
        const auto frame = wait_raw_frame(second, 0x09);
        check(frame.has_value() && room_client::to_hex(*frame) == "09",
              "A3b room IdIpCollision wire golden is exactly 09");
    }
    {
        const auto port = take_port();
        RoomGuard room(port, 1);
        RawRoomPeer first(port, "fullfirst-1", room_client::network_version);
        verify(wait_raw_frame(first, 0x02).has_value(), "A3b the capacity 1 raw peer joins the room");
        RawRoomPeer second(port, "fullsecond-2", room_client::network_version);
        const auto frame = wait_raw_frame(second, 0x0D);
        check(frame.has_value() && room_client::to_hex(*frame) == "0d",
              "A3b room IdRoomIsFull wire golden is exactly 0d");
    }
    {
        const auto port = take_port();
        RoomGuard room(port, 2);
        RawRoomPeer peer(port, "closed-1", room_client::network_version);
        verify(wait_raw_frame(peer, 0x02).has_value(),
               "A3b the raw peer joins before the room is closed");
        room.close();
        const auto frame = wait_raw_frame(peer, 0x0C);
        check(frame.has_value() && room_client::to_hex(*frame) == "0c",
              "A3b room IdCloseRoom wire golden is exactly 0c");
    }
    note("a3b.room_wire_goldens", "0a00000001,0b,08,09,0d,0c");
}

// ===========================================================================
// ===========================================================================
// A3c: multi-fault joins pin the full local check order (V-016l).
//   real Citra order: room full -> password -> nickname -> MAC -> console id ->
//   version (citra-master/src/network/room.cpp:302-360). Every case below carries
//   two faults at once, so its independent hand written golden proves which check
//   ran first. The goldens are literals, never produced by an encoder.
// ===========================================================================
void group_a3c_order() {
    using Counters = citra_gateway::Counters;
    using CounterField = std::uint64_t Counters::*;

    {
        const auto port = take_port();
        RoomGuard room(port, 1);
        check(room.information().member_slots == 1,
              "A3c the in-process room reports member_slots == 1");
        check(room.capacity() == 1, "A3c RoomGuard keeps the capacity it created");
    }

    const auto run_fault = [&](const std::string& label, std::uint32_t capacity,
                               const std::string& room_password, bool pre_join_first,
                               const std::string& first_nickname, const std::string& first_console,
                               const citra_room::MacAddress& first_mac,
                               const std::string& second_nickname,
                               const std::string& second_console,
                               const citra_room::MacAddress& second_mac,
                               std::uint32_t second_version, const std::string& second_password,
                               const std::string& golden, citra_room::MessageId expected_id,
                               CounterField expected_counter, std::uint64_t expected_value,
                               const std::vector<CounterField>& shadowed, const std::string& tag) {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, capacity, room_password);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room, room_password));
        gateway.open();
        CitraPeer first;
        std::vector<CitraPeer*> watched;
        if (pre_join_first) {
            first.connect(gateway.port());
            watched.push_back(&first);
            verify(join_peer(gateway, first, first_nickname, first_console, first_mac,
                             citra_room::network_version, room_password),
                   label + ": the first peer joins");
        }
        CitraPeer second;
        second.connect(gateway.port());
        watched.push_back(&second);
        second.send(citra_join_bytes(second_nickname, second_console, second_mac, second_version,
                                     second_password));
        verify(wait_error_frame(gateway, second, watched),
               label + ": the second peer receives one rejection frame");
        check(hex_of(second.raw_frames()[0]) == golden,
              label + ": hand written golden is " + golden);
        const Counters counters = gateway.counters();
        check(counters.*expected_counter == expected_value,
              label + ": the deciding local counter equals " + std::to_string(expected_value));
        for (const CounterField field : shadowed) {
            check(counters.*field == 0, label + ": the shadowed counter stays 0");
        }
        const std::string expected_name = citra_room::message_name(expected_id);
        check(has_single_hit(counters.error_map_hits, expected_name, 1),
              label + ": exactly one " + expected_name + " rejection");
        const std::size_t expect_members = pre_join_first ? 1U : 0U;
        check(room_size(room) == expect_members,
              label + ": the room member table holds only the accepted peers");
        check(counters.room_join_successes == expect_members,
              label + ": room join successes match the accepted peers");
        dump_documents(gateway, tag);
        note(tag, golden);
    };

    const citra_room::MacAddress sentinel = citra_room::no_preferred_mac;
    const citra_room::MacAddress fixed{0x00, 0x1F, 0x32, 0x04, 0x05, 0x06};

    // 1. room full + wrong version: the full check is first -> Citra 12 = 0c.
    run_fault("A3c full+version", 1, "", true, "alpha-1", "console-alpha", sentinel, "beta-2",
              "console-beta", sentinel, 3, "", "0c", citra_room::MessageId::RoomIsFull,
              &Counters::local_room_full_rejections, 1,
              {&Counters::local_version_rejections, &Counters::local_wrong_password_rejections},
              "a3c_full_version");

    // 2. wrong password + wrong version: password is second -> Citra 10 = 0a.
    run_fault("A3c password+version", 4, "local-secret", false, "", "", sentinel, "beta-2",
              "console-beta", sentinel, 3, "wrong-one", "0a", citra_room::MessageId::WrongPassword,
              &Counters::local_wrong_password_rejections, 1,
              {&Counters::local_version_rejections, &Counters::local_room_full_rejections},
              "a3c_password_version");

    // 3. wrong password + duplicate nickname: password wins -> 0a.
    run_fault("A3c password+name", 4, "local-secret", true, "alpha-1", "console-alpha", sentinel,
              "alpha-1", "console-beta", sentinel, 4, "wrong-one", "0a",
              citra_room::MessageId::WrongPassword, &Counters::local_wrong_password_rejections, 1,
              {&Counters::local_name_collision_rejections, &Counters::local_mac_collision_rejections},
              "a3c_password_name");

    // 4. duplicate nickname + duplicate MAC: nickname wins -> Citra 7 = 07.
    run_fault("A3c name+mac", 4, "", true, "alpha-1", "console-alpha", fixed, "alpha-1",
              "console-beta", fixed, 4, "", "07", citra_room::MessageId::NameCollision,
              &Counters::local_name_collision_rejections, 1,
              {&Counters::local_mac_collision_rejections, &Counters::local_console_id_collision_rejections},
              "a3c_name_mac");

    // 5. duplicate MAC + duplicate console id: MAC wins -> Citra 8 = 08.
    run_fault("A3c mac+console", 4, "", true, "alpha-1", "console-alpha", fixed, "beta-2",
              "console-alpha", fixed, 4, "", "08", citra_room::MessageId::MacCollision,
              &Counters::local_mac_collision_rejections, 1,
              {&Counters::local_console_id_collision_rejections, &Counters::local_version_rejections},
              "a3c_mac_console");

    // 6. duplicate console id + wrong version: console id wins -> Citra 13 = 0d.
    run_fault("A3c console+version", 4, "", true, "alpha-1", "console-alpha", sentinel, "beta-2",
              "console-alpha", sentinel, 3, "", "0d", citra_room::MessageId::ConsoleIdCollision,
              &Counters::local_console_id_collision_rejections, 1,
              {&Counters::local_version_rejections, &Counters::local_name_collision_rejections},
              "a3c_console_version");

    // 7. version fault alone, checked last -> Citra 9 with u32 4 = 0900000004.
    run_fault("A3c version only", 4, "", false, "", "", sentinel, "beta-2", "console-beta",
              sentinel, 3, "", "0900000004", citra_room::MessageId::VersionMismatch,
              &Counters::local_version_rejections, 1,
              {&Counters::local_room_full_rejections, &Counters::local_wrong_password_rejections,
               &Counters::local_name_collision_rejections, &Counters::local_mac_collision_rejections,
               &Counters::local_console_id_collision_rejections},
              "a3c_version_only");

    // 8. the regex branch of the nickname rule (no room peer needed) -> 07.
    run_fault("A3c invalid nickname", 4, "", false, "", "", sentinel, "ab", "console-beta",
              sentinel, 4, "", "07", citra_room::MessageId::NameCollision,
              &Counters::local_name_collision_rejections, 1,
              {&Counters::local_mac_collision_rejections, &Counters::local_version_rejections},
              "a3c_invalid_nickname");

    // The gateway's local nickname rule must be the frozen client codec's rule.
    const std::vector<std::string> samples = {"abcd",
                                              "abc",
                                              "ab",
                                              "",
                                              "name with space",
                                              "Name.With_Under-Score",
                                              "01234567890123456789",
                                              "012345678901234567890",
                                              "bad!",
                                              "  pad  ",
                                              "A1_-"};
    for (const std::string& sample : samples) {
        check(citra_gateway::is_valid_nickname(sample) == citra_room::is_valid_nickname(sample),
              "A3c nickname rule agrees with citra_room for '" + sample + "'");
    }
}

// ===========================================================================
// A4: declared payload category is byte identical end to end, compared as hex.
// ===========================================================================
void group_a4_payload() {
    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 4);
    citra_gateway::Gateway gateway(gateway_options(gw_port, room));
    gateway.open();

    CitraPeer alpha;
    alpha.connect(gateway.port());
    verify(join_peer(gateway, alpha, "alpha-1", "console-alpha"), "A4 alpha joins");
    CitraPeer beta;
    beta.connect(gateway.port());
    verify(join_peer(gateway, beta, "beta-2", "console-beta", citra_room::no_preferred_mac,
                     citra_room::network_version, "", {&alpha, &beta}),
           "A4 beta joins");
    const auto alpha_mac = alpha.assigned_mac();
    const auto beta_mac = beta.assigned_mac();
    verify(alpha_mac.has_value() && beta_mac.has_value(), "A4 both peers hold assigned MACs");

    const auto payload = synthetic_payload(64, 0x5A);
    const auto unicast_frame = citra_wifi_bytes(*alpha_mac, *beta_mac, payload);
    const std::size_t beta_baseline = beta.raw_count();
    alpha.send(unicast_frame);
    const bool delivered = drive(gateway, {&alpha, &beta},
                                 [&] { return beta.raw_count() > beta_baseline; }, 4000);
    verify(delivered, "A4 unicast payload reaches the destination client");
    check(hex_of(beta.raw_frames()[beta_baseline]) == hex_of(unicast_frame),
          "A4 received Citra frame hex equals the sent frame hex byte for byte");
    const auto& received = beta.raw_frames()[beta_baseline];
    const auto payload_hex = hex_of(payload);
    const bool tail_ok =
        received.size() >= payload.size() &&
        hex_of(std::vector<std::uint8_t>(received.end() - static_cast<std::ptrdiff_t>(payload.size()),
                                         received.end())) == payload_hex;
    check(tail_ok, "A4 opaque payload bytes are identical at the tail of the received frame");
    check(alpha.wifi_frames() == 0, "A4 unicast is not echoed back to the sender");
    check(beta.undecodable().empty(), "A4 every delivered frame decodes as Citra v4");

    const auto counters = gateway.counters();
    check(counters.proxy_frames_emitted == 1,
          "A4 exactly one room Proxy frame emitted from the Citra payload");
    check(counters.proxy_frames_consumed == 1,
          "A4 exactly one room Proxy frame consumed back into Citra");
    check(counters.payload_forwarded == 2, "A4 payload forwarded on both directions");
    check(counters.payload_rejected_unknown_category == 0,
          "A4 no declared category was rejected while forwarding");
    check(counters.room_frames_rejected == 0, "A4 no room frame rejected on the data plane");

    const auto captures = gateway.data_plane_captures();
    verify(captures.size() >= 2, "A4 both data plane captures recorded");
    const auto& outbound = captures[captures.size() - 2];
    const auto& inbound = captures[captures.size() - 1];
    check(outbound.direction == "citra_to_room" && inbound.direction == "room_to_citra",
          "A4 capture directions are citra_to_room then room_to_citra");
    check(outbound.opaque_hex == payload_hex && inbound.opaque_hex == payload_hex,
          "A4 both captures carry the identical opaque payload hex");
    check(outbound.content_bytes == payload.size() && inbound.content_bytes == payload.size(),
          "A4 Zstd frame content size equals the opaque payload size");
    check(outbound.wire_bytes == inbound.wire_bytes && outbound.wire_bytes > 0,
          "A4 the single Zstd frame is relayed unchanged in size");
    check(outbound.source_mac == citra_gateway::mac_to_string(*alpha_mac) &&
              outbound.destination_mac == citra_gateway::mac_to_string(*beta_mac),
          "A4 outbound capture records the mapped source and destination MACs");
    check(inbound.source_mac == citra_gateway::mac_to_string(*alpha_mac) &&
              inbound.destination_mac == citra_gateway::mac_to_string(*beta_mac),
          "A4 inbound capture preserves the source and destination MACs");

    const auto broadcast_payload = synthetic_payload(32, 0x11);
    const auto broadcast_frame =
        citra_wifi_bytes(*alpha_mac, citra_room::broadcast_mac, broadcast_payload);
    const std::size_t beta_broadcast_baseline = beta.raw_count();
    alpha.send(broadcast_frame);
    const bool broadcast_delivered = drive(gateway, {&alpha, &beta},
                                           [&] { return beta.raw_count() > beta_broadcast_baseline; },
                                           4000);
    check(broadcast_delivered, "A4 broadcast payload reaches the other client");
    check(hex_of(beta.raw_frames()[beta_broadcast_baseline]) == hex_of(broadcast_frame),
          "A4 broadcast client frame hex equals the sent frame hex");
    check(alpha.wifi_frames() == 0, "A4 broadcast is never echoed to the sender");
    check(gateway.counters().proxy_frames_emitted == 2,
          "A4 second Proxy frame emitted for the broadcast");

    // V-016k: Citra's ASSERT is unconditionally fatal, so the gateway may only ever
    // emit WifiPacket frames of type Data (and it synthesises no LLC/SecureData at
    // all). Every other Citra frame type is refused here and counted, never relayed.
    const std::size_t beta_before_reject = beta.raw_count();
    const auto rejected_before = gateway.counters();
    const citra_room::FrameType non_data_types[] = {
        citra_room::FrameType::Beacon, citra_room::FrameType::Authentication,
        citra_room::FrameType::AssociationResponse, citra_room::FrameType::Deauthentication,
        citra_room::FrameType::NodeMap,
    };
    for (const auto type : non_data_types) {
        alpha.send(citra_wifi_bytes(*alpha_mac, *beta_mac, payload, type));
    }
    citra_room::ChatRequest chat;
    chat.message = "synthetic chat, never a capture";
    alpha.send(citra_room::encode(chat, citra_room::Direction::ClientToServer));
    drive(gateway, {&alpha, &beta}, [&] { return false; }, 300);
    const auto rejected_after = gateway.counters();
    check(rejected_after.payload_rejected_unknown_category ==
              rejected_before.payload_rejected_unknown_category + 5,
          "A4 the five non Data Citra frame types are rejected and counted");
    check(beta.raw_count() == beta_before_reject + 1 &&
              std::holds_alternative<citra_room::ChatMessage>(beta.messages().back()) &&
              std::get<citra_room::ChatMessage>(beta.messages().back()).message == chat.message,
          "A4 only the supported chat message is forwarded once");
    check(rejected_after.proxy_frames_emitted == rejected_before.proxy_frames_emitted,
          "A4 no room Proxy frame emitted for an undeclared category");

    const auto transmitter_hex = hex_of(*alpha_mac);
    check(hex_of(beta.raw_frames()[beta_baseline]).substr(6, 12) == transmitter_hex,
          "A4 the transmitted frame carries the mapped transmitter MAC at the documented offset");
    check(hex_of(beta.raw_frames()[beta_broadcast_baseline]).substr(6, 12) == transmitter_hex,
          "A4 a host transmitter MAC stays stable across frames (V-016k)");
    for (const auto* peer : {&alpha, &beta}) {
        bool only_data = true;
        for (const auto& message : peer->messages()) {
            if (const auto* wifi = std::get_if<citra_room::WifiPacket>(&message)) {
                if (wifi->type != citra_room::FrameType::Data) {
                    only_data = false;
                }
            }
        }
        check(only_data, "A4 every delivered Citra WifiPacket uses the Data frame type (V-016k)");
    }

    dump_documents(gateway, "a4_payload");
}

// ===========================================================================
// A5: fail closed boundaries.
// ===========================================================================
void group_a5_fail_closed() {
    const auto plain = synthetic_payload(64, 0x33);
    const auto good_frame = zstd_frame(plain, 1);
    std::string why;

    check(citra_gateway::valid_proxy_frame(good_frame, 65536, 65536, &why),
          "A5 a single well formed Zstd frame passes valid_proxy_frame");
    citra_room::Bytes recovered;
    check(citra_gateway::decompress_proxy_frame(good_frame, 65536, recovered, &why) &&
              recovered == plain,
          "A5 decompress_proxy_frame returns the original plain bytes");
    check(!citra_gateway::valid_proxy_frame(
              room_client::Bytes(good_frame.begin(), good_frame.begin() + good_frame.size() / 2),
              65536, 65536, &why),
          "A5 a truncated Zstd frame is refused");
    room_client::Bytes trailing = good_frame;
    trailing.push_back(0x00);
    check(!citra_gateway::valid_proxy_frame(trailing, 65536, 65536, &why),
          "A5 trailing bytes after the frame are refused");
    room_client::Bytes concatenated = good_frame;
    concatenated.insert(concatenated.end(), good_frame.begin(), good_frame.end());
    check(!citra_gateway::valid_proxy_frame(concatenated, 65536, 65536, &why),
          "A5 concatenated frames are refused");
    const auto unknown_size = zstd_frame_unknown_size(plain);
    check(!citra_gateway::valid_proxy_frame(unknown_size, 65536, 65536, &why),
          "A5 a Zstd frame with unknown content size is refused");
    check(!citra_gateway::valid_proxy_frame(good_frame, 65536, 8, &why),
          "A5 a frame over the decompressed cap is refused");
    check(!citra_gateway::valid_proxy_frame(good_frame, 4, 65536, &why),
          "A5 a frame over the compressed cap is refused");
    room_client::Bytes produced;
    check(citra_gateway::compress_proxy_frame(plain, 65536, 1, produced, &why),
          "A5 compress_proxy_frame produces a frame");
    check(citra_gateway::valid_proxy_frame(produced, 65536, 65536, &why),
          "A5 the produced frame passes its own validator");
    const auto incompressible = synthetic_payload(4096, 0x7F);
    check(!citra_gateway::compress_proxy_frame(incompressible, 8, 1, produced, &why),
          "A5 compress_proxy_frame refuses a result over the compressed cap");
    room_client::Bytes not_a_frame{0x00, 0x01, 0x02, 0x03};
    check(!citra_gateway::decompress_proxy_frame(not_a_frame, 65536, recovered, &why),
          "A5 decompress_proxy_frame refuses a non Zstd frame");

    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 4, "local-secret");
    citra_gateway::Gateway gateway(gateway_options(gw_port, room, "local-secret"));
    gateway.open();

    CitraPeer alpha;
    alpha.connect(gateway.port());
    verify(join_peer(gateway, alpha, "alpha-1", "console-alpha", citra_room::no_preferred_mac,
                     citra_room::network_version, "local-secret"),
           "A5 alpha joins for the boundary group");
    CitraPeer beta;
    beta.connect(gateway.port());
    verify(join_peer(gateway, beta, "beta-2", "console-beta", citra_room::no_preferred_mac,
                     citra_room::network_version, "local-secret", {&alpha, &beta}),
           "A5 beta joins for the boundary group");
    const auto alpha_identity = identity_for(gateway, "alpha-1");
    const auto beta_identity = identity_for(gateway, "beta-2");
    verify(alpha_identity.has_value() && beta_identity.has_value(), "A5 both identities known");
    const auto alpha_id = client_id_for(gateway, "alpha-1");
    const auto alpha_mac = alpha.assigned_mac();
    const auto beta_mac = beta.assigned_mac();
    verify(alpha_mac.has_value() && beta_mac.has_value(), "A5 both MACs known");

    RawRoomPeer gamma(room_port, "gamma-3", room_client::network_version,
                      room_client::no_preferred_ip, "local-secret");
    const auto gamma_ip = wait_assigned_ip(gamma);
    verify(gamma_ip.has_value(), "A5 a third room member joined without a session identity");
    const bool three_members =
        drive(gateway, {&alpha, &beta},
              [&] { return gateway.counters().members_in_room >= 3; }, 3000);
    verify(three_members, "A5 a third room member is visible to the gateway transports");

    struct LdnCase {
        room_client::LdnType type;
        std::size_t size;
        const char* name;
    };
    const LdnCase ldn_cases[] = {
        {room_client::LdnType::Scan, 0, "Scan"},
        {room_client::LdnType::ScanResponse, 0x480, "ScanResponse"},
        {room_client::LdnType::Connect, 0x40, "Connect"},
        {room_client::LdnType::SyncNetwork, 0x480, "SyncNetwork"},
        {room_client::LdnType::Disconnect, 0x40, "Disconnect"},
        {room_client::LdnType::DestroyNetwork, 0, "DestroyNetwork"},
    };
    for (const auto& ldn_case : ldn_cases) {
        room_client::LdnPacket packet;
        packet.type = ldn_case.type;
        packet.local_ip = beta_identity->fake_ip;
        packet.remote_ip = alpha_identity->fake_ip;
        packet.broadcast = false;
        packet.data = synthetic_payload(ldn_case.size, 0x21);
        const auto before = gateway.counters();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, packet);
        const auto after = gateway.counters();
        check(accepted && after.payload_rejected_unknown_category ==
                              before.payload_rejected_unknown_category + 1 &&
                  after.transport_boundary_rejections == before.transport_boundary_rejections,
              std::string("A5 LDN ") + ldn_case.name + " with the exact body size 0x" +
                  std::to_string(ldn_case.size) +
                  " passes the frozen boundary and is refused as an undeclared category");
        room_client::LdnPacket oversized = packet;
        oversized.data.push_back(0x00);
        const auto before_plus = gateway.counters();
        const bool accepted_plus = gateway.inject_room_message_for_test(alpha_id, oversized);
        const auto after_plus = gateway.counters();
        check(!accepted_plus &&
                  after_plus.transport_boundary_rejections ==
                      before_plus.transport_boundary_rejections + 1,
              std::string("A5 LDN ") + ldn_case.name +
                  " with body size +1 is refused by the boundary");
    }

    {
        room_client::Bytes raw;
        raw.push_back(0x06);
        raw.push_back(0xFF);
        raw.push_back(beta_identity->fake_ip[0]);
        raw.push_back(beta_identity->fake_ip[1]);
        raw.push_back(beta_identity->fake_ip[2]);
        raw.push_back(beta_identity->fake_ip[3]);
        raw.push_back(alpha_identity->fake_ip[0]);
        raw.push_back(alpha_identity->fake_ip[1]);
        raw.push_back(alpha_identity->fake_ip[2]);
        raw.push_back(alpha_identity->fake_ip[3]);
        raw.push_back(0x00);
        const bool accepted = gateway.inject_room_raw_for_test(alpha_id, raw);
        check(!accepted && gateway.is_open(),
              "A5 an unknown LDN type is refused without disturbing the gateway process");
    }

    room_client::ProxyPacket proxy;
    proxy.local.family = room_client::Domain::Inet;
    proxy.local.ip = beta_identity->fake_ip;
    proxy.local.port = 0;
    proxy.remote.family = room_client::Domain::Inet;
    proxy.remote.ip = alpha_identity->fake_ip;
    proxy.remote.port = 0;
    proxy.protocol = room_client::SocketProtocol::Udp;
    proxy.broadcast = false;
    proxy.data = compress_payload(plain);
    {
        const auto before = gateway.counters();
        const std::size_t alpha_baseline = alpha.raw_count();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, proxy);
        const bool delivered = drive(gateway, {&alpha, &beta},
                                     [&] { return alpha.raw_count() > alpha_baseline; }, 3000);
        const auto after = gateway.counters();
        check(accepted && delivered, "A5 a well formed inbound Proxy frame is delivered to Citra");
        const auto* wifi = alpha.raw_count() > alpha_baseline
                               ? std::get_if<citra_room::WifiPacket>(&alpha.messages()[alpha_baseline])
                               : nullptr;
        check(wifi != nullptr && wifi->data == plain,
              "A5 delivered WifiPacket carries the plain bytes");
        check(wifi != nullptr && wifi->transmitter == *beta_mac &&
                  wifi->destination == *alpha_mac && wifi->channel == 0 &&
                  wifi->type == citra_room::FrameType::Data,
              "A5 delivered WifiPacket carries the mapped MACs, channel 0 and Data type");
        check(after.proxy_frames_consumed == before.proxy_frames_consumed + 1,
              "A5 one inbound Proxy frame consumed");
        check(after.payload_forwarded == before.payload_forwarded + 1,
              "A5 inbound payload counted as forwarded");
    }

    {
        // A room member that no Citra session owns: the frozen transport accepts
        // it (it is a member) and the gateway's own identity check must refuse it.
        room_client::ProxyPacket unnamed = proxy;
        unnamed.local.ip = *gamma_ip;
        unnamed.remote.ip = alpha_identity->fake_ip;
        const std::size_t alpha_baseline = alpha.raw_count();
        const auto before = gateway.counters();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, unnamed);
        const auto after = gateway.counters();
        check(accepted && after.unknown_source_rejections ==
                               before.unknown_source_rejections + 1,
              "A5 a room member with no session identity is refused by the gateway itself");
        check(alpha.raw_count() == alpha_baseline,
              "A5 the identity-less source produced no Citra frame");
    }

    {
        room_client::ProxyPacket echo = proxy;
        echo.local.ip = alpha_identity->fake_ip;
        echo.remote.ip = alpha_identity->fake_ip;
        const auto before = gateway.counters();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, echo);
        const auto after = gateway.counters();
        check(!accepted && after.transport_boundary_rejections ==
                               before.transport_boundary_rejections + 1,
              "A5 a frame whose source is the target itself is refused as a self echo");
    }

    {
        room_client::ProxyPacket stranger = proxy;
        stranger.local.ip = alpha_identity->fake_ip;
        stranger.local.ip[3] = static_cast<std::uint8_t>(alpha_identity->fake_ip[3] ^ 0x40);
        const auto before = gateway.counters();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, stranger);
        const auto after = gateway.counters();
        check(!accepted && after.transport_boundary_rejections ==
                               before.transport_boundary_rejections + 1,
              "A5 a frame from an address that is not a room member is refused");
    }

    {
        room_client::ProxyPacket wrong_destination = proxy;
        wrong_destination.local.ip = beta_identity->fake_ip;
        wrong_destination.remote.ip = beta_identity->fake_ip;
        const auto before = gateway.counters();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, wrong_destination);
        const auto after = gateway.counters();
        check(!accepted && after.transport_boundary_rejections ==
                               before.transport_boundary_rejections + 1,
              "A5 a unicast frame that is not addressed to this client is refused");
    }

    {
        room_client::ProxyPacket malformed = proxy;
        malformed.data = room_client::Bytes{0x00, 0x01, 0x02, 0x03};
        const auto before = gateway.counters();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, malformed);
        const auto after = gateway.counters();
        check(!accepted && after.transport_boundary_rejections ==
                               before.transport_boundary_rejections + 1,
              "A5 an inbound Proxy payload that is not a Zstd frame is refused");
    }

    {
        room_client::ProxyPacket broadcast = proxy;
        broadcast.broadcast = true;
        const std::size_t alpha_baseline = alpha.raw_count();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, broadcast);
        const bool delivered = drive(gateway, {&alpha, &beta},
                                     [&] { return alpha.raw_count() > alpha_baseline; }, 3000);
        check(accepted && delivered, "A5 an inbound broadcast Proxy frame is delivered");
        const auto* wifi = alpha.raw_count() > alpha_baseline
                               ? std::get_if<citra_room::WifiPacket>(&alpha.messages()[alpha_baseline])
                               : nullptr;
        check(wifi != nullptr && wifi->destination == citra_room::broadcast_mac,
              "A5 an inbound broadcast is re-emitted with the Citra broadcast MAC");
    }

    const std::size_t beta_reject_baseline = beta.raw_count();
    const auto dest_before = gateway.counters();
    alpha.send(citra_wifi_bytes(*alpha_mac, *alpha_mac, plain));
    alpha.send(citra_wifi_bytes(citra_room::MacAddress{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                                *beta_mac, plain));
    alpha.send(citra_wifi_bytes(
        *alpha_mac, citra_room::MacAddress{0x00, 0x1F, 0x32, 0x99, 0x99, 0x99}, plain));
    drive(gateway, {&alpha, &beta}, [&] { return false; }, 200);
    const auto dest_after = gateway.counters();
    check(dest_after.self_echo_rejections == dest_before.self_echo_rejections + 1,
          "A5 a Citra payload addressed to its own MAC is refused as a self echo");
    check(dest_after.sentinel_mac_rejections == dest_before.sentinel_mac_rejections + 1,
          "A5 a sentinel transmitter MAC is refused");
    check(dest_after.destination_unmapped_rejections ==
              dest_before.destination_unmapped_rejections + 1,
          "A5 a destination MAC with no session mapping is refused, never broadcast");
    check(dest_after.proxy_frames_emitted == dest_before.proxy_frames_emitted,
          "A5 none of the refused Citra payloads produced a room frame");
    check(beta.raw_count() == beta_reject_baseline,
          "A5 none of the refused Citra payloads reached any client");

    dump_documents(gateway, "a5_fail_closed");
}

// ===========================================================================
// A6: negative tests. Every rejection must leave the state untouched.
// ===========================================================================
void group_a6_negative() {
    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 4);
    citra_gateway::Gateway gateway(gateway_options(gw_port, room));
    gateway.open();

    CitraPeer framing;
    framing.connect(gateway.port());
    const auto join_frame = citra_join_bytes("nega-1", "console-nega", citra_room::no_preferred_mac);
    const auto wifi_frame = citra_wifi_bytes(citra_room::MacAddress{0x00, 0x1F, 0x32, 0x00, 0x00, 0x02},
                                             citra_room::broadcast_mac, synthetic_payload(64, 0x44));
    citra_room::ChatRequest chat;
    chat.message = "synthetic negative test frame";
    const auto chat_frame = citra_room::encode(chat, citra_room::Direction::ClientToServer);

    std::size_t expected_prefixes = 0;
    for (const auto* frame : {&join_frame, &wifi_frame, &chat_frame}) {
        for (std::size_t length = 0; length < frame->size(); ++length) {
            framing.send(citra_room::Bytes(frame->begin(),
                                           frame->begin() + static_cast<std::ptrdiff_t>(length)));
            ++expected_prefixes;
        }
    }
    const auto before_prefix = gateway.counters();
    const bool prefixes_done =
        drive(gateway, {&framing},
              [&] {
                  return gateway.counters().frames_rejected >=
                             before_prefix.frames_rejected + expected_prefixes &&
                         gateway.counters().prefix_truncation_rejections >=
                             before_prefix.prefix_truncation_rejections + expected_prefixes;
              },
              6000);
    const auto after_prefix = gateway.counters();
    check(prefixes_done, "A6 every prefix truncation of every Citra C2S message is rejected");
    check(after_prefix.frames_rejected == before_prefix.frames_rejected + expected_prefixes,
          "A6 the rejected frame count equals the number of prefix truncations");
    check(after_prefix.prefix_truncation_rejections ==
              before_prefix.prefix_truncation_rejections + expected_prefixes,
          "A6 every prefix truncation is classified as a truncated frame");
    note("a6.prefix_truncations", std::to_string(expected_prefixes));
    verify(!framing.peer_closed(), "A6 truncated frames never close the client connection");

    verify(join_peer(gateway, framing, "nega-1", "console-nega"),
           "A6 the connection still joins after the truncation storm");
    verify(wait_room_member(gateway, room, "nega-1", true), "A6 the client is in the room table");

    const auto joined_before = gateway.counters();
    auto joined_frame = join_frame;
    joined_frame.push_back(0x00);
    framing.send(joined_frame);
    framing.send(citra_room::Bytes{0x7F});
    for (std::uint8_t id = 17; id <= 23; ++id) {
        framing.send(citra_room::Bytes{id});
    }
    framing.send(citra_room::Bytes{0x05, 0xFF});
    citra_room::RoomInformation wrong_direction_info;
    wrong_direction_info.member_slots = 4;
    framing.send(citra_room::encode(wrong_direction_info, citra_room::Direction::ServerToClient));
    framing.send(citra_room::encode(citra_room::JoinSuccess{}, citra_room::Direction::ServerToClient));
    framing.send(citra_room::encode(citra_room::StatusMessage{},
                                    citra_room::Direction::ServerToClient));
    framing.send(citra_wifi_bytes(citra_room::MacAddress{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                                  citra_room::broadcast_mac, synthetic_payload(16, 0x55)));
    framing.send(citra_wifi_bytes(*framing.assigned_mac(), *framing.assigned_mac(),
                                  synthetic_payload(16, 0x66)));
    const bool bad_done =
        drive(gateway, {&framing},
              [&] {
                  const auto counters = gateway.counters();
                  return counters.trailing_byte_rejections >=
                             joined_before.trailing_byte_rejections + 1 &&
                         counters.unknown_id_rejections >= joined_before.unknown_id_rejections + 8 &&
                         counters.unknown_enum_rejections >=
                             joined_before.unknown_enum_rejections + 1 &&
                         counters.wrong_direction_rejections >=
                             joined_before.wrong_direction_rejections + 3 &&
                         counters.sentinel_mac_rejections >=
                             joined_before.sentinel_mac_rejections + 1 &&
                         counters.self_echo_rejections >= joined_before.self_echo_rejections + 1;
              },
              6000);
    const auto joined_after = gateway.counters();
    check(bad_done, "A6 every malformed, unknown, unsupported and wrong direction frame is rejected");
    check(joined_after.trailing_byte_rejections == joined_before.trailing_byte_rejections + 1,
          "A6 a frame with trailing bytes is rejected");
    check(joined_after.unknown_id_rejections == joined_before.unknown_id_rejections + 8,
          "A6 unknown and unsupported message ids are rejected (0x7F plus ids 17..23)");
    check(joined_after.unknown_enum_rejections == joined_before.unknown_enum_rejections + 1,
          "A6 an unknown enum value is rejected");
    check(joined_after.wrong_direction_rejections == joined_before.wrong_direction_rejections + 3,
          "A6 server to client frames fed in the client to server direction are rejected");
    check(joined_after.sentinel_mac_rejections == joined_before.sentinel_mac_rejections + 1,
          "A6 a sentinel transmitter MAC is rejected");
    check(joined_after.self_echo_rejections == joined_before.self_echo_rejections + 1,
          "A6 a payload addressed to the sender itself is rejected");
    check(joined_after.clients_joined == joined_before.clients_joined,
          "A6 no rejection changed the joined state of the client");
    check(joined_after.clients_left == joined_before.clients_left,
          "A6 no rejection detached the client from the room");
    check(gateway.is_open() && gateway.client_count() == 1,
          "A6 malformed input never terminates the gateway process or the client");
    check(member_for(room, "nega-1").has_value(), "A6 the room member table is unchanged");

    // V-023: this block used to assert that a 501 byte Citra frame is rejected.
    // That was wrong. The upstream 500 byte constant only truncates chat; the
    // frozen codec's data plane limit is Limits::data_bytes (60000) and its whole
    // frame limit is Limits::packet_bytes (65536). A 501 byte data frame must be
    // relayed byte for byte, so a second peer is required for the relay to happen.
    CitraPeer bulk;
    bulk.connect(gateway.port());
    verify(join_peer(gateway, bulk, "nega-2", "console-nega-2", citra_room::no_preferred_mac,
                     citra_room::network_version, "", {&framing, &bulk}),
           "A6 the bulk payload peer joins");
    verify(wait_room_member(gateway, room, "nega-2", true),
           "A6 the bulk payload peer is in the room table");

    const auto large_before = gateway.counters();
    const auto mid_payload = synthetic_payload(482, 0x77);
    const auto mid_frame =
        citra_wifi_bytes(*framing.assigned_mac(), citra_room::broadcast_mac, mid_payload);
    const auto mid_manual =
        citra_wifi_frame_manual(*framing.assigned_mac(), citra_room::broadcast_mac, mid_payload);
    check(mid_frame.size() == 501, "A6 the first large data frame is 501 bytes");
    check(hex_of(mid_frame) == hex_of(mid_manual),
          "A6 the 501 byte frame equals the hand written golden, not a round trip");
    const std::size_t bulk_before_mid = bulk.raw_count();
    framing.send(mid_frame);
    const bool mid_delivered =
        drive(gateway, {&framing, &bulk}, [&] { return bulk.raw_count() > bulk_before_mid; }, 8000);
    check(mid_delivered, "A6 a 501 byte Citra data frame is accepted and relayed");
    check(bulk.raw_count() == bulk_before_mid + 1 &&
              hex_of(bulk.raw_frames()[bulk_before_mid]) == hex_of(mid_manual),
          "A6 the relayed 501 byte frame is byte identical to the hand written golden");

    const auto large_payload = synthetic_payload(1181, 0x78);
    const auto large_frame =
        citra_wifi_bytes(*framing.assigned_mac(), citra_room::broadcast_mac, large_payload);
    const auto large_manual = citra_wifi_frame_manual(*framing.assigned_mac(),
                                                      citra_room::broadcast_mac, large_payload);
    check(large_frame.size() == 1200, "A6 the second large data frame is 1200 bytes");
    check(hex_of(large_frame) == hex_of(large_manual),
          "A6 the 1200 byte frame equals the hand written golden, not a round trip");
    const std::size_t bulk_before_large = bulk.raw_count();
    framing.send(large_frame);
    const bool large_delivered = drive(
        gateway, {&framing, &bulk}, [&] { return bulk.raw_count() > bulk_before_large; }, 8000);
    check(large_delivered, "A6 a 1200 byte Citra data frame is accepted and relayed");
    check(bulk.raw_count() == bulk_before_large + 1 &&
              hex_of(bulk.raw_frames()[bulk_before_large]) == hex_of(large_manual),
          "A6 the relayed 1200 byte frame is byte identical to the hand written golden");
    const auto large_after = gateway.counters();
    check(large_after.oversize_rejections == large_before.oversize_rejections,
          "A6 no data frame between 501 and 60000 bytes is dropped by a pre decode cap");
    check(large_after.payload_forwarded == large_before.payload_forwarded + 4,
          "A6 both large frames are forwarded in both directions");
    const auto large_captures = gateway.data_plane_captures();
    verify(large_captures.size() >= 2, "A6 the large data plane captures are recorded");
    const auto& large_out = large_captures[large_captures.size() - 2];
    check(large_out.direction == "citra_to_room" &&
              large_out.content_bytes == large_payload.size() &&
              large_out.opaque_bytes == large_payload.size(),
          "A6 the Yuzu side Zstd frame carries the whole 1181 byte payload");
    const std::vector<std::uint8_t> payload_head(large_payload.begin(),
                                                 large_payload.begin() + 512);
    check(large_out.opaque_hex == hex_of(payload_head),
          "A6 the recorded opaque bytes start with the identical payload bytes");
    note("a6.large_frame_sizes", "501,1200");
    note("a6.large_frame_hex_head", hex_of(large_manual).substr(0, 64));
    note("a6.large_frame_hex_tail",
         hex_of(large_manual).substr(hex_of(large_manual).size() - 64));

    // Truly over the frozen codec limits: data above Limits::data_bytes (60000)
    // and a chat body above Limits::chat_bytes (500) must still fail closed.
    const auto limit_before = gateway.counters();
    const std::size_t bulk_before_limit = bulk.raw_count();
    framing.send(citra_wifi_frame_manual(*framing.assigned_mac(), citra_room::broadcast_mac,
                                         synthetic_payload(60001, 0x79)));
    framing.send(citra_chat_frame_manual(std::string(601, 'c')));
    const bool limit_done =
        drive(gateway, {&framing, &bulk},
              [&] {
                  return gateway.counters().limit_exceeded_rejections >=
                         limit_before.limit_exceeded_rejections + 2;
              },
              6000);
    const auto limit_after = gateway.counters();
    check(limit_done, "A6 data over 60000 bytes and a chat body over 500 bytes are rejected");
    check(limit_after.limit_exceeded_rejections == limit_before.limit_exceeded_rejections + 2,
          "A6 both over limit frames are classified as frozen codec limit violations");
    check(bulk.raw_count() == bulk_before_limit, "A6 over limit frames are never forwarded");
    check(limit_after.clients_joined == limit_before.clients_joined &&
              gateway.client_count() == 2 && member_for(room, "nega-1").has_value(),
          "A6 an over limit rejection leaves both sessions and the room table untouched");
    note("a6.limit_exceeded_rejections", std::to_string(limit_after.limit_exceeded_rejections));

    CitraPeer declared;
    declared.connect(gateway.port());
    const auto declared_before = gateway.counters();
    declared.send_prefix_only(70000);
    const bool declared_closed =
        drive(gateway, {&declared}, [&] { return declared.peer_closed(); }, 4000);
    const auto declared_after = gateway.counters();
    check(declared_after.oversize_rejections >= declared_before.oversize_rejections + 1,
          "A6 a declared frame length over the maximum frame size is rejected");
    check(declared_closed, "A6 the oversize framing probe connection is closed explicitly");
    check(gateway.is_open(), "A6 the gateway survives the oversize framing probe");

    dump_documents(gateway, "a6_negative");
}

// ===========================================================================
// A7: release regression. A rejected client must not block the next one.
// ===========================================================================
void group_a7_release() {
    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 1, "local-secret");
        citra_gateway::Gateway gateway(gateway_options(gw_port, room, "local-secret"));
        gateway.open();
        CitraPeer rejected;
        rejected.connect(gateway.port());
        rejected.send(citra_join_bytes("rel-1", "console-rel-1", citra_room::no_preferred_mac,
                                       citra_room::network_version, "incorrect"));
        verify(wait_error_frame(gateway, rejected), "A7 the wrong password client is rejected");
        check(hex_of(rejected.raw_frames()[0]) == "0a",
              "A7 the rejected client observes the mapped room error");

        CitraPeer fresh;
        fresh.connect(gateway.port());
        const auto start = now_ms();
        fresh.send(citra_join_bytes("rel-2", "console-rel-2", citra_room::no_preferred_mac,
                                    citra_room::network_version, "local-secret"));
        const bool joined =
            drive(gateway, {&fresh, &rejected}, [&] { return fresh.raw_count() >= 2; }, 4000);
        const auto elapsed = static_cast<int>(now_ms() - start);
        note("a7.capacity1_password_release_ms", std::to_string(elapsed));
        check(joined, "A7 a fresh client joins immediately after a rejected client");
        check(elapsed <= 1000, "A7 the fresh join completes within the 1000 ms bound");
        check(room_size(room) == 1, "A7 the capacity 1 room holds exactly the fresh client");
        dump_documents(gateway, "a7_password_release");
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 1);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();
        CitraPeer owner;
        owner.connect(gateway.port());
        verify(join_peer(gateway, owner, "rel-1", "console-rel-1"), "A7 the room owner joins");
        CitraPeer refused;
        refused.connect(gateway.port());
        refused.send(citra_join_bytes("rel-2", "console-rel-2", citra_room::no_preferred_mac));
        verify(wait_error_frame(gateway, refused, {&owner, &refused}),
               "A7 the second client is refused by the full room");
        check(hex_of(refused.raw_frames()[0]) == "0c", "A7 the full room error is mapped");
        check(room_size(room) == 1, "A7 the refused client never occupied a slot");

        owner.close_now();
        verify(wait_room_member(gateway, room, "rel-1", false), "A7 the room owner is released");

        CitraPeer next;
        next.connect(gateway.port());
        const auto start = now_ms();
        next.send(citra_join_bytes("rel-3", "console-rel-3", citra_room::no_preferred_mac));
        const bool joined =
            drive(gateway, {&next, &refused}, [&] { return next.raw_count() >= 2; }, 4000);
        const auto elapsed = static_cast<int>(now_ms() - start);
        note("a7.capacity1_reuse_release_ms", std::to_string(elapsed));
        check(joined, "A7 a new client joins immediately after the owner disconnects");
        check(elapsed <= 1000, "A7 the reuse join completes within the 1000 ms bound");
        dump_documents(gateway, "a7_slot_reuse");
    }
}

// ===========================================================================
// A8: isolation and bounded queues on both sides.
// ===========================================================================
void group_a8_isolation() {
    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();

        CitraPeer a;
        a.connect(gateway.port());
        verify(join_peer(gateway, a, "iso-1", "console-iso-1"), "A8 iso-1 joins");
        CitraPeer b;
        b.connect(gateway.port());
        verify(join_peer(gateway, b, "iso-2", "console-iso-2", citra_room::no_preferred_mac,
                         citra_room::network_version, "", {&a, &b}),
               "A8 iso-2 joins");
        CitraPeer c;
        c.connect(gateway.port());
        verify(join_peer(gateway, c, "iso-3", "console-iso-3", citra_room::no_preferred_mac,
                         citra_room::network_version, "", {&a, &b, &c}),
               "A8 iso-3 joins");
        const auto b_mac = b.assigned_mac();
        const auto c_mac = c.assigned_mac();
        verify(b_mac.has_value() && c_mac.has_value(), "A8 both remaining peers hold MACs");

        a.send(citra_room::Bytes{0x7F});
        a.send(citra_room::Bytes{0x03, 0xFF, 0xFF});
        a.close_now();
        const auto left_before = gateway.counters();
        const bool released = drive(gateway, {&b, &c},
                                    [&] {
                                        return gateway.counters().clients_left >=
                                               left_before.clients_left + 1;
                                    },
                                    4000);
        check(released, "A8 the malformed client detaches without affecting the others");
        check(gateway.client_count() == 2, "A8 the other two clients stay connected");

        const auto payload = synthetic_payload(48, 0x19);
        const auto frame = citra_wifi_bytes(*b_mac, *c_mac, payload);
        const std::size_t c_baseline = c.raw_count();
        b.send(frame);
        const bool delivered = drive(gateway, {&b, &c}, [&] {
            return std::find(c.raw_frames().begin() + c_baseline, c.raw_frames().end(), frame) != c.raw_frames().end();
        }, 4000);
        check(delivered, "A8 the surviving clients still exchange payloads");
        check(std::count(c.raw_frames().begin() + c_baseline, c.raw_frames().end(), frame) == 1,
              "A8 the surviving exchange is still byte identical");
        check(room_size(room) == 2, "A8 the room member table holds the two survivors");
        dump_documents(gateway, "a8_isolation");
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 2);
        auto options = gateway_options(gw_port, room);
        options.per_client_inbox_bytes = 64;
        options.per_client_outbox_bytes = 16;
        options.per_client_outbox_frames = 1;
        citra_gateway::Gateway gateway(options);
        gateway.open();

        CitraPeer small;
        small.connect(gateway.port());
        small.send(citra_join_bytes("cap-1", "console-cap-1", citra_room::no_preferred_mac));
        const bool outbox_hit =
            drive(gateway, {&small}, [&] { return gateway.counters().outbox_overflows >= 1; }, 4000);
        check(outbox_hit, "A8 the outbound queue bound is enforced and counted");
        check(gateway.counters().queue_overflows >= 1,
              "A8 an outbound queue overflow is counted as a queue overflow");
        check(gateway.is_open(), "A8 the outbound overflow does not terminate the gateway");

        CitraPeer flood;
        flood.connect(gateway.port());
        flood.send(citra_room::Bytes(1000, 0x00));
        const bool inbox_hit =
            drive(gateway, {&flood}, [&] { return gateway.counters().inbox_overflows >= 1; }, 4000);
        check(inbox_hit, "A8 the inbound queue bound is enforced and counted");
        check(gateway.counters().queue_overflows >= 2,
              "A8 both queue overflow classes are counted");
        check(gateway.is_open(), "A8 the inbound overflow does not terminate the gateway");
        dump_documents(gateway, "a8_bounds");
    }
}

// ===========================================================================
// A10: general acceptance items (loopback only, explicit port conflict,
// no background workers, no leaked ENet hosts).
// ===========================================================================
void group_a10_general() {
    const auto port = take_port();
    const auto unused_room = take_port();
    citra_gateway::Gateway first(gateway_options(port, unused_room));
    first.open();
    check(first.is_open() && first.port() == port, "A10 the gateway listens on the requested port");

    citra_gateway::Gateway second(gateway_options(port, unused_room));
    bool conflicted = false;
    try {
        second.open();
    } catch (const std::exception&) {
        conflicted = true;
    }
    check(conflicted, "A10 a second listener on the same port fails explicitly");
    check(second.counters().port_conflicts == 1, "A10 the port conflict is counted");
    check(first.is_open(), "A10 the first listener is unaffected by the conflict");

    bool non_loopback = false;
    {
        auto options = gateway_options(take_port(), unused_room);
        options.listen_address = "8.8.8.8";
        citra_gateway::Gateway remote(options);
        try {
            remote.open();
        } catch (const std::exception&) {
            non_loopback = true;
        }
    }
    check(non_loopback, "A10 a non loopback listen address is refused");

    bool non_numeric = false;
    {
        auto options = gateway_options(take_port(), unused_room);
        options.listen_address = "localhost";
        citra_gateway::Gateway named(options);
        try {
            named.open();
        } catch (const std::exception&) {
            non_numeric = true;
        }
    }
    check(non_numeric, "A10 a non numeric listen address is refused");

    // The port conflict counter lives on the second gateway, which failed to open.
    dump_documents(first, "a10_general");
    dump_documents(second, "a10_port_conflict");
}

// ===========================================================================
// B1: the G-b' control plane (docs/M4-CONTROL-PLANE.md section 7.2/7.3/7.4).
//     Every byte golden below comes from either a hand written fixture under
//     ../citra-control/fixtures (independent oracle) or a documented structure
//     offset in section 2 of that document.  No golden is produced by our own
//     encoder, and every derivation is recomputed from the report text here.
// ===========================================================================
std::string upper_hex32(std::uint32_t value) {
    static const char* digits = "0123456789ABCDEF";
    std::string out(8, '0');
    for (int i = 7; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = digits[value & 0x0F];
        value >>= 4;
    }
    return out;
}

// The AssociationResponse body stores the network id as eight ASCII hex
// characters (high nibble first), so the byte level golden is the ASCII
// encoding of that text, not the text itself.
std::string ascii_bytes_hex(const std::string& text) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(text.size() * 2);
    for (const char raw : text) {
        const auto byte = static_cast<std::uint8_t>(raw);
        out += digits[byte >> 4];
        out += digits[byte & 0x0F];
    }
    return out;
}

// Independent reimplementation of the documented FNV-1a and lowbias32 steps
// (control.hpp / gateway.cpp).  Deliberately not shared code with the bridge.
std::uint32_t spec_fnv1a32(const std::string& text) {
    std::uint32_t hash = 2166136261u;
    for (const char raw : text) {
        hash ^= static_cast<std::uint8_t>(raw);
        hash *= 16777619u;
    }
    return hash;
}

std::uint32_t spec_lowbias32(std::uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
}

citra_room::Bytes bytes_from_hex(const std::string& hex) {
    verify(hex.size() % 2 == 0, "B1 hex text has an even number of digits");
    citra_room::Bytes out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

// Reads "<name> = <hex groups>" out of a fixtures/*.hex file (comments start #).
std::string fixture_hex(const std::string& path, const std::string& name) {
    std::ifstream in(path, std::ios::binary);
    verify(static_cast<bool>(in), "B1 fixture is readable: " + path);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const auto equals = line.find('=');
        if (equals == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, equals);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) {
            key.pop_back();
        }
        if (key != name) {
            continue;
        }
        std::string out;
        std::istringstream tokens(line.substr(equals + 1));
        std::string token;
        while (tokens >> token) {
            for (const char c : token) {
                if (std::isxdigit(static_cast<unsigned char>(c)) != 0) {
                    out.push_back(c);
                }
            }
        }
        return out;
    }
    return std::string();
}

std::string hex_slice(const std::string& hex, std::size_t offset, std::size_t bytes) {
    const std::size_t begin = offset * 2;
    if (begin + bytes * 2 > hex.size()) {
        return std::string();
    }
    return hex.substr(begin, bytes * 2);
}

std::uint64_t json_counter(const std::string& text, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    const auto at = text.find(needle);
    if (at == std::string::npos) {
        return 0;
    }
    std::size_t index = at + needle.size();
    std::uint64_t value = 0;
    while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
        value = value * 10 + static_cast<std::uint64_t>(text[index] - '0');
        ++index;
    }
    return value;
}

// The bridge counters are aggregated into the "control" object of counters_json.
std::uint64_t control_counter(const citra_gateway::Gateway& gateway, const std::string& key) {
    const std::string text = gateway.counters_json();
    const auto control = text.find("\"control\":{");
    if (control == std::string::npos) {
        return 0;
    }
    return json_counter(text.substr(control), key);
}

std::vector<citra_gateway::EmittedFrame> emitted_of_kind(const citra_gateway::Gateway& gateway,
                                                         const std::string& kind) {
    std::vector<citra_gateway::EmittedFrame> out;
    for (const auto& frame : gateway.emitted_frames()) {
        if (frame.kind == kind) {
            out.push_back(frame);
        }
    }
    return out;
}

// Section 7.4 asks the run to export the emitted byte sequence in hex.  B1
// clears the gateway log between steps to isolate each event, so the harness
// archives every emission before each clear and writes the archive as
// <tag>.emitted.json (same object shape as Gateway::emitted_json()).
std::vector<citra_gateway::EmittedFrame> g_emitted_archive;

void archive_emitted(const citra_gateway::Gateway& gateway) {
    for (const auto& frame : gateway.emitted_frames()) {
        g_emitted_archive.push_back(frame);
    }
}

void write_emitted_archive(const std::string& tag) {
    std::string text = "[\n";
    for (std::size_t i = 0; i < g_emitted_archive.size(); ++i) {
        const auto& frame = g_emitted_archive[i];
        if (i != 0) {
            text += ",\n";
        }
        text += " {\"seq\":" + std::to_string(frame.seq) +
                ",\"time_ms\":" + std::to_string(frame.time_ms) +
                ",\"client_id\":" + std::to_string(frame.client_id) +
                ",\"direction\":\"" + frame.direction + "\",\"kind\":\"" + frame.kind +
                "\",\"bytes\":" + std::to_string(frame.bytes) + ",\"hex\":\"" + frame.hex + "\"}";
    }
    text += "\n]\n";
    const std::string path = g_evidence_dir + "/" + tag + ".emitted.json";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        check(false, "B1 emitted byte sequence exported: " + path);
        return;
    }
    out << text;
    check(true, "B1 emitted byte sequence exported: " + path + " (" +
                    std::to_string(g_emitted_archive.size()) + " frames)");
}

std::uint8_t frame_type_byte(citra_room::FrameType type) {
    return static_cast<std::uint8_t>(type);
}

std::uint8_t ldn_type_byte(room_client::LdnType type) {
    return static_cast<std::uint8_t>(type);
}

void group_b1_control() {
    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 4);
    citra_gateway::Options options = gateway_options(gw_port, room);
    options.control_plane_enabled = true;
    citra_gateway::Gateway gateway(options);
    gateway.open();
    g_emitted_archive.clear();

    CitraPeer alpha;
    alpha.connect(gw_port);
    verify(join_peer(gateway, alpha, "alpha-1", "console-alpha"), "B1 alpha joins through the gateway");
    const std::uint64_t alpha_id = client_id_for(gateway, "alpha-1");
    verify(alpha_id != 0, "B1 alpha appears in the client table");
    const auto alpha_mac = alpha.assigned_mac();
    verify(alpha_mac.has_value(), "B1 alpha received an assigned MAC");
    const std::string alpha_mac_hex = hex_of(*alpha_mac);

    // Documented deterministic derivations, recomputed here from the report.
    const std::string room_name = "G-b-loopback";
    const std::uint32_t seed = spec_fnv1a32(room_name + ":" + std::to_string(room_port));
    const std::uint32_t bssid_hash =
        spec_fnv1a32("citra-gateway-bssid:" + room_name + ":" + std::to_string(seed));
    const std::array<std::uint8_t, 6> bssid{
        0x02, 0x00, static_cast<std::uint8_t>((bssid_hash >> 24) & 0xFF),
        static_cast<std::uint8_t>((bssid_hash >> 16) & 0xFF),
        static_cast<std::uint8_t>((bssid_hash >> 8) & 0xFF),
        static_cast<std::uint8_t>(bssid_hash & 0xFF)};
    const std::string bssid_hex = hex_of(bssid);
    const std::uint32_t network_id = spec_lowbias32(seed ^ 0x55445331u);

    const auto beacons = [&] {
        std::vector<citra_room::WifiPacket> out;
        for (const auto& message : alpha.messages()) {
            if (const auto* wifi = std::get_if<citra_room::WifiPacket>(&message)) {
                if (wifi->type == citra_room::FrameType::Beacon) {
                    out.push_back(*wifi);
                }
            }
        }
        return out;
    };
    const auto has_type = [&](citra_room::FrameType type) {
        for (const auto& message : alpha.messages()) {
            if (const auto* wifi = std::get_if<citra_room::WifiPacket>(&message)) {
                if (wifi->type == type) {
                    return true;
                }
            }
        }
        return false;
    };
    const auto receive_hex = [&](citra_room::FrameType type) {
        std::string out;
        for (const auto& message : alpha.messages()) {
            if (const auto* wifi = std::get_if<citra_room::WifiPacket>(&message)) {
                if (wifi->type == type) {
                    out = hex_of(wifi->data);
                }
            }
        }
        return out;
    };

    // --- section 7.2 event 11: the beacon against the D1 layout rules ------
    // crossplay/citra-control/fixtures/beacon_n1.hex is a frozen one-node
    // artifact.  D1/R6 reject any beacon whose record count differs from
    // max_nodes, so it is now the NEGATIVE control: parse_beacon_frame must
    // refuse it with Err::BadLength and the beacon_max_nodes_too_small event.
    // (parse_beacon_frame lives in uds_frames.cpp, which this harness already
    // links as control_uds; guard_beacon_layout lives in translate.cpp, which
    // build.ps1 does not link -- see the G4.2 conflict in the report.)
    const std::string fixture_beacon =
        fixture_hex("../citra-control/fixtures/beacon_n1.hex", "frame");
    verify(fixture_beacon.size() == 139 * 2,
           "B1 the legacy beacon fixture is 139 bytes (one node, no appdata)");
    {
        const citra_room::Bytes legacy = bytes_from_hex(fixture_beacon);
        citra_control::Diag legacy_diag;
        const auto refused =
            citra_control::parse_beacon_frame(legacy.data(), legacy.size(), bssid, &legacy_diag);
        check(!refused.ok() && refused.err == citra_control::Err::BadLength,
              "B1 the legacy one-node beacon fixture is refused with Err::BadLength");
        bool small_event = false;
        for (const std::string& line : legacy_diag.log.lines) {
            if (line.find("beacon_max_nodes_too_small") != std::string::npos) {
                small_event = true;
            }
        }
        check(small_event, "B1 the legacy beacon fixture raises beacon_max_nodes_too_small");
    }
    check(drive(gateway, {&alpha}, [&] { return beacons().size() >= 1; }, 2000),
          "B1 the control plane emits a beacon right after the join");
    const auto first_beacons = beacons();
    check(!first_beacons.empty(), "B1 a first beacon was captured for the layout assertions");
    const citra_room::Bytes first_beacon =
        first_beacons.empty() ? citra_room::Bytes{} : first_beacons[0].data;
    const std::string beacon_hex = hex_of(first_beacon);
    // No LDN station has joined yet, so connected == 1 and the advertised
    // capacity is the single kControlBeaconCapacity constant.
    const std::size_t beacon_connected = 1;
    const std::size_t beacon_capacity =
        std::max<std::size_t>(citra_gateway::kControlBeaconCapacity, beacon_connected);
    check(first_beacon.size() == 171 + 40 * (beacon_capacity - 2),
          "B1 the emitted beacon is 171 + 40 * (capacity - 2) bytes (251 at capacity 4)");
    {
        citra_control::Diag beacon_diag;
        const auto parsed = citra_control::parse_beacon_frame(first_beacon.data(), first_beacon.size(),
                                                              bssid, &beacon_diag);
        check(parsed.ok(), "B1 the emitted beacon parses back through parse_beacon_frame");
        if (parsed.ok()) {
            check(parsed.value.network_info.max_nodes == beacon_capacity,
                  "B1 the parsed beacon declares max_nodes == the advertised capacity");
            check(parsed.value.network_info.total_nodes == beacon_connected,
                  "B1 the parsed beacon declares total_nodes == the connected count (1)");
            check(parsed.value.nodes.size() == beacon_capacity,
                  "B1 the parsed beacon carries exactly capacity node records");
            bool records_ok = parsed.value.nodes.size() == beacon_capacity;
            if (!parsed.value.nodes.empty()) {
                records_ok = records_ok && parsed.value.nodes[0].network_node_id == 1;
                for (std::size_t i = 1; i < parsed.value.nodes.size(); ++i) {
                    if (parsed.value.nodes[i].friend_code_seed != 0 ||
                        parsed.value.nodes[i].network_node_id != 0) {
                        records_ok = false;
                    }
                }
            }
            check(records_ok, "B1 beacon record 0 is the host at UDS node 1 and the spare slots are empty");
        }
    }
    check(drive(gateway, {&alpha}, [&] { return beacons().size() >= 2; }, 3000),
          "B1 a second beacon arrives on the 200 ms control interval");
    const auto beacon_list = beacons();
    check(beacon_list.size() >= 2, "B1 two beacons were observed by the Citra client");
    bool beacon_tx_stable = beacon_list.size() >= 2;
    for (std::size_t i = 1; i < beacon_list.size(); ++i) {
        if (beacon_list[i].transmitter != beacon_list[0].transmitter) {
            beacon_tx_stable = false;
        }
    }
    check(beacon_tx_stable, "B1 the beacon transmitter MAC is stable across beacons");
    const bool beacon_bssid_ok = !beacon_list.empty() && beacon_list[0].transmitter == bssid;
    check(beacon_bssid_ok, "B1 the beacon transmitter equals the documented room derived BSSID");
    check(control_counter(gateway, "beacon_emitted") >= 2,
          "B1 beacon_emitted counts both the lifecycle beacon and the periodic one");
    check(control_counter(gateway, "beacon_skipped") == 0,
          "B1 no beacon is skipped while the AP is idle");
    check(control_counter(gateway, "ap_created") == 1 && control_counter(gateway, "ap_rejected") == 0,
          "B1 the AP lifecycle reached Created exactly once");

    // --- section 7.2 event 7: Authentication SEQ1 fold (V-016k) ------------
    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    const citra_room::Bytes auth_refused_body{0x00, 0x00, 0x01, 0x00, 0x01, 0x00};
    gateway.inject_citra_frame_for_test(
        alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, auth_refused_body,
                                          frame_type_byte(citra_room::FrameType::Authentication)));
    check(control_counter(gateway, "auth_refused") == 1,
          "B1 a refused Authentication is counted as refused");
    check(gateway.emitted_frames().empty(),
          "B1 a refused Authentication never produces an AssociationResponse (V-016k)");

    const citra_room::Bytes auth_short{0x00, 0x00, 0x01, 0x00, 0x00};
    gateway.inject_citra_frame_for_test(
        alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, auth_short,
                                          frame_type_byte(citra_room::FrameType::Authentication)));
    check(control_counter(gateway, "auth_rejected") == 1,
          "B1 a five byte Authentication frame is rejected by the exact length gate");
    check(gateway.emitted_frames().empty(), "B1 a rejected Authentication emits no frame");

    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    const citra_room::Bytes auth_seq1{0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    auto wrong_control_mac = *alpha_mac;
    wrong_control_mac[5] ^= 0x40;
    const citra_room::MacAddress zero_control_mac{};
    for (const auto& source : {wrong_control_mac, zero_control_mac}) {
        const auto before = gateway.counters();
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(source, citra_room::broadcast_mac, auth_seq1,
                                              frame_type_byte(citra_room::FrameType::Authentication)));
        check(gateway.counters().payload_rejected_source == before.payload_rejected_source + 1 &&
                  control_counter(gateway, "auth_seq1_accepted") == 0 && gateway.emitted_frames().empty(),
              "B1 invalid-source Authentication cannot mutate state or emit responses");
    }
    gateway.inject_citra_frame_for_test(
        alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, auth_seq1,
                                          frame_type_byte(citra_room::FrameType::Authentication)));
    // V-262: the inbound census must describe the Citra wire without a packet
    // capture -- per frame type counts plus bounded raw samples.
    {
        const std::string inbound = gateway.inbound_json();
        check(inbound.rfind("{\"by_type\":{", 0) == 0 &&
                  inbound.find("\"Authentication\":") != std::string::npos,
              "V-262 inbound.json counts inbound frames by frame type");
        check(inbound.find("\"samples\":{") != std::string::npos &&
                  inbound.find("\"transmitter\":\"") != std::string::npos &&
                  inbound.find("\"data_hex\":\"") != std::string::npos,
              "V-262 inbound.json keeps a raw sample per frame type");
    }
    std::string auth_seq2_hex;
    std::string assoc_hex;
    bool auth_side_ok = !gateway.emitted_frames().empty();
    for (const auto& frame : gateway.emitted_frames()) {
        if (frame.kind == "citra.auth_seq2") {
            auth_seq2_hex = frame.hex;
        } else if (frame.kind == "citra.assoc_response") {
            assoc_hex = frame.hex;
        } else {
            auth_side_ok = false;
        }
        if (frame.direction != "citra") {
            auth_side_ok = false;
        }
    }
    check(auth_seq2_hex == "000002000000",
          "B1 the Authentication SEQ2 golden is exactly 00 00 02 00 00 00");
    check(assoc_hex == std::string("3104000001c00008") + ascii_bytes_hex(upper_hex32(network_id)),
          "B1 the AssociationResponse golden matches the documented layout and derived network id");
    check(auth_side_ok, "B1 the SEQ1 fold emits only Citra side control frames");
    check(control_counter(gateway, "auth_seq1_accepted") == 1 &&
              control_counter(gateway, "auth_seq2_emitted") == 1 &&
              control_counter(gateway, "assoc_response_emitted") == 1,
          "B1 the SEQ1 fold emitted one SEQ2 and one AssociationResponse");
    check(drive(gateway,
                {&alpha},
                [&] {
                    return has_type(citra_room::FrameType::Authentication) &&
                           has_type(citra_room::FrameType::AssociationResponse);
                },
                2000),
          "B1 the Citra client receives the SEQ2 and AssociationResponse frames");
    check(receive_hex(citra_room::FrameType::Authentication) == auth_seq2_hex &&
              receive_hex(citra_room::FrameType::AssociationResponse) == assoc_hex,
          "B1 the received Citra frames are byte identical to the emitted control frames");

    // --- section 7.2 event 10: UDS data before and after the EAPoL fold ---
    // Independent wire fixture: protocol size 15, SecureData size 11,
    // channel 33, sequence 300, broadcast destination, assigned source 2.
    citra_room::Bytes secure_data = bytes_from_hex(
        "aaaa03000000876d000f0000000b0021012cffff000211");
    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    gateway.inject_citra_frame_for_test(
        alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, secure_data,
                                          frame_type_byte(citra_room::FrameType::Data)));
    check(control_counter(gateway, "citra_data_not_connected") == 1,
          "B1 a UDS data frame before the fold is counted as not connected and dropped");
    check(gateway.emitted_frames().empty() && gateway.counters().proxy_frames_emitted == 0,
          "B1 a UDS data frame before the fold is not forwarded");

    // --- section 7.2 event 8: the EAPoL-Start fold, against fixtures -------
    const std::string eapol_fixture =
        fixture_hex("../citra-control/fixtures/uds_eapol_start.hex", "frame");
    check(eapol_fixture.size() == 0x38 * 2, "B1 the EAPoL-Start oracle fixture is 0x38 bytes");
    const citra_room::Bytes eapol_start = bytes_from_hex(eapol_fixture);
    for (const auto& source : {wrong_control_mac, zero_control_mac}) {
        const auto before = gateway.counters();
        const auto emitted = gateway.emitted_frames().size();
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(source, citra_room::broadcast_mac, eapol_start,
                                              frame_type_byte(citra_room::FrameType::Data)));
        check(gateway.counters().payload_rejected_source == before.payload_rejected_source + 1 &&
                  control_counter(gateway, "eapol_start_accepted") == 0 &&
                  gateway.emitted_frames().size() == emitted,
              "B1 invalid-source EAPoL cannot complete association or emit member updates");
    }
    const citra_room::Bytes eapol_truncated(eapol_start.begin(), eapol_start.begin() + 16);
    gateway.inject_citra_frame_for_test(
        alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, eapol_truncated,
                                          frame_type_byte(citra_room::FrameType::Data)));
    check(control_counter(gateway, "eapol_rejected") == 1,
          "B1 a truncated EAPoL-Start is rejected by the exact length gate");

    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    gateway.inject_citra_frame_for_test(
        alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, eapol_start,
                                          frame_type_byte(citra_room::FrameType::Data)));
    std::string node_map_hex;
    std::string logoff_hex;
    for (const auto& frame : gateway.emitted_frames()) {
        if (frame.kind == "citra.node_map") {
            node_map_hex = frame.hex;
        } else if (frame.kind == "citra.eapol_logoff") {
            logoff_hex = frame.hex;
        }
    }
    // N6/D3: this fixture declares network_node_id = 2, exactly the value the
    // old code copied from the wire, which is why it masked the defect -- the
    // spec oracle below declares 0 and must give the same assigned id.
    const std::string eapol_start_hex = hex_of(eapol_start);
    for (const auto& source : {wrong_control_mac, zero_control_mac}) {
        const auto before = gateway.counters();
        const auto emitted = gateway.emitted_frames().size();
        const auto accepted = control_counter(gateway, "deauth_accepted");
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(source, citra_room::broadcast_mac, {},
                                              frame_type_byte(citra_room::FrameType::Deauthentication)));
        check(gateway.counters().payload_rejected_source == before.payload_rejected_source + 1 &&
                  control_counter(gateway, "deauth_accepted") == accepted &&
                  gateway.emitted_frames().size() == emitted,
              "B1 invalid-source Deauthentication cannot remove the joined identity");
    }
    check(hex_slice(eapol_start_hex, 48, 2) == "0002",
          "B1 the EAPoL-Start fixture declares network node id 2 (the old, masking case)");
    check(node_map_hex == std::string("0100000000000000") + alpha_mac_hex + "0200",
          "B1 the broadcast NodeMap golden is count 1 plus the session MAC and the assigned peer id 2");
    check(logoff_hex.size() == 0x2A0 * 2, "B1 the EAPoL-Logoff frame is exactly 0x2A0 bytes");
    check(hex_slice(logoff_hex, 0, 8) == "aaaa03000000888e" && hex_slice(logoff_hex, 8, 2) == "0202" &&
              hex_slice(logoff_hex, 10, 2) == "0000" && hex_slice(logoff_hex, 12, 2) == "0002",
          "B1 the EAPoL-Logoff assigned node id 0x0002 is derived, not copied from the Start");
    check(hex_slice(logoff_hex, 14, 6) == "000000000000" &&
              hex_slice(logoff_hex, 20, 6) == "000000000000" && hex_slice(logoff_hex, 26, 1) == "02" &&
              hex_slice(logoff_hex, 27, 1) == "04",
          "B1 the EAPoL-Logoff client MAC is all zero, two nodes connected and a 4 node capacity");
    check(hex_slice(logoff_hex, 64, 2) == "0001" && hex_slice(logoff_hex, 104, 2) == "0002" &&
              hex_slice(logoff_hex, 144, 2) == "0000" && hex_slice(logoff_hex, 184, 2) == "0000",
          "B1 the EAPoL-Logoff records are host 1, peer 2, then the empty slots 0 and 0");
    check(hex_slice(logoff_hex, 72, 8) == hex_slice(eapol_start_hex, 16, 8) &&
              hex_slice(logoff_hex, 80, 20) == hex_slice(eapol_start_hex, 24, 20),
          "B1 the EAPoL-Logoff record 1 echoes the injected Start seed and username");
    check(control_counter(gateway, "eapol_start_accepted") == 1 &&
              control_counter(gateway, "node_map_emitted") == 1 &&
              control_counter(gateway, "logoff_frame_emitted") == 1,
          "B1 the EAPoL-Start fold emitted the NodeMap and the Logoff exactly once");

    // N6/D3 strong case: the real host oracle (spec section 0.1) declares an
    // uninitialised network_node_id = 0, so a copied id would be wrong.  Fold it
    // through a private bridge (the gateway's own plane is already Connected and
    // would refuse a second Start) and prove the ids and records come from the
    // N1 table, not from the wire.
    {
        const std::string oracle_start_hex =
            "aaaa03000000888e0201000100010000" "7b330000165bf81d"
            "0043004900540052004100000000000000000000" "00000000" "0000" "000000000000";
        verify(oracle_start_hex.size() == 0x38 * 2, "B1 the spec oracle EAPoL-Start is 0x38 bytes");
        check(hex_slice(oracle_start_hex, 48, 2) == "0000",
              "B1 the spec oracle EAPoL-Start declares the uninitialised node id 0");
        const citra_room::Bytes oracle_start = bytes_from_hex(oracle_start_hex);
        citra_gateway::ControlOptions oracle_options;
        oracle_options.room_name = room_name;
        oracle_options.room_seed = seed;
        oracle_options.scene_id = 0;
        citra_gateway::ControlBridge oracle_bridge(oracle_options, room_client::IPv4{10, 83, 0, 200},
                                                   *alpha_mac);
        const auto oracle_beacons = oracle_bridge.start();
        check(!oracle_beacons.empty(), "B1 the private control bridge emits its first beacon");
        // Fidelity guard (gc7): the periodic emission rate must equal the
        // interval the Beacon frame advertizes (citra_control's default 100 ms).
        // The gateway declared 100 ms and emitted every 200 ms, so the second
        // beacon that lists a joining client arrived after its ~285 ms
        // association deadline.
        std::uint16_t advertized_interval = 0;
        if (!oracle_beacons.empty() && oracle_beacons[0].citra_data.size() >= 10) {
            advertized_interval = static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(oracle_beacons[0].citra_data[8]) |
                static_cast<std::uint16_t>(static_cast<std::uint16_t>(oracle_beacons[0].citra_data[9]) << 8));
        }
        check(advertized_interval == oracle_options.beacon_interval_ms &&
                  oracle_options.beacon_interval_ms == citra_control::kDefaultBeaconInterval,
              "B1 the gateway emits beacons at the interval its own Beacon frame advertizes");
        const citra_room::Bytes oracle_auth{0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        citra_room::WifiPacket oracle_auth_wifi;
        oracle_auth_wifi.type = citra_room::FrameType::Authentication;
        oracle_auth_wifi.channel = 6;
        oracle_auth_wifi.transmitter = *alpha_mac;
        oracle_auth_wifi.destination = citra_room::broadcast_mac;
        oracle_auth_wifi.data = oracle_auth;
        oracle_bridge.on_citra_wifi(oracle_auth_wifi, 0);
        // D6: periodic advertising must not consume an in-flight association.
        oracle_bridge.tick(100);
        const auto associating_beacons = oracle_bridge.tick(100 + oracle_options.beacon_interval_ms);
        check(associating_beacons.size() == 1 && associating_beacons[0].kind == "citra.beacon",
              "D6 a periodic beacon is emitted while waiting for EAPoL-Start");
        const auto oracle_folded = oracle_bridge.on_citra_eapol(oracle_start, 0);
        std::string oracle_node_map_hex;
        std::string oracle_logoff_hex;
        for (const auto& frame : oracle_folded) {
            if (frame.kind == "citra.node_map") {
                oracle_node_map_hex = hex_of(frame.citra_data);
            } else if (frame.kind == "citra.eapol_logoff") {
                oracle_logoff_hex = hex_of(frame.citra_data);
            }
        }
        check(oracle_node_map_hex == std::string("0100000000000000") + alpha_mac_hex + "0200",
              "B1 the id 0 oracle Start yields the same count 1 NodeMap with assigned peer id 2");
        check(oracle_logoff_hex.size() == 0x2A0 * 2,
              "B1 the id 0 oracle Start yields a 0x2A0 EAPoL-Logoff");
        check(hex_slice(oracle_logoff_hex, 12, 2) == "0002" &&
                  hex_slice(oracle_logoff_hex, 14, 6) == "000000000000" &&
                  hex_slice(oracle_logoff_hex, 26, 1) == "02" && hex_slice(oracle_logoff_hex, 27, 1) == "04",
              "B1 the id 0 Logoff carries assigned 2, a zero client MAC, connected 2 and max 4");
        check(hex_slice(oracle_logoff_hex, 64, 2) == "0001" && hex_slice(oracle_logoff_hex, 104, 2) == "0002" &&
                  hex_slice(oracle_logoff_hex, 144, 2) == "0000" && hex_slice(oracle_logoff_hex, 184, 2) == "0000",
              "B1 the id 0 Logoff records are host 1, peer 2, then the empty slots 0 and 0");
        check(hex_slice(oracle_start_hex, 16, 8) == "7b330000165bf81d" &&
                  hex_slice(oracle_start_hex, 24, 20) ==
                      "0043" "0049" "0054" "0052" "0041" "0000" "0000" "0000" "0000" "0000",
              "B1 the spec oracle Start carries the CITRA seed and username");
        check(hex_slice(oracle_logoff_hex, 72, 8) == "7b330000165bf81d" &&
                  hex_slice(oracle_logoff_hex, 80, 20) ==
                      "0043" "0049" "0054" "0052" "0041" "0000" "0000" "0000" "0000" "0000",
              "B1 the id 0 Logoff record 1 echoes the oracle seed and the CITRA username");
        for (std::uint64_t tick = 2; tick <= 4; ++tick) {
            const auto periodic = oracle_bridge.tick(100 + tick * oracle_options.beacon_interval_ms);
            check(periodic.size() == 1 && periodic[0].kind == "citra.beacon",
                  "D6 periodic beacons continue after the client joins without extra handshake frames");
            if (periodic.size() == 1) {
                const auto parsed_beacon = citra_control::parse_beacon_frame(
                    periodic[0].citra_data.data(), periodic[0].citra_data.size(),
                    oracle_bridge.bssid());
                check(parsed_beacon.ok() && parsed_beacon.value.network_info.total_nodes == 2 &&
                          parsed_beacon.value.nodes.size() >= 2 &&
                          parsed_beacon.value.nodes[1].network_node_id == 2,
                      "D6 joined-client beacons retain valid node records and connected count");
            }
        }
        check(oracle_bridge.counters().at("eapol_start_accepted") == 1 &&
                  oracle_bridge.counters().at("auth_seq1_accepted") == 1 &&
                  oracle_bridge.on_citra_secure_data(),
              "D6 beacon ticks preserve the completed association and data admission");
        auto deauth = oracle_auth_wifi;
        deauth.type = citra_room::FrameType::Deauthentication;
        deauth.data = {1};
        oracle_bridge.on_citra_wifi(deauth, 0);
        check(oracle_bridge.counters().at("deauth_rejected") == 1 &&
                  oracle_bridge.on_citra_secure_data(),
              "D7 malformed deauthentication preserves the existing association");
        deauth.data.clear();
        oracle_bridge.on_citra_wifi(deauth, 0);
        check(oracle_bridge.counters().at("deauth_accepted") == 1 &&
                  !oracle_bridge.on_citra_secure_data(),
              "D7 accepted deauthentication closes data admission");
        const auto after_deauth = oracle_bridge.tick(100 + 5 * oracle_options.beacon_interval_ms);
        bool peer_cleared = false;
        if (after_deauth.size() == 1) {
            const auto beacon = citra_control::parse_beacon_frame(
                after_deauth[0].citra_data.data(), after_deauth[0].citra_data.size(), oracle_bridge.bssid());
            peer_cleared = beacon.ok() && beacon.value.network_info.total_nodes == 1 &&
                           beacon.value.nodes.size() >= 2 &&
                           beacon.value.nodes[1].network_node_id == 0 &&
                           beacon.value.nodes[1].friend_code_seed == 0 &&
                           beacon.value.nodes[1].username == citra_control::Username{};
        }
        check(peer_cleared, "D7 periodic beacons clear the departed peer id, seed and name");
        auto new_start = oracle_start;
        new_start[16] = 0x42;
        std::fill_n(new_start.begin() + 24, 20, 0);
        new_start[25] = 'N';
        oracle_bridge.on_citra_wifi(oracle_auth_wifi, 0);
        const auto rejoined = oracle_bridge.on_citra_eapol(new_start, 0);
        bool fresh_identity = false;
        for (const auto& emission : rejoined) {
            if (emission.kind == "citra.eapol_logoff") {
                const auto logoff = citra_control::parse_eapol_logoff_frame(
                    emission.citra_data.data(), emission.citra_data.size());
                fresh_identity = logoff.ok() && logoff.value.nodes[1].username[0] == 'N' &&
                                 logoff.value.nodes[1].username[1] == 0 &&
                                 (logoff.value.nodes[1].friend_code_seed >> 56) == 0x42;
            }
        }
        check(fresh_identity && oracle_bridge.on_citra_secure_data(),
              "D7 rejoining uses the new Start identity and restores data admission");
    }

    // V-129/gc7 fidelity fix: the AssociationResponse SSID tag carries the same
    // network id the Beacon advertizes.  With the mhxx UDS profile the beacon
    // says network_id 0, so the assoc SSID must be ASCII "00000000" -- exactly
    // what a real MHXX host sends -- instead of the derived id.
    {
        citra_gateway::ControlOptions prof_options;
        prof_options.room_name = room_name;
        prof_options.room_seed = seed;
        prof_options.have_uds_network_id = true;
        prof_options.uds_network_id = 0;
        citra_gateway::ControlBridge prof_bridge(prof_options, room_client::IPv4{10, 83, 0, 200}, *alpha_mac);
        const auto prof_beacons = prof_bridge.start();
        bool beacon_netid_is_zero = false;
        if (!prof_beacons.empty() && !prof_beacons[0].citra_data.empty()) {
            const auto parsed = citra_control::parse_beacon_frame(
                prof_beacons[0].citra_data.data(), prof_beacons[0].citra_data.size(), prof_bridge.bssid());
            beacon_netid_is_zero = parsed.ok() && parsed.value.network_info.network_id == 0;
        }
        check(beacon_netid_is_zero, "B1 the profiled beacon advertizes the profile network id 0");
        citra_room::WifiPacket prof_auth_wifi;
        prof_auth_wifi.type = citra_room::FrameType::Authentication;
        prof_auth_wifi.channel = 6;
        prof_auth_wifi.transmitter = *alpha_mac;
        prof_auth_wifi.destination = citra_room::broadcast_mac;
        prof_auth_wifi.data = citra_room::Bytes{0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        std::string prof_assoc_hex;
        for (const auto& frame : prof_bridge.on_citra_wifi(prof_auth_wifi, 0)) {
            if (frame.kind == "citra.assoc_response") {
                prof_assoc_hex = hex_of(frame.citra_data);
            }
        }
        check(prof_assoc_hex == std::string("3104000001c00008") +
                                    ascii_bytes_hex(upper_hex32(std::uint32_t{0})),
              "B1 a profile network id of 0 puts that same id in the AssociationResponse SSID");
    }

    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    for (const std::uint16_t source : {0u, 1u, 3u, 65535u}) {
        auto invalid = secure_data;
        invalid[20] = static_cast<std::uint8_t>(source >> 8);
        invalid[21] = static_cast<std::uint8_t>(source);
        const auto before = gateway.counters();
        const auto accepted = control_counter(gateway, "citra_data_accepted");
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, invalid,
                                              frame_type_byte(citra_room::FrameType::Data)));
        check(gateway.counters().payload_rejected_source == before.payload_rejected_source + 1 &&
                  gateway.counters().proxy_frames_emitted == before.proxy_frames_emitted &&
                  control_counter(gateway, "citra_data_accepted") == accepted &&
                  gateway.emitted_frames().empty(),
              "B1 a foreign SecureData source cannot pass the associated guest identity gate");
    }
    auto truncated_secure = secure_data;
    truncated_secure.resize(16);
    auto bad_secure_length = secure_data;
    bad_secure_length[9] = 0x10;
    auto management_secure = secure_data;
    management_secure[14] = 1;
    for (const auto& invalid : {truncated_secure, bad_secure_length, management_secure}) {
        const auto before = gateway.counters();
        const auto accepted = control_counter(gateway, "citra_data_accepted");
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, invalid,
                                              frame_type_byte(citra_room::FrameType::Data)));
        check(gateway.counters().payload_rejected_boundary == before.payload_rejected_boundary + 1 &&
                  gateway.counters().proxy_frames_emitted == before.proxy_frames_emitted &&
                  control_counter(gateway, "citra_data_accepted") == accepted &&
                  gateway.emitted_frames().empty(),
              "B1 malformed SecureData cannot advance acceptance or emit a proxy");
    }
    gateway.inject_citra_frame_for_test(
        alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, secure_data,
                                          frame_type_byte(citra_room::FrameType::Data)));
    check(control_counter(gateway, "citra_data_accepted") == 1,
          "B1 a UDS data frame after the fold is accepted by the control plane");
    check(control_counter(gateway, "citra_data_not_connected") == 1,
          "B1 only the pre-fold UDS data frame was counted as not connected");
    check(gateway.counters().proxy_frames_emitted == 1,
          "B1 the accepted UDS data frame continues along the opaque G-b proxy path");

    const citra_room::Bytes inbound_beacon{0x00};
    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    gateway.inject_citra_frame_for_test(
        alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, inbound_beacon,
                                          frame_type_byte(citra_room::FrameType::Beacon)));
    check(control_counter(gateway, "citra_wrong_direction") == 1 && gateway.emitted_frames().empty(),
          "B1 an inbound Beacon is a direction error that emits nothing");

    // --- section 7.2 events 1-6: Yuzu LDN bodies --------------------------
    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    room_client::LdnPacket bad_length;
    bad_length.type = room_client::LdnType::Scan;
    bad_length.local_ip = room_client::IPv4{10, 83, 0, 7};
    bad_length.data = citra_room::Bytes{0x00};
    verify(gateway.inject_ldn_message_for_test(alpha_id, bad_length),
           "B1 a Yuzu LDN packet is injectable through the gateway");
    check(control_counter(gateway, "ldn_bad_length") == 1,
          "B1 a one byte Scan body fails the exact length gate");

    room_client::LdnPacket scan_response_in;
    scan_response_in.type = room_client::LdnType::ScanResponse;
    scan_response_in.local_ip = room_client::IPv4{10, 83, 0, 7};
    scan_response_in.data.assign(0x480, 0x00);
    gateway.inject_ldn_message_for_test(alpha_id, scan_response_in);
    check(control_counter(gateway, "ldn_direction_rejected") == 1,
          "B1 an inbound ScanResponse is a direction error");

    room_client::LdnPacket zero_source;
    zero_source.type = room_client::LdnType::Scan;
    zero_source.local_ip = room_client::IPv4{};
    gateway.inject_ldn_message_for_test(alpha_id, zero_source);
    check(control_counter(gateway, "ldn_bad_source") == 1, "B1 a Scan from 0.0.0.0 is rejected");

    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    room_client::LdnPacket scan;
    scan.type = room_client::LdnType::Scan;
    scan.local_ip = room_client::IPv4{10, 83, 0, 7};
    gateway.inject_ldn_message_for_test(alpha_id, scan);
    const auto scan_out = emitted_of_kind(gateway, "room.scan_resp");
    check(scan_out.size() == 1 && scan_out[0].direction == "room" && scan_out[0].bytes == 0x480,
          "B1 a Yuzu Scan produces exactly one unicast ScanResponse of 0x480 bytes");

    std::string gateway_fake_ip;
    for (const auto& snapshot : gateway.clients()) {
        if (snapshot.id == alpha_id) {
            gateway_fake_ip = snapshot.fake_ip;
        }
    }
    verify(!gateway_fake_ip.empty(), "B1 the gateway session has an assigned fake IPv4");
    std::array<std::uint8_t, 4> fake{};
    {
        std::istringstream parts(gateway_fake_ip);
        std::string part;
        int index = 0;
        while (index < 4 && std::getline(parts, part, '.')) {
            fake[static_cast<std::size_t>(index)] = static_cast<std::uint8_t>(std::stoi(part));
            ++index;
        }
        verify(index == 4, "B1 the gateway fake IPv4 has four octets");
    }
    const std::array<std::uint8_t, 4> fake_reversed{fake[3], fake[2], fake[1], fake[0]};
    const std::string scan_hex = scan_out.empty() ? std::string() : scan_out[0].hex;
    check(hex_slice(scan_hex, 0x20, 6) == bssid_hex,
          "B1 the ScanResponse common network info carries the room derived BSSID");
    check(hex_slice(scan_hex, 0x26, 1) == "0c" &&
              hex_slice(scan_hex, 0x27, 12) == "472d622d6c6f6f706261636b",
          "B1 the ScanResponse SSID equals the room name (length 12, ASCII)");
    check(hex_slice(scan_hex, 0x48, 2) == "0600" && hex_slice(scan_hex, 0x4A, 1) == "03" &&
              hex_slice(scan_hex, 0x4B, 1) == "02",
          "B1 the ScanResponse channel, link level and network type match the declared constants");
    // V-239: node_count_max presents the measured MHGU hub capacity (4, from
    // g2-run2 real AP frames) instead of the frozen LDN max of 8; the bridge
    // synthesizes an empty hall, so node_count stays 1.
    check(hex_slice(scan_hex, 0x66, 1) == "04" && hex_slice(scan_hex, 0x67, 1) == "01",
          "B1 the ScanResponse declares node_count_max 4 (measured MHGU capacity) and node_count 1");
    // V-239: the bridge host carries a non-empty hunter name on node 0.
    check(hex_slice(scan_hex, 0x74, 5) == "416c696365",
          "B1 ScanResponse node[0] advertises the host name Alice");
    check(hex_slice(scan_hex, 0x68, 4) == hex_of(fake_reversed) &&
              hex_slice(scan_hex, 0x6C, 6) == bssid_hex && hex_slice(scan_hex, 0x72, 1) == "00" &&
              hex_slice(scan_hex, 0x73, 1) == "01",
          "B1 ScanResponse node[0] is the host with the byte reversed gateway fake IPv4 (V-016p)");
    // V-239: advertise data stays zero in this no-option harness run; the
    // --ldn-advertise-hex path is exercised manually against real traces.
    check(hex_slice(scan_hex, 0x26A, 2) == "0000",
          "B1 the ScanResponse advertise data size is zero without CLI input");
    check(control_counter(gateway, "ldn_scan_accepted") == 1 &&
              control_counter(gateway, "scan_resp_emitted") == 1,
          "B1 the accepted Scan incremented the LDN and synthesis counters");

    const std::string node_info_hex =
        fixture_hex("../citra-control/fixtures/ldn_node_info.hex", "node_info");
    check(node_info_hex.size() == 0x40 * 2, "B1 the LdnNodeInfo oracle fixture is 0x40 bytes");
    const citra_room::Bytes node_info = bytes_from_hex(node_info_hex);

    // D4 station metadata: wire fixtures are independent of the bridge's encoder.
    {
        citra_gateway::ControlOptions metadata_options;
        citra_gateway::ControlBridge metadata_bridge(metadata_options, {10, 83, 0, 200}, *alpha_mac);
        citra_gateway::ControlBridge mirror(metadata_options, {10, 83, 0, 201}, *alpha_mac);
        metadata_bridge.start();
        mirror.start();
        room_client::LdnPacket request;
        request.type = room_client::LdnType::Connect;
        request.local_ip = {10, 83, 0, 1};
        request.data = node_info;
        request.data[0x2e] = 0x34;
        request.data[0x2f] = 0x12;
        const auto joined = metadata_bridge.on_ldn(request, {});
        check(joined.accepted && metadata_bridge.station_count() == 1,
              "D4 a representable station name is admitted");
        bool source_preserved = false;
        for (const auto& emission : joined.emissions) {
            if (emission.kind == "room.sync_network") {
                const auto wire = hex_of(emission.ldn_body);
                source_preserved = hex_slice(wire, 0xb4, 33) == hex_slice(node_info_hex, 12, 33) &&
                                   hex_slice(wire, 0xd6, 2) == "3412";
            }
        }
        check(source_preserved, "D4 SyncNetwork preserves source name bytes and nondefault version");
        citra_control::UserNameBytes source_name{};
        std::copy_n(node_info.begin() + 12, source_name.size(), source_name.begin());
        mirror.mirror_connect(request.local_ip, {2, 0, 0, 0, 0, 1},
                              {10, 83, 0, 1}, true, source_name, 0x1234);
        check(mirror.station_count() == 1 && mirror.stations()[0].user_name == source_name &&
                  mirror.stations()[0].local_communication_version == 0x1234,
              "D4 mirrored stations keep the same source name and version");
        const citra_control::Username expected_name{'P', 'L', 'A', 'Y', 'E', 'R', '1'};
        for (auto* bridge : {&metadata_bridge, &mirror}) {
            bridge->tick(100);
            const auto periodic = bridge->tick(100 + metadata_options.beacon_interval_ms);
            bool name_preserved = false;
            if (periodic.size() == 1) {
                const auto beacon = citra_control::parse_beacon_frame(
                    periodic[0].citra_data.data(), periodic[0].citra_data.size(), bridge->bssid());
                name_preserved = beacon.ok() && beacon.value.nodes.size() >= 3 &&
                                 beacon.value.nodes[2].username == expected_name &&
                                 beacon.value.nodes[2].friend_code_seed == 0;
            }
            check(name_preserved, "D4 owner and mirror UDS beacons preserve the mapped station name");
        }
        auto invalid = request;
        invalid.local_ip = {10, 83, 0, 2};
        std::fill_n(invalid.data.begin() + 12, 11, 'X');
        invalid.data[23] = 0;
        const auto refused = metadata_bridge.on_ldn(invalid, {});
        check(!refused.accepted && refused.emissions.empty() && metadata_bridge.station_count() == 1,
              "D4 an overlong name is refused before any session change");
        citra_control::UserNameBytes invalid_name{};
        invalid_name[0] = 0xc3;
        mirror.mirror_connect(invalid.local_ip, {2, 0, 0, 0, 0, 2}, {}, false, invalid_name);
        check(mirror.station_count() == 1,
              "D4 an unsupported mirrored name cannot mutate station membership");
        citra_room::WifiPacket metadata_auth;
        metadata_auth.type = citra_room::FrameType::Authentication;
        metadata_auth.transmitter = *alpha_mac;
        metadata_auth.data = {0, 0, 1, 0, 0, 0};
        metadata_bridge.on_citra_wifi(metadata_auth, 0);
        const auto folded = metadata_bridge.on_citra_eapol(eapol_start, 0);
        bool logoff_name_preserved = false;
        for (const auto& emission : folded) {
            if (emission.kind == "citra.eapol_logoff") {
                const auto logoff = citra_control::parse_eapol_logoff_frame(
                    emission.citra_data.data(), emission.citra_data.size());
                logoff_name_preserved = logoff.ok() &&
                                       logoff.value.nodes[2].username == expected_name &&
                                       logoff.value.nodes[2].friend_code_seed == 0;
            }
        }
        check(logoff_name_preserved, "D4 EAPoL-Logoff and Beacon share the mapped station name");
        metadata_bridge.mirror_disconnect(request.local_ip);
        request.data[12] = 'N';
        request.data[13] = 0;
        check(metadata_bridge.on_ldn(request, {}).accepted &&
                  metadata_bridge.stations()[0].uds_username[0] == 'N' &&
                  metadata_bridge.stations()[0].uds_username[1] == 0,
              "D4 rejoining a freed slot does not reuse the previous station name");
    }

    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    room_client::LdnPacket connect;
    connect.type = room_client::LdnType::Connect;
    connect.local_ip = room_client::IPv4{10, 83, 0, 1};
    connect.data = node_info;
    gateway.inject_ldn_message_for_test(alpha_id, connect);
    const auto sync_out = emitted_of_kind(gateway, "room.sync_network");
    check(sync_out.size() == 1 && sync_out[0].direction == "room" && sync_out[0].bytes == 0x480,
          "B1 a Yuzu Connect produces exactly one SyncNetwork of 0x480 bytes");
    const std::string sync_hex = sync_out.empty() ? std::string() : sync_out[0].hex;
    check(hex_slice(sync_hex, 0x67, 1) == "02",
          "B1 the SyncNetwork node count is 2 after the first station");
    check(hex_slice(sync_hex, 0xA8, 4) == "0a530001" && hex_slice(sync_hex, 0xAC, 6) == "020000000001" &&
              hex_slice(sync_hex, 0xB2, 1) == "01" && hex_slice(sync_hex, 0xB3, 1) == "01",
          "B1 SyncNetwork node[1] carries the station IPv4 and MAC from the independent fixture");
    check(control_counter(gateway, "ldn_connect_accepted") == 1 &&
              control_counter(gateway, "sync_network_emitted") == 1,
          "B1 the accepted Connect incremented the LDN and synthesis counters");

    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    gateway.inject_ldn_message_for_test(alpha_id, connect);
    check(control_counter(gateway, "ldn_connect_rejected") == 1 && gateway.emitted_frames().empty(),
          "B1 a repeated Connect from the same fake IPv4 is rejected");

    room_client::LdnPacket disconnect_unknown;
    disconnect_unknown.type = room_client::LdnType::Disconnect;
    disconnect_unknown.local_ip = room_client::IPv4{10, 83, 0, 9};
    disconnect_unknown.data = node_info;
    gateway.inject_ldn_message_for_test(alpha_id, disconnect_unknown);
    check(control_counter(gateway, "ldn_unknown_source") == 1,
          "B1 a Disconnect from an unknown fake IPv4 is rejected");

    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    room_client::LdnPacket disconnect;
    disconnect.type = room_client::LdnType::Disconnect;
    disconnect.local_ip = room_client::IPv4{10, 83, 0, 1};
    disconnect.data = node_info;
    gateway.inject_ldn_message_for_test(alpha_id, disconnect);
    check(control_counter(gateway, "ldn_disconnect_accepted") == 1 && gateway.emitted_frames().empty(),
          "B1 the accepted Disconnect empties the station table without a broadcast");

    // --- section 7.1 ownership: only the lowest joined id owns the plane ---
    CitraPeer beta;
    beta.connect(gw_port);
    verify(join_peer(gateway, beta, "beta-1", "console-beta", citra_room::no_preferred_mac,
                     citra_room::network_version, std::string(), {&alpha, &beta}),
           "B1 a second Citra client joins through the gateway");
    const std::uint64_t beta_id = client_id_for(gateway, "beta-1");
    verify(beta_id != 0 && beta_id != alpha_id, "B1 the second client has its own client id");
    const std::uint64_t scan_accepted_before = control_counter(gateway, "ldn_scan_accepted");
    gateway.inject_ldn_message_for_test(beta_id, scan);
    check(control_counter(gateway, "ldn_non_owner_ignored") == 1,
          "B1 an LDN packet from a non owner session is ignored and counted");
    check(control_counter(gateway, "ldn_scan_accepted") == scan_accepted_before,
          "B1 a non owner LDN packet never reaches the control plane");

    // Native stations occupy nodes[node_id], including holes after departures.
    auto second_connect = connect;
    second_connect.local_ip = room_client::IPv4{10, 83, 0, 2};
    second_connect.data[9] = 2; // independently distinct station MAC
    gateway.inject_ldn_message_for_test(alpha_id, connect);
    gateway.inject_ldn_message_for_test(alpha_id, second_connect);
    gateway.inject_ldn_message_for_test(alpha_id, disconnect);
    gateway.clear_emitted_for_test();
    gateway.inject_ldn_message_for_test(alpha_id, scan);
    auto hole_frames = emitted_of_kind(gateway, "room.scan_resp");
    verify(hole_frames.size() == 1, "B1 sparse station table still emits one ScanResponse");
    const auto hole_hex = hole_frames[0].hex;
    check(hex_slice(hole_hex, 0x67, 1) == "02",
          "B1 sparse table count is connected players rather than highest occupied slot");
    check(hex_slice(hole_hex, 0xB3, 1) == "00" &&
              hex_slice(hole_hex, 0xEC, 6) == "020000000002" &&
              hex_slice(hole_hex, 0xF2, 2) == "0201",
          "B1 departing node 1 leaves node 2 connected in native slot 2");
    gateway.clear_emitted_for_test();
    gateway.inject_ldn_message_for_test(alpha_id, connect);
    auto rejoined_frames = emitted_of_kind(gateway, "room.sync_network");
    verify(!rejoined_frames.empty(), "B1 rejoin emits SyncNetwork to connected stations");
    const auto rejoined_hex = rejoined_frames[0].hex;
    check(hex_slice(rejoined_hex, 0x67, 1) == "03" &&
              hex_slice(rejoined_hex, 0xAC, 6) == "020000000001" &&
              hex_slice(rejoined_hex, 0xB2, 2) == "0101" &&
              hex_slice(rejoined_hex, 0xEC, 6) == "020000000002" &&
              hex_slice(rejoined_hex, 0xF2, 2) == "0201",
          "B1 rejoin reuses free node 1 without moving or renumbering node 2");

    archive_emitted(gateway);
    gateway.clear_emitted_for_test();
    room_client::LdnPacket destroy;
    destroy.type = room_client::LdnType::DestroyNetwork;
    destroy.local_ip = room_client::IPv4{10, 83, 0, 1};
    gateway.inject_ldn_message_for_test(alpha_id, destroy);
    check(control_counter(gateway, "ldn_destroy_accepted") == 1 && gateway.emitted_frames().empty(),
          "B1 DestroyNetwork clears the station table and emits nothing (the host left)");

    bool only_declared = true;
    for (const auto& frame : g_emitted_archive) {
        const bool citra_ok =
            frame.direction == "citra" &&
            (frame.kind == "citra.beacon" || frame.kind == "citra.auth_seq2" ||
             frame.kind == "citra.assoc_response" || frame.kind == "citra.node_map" ||
             frame.kind == "citra.eapol_logoff");
        const bool room_ok =
            frame.direction == "room" &&
            (frame.kind == "room.scan_resp" || frame.kind == "room.sync_network");
        if (!citra_ok && !room_ok) {
            only_declared = false;
        }
    }
    check(only_declared, "B1 every emission is a declared section 7.2 control frame on its own side");
    check(control_counter(gateway, "invented_fields") > 0 &&
              control_counter(gateway, "undefined_fields") > 0,
          "B1 unmapped fields are counted instead of silently invented (section 5.4)");
    check(control_counter(gateway, "outbox_invalid") == 0 && control_counter(gateway, "emit_failed") == 0,
          "B1 the control plane outbox validator never rejected an emission");

    note("b1.beacon_fixture_bytes", std::to_string(fixture_beacon.size() / 2));
    note("b1.beacon_hex_head", beacon_hex.substr(0, 62));
    note("b1.assoc_response", assoc_hex);
    note("b1.node_map", node_map_hex);
    note("b1.logoff_bytes", std::to_string(logoff_hex.size() / 2));
    note("b1.scan_resp_bytes", std::to_string(scan_hex.size() / 2));
    note("b1.sync_network_bytes", std::to_string(sync_hex.size() / 2));
    note("b1.bssid", bssid_hex);
    note("b1.network_id", upper_hex32(network_id));
    note("b1.beacon_transmitter", hex_of(beacon_list.empty() ? bssid : beacon_list[0].transmitter));
    note("b1.emitted_frames", std::to_string(g_emitted_archive.size()));
    dump_documents(gateway, "b1_control");
    write_emitted_archive("b1_control");
}

// ===========================================================================
// B2: the same control plane over a real in process room relay.  Section 7.4
// forbids substituting the injection helpers for real timing evidence, so the
// three control exchanges below are driven through ENet and timed.
// ===========================================================================
bool pump_room_pair(citra_gateway::Gateway& gateway, RawRoomPeer& peer,
                    const std::function<bool()>& done, int bound_ms = 2000) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(bound_ms);
    for (;;) {
        gateway.tick(0);
        peer.pump(1);
        if (done()) {
            return true;
        }
        if (Clock::now() >= deadline) {
            return false;
        }
        ::Sleep(1);
    }
}

const room_client::Bytes* find_ldn_frame(const RawRoomPeer& peer, std::uint8_t type,
                                         std::size_t body_bytes) {
    for (const auto& frame : peer.raw_frames()) {
        // IdLdnPacket wire: id(1) type(1) local(4) remote(4) broadcast(1) u32 length(4) body.
        if (frame.size() < 15) {
            continue;
        }
        const std::uint32_t declared = (static_cast<std::uint32_t>(frame[11]) << 24) |
                                       (static_cast<std::uint32_t>(frame[12]) << 16) |
                                       (static_cast<std::uint32_t>(frame[13]) << 8) |
                                       static_cast<std::uint32_t>(frame[14]);
        if (frame.size() == 15 + body_bytes && declared == body_bytes && frame[0] == 0x06 &&
            frame[1] == type) {
            return &frame;
        }
    }
    return nullptr;
}

void group_b2_control_loopback() {
    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 4);
    citra_gateway::Options options = gateway_options(gw_port, room);
    options.control_plane_enabled = true;
    citra_gateway::Gateway gateway(options);
    gateway.open();

    RawRoomPeer yuzu(room_port, "yuzu-1", room_client::network_version);
    const auto yuzu_ip = wait_assigned_ip(yuzu);
    verify(yuzu_ip.has_value(), "B2 the raw Yuzu peer joined the room");

    CitraPeer alpha;
    alpha.connect(gw_port);
    const std::uint64_t beacon_t0 = now_ms();
    verify(join_peer(gateway, alpha, "alpha-1", "console-alpha"),
           "B2 alpha joins through the gateway");
    const bool beacon_arrived = drive(gateway, {&alpha}, [&] { return alpha.wifi_frames() >= 1; }, 2000);
    const std::uint64_t beacon_ms = now_ms() - beacon_t0;
    check(beacon_arrived, "B2 the beacon reaches the Citra client over the real loopback");
    check(beacon_ms <= 1000, "B2 the beacon arrives inside the Yuzu one second scan window");
    note("b2.beacon_ms", std::to_string(beacon_ms));

    room_client::LdnPacket scan;
    scan.type = room_client::LdnType::Scan;
    scan.local_ip = *yuzu_ip;
    scan.remote_ip = room_client::IPv4{};
    scan.broadcast = true;
    const std::uint64_t scan_t0 = now_ms();
    yuzu.send(scan);
    const bool scan_arrived = pump_room_pair(
        gateway, yuzu,
        [&] {
            return find_ldn_frame(yuzu, ldn_type_byte(room_client::LdnType::ScanResponse), 0x480) !=
                   nullptr;
        },
        2000);
    const std::uint64_t scan_ms = now_ms() - scan_t0;
    check(scan_arrived, "B2 the ScanResponse reaches the Yuzu peer through the room relay");
    check(scan_ms <= 1000, "B2 the ScanResponse arrives inside the Yuzu Scan wait window");
    note("b2.scan_resp_ms", std::to_string(scan_ms));
    const room_client::Bytes* scan_raw =
        find_ldn_frame(yuzu, ldn_type_byte(room_client::LdnType::ScanResponse), 0x480);
    check(scan_raw != nullptr && (*scan_raw)[0] == 0x06 && (*scan_raw)[10] == 0x00 &&
              std::equal(yuzu_ip->begin(), yuzu_ip->end(), scan_raw->begin() + 6),
          "B2 the ScanResponse raw frame is a genuine unicast IdLdnPacket for the peer");

    const std::string node_info_hex =
        fixture_hex("../citra-control/fixtures/ldn_node_info.hex", "node_info");
    room_client::LdnPacket connect;
    connect.type = room_client::LdnType::Connect;
    connect.local_ip = *yuzu_ip;
    connect.remote_ip = room_client::IPv4{};
    connect.broadcast = true;
    connect.data = bytes_from_hex(node_info_hex);
    const std::uint64_t sync_t0 = now_ms();
    yuzu.send(connect);
    const bool sync_arrived = pump_room_pair(
        gateway, yuzu,
        [&] {
            return find_ldn_frame(yuzu, ldn_type_byte(room_client::LdnType::SyncNetwork), 0x480) !=
                   nullptr;
        },
        2000);
    const std::uint64_t sync_ms = now_ms() - sync_t0;
    check(sync_arrived, "B2 the SyncNetwork reaches the Yuzu peer through the room relay");
    check(sync_ms <= 1000, "B2 the SyncNetwork arrives promptly after the Connect");
    note("b2.sync_network_ms", std::to_string(sync_ms));
    const room_client::Bytes* sync_raw =
        find_ldn_frame(yuzu, ldn_type_byte(room_client::LdnType::SyncNetwork), 0x480);
    check(sync_raw != nullptr && (*sync_raw)[0] == 0x06 && (*sync_raw)[10] == 0x00 &&
              (*sync_raw)[15 + 0x67] == 0x02 &&
              std::equal(yuzu_ip->begin(), yuzu_ip->end(), sync_raw->begin() + 6),
          "B2 the SyncNetwork raw frame is a genuine unicast IdLdnPacket with node count 2");
    dump_documents(gateway, "b2_control_loopback");
}

// ===========================================================================
// B3 (G-c / V-027): the Citra-side deliverable transport is ENet/UDP.
// A real ENet peer performs a v4 join over UDP with bare citra_room v4
// messages and the hand written A2/A3 goldens; the TCP + 4 byte length prefix
// listener stays reachable through the harness-only Options flag and is
// labelled as a test transport, never as the delivery path.
// ===========================================================================
citra_gateway::Options enet_gateway_options(std::uint16_t listen_port, RoomGuard& room,
                                           const std::string& password = std::string()) {
    citra_gateway::Options options = gateway_options(listen_port, room, password);
    options.citra_tcp_test_transport = false;  // the deliverable transport
    return options;
}

void group_b3_citra_enet() {
    // --- the default (deliverable) Citra transport is an ENet/UDP host ------
    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(enet_gateway_options(gw_port, room));
        gateway.open();
        check(gateway.counters_json().find("\"citra_transport\":\"enet\"") != std::string::npos,
              "B3 the gateway reports the Citra side as ENet/UDP");
        check(gateway.counters().citra_tcp_accepts == 0,
              "B3 opening the gateway accepts no TCP connection");

        // A Citra version 3 client must still receive the hand written A2
        // golden over the new wire, byte for byte.
        EnetCitraPeer wrong(gateway.port());
        verify(connect_enet_peer(gateway, wrong), "B3 the ENet/UDP peer completes the handshake");
        wrong.send(
            citra_join_bytes("b3-zeta", "console-b3-zeta", citra_room::no_preferred_mac, 3, ""));
        // The rejection must reach the peer before the gateway tears the peer down:
        // the gateway waits until ENet has no reliable data in flight (or the close
        // grace elapses) before it disconnects, otherwise the final v4 message is
        // dropped inside enet_peer_disconnect_now.
        verify(until_enet(gateway, {&wrong}, [&] { return wrong.raw_count() >= 1; }),
               "B3 the version rejection arrives over ENet/UDP");
        check(hex_of(wrong.raw_frames()[0]) == "0900000004",
              "B3 Citra version mismatch over ENet is exactly 09 00000004");
        check(wrong.raw_frames()[0].size() == 5,
              "B3 the rejection is a bare 5 byte message, not a length prefixed frame");
        check(gateway.counters().local_version_rejections == 1,
              "B3 the ENet version rejection is counted once");
        check(room_size(room) == 0, "B3 the rejected ENet client never reaches the room table");
        dump_documents(gateway, "b3_citra_enet_version");
    }

    // --- a real ENet/UDP v4 client joins, and errors keep their goldens -----
    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(enet_gateway_options(gw_port, room));
        gateway.open();

        EnetCitraPeer alpha(gateway.port());
        verify(connect_enet_peer(gateway, alpha), "B3 the accepted ENet client connects over UDP");
        alpha.send(citra_join_bytes("b3-alpha", "console-b3-alpha", citra_room::no_preferred_mac));
        verify(until_enet(gateway, {&alpha}, [&] { return alpha.raw_count() >= 2; }),
               "B3 a real ENet/UDP v4 client joins through the gateway");
        check(alpha.raw_frames()[0][0] == 0x03 && alpha.raw_frames()[1][0] == 0x02,
              "B3 RoomInformation precedes JoinSuccess on the ENet wire");
        check(alpha.raw_frames()[1].size() == 7 && alpha.every_frame_decodes(),
              "B3 JoinSuccess is a bare 7 byte message (id + MAC), so no length prefix is in use");
        const auto room_info_message =
            citra_room::decode(alpha.raw_frames()[0], citra_room::Direction::ServerToClient);
        check(citra_room::encode(room_info_message, citra_room::Direction::ServerToClient) ==
                  alpha.raw_frames()[0],
              "B3 the RoomInformation on the ENet wire round-trips byte for byte");
        verify(wait_room_member(gateway, room, "b3-alpha", true),
               "B3 the ENet client appears in the original room member table");
        check(gateway.counters().citra_enet_connects >= 1,
              "B3 at least one ENet connection was recorded");
        check(gateway.counters().citra_enet_receives >= 1,
              "B3 the join request was received as an ENet packet");
        check(gateway.counters().citra_tcp_accepts == 0,
              "B3 the accepted session never touched the TCP listener");
        bool any_enet = false;
        bool any_tcp = false;
        for (const auto& snapshot : gateway.clients()) {
            any_enet = any_enet || snapshot.transport == "enet";
            any_tcp = any_tcp || snapshot.transport == "tcp";
        }
        check(any_enet && !any_tcp, "B3 every live Citra session is reported as ENet/UDP");

        // A duplicate nickname must still produce the hand written NameCollision
        // golden (07): the wire changed, the protocol did not.
        EnetCitraPeer twin(gateway.port());
        verify(connect_enet_peer(gateway, twin), "B3 the second ENet client connects over UDP");
        twin.send(citra_join_bytes("b3-alpha", "console-b3-twin", citra_room::no_preferred_mac));
        verify(until_enet(gateway, {&alpha, &twin}, [&] { return twin.raw_count() >= 1; }),
               "B3 the name collision reaches the second ENet client");
        check(hex_of(twin.raw_frames()[0]) == "07",
              "B3 nickname collision over ENet is still exactly the golden 07");
        check(gateway.counters().local_name_collision_rejections == 1,
              "B3 the name collision was rejected locally");

        // The old TCP framing must NOT be the delivery path: a length prefixed
        // join arrives as one malformed message and never reaches the room.
        EnetCitraPeer prefixed_peer(gateway.port());
        verify(connect_enet_peer(gateway, prefixed_peer), "B3 the prefixed probe connects over UDP");
        const auto join =
            citra_join_bytes("b3-prefixed", "console-b3-prefixed", citra_room::no_preferred_mac);
        citra_room::Bytes prefixed;
        prefixed.push_back(static_cast<std::uint8_t>((join.size() >> 24) & 0xFF));
        prefixed.push_back(static_cast<std::uint8_t>((join.size() >> 16) & 0xFF));
        prefixed.push_back(static_cast<std::uint8_t>((join.size() >> 8) & 0xFF));
        prefixed.push_back(static_cast<std::uint8_t>(join.size() & 0xFF));
        prefixed.insert(prefixed.end(), join.begin(), join.end());
        prefixed_peer.send(prefixed);
        verify(until_enet(gateway, {&alpha, &twin, &prefixed_peer},
                          [&] { return !gateway.counters().decode_error_codes.empty(); }),
               "B3 the length prefixed probe is read as a citra frame");
        check(prefixed_peer.raw_count() == 0 && room_size(room) == 1,
              "B3 a TCP length prefixed join is rejected instead of being unframed");
        check(prefixed_peer.every_frame_decodes(),
              "B3 the gateway answered the prefixed probe with well formed v4 messages only");

        // A second ENet host on the same UDP port must fail loudly.
        citra_gateway::Gateway conflicting(enet_gateway_options(gw_port, room));
        bool threw = false;
        try {
            conflicting.open();
        } catch (const std::exception&) {
            threw = true;
        }
        check(threw, "B3 a second ENet/UDP bind on the same port fails loudly");
        check(conflicting.counters().port_conflicts == 1,
              "B3 the ENet port conflict is counted once with no silent fallback");
        // Export the failed opener's counters so the build script can re-check
        // the conflict count from machine readable evidence.
        dump_documents(conflicting, "b3_citra_enet_portconflict");

        const citra_room::Bytes room_info_head(alpha.raw_frames()[0].begin(),
                                               alpha.raw_frames()[0].begin() + 6);
        note("b3.join_success_hex", hex_of(alpha.raw_frames()[1]));
        note("b3.room_info_hex_head", hex_of(room_info_head));
        note("b3.room_info_bytes", std::to_string(alpha.raw_frames()[0].size()));
        note("b3.enet_connects", std::to_string(gateway.counters().citra_enet_connects));
        note("b3.enet_receives", std::to_string(gateway.counters().citra_enet_receives));
        note("b3.tcp_accepts", std::to_string(gateway.counters().citra_tcp_accepts));
        dump_documents(gateway, "b3_citra_enet");
    }

    // --- the wrong password golden survives the ENet wire as well ----------
    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4, "local-secret");
        citra_gateway::Gateway gateway(enet_gateway_options(gw_port, room, "local-secret"));
        gateway.open();
        EnetCitraPeer peer(gateway.port());
        verify(connect_enet_peer(gateway, peer), "B3 the password probe connects over ENet");
        peer.send(citra_join_bytes("b3-alpha", "console-b3-alpha", citra_room::no_preferred_mac,
                                   citra_room::network_version, "wrong-one"));
        verify(until_enet(gateway, {&peer}, [&] { return peer.raw_count() >= 1; }),
               "B3 the wrong password rejection arrives over ENet");
        check(hex_of(peer.raw_frames()[0]) == "0a",
              "B3 wrong password over ENet is still exactly the golden 0a");
        check(gateway.counters().local_wrong_password_rejections == 1,
              "B3 the wrong password was rejected locally");
        dump_documents(gateway, "b3_citra_enet_password");
    }

    // --- the TCP length prefix listener is harness only and labelled --------
    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();
        check(gateway.counters_json().find("\"citra_transport\":\"tcp-test\"") !=
                  std::string::npos,
              "B3 the harness TCP transport reports itself as tcp-test");
        CitraPeer peer;
        peer.connect(gateway.port());
        verify(join_peer(gateway, peer, "b3-tcp", "console-b3-tcp"),
               "B3 the harness TCP client still joins");
        check(gateway.counters().citra_tcp_accepts == 1,
              "B3 the harness TCP listener records exactly one accept");
        bool any_tcp = false;
        for (const auto& snapshot : gateway.clients()) {
            any_tcp = any_tcp || snapshot.transport == "tcp";
        }
        check(any_tcp, "B3 the harness TCP session is labelled tcp, not enet");
        check(gateway.counters().citra_enet_connects == 0,
              "B3 the harness TCP session records no ENet connection");
        dump_documents(gateway, "b3_citra_enet_tcp");
    }
}

// ---------------------------------------------------------------------------
// B4 (V-028 feedback): the departed-session ledger and the v4 SetGameInfo
// translation.  Both address real-client defects reported against V-027.
// ---------------------------------------------------------------------------

// citra-master room_member.cpp SendGameInfo: the client-only SetGameInfo
// message carries a u32 length prefixed name and a u64 id (protocol.cpp:397).
citra_room::Bytes citra_set_game_info_bytes(const std::string& name, std::uint64_t id) {
    citra_room::Bytes frame;
    frame.push_back(static_cast<std::uint8_t>(citra_room::MessageId::SetGameInfo));
    const auto size = static_cast<std::uint32_t>(name.size());
    for (unsigned i = 4; i-- > 0;) {
        frame.push_back(static_cast<std::uint8_t>(size >> (i * 8)));
    }
    frame.insert(frame.end(), name.begin(), name.end());
    for (unsigned i = 8; i-- > 0;) {
        frame.push_back(static_cast<std::uint8_t>(id >> (i * 8)));
    }
    return frame;
}

void group_b5_early_game_info() {
    RoomGuard room(take_port(), 4);
    auto options = gateway_options(take_port(), room);
    citra_gateway::Gateway gateway(options);
    gateway.open();
    CitraPeer alpha;
    alpha.connect(gateway.port());
    alpha.send(citra_set_game_info_bytes("before-join", 9));
    verify(drive(gateway, {&alpha}, [&] {
        return gateway.counters().set_game_info_rejected == 1;
    }), "B5 game info before JoinRequest is still rejected");
    alpha.send(citra_join_bytes("b5-alpha", "console-b5-alpha", citra_room::no_preferred_mac,
                                citra_room::network_version, ""));
    alpha.send(citra_set_game_info_bytes("early-old", 0x1111));
    alpha.send(citra_set_game_info_bytes("early-latest", 0x2222));
    alpha.send(citra_set_game_info_bytes(std::string("bad\0name", 8), 0x3333));
    verify(drive(gateway, {&alpha}, [&] {
        const auto member = member_for(room, "b5-alpha");
        return member && member->game.name == "early-latest";
    }), "B5 early game metadata survives the asynchronous upstream join");
    check(gateway.counters().set_game_info_deferred == 2 &&
              gateway.counters().set_game_info_replaced == 1,
          "B5 one bounded pending slot retains the latest valid update");
    const auto member = member_for(room, "b5-alpha");
    check(member && member->game.id == 0x2222 && member->game.version == "gw-v1",
          "B5 mapped name/id remain exact and absent version stays explicit placeholder");
    check(gateway.counters().set_game_info_accepted == 1 &&
              gateway.counters().set_game_info_version_placeholder == 1 &&
              gateway.counters().set_game_info_rejected == 2,
          "B5 invalid pending update does not evict the valid value or count as forwarded");

    CitraPeer beta;
    beta.connect(gateway.port());
    beta.send(citra_join_bytes("b5-beta", "console-b5-beta", citra_room::no_preferred_mac,
                               citra_room::network_version, ""));
    beta.send(citra_set_game_info_bytes("beta-early", 0x4444));
    verify(drive(gateway, {&alpha, &beta}, [&] {
        const auto value = member_for(room, "b5-beta");
        return value && value->game.name == "beta-early";
    }), "B5 the second pending update targets its own upstream peer");
    const auto still_alpha = member_for(room, "b5-alpha");
    check(still_alpha && still_alpha->game.name == "early-latest" &&
              still_alpha->game.id == 0x2222,
          "B5 concurrent session metadata never crosses identities");
    alpha.close_now();
    verify(drive(gateway, {&beta}, [&] { return !member_for(room, "b5-alpha"); }),
           "B5 first session fully leaves the upstream room");
    CitraPeer again;
    again.connect(gateway.port());
    again.send(citra_join_bytes("b5-alpha", "console-b5-alpha", citra_room::no_preferred_mac,
                                citra_room::network_version, ""));
    verify(drive(gateway, {&again, &beta}, [&] {
        const auto value = member_for(room, "b5-alpha");
        return value && value->game.name == "CitraGateway";
    }), "B5 a replacement session does not inherit departed game metadata");
    dump_documents(gateway, "b5_early_game_info");
    gateway.close();

    auto native_options = enet_gateway_options(take_port(), room);
    citra_gateway::Gateway native(native_options);
    native.open();
    EnetCitraPeer peer(native.port());
    verify(connect_enet_peer(native, peer), "B5 native ENet client connects");
    peer.send(citra_join_bytes("b5-native", "console-b5-native", citra_room::no_preferred_mac,
                               citra_room::network_version, ""));
    peer.send(citra_set_game_info_bytes("native-early", 0x5555));
    verify(until_enet(native, {&peer}, [&] {
        const auto value = member_for(room, "b5-native");
        return value && value->game.name == "native-early" && value->game.id == 0x5555;
    }), "B5 native Citra JoinRequest then SetGameInfo ordering works over ENet");
    check(native.counters().set_game_info_rejected == 0,
          "B5 the native ordering no longer produces a spurious metadata rejection");
    dump_documents(native, "b5_early_game_info_enet");
    native.close();

    // Upstream rejection must discard the pending value, never announce it.
    RoomGuard rejecting_room(take_port(), 4, "upstream-only-secret");
    auto rejected_options = gateway_options(take_port(), rejecting_room.port(), 4, "");
    citra_gateway::Gateway rejected(rejected_options);
    rejected.open();
    CitraPeer refused;
    refused.connect(rejected.port());
    refused.send(citra_join_bytes("b5-refused", "console-b5-refused", citra_room::no_preferred_mac,
                                  citra_room::network_version, ""));
    refused.send(citra_set_game_info_bytes("must-not-escape", 0x6666));
    verify(drive(rejected, {&refused}, [&] {
        return rejected.counters().set_game_info_discarded == 1;
    }), "B5 upstream rejection destroys pending metadata with the session");
    check(rejected.counters().set_game_info_accepted == 0 && rejecting_room.members().empty(),
          "B5 rejected joins never publish pending metadata upstream");
    rejected.close();

    auto bounded_options = gateway_options(take_port(), room);
    bounded_options.room_outgoing_packets = 1;
    citra_gateway::Gateway bounded(bounded_options);
    bounded.open();
    CitraPeer limited;
    limited.connect(bounded.port());
    limited.send(citra_join_bytes("b5-limited", "console-b5-limited", citra_room::no_preferred_mac,
                                  citra_room::network_version, ""));
    verify(drive(bounded, {&limited}, [&] {
        const auto value = member_for(room, "b5-limited");
        return value && value->game.name == "CitraGateway";
    }), "B5 bounded-send metadata test joins normally");
    // Let the initial GameInfo ACK return its single packet budget first.
    drive(bounded, {&limited}, [] { return false; }, 150);
    limited.send(citra_set_game_info_bytes("first-fits", 0x7777));
    limited.send(citra_set_game_info_bytes("second-is-backpressured", 0x7778));
    verify(drive(bounded, {&limited}, [&] {
        return bounded.counters().set_game_info_rejected == 1;
    }), "B5 exhausted send budget is reported as rejected rather than accepted");
    check(bounded.counters().set_game_info_accepted == 1 &&
              bounded.counters().set_game_info_version_placeholder == 1 &&
              bounded.counters().queue_overflows == 1,
          "B5 false transport send result cannot count as a successful translation");
    drive(bounded, {&limited}, [] { return false; }, 150);
    limited.send(citra_set_game_info_bytes("fits-budget", 0x8888));
    verify(drive(bounded, {&limited}, [&] {
        const auto value = member_for(room, "b5-limited");
        return value && value->game.name == "fits-budget" && value->game.id == 0x8888;
    }), "B5 a rejected metadata packet does not break later valid updates");
    bounded.close();
}

// Room UI must reflect real upstream state without granting game routing identities.
void group_b20_room_ui() {
    RoomGuard room(take_port(), 4);
    citra_gateway::Gateway gateway(enet_gateway_options(take_port(), room));
    gateway.open();
    EnetCitraPeer alpha(gateway.port());
    verify(connect_enet_peer(gateway, alpha), "B20 native Citra connects");
    alpha.send(citra_join_bytes("ui-alpha", "ui-console", citra_room::no_preferred_mac,
                                citra_room::network_version, ""));
    alpha.send(citra_set_game_info_bytes("MONSTER HUNTER XX", 0x197100));
    auto latest = [&]() {
        citra_room::RoomInformation info;
        for (const auto& frame : alpha.raw_frames()) {
            const auto message = citra_room::decode(frame, citra_room::Direction::ServerToClient);
            if (const auto* value = std::get_if<citra_room::RoomInformation>(&message)) info = *value;
        }
        return info;
    };
    auto row = [&](const std::string& name) -> std::optional<citra_room::Member> {
        for (const auto& member : latest().members) if (member.nickname == name) return member;
        return std::nullopt;
    };
    verify(until_enet(gateway, {&alpha}, [&] {
        const auto self = row("ui-alpha");
        return self && self->game_name == "MONSTER HUNTER XX" && self->game_id == 0x197100;
    }), "B20 own actual game is republished after asynchronous join");
    auto native = std::make_unique<RawRoomPeer>(room.port(), "ui-gu", room_client::network_version);
    auto wait = [&](const std::function<bool()>& done) {
        return until_enet(gateway, {&alpha}, [&] { native->pump(0); return done(); });
    };
    verify(wait([&] { return row("ui-gu").has_value(); }),
           "B20 native upstream member appears after join");
    native->send(room_client::GameInfo{"Monster Hunter GU", 0x100770008dd8000ULL, "1.4"});
    verify(wait([&] {
        auto gu = row("ui-gu");
        return gu && gu->game_name == "Monster Hunter GU" && gu->game_id == 0x100770008dd8000ULL;
    }), "B20 upstream game name and id update live");
    const auto display_mac = row("ui-gu")->mac;
    const auto routing_identities = gateway.identities();
    check(routing_identities.size() == 1 && !std::any_of(routing_identities.begin(), routing_identities.end(), [&](const auto& entry) { return entry.mac == display_mac; }),
          "B20 upstream display MAC never authorizes game routing");
    native->send(room_client::GameInfo{"", 0, ""});
    verify(wait([&] { auto gu = row("ui-gu"); return gu && gu->game_name.empty() && gu->game_id == 0; }),
           "B20 stopping the native game clears displayed state");
    check(row("ui-gu")->mac == display_mac, "B20 upstream display identity survives status updates");
    alpha.send(citra_room::encode(citra_room::ChatRequest{"XX says hello / \xe4\xb8\xad\xe6\x96\x87"}, citra_room::Direction::ClientToServer));
    auto native_chat_count = [&]() {
        std::size_t count = 0;
        for (const auto& message : native->messages()) {
            if (const auto* chat = std::get_if<room_client::ChatMessage>(&message)) {
                if (chat->nickname == "ui-alpha" && chat->message == "XX says hello / \xe4\xb8\xad\xe6\x96\x87") ++count;
            }
        }
        return count;
    };
    verify(wait([&] { return native_chat_count() == 1; }), "B20 Citra chat reaches native room once with identity");
    native->send(room_client::ChatRequest{"GU replies / \xe4\xbd\xa0\xe5\xa5\xbd"});
    auto citra_chat_count = [&]() {
        std::size_t count = 0;
        for (const auto& frame : alpha.raw_frames()) {
            const auto message = citra_room::decode(frame, citra_room::Direction::ServerToClient);
            if (const auto* chat = std::get_if<citra_room::ChatMessage>(&message)) {
                if (chat->nickname == "ui-gu" && chat->message == "GU replies / \xe4\xbd\xa0\xe5\xa5\xbd") ++count;
            }
        }
        return count;
    };
    verify(wait([&] { return citra_chat_count() == 1; }), "B20 native chat reaches Citra once without echo loop");
    alpha.send(citra_set_game_info_bytes("", 0));
    verify(wait([&] { auto self = row("ui-alpha"); return self && self->game_name.empty() && self->game_id == 0; }),
           "B20 Citra stopping a game clears both room displays");
    native->leave();
    verify(wait([&] { return !row("ui-gu"); }), "B20 native departure removes the Citra room row");
    native.reset();
    dump_documents(gateway, "b20_room_ui");
    gateway.close();
}

void group_b4_session_ledger() {
    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 4);
    auto options = enet_gateway_options(gw_port, room);
    options.control_plane_enabled = true;
    citra_gateway::Gateway gateway(options);
    gateway.open();

    // --- a v4 SetGameInfo is a declared category with an ADR-009 translation --
    EnetCitraPeer alpha(gateway.port());
    verify(connect_enet_peer(gateway, alpha), "B4 the ENet/UDP peer connects");
    alpha.send(citra_join_bytes("b4-alpha", "console-b4-alpha", citra_room::no_preferred_mac,
                                citra_room::network_version, ""));
    verify(until_enet(gateway, {&alpha}, [&] { return member_for(room, "b4-alpha").has_value(); }),
           "B4 the ENet client joins the room member table");
    // The gateway sends GameInfo right after JoinSuccess; the room member row can
    // appear before that packet lands, so wait for the declared game identity.
    const bool declared_game = until_enet(gateway, {&alpha}, [&] {
        const auto member = member_for(room, "b4-alpha");
        return member.has_value() && member->game.name == "CitraGateway" &&
               member->game.version == "gw-v1";
    });
    const auto before_set = member_for(room, "b4-alpha");
    check(declared_game,
          "B4 the room peer starts with the declared gateway game name and version");

    const auto unknown_before = gateway.counters().payload_rejected_unknown_category;
    const auto accepted_before = gateway.counters().set_game_info_accepted;
    alpha.send(citra_set_game_info_bytes("b4-alpha-game", 0x1234));
    const bool applied = until_enet(gateway, {&alpha}, [&] {
        const auto member = member_for(room, "b4-alpha");
        return member.has_value() && member->game.name == "b4-alpha-game";
    });
    const auto after_set = member_for(room, "b4-alpha");
    check(applied && after_set.has_value() && after_set->game.id == 0x1234,
          "B4 SetGameInfo reaches this client's own room member (room.cpp HandleGameInfoPacket)");
    check(after_set.has_value() && after_set->game.version == "gw-v1",
          "B4 the unmappable v1 game version stays the declared gateway placeholder");
    check(gateway.counters().set_game_info_accepted == accepted_before + 1 &&
              gateway.counters().set_game_info_version_placeholder == 1,
          "B4 the accepted SetGameInfo and its version placeholder are counted");
    check(gateway.counters().payload_rejected_unknown_category == unknown_before,
          "B4 SetGameInfo is no longer counted as an unknown category");
    bool set_event = false;
    for (const auto& event : gateway.events()) {
        if (event.kind == "payload.set_game_info") {
            set_event = true;
        }
    }
    check(set_event, "B4 the accepted SetGameInfo is recorded as an event");

    // A second session must never receive the first session's game info.
    EnetCitraPeer beta(gateway.port());
    verify(connect_enet_peer(gateway, beta), "B4 a second ENet/UDP peer connects");
    beta.send(citra_join_bytes("b4-beta", "console-b4-beta", citra_room::no_preferred_mac,
                               citra_room::network_version, ""));
    verify(until_enet(gateway, {&alpha, &beta},
                      [&] { return member_for(room, "b4-beta").has_value(); }),
           "B4 the second client joins the room member table");
    beta.send(citra_set_game_info_bytes("b4-beta-game", 0x5678));
    verify(until_enet(gateway, {&alpha, &beta},
                      [&] {
                          const auto member = member_for(room, "b4-beta");
                          return member.has_value() && member->game.name == "b4-beta-game";
                      }),
           "B4 the second client's SetGameInfo is applied to its own peer");
    const auto alpha_member = member_for(room, "b4-alpha");
    check(alpha_member.has_value() && alpha_member->game.name == "b4-alpha-game" &&
              alpha_member->game.id == 0x1234,
          "B4 a SetGameInfo never writes another session's room peer");

    // --- the dump keeps departed sessions and cumulative control counters -----
    const auto alpha_identity = identity_for(gateway, "b4-alpha");
    verify(alpha_identity.has_value(), "B4 the live identity exists before departure");
    const std::string alpha_ip = citra_gateway::ip_to_string(alpha_identity->fake_ip);
    const auto beacons_before = control_counter(gateway, "beacon_emitted");
    check(beacons_before >= 1, "B4 the control plane emitted beacons before departure");

    alpha.close_now();
    const bool gone =
        until_enet(gateway, {&beta}, [&] { return client_id_for(gateway, "b4-alpha") == 0; });
    check(gone, "B4 the departed session leaves the live client list");

    const std::string clients = gateway.clients_json();
    const std::string identities = gateway.identities_json();
    const std::string counters = gateway.counters_json();
    check(clients.find("\"b4-alpha\"") != std::string::npos &&
              clients.find("\"phase\":\"Departed\"") != std::string::npos &&
              clients.find("\"departed\":true") != std::string::npos,
          "B4 the dump keeps the departed client's nickname and marks it departed");
    check(clients.find("\"fake_ip\":\"" + alpha_ip + "\"") != std::string::npos &&
              clients.find("\"assigned_fake_ip\":\"" + alpha_ip + "\"") != std::string::npos,
          "B4 the departed client keeps its fake IPv4 under every documented field name");
    check(identities.find("\"b4-alpha\"") != std::string::npos &&
              identities.find("\"fake_ip\":\"" + alpha_ip + "\"") != std::string::npos,
          "B4 the identity dump keeps the departed client's nickname and fake IPv4");
    check(counters.find("\"control_scope\":\"cumulative\"") != std::string::npos,
          "B4 counters label the control scope as cumulative");
    check(json_counter(counters, "control_sessions_departed") >= 1,
          "B4 the departed control session is counted");
    check(control_counter(gateway, "beacon_emitted") >= beacons_before,
          "B4 control counters survive the session that produced them");
    check(control_counter(gateway, "beacon_emitted") > 0,
          "B4 the cumulative control counters are not zeroed by the departure");

    note("b4.departed_client", "b4-alpha");
    note("b4.departed_fake_ip", alpha_ip);
    note("b4.set_game_info_accepted", std::to_string(gateway.counters().set_game_info_accepted));
    note("b4.control_scope", "cumulative");
    note("b4.control_sessions_departed",
         std::to_string(json_counter(counters, "control_sessions_departed")));
    note("b4.beacon_cumulative", std::to_string(control_counter(gateway, "beacon_emitted")));
    dump_documents(gateway, "b4_session_ledger");
}

// G2 channel C trace recorder: pure module tests. No sockets, no real room
// server and no game files; every frame below is synthetic and every record is
// rendered from an injected stamp so the whole group is deterministic.
void group_t1_trace() {
    using citra_gateway::TraceContext;
    using citra_gateway::TraceRecord;
    using citra_gateway::TraceSink;
    using citra_gateway::TraceStamp;
    using citra_gateway::TraceStructure;

    auto field_value = [](const TraceStructure& structure, const std::string& name) -> std::string {
        for (const auto& field : structure.fields) {
            if (field.name == name) {
                return field.value;
            }
        }
        return "<missing>";
    };
    auto contains = [](const std::string& haystack, const std::string& needle) {
        return haystack.find(needle) != std::string::npos;
    };

    // 1. SHA-256 stability and FIPS 180-4 vectors.
    check(citra_gateway::trace_sha256_hex(nullptr, 0) ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "T1 sha256 of empty input matches FIPS 180-4");
    const std::vector<std::uint8_t> abc{'a', 'b', 'c'};
    check(citra_gateway::trace_sha256_hex(abc) ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "T1 sha256 of abc matches FIPS 180-4");
    std::vector<std::uint8_t> longer(1000);
    for (std::size_t i = 0; i < longer.size(); ++i) {
        longer[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    check(citra_gateway::trace_sha256_hex(longer) == citra_gateway::trace_sha256_hex(longer),
          "T1 sha256 is stable across calls");
    check(citra_gateway::trace_sha256_hex(longer).size() == 64,
          "T1 sha256 renders as 64 lower-case hex digits");

    // 2. Citra SecureData field extraction from a synthetic LLC+SecureData frame.
    //    LLC AA AA 03 00 00 00 87 6D; protocol_size=18, reserved=0,
    //    securedata_size=14, is_management=0, channel=33, seqno=300, dest=7,
    //    src=2, then a 4 byte payload.
    const std::vector<std::uint8_t> secure = {
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x87, 0x6D,  // LLC
        0x00, 0x12, 0x00, 0x00, 0x00, 0x0E,              // protocol/securedata sizes
        0x00,                                            // is_management
        0x21,                                            // data_channel 33
        0x01, 0x2C,                                      // seqno 300
        0x00, 0x07,                                      // dest node 7
        0x00, 0x02,                                      // src node 2
        0x10, 0x20, 0x30, 0x40,                          // payload
    };
    const TraceStructure secure_structure =
        citra_gateway::trace_decode_citra_secure_data(secure.data(), secure.size());
    check(secure_structure.decoded, "T1 SecureData frame decodes");
    check(secure_structure.name == "citra_secure_data", "T1 SecureData structure name");
    check(field_value(secure_structure, "src_node_id") == "2", "T1 SecureData src node id");
    check(field_value(secure_structure, "dest_node_id") == "7", "T1 SecureData dest node id");
    check(field_value(secure_structure, "data_channel") == "33", "T1 SecureData data channel");
    check(field_value(secure_structure, "is_management") == "0", "T1 SecureData is_management");
    check(field_value(secure_structure, "seqno") == "300", "T1 SecureData seqno");
    check(field_value(secure_structure, "payload_bytes") == "4", "T1 SecureData payload bytes");

    // 3. Undecoded paths: truncation, a bad LLC tag and an out of range LDN type
    //    must set every field to the literal "undecoded" and keep a reason.
    const std::vector<std::uint8_t> truncated = {0xAA, 0xAA, 0x03};
    const TraceStructure short_structure =
        citra_gateway::trace_decode_citra_secure_data(truncated.data(), truncated.size());
    check(!short_structure.decoded, "T1 short SecureData frame is undecoded");
    check(!short_structure.reason.empty(), "T1 undecoded frame keeps a reason");
    check(field_value(short_structure, "src_node_id") == "\"undecoded\"",
          "T1 undecoded fields use the literal undecoded");
    std::vector<std::uint8_t> bad_tag = secure;
    bad_tag[0] = 0x00;
    const TraceStructure bad_structure =
        citra_gateway::trace_decode_citra_secure_data(bad_tag.data(), bad_tag.size());
    check(!bad_structure.decoded, "T1 bad LLC tag is undecoded");
    const TraceStructure bad_ldn = citra_gateway::trace_decode_yuzu_ldn(9, nullptr, 0);
    check(!bad_ldn.decoded, "T1 out of range LDN type is undecoded");
    check(field_value(bad_ldn, "ldn_type") == "\"undecoded\"",
          "T1 undecoded LDN fields use the literal undecoded");

    // 4. LDN type table against the frozen body sizes.
    const std::vector<std::uint8_t> connect_body(0x40);
    const TraceStructure connect_ldn =
        citra_gateway::trace_decode_yuzu_ldn(2, connect_body.data(), connect_body.size());
    check(connect_ldn.decoded, "T1 LDN Connect decodes");
    check(field_value(connect_ldn, "ldn_expected_body_bytes") == "64", "T1 LDN Connect body size");
    check(field_value(connect_ldn, "ldn_size_ok") == "true", "T1 LDN Connect size matches");
    const TraceStructure scan_ldn = citra_gateway::trace_decode_yuzu_ldn(0, nullptr, 5);
    check(field_value(scan_ldn, "ldn_expected_body_bytes") == "0", "T1 LDN Scan body size");
    check(field_value(scan_ldn, "ldn_size_ok") == "false", "T1 LDN Scan size mismatch flagged");

    // 5. Yuzu Proxy frame: a real Zstd frame round trips; malformed frames are
    //    undecoded. No capture bytes are involved.
    const std::string plain_text = "gateway-trace-proxy-payload";
    std::vector<std::uint8_t> compressed(ZSTD_compressBound(plain_text.size()));
    const std::size_t compressed_size = ZSTD_compress(compressed.data(), compressed.size(),
                                                      plain_text.data(), plain_text.size(), 1);
    check(!ZSTD_isError(compressed_size), "T1 synthetic zstd frame compresses");
    compressed.resize(compressed_size);
    const auto* plain_bytes = reinterpret_cast<const std::uint8_t*>(plain_text.data());
    const TraceStructure proxy = citra_gateway::trace_decode_yuzu_proxy(
        compressed.data(), compressed.size(), plain_bytes, plain_text.size(), true);
    check(proxy.decoded, "T1 proxy frame decodes");
    check(field_value(proxy, "compressed_bytes") == std::to_string(compressed.size()),
          "T1 proxy compressed length");
    check(field_value(proxy, "decompressed_bytes") == std::to_string(plain_text.size()),
          "T1 proxy decompressed length");
    check(field_value(proxy, "zstd_frame_ok") == "true", "T1 proxy zstd frame verified");
    const TraceStructure empty_proxy =
        citra_gateway::trace_decode_yuzu_proxy(nullptr, 0, nullptr, 0, true);
    check(!empty_proxy.decoded, "T1 empty proxy frame is undecoded");
    std::vector<std::uint8_t> trailing = compressed;
    trailing.push_back(0x00);
    check(!citra_gateway::trace_decode_yuzu_proxy(trailing.data(), trailing.size(), plain_bytes,
                                                  plain_text.size(), true)
               .decoded,
          "T1 proxy frame with trailing bytes is undecoded");
    check(!citra_gateway::trace_decode_yuzu_proxy(compressed.data(), compressed.size(), plain_bytes,
                                                  plain_text.size() + 1, true)
               .decoded,
          "T1 proxy frame with a size mismatch is undecoded");
    std::vector<std::uint8_t> cut(compressed.begin(), compressed.end() - 1);
    check(!citra_gateway::trace_decode_yuzu_proxy(cut.data(), cut.size(), plain_bytes,
                                                  plain_text.size(), true)
               .decoded,
          "T1 truncated proxy frame is undecoded");

    // 6. Record rendering: stable order, deterministic, JSON escaped.
    TraceRecord record;
    record.context.manifest_id = "m\"1";
    record.context.run_id = "run\\2";
    record.context.channel = "C";
    record.context.platform = std::string("win") + static_cast<char>(0x01);
    record.context.build_id = "b\n3";
    record.context.role = "host";
    record.event_label = "citra.in\ttab";
    record.context.stage = "unspecified";
    record.direction = "citra->gateway";
    record.stamp.utc = "2026-01-02T03:04:05Z";
    record.stamp.monotonic_ms = 42;
    record.length = 3;
    record.sha256 = "abc";
    record.structure.name = "citra_message";
    record.structure.decoded = true;
    record.structure.fields.push_back(
        citra_gateway::trace_field_string("citra_message", "join\"req"));
    const std::string line = TraceSink::render(record);
    check(contains(line, "\"manifest_id\":\"m\\\"1\""), "T1 JSON escapes a quote");
    check(contains(line, "\"run_id\":\"run\\\\2\""), "T1 JSON escapes a backslash");
    check(contains(line, "\"build_id\":\"b\\n3\""), "T1 JSON escapes a newline");
    check(contains(line, "\"event_label\":\"citra.in\\ttab\""), "T1 JSON escapes a tab");
    check(contains(line, "\"platform\":\"win\\u0001\""), "T1 JSON escapes a control byte");
    check(contains(line, "\"citra_message\":\"join\\\"req\""), "T1 JSON escapes a field value");
    check(line.find('\n') == std::string::npos, "T1 rendered JSON holds no raw newline");
    check(line.find("\"manifest_id\"") < line.find("\"run_id\"") &&
              line.find("\"run_id\"") < line.find("\"event_label\"") &&
              line.find("\"event_label\"") < line.find("\"direction\"") &&
              line.find("\"direction\"") < line.find("\"utc\"") &&
              line.find("\"utc\"") < line.find("\"monotonic_ms\"") &&
              line.find("\"monotonic_ms\"") < line.find("\"length\"") &&
              line.find("\"length\"") < line.find("\"sha256\""),
          "T1 rendered field order is stable");
    check(TraceSink::render(record) == line, "T1 rendering is deterministic");
    note("t1.trace_line", line);

    // 7. Injection: make_record hashes the bytes and copies raw only when asked.
    TraceStamp stamp;
    stamp.utc = "2026-01-02T03:04:05Z";
    stamp.monotonic_ms = 1234;
    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    const TraceRecord built = citra_gateway::trace_make_record(
        record.context, "proxy.out", "gateway->room", stamp, payload.data(), payload.size(),
        secure_structure, false);
    check(built.length == 3, "T1 make_record carries the caller length");
    check(built.raw.empty(), "T1 make_record omits raw by default");
    check(built.sha256 == citra_gateway::trace_sha256_hex(payload),
          "T1 make_record hashes the raw bytes");
    check(built.stamp.utc == "2026-01-02T03:04:05Z" && built.stamp.monotonic_ms == 1234,
          "T1 make_record takes the injected stamp");

    // 8. Off by default, fail closed, JSON Lines file, raw gating.
    std::error_code ec;
    // The evidence directory is the ASCII relative path build.ps1 hands to this
    // harness (".build-direct/evidence"). %TEMP% is not usable here: on a host
    // whose user name is non-ASCII, MinGW's narrow std::ofstream cannot open the
    // resulting absolute path.
    const std::filesystem::path temp = std::filesystem::path(g_evidence_dir) / "t1-trace";
    std::filesystem::remove_all(temp, ec);
    std::filesystem::create_directories(temp, ec);

    // The CLI passes --trace-out as active-code-page bytes, not UTF-8; a narrow
    // std::filesystem::path conversion throws on such bytes. The helper must
    // decode them (and never throw) so a non-ASCII trace path still opens.
    {
        const std::wstring wide = L"t1-trace/\u5B50\u76EE\u5F55/trace.jsonl";
        const int needed = WideCharToMultiByte(CP_ACP, 0, wide.c_str(),
                                               static_cast<int>(wide.size()), nullptr, 0,
                                               nullptr, nullptr);
        std::string narrow(static_cast<std::size_t>(needed > 0 ? needed : 0), '\0');
        if (needed > 0) {
            WideCharToMultiByte(CP_ACP, 0, wide.c_str(), static_cast<int>(wide.size()),
                                narrow.data(), needed, nullptr, nullptr);
        }
        bool decoded_ok = false;
        try {
            decoded_ok = !citra_gateway::trace_path_from_narrow(narrow).empty();
        } catch (...) {
            decoded_ok = false;
        }
        check(decoded_ok, "T1 non-ASCII path decodes without throwing");
    }

    TraceSink off_sink;
    std::string why;
    check(!off_sink.enabled(), "T1 a fresh sink is disabled by default");
    check(off_sink.write(record, &why), "T1 writing while disabled is a no-op success");

    citra_gateway::Options default_options;
    default_options.citra_tcp_test_transport = true;
    citra_gateway::Gateway default_gateway(default_options);
    check(!default_gateway.trace_enabled(), "T1 gateway tracing is off by default");
    default_gateway.close();

    citra_gateway::Options bad_options;
    bad_options.citra_tcp_test_transport = true;
    bad_options.trace_path = (temp / "missing-dir" / "trace.jsonl").string();
    citra_gateway::Gateway bad_gateway(bad_options);
    bool threw = false;
    try {
        bad_gateway.open();
    } catch (const std::exception&) {
        threw = true;
    }
    check(threw, "T1 gateway open fails closed on an unopenable trace path");
    bad_gateway.close();

    const std::filesystem::path path = temp / "trace.jsonl";
    TraceSink sink;
    check(sink.open(path.string(), false, &why), "T1 trace file opens");
    check(sink.enabled() && !sink.raw_enabled(), "T1 opened sink is enabled without raw");
    check(sink.write(record, &why), "T1 trace line writes");
    sink.close();
    std::ifstream in(path, std::ios::binary);
    const std::string content((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    in.close();
    check(!contains(content, "raw_hex"), "T1 records omit raw bytes unless requested");
    check(!content.empty() && content.find('\n') == content.size() - 1,
          "T1 trace file is exactly one JSON line");

    const std::filesystem::path raw_path = temp / "trace-raw.jsonl";
    TraceSink raw_sink;
    check(raw_sink.open(raw_path.string(), true, &why), "T1 raw trace file opens");
    check(raw_sink.raw_enabled(), "T1 raw tracing can be enabled");
    TraceRecord raw_record = record;
    raw_record.raw = {0x0A, 0xB5};
    check(raw_sink.write(raw_record, &why), "T1 raw trace line writes");
    raw_sink.close();
    std::ifstream raw_in(raw_path, std::ios::binary);
    const std::string raw_content((std::istreambuf_iterator<char>(raw_in)),
                                  std::istreambuf_iterator<char>());
    raw_in.close();
    check(contains(raw_content, "\"raw_hex\":\"0ab5\""),
          "T1 raw bytes render as lower-case hex");
    note("t1.raw_trace_line", raw_content.substr(0, raw_content.find('\n')));

    // 9. Self-describing markers: a traced run with zero frames still writes
    //    exactly one run.begin, and a stage file change appends one stage.begin.
    const TraceRecord marker =
        citra_gateway::trace_make_marker(record.context, "run.begin", stamp);
    check(marker.direction == "n/a", "T1 marker direction is n/a");
    check(marker.length == 0, "T1 marker length is zero");
    check(marker.sha256 ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "T1 marker hashes the empty input");
    check(marker.structure.name == "marker" && marker.structure.decoded,
          "T1 marker uses the marker structure");
    check(marker.stamp.utc == stamp.utc && marker.stamp.monotonic_ms == stamp.monotonic_ms,
          "T1 marker takes the injected stamp");

    TraceContext run_context;
    run_context.manifest_id = "citra-gateway";
    run_context.run_id = "run-7";
    run_context.channel = "A";
    run_context.platform = "windows-x86_64";
    run_context.build_id = "citra-gateway/g2-trace-1";
    run_context.role = "host";
    run_context.stage = "unspecified";

    const std::filesystem::path run_dir = std::filesystem::path(g_evidence_dir) / "t1-run";
    std::filesystem::remove_all(run_dir, ec);
    std::filesystem::create_directories(run_dir, ec);

    citra_gateway::Options run_options;
    run_options.citra_tcp_test_transport = true;
    run_options.listen_port = take_port();
    run_options.trace_path = (run_dir / "run.jsonl").string();
    run_options.trace_context = run_context;
    run_options.trace_clock = []() {
        TraceStamp injected;
        injected.utc = "2026-02-03T04:05:06Z";
        injected.monotonic_ms = 7;
        return injected;
    };
    citra_gateway::Gateway traced_gateway(run_options);
    bool run_opened = false;
    try {
        traced_gateway.open();
        run_opened = true;
    } catch (const std::exception&) {
    }
    check(run_opened, "T1 traced gateway opens");
    check(traced_gateway.trace_enabled(), "T1 traced gateway reports tracing on");
    const std::string identity = traced_gateway.trace_json();
    traced_gateway.tick(0);
    traced_gateway.close();

    std::ifstream run_in(run_dir / "run.jsonl", std::ios::binary);
    const std::string run_content((std::istreambuf_iterator<char>(run_in)),
                                  std::istreambuf_iterator<char>());
    run_in.close();
    std::size_t run_lines = 0;
    for (const char ch : run_content) {
        if (ch == '\n') {
            ++run_lines;
        }
    }
    check(run_lines == 1, "T1 a zero frame run writes exactly one record");
    check(contains(run_content, "\"event_label\":\"run.begin\""),
          "T1 the zero frame record is run.begin");
    check(contains(run_content, "\"direction\":\"n/a\""), "T1 run.begin direction is n/a");
    check(contains(run_content, "\"length\":0"), "T1 run.begin length is zero");
    check(contains(run_content, "\"monotonic_ms\":7"), "T1 run.begin takes the injected stamp");
    check(contains(run_content, "\"channel\":\"A\"") &&
              contains(run_content, "\"run_id\":\"run-7\""),
          "T1 run.begin carries the injected identity");
    note("t1.run_begin_line", run_content.substr(0, run_content.find('\n')));
    check(contains(identity, "\"channel\":\"A\"") && contains(identity, "\"enabled\":true"),
          "T1 trace identity echoes channel and enabled");
    check(contains(identity, "\"raw_enabled\":false"), "T1 trace identity echoes the raw switch");
    check(contains(identity, "run.jsonl"), "T1 trace identity echoes the trace path");

    // 10. Stage file: read at open and on every tick; one marker per change.
    const std::filesystem::path stage_file = run_dir / "stage.txt";
    {
        std::ofstream out(stage_file, std::ios::binary);
        out << "menu\n";
    }
    citra_gateway::Options stage_options;
    stage_options.citra_tcp_test_transport = true;
    stage_options.listen_port = take_port();
    stage_options.trace_path = (run_dir / "stage.jsonl").string();
    stage_options.trace_stage_file = stage_file.string();
    stage_options.trace_context = run_context;
    stage_options.trace_clock = run_options.trace_clock;
    citra_gateway::Gateway stage_gateway(stage_options);
    bool stage_opened = false;
    try {
        stage_gateway.open();
        stage_opened = true;
    } catch (const std::exception&) {
    }
    check(stage_opened, "T1 stage traced gateway opens");
    {
        std::ofstream out(stage_file, std::ios::binary | std::ios::trunc);
        out << "loading\n";
    }
    stage_gateway.tick(0);
    stage_gateway.tick(0);
    stage_gateway.close();

    std::ifstream stage_in(run_dir / "stage.jsonl", std::ios::binary);
    const std::string stage_content((std::istreambuf_iterator<char>(stage_in)),
                                    std::istreambuf_iterator<char>());
    stage_in.close();
    std::size_t stage_lines = 0;
    for (const char ch : stage_content) {
        if (ch == '\n') {
            ++stage_lines;
        }
    }
    check(stage_lines == 2, "T1 a stage change appends exactly one marker");
    check(contains(stage_content, "\"event_label\":\"run.begin\"") &&
              contains(stage_content, "\"event_label\":\"stage.begin\""),
          "T1 the stage run holds run.begin and stage.begin");
    check(contains(stage_content, "\"stage\":\"menu\""),
          "T1 run.begin carries the initial stage");
    check(contains(stage_content, "\"stage\":\"loading\""),
          "T1 stage.begin carries the new stage");
    note("t1.stage_trace_lines", std::to_string(stage_lines));
    std::filesystem::remove_all(run_dir, ec);

    std::filesystem::remove_all(temp, ec);
}


// ===========================================================================
// A11: --citra-peer-relay (V-047/V-048). Transport-only passthrough for
// Citra<->Citra: every WifiPacket type crosses unchanged, with the frame type
// and channel carried in a 7 byte CRLY wrapper. With the switch off the frozen
// Data-only behaviour must stay byte for byte intact.
// ===========================================================================
void group_a11_peer_relay() {
    const auto payload = synthetic_payload(48, 0x6C);

    // (c) relay off: a Beacon is still refused and counted, like A4.
    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Gateway gateway(gateway_options(gw_port, room));
        gateway.open();

        CitraPeer alpha;
        alpha.connect(gateway.port());
        verify(join_peer(gateway, alpha, "alpha-off", "console-alpha-off"),
               "A11 relay off alpha joins");
        CitraPeer beta;
        beta.connect(gateway.port());
        verify(join_peer(gateway, beta, "beta-off", "console-beta-off",
                         citra_room::no_preferred_mac, citra_room::network_version, "",
                         {&alpha, &beta}),
               "A11 relay off beta joins");
        const auto alpha_mac = alpha.assigned_mac();
        const auto beta_mac = beta.assigned_mac();
        verify(alpha_mac.has_value() && beta_mac.has_value(),
               "A11 relay off both peers hold MACs");

        const auto before = gateway.counters();
        const std::size_t beta_baseline = beta.raw_count();
        alpha.send(citra_wifi_bytes(*alpha_mac, citra_room::broadcast_mac, payload,
                                    citra_room::FrameType::Beacon, 6));
        drive(gateway, {&alpha, &beta}, [&] { return false; }, 300);
        const auto after = gateway.counters();
        check(after.payload_rejected_unknown_category ==
                  before.payload_rejected_unknown_category + 1,
              "A11 with the relay off a Beacon is still rejected and counted");
        check(beta.raw_count() == beta_baseline,
              "A11 with the relay off the Beacon never reaches the peer");
        check(after.proxy_frames_emitted == before.proxy_frames_emitted,
              "A11 with the relay off the Beacon produces no room frame");
        check(after.peer_relay_frames_emitted == 0 &&
                  after.peer_relay_frames_consumed == 0 &&
                  after.peer_relay_bad_wrapper == 0,
              "A11 the peer relay counters stay 0 while the switch is off");
    }

    const auto room_port = take_port();
    const auto gw_port = take_port();
    RoomGuard room(room_port, 4);
    auto options = gateway_options(gw_port, room);
    options.citra_peer_relay = true;
    const auto relay_trace_path = std::filesystem::path(g_evidence_dir) / "a11-relay.jsonl";
    options.trace_path = relay_trace_path.string();
    options.trace_raw = true;
    options.trace_context.channel = "A";
    citra_gateway::Gateway gateway(options);
    gateway.open();

    CitraPeer alpha;
    alpha.connect(gateway.port());
    verify(join_peer(gateway, alpha, "alpha-relay", "console-alpha-relay"),
           "A11 relay alpha joins");
    CitraPeer beta;
    beta.connect(gateway.port());
    verify(join_peer(gateway, beta, "beta-relay", "console-beta-relay",
                     citra_room::no_preferred_mac, citra_room::network_version, "",
                     {&alpha, &beta}),
           "A11 relay beta joins");
    const auto alpha_mac = alpha.assigned_mac();
    const auto beta_mac = beta.assigned_mac();
    verify(alpha_mac.has_value() && beta_mac.has_value(), "A11 relay both peers hold MACs");

    // (a) a broadcast Beacon keeps type, channel, transmitter and payload.
    const std::size_t beta_beacon_base = beta.raw_count();
    const auto before_beacon = gateway.counters();
    alpha.send(citra_wifi_bytes(*alpha_mac, citra_room::broadcast_mac, payload,
                                citra_room::FrameType::Beacon, 6));
    const bool beacon_delivered =
        drive(gateway, {&alpha, &beta},
              [&] { return beta.raw_count() > beta_beacon_base; }, 4000);
    verify(beacon_delivered, "A11 a relayed Beacon reaches the peer");
    {
        const auto* wifi =
            std::get_if<citra_room::WifiPacket>(&beta.messages()[beta_beacon_base]);
        check(wifi != nullptr && wifi->type == citra_room::FrameType::Beacon &&
                  wifi->channel == 6 && wifi->data == payload,
              "A11 the relayed Beacon keeps its type, channel and payload");
        check(wifi != nullptr && wifi->transmitter == *alpha_mac &&
                  wifi->destination == citra_room::broadcast_mac,
              "A11 the relayed Beacon keeps the transmitter and the broadcast destination");
    }
    const auto after_beacon = gateway.counters();
    check(after_beacon.peer_relay_frames_emitted ==
                  before_beacon.peer_relay_frames_emitted + 1 &&
              after_beacon.peer_relay_frames_consumed ==
                  before_beacon.peer_relay_frames_consumed + 1,
          "A11 the wrapped Beacon is counted on both the emit and consume side");
    check(after_beacon.channel_normalized == before_beacon.channel_normalized,
          "A11 a wrapped frame is not counted as a channel normalisation");
    check(after_beacon.payload_rejected_unknown_category ==
              before_beacon.payload_rejected_unknown_category,
          "A11 a relayed Beacon is not rejected as an unknown category");

    // (b) a unicast management frame (NodeMap) keeps type, channel and MACs.
    const std::size_t beta_nodemap_base = beta.raw_count();
    alpha.send(citra_wifi_bytes(*alpha_mac, *beta_mac, payload,
                                citra_room::FrameType::NodeMap, 11));
    const bool nodemap_delivered =
        drive(gateway, {&alpha, &beta},
              [&] { return beta.raw_count() > beta_nodemap_base; }, 4000);
    verify(nodemap_delivered, "A11 a relayed unicast NodeMap reaches its destination");
    {
        const auto* wifi =
            std::get_if<citra_room::WifiPacket>(&beta.messages()[beta_nodemap_base]);
        check(wifi != nullptr && wifi->type == citra_room::FrameType::NodeMap &&
                  wifi->channel == 11 && wifi->data == payload,
              "A11 the relayed NodeMap keeps its type, channel and payload");
        check(wifi != nullptr && wifi->transmitter == *alpha_mac &&
                  wifi->destination == *beta_mac,
              "A11 the relayed NodeMap keeps the unicast transmitter and destination");
    }
    check(alpha.wifi_frames() == 0, "A11 relayed WifiPackets are not echoed back to the sender");

    // (e) a CRLY wrapper with an out of range frame type is refused and counted.
    const auto alpha_identity = identity_for(gateway, "alpha-relay");
    const auto beta_identity = identity_for(gateway, "beta-relay");
    verify(alpha_identity.has_value() && beta_identity.has_value(),
           "A11 relay both identities are known");
    const std::uint64_t alpha_id = client_id_for(gateway, "alpha-relay");
    room_client::Bytes bad_plain{0x43, 0x52, 0x4C, 0x59, 0x01, 0x06, 0x00};
    bad_plain.insert(bad_plain.end(), payload.begin(), payload.end());
    room_client::ProxyPacket bad;
    bad.local.family = room_client::Domain::Inet;
    bad.local.ip = beta_identity->fake_ip;
    bad.local.port = 0;
    bad.remote.family = room_client::Domain::Inet;
    bad.remote.ip = alpha_identity->fake_ip;
    bad.remote.port = 0;
    bad.protocol = room_client::SocketProtocol::Udp;
    bad.broadcast = false;
    bad.data = compress_payload(bad_plain);
    {
        const auto before = gateway.counters();
        const std::size_t alpha_baseline = alpha.raw_count();
        const bool accepted = gateway.inject_room_message_for_test(alpha_id, bad);
        drive(gateway, {&alpha, &beta}, [&] { return false; }, 300);
        const auto after = gateway.counters();
        check(accepted && after.peer_relay_bad_wrapper == before.peer_relay_bad_wrapper + 1,
              "A11 a CRLY wrapper with an out of range frame type is refused and counted");
        check(alpha.raw_count() == alpha_baseline,
              "A11 the bad wrapper produced no Citra frame");
    }

    dump_documents(gateway, "a11_peer_relay");
    gateway.close();
    std::ifstream relay_trace_in(relay_trace_path, std::ios::binary);
    const std::string relay_trace((std::istreambuf_iterator<char>(relay_trace_in)),
                                  std::istreambuf_iterator<char>());
    check(relay_trace.find("\"wifi_channel\":6") != std::string::npos,
          "A11 Beacon trace records the radio channel as wifi_channel");
    check(relay_trace.find("\"channel\":6") == std::string::npos &&
              relay_trace.find("\"channel\":\"A\"") != std::string::npos,
          "A11 radio channel does not overwrite trace identity channel");
}

void group_b6_invalid_node_state() {
    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-node-validation";
    const citra_room::MacAddress mac{2,0,0,0,0,9};
    citra_gateway::ControlBridge bridge(options, room_client::IPv4{10,83,0,9}, mac);
    bridge.start();
    citra_gateway::LdnContext context;
    context.have_mapped_mac = true;
    context.mapped_mac = citra_room::MacAddress{2,0,0,0,0,1};
    room_client::LdnPacket packet;
    packet.type = room_client::LdnType::Connect;
    packet.local_ip = room_client::IPv4{10,83,0,1};
    packet.data.assign(64,0); // valid empty username, fallback MAC permitted
    const auto valid = packet.data;
    for (int invalid = 0; invalid < 2; ++invalid) {
        packet.data = valid;
        if (invalid == 0) packet.data[11] = 2; // invalid connected enum
        else std::fill(packet.data.begin()+12,packet.data.begin()+45,'x'); // no NUL
        auto result = bridge.on_ldn(packet,context);
        check(!result.accepted && result.emissions.empty() && bridge.station_count()==0,
              "B6 invalid Connect cannot use a mapped MAC to bypass body validation");
    }
    packet.data = valid;
    auto joined = bridge.on_ldn(packet,context);
    check(joined.accepted && bridge.station_count()==1 && !joined.emissions.empty(),
          "B6 valid Connect after malformed attempts still allocates the first station");
    check(bridge.stations()[0].node_id==1 && bridge.stations()[0].mac==context.mapped_mac,
          "B6 legal MAC fallback is retained without consuming IDs on rejected Connect");
    // V-243: the cross-game session phase advances on the first admission and
    // returns to ApStandby when the last guest leaves.
    check(std::string(bridge.session_phase()) == "StationAdmitted",
          "B6 the session phase is StationAdmitted after the first Connect");
    packet.type = room_client::LdnType::Disconnect;
    for (int invalid = 0; invalid < 2; ++invalid) {
        packet.data = valid;
        if (invalid == 0) packet.data[11] = 2;
        else std::fill(packet.data.begin()+12,packet.data.begin()+45,'x');
        auto result = bridge.on_ldn(packet,context);
        check(!result.accepted && result.emissions.empty() && bridge.station_count()==1,
              "B6 invalid Disconnect cannot remove an existing station or emit sync");
    }
    packet.data = valid;
    auto departed = bridge.on_ldn(packet,context);
    check(departed.accepted && bridge.station_count()==0,
          "B6 valid Disconnect still succeeds after rejected bodies");
    check(std::string(bridge.session_phase()) == "ApStandby",
          "B6 the session phase returns to ApStandby when the hall dissolves");
    check(bridge.counters().at("ldn_bad_body")==4 &&
              bridge.counters().at("ldn_connect_accepted")==1 &&
              bridge.counters().at("ldn_disconnect_accepted")==1 &&
              bridge.counters().at("ldn_mac_filled")==1,
          "B6 malformed bodies are rejected and never counted as accepted metadata fallback");
}

// V-112: the synthetic host's game-layer dialogue (EtherType 0x876d).  A real
// MHXX host answers the guest's EAPoL-Start with SecureData frames and the
// guest waits for that traffic; the gateway replays captured host frames from
// Options::game_script.  These cases pin the trigger arithmetic, the byte
// identity of the replayed payload and the byte-for-byte unchanged default.
// V-239: cross-game identity override.  A real MHGU client filters ScanResp on
// IntentId.local_communication_id and reads the private advertise structure;
// these pin the override and the verbatim advertise carry.
void group_b8_ldn_identity_override() {
    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-ldn-override";
    options.ldn_comm_id_override = 0x0100770008dd8000ULL;
    options.ldn_advertise_data = {0x43, 0x7f, 0xe9, 0x4d, 0x00, 0x11};
    const citra_room::MacAddress mac{2, 0, 0, 0, 0, 8};
    citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 83, 0, 8}, mac);
    bridge.start();
    citra_gateway::LdnContext context;
    context.have_mapped_mac = true;
    context.mapped_mac = citra_room::MacAddress{2, 0, 0, 0, 0, 2};
    room_client::LdnPacket scan;
    scan.type = room_client::LdnType::Scan;
    scan.local_ip = room_client::IPv4{10, 83, 0, 2};
    const auto result = bridge.on_ldn(scan, context);
    check(result.accepted && !result.emissions.empty(),
          "B8 an override-options Scan still produces emissions");
    bool seen = false;
    for (const auto& emission : result.emissions) {
        if (emission.kind != "room.scan_resp") {
            continue;
        }
        seen = true;
        const std::string hex = hex_of(emission.ldn_body);
        check(hex_slice(hex, 0x00, 8) == "0080dd0800770001",
              "B8 the ScanResponse advertises the overridden communication id");
        check(hex_slice(hex, 0x26A, 2) == "0600",
              "B8 the ScanResponse advertises the override advertise size (6)");
        check(hex_slice(hex, 0x26C, 6) == "437fe94d0011",
              "B8 the override advertise bytes are carried verbatim");
        // V-239 measured: node_count_max presents the MHGU hub capacity 4.
        check(hex_slice(hex, 0x66, 1) == "04",
              "B8 the ScanResponse node_count_max is the measured MHGU capacity");
    }
    check(seen, "B8 the emissions include a room.scan_resp");
    check(bridge.counters().at("scan_resp_emitted") == 1,
          "B8 the scan_resp counter increments under override options");
}

// V-245: the C++ port of the V-242 heartbeat-pair learner, plus its wiring into
// the control bridge through the decompressed inbound Proxy path.
void group_b9_heartbeat_learner() {
    const citra_control::HeartbeatLearnerOptions defaults{};
    auto make_observation = [](std::uint8_t kind, std::array<std::uint8_t, 4> sender, int i) {
        const std::uint32_t t = (static_cast<std::uint32_t>(i) * 7919u + 17u) & 0xFFFFu;
        const std::uint32_t u = (static_cast<std::uint32_t>(i) * 6553u + 11u) & 0xFFFFu;
        return citra_control::HeartbeatObservation{kind, sender, static_cast<std::uint16_t>(t),
                                                   static_cast<std::uint16_t>(t ^ 0x5A5A),
                                                   static_cast<std::uint16_t>(u ^ 0xA5A5)};
    };

    // A valid pair: two kinds, one sender each, high-entropy time fields.
    std::vector<citra_control::HeartbeatObservation> packets;
    const std::array<std::uint8_t, 4> host_sender{1, 2, 3, 4};
    const std::array<std::uint8_t, 4> guest_sender{5, 6, 7, 8};
    for (int i = 0; i < 40; ++i) {
        packets.push_back(make_observation(0xA0, host_sender, i));
        packets.push_back(make_observation(0xDA, guest_sender, i + 500));
    }
    {
        const auto learned = citra_control::learn_heartbeat_pair(packets, defaults);
        check(learned.learned && learned.total_packets == packets.size()
                  && learned.candidates.size() == 2,
              "B9 the learner pairs two single-sender high-entropy kinds");
        check(learned.candidates[0].kind == 0xA0 && learned.candidates[0].sender == host_sender,
              "B9 the first candidate carries the host kind and sender");
        check(learned.candidates[1].kind == 0xDA && learned.candidates[1].sender == guest_sender,
              "B9 the second candidate carries the guest kind and sender");
    }
    // Kinds seen from several senders are data, never heartbeats.
    {
        auto mixed = packets;
        for (std::size_t i = 0; i < 25; ++i) {
            mixed.push_back(make_observation(0xA0, guest_sender, static_cast<int>(1000 + i)));
        }
        const auto learned = citra_control::learn_heartbeat_pair(mixed, defaults);
        check(!learned.learned && learned.candidates.size() == 1,
              "B9 a kind observed from two senders is excluded from candidacy");
    }
    // Low-entropy time fields fail the gate.
    {
        auto flat = packets;
        for (auto& observation : flat) {
            observation.rel_time = 0;
            observation.time_echo = 0;
        }
        const auto learned = citra_control::learn_heartbeat_pair(flat, defaults);
        check(!learned.learned && learned.candidates.empty(),
              "B9 all-zero time fields fail the entropy gate");
    }
    // Malformed input throws; options out of range throw.
    bool threw = false;
    try {
        const citra_control::HeartbeatLearnerOptions options{};
        citra_control::learn_heartbeat_pair({}, options);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    check(threw, "B9 an empty observation vector is rejected");
    threw = false;
    try {
        citra_control::HeartbeatLearnerOptions bad{};
        bad.min_share = 0.0;
        citra_control::learn_heartbeat_pair(packets, bad);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    check(threw, "B9 a zero share threshold is rejected");

    // ControlBridge integration: observations flow through the decompressed
    // Proxy path and the pair is learned exactly once.
    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b9";
    const citra_room::MacAddress mac{2, 0, 0, 0, 0, 11};
    citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 83, 0, 11}, mac);
    const std::array<std::uint8_t, 4> bridge_sender{10, 83, 0, 11};
    for (int i = 0; i < 40; ++i) {
        const auto a = make_observation(0x23, bridge_sender, i);
        bridge.observe_heartbeat(a.sender, a.kind, a.seq, a.rel_time, a.time_echo);
        const auto b = make_observation(0xCC, {10, 83, 0, 12}, i + 500);
        bridge.observe_heartbeat(b.sender, b.kind, b.seq, b.rel_time, b.time_echo);
    }
    check(bridge.heartbeat_pair_learned(),
          "B9 the control bridge learns the heartbeat pair from observed packets");
    check(bridge.counters().at("heartbeat_pair_learned") == 1,
          "B9 the learned counter increments exactly once (replays are idempotent)");
    check(bridge.counters().at("heartbeat_observations") == 80,
          "B9 every observation is counted");
}

// V-245: SyncNetwork fan-out and NodeMap behaviour guards for the cross-game
// state machine (docs/MH-SESSION-CONVERSION-STATE-MACHINE.md §2).
void group_b10_sync_fanout() {
    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b10";
    const citra_room::MacAddress mac{2, 0, 0, 0, 0, 20};
    citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 83, 0, 20}, mac);
    bridge.start();

    citra_gateway::LdnContext ctx_a;
    ctx_a.have_mapped_mac = true;
    ctx_a.mapped_mac = citra_room::MacAddress{2, 0, 0, 0, 0, 21};
    citra_gateway::LdnContext ctx_b;
    ctx_b.have_mapped_mac = true;
    ctx_b.mapped_mac = citra_room::MacAddress{2, 0, 0, 0, 0, 22};

    room_client::LdnPacket scan;
    scan.type = room_client::LdnType::Scan;
    scan.local_ip = room_client::IPv4{10, 83, 0, 21};
    (void)bridge.on_ldn(scan, ctx_a); // AP_STANDBY answers the first scan

    room_client::LdnPacket connect1;
    connect1.type = room_client::LdnType::Connect;
    connect1.local_ip = room_client::IPv4{10, 83, 0, 21};
    connect1.data.assign(64, 0);
    const auto admitted1 = bridge.on_ldn(connect1, ctx_a);
    check(admitted1.accepted && std::string(bridge.session_phase()) == "StationAdmitted",
          "B10 the first guest admission advances the session phase");

    // The first admission fans SyncNetwork out to every connected client --
    // which at this instant is only the connecting guest itself.
    std::size_t first_sync = 0;
    for (const auto& emission : admitted1.emissions) {
        if (emission.kind == "room.sync_network") {
            ++first_sync;
        }
    }
    check(first_sync >= 1, "B10 the first admission emits at least one SyncNetwork");

    // Second guest: the fan-out must now reach BOTH clients (M4 spec rule:
    // every Connect/Disconnect pushes one unicast SyncNetwork per client).
    room_client::LdnPacket connect2;
    connect2.type = room_client::LdnType::Connect;
    connect2.local_ip = room_client::IPv4{10, 83, 0, 22};
    connect2.data.assign(64, 0);
    const auto admitted2 = bridge.on_ldn(connect2, ctx_b);
    check(admitted2.accepted, "B10 the second guest admission is accepted");
    std::size_t second_sync = 0;
    bool reaches_first = false;
    bool reaches_second = false;
    for (const auto& emission : admitted2.emissions) {
        if (emission.kind != "room.sync_network") {
            continue;
        }
        ++second_sync;
        if (emission.ldn_remote_ip == room_client::IPv4{10, 83, 0, 21}) {
            reaches_first = true;
        }
        if (emission.ldn_remote_ip == room_client::IPv4{10, 83, 0, 22}) {
            reaches_second = true;
        }
    }
    check(second_sync == 2, "B10 the second admission emits two unicast SyncNetwork frames");
    check(reaches_first && reaches_second,
          "B10 both connected clients receive their own SyncNetwork copy");

    // Documented V-243 pending proof: station admission currently emits no
    // Citra-side NodeMap (the presentation linkage is not implemented).  Guard
    // the current behaviour so any future change is a conscious decision.
    std::size_t nodemap = 0;
    for (const auto& emission : admitted2.emissions) {
        if (emission.kind == "citra.node_map") {
            ++nodemap;
        }
    }
    check(nodemap == 0,
          "B10 station admission emits no Citra NodeMap yet (V-243 pending proof)");

    // First guest leaves: the remaining client gets one unicast SyncNetwork.
    room_client::LdnPacket leave;
    leave.type = room_client::LdnType::Disconnect;
    leave.local_ip = room_client::IPv4{10, 83, 0, 21};
    leave.data.assign(64, 0);
    const auto departed1 = bridge.on_ldn(leave, ctx_a);
    std::size_t leave_sync = 0;
    for (const auto& emission : departed1.emissions) {
        if (emission.kind == "room.sync_network") {
            ++leave_sync;
        }
    }
    check(leave_sync == 1,
          "B10 the first Disconnect notifies the remaining client (one unicast SyncNetwork)");
    check(std::string(bridge.session_phase()) == "StationAdmitted",
          "B10 the phase stays StationAdmitted while a guest remains");
    // Last guest leaves: the fan-out collapses (nobody left to notify) and the
    // phase returns to ApStandby.
    room_client::LdnPacket leave2;
    leave2.type = room_client::LdnType::Disconnect;
    leave2.local_ip = room_client::IPv4{10, 83, 0, 22};
    leave2.data.assign(64, 0);
    (void)bridge.on_ldn(leave2, ctx_b);
    check(std::string(bridge.session_phase()) == "ApStandby",
          "B10 the phase returns to ApStandby once every guest is gone");
}

// V-264: the host broadcasts its member table once, at hall creation, normally
// before any Yuzu member has connected.  The payload waits in a bounded buffer
// and is flushed into the same emission list as the Connect handling.
void group_b13_pending_host_flush() {
    const std::array<std::uint8_t, 4> xx_host{0xb3, 0x5e, 0xe2, 0x7f};
    const std::array<std::uint8_t, 4> gu_host{0xc0, 0xa8, 0x02, 0x2f};
    const citra_room::MacAddress mac{2, 0, 0, 0, 0, 34};
    const citra_room::Bytes body = bytes_from_hex(
        "01114900000000000000000002000000"
        "e6147194d33f87880100000000000000"
        "b35ee27f3039000000");
    citra_room::Bytes packet{0x32, 0xab, 0x98, 0x64, 0x01, 0x01, 0x00, 0x00,
                             0x11, 0x2e, 0x00, 0x00,
                             0x08, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x00, 0x00};
    packet.insert(packet.end(), xx_host.begin(), xx_host.end());
    packet.insert(packet.end(), {0x03, 0x00, 0x30, 0x39});
    packet.insert(packet.end(), 4, 0x00);
    packet.insert(packet.end(), body.begin(), body.end());
    citra_room::Bytes secure_head(22, 0x00);
    secure_head[0] = 0xaa;
    secure_head[1] = 0xaa;
    secure_head[2] = 0x03;
    secure_head[6] = 0x87;
    secure_head[7] = 0x6d;
    citra_room::Bytes payload = secure_head;
    payload.insert(payload.end(), packet.begin(), packet.end());

    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b13";
    options.ldn_announce_forward = true;
    options.ldn_identity_pairs.push_back({xx_host, gu_host});
    citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 83, 0, 36}, mac);
    bridge.start();
    check(bridge.on_citra_game_payload(payload).empty() &&
              bridge.counters().at("announce_prereq_rejected") == 1 &&
              bridge.counters().at("announce_host_pending") == 1,
          "B13 a host payload without a station is buffered, not dropped");

    citra_gateway::LdnContext ctx;
    ctx.have_mapped_mac = true;
    ctx.mapped_mac = citra_room::MacAddress{2, 0, 0, 0, 0, 35};
    room_client::LdnPacket scan;
    scan.type = room_client::LdnType::Scan;
    scan.local_ip = room_client::IPv4{10, 83, 0, 37};
    (void)bridge.on_ldn(scan, ctx);
    room_client::LdnPacket connect;
    connect.type = room_client::LdnType::Connect;
    connect.local_ip = room_client::IPv4{10, 83, 0, 37};
    connect.data.assign(64, 0);
    const auto handling = bridge.on_ldn(connect, ctx);
    int proxy_count = 0;
    for (const auto& emission : handling.emissions) {
        if (emission.room_proxy) {
            ++proxy_count;
            check(emission.kind == "room.proxy.announce.host" && !emission.to_citra,
                  "B13 the flushed emission keeps the host proxy kind");
            const std::string forwarded = hex_of(emission.proxy_data);
            check(hex_slice(forwarded, 0, 4) == "32ab9864" &&
                      hex_slice(forwarded, 64, 4) == "c0a8022f",
                  "B13 the flushed frame is translated, not replayed raw");
        }
    }
    check(proxy_count == 1, "B13 the station admission flushes exactly one host proxy frame");
    check(bridge.counters().at("announce_host_flushed") == 1 &&
              bridge.counters().at("announce_host_payloads") == 1 &&
              bridge.counters().at("announce_forwarded") == 1,
          "B13 the flush is counted as a forwarded host payload");
}
// V-266: reverse UDS association injection.  Citra's nwm_uds only answers game
// traffic for MACs that sit in its node_map, and MHXX decides "somebody joined
// the hall" from that same map -- until the gateway presents the admitted Yuzu
// station to Citra as a joining UDS guest the map holds only Citra itself and no
// Pia byte is ever produced.  This group drives the synthesised guest handshake
// (SEQ1 -> AssociationResponse -> EAPoL-Start -> Logoff) through the bridge API
// and checks the bytes, the addresses and every counter.  It is structural only:
// no Citra, no game and no wire participate.
void group_b14_guest_inject() {
    const citra_room::MacAddress citra_mac{2, 0, 0, 0, 0, 40};
    const citra_room::MacAddress station_mac{2, 0, 0, 0, 0, 41};
    // Successful AssociationResponse exactly as GenerateAssocResponseFrame writes
    // it: capabilities 0x0431, status 0, assoc_id 1 | 0xC000, SSID tag 0 + 8
    // uppercase-hex ASCII characters of the network id.
    const citra_room::Bytes assoc_ok = bytes_from_hex("3104000001c000083030303030303030");
    const citra_room::Bytes assoc_refused =
        bytes_from_hex("3104010001c000083030303030303030");

    const auto admit = [](citra_gateway::ControlBridge& bridge,
                          const citra_room::MacAddress& mac, const room_client::IPv4& ip) {
        citra_gateway::LdnContext ctx;
        ctx.have_mapped_mac = true;
        ctx.mapped_mac = mac;
        room_client::LdnPacket scan;
        scan.type = room_client::LdnType::Scan;
        scan.local_ip = ip;
        (void)bridge.on_ldn(scan, ctx);
        room_client::LdnPacket connect;
        connect.type = room_client::LdnType::Connect;
        connect.local_ip = ip;
        connect.data.assign(64, 0);
        return bridge.on_ldn(connect, ctx);
    };
    const auto beacon = [&](const citra_room::MacAddress& mac) {
        citra_room::WifiPacket wifi;
        wifi.type = citra_room::FrameType::Beacon;
        wifi.channel = 11;
        wifi.transmitter = mac;
        wifi.destination = citra_room::broadcast_mac;
        // The payload is opaque on this path: only the frame type carries the
        // "Citra is hosting" fact.
        wifi.data.assign(64, 0x00);
        return wifi;
    };
    const auto citra_wifi = [&](citra_room::FrameType type, const citra_room::MacAddress& to,
                                const citra_room::Bytes& data) {
        citra_room::WifiPacket wifi;
        wifi.type = type;
        wifi.channel = 11;
        wifi.transmitter = citra_mac;
        wifi.destination = to;
        wifi.data = data;
        return wifi;
    };
    const auto count_kind = [](const std::vector<citra_gateway::ControlEmission>& emissions,
                               const std::string& kind) {
        std::size_t count = 0;
        for (const auto& emission : emissions) {
            if (emission.kind == kind) {
                ++count;
            }
        }
        return count;
    };
    const auto find_kind = [](const std::vector<citra_gateway::ControlEmission>& emissions,
                              const std::string& kind) -> const citra_gateway::ControlEmission* {
        for (const auto& emission : emissions) {
            if (emission.kind == kind) {
                return &emission;
            }
        }
        return nullptr;
    };
    const auto logoff = [&]() {
        citra_control::EapolLogoffPacket packet;
        packet.assigned_node_id = 2;
        packet.client_mac_address = station_mac;
        packet.connected_nodes = 2;
        packet.max_nodes = 4;
        packet.nodes[0].network_node_id = 1;
        packet.nodes[1].network_node_id = 2;
        packet.nodes[1].username[0] = 'S';
        return citra_control::build_eapol_logoff_frame(packet);
    }();

    // --- gate off: the historical behaviour, byte for byte ------------------
    {
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b14-off";
        citra_gateway::ControlBridge off(options, room_client::IPv4{10, 83, 1, 40}, citra_mac);
        off.start();
        (void)off.on_citra_wifi(beacon(citra_mac), 10);
        const auto handling = admit(off, station_mac, room_client::IPv4{10, 83, 1, 41});
        check(handling.accepted &&
                  count_kind(handling.emissions, "citra.guest.auth_seq1") == 0 &&
                  off.counters().at("guest_inject_started") == 0,
              "B14 with the gate off an admitted station injects no authentication frame");
        check(off.station_count() == 1 &&
                  off.stations()[0].guest_inject_state ==
                      citra_gateway::GuestInjectionState::Idle &&
                  !off.stations()[0].have_uds_node_id,
              "B14 with the gate off the station stays Idle and gains no node id");
        // With the gate off Citra's AssociationResponse keeps its historical drop
        // (the Beacon above is one such drop itself, so compare against the
        // running total rather than an absolute count).
        const auto before = off.counters().at("citra_wrong_direction");
        const auto dropped =
            off.on_citra_wifi(citra_wifi(citra_room::FrameType::AssociationResponse,
                                         station_mac, assoc_ok),
                              20);
        check(dropped.empty() && off.counters().at("citra_wrong_direction") == before + 1 &&
                  off.counters().at("guest_inject_assoc_ok") == 0,
              "B14 with the gate off an AssociationResponse is still a wrong-direction drop");
    }

    // --- gate on, but no proof that Citra is the UDS host -------------------
    {
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b14-nohost";
        options.ldn_guest_inject = true;
        citra_gateway::ControlBridge nohost(options, room_client::IPv4{10, 83, 1, 40}, citra_mac);
        nohost.start();
        const auto handling = admit(nohost, station_mac, room_client::IPv4{10, 83, 1, 41});
        check(handling.accepted &&
                  count_kind(handling.emissions, "citra.guest.auth_seq1") == 0 &&
                  nohost.counters().at("guest_inject_no_host") == 1 &&
                  nohost.counters().at("guest_inject_started") == 0,
              "B14 without a Citra Beacon the injection is not armed and says why");
        check(!nohost.game_return_station(room_client::IPv4{10, 83, 1, 41}).has_value(),
              "B14 game return requires a seen Citra Beacon");
    }

    // --- the full synthesised sequence -------------------------------------
    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b14";
    options.ldn_guest_inject = true;
    citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 83, 1, 40}, citra_mac);
    bridge.start();
    (void)bridge.on_citra_wifi(beacon(citra_mac), 10);
    check(bridge.counters().at("citra_beacon_seen") == 1 &&
              bridge.stations().empty(),
          "B14 the Citra Beacon alone does not arm anything (no station yet)");
    const auto admitted = admit(bridge, station_mac, room_client::IPv4{10, 83, 1, 41});
    check(admitted.accepted && bridge.station_count() == 1 &&
              bridge.stations()[0].mac == station_mac,
          "B14 the fixture admits one Yuzu station");
    const auto* auth = find_kind(admitted.emissions, "citra.guest.auth_seq1");
    check(auth != nullptr && auth->to_citra &&
              auth->citra_type == citra_room::FrameType::Authentication,
          "B14 the admission answers with one Citra Authentication emission");
    check(auth != nullptr && auth->citra_data.size() == 6 &&
              hex_of(auth->citra_data) == "000001000000",
          "B14 the injected frame is the 6 byte Authentication SEQ1 body");
    check(auth != nullptr && auth->have_citra_addresses &&
              auth->citra_transmitter == bridge.stations()[0].mac &&
              auth->citra_destination == bridge.bssid(),
          "B14 the SEQ1 is sourced from the station MAC and addressed to the bssid");
    check(bridge.stations()[0].guest_inject_state ==
                  citra_gateway::GuestInjectionState::AwaitAssocResp &&
              bridge.counters().at("guest_inject_started") == 1 &&
              bridge.counters().at("guest_inject_auth_seq1_emitted") == 1,
          "B14 the station waits for an AssociationResponse and the injection is counted");

    // Citra answers SEQ1 with SEQ2 (and the AssociationResponse below).
    const auto seq2_out = bridge.on_citra_wifi(
        citra_wifi(citra_room::FrameType::Authentication, station_mac,
                   bytes_from_hex("000002000000")),
        20);
    check(seq2_out.empty() && bridge.counters().at("guest_inject_auth_seq2") == 1 &&
              bridge.stations()[0].guest_inject_state ==
                  citra_gateway::GuestInjectionState::AwaitAssocResp,
          "B14 Citra's SEQ2 is recorded and does not advance the machine");

    // The successful AssociationResponse triggers the EAPoL-Start.
    const auto start_out = bridge.on_citra_wifi(
        citra_wifi(citra_room::FrameType::AssociationResponse, station_mac, assoc_ok), 30);
    const auto* start = find_kind(start_out, "citra.guest.eapol_start");
    check(start_out.size() == 1 && start != nullptr && start->to_citra &&
              start->citra_type == citra_room::FrameType::Data,
          "B14 a successful AssociationResponse answers with one EAPoL-Start Data frame");
    check(start != nullptr && start->citra_data.size() == 56 &&
              hex_of(start->citra_data) ==
                  "aaaa03000000888e" "0201" "0001" "0001" "0000" + std::string(80, '0'),
          "B14 the EAPoL-Start echoes the masked association id and declares node id 0");
    check(start != nullptr && start->citra_transmitter == bridge.stations()[0].mac &&
              start->citra_destination == bridge.bssid(),
          "B14 the EAPoL-Start keeps the station's source MAC");
    check(bridge.stations()[0].guest_inject_state ==
                  citra_gateway::GuestInjectionState::AwaitLogoff &&
              bridge.counters().at("guest_inject_assoc_ok") == 1 &&
              bridge.counters().at("guest_inject_eapol_start_emitted") == 1,
          "B14 the station now waits for Citra's EAPoL-Logoff");

    // The Logoff carries the node id Citra assigned and the served MAC.
    check(logoff.ok(), "B14 the fixture builds an EAPoL-Logoff frame");
    const auto logoff_out = bridge.on_citra_eapol(logoff.value, 40);
    check(logoff_out.empty() && bridge.stations()[0].have_uds_node_id &&
              bridge.stations()[0].uds_node_id == 2 &&
              bridge.stations()[0].guest_inject_state == citra_gateway::GuestInjectionState::Done,
          "B14 the EAPoL-Logoff hands the station Citra's assigned node id");
    check(bridge.counters().at("guest_inject_logoff_ok") == 1 &&
              bridge.counters().at("guest_inject_logoff_unmatched") == 0 &&
              bridge.counters().at("guest_inject_timeout") == 0 &&
              bridge.counters().at("eapol_rejected") == 0 &&
              bridge.counters().at("guest_inject_emit_failed") == 0,
          "B14 the consumed Logoff is counted once and never reaches the peer-side path");

    const room_client::IPv4 station_ip{10, 83, 1, 41};
    const auto admitted_station = bridge.game_return_station(station_ip);
    check(admitted_station.has_value() && admitted_station->mac == station_mac &&
              admitted_station->uds_node_id == 2 && admitted_station->have_guest_identity_word,
          "B14 game return resolves only the completed injected station");
    check(!bridge.game_return_station(room_client::IPv4{10, 83, 1, 99}).has_value(),
          "B14 game return rejects an unknown fake IP");

    // Reverse translation keeps the MH packet shape and rewrites only the
    // measured sender/body address words. The explicit pair's GU word is the
    // session fake IP; no host identity is inferred without that pair.
    citra_gateway::ControlOptions return_options;
    return_options.room_name = "synthetic-b14-game-return";
    return_options.ldn_guest_inject = true;
    const room_client::IPv4 session_ip{10, 83, 1, 40};
    const std::array<std::uint8_t, 4> xx_host{1, 2, 3, 4};
    const std::array<std::uint8_t, 4> gu_host{10, 83, 1, 40};
    return_options.ldn_identity_pairs.push_back({xx_host, gu_host});
    citra_gateway::ControlBridge return_bridge(return_options, session_ip, citra_mac);
    return_bridge.start();
    (void)return_bridge.on_citra_wifi(beacon(citra_mac), 10);
    (void)admit(return_bridge, station_mac, station_ip);
    (void)return_bridge.on_citra_wifi(
        citra_wifi(citra_room::FrameType::AssociationResponse, station_mac, assoc_ok), 20);
    (void)return_bridge.on_citra_eapol(logoff.value, 30);
    const citra_room::Bytes original_return{
        0x32, 0xab, 0x98, 0x64, 0x01, 0x00, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 10, 83, 1, 40,
        0x03, 0x00, 0x30, 0x39, 0x20, 0x21, 0x22, 0x23,
        10, 83, 1, 41, 10, 83, 1, 40};
    const citra_room::Bytes original_return_copy = original_return;
    const auto translated_return = return_bridge.translate_game_return(original_return);
    check(translated_return.has_value() &&
              std::equal(translated_return->begin() + 20, translated_return->begin() + 24,
                         xx_host.begin()) &&
              std::equal(translated_return->begin() + 32, translated_return->begin() + 36,
                         admitted_station->guest_identity_word.begin()) &&
              std::equal(translated_return->begin() + 36, translated_return->begin() + 40,
                         xx_host.begin()),
          "B14 reverse translation maps the explicit host pair and admitted station word");
    check(original_return == original_return_copy &&
              translated_return.has_value() && (*translated_return)[4] == original_return[4] &&
              (*translated_return)[5] == original_return[5] &&
              std::equal(translated_return->begin() + 24, translated_return->begin() + 32,
                         original_return.begin() + 24),
          "B14 reverse translation leaves input and all unrelated header bytes unchanged");
    check(!return_bridge.translate_game_return(citra_room::Bytes{0x32, 0xab}).has_value(),
          "B14 reverse translation rejects a truncated MH packet");
    auto bad_magic = original_return;
    bad_magic[0] = 0x33;
    check(!return_bridge.translate_game_return(bad_magic).has_value(),
          "B14 reverse translation rejects a non-MH magic");
    auto bad_route = original_return;
    bad_route[24] = 0x09;
    check(!return_bridge.translate_game_return(bad_route).has_value(),
          "B14 reverse translation rejects routes outside the measured whitelist");
    auto bad_mode = original_return;
    bad_mode[4] = 2;
    check(!return_bridge.translate_game_return(bad_mode).has_value(),
          "B14 reverse translation rejects an unknown packet mode");
    auto bad_kind = original_return;
    bad_kind[5] = 2;
    check(!return_bridge.translate_game_return(bad_kind).has_value(),
          "B14 reverse translation rejects an unknown packet kind");

    citra_gateway::ControlOptions conflict_options = return_options;
    conflict_options.room_name = "synthetic-b14-game-return-conflict";
    conflict_options.ldn_identity_pairs.clear();
    const std::array<std::uint8_t, 4> station_ip_word{10, 83, 1, 41};
    conflict_options.ldn_identity_pairs.push_back({xx_host, station_ip_word});
    citra_gateway::ControlBridge conflict_bridge(conflict_options, session_ip, citra_mac);
    conflict_bridge.start();
    (void)conflict_bridge.on_citra_wifi(beacon(citra_mac), 10);
    (void)admit(conflict_bridge, station_mac, station_ip);
    (void)conflict_bridge.on_citra_wifi(
        citra_wifi(citra_room::FrameType::AssociationResponse, station_mac, assoc_ok), 20);
    (void)conflict_bridge.on_citra_eapol(logoff.value, 30);
    check(!conflict_bridge.translate_game_return(original_return).has_value(),
          "B14 reverse translation fails closed when one source word has conflicting targets");

    citra_gateway::ControlOptions no_inject_options;
    no_inject_options.room_name = "synthetic-b14-game-return-no-inject";
    citra_gateway::ControlBridge no_inject(no_inject_options, session_ip, citra_mac);
    no_inject.start();
    (void)no_inject.on_citra_wifi(beacon(citra_mac), 10);
    (void)admit(no_inject, station_mac, station_ip);
    check(!no_inject.game_return_station(station_ip).has_value(),
          "B14 game return rejects stations when guest injection is disabled");
    citra_room::Bytes unrelated_return(36, 0x5a);
    unrelated_return[0] = 0x32;
    unrelated_return[1] = 0xab;
    unrelated_return[2] = 0x98;
    unrelated_return[3] = 0x64;
    unrelated_return[4] = 1;
    unrelated_return[5] = 0;
    unrelated_return[24] = 0x03;
    unrelated_return[25] = 0x00;
    unrelated_return[26] = 0x30;
    unrelated_return[27] = 0x39;
    const auto unrelated_translated = no_inject.translate_game_return(unrelated_return);
    check(unrelated_translated.has_value() && *unrelated_translated == unrelated_return,
          "B14 reverse translation passes a valid packet through when no identity word matches");
    const auto no_pair_translated = no_inject.translate_game_return(original_return);
    check(no_pair_translated.has_value() && *no_pair_translated == original_return,
          "B14 reverse translation does not infer a host word from the session fake IP");

    citra_gateway::ControlBridge bad_node(return_options, session_ip, citra_mac);
    bad_node.start();
    (void)bad_node.on_citra_wifi(beacon(citra_mac), 10);
    (void)admit(bad_node, station_mac, station_ip);
    (void)bad_node.on_citra_wifi(
        citra_wifi(citra_room::FrameType::AssociationResponse, station_mac, assoc_ok), 20);
    citra_control::EapolLogoffPacket invalid_node_logoff;
    invalid_node_logoff.assigned_node_id = 1;
    invalid_node_logoff.client_mac_address = station_mac;
    const auto invalid_node_frame = citra_control::build_eapol_logoff_frame(invalid_node_logoff);
    check(invalid_node_frame.ok(), "B14 invalid-node fixture builds a Logoff frame");
    (void)bad_node.on_citra_eapol(invalid_node_frame.value, 30);
    check(!bad_node.game_return_station(station_ip).has_value(),
          "B14 game return rejects an injected station with an invalid Citra node id");

    return_bridge.invalidate_game_return_admission();
    check(return_bridge.station_count() == 1 &&
              !return_bridge.game_return_station(station_ip).has_value() &&
              !return_bridge.stations()[0].have_uds_node_id &&
              return_bridge.stations()[0].uds_node_id == 0 &&
              return_bridge.stations()[0].guest_inject_state ==
                  citra_gateway::GuestInjectionState::Idle,
          "B14 invalidation clears return admission without removing the LDN station");
    bridge.mirror_disconnect(station_ip);
    check(!bridge.game_return_station(station_ip).has_value() && bridge.station_count() == 0,
          "B14 game return stops resolving after station disconnect");

    // --- a refused AssociationResponse must never produce an EAPoL-Start ---
    {
        citra_gateway::ControlOptions refused_options;
        refused_options.room_name = "synthetic-b14-refused";
        refused_options.ldn_guest_inject = true;
        citra_gateway::ControlBridge refused(refused_options, room_client::IPv4{10, 83, 1, 40},
                                            citra_mac);
        refused.start();
        (void)refused.on_citra_wifi(beacon(citra_mac), 10);
        (void)admit(refused, station_mac, room_client::IPv4{10, 83, 1, 42});
        const auto denied = refused.on_citra_wifi(
            citra_wifi(citra_room::FrameType::AssociationResponse, station_mac, assoc_refused), 20);
        check(denied.empty() && refused.counters().at("guest_inject_assoc_refused") == 1 &&
                  refused.counters().at("guest_inject_eapol_start_emitted") == 0 &&
                  refused.counters().at("guest_inject_assoc_ok") == 0 &&
                  refused.stations()[0].guest_inject_state ==
                      citra_gateway::GuestInjectionState::Idle,
              "B14 a refused AssociationResponse ends the attempt without an EAPoL-Start");
        // A Logoff arriving anyway must not hand out a node id.
        (void)refused.on_citra_eapol(logoff.value, 30);
        check(!refused.stations()[0].have_uds_node_id &&
                  refused.counters().at("guest_inject_logoff_ok") == 0,
              "B14 a Logoff after the refusal assigns no node id");
    }

    // --- timeout and late frames -------------------------------------------
    {
        citra_gateway::ControlOptions slow_options;
        slow_options.room_name = "synthetic-b14-timeout";
        slow_options.ldn_guest_inject = true;
        citra_gateway::ControlBridge slow(slow_options, room_client::IPv4{10, 83, 1, 40}, citra_mac);
        slow.start();
        (void)slow.on_citra_wifi(beacon(citra_mac), 100);
        (void)admit(slow, station_mac, room_client::IPv4{10, 83, 1, 43});
        const std::uint64_t armed = 100;
        const auto early = slow.tick(armed + citra_gateway::kControlGuestInjectTimeoutMs - 1);
        check(slow.counters().at("guest_inject_timeout") == 0 &&
                  slow.stations()[0].guest_inject_state ==
                      citra_gateway::GuestInjectionState::AwaitAssocResp &&
                  count_kind(early, "citra.guest.auth_seq1") == 0,
              "B14 the injection stays armed one millisecond before the timeout");
        const auto late = slow.tick(armed + citra_gateway::kControlGuestInjectTimeoutMs);
        check(slow.counters().at("guest_inject_timeout") == 1 &&
                  slow.stations()[0].guest_inject_state ==
                      citra_gateway::GuestInjectionState::Idle &&
                  count_kind(late, "citra.guest.eapol_start") == 0,
              "B14 the timeout returns the station to Idle and is counted, not silent");
        // A late AssociationResponse cannot revive the timed-out attempt.
        const auto after = slow.on_citra_wifi(
            citra_wifi(citra_room::FrameType::AssociationResponse, station_mac, assoc_ok), 2000);
        check(after.empty() && slow.counters().at("guest_inject_eapol_start_emitted") == 0 &&
                  slow.counters().at("guest_inject_timeout") == 1,
              "B14 a late AssociationResponse after the timeout sends no EAPoL-Start");
    }

    // --- repeated Connect and a same-MAC station ---------------------------
    {
        citra_gateway::ControlOptions dup_options;
        dup_options.room_name = "synthetic-b14-dup";
        dup_options.ldn_guest_inject = true;
        citra_gateway::ControlBridge dup(dup_options, room_client::IPv4{10, 83, 1, 40}, citra_mac);
        dup.start();
        (void)dup.on_citra_wifi(beacon(citra_mac), 10);
        const auto first = admit(dup, station_mac, room_client::IPv4{10, 83, 1, 44});
        check(count_kind(first.emissions, "citra.guest.auth_seq1") == 1,
              "B14 the first admission of the duplicate fixture injects once");
        const auto again = admit(dup, station_mac, room_client::IPv4{10, 83, 1, 44});
        check(!again.accepted && dup.counters().at("ldn_connect_rejected") == 1 &&
                  count_kind(again.emissions, "citra.guest.auth_seq1") == 0 &&
                  dup.counters().at("guest_inject_started") == 1,
              "B14 a repeated Connect from the same source never arms a second injection");
        const auto twin = admit(dup, station_mac, room_client::IPv4{10, 83, 1, 45});
        check(twin.accepted && count_kind(twin.emissions, "citra.guest.auth_seq1") == 0 &&
                  dup.counters().at("guest_inject_duplicate") == 1 &&
                  dup.counters().at("guest_inject_started") == 1 &&
                  dup.counters().at("guest_inject_auth_seq1_emitted") == 1,
              "B14 a second station declaring the same MAC does not arm a second injection");
    }

    // --- Citra's real Logoff carries no MAC at all --------------------------
    // citra-master's GenerateEAPoLLogoffFrame never writes client_mac_address:
    // uds_data.cpp:349-373 value-initialises the packet and copies only the node
    // records, so its mac_address parameter is dead and the field is six zero
    // bytes on the wire.  The node id must still reach the station, and the
    // attribution must be counted as ordered rather than as a MAC mismatch.
    {
        citra_control::EapolLogoffPacket real_packet;
        real_packet.assigned_node_id = 3;
        // client_mac_address stays all zero, exactly as Citra emits it.
        real_packet.connected_nodes = 2;
        real_packet.max_nodes = 4;
        real_packet.nodes[0].network_node_id = 1;
        real_packet.nodes[2].network_node_id = 3;
        real_packet.nodes[2].username[0] = 'S';
        const auto real_logoff = citra_control::build_eapol_logoff_frame(real_packet);
        check(real_logoff.ok(), "B14 the fixture builds the MAC-less Logoff Citra really sends");
        citra_gateway::ControlOptions real_options;
        real_options.room_name = "synthetic-b14-real-logoff";
        real_options.ldn_guest_inject = true;
        citra_gateway::ControlBridge real(real_options, room_client::IPv4{10, 83, 1, 40}, citra_mac);
        real.start();
        (void)real.on_citra_wifi(beacon(citra_mac), 10);
        (void)admit(real, station_mac, room_client::IPv4{10, 83, 1, 46});
        (void)real.on_citra_wifi(
            citra_wifi(citra_room::FrameType::AssociationResponse, station_mac, assoc_ok), 20);
        const auto real_out = real.on_citra_eapol(real_logoff.value, 30);
        check(real_out.empty() && real.stations()[0].have_uds_node_id &&
                  real.stations()[0].uds_node_id == 3 &&
                  real.stations()[0].guest_inject_state ==
                      citra_gateway::GuestInjectionState::Done,
              "B14 a MAC-less Logoff still hands the station Citra's assigned node id");
        check(real.counters().at("guest_inject_logoff_ordered") == 1 &&
                  real.counters().at("guest_inject_logoff_ok") == 1 &&
                  real.counters().at("guest_inject_logoff_unmatched") == 0 &&
                  real.counters().at("eapol_rejected") == 0,
              "B14 the MAC-less Logoff is counted as ordered attribution, not as a mismatch");
    }

    // --- a Logoff naming an unknown MAC assigns nothing ---------------------
    {
        citra_control::EapolLogoffPacket foreign_packet;
        foreign_packet.assigned_node_id = 4;
        foreign_packet.client_mac_address = citra_room::MacAddress{2, 0, 0, 0, 0, 99};
        foreign_packet.connected_nodes = 2;
        foreign_packet.max_nodes = 4;
        const auto foreign_logoff = citra_control::build_eapol_logoff_frame(foreign_packet);
        check(foreign_logoff.ok(), "B14 the fixture builds a Logoff naming a foreign MAC");
        citra_gateway::ControlOptions foreign_options;
        foreign_options.room_name = "synthetic-b14-foreign-logoff";
        foreign_options.ldn_guest_inject = true;
        citra_gateway::ControlBridge foreign(foreign_options, room_client::IPv4{10, 83, 1, 40},
                                             citra_mac);
        foreign.start();
        (void)foreign.on_citra_wifi(beacon(citra_mac), 10);
        (void)admit(foreign, station_mac, room_client::IPv4{10, 83, 1, 47});
        (void)foreign.on_citra_wifi(
            citra_wifi(citra_room::FrameType::AssociationResponse, station_mac, assoc_ok), 20);
        const auto foreign_out = foreign.on_citra_eapol(foreign_logoff.value, 30);
        check(foreign_out.empty() && !foreign.stations()[0].have_uds_node_id &&
                  foreign.counters().at("guest_inject_logoff_unmatched") == 1 &&
                  foreign.counters().at("guest_inject_logoff_ok") == 0 &&
                  foreign.stations()[0].guest_inject_state ==
                      citra_gateway::GuestInjectionState::AwaitLogoff,
              "B14 a Logoff naming a foreign MAC assigns no node id and stays fail-closed");
    }
}

// V-302: an admitted injected guest must leave Citra's UDS node_map too.
void group_b302_guest_departure() {
    const citra_room::MacAddress host{2, 0, 0, 0, 3, 1};
    const citra_room::MacAddress guest{2, 0, 0, 0, 3, 2};
    const room_client::IPv4 ip{10, 83, 3, 2};
    for (const int mode : {0, 1, 2}) {
        const bool inject = mode != 0;
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b302-departure";
        options.ldn_guest_inject = inject;
        citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 83, 3, 1}, host);
        bridge.start();
        citra_room::WifiPacket beacon;
        beacon.type = citra_room::FrameType::Beacon;
        beacon.transmitter = host;
        beacon.destination = citra_room::broadcast_mac;
        beacon.data.assign(64, 0);
        (void)bridge.on_citra_wifi(beacon, 10);
        citra_gateway::LdnContext context;
        context.have_mapped_mac = true;
        context.mapped_mac = guest;
        room_client::LdnPacket packet;
        packet.local_ip = ip;
        packet.type = room_client::LdnType::Scan;
        (void)bridge.on_ldn(packet, context);
        packet.type = room_client::LdnType::Connect;
        packet.data.assign(64, 0);
        (void)bridge.on_ldn(packet, context);
        if (mode == 2) {
            citra_room::WifiPacket assoc;
            assoc.type = citra_room::FrameType::AssociationResponse;
            assoc.transmitter = host;
            assoc.destination = guest;
            assoc.data = bytes_from_hex("3104000001c000083030303030303030");
            (void)bridge.on_citra_wifi(assoc, 20);
            citra_control::EapolLogoffPacket logoff;
            logoff.assigned_node_id = 2;
            logoff.client_mac_address = guest;
            logoff.connected_nodes = 2;
            logoff.max_nodes = 4;
            const auto built = citra_control::build_eapol_logoff_frame(logoff);
            (void)bridge.on_citra_eapol(built.value, 30);
            check(bridge.stations()[0].guest_inject_state == citra_gateway::GuestInjectionState::Done,
                  "B302 departure fixture reaches completed native association");
        }
        // Even an unfinished authentication can leave a host node_map entry.
        packet.type = room_client::LdnType::Disconnect;
        const auto departed = bridge.on_ldn(packet, context);
        std::size_t deauth = 0;
        for (const auto& emission : departed.emissions) {
            if (emission.to_citra && emission.citra_type == citra_room::FrameType::Deauthentication) {
                ++deauth;
                check(emission.have_citra_addresses && emission.citra_transmitter == guest &&
                          emission.citra_destination == host &&
                          emission.citra_data.empty(),
                      "B302 departure names the admitted guest and uses native empty body");
            }
        }
        check(departed.accepted && bridge.station_count() == 0 && deauth == (inject ? 1u : 0u),
              "B302 accepted departure releases exactly the injected Citra guest");
        check(bridge.on_ldn(packet, context).emissions.empty(),
              "B302 unknown repeated departure emits no Citra frame");
        packet.type = room_client::LdnType::Scan;
        packet.data.clear();
        (void)bridge.on_ldn(packet, context);
        packet.type = room_client::LdnType::Connect;
        packet.data.assign(64, 0);
        const auto rejoined = bridge.on_ldn(packet, context);
        check(rejoined.accepted && bridge.station_count() == 1,
              "B302 same MAC can begin a new admission after departure");
    }
}

void group_b318_reverse_multi_discovery() {
    RoomGuard room(take_port(), 6);
    auto options = gateway_options(take_port(), room);
    options.control_plane_enabled = true;
    options.ldn_gu_host_discovery = true;
    options.ldn_comm_id_override = 0x0100770008dd8000ULL;
    options.have_uds_wlan_comm_id = true;
    options.uds_wlan_comm_id = 0x00197110;
    citra_gateway::Gateway gateway(options);
    gateway.open();
    RawRoomPeer host(room.port(), "gu-host", room_client::network_version);
    CitraPeer alpha, bobby;
    alpha.connect(gateway.port());
    verify(join_peer(gateway, alpha, "Alice", "alice-318"), "B318 first Citra joins");
    bobby.connect(gateway.port());
    verify(join_peer(gateway, bobby, "Bobby", "bobby-318", citra_room::no_preferred_mac,
                     citra_room::network_version, "", {&alpha, &bobby}), "B318 second Citra joins");
    verify(drive(gateway, {&alpha, &bobby}, [&] {
        host.pump(0);
        return host.message_of(room_client::MessageId::JoinSuccess).has_value();
    }), "B318 native GU peer joins");
    const auto host_ip = std::get<room_client::JoinSuccess>(*host.message_of(room_client::MessageId::JoinSuccess)).assigned_ip;
    citra_control::LdnNetworkInfoBody network;
    network.network_id.intent_id.local_communication_id = options.ldn_comm_id_override;
    network.common.bssid = {2, 0, 10, 83, 18, 1};
    network.common.channel = 6;
    network.common.network_type = 2;
    network.ldn.node_count = 2;
    network.ldn.node_count_max = 4;
    for (unsigned i = 0; i < 2; ++i) {
        network.ldn.nodes[i].mac_address = {2, 0, 10, 83, 18, static_cast<std::uint8_t>(i+1)};
        network.ldn.nodes[i].node_id = i;
        network.ldn.nodes[i].is_connected = 1;
        network.ldn.nodes[i].user_name[0] = 'G';
    }
    network.ldn.advertise_data_size = 200;
    network.ldn.advertise_data[8] = network.ldn.advertise_data[0x1c] = network.ldn.advertise_data[0x20] = 1;
    const auto bytes = citra_control::serialize_ldn_network_info(network);
    verify(bytes.ok(), "B318 a native hall with an existing guest serializes");
    auto reply_to_scans = [&] {
        static_cast<void>(host.pump(0));
        // Only answer each real scan once, addressed to its requesting transport.
    };
    std::size_t seen = 0;
    auto serve = [&] {
        reply_to_scans();
        while (seen < host.messages().size()) {
            const auto& message = host.messages()[seen++];
            const auto* scan = std::get_if<room_client::LdnPacket>(&message);
            if (!scan || scan->type != room_client::LdnType::Scan) continue;
            room_client::LdnPacket response;
            response.type = room_client::LdnType::ScanResponse;
            response.local_ip = host_ip;
            response.remote_ip = scan->local_ip;
            response.data = bytes.value;
            host.send(response);
        }
    };
    verify(drive(gateway, {&alpha, &bobby}, [&] {
        serve();
        return alpha.wifi_frames() > 0 && bobby.wifi_frames() > 0;
    }, 4000), "B318 both Citra sessions discover a populated GU hall");
    for (const auto* peer : {&alpha, &bobby}) {
        bool valid = false;
        for (const auto& message : peer->messages()) {
            const auto* wifi = std::get_if<citra_room::WifiPacket>(&message);
            if (!wifi || wifi->type != citra_room::FrameType::Beacon) continue;
            const auto parsed = citra_control::parse_beacon_frame(wifi->data.data(), wifi->data.size(), wifi->transmitter);
            valid = parsed.ok() && parsed.value.network_info.total_nodes == 2;
        }
        check(valid, "B318 each session receives a valid beacon with the real two-member count");
    }
    check(control_counter(gateway, "ldn_non_owner_ignored") == 0,
          "B318 reverse guest replies never use synthetic AP owner suppression");
    dump_documents(gateway, "b318_reverse_multi_discovery");
    gateway.close();
}

void group_b322_gateway_peer_mesh(bool dual = false) {
    RoomGuard room(take_port(),8);
    auto options=gateway_options(take_port(),room);
    options.control_plane_enabled=true;
    options.ldn_dual_host=dual;options.proxy_udp_port=12345;
    options.ldn_gu_host_discovery=options.ldn_gu_host_admission=true;
    options.ldn_comm_id_override=0x0100770008dd8000ULL;
    options.have_uds_wlan_comm_id=true;options.uds_wlan_comm_id=0x00197110;
    citra_gateway::Gateway gateway(options);gateway.open();
    RawRoomPeer host(room.port(),"gu-host",room_client::network_version);
    CitraPeer a,b,c;std::vector<CitraPeer*> watched{&a,&b,&c};
    unsigned index=0;
    std::vector<CitraPeer*> joined;
    for(auto* p:watched) {
        p->connect(gateway.port());
        joined.push_back(p);
        ++index;
        verify(join_peer(gateway,*p,"mesh-"+std::to_string(index),"mesh-console-"+std::to_string(index),
                         citra_room::no_preferred_mac,citra_room::network_version,"",joined),
               "B322 three independent Citra room sessions join");
    }
    verify(drive(gateway,watched,[&]{host.pump(0);return host.message_of(room_client::MessageId::JoinSuccess).has_value();}),
           "B322 native host room session joins");
    const auto host_ip=std::get<room_client::JoinSuccess>(*host.message_of(room_client::MessageId::JoinSuccess)).assigned_ip;
    const citra_room::MacAddress host_mac{2,0,host_ip[0],host_ip[1],host_ip[2],host_ip[3]};
    citra_control::LdnNetworkInfoBody net;
    net.network_id.intent_id.local_communication_id=options.ldn_comm_id_override;
    net.network_id.session_id.low=322;net.common.bssid=host_mac;
    net.common.channel=6;net.common.network_type=2;net.ldn.node_count=1;net.ldn.node_count_max=4;
    net.ldn.nodes[0].mac_address=host_mac;net.ldn.nodes[0].is_connected=1;net.ldn.nodes[0].user_name[0]='H';
    net.ldn.advertise_data_size=200;
    net.ldn.advertise_data[8]=net.ldn.advertise_data[0x1c]=net.ldn.advertise_data[0x20]=1;
    auto sync_all=[&]{for(unsigned i=1;i<net.ldn.node_count;++i){
        room_client::LdnPacket l;l.type=room_client::LdnType::SyncNetwork;l.local_ip=host_ip;
        l.remote_ip=net.ldn.nodes[i].ipv4_address;std::reverse(l.remote_ip.begin(),l.remote_ip.end());
        l.data=citra_control::serialize_ldn_network_info(net).value;host.send(l);
    }};
    std::size_t seen=0;
    auto serve=[&]{host.pump(0);while(seen<host.messages().size()) {
        const auto* l=std::get_if<room_client::LdnPacket>(&host.messages()[seen++]);if(!l)continue;
        if(l->type==room_client::LdnType::Scan) {
            room_client::LdnPacket reply;reply.type=room_client::LdnType::ScanResponse;
            reply.local_ip=host_ip;reply.remote_ip=l->local_ip;
            reply.data=citra_control::serialize_ldn_network_info(net).value;host.send(reply);
        } else if(l->type==room_client::LdnType::Connect) {
            const auto node=citra_control::parse_ldn_node_info(l->data.data(),l->data.size());
            verify(node.ok(),"B322 native Connect preserves its guest identity");
            const auto slot=net.ldn.node_count++;
            verify(slot<4,"B322 native host never overfills four-player hall");
            net.ldn.nodes[slot]=node.value;net.ldn.nodes[slot].node_id=slot;sync_all();
        }
    }};
    verify(drive(gateway,watched,[&]{serve();return a.wifi_frames()&&b.wifi_frames()&&c.wifi_frames();},4000),
           "B322 each peer receives actual room-routed hall discovery");
    index=0;
    for(auto* p:watched) {
        const auto mac=*p->assigned_mac();citra_room::WifiPacket w;
        w.type=citra_room::FrameType::Authentication;w.channel=6;w.transmitter=mac;w.destination=host_mac;
        w.data=citra_control::build_authentication_frame({}).value;
        p->send(citra_room::encode(w,citra_room::Direction::ClientToServer));
        verify(drive(gateway,watched,[&]{
            serve();
            for(const auto& m:p->messages()) {
                if(const auto* f=std::get_if<citra_room::WifiPacket>(&m);
                   f&&f->type==citra_room::FrameType::AssociationResponse) return true;
            }
            return false;
        }),
            "B322 real gateway associates each guest");
        citra_control::EapolStartPacket start;start.association_id=1;
        start.node.friend_code_seed=0x3220000+index;start.node.username[0]='A'+index;
        w.type=citra_room::FrameType::Data;w.data=citra_control::build_eapol_start_frame(start).value;
        p->send(citra_room::encode(w,citra_room::Direction::ClientToServer));++index;
        verify(drive(gateway,watched,[&]{serve();return net.ldn.node_count==index+1;}),"B322 native host admits each guest");
    }
    sync_all();
    verify(drive(gateway,watched,[&]{serve();for(auto* p:watched){bool synced=false;
        for(const auto& m:p->messages())if(const auto* w=std::get_if<citra_room::WifiPacket>(&m);w&&w->type==citra_room::FrameType::Data){
            auto v=citra_control::parse_eapol_logoff_frame(w->data.data(),w->data.size());
            if(v.ok()&&v.value.connected_nodes==4)synced=true;
        }if(!synced)return false;}return true;}),"B322 every guest sees the complete four-player native Sync");
    auto occurrences=[](const CitraPeer& p,const citra_room::Bytes& raw){return std::count(p.raw_frames().begin(),p.raw_frames().end(),raw);};
    const auto proxy_baseline=gateway.counters().proxy_frames_emitted;
    for(unsigned sender=0;sender<3;++sender)for(unsigned receiver=0;receiver<3;++receiver) {
        if(sender==receiver)continue;
        citra_control::SecureDataFrame data;data.header.data_channel=243;
        data.header.src_node_id=sender+2;data.header.dest_node_id=receiver+2;
        data.payload=synthetic_payload(112,static_cast<std::uint8_t>(sender*3+receiver));
        citra_room::WifiPacket w;w.type=citra_room::FrameType::Data;w.channel=6;
        w.transmitter=*watched[sender]->assigned_mac();w.destination=*watched[receiver]->assigned_mac();
        w.data=citra_control::build_secure_data_frame(data).value;
        const auto raw=citra_room::encode(w,citra_room::Direction::ClientToServer);watched[sender]->send(raw);
        verify(drive(gateway,watched,[&]{serve();return occurrences(*watched[receiver],raw)==1;}),
               "B322 each of six directed guest links delivers the exact frame once");
        for(unsigned other=0;other<3;++other)if(other!=receiver)
            check(occurrences(*watched[other],raw)==0,"B322 unicast is not echoed or widened to another guest");
    }
    for(unsigned sender=0;sender<3;++sender) {
        citra_control::SecureDataFrame data;data.header.data_channel=243;data.header.src_node_id=sender+2;
        data.header.dest_node_id=0xffff;data.payload=synthetic_payload(120,0x70+sender);
        citra_room::WifiPacket w;w.type=citra_room::FrameType::Data;w.channel=6;
        w.transmitter=*watched[sender]->assigned_mac();w.destination=citra_room::broadcast_mac;
        w.data=citra_control::build_secure_data_frame(data).value;
        const auto raw=citra_room::encode(w,citra_room::Direction::ClientToServer);watched[sender]->send(raw);
        verify(drive(gateway,watched,[&]{serve();for(unsigned i=0;i<3;++i)if(i!=sender&&occurrences(*watched[i],raw)!=1)return false;return true;}),
               "B322 broadcast reaches both other guests once");
        check(occurrences(*watched[sender],raw)==0,"B322 broadcast is not echoed to its origin");
    }
    check(gateway.counters().proxy_frames_emitted==proxy_baseline,"B322 native XX peer data never crosses the GU codec");
    dump_documents(gateway,"b322_four_player_peer_mesh");gateway.close();
}

void group_b323_dual_host_roles() {
    RoomGuard room(take_port(),8);auto options=gateway_options(take_port(),room);
    options.control_plane_enabled=true;options.ldn_dual_host=true;options.proxy_udp_port=12345;
    options.ldn_comm_id_override=0x0100770008dd8000ULL;
    options.have_uds_wlan_comm_id=true;options.uds_wlan_comm_id=0x00197110;
    citra_gateway::Gateway gateway(options);gateway.open();
    RawRoomPeer native(room.port(),"native-323",room_client::network_version);
    CitraPeer guest,host;guest.connect(gateway.port());
    verify(join_peer(gateway,guest,"dual-guest","dual-guest-console"),"B323 lower-ID idle client joins");
    host.connect(gateway.port());
    verify(join_peer(gateway,host,"dual-host","dual-host-console",citra_room::no_preferred_mac,
                     citra_room::network_version,"",{&guest,&host}),"B323 higher-ID host client joins");
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return native.message_of(room_client::MessageId::JoinSuccess).has_value();}),
           "B323 native GU scanner joins");
    const auto native_ip=std::get<room_client::JoinSuccess>(*native.message_of(room_client::MessageId::JoinSuccess)).assigned_ip;
    const auto host_mac=*host.assigned_mac(),guest_mac=*guest.assigned_mac();
    room_client::IPv4 host_ip{};
    for(const auto& identity:gateway.identities())if(identity.mac==host_mac)host_ip=identity.fake_ip;
    citra_control::BeaconParams params;params.source_mac=host_mac;
    params.network_info.host_mac_address=host_mac;params.network_info.channel=11;
    params.network_info.initialized=1;params.network_info.wlan_comm_id=options.uds_wlan_comm_id;
    params.network_info.network_id=323;params.network_info.attributes=0x8000;
    params.network_info.total_nodes=1;params.network_info.max_nodes=4;
    params.appdata_size=200;params.appdata[0]=1;params.appdata[8]=1;
    params.appdata[0x1c]=params.appdata[0x20]=1;params.appdata[52]='D';
    params.nodes.resize(4);params.nodes[0].network_node_id=1;
    params.nodes[0].friend_code_seed=0x1234567890abcdefULL;params.bitmask=1;
    citra_room::WifiPacket beacon;beacon.type=citra_room::FrameType::Beacon;beacon.channel=11;
    beacon.transmitter=host_mac;beacon.destination=citra_room::broadcast_mac;
    beacon.data=citra_control::build_beacon_frame(params).value;
    const auto beacon_raw=citra_room::encode(beacon,citra_room::Direction::ClientToServer);
    host.send(beacon_raw);
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return std::find(guest.raw_frames().begin(),guest.raw_frames().end(),beacon_raw)!=guest.raw_frames().end();}),
           "B323 valid real host beacon selects the higher-ID host and reaches idle Citra");
    room_client::LdnPacket scan;scan.type=room_client::LdnType::Scan;
    scan.local_ip=native_ip;scan.broadcast=true;native.send(scan);
    auto found_response=[&] {
        for(const auto& message:native.messages()) {
            if(const auto* l=std::get_if<room_client::LdnPacket>(&message);
               l&&l->type==room_client::LdnType::ScanResponse&&l->local_ip==host_ip) return true;
        }
        return false;
    };
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return found_response();}),
           "B323 Yuzu discovers the real Citra hall without a mode restart");
    citra_control::LdnNodeInfo node;node.mac_address={2,0,10,83,23,9};
    node.ipv4_address=native_ip;std::reverse(node.ipv4_address.begin(),node.ipv4_address.end());
    node.user_name[0]='G';node.is_connected=1;node.node_id=1;
    room_client::LdnPacket connect;connect.type=room_client::LdnType::Connect;
    connect.local_ip=native_ip;connect.remote_ip=host_ip;
    connect.data=citra_control::serialize_ldn_node_info(node).value;native.send(connect);
    auto has_auth=[&] {
        for(const auto& m:host.messages()) {
            if(const auto* w=std::get_if<citra_room::WifiPacket>(&m);
               w&&w->type==citra_room::FrameType::Authentication&&w->transmitter==node.mac_address) return true;
        }
        return false;
    };
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return has_auth();}),
           "B323 native GU admission injects authentication into the correct Citra host");
    citra_room::WifiPacket assoc;assoc.type=citra_room::FrameType::AssociationResponse;assoc.channel=11;
    assoc.transmitter=host_mac;assoc.destination=node.mac_address;
    assoc.data=bytes_from_hex("3104000001c000083030303030303030");
    host.send(citra_room::encode(assoc,citra_room::Direction::ClientToServer));
    auto has_start=[&]{for(const auto& m:host.messages())if(const auto* w=std::get_if<citra_room::WifiPacket>(&m);
        w&&w->type==citra_room::FrameType::Data&&w->transmitter==node.mac_address) {
            const auto v=citra_control::parse_eapol_start_frame(w->data.data(),w->data.size());if(v.ok())return true;
        }return false;};
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return has_start();}),"B323 host association reaches the forward guest injection state");
    citra_control::EapolLogoffPacket logoff;logoff.assigned_node_id=2;logoff.client_mac_address=node.mac_address;
    logoff.connected_nodes=2;logoff.max_nodes=4;logoff.nodes[0].network_node_id=1;
    logoff.nodes[0].friend_code_seed=params.nodes[0].friend_code_seed;logoff.nodes[1].network_node_id=2;
    assoc.type=citra_room::FrameType::Data;assoc.data=citra_control::build_eapol_logoff_frame(logoff).value;
    host.send(citra_room::encode(assoc,citra_room::Direction::ClientToServer));
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return control_counter(gateway,"guest_inject_logoff_ok")>0;}),
           "B323 native guest completes association while dual mode stays enabled");
    citra_control::LdnNetworkInfoBody gu_hall;
    gu_hall.network_id.intent_id.local_communication_id=options.ldn_comm_id_override;
    const citra_room::MacAddress native_bssid{2,0,native_ip[0],native_ip[1],native_ip[2],native_ip[3]};
    gu_hall.common.bssid=native_bssid;gu_hall.common.channel=6;gu_hall.common.network_type=2;
    gu_hall.ldn.node_count=1;gu_hall.ldn.node_count_max=4;
    gu_hall.ldn.nodes[0].mac_address=native_bssid;gu_hall.ldn.nodes[0].is_connected=1;
    gu_hall.ldn.nodes[0].user_name[0]='G';gu_hall.ldn.advertise_data_size=200;
    gu_hall.ldn.advertise_data[8]=gu_hall.ldn.advertise_data[0x1c]=gu_hall.ldn.advertise_data[0x20]=1;
    room_client::LdnPacket gu_reply;gu_reply.type=room_client::LdnType::ScanResponse;gu_reply.local_ip=native_ip;
    for(const auto& identity:gateway.identities())if(identity.mac==guest_mac)gu_reply.remote_ip=identity.fake_ip;
    gu_reply.data=citra_control::serialize_ldn_network_info(gu_hall).value;native.send(gu_reply);
    verify(drive(gateway,{&guest,&host},[&] {
        native.pump(0);
        for(const auto& m:guest.messages()) {
            if(const auto* w=std::get_if<citra_room::WifiPacket>(&m);
               w&&w->type==citra_room::FrameType::Beacon&&w->transmitter==native_bssid) return true;
        }
        return false;
    }),"B323 GU hall remains discoverable while a different Citra session hosts");
    // Native local Citra frames do not enter the GU conversion path.
    citra_room::WifiPacket local;local.type=citra_room::FrameType::Authentication;local.channel=11;
    local.transmitter=guest_mac;local.destination=host_mac;local.data=citra_control::build_authentication_frame({}).value;
    const auto local_raw=citra_room::encode(local,citra_room::Direction::ClientToServer);guest.send(local_raw);
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return std::find(host.raw_frames().begin(),host.raw_frames().end(),local_raw)!=host.raw_frames().end();}),
           "B323 local Citra joins the real Citra host directly");
    // V325: complete the actual mixed-hall peer path after GU joined first.
    const auto host_word = citra_gateway::mhxx_identity_word_from_seed(params.nodes[0].friend_code_seed);
    const auto packet = [&](std::size_t size, std::uint8_t kind, std::uint32_t route) {
        citra_room::Bytes bytes(size, 0);
        bytes[0]=0x32;bytes[1]=0xab;bytes[2]=0x98;bytes[3]=0x64;bytes[4]=1;bytes[5]=kind;
        bytes[14]=static_cast<std::uint8_t>((size-32)>>8);bytes[15]=static_cast<std::uint8_t>(size-32);
        bytes[24]=static_cast<std::uint8_t>(route>>24);bytes[25]=static_cast<std::uint8_t>(route>>16);
        bytes[26]=static_cast<std::uint8_t>(route>>8);bytes[27]=static_cast<std::uint8_t>(route);
        return bytes;
    };
    citra_control::SecureDataFrame host_game;
    host_game.header.src_node_id=1;host_game.header.dest_node_id=0xffff;host_game.header.data_channel=243;
    host_game.payload=packet(40,0,0x01000000);host_game.payload[32]=5;
    std::copy(host_word.begin(),host_word.end(),host_game.payload.begin()+20);
    auto host_wifi=local;host_wifi.transmitter=host_mac;host_wifi.destination=citra_room::broadcast_mac;
    host_wifi.type=citra_room::FrameType::Data;host_wifi.data=citra_control::build_secure_data_frame(host_game).value;
    host.send(citra_room::encode(host_wifi,citra_room::Direction::ClientToServer));
    auto gu_join=packet(120,1,0x01000000);gu_join[15]=86;gu_join[32]=1;gu_join[33]=0xfd;gu_join[34]=7;
    std::copy(native_ip.begin(),native_ip.end(),gu_join.begin()+20);
    std::copy(host_ip.begin(),host_ip.end(),gu_join.begin()+36);
    gu_join[40]=0x30;gu_join[41]=0x39;
    for(const auto offset:{44,50,62})std::copy(native_ip.begin(),native_ip.end(),gu_join.begin()+offset);
    gu_join[48]=gu_join[54]=0x30;gu_join[49]=gu_join[55]=0x39;
    gu_join[56]=0x12;gu_join[57]=0x34;
    const auto send_native_game=[&](const room_client::IPv4& target,const citra_room::Bytes& plain) {
        room_client::ProxyPacket proxy;proxy.local.family=proxy.remote.family=room_client::Domain::Inet;
        proxy.local.ip=native_ip;proxy.remote.ip=target;proxy.local.port=proxy.remote.port=12345;
        proxy.protocol=room_client::SocketProtocol::Udp;proxy.data=compress_payload(plain);native.send(proxy);
    };
    send_native_game(host_ip,gu_join);
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return control_counter(gateway,"join_request_restructured")>0;}),
           "B325 native GU first negotiates its original descriptor with Citra host");
    citra_control::EapolStartPacket local_start;local_start.node.friend_code_seed=0xabcdef9876543210ULL;
    local_start.node.username[0]='L';
    local.type=citra_room::FrameType::Data;local.transmitter=guest_mac;local.destination=host_mac;
    local.data=citra_control::build_eapol_start_frame(local_start).value;
    const auto local_start_raw=citra_room::encode(local,citra_room::Direction::ClientToServer);guest.send(local_start_raw);
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return std::find(host.raw_frames().begin(),host.raw_frames().end(),local_start_raw)!=host.raw_frames().end();}),
           "B325 local guest declares its own EAPoL identity to the real host");
    logoff.assigned_node_id=3;logoff.client_mac_address={};logoff.connected_nodes=3;
    logoff.nodes[2]=local_start.node;logoff.nodes[2].network_node_id=3;
    host_wifi.data=citra_control::build_eapol_logoff_frame(logoff).value;
    const auto local_logoff_raw=citra_room::encode(host_wifi,citra_room::Direction::ClientToServer);host.send(local_logoff_raw);
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return std::find(guest.raw_frames().begin(),guest.raw_frames().end(),local_logoff_raw)!=guest.raw_frames().end();}),
           "B325 broadcast MAC-less host Logoff authenticates local Citra as node3");
    room_client::IPv4 local_ip{};for(const auto& identity:gateway.identities())if(identity.mac==guest_mac)local_ip=identity.fake_ip;
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);for(const auto& m:native.messages()) {
        if(const auto* l=std::get_if<room_client::LdnPacket>(&m);l && l->type==room_client::LdnType::SyncNetwork) {
            const auto n=citra_control::parse_ldn_network_info(l->data.data(),l->data.size());
            if(n.ok() && n.value.ldn.node_count==3 && n.value.ldn.nodes[2].is_connected &&
               n.value.ldn.nodes[2].mac_address==guest_mac) return true;
        }
    }return false;}),"B333 authenticated local Citra joins native network before peer game traffic");
    const auto local_word=citra_gateway::mhxx_identity_word_from_seed(local_start.node.friend_code_seed);
    auto peer_request=gu_join;peer_request.erase(peer_request.begin()+36,peer_request.begin()+44);
    peer_request[5]=peer_request[33];peer_request[15]=78;std::copy(local_word.begin(),local_word.end(),peer_request.begin()+20);
    for(const auto offset:{36,42,54})std::copy(local_word.begin(),local_word.end(),peer_request.begin()+offset);
    peer_request[48]=0x56;peer_request[49]=0x78;
    citra_control::SecureDataFrame peer_frame;peer_frame.header.src_node_id=3;peer_frame.header.dest_node_id=2;
    peer_frame.header.data_channel=243;peer_frame.payload=peer_request;
    local.destination=node.mac_address;local.data=citra_control::build_secure_data_frame(peer_frame).value;
    const auto before_peer=native.messages().size();guest.send(citra_room::encode(local,citra_room::Direction::ClientToServer));
    const auto has_peer_request=[&] {
        for(std::size_t n=before_peer;n<native.messages().size();++n) {
            const auto* proxy=std::get_if<room_client::ProxyPacket>(&native.messages()[n]);if(!proxy)continue;
            citra_room::Bytes decoded;if(!citra_gateway::decompress_proxy_frame(proxy->data,65536,decoded,nullptr))continue;
            if(proxy->local.ip==local_ip && proxy->remote.ip==native_ip && !proxy->broadcast && decoded.size()==120 &&
               std::equal(local_ip.begin(),local_ip.end(),decoded.begin()+44))return true;
        }return false;
    };
    verify(drive(gateway,{&guest,&host},[&]{native.pump(0);return has_peer_request();}),
           "B325 real gateway delivers node3-to-node2 request once using the local guest upstream IP");
    auto peer_accept=gu_join;peer_accept[5]=peer_accept[33]=0x95;peer_accept[35]=1;
    std::copy(local_ip.begin(),local_ip.end(),peer_accept.begin()+36);
    peer_accept[42]=0x56;peer_accept[43]=0x78;
    send_native_game(local_ip,peer_accept);
    verify(drive(gateway,{&guest,&host},[&] {
        native.pump(0);
        for(const auto& message:guest.messages()) {
            const auto* wifi=std::get_if<citra_room::WifiPacket>(&message);
            if(!wifi || wifi->type!=citra_room::FrameType::Data || wifi->transmitter!=node.mac_address || wifi->channel!=11)continue;
            const auto decoded=citra_control::parse_secure_data_frame(wifi->data.data(),wifi->data.size());
            if(decoded.ok() && decoded.value.header.src_node_id==2 && decoded.value.header.dest_node_id==3 &&
               decoded.value.payload.size()==112 && decoded.value.payload[35]==1 &&
               decoded.value.payload[5]==0x95 && decoded.value.payload[33]==0x95)return true;
        }return false;
    }),"B325 native GU peer accept returns directly to local Citra node3 on actual hall RF channel");
    local.type=citra_room::FrameType::Deauthentication;local.transmitter=host_mac;
    local.destination=citra_room::broadcast_mac;local.data=citra_control::build_deauthentication_frame().value;
    host.send(citra_room::encode(local,citra_room::Direction::ClientToServer));
    verify(drive(gateway,{&guest,&host},[&] {
        native.pump(0);
        for(const auto& m:native.messages()) {
            if(const auto* l=std::get_if<room_client::LdnPacket>(&m);
               l&&l->type==room_client::LdnType::DestroyNetwork&&l->local_ip==host_ip) return true;
        }
        return false;
    }),
           "B323 closing Citra hall destroys old native membership");
    const auto baseline=native.messages().size();
    verify(drive(gateway,{&guest,&host},[&] {
        native.pump(0);
        for(std::size_t n=baseline;n<native.messages().size();++n) {
            if(const auto* l=std::get_if<room_client::LdnPacket>(&native.messages()[n]);
               l&&l->type==room_client::LdnType::Scan&&l->local_ip==host_ip) return true;
        }
        return false;
    },2500),
           "B323 former Citra host resumes native GU discovery on the same room session");
    dump_documents(gateway,"b323_dual_host_roles");gateway.close();
}

void group_b323_independent_halls() {
    RoomGuard room(take_port(),8);auto options=gateway_options(take_port(),room);
    options.control_plane_enabled=true;options.ldn_dual_host=true;options.proxy_udp_port=12345;
    options.ldn_comm_id_override=0x0100770008dd8000ULL;
    options.have_uds_wlan_comm_id=true;options.uds_wlan_comm_id=0x00197110;
    citra_gateway::Gateway gateway(options);gateway.open();
    RawRoomPeer native(room.port(),"native-hall",room_client::network_version);
    CitraPeer searcher,a,b;std::vector<CitraPeer*> watched{&searcher,&a,&b},joined;
    unsigned ordinal=0;
    for(auto* p:watched) {
        p->connect(gateway.port());joined.push_back(p);++ordinal;
        verify(join_peer(gateway,*p,"independent-"+std::to_string(ordinal),"independent-console-"+std::to_string(ordinal),
                         citra_room::no_preferred_mac,citra_room::network_version,"",joined),
               "B323 independent Citra session joins");
    }
    verify(drive(gateway,watched,[&]{native.pump(0);return native.message_of(room_client::MessageId::JoinSuccess).has_value();}),
           "B323 independent native hall joins the room");
    const auto native_ip=std::get<room_client::JoinSuccess>(*native.message_of(room_client::MessageId::JoinSuccess)).assigned_ip;
    const citra_room::MacAddress gu_mac{2,0,native_ip[0],native_ip[1],native_ip[2],native_ip[3]};
    auto ip_of=[&](CitraPeer& p){for(const auto& id:gateway.identities())if(id.mac==*p.assigned_mac())return id.fake_ip;return room_client::IPv4{};};
    const auto ip_a=ip_of(a),ip_b=ip_of(b);
    citra_control::LdnNetworkInfoBody gu;
    gu.network_id.intent_id.local_communication_id=options.ldn_comm_id_override;
    gu.network_id.session_id.low=0x323;gu.common.bssid=gu_mac;gu.common.channel=6;gu.common.network_type=2;
    gu.ldn.node_count=1;gu.ldn.node_count_max=4;gu.ldn.nodes[0].mac_address=gu_mac;
    gu.ldn.nodes[0].is_connected=1;gu.ldn.nodes[0].user_name[0]='G';gu.ldn.advertise_data_size=200;
    gu.ldn.advertise_data[8]=gu.ldn.advertise_data[0x1c]=gu.ldn.advertise_data[0x20]=1;
    auto make_beacon=[&](CitraPeer& p,unsigned generation,char name) {
        citra_control::BeaconParams params;params.source_mac=*p.assigned_mac();
        params.network_info.host_mac_address=params.source_mac;params.network_info.channel=11;
        params.network_info.initialized=1;params.network_info.wlan_comm_id=options.uds_wlan_comm_id;
        params.network_info.network_id=generation;params.network_info.attributes=0x8000;
        params.network_info.total_nodes=1;params.network_info.max_nodes=4;
        params.appdata_size=200;params.appdata[0]=generation;params.appdata[8]=1;
        params.appdata[0x1c]=params.appdata[0x20]=1;params.appdata[52]=name;
        params.nodes.resize(4);params.nodes[0].network_node_id=1;
        params.nodes[0].friend_code_seed=0x323000000ULL+generation;params.bitmask=1;
        citra_room::WifiPacket w;w.type=citra_room::FrameType::Beacon;w.channel=11;
        w.transmitter=params.source_mac;w.destination=citra_room::broadcast_mac;
        w.data=citra_control::build_beacon_frame(params).value;
        return citra_room::encode(w,citra_room::Direction::ClientToServer);
    };
    const auto beacon_a=make_beacon(a,1,'A'),beacon_b=make_beacon(b,2,'B');
    a.send(beacon_a);b.send(beacon_b);
    bool a_alive=true;std::uint64_t refreshed=0;std::size_t seen=0;
    auto serve=[&] {
        native.pump(0);
        while(seen<native.messages().size()) {
            if(const auto* scan=std::get_if<room_client::LdnPacket>(&native.messages()[seen++]);
               scan&&scan->type==room_client::LdnType::Scan) {
                room_client::LdnPacket response;response.type=room_client::LdnType::ScanResponse;
                response.local_ip=native_ip;response.remote_ip=scan->local_ip;
                response.data=citra_control::serialize_ldn_network_info(gu).value;native.send(response);
            }
        }
        if(now_ms()-refreshed>=100) {refreshed=now_ms();if(a_alive)a.send(beacon_a);b.send(beacon_b);}
    };
    auto has_raw=[&](const citra_room::Bytes& raw){return std::find(searcher.raw_frames().begin(),searcher.raw_frames().end(),raw)!=searcher.raw_frames().end();};
    auto has_gu=[&]{for(const auto& m:searcher.messages()) {
        if(const auto* w=std::get_if<citra_room::WifiPacket>(&m);w&&w->type==citra_room::FrameType::Beacon&&w->transmitter==gu_mac)return true;
    }return false;};
    verify(drive(gateway,watched,[&]{serve();return has_raw(beacon_a)&&has_raw(beacon_b)&&has_gu();},4000),
           "B323 one searching Citra sees two independent Citra halls and the native GU hall simultaneously");
    auto scan_halls=[&]{room_client::LdnPacket scan;scan.type=room_client::LdnType::Scan;
        scan.local_ip=native_ip;scan.broadcast=true;native.send(scan);};
    auto response_since=[&](std::size_t start,const room_client::IPv4& ip){for(std::size_t n=start;n<native.messages().size();++n) {
        if(const auto* l=std::get_if<room_client::LdnPacket>(&native.messages()[n]);
           l&&l->type==room_client::LdnType::ScanResponse&&l->local_ip==ip)return true;
    }return false;};
    auto baseline=native.messages().size();scan_halls();
    verify(drive(gateway,watched,[&]{serve();return response_since(baseline,ip_a)&&response_since(baseline,ip_b);}),
           "B323 native Yuzu scan receives both Citra host responses rather than one global owner");
    citra_room::WifiPacket deauth;deauth.type=citra_room::FrameType::Deauthentication;deauth.channel=11;
    deauth.transmitter=*a.assigned_mac();deauth.destination=citra_room::broadcast_mac;
    deauth.data=citra_control::build_deauthentication_frame().value;
    a_alive=false;a.send(citra_room::encode(deauth,citra_room::Direction::ClientToServer));
    baseline=native.messages().size();
    verify(drive(gateway,watched,[&]{serve();for(std::size_t n=baseline;n<native.messages().size();++n) {
        if(const auto* l=std::get_if<room_client::LdnPacket>(&native.messages()[n]);
           l&&l->type==room_client::LdnType::Scan&&l->local_ip==ip_a)return true;
    }return false;},2500),"B323 closing only hall A returns only that session to GU search");
    baseline=native.messages().size();scan_halls();
    verify(drive(gateway,watched,[&]{serve();return response_since(baseline,ip_b);}),
           "B323 hall B remains discoverable after hall A closes");
    check(!response_since(baseline,ip_a),"B323 closed hall A is not advertised from stale metadata");
    const auto before=searcher.raw_count();
    verify(drive(gateway,watched,[&]{serve();for(std::size_t n=before;n<searcher.messages().size();++n) {
        if(const auto* w=std::get_if<citra_room::WifiPacket>(&searcher.messages()[n]);
           w&&w->type==citra_room::FrameType::Beacon&&w->transmitter==gu_mac)return true;
    }return false;},2500),"B323 native GU hall discovery continues after another Citra hall closes");
    dump_documents(gateway,"b323_independent_halls");gateway.close();
}

void group_b319_shared_guest_identities() {
    citra_gateway::ControlOptions options;
    options.ldn_gu_host_discovery = options.ldn_gu_host_admission = true;
    options.have_uds_wlan_comm_id = true;
    const room_client::IPv4 host_ip{10,83,19,1}, ip_a{10,83,19,2}, ip_b{10,83,19,3};
    const citra_room::MacAddress host{2,0,10,83,19,1}, mac_a{2,0,10,83,19,2}, mac_b{2,0,10,83,19,3};
    citra_gateway::ControlBridge a(options,ip_a,mac_a), b(options,ip_b,mac_b);
    a.start(); b.start(); a.tick(100); b.tick(100);
    citra_control::LdnNetworkInfoBody network;
    network.network_id.session_id.low = 319;
    network.common.bssid = host;
    network.common.channel = 6; network.common.network_type = 2;
    network.ldn.node_count=1; network.ldn.node_count_max=4;
    network.ldn.nodes[0].mac_address=host;
    network.ldn.nodes[0].is_connected=1;
    network.ldn.nodes[0].user_name[0]='G';
    network.ldn.advertise_data_size=200;
    network.ldn.advertise_data[8]=network.ldn.advertise_data[0x1c]=network.ldn.advertise_data[0x20]=1;
    room_client::LdnPacket packet;
    packet.type=room_client::LdnType::ScanResponse; packet.local_ip=host_ip;
    packet.data=citra_control::serialize_ldn_network_info(network).value;
    std::vector<citra_gateway::GuHostGuestIdentity> peers;
    unsigned slot=1;
    for (auto* bridge : {&a,&b}) {
        packet.remote_ip = bridge==&a ? ip_a : ip_b;
        verify(bridge->on_ldn(packet,{}).accepted,"B319 each guest learns the selected hall");
        citra_room::WifiPacket wifi;
        wifi.transmitter=bridge==&a ? mac_a : mac_b; wifi.destination=host;
        wifi.type=citra_room::FrameType::Authentication;
        wifi.data=citra_control::build_authentication_frame({}).value;
        verify(bridge->on_citra_wifi(wifi,101).size()==2,"B319 each guest authenticates independently");
        citra_control::EapolStartPacket start;
        start.association_id=1; start.node.friend_code_seed=bridge==&a ? 0x12345678 : 0xabcdef12;
        start.node.username[0]=bridge==&a ? 'A' : 'B';
        wifi.type=citra_room::FrameType::Data;
        wifi.data=citra_control::build_eapol_start_frame(start).value;
        auto connect=bridge->on_citra_wifi(wifi,102);
        verify(connect.size()==1,"B319 each EAPoL yields its own native Connect");
        auto node=citra_control::parse_ldn_node_info(connect[0].ldn_body.data(),connect[0].ldn_body.size());
        verify(node.ok(),"B319 admitted node carries the authenticated identity");
        network.ldn.nodes[slot]=node.value;
        network.ldn.nodes[slot].node_id=slot;
        ++slot;
        peers.push_back(*bridge->gu_host_guest_identity());
    }
    network.ldn.node_count=3;
    packet.type=room_client::LdnType::SyncNetwork;
    packet.data=citra_control::serialize_ldn_network_info(network).value;
    a.set_gu_host_guest_identities(peers); b.set_gu_host_guest_identities(peers);
    for (auto* bridge : {&a,&b}) {
        packet.remote_ip=bridge==&a ? ip_a : ip_b;
        auto sync=bridge->on_ldn(packet,{});
        verify(sync.accepted && sync.emissions.size()==2,"B319 both accept the three-member native Sync");
        auto logoff=citra_control::parse_eapol_logoff_frame(sync.emissions[1].citra_data.data(),sync.emissions[1].citra_data.size());
        check(logoff.ok() && logoff.value.nodes[1].friend_code_seed==peers[0].node.friend_code_seed &&
                  logoff.value.nodes[2].friend_code_seed==peers[1].node.friend_code_seed &&
                  logoff.value.assigned_node_id==(bridge==&a ? 2 : 3),
              "B319 logoff preserves both real seeds and assigns distinct node IDs");
    }
    citra_room::Bytes announce(140,0);
    const citra_room::Bytes header{0x32,0xab,0x98,0x64,1,0};
    std::copy(header.begin(),header.end(),announce.begin());
    announce[15]=105;announce[24]=3;announce[26]=0x30;announce[27]=0x39;
    announce[32]=1;announce[33]=0x11;announce[34]=73;
    std::copy(host_ip.begin(),host_ip.end(),announce.begin()+20);
    for(unsigned i=0;i<8;++i) announce[64+9*i+8]=0xff;
    unsigned index=0;
    for(const auto& ip : {host_ip,ip_a,ip_b}) {
        auto dst=announce.begin()+64+9*index;
        std::copy(ip.begin(),ip.end(),dst);dst[4]=0x30;dst[5]=0x39;dst[8]=index++;
    }
    for(auto* bridge : {&a,&b}) {
        auto result=bridge->translate_gu_host_announcement(host_ip,announce);
        const auto word_a=citra_gateway::mhxx_identity_word_from_seed(peers[0].node.friend_code_seed);
        const auto word_b=citra_gateway::mhxx_identity_word_from_seed(peers[1].node.friend_code_seed);
        check(result && std::equal(word_a.begin(),word_a.end(),result->begin()+73) &&
                  std::equal(word_b.begin(),word_b.end(),result->begin()+82) && (*result)[80]==2 && (*result)[89]==3,
              "B319 every guest sees the same proven three-member game table");
    }
    a.set_gu_host_guest_identities({});
    check(!a.translate_gu_host_announcement(host_ip,announce),"B319 unknown extra guest remains refused");
    auto foreign=peers;foreign[1].session_low++;
    a.set_gu_host_guest_identities(foreign);
    check(!a.translate_gu_host_announcement(host_ip,announce),"B319 another hall session cannot donate a guest seed");
    auto forged=peers;forged[1].guest_ip[3]++;
    a.set_gu_host_guest_identities(forged);
    check(!a.translate_gu_host_announcement(host_ip,announce),"B319 known MAC with unproven IP remains refused");
    forged=peers;forged[1].node.username[0]='Z';a.set_gu_host_guest_identities(forged);
    check(!a.translate_gu_host_announcement(host_ip,announce),"B319 username must match the current Sync node");
    a.set_gu_host_guest_identities(peers);
    auto bad=announce;bad[82]++;
    check(!a.translate_gu_host_announcement(host_ip,bad),"B319 unknown occupied endpoint is still refused");
}

void group_b321_four_player_rosters() {
    for (unsigned count = 2; count <= 4; ++count) {
        citra_gateway::ControlOptions options;
        options.ldn_gu_host_discovery = options.ldn_gu_host_admission = true;
        options.have_uds_wlan_comm_id = true;
        const room_client::IPv4 host_ip{10,83,21,1};
        const citra_room::MacAddress host{2,0,10,83,21,1};
        citra_control::LdnNetworkInfoBody net;
        net.network_id.session_id.low = 321;
        net.common.bssid=host; net.common.channel=6; net.common.network_type=2;
        net.ldn.node_count=1; net.ldn.node_count_max=4;
        net.ldn.nodes[0].mac_address=host; net.ldn.nodes[0].is_connected=1;
        net.ldn.nodes[0].user_name[0]='H';
        net.ldn.advertise_data_size=200;
        net.ldn.advertise_data[8]=net.ldn.advertise_data[0x1c]=net.ldn.advertise_data[0x20]=1;
        std::vector<std::unique_ptr<citra_gateway::ControlBridge>> bridges;
        std::vector<citra_gateway::GuHostGuestIdentity> peers;
        const citra_room::Bytes header{0x32,0xab,0x98,0x64,1,0};
        for(unsigned slot=1;slot<count;++slot) {
            room_client::IPv4 ip{10,83,21,static_cast<std::uint8_t>(slot+1)};
            citra_room::MacAddress mac{2,0,10,83,21,static_cast<std::uint8_t>(slot+1)};
            auto b=std::make_unique<citra_gateway::ControlBridge>(options,ip,mac);
            b->start();b->tick(100);
            auto clean=net;clean.ldn.node_count=1;
            for(unsigned n=1;n<8;++n)clean.ldn.nodes[n]={};
            room_client::LdnPacket l;l.local_ip=host_ip;l.remote_ip=ip;
            l.type=room_client::LdnType::ScanResponse;
            l.data=citra_control::serialize_ldn_network_info(clean).value;
            verify(b->on_ldn(l,{}).accepted,"B321 guest discovers the same hall");
            citra_room::WifiPacket w;w.transmitter=mac;w.destination=host;
            w.type=citra_room::FrameType::Authentication;
            w.data=citra_control::build_authentication_frame({}).value;
            verify(b->on_citra_wifi(w,101).size()==2,"B321 each guest authenticates");
            citra_control::EapolStartPacket start;start.association_id=1;
            start.node.friend_code_seed=0x123400000000ULL+slot;
            start.node.username[0]=static_cast<char16_t>('A'+slot);
            w.type=citra_room::FrameType::Data;
            w.data=citra_control::build_eapol_start_frame(start).value;
            const auto connect=b->on_citra_wifi(w,102);
            verify(connect.size()==1,"B321 every guest emits its own Connect");
            const auto node=citra_control::parse_ldn_node_info(connect[0].ldn_body.data(),connect[0].ldn_body.size());
            verify(node.ok(),"B321 native identity parses");
            net.ldn.nodes[slot]=node.value;net.ldn.nodes[slot].node_id=slot;
            peers.push_back(*b->gu_host_guest_identity());bridges.push_back(std::move(b));
        }
        net.ldn.node_count=count;
        for(auto& b:bridges) {
            b->set_gu_host_guest_identities(peers);
            room_client::LdnPacket l;l.local_ip=host_ip;l.remote_ip=b->gu_host_guest_identity()->guest_ip;
            l.type=room_client::LdnType::SyncNetwork;l.data=citra_control::serialize_ldn_network_info(net).value;
            verify(b->on_ldn(l,{}).accepted,"B321 accepts the complete native member sync");
            citra_room::Bytes announce(140,0);std::copy(header.begin(),header.end(),announce.begin());
            announce[15]=105;announce[24]=3;announce[26]=0x30;announce[27]=0x39;
            announce[32]=1;announce[33]=0x11;announce[34]=73;
            std::copy(host_ip.begin(),host_ip.end(),announce.begin()+20);
            for(unsigned j=0;j<8;++j)announce[64+9*j+8]=0xff;
            for(unsigned j=0;j<count;++j) {
                auto ip=j ? peers[j-1].guest_ip : host_ip;
                std::copy(ip.begin(),ip.end(),announce.begin()+64+9*j);
                announce[68+9*j]=0x30;announce[69+9*j]=0x39;announce[72+9*j]=j;
            }
            verify(b->on_gu_host_proxy(host_ip,announce).size()==1,"B321 all occupied announcement slots translate");
            const auto own=*b->gu_host_guest_identity();
            const auto word=citra_gateway::mhxx_identity_word_from_seed(own.node.friend_code_seed);
            citra_room::Bytes request(112,0);std::copy(header.begin(),header.end(),request.begin());
            request[5]=1;request[15]=78;request[24]=1;request[32]=1;request[33]=0x0f;request[34]=7;
            for(const auto field:{36u,42u,54u,65u,71u,89u,100u})
                std::copy(word.begin(),word.end(),request.begin()+field);
            request[40]=request[46]=0x30;request[41]=request[47]=0x39;
            request[48]=static_cast<std::uint8_t>(own.guest_ip[3]);request[49]=0x88;
            request[85]=0xab;request[104]=0xcd;
            citra_control::SecureDataFrame data;data.header.src_node_id=own.guest_ip[3];
            data.header.dest_node_id=1;data.header.data_channel=243;data.payload=request;
            citra_room::WifiPacket w;w.transmitter=own.mac;w.destination=host;w.type=citra_room::FrameType::Data;
            w.data=citra_control::build_secure_data_frame(data).value;
            verify(b->on_gu_host_guest_game(w).size()==1,"B321 stores each full guest descriptor");
            citra_room::Bytes accept(120,0);std::copy(request.begin(),request.begin()+36,accept.begin());
            accept[15]=86;accept[35]=1;
            std::copy(own.guest_ip.begin(),own.guest_ip.end(),accept.begin()+36);
            accept[40]=0x30;accept[41]=0x39;accept[42]=request[48];accept[43]=request[49];
            for(const auto field:{44u,50u,62u})std::copy(host_ip.begin(),host_ip.end(),accept.begin()+field);
            verify(b->on_gu_host_proxy(host_ip,accept).size()==1,"B321 stores the negotiated host descriptor");
        }
        peers.clear();for(auto& b:bridges)peers.push_back(*b->gu_host_guest_identity());
        for(auto& b:bridges) {
            b->set_gu_host_guest_identities(peers);
            const auto own=*b->gu_host_guest_identity();
            for(const auto& sender:peers) {
                if(sender.mac==own.mac)continue;
                citra_control::SecureDataFrame data;
                data.header.data_channel=243;data.header.src_node_id=sender.guest_ip[3];
                data.header.dest_node_id=own.guest_ip[3];data.payload=synthetic_payload(112,0x32);
                citra_room::WifiPacket w;w.type=citra_room::FrameType::Data;w.channel=6;
                w.transmitter=sender.mac;w.destination=own.mac;
                w.data=citra_control::build_secure_data_frame(data).value;
                check(b->accepts_gu_host_peer_wifi(w),"B322 every authenticated player pair can exchange native XX frames");
                data.header.src_node_id=1;w.data=citra_control::build_secure_data_frame(data).value;
                check(!b->accepts_gu_host_peer_wifi(w),"B322 peer cannot spoof the host node");
                data.header.src_node_id=sender.guest_ip[3];data.header.dest_node_id=1;
                w.data=citra_control::build_secure_data_frame(data).value;
                check(!b->accepts_gu_host_peer_wifi(w),"B322 node destination must match recipient MAC");
                data.header.dest_node_id=0xffff;w.destination=citra_room::broadcast_mac;
                w.data=citra_control::build_secure_data_frame(data).value;
                check(b->accepts_gu_host_peer_wifi(w),"B322 broadcast reaches other authenticated hall guests");
                data.header.data_channel=33;w.data=citra_control::build_secure_data_frame(data).value;
                check(!b->accepts_gu_host_peer_wifi(w),"B322 unrelated secure channel is refused");
                data.header.data_channel=243;w.data=citra_control::build_secure_data_frame(data).value;
                auto foreign=peers;for(auto& peer:foreign)peer.session_low++;
                b->set_gu_host_guest_identities(foreign);
                check(!b->accepts_gu_host_peer_wifi(w),"B322 foreign hall identity cannot receive peer traffic");
                b->set_gu_host_guest_identities(peers);
            }
            citra_room::Bytes roster(52+72*count,0);std::copy(header.begin(),header.end(),roster.begin());
            const auto length=roster.size()-32;roster[14]=length>>8;roster[15]=length;
            std::copy(host_ip.begin(),host_ip.end(),roster.begin()+20);
            roster[24]=2;roster[32]=2;roster[33]=count;roster[35]=count-1;
            for(const auto field:{48u,54u,66u})std::copy(host_ip.begin(),host_ip.end(),roster.begin()+field);
            for(unsigned j=1;j<count;++j) {
                auto native=peers[j-1].descriptor;
                const auto word=citra_gateway::mhxx_identity_word_from_seed(peers[j-1].node.friend_code_seed);
                for(const auto field:{0u,6u,18u,29u,35u,53u,64u})
                    if(std::equal(word.begin(),word.end(),native.begin()+field))
                        std::copy(peers[j-1].guest_ip.begin(),peers[j-1].guest_ip.end(),native.begin()+field);
                std::copy(native.begin(),native.end(),roster.begin()+48+72*j);
            }
            const auto out=b->on_gu_host_proxy(host_ip,roster);
            verify(out.size()==1,"B321 each guest accepts every proven member in initial roster");
            const auto frame=citra_control::parse_secure_data_frame(out[0].citra_data.data(),out[0].citra_data.size());
            for(unsigned j=1;j<count;++j)
                check(frame.ok()&&std::equal(peers[j-1].descriptor.begin(),peers[j-1].descriptor.end(),frame.value.payload.begin()+48+72*j),
                      "B321 restores all70 bytes of each guest descriptor");
            auto periodic=roster;periodic.erase(periodic.begin()+44,periodic.begin()+48);periodic.resize(332,0);
            periodic[14]=1;periodic[15]=44;periodic[32]=0x20;periodic[35]=0;
            check(b->on_gu_host_proxy(host_ip,periodic).size()==1,"B321 periodic roster supports every count through four");
            auto bad=roster;bad[48+72*(count-1)+14]^=1;
            check(b->on_gu_host_proxy(host_ip,bad).empty(),"B321 altered final player descriptor is refused");
            if(count>2) {
                bad=roster;std::copy_n(bad.begin()+120,70,bad.begin()+192);
                check(b->on_gu_host_proxy(host_ip,bad).empty(),"B321 duplicate player descriptor is refused");
                auto missing=peers;missing.pop_back();b->set_gu_host_guest_identities(missing);
                if(b->gu_host_guest_identity()->mac!=peers.back().mac)
                    check(b->on_gu_host_proxy(host_ip,roster).empty(),"B321 unknown final guest cannot be partially translated");
            }
        }
    }
}

void group_b328_native_gu_guests() {
    for (unsigned count = 3; count <= 4; ++count) {
        citra_gateway::ControlOptions options;
        options.ldn_gu_host_discovery = options.ldn_gu_host_admission = true;
        options.have_uds_wlan_comm_id = true;
        const room_client::IPv4 host_ip{10,83,21,1};
        const citra_room::MacAddress host{2,0,10,83,21,1};
        citra_control::LdnNetworkInfoBody net;
        net.network_id.session_id.low = 321;
        net.common.bssid=host; net.common.channel=6; net.common.network_type=2;
        net.ldn.node_count=1; net.ldn.node_count_max=4;
        net.ldn.nodes[0].mac_address=host; net.ldn.nodes[0].is_connected=1;
        net.ldn.nodes[0].user_name[0]='H';
        net.ldn.advertise_data_size=200;
        net.ldn.advertise_data[8]=net.ldn.advertise_data[0x1c]=net.ldn.advertise_data[0x20]=1;
        std::vector<std::unique_ptr<citra_gateway::ControlBridge>> bridges;
        std::vector<citra_gateway::GuHostGuestIdentity> peers;
        const citra_room::Bytes header{0x32,0xab,0x98,0x64,1,0};
        for(unsigned slot=1;slot<count;++slot) {
            room_client::IPv4 ip{10,83,21,static_cast<std::uint8_t>(slot+1)};
            citra_room::MacAddress mac{2,0,10,83,21,static_cast<std::uint8_t>(slot+1)};
            auto b=std::make_unique<citra_gateway::ControlBridge>(options,ip,mac);
            b->start();b->tick(100);
            auto clean=net;clean.ldn.node_count=1;
            for(unsigned n=1;n<8;++n)clean.ldn.nodes[n]={};
            room_client::LdnPacket l;l.local_ip=host_ip;l.remote_ip=ip;
            l.type=room_client::LdnType::ScanResponse;
            l.data=citra_control::serialize_ldn_network_info(clean).value;
            verify(b->on_ldn(l,{}).accepted,"B328 guest discovers the same hall");
            citra_room::WifiPacket w;w.transmitter=mac;w.destination=host;
            w.type=citra_room::FrameType::Authentication;
            w.data=citra_control::build_authentication_frame({}).value;
            verify(b->on_citra_wifi(w,101).size()==2,"B328 each guest authenticates");
            citra_control::EapolStartPacket start;start.association_id=1;
            start.node.friend_code_seed=0x123400000000ULL+slot;
            start.node.username[0]=static_cast<char16_t>('A'+slot);
            w.type=citra_room::FrameType::Data;
            w.data=citra_control::build_eapol_start_frame(start).value;
            const auto connect=b->on_citra_wifi(w,102);
            verify(connect.size()==1,"B328 every guest emits its own Connect");
            const auto node=citra_control::parse_ldn_node_info(connect[0].ldn_body.data(),connect[0].ldn_body.size());
            verify(node.ok(),"B328 native identity parses");
            net.ldn.nodes[slot]=node.value;net.ldn.nodes[slot].node_id=slot;
            peers.push_back(*b->gu_host_guest_identity());bridges.push_back(std::move(b));
        }
        net.ldn.node_count=count;
        for(auto& b:bridges) {
            b->set_gu_host_guest_identities(peers);
            room_client::LdnPacket l;l.local_ip=host_ip;l.remote_ip=b->gu_host_guest_identity()->guest_ip;
            l.type=room_client::LdnType::SyncNetwork;l.data=citra_control::serialize_ldn_network_info(net).value;
            verify(b->on_ldn(l,{}).accepted,"B328 accepts the complete native member sync");
            citra_room::Bytes announce(140,0);std::copy(header.begin(),header.end(),announce.begin());
            announce[15]=105;announce[24]=3;announce[26]=0x30;announce[27]=0x39;
            announce[32]=1;announce[33]=0x11;announce[34]=73;
            std::copy(host_ip.begin(),host_ip.end(),announce.begin()+20);
            for(unsigned j=0;j<8;++j)announce[64+9*j+8]=0xff;
            for(unsigned j=0;j<count;++j) {
                auto ip=j ? peers[j-1].guest_ip : host_ip;
                std::copy(ip.begin(),ip.end(),announce.begin()+64+9*j);
                announce[68+9*j]=0x30;announce[69+9*j]=0x39;announce[72+9*j]=j;
            }
            verify(b->on_gu_host_proxy(host_ip,announce).size()==1,"B328 all occupied announcement slots translate");
            const auto own=*b->gu_host_guest_identity();
            const auto word=citra_gateway::mhxx_identity_word_from_seed(own.node.friend_code_seed);
            citra_room::Bytes request(112,0);std::copy(header.begin(),header.end(),request.begin());
            request[5]=1;request[15]=78;request[24]=1;request[32]=1;request[33]=0x0f;request[34]=7;
            for(const auto field:{36u,42u,54u,65u,71u,89u,100u})
                std::copy(word.begin(),word.end(),request.begin()+field);
            request[40]=request[46]=0x30;request[41]=request[47]=0x39;
            request[48]=static_cast<std::uint8_t>(own.guest_ip[3]);request[49]=0x88;
            request[85]=0xab;request[104]=0xcd;
            citra_control::SecureDataFrame data;data.header.src_node_id=own.guest_ip[3];
            data.header.dest_node_id=1;data.header.data_channel=243;data.payload=request;
            citra_room::WifiPacket w;w.transmitter=own.mac;w.destination=host;w.type=citra_room::FrameType::Data;
            w.data=citra_control::build_secure_data_frame(data).value;
            verify(b->on_gu_host_guest_game(w).size()==1,"B328 stores each full guest descriptor");
            citra_room::Bytes accept(120,0);std::copy(request.begin(),request.begin()+36,accept.begin());
            accept[15]=86;accept[35]=1;
            std::copy(own.guest_ip.begin(),own.guest_ip.end(),accept.begin()+36);
            accept[40]=0x30;accept[41]=0x39;accept[42]=request[48];accept[43]=request[49];
            for(const auto field:{44u,50u,62u})std::copy(host_ip.begin(),host_ip.end(),accept.begin()+field);
            verify(b->on_gu_host_proxy(host_ip,accept).size()==1,"B328 stores the negotiated host descriptor");
        }
        peers.clear();for(auto& b:bridges)peers.push_back(*b->gu_host_guest_identity());
        for(auto& b:bridges) {
            const auto own=*b->gu_host_guest_identity();
            std::vector<room_client::IPv4> native_ips;
            for (const auto& peer : peers) if (peer.mac != own.mac) native_ips.push_back(peer.guest_ip);
            b->set_gu_host_guest_identities({own});
            b->set_gu_host_native_members(native_ips);
            room_client::LdnPacket sync; sync.type=room_client::LdnType::SyncNetwork;
            sync.local_ip=host_ip;sync.remote_ip=own.guest_ip;
            sync.data=citra_control::serialize_ldn_network_info(net).value;
            verify(b->on_ldn(sync,{}).accepted,"B328 native guests are bound to selected host Sync and room members");
            citra_room::Bytes announce(140,0);std::copy(header.begin(),header.end(),announce.begin());
            announce[15]=105;announce[24]=3;announce[26]=0x30;announce[27]=0x39;
            announce[32]=1;announce[33]=0x11;announce[34]=73;
            std::copy(host_ip.begin(),host_ip.end(),announce.begin()+20);
            for(unsigned j=0;j<8;++j)announce[64+9*j+8]=0xff;
            for(unsigned j=0;j<count;++j) {
                auto ip=j ? peers[j-1].guest_ip : host_ip;
                std::copy(ip.begin(),ip.end(),announce.begin()+64+9*j);
                announce[68+9*j]=0x30;announce[69+9*j]=0x39;announce[72+9*j]=j;
            }
            check(b->on_gu_host_proxy(host_ip,announce).size()==1,
                  "B328 native guests do not suppress the existing Citra's game announcement");
            citra_room::Bytes roster(52+72*count,0);std::copy(header.begin(),header.end(),roster.begin());
            const auto length=roster.size()-32;roster[14]=length>>8;roster[15]=length;
            std::copy(host_ip.begin(),host_ip.end(),roster.begin()+20);
            roster[24]=2;roster[32]=2;roster[33]=count;roster[35]=count-1;
            for(const auto field:{48u,54u,66u})std::copy(host_ip.begin(),host_ip.end(),roster.begin()+field);
            for(unsigned j=1;j<count;++j) {
                auto native=peers[j-1].descriptor;
                const auto word=citra_gateway::mhxx_identity_word_from_seed(peers[j-1].node.friend_code_seed);
                for(const auto field:{0u,6u,18u,29u,35u,53u,64u})
                    if(std::equal(word.begin(),word.end(),native.begin()+field))
                        std::copy(peers[j-1].guest_ip.begin(),peers[j-1].guest_ip.end(),native.begin()+field);
                std::copy(native.begin(),native.end(),roster.begin()+48+72*j);
            }
            const auto out=b->on_gu_host_proxy(host_ip,roster);
            verify(out.size()==1,"B328 each guest accepts every proven member in initial roster");
            const auto frame=citra_control::parse_secure_data_frame(out[0].citra_data.data(),out[0].citra_data.size());
            for(unsigned j=1;j<count;++j) {
                auto expected=peers[j-1].descriptor;
                if (peers[j-1].mac != own.mac) {
                    expected.fill(0);
                    const auto& ip=peers[j-1].guest_ip;
                    const auto word=citra_gateway::mhxx_identity_word_from_seed(
                        0x4755000000000000ULL | citra_control::load_u32be(ip.data()));
                    for(const auto sub:{0u,35u}) {
                        for(const auto field:{sub,sub+6,sub+29}) {
                            std::copy(word.begin(),word.end(),expected.begin()+field);
                            expected[field+4]=0x30;expected[field+5]=0x39;
                        }
                        std::copy_n(peers[j-1].descriptor.begin()+12,2,expected.begin()+sub+12);
                        std::copy(word.begin(),word.end(),expected.begin()+sub+18);
                    }
                }
                check(frame.ok()&&std::equal(expected.begin(),expected.end(),frame.value.payload.begin()+48+72*j),
                      "B328 native guest uses its declared unique canonical XX descriptor; Citra remains exact");
            }
            for(const auto& native:peers) {
                if(native.mac==own.mac)continue;
                auto native_descriptor=native.descriptor;
                const auto nw=citra_gateway::mhxx_identity_word_from_seed(native.node.friend_code_seed);
                for(const auto field:{0u,6u,18u,29u,35u,53u,64u})
                    if(std::equal(nw.begin(),nw.end(),native_descriptor.begin()+field))
                        std::copy(native.guest_ip.begin(),native.guest_ip.end(),native_descriptor.begin()+field);
                citra_room::Bytes request(120,0);std::copy(header.begin(),header.end(),request.begin());
                request[5]=1;request[15]=86;request[24]=1;request[32]=1;request[33]=0x71;request[34]=7;
                std::copy(native.guest_ip.begin(),native.guest_ip.end(),request.begin()+20);
                std::copy(own.guest_ip.begin(),own.guest_ip.end(),request.begin()+36);
                request[40]=0x30;request[41]=0x39;
                std::copy_n(own.descriptor.begin()+12,2,request.begin()+42);
                std::copy(native_descriptor.begin(),native_descriptor.end(),request.begin()+44);
                const auto incoming=b->on_gu_native_peer_proxy(native.guest_ip,request);
                verify(incoming.size()==1,"B328 native Yuzu initiates direct peer handshake with existing Citra");
                const auto parsed=citra_control::parse_secure_data_frame(incoming[0].citra_data.data(),incoming[0].citra_data.size());
                check(parsed.ok() && parsed.value.header.src_node_id==native.guest_ip[3] &&
                      parsed.value.header.dest_node_id==own.guest_ip[3],"B328 native peer request retains actual UDS node IDs");
                auto bad=request;bad[42]^=1;
                check(b->on_gu_native_peer_proxy(native.guest_ip,bad).empty(),"B328 direct peer cannot borrow another target short identity");
                check(b->on_gu_native_peer_proxy(host_ip,request).empty(),"B328 native peer source cannot be the hall host");
                citra_control::SecureDataFrame reply;reply.header.src_node_id=own.guest_ip[3];
                reply.header.dest_node_id=native.guest_ip[3];reply.header.data_channel=243;
                reply.payload.assign(112,0);std::copy(header.begin(),header.end(),reply.payload.begin());
                reply.payload[15]=78;reply.payload[24]=1;reply.payload[32]=1;reply.payload[33]=0x72;
                reply.payload[34]=7;reply.payload[35]=1;
                const auto ownword=citra_gateway::mhxx_identity_word_from_seed(own.node.friend_code_seed);
                std::copy(ownword.begin(),ownword.end(),reply.payload.begin()+20);
                std::copy(own.descriptor.begin(),own.descriptor.end(),reply.payload.begin()+36);
                citra_room::WifiPacket wifi;wifi.type=citra_room::FrameType::Data;
                wifi.transmitter=own.mac;wifi.destination=native.mac;
                wifi.data=citra_control::build_secure_data_frame(reply).value;
                const auto outgoing=b->on_gu_native_peer_game(wifi);
                verify(outgoing.size()==1 && outgoing[0].proxy_remote_ip==native.guest_ip &&
                       !outgoing[0].proxy_broadcast && outgoing[0].proxy_data.size()==120,
                       "B328 Citra accept returns only to the native guest that requested it");
                auto expected=own.descriptor;
                for(const auto field:{0u,6u,18u,29u,35u,53u,64u})
                    if(std::equal(ownword.begin(),ownword.end(),expected.begin()+field))
                        std::copy(own.guest_ip.begin(),own.guest_ip.end(),expected.begin()+field);
                check(std::equal(expected.begin(),expected.end(),outgoing[0].proxy_data.begin()+44),
                      "B328 native peer sees exact Citra descriptor already installed by its host");
                reply.header.src_node_id=1;wifi.data=citra_control::build_secure_data_frame(reply).value;
                check(b->on_gu_native_peer_game(wifi).empty(),"B328 native peer path rejects a spoofed Citra source node");
            }
            auto periodic=roster;periodic.erase(periodic.begin()+44,periodic.begin()+48);periodic.resize(332,0);
            periodic[14]=1;periodic[15]=44;periodic[32]=0x20;periodic[35]=0;
            check(b->on_gu_host_proxy(host_ip,periodic).size()==1,"B328 periodic roster supports every count through four");
            auto bad=roster;bad[48+72*(count-1)+14]^=1;
            check(b->on_gu_host_proxy(host_ip,bad).empty(),"B328 altered final player descriptor is refused");
            if(count>2) {
                bad=roster;std::copy_n(bad.begin()+120,70,bad.begin()+192);
                check(b->on_gu_host_proxy(host_ip,bad).empty(),"B328 duplicate player descriptor is refused");
                auto missing=native_ips;
                missing.erase(std::remove(missing.begin(),missing.end(),peers.back().guest_ip),missing.end());
                b->set_gu_host_native_members(missing);
                if(b->gu_host_guest_identity()->mac!=peers.back().mac)
                    check(b->on_gu_host_proxy(host_ip,roster).empty(),"B328 unknown final guest cannot be partially translated");
            }
        }
    }
}

void group_b328_citra_host_multi_gu() {
    for(unsigned guests=2;guests<=3;++guests) {
        const room_client::IPv4 host_ip{10,83,28,1};
        const citra_room::MacAddress host_mac{0,0x1f,0x32,0,0,1};
        const auto hostword=citra_gateway::mhxx_identity_word_from_seed(0x12345678);
        citra_gateway::ControlOptions options;
        options.ldn_guest_inject=options.ldn_game_return=options.ldn_announce_forward=true;
        options.ldn_identity_pairs.push_back({hostword,host_ip});
        citra_gateway::ControlBridge bridge(options,host_ip,host_mac);bridge.start();
        citra_room::WifiPacket wifi;wifi.type=citra_room::FrameType::Beacon;
        wifi.transmitter=host_mac;wifi.data.assign(64,0);bridge.on_citra_wifi(wifi,10);
        std::vector<room_client::IPv4> ips;
        std::vector<citra_room::MacAddress> macs;
        std::vector<citra_room::Bytes> original,canonical;
        std::vector<std::array<std::uint8_t,4>> words;
        const citra_room::Bytes magic{0x32,0xab,0x98,0x64,1,0};
        auto mh=[&](unsigned size,unsigned route) {
            citra_room::Bytes b(size,0);std::copy(magic.begin(),magic.end(),b.begin());
            b[14]=(size-32)>>8;b[15]=size-32;b[24]=route;
            return b;
        };
        auto send_host=[&](const citra_room::Bytes& plain,unsigned destination) {
            citra_control::SecureDataFrame frame;frame.header.src_node_id=1;
            frame.header.dest_node_id=destination;frame.header.data_channel=243;frame.payload=plain;
            return bridge.on_citra_game_payload(citra_control::build_secure_data_frame(frame).value);
        };
        for(unsigned i=0;i<guests;++i) {
            const room_client::IPv4 ip{10,83,28,static_cast<std::uint8_t>(i+2)};
            const citra_room::MacAddress mac{2,0,10,83,28,static_cast<std::uint8_t>(i+2)};
            ips.push_back(ip);macs.push_back(mac);
            citra_gateway::LdnContext ctx;ctx.have_mapped_mac=true;ctx.mapped_mac=mac;
            room_client::LdnPacket packet;packet.local_ip=ip;packet.type=room_client::LdnType::Scan;
            bridge.on_ldn(packet,ctx);packet.type=room_client::LdnType::Connect;packet.data.assign(64,0);
            verify(bridge.on_ldn(packet,ctx).accepted,"B328 independent native GU admission reaches Citra host");
            wifi.type=citra_room::FrameType::AssociationResponse;wifi.destination=mac;
            wifi.data=bytes_from_hex("3104000001c000083030303030303030");
            const auto assoc=bridge.on_citra_wifi(wifi,20+i*100);
            verify(assoc.size()==1,"B328 each guest receives its own EAPoL Start");
            const auto start=citra_control::parse_eapol_start_frame(assoc[0].citra_data.data(),assoc[0].citra_data.size());
            verify(start.ok(),"B328 declared guest identity is encoded in the actual association frame");
            const auto word=citra_gateway::mhxx_identity_word_from_seed(start.value.node.friend_code_seed);
            check(std::find(words.begin(),words.end(),word)==words.end(),"B328 no two injected guests share a game identity");
            words.push_back(word);
            citra_control::EapolLogoffPacket logoff;logoff.assigned_node_id=i+2;
            logoff.connected_nodes=i+2;logoff.max_nodes=4;logoff.client_mac_address=mac;
            for(unsigned n=0;n<i+2;++n)logoff.nodes[n].network_node_id=n+1;
            bridge.on_citra_eapol(citra_control::build_eapol_logoff_frame(logoff).value,30+i*100);
            auto request=mh(120,1);request[5]=1;request[32]=1;request[33]=0x70+i;request[34]=7;
            std::copy(ip.begin(),ip.end(),request.begin()+20);
            std::copy(host_ip.begin(),host_ip.end(),request.begin()+36);request[40]=0x30;request[41]=0x39;
            for(const auto at:{44u,50u,62u})std::copy(ip.begin(),ip.end(),request.begin()+at);
            request[48]=request[54]=0x30;request[49]=request[55]=0x39;
            request[56]=0x40+i;request[57]=0x80+i;
            const auto converted=bridge.translate_game_return(ip,request);
            verify(converted && converted->size()==112,"B328 each GU join has its own translated canonical descriptor");
            original.emplace_back(request.begin()+44,request.begin()+114);
            canonical.emplace_back(converted->begin()+36,converted->begin()+106);
            check(std::equal(word.begin(),word.end(),converted->begin()+54) &&
                  std::equal(word.begin(),word.end(),converted->begin()+89),
                  "B329 both embedded registry address keys identify this guest");
            for(unsigned previous=0;previous<i;++previous)
                check(!std::equal(canonical[previous].begin()+18,canonical[previous].begin()+22,
                                  canonical.back().begin()+18),
                      "B329 native registry fallback cannot reuse an earlier guest by embedded key");
            auto accept=mh(112,1);accept[32]=1;accept[33]=0x90+i;accept[34]=7;accept[35]=1;
            std::copy(hostword.begin(),hostword.end(),accept.begin()+20);
            for(const auto at:{36u,42u,54u})std::copy(hostword.begin(),hostword.end(),accept.begin()+at);
            accept[40]=accept[46]=0x30;accept[41]=accept[47]=0x39;
            const auto out=send_host(accept,i+2);
            verify(out.size()==1,"B328 addressed Citra accept is emitted once");
            check(!out[0].proxy_broadcast && out[0].proxy_remote_ip==ip && out[0].proxy_data.size()==120 &&
                  std::equal(ip.begin(),ip.end(),out[0].proxy_data.begin()+36) &&
                  out[0].proxy_data[42]==request[56] && out[0].proxy_data[43]==request[57],
                  "B328 addressed accept cannot borrow another guest endpoint or short identity");
        }
        for(unsigned round=0;round<3;++round)for(unsigned i=0;i<guests;++i) {
            auto incoming=mh(64,0x20);incoming[5]=0x70+i;
            std::copy(ips[i].begin(),ips[i].end(),incoming.begin()+20);
            incoming[32]=0x55;
            check(bridge.translate_game_return(ips[i],incoming).has_value(),
                  "B328 every GU negotiated stream survives later guests joining and interleaved packets");
            std::copy(ips[(i+1)%guests].begin(),ips[(i+1)%guests].end(),incoming.begin()+20);
            check(!bridge.translate_game_return(ips[i],incoming),"B328 authenticated room source rejects another member sender word");
            auto outgoing=mh(64,0x20);outgoing[5]=0x90+i;outgoing[32]=0x55;
            std::copy(hostword.begin(),hostword.end(),outgoing.begin()+20);
            const auto out=send_host(outgoing,i+2);
            check(out.size()==1 && out[0].proxy_remote_ip==ips[i] && !out[0].proxy_broadcast,
                  "B328 per-guest Citra bulk stays addressed to its real UDS destination");
        }
        auto roster=mh(52+72*(guests+1),2);roster[32]=2;roster[33]=guests+1;roster[35]=guests;
        std::copy(hostword.begin(),hostword.end(),roster.begin()+20);
        for(unsigned i=0;i<guests;++i)std::copy(canonical[i].begin(),canonical[i].end(),roster.begin()+120+72*i);
        const auto out=send_host(roster,0xffff);
        verify(out.size()==guests,"B328 common roster reaches every admitted GU exactly once");
        for(const auto& emission:out)for(unsigned i=0;i<guests;++i)
            check(std::equal(original[i].begin(),original[i].end(),emission.proxy_data.begin()+120+72*i),
                  "B328 every recipient sees every original full GU descriptor, not only the last join");
        room_client::LdnPacket leave;leave.type=room_client::LdnType::Disconnect;
        leave.local_ip=ips.back();leave.data.assign(64,0);
        verify(bridge.on_ldn(leave,{}).accepted,"B328 one guest departs without resetting the host");
        auto stream=mh(64,0x20);stream[5]=0x70;
        std::copy(ips[0].begin(),ips[0].end(),stream.begin()+20);
        check(bridge.translate_game_return(ips[0],stream).has_value(),"B328 surviving guest retains its negotiated stream after peer leaves");
        check(!bridge.translate_game_return(ips.back(),stream),"B328 departed guest cannot reuse its retired admission");
    }
}

void group_b304_reverse_discovery() {
    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b304";
    options.ldn_gu_host_discovery = true;
    options.ldn_comm_id_override = 0x0100770008dd8000ULL;
    options.have_uds_wlan_comm_id = true;
    options.uds_wlan_comm_id = 0x00197110;
    options.uds_attributes = 0x80;
    const room_client::IPv4 local{10, 83, 4, 1}, remote{10, 83, 4, 2};
    const citra_room::MacAddress host{2, 0, 10, 83, 4, 2};
    citra_gateway::ControlBridge bridge(options, local, {2, 0, 10, 83, 4, 1});
    check(bridge.start().empty(), "B304 reverse discovery starts without a template beacon");
    const auto first = bridge.tick(100);
    check(first.size() == 1 && !first[0].to_citra && first[0].ldn_broadcast &&
              first[0].ldn_type == room_client::LdnType::Scan && first[0].ldn_body.empty(),
          "B304 reverse discovery emits a standard empty broadcast scan");
    citra_control::LdnNetworkInfoBody network;
    network.network_id.intent_id.local_communication_id = options.ldn_comm_id_override;
    network.common.bssid = host;
    network.common.channel = 6;
    network.common.network_type = 2;
    network.ldn.node_count = 1;
    network.ldn.node_count_max = 4;
    network.ldn.nodes[0].mac_address = host;
    network.ldn.nodes[0].is_connected = 1;
    network.ldn.nodes[0].user_name[0] = 'G';
    network.ldn.advertise_data_size = 200;
    network.ldn.advertise_data[8] = network.ldn.advertise_data[0x1c] =
        network.ldn.advertise_data[0x20] = 1;
    network.ldn.advertise_data[0x58] = 0x12;
    const auto built = citra_control::serialize_ldn_network_info(network);
    check(built.ok(), "B304 GU discovery fixture has valid native NetworkInfo");
    room_client::LdnPacket response;
    response.type = room_client::LdnType::ScanResponse;
    response.local_ip = remote;
    response.remote_ip = local;
    response.data = built.value;
    const auto accepted = bridge.on_ldn(response, {});
    check(accepted.accepted && accepted.emissions.size() == 1 &&
              accepted.emissions[0].citra_transmitter == host &&
              accepted.emissions[0].citra_destination == citra_room::broadcast_mac,
          "B304 a live GU host becomes a Citra broadcast with the host MAC");
    if (!accepted.emissions.empty()) {
        const auto& bytes = accepted.emissions[0].citra_data;
        const auto beacon = citra_control::parse_beacon_frame(bytes.data(), bytes.size(), host);
        check(beacon.ok() && beacon.value.appdata_size == 200 &&
                  beacon.value.appdata[0x50] == 0x12 &&
                  beacon.value.network_info.wlan_comm_id == 0x00197110 &&
                  beacon.value.network_info.total_nodes == 1 &&
                  beacon.value.network_info.max_nodes == 4,
              "B304 converted GU beacon passes native SHA and encrypted node decoding");
    }
    response.remote_ip = remote;
    check(!bridge.on_ldn(response, {}).accepted,
          "B304 a response addressed to another station cannot refresh a hall");
    response.remote_ip = local;
    response.data.pop_back();
    check(!bridge.on_ldn(response, {}).accepted,
          "B304 truncated GU NetworkInfo cannot refresh a hall");
    const auto expired = bridge.tick(1701);
    check(std::none_of(expired.begin(), expired.end(), [](const auto& e) { return e.to_citra; }) &&
              bridge.counters().at("gu_host_hall_expired") == 1,
          "B304 expired GU halls stop producing Citra beacons");
    citra_room::WifiPacket auth;
    auth.type = citra_room::FrameType::Authentication;
    check(bridge.on_citra_wifi(auth, 1702).empty(),
          "B304 discovery role does not accidentally serve synthetic admission");
}

void group_b305_reverse_association() {
    citra_gateway::ControlOptions options;
    options.ldn_gu_host_discovery = options.ldn_gu_host_admission = true;
    options.have_uds_wlan_comm_id = true;
    options.uds_wlan_comm_id = 0x00197110;
    options.ldn_comm_id_override = 0x0100770008dd8000ULL;
    const room_client::IPv4 local{10, 83, 5, 1}, remote{10, 83, 5, 2};
    const citra_room::MacAddress guest{2, 0, 10, 83, 5, 1}, host{2, 0, 10, 83, 5, 2};
    citra_gateway::ControlBridge bridge(options, local, guest);
    bridge.start();
    bridge.tick(100);
    citra_control::LdnNetworkInfoBody network;
    network.network_id.intent_id.local_communication_id = options.ldn_comm_id_override;
    network.network_id.session_id.low = 15;
    network.common.bssid = host;
    network.common.channel = 6;
    network.common.network_type = 2;
    network.ldn.node_count = 1;
    network.ldn.node_count_max = 4;
    network.ldn.nodes[0].mac_address = host;
    network.ldn.nodes[0].is_connected = 1;
    network.ldn.nodes[0].user_name[0] = 'G';
    network.ldn.advertise_data_size = 200;
    network.ldn.advertise_data[8] = network.ldn.advertise_data[0x1c] =
        network.ldn.advertise_data[0x20] = 1;
    room_client::LdnPacket packet;
    packet.type = room_client::LdnType::ScanResponse;
    packet.local_ip = remote;
    packet.remote_ip = local;
    packet.data = citra_control::serialize_ldn_network_info(network).value;
    check(bridge.on_ldn(packet, {}).accepted, "B305 real hall must precede reverse admission");
    citra_room::WifiPacket wifi;
    wifi.transmitter = guest;
    wifi.destination = host;
    wifi.type = citra_room::FrameType::Authentication;
    wifi.data = citra_control::build_authentication_frame({}).value;
    wifi.destination[5] ^= 1;
    check(bridge.on_citra_wifi(wifi, 101).empty(), "B305 unknown host gets no association");
    wifi.destination = host;
    const auto auth = bridge.on_citra_wifi(wifi, 102);
    check(auth.size() == 2 && auth[0].citra_transmitter == host &&
              auth[1].citra_type == citra_room::FrameType::AssociationResponse &&
              auth[1].citra_destination == guest,
          "B305 authentication uses the selected GU host and actual XX guest");
    check(bridge.on_citra_wifi(wifi, 103).empty(), "B305 repeated authentication cannot double connect");
    citra_control::EapolStartPacket start;
    start.association_id = 1;
    start.node.friend_code_seed = 0x12345678;
    start.node.username[0] = 'X';
    wifi.type = citra_room::FrameType::Data;
    wifi.data = citra_control::build_eapol_start_frame(start).value;
    wifi.transmitter[5] ^= 1;
    check(bridge.on_citra_wifi(wifi, 104).empty(), "B305 foreign EAPoL cannot consume pending admission");
    wifi.transmitter = guest;
    const auto connect = bridge.on_citra_wifi(wifi, 105);
    check(connect.size() == 1 && connect[0].ldn_type == room_client::LdnType::Connect &&
              connect[0].ldn_remote_ip == remote && !connect[0].to_citra,
          "B305 EAPoL emits native LDN Connect and never premature logoff");
    if (connect.empty()) return;
    const auto node = citra_control::parse_ldn_node_info(connect[0].ldn_body.data(),
                                                     connect[0].ldn_body.size());
    check(node.ok() && node.value.mac_address == guest && node.value.user_name[0] == 'X' &&
              node.value.ipv4_address == room_client::IPv4{1, 5, 83, 10},
          "B305 Connect carries guest MAC, UTF-8 name and native reversed IP");
    check(bridge.on_citra_wifi(wifi, 106).empty(), "B305 repeated EAPoL does not duplicate native Connect");
    network.ldn.nodes[1] = node.value;
    network.ldn.nodes[1].node_id = 1;
    network.ldn.node_count = 2;
    packet.type = room_client::LdnType::SyncNetwork;
    packet.data = citra_control::serialize_ldn_network_info(network).value;
    packet.local_ip = local;
    check(!bridge.on_ldn(packet, {}).accepted, "B305 foreign SyncNetwork cannot admit the guest");
    packet.local_ip = remote;
    network.network_id.session_id.low++;
    packet.data = citra_control::serialize_ldn_network_info(network).value;
    check(!bridge.on_ldn(packet, {}).accepted, "B305 another hall session cannot complete admission");
    network.network_id.session_id.low--;
    packet.data = citra_control::serialize_ldn_network_info(network).value;
    const auto sync = bridge.on_ldn(packet, {});
    check(sync.accepted && sync.emissions.size() == 2,
          "B305 GU membership confirmation emits node map and logoff");
    if (sync.emissions.size() == 2) {
        const auto& bytes = sync.emissions[1].citra_data;
        const auto logoff = citra_control::parse_eapol_logoff_frame(bytes.data(), bytes.size());
        check(logoff.ok() && logoff.value.assigned_node_id == 2 &&
                  logoff.value.nodes[1].friend_code_seed == start.node.friend_code_seed &&
                  logoff.value.nodes[1].username == start.node.username &&
                  logoff.value.connected_nodes == 2,
              "B305 logoff preserves XX identity with GU-assigned node index plus one");
    }
    wifi.type = citra_room::FrameType::Deauthentication;
    wifi.data.clear();
    citra_room::Bytes announce(140, 0);
    const citra_room::Bytes announce_header{0x32, 0xab, 0x98, 0x64, 1, 0};
    std::copy(announce_header.begin(), announce_header.end(), announce.begin());
    announce[15] = 105;
    std::copy(remote.begin(), remote.end(), announce.begin() + 20);
    announce[24] = 3; announce[26] = 0x30; announce[27] = 0x39;
    announce[32] = 1; announce[33] = 0x11; announce[34] = 73; announce[44] = 2;
    announce[48] = 0x57; announce[52] = 0x93; announce[56] = 1;
    for (std::size_t i = 0; i < 8; ++i) announce[64 + 9 * i + 8] = 0xff;
    std::copy(remote.begin(), remote.end(), announce.begin() + 64);
    announce[68] = 0x30; announce[69] = 0x39; announce[72] = 0;
    std::copy(local.begin(), local.end(), announce.begin() + 73);
    announce[77] = 0x30; announce[78] = 0x39; announce[81] = 1;
    const auto expanded = bridge.translate_gu_host_announcement(remote, announce);
    check(expanded && expanded->size() == 176 && (*expanded)[15] == 141 &&
              (*expanded)[34] == 109 && (*expanded)[71] == 1 && (*expanded)[80] == 2 &&
              (*expanded)[48] == 0x57 && (*expanded)[52] == 0x93 && (*expanded)[171] == 0xff,
          "B306 reverse announcement expands native slots and preserves session words");
    const auto host_word = citra_gateway::mhxx_identity_word_from_seed(0);
    const auto guest_word = citra_gateway::mhxx_identity_word_from_seed(start.node.friend_code_seed);
    check(expanded && std::equal(host_word.begin(), host_word.end(), expanded->begin() + 20) &&
              std::equal(host_word.begin(), host_word.end(), expanded->begin() + 64) &&
              std::equal(guest_word.begin(), guest_word.end(), expanded->begin() + 73),
          "B306 reverse announcement derives endpoints from the actual advertised UDS seeds");
    const auto emissions = bridge.on_gu_host_proxy(remote, announce);
    const auto secure = emissions.empty() ? citra_room::Bytes{} : emissions[0].citra_data;
    const auto decoded = citra_control::parse_secure_data_frame(secure.data(), secure.size());
    check(emissions.size() == 1 && emissions[0].citra_transmitter == host &&
              emissions[0].citra_destination == guest && decoded.ok() &&
              decoded.value.header.src_node_id == 1 && decoded.value.header.dest_node_id == 0xffff &&
              decoded.value.header.data_channel == 243 && expanded && decoded.value.payload == *expanded,
          "B306 selected GU host emits a native UDS broadcast to the associated guest");
    check(!bridge.translate_gu_host_announcement(local, announce),
          "B306 another room member cannot claim the selected GU host");
    auto bad_announce = announce;
    bad_announce[44] = 4;
    const auto four_declared = bridge.translate_gu_host_announcement(remote, bad_announce);
    check(four_declared && (*four_declared)[44] == 4 &&
              std::equal(expanded->begin() + 64, expanded->end(), four_declared->begin() + 64),
          "B312 native declaration4 accepts two confirmed occupants and preserves empty slots");
    bad_announce[44] = 10;
    const auto rejoin_metadata = bridge.translate_gu_host_announcement(remote, bad_announce);
    check(rejoin_metadata && (*rejoin_metadata)[44] == 10 &&
              std::equal(expanded->begin() + 64, expanded->end(), rejoin_metadata->begin() + 64),
          "B315 actual rejoin metadata10 preserves the two confirmed occupants");
    bad_announce[44] = 0; bad_announce[45] = 1; bad_announce[46] = 0x82; bad_announce[47] = 0xff;
    const auto opaque_metadata = bridge.translate_gu_host_announcement(remote, bad_announce);
    check(opaque_metadata && std::equal(bad_announce.begin() + 44, bad_announce.begin() + 48,
                                       opaque_metadata->begin() + 44),
          "B315 all four opaque announcement metadata bytes survive independently of slot validation");
    bad_announce[82] = 10;
    check(!bridge.translate_gu_host_announcement(remote, bad_announce),
          "B315 opaque metadata never authorizes an unknown occupied endpoint");
    bad_announce = announce; bad_announce[44] = 4; bad_announce[82] = 10;
    check(!bridge.translate_gu_host_announcement(remote, bad_announce),
          "B312 declaration4 cannot authorize an unknown occupied endpoint");
    bad_announce = announce;
    bad_announce[73] ^= 1;
    check(!bridge.translate_gu_host_announcement(remote, bad_announce),
          "B306 unconfirmed guest endpoint cannot enter the member table");
    bad_announce = announce; bad_announce[15]--;
    check(!bridge.translate_gu_host_announcement(remote, bad_announce),
          "B306 malformed native length is rejected");
    citra_room::Bytes reverse_request(112, 0);
    std::copy(announce_header.begin(), announce_header.end(), reverse_request.begin());
    reverse_request[5] = 1; reverse_request[13] = 0xfd; reverse_request[15] = 78;
    reverse_request[24] = 1; reverse_request[32] = 1; reverse_request[33] = 0x0f;
    reverse_request[34] = 7;
    for (const auto offset : {36u, 42u, 54u})
        std::copy(guest_word.begin(), guest_word.end(), reverse_request.begin() + offset);
    reverse_request[40] = reverse_request[46] = 0x30;
    reverse_request[41] = reverse_request[47] = 0x39;
    reverse_request[48] = 0x21; reverse_request[49] = 0x88;
    reverse_request[50] = 0xea; reverse_request[51] = 0xda;
    reverse_request[52] = 0x21; reverse_request[53] = 0x88;
    reverse_request[85] = 0xab; // Secondary descriptor byte must not be zeroed.
    reverse_request[106] = 0xea; reverse_request[107] = 0xfb;
    reverse_request[108] = 0x79; reverse_request[109] = 0xc0;
    citra_control::SecureDataFrame guest_frame;
    guest_frame.header.src_node_id = 2; guest_frame.header.dest_node_id = 1;
    guest_frame.header.data_channel = 243; guest_frame.payload = reverse_request;
    citra_room::WifiPacket guest_wifi;
    guest_wifi.type = citra_room::FrameType::Data;
    guest_wifi.transmitter = guest; guest_wifi.destination = host;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto reverse_join = bridge.on_gu_host_guest_game(guest_wifi);
    check(reverse_join.size() == 1 && reverse_join[0].room_proxy &&
              !reverse_join[0].proxy_broadcast && reverse_join[0].proxy_remote_ip == remote &&
              reverse_join[0].proxy_data.size() == 120 && reverse_join[0].proxy_data[15] == 86 &&
              reverse_join[0].proxy_data[93] == 0xab && reverse_join[0].proxy_data[114] == 0xea &&
              std::equal(remote.begin(), remote.end(), reverse_join[0].proxy_data.begin() + 36) &&
              std::equal(local.begin(), local.end(), reverse_join[0].proxy_data.begin() + 44),
          "B307 reverse guest request adds addressed endpoint8 and retains all70 descriptor bytes");
    guest_frame.header.src_node_id = 1;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    check(bridge.on_gu_host_guest_game(guest_wifi).empty(), "B307 a host-node spoof cannot send a guest request");
    guest_frame.header.src_node_id = 2; guest_frame.header.data_channel = 33;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    check(bridge.on_gu_host_guest_game(guest_wifi).empty(), "B307 generic codec channel cannot enter native guest path");
    citra_room::Bytes native_accept(120, 0);
    std::copy(reverse_request.begin(), reverse_request.begin() + 36, native_accept.begin());
    native_accept[15] = 86; native_accept[35] = 1;
    std::copy(local.begin(), local.end(), native_accept.begin() + 36);
    native_accept[40] = 0x30; native_accept[41] = 0x39;
    native_accept[42] = 0x21; native_accept[43] = 0x88;
    for (const auto offset : {44u, 50u, 62u})
        std::copy(remote.begin(), remote.end(), native_accept.begin() + offset);
    native_accept[48] = native_accept[54] = 0x30;
    native_accept[49] = native_accept[55] = 0x39;
    native_accept[93] = 0x7c; native_accept[114] = 0x6b;
    const auto accepted_join = bridge.on_gu_host_proxy(remote, native_accept);
    const auto accepted_bytes = accepted_join.empty() ? citra_room::Bytes{} : accepted_join[0].citra_data;
    const auto accepted_secure = citra_control::parse_secure_data_frame(accepted_bytes.data(), accepted_bytes.size());
    check(accepted_secure.ok() && accepted_secure.value.header.dest_node_id == 2 &&
              accepted_secure.value.payload.size() == 112 && accepted_secure.value.payload[5] == 0 &&
              accepted_secure.value.payload[85] == 0x7c && accepted_secure.value.payload[106] == 0x6b &&
              std::equal(host_word.begin(), host_word.end(), accepted_secure.value.payload.begin() + 36),
          "B307 native GU accept removes only endpoint8 and maps the complete host descriptor");
    native_accept[36] ^= 1;
    check(bridge.on_gu_host_proxy(remote, native_accept).empty(), "B307 accept for another guest cannot cross the session boundary");
    guest_frame.header.data_channel = 243;
    citra_room::Bytes ack(reverse_request.begin(), reverse_request.begin() + 40);
    ack[15] = 8; ack[32] = 5; ack[33] = ack[34] = ack[35] = 0;
    ack[36] = 0x51; ack[37] = 0x53; ack[38] = 0x44; ack[39] = 0x34;
    guest_frame.payload = ack;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto reverse_ack = bridge.on_gu_host_guest_game(guest_wifi);
    check(reverse_ack.size() == 1 && reverse_ack[0].proxy_data == ack &&
              !reverse_ack[0].proxy_broadcast,
          "B308 guest ACK retains the native host counter and unicast destination");
    citra_room::Bytes blob(268, 0);
    std::copy_n(ack.begin(), 32, blob.begin());
    blob[15] = 235; blob[32] = 2; blob[34] = 7; blob[35] = 2;
    blob[0x4d] = 'X'; blob[0x107] = 0xb7; blob[0x10a] = 0xbc;
    guest_frame.payload = blob;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto reverse_blob = bridge.on_gu_host_guest_game(guest_wifi);
    check(reverse_blob.size() == 1 && reverse_blob[0].proxy_data.size() == 828 &&
              reverse_blob[0].proxy_data[5] == 1 && reverse_blob[0].proxy_data[35] == 4 &&
              reverse_blob[0].proxy_data[0x338] == 0xb7 && reverse_blob[0].proxy_data[0x33b] == 0xbc &&
              reverse_blob[0].proxy_data[0x4c] == 'X' &&
              std::equal(network.ldn.advertise_data.begin() + 0x14,
                         network.ldn.advertise_data.begin() + 0x1c,
                         reverse_blob[0].proxy_data.begin() + 0x25),
          "B308 guest blob expands names and counter using this GU hall host identifier");
    auto compound = ack;
    compound.insert(compound.end(), blob.begin() + 12, blob.end());
    guest_frame.payload = compound;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto reverse_compound = bridge.on_gu_host_guest_game(guest_wifi);
    check(reverse_compound.size() == 1 && reverse_compound[0].proxy_data.size() == 856 &&
              std::equal(ack.begin(), ack.end(), reverse_compound[0].proxy_data.begin()),
          "B308 coalesced ACK and blob retain one datagram and the outer sequence");
    compound.pop_back();
    guest_frame.payload = compound;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    check(bridge.on_gu_host_guest_game(guest_wifi).empty(),
          "B308 truncated coalesced blob cannot emit a partial ACK");
    auto host_ack = ack;
    host_ack[5] = 0;
    std::copy(remote.begin(), remote.end(), host_ack.begin() + 20);
    const auto host_ack_out = bridge.on_gu_host_proxy(remote, host_ack);
    const auto host_ack_secure = host_ack_out.empty() ? citra_control::SecureDataFrame{} :
        citra_control::parse_secure_data_frame(host_ack_out[0].citra_data.data(),
                                              host_ack_out[0].citra_data.size()).value;
    check(host_ack_out.size() == 1 && host_ack_secure.header.dest_node_id == 2 &&
              host_ack_secure.payload.size() == 40 && host_ack_secure.payload[39] == 0x34 &&
              std::equal(host_word.begin(), host_word.end(), host_ack_secure.payload.begin() + 20),
          "B309 native host ACK maps the sender and preserves the guest counter");
    auto host_blob = reverse_blob[0].proxy_data;
    host_blob[5] = 0;
    std::copy(remote.begin(), remote.end(), host_blob.begin() + 20);
    const auto host_blob_out = bridge.on_gu_host_proxy(remote, host_blob);
    const auto host_blob_secure = host_blob_out.empty() ? citra_control::SecureDataFrame{} :
        citra_control::parse_secure_data_frame(host_blob_out[0].citra_data.data(),
                                              host_blob_out[0].citra_data.size()).value;
    check(host_blob_out.size() == 1 && host_blob_secure.header.dest_node_id == 2 &&
              host_blob_secure.payload.size() == 268 && host_blob_secure.payload[5] == 0 &&
              host_blob_secure.payload[35] == 2 && host_blob_secure.payload[0x4d] == 'X' &&
              host_blob_secure.payload[0x107] == 0xb7 && host_blob_secure.payload[0x10a] == 0xbc,
          "B309 native host blob maps GU names and counter back into XX family02");
    host_blob[20] ^= 1;
    check(bridge.on_gu_host_proxy(remote, host_blob).empty(),
          "B309 native host blob cannot claim another sender identity");
    citra_room::Bytes peer_connect(48, 0);
    std::copy_n(reverse_request.begin(), 32, peer_connect.begin());
    peer_connect[15] = 14; peer_connect[24] = 2; peer_connect[32] = 1; peer_connect[33] = 0xfd;
    std::copy(guest_word.begin(), guest_word.end(), peer_connect.begin() + 20);
    std::copy(guest_word.begin(), guest_word.end(), peer_connect.begin() + 36);
    peer_connect[40] = 0x30; peer_connect[41] = 0x39;
    peer_connect[42] = 0xd0; peer_connect[43] = 0x1e; peer_connect[44] = 0x38; peer_connect[45] = 0x9d;
    guest_frame.payload = peer_connect;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto peer_out = bridge.on_gu_host_guest_game(guest_wifi);
    check(peer_out.size() == 1 && peer_out[0].proxy_data.size() == 48 &&
              std::equal(local.begin(), local.end(), peer_out[0].proxy_data.begin() + 20) &&
              std::equal(local.begin(), local.end(), peer_out[0].proxy_data.begin() + 36) &&
              std::equal(peer_connect.begin() + 40, peer_connect.end(), peer_out[0].proxy_data.begin() + 40),
          "B310 guest game connect maps only canonical sender and endpoint, retaining counter");
    peer_connect[36] ^= 1;
    guest_frame.payload = peer_connect;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    check(bridge.on_gu_host_guest_game(guest_wifi).empty(),
          "B310 guest game connect cannot claim another endpoint");
    citra_room::Bytes roster(196, 0);
    std::copy_n(host_ack.begin(), 32, roster.begin());
    roster[15] = 164; roster[24] = 2; roster[32] = roster[33] = 2; roster[35] = 1;
    std::copy_n(native_accept.begin() + 44, 70, roster.begin() + 48);
    std::copy_n(reverse_join[0].proxy_data.begin() + 44, 70, roster.begin() + 120);
    const auto roster_out = bridge.on_gu_host_proxy(remote, roster);
    const auto roster_secure = roster_out.empty() ? citra_control::SecureDataFrame{} :
        citra_control::parse_secure_data_frame(roster_out[0].citra_data.data(), roster_out[0].citra_data.size()).value;
    check(roster_out.size() == 1 && roster_secure.header.dest_node_id == 2 &&
              std::equal(reverse_request.begin() + 36, reverse_request.begin() + 106,
                         roster_secure.payload.begin() + 120) &&
              std::equal(host_word.begin(), host_word.end(), roster_secure.payload.begin() + 48),
          "B311 roster restores all70 bytes of the local guest and maps the native host descriptor");
    roster[189] ^= 1;
    check(bridge.on_gu_host_proxy(remote, roster).empty(),
          "B311 unknown secondary roster fields cannot be partially rewritten");
    citra_room::Bytes periodic(332, 0);
    std::copy_n(host_ack.begin(), 32, periodic.begin());
    periodic[14] = 1; periodic[15] = 44; periodic[24] = 2;
    periodic[32] = 0x20; periodic[33] = 2;
    std::copy_n(native_accept.begin() + 44, 70, periodic.begin() + 44);
    std::copy_n(reverse_join[0].proxy_data.begin() + 44, 70, periodic.begin() + 116);
    const auto periodic_out = bridge.on_gu_host_proxy(remote, periodic);
    const auto periodic_secure = periodic_out.empty() ? citra_control::SecureDataFrame{} :
        citra_control::parse_secure_data_frame(periodic_out[0].citra_data.data(), periodic_out[0].citra_data.size()).value;
    check(periodic_out.size() == 1 &&
              std::equal(reverse_request.begin() + 36, reverse_request.begin() + 106,
                         periodic_secure.payload.begin() + 116) &&
              std::equal(host_word.begin(), host_word.end(), periodic_secure.payload.begin() + 44),
          "B314 periodic332 roster restores exact descriptors at its native offsets");
    citra_room::Bytes heartbeat(48, 0);
    std::copy_n(host_ack.begin(), 32, heartbeat.begin());
    heartbeat[15] = 16; heartbeat[24] = 6; heartbeat[47] = 0xa7;
    auto host_compound = periodic;
    host_compound.insert(host_compound.end(), heartbeat.begin() + 12, heartbeat.end());
    const auto compound_out = bridge.on_gu_host_proxy(remote, host_compound);
    const auto compound_secure = compound_out.empty() ? citra_control::SecureDataFrame{} :
        citra_control::parse_secure_data_frame(compound_out[0].citra_data.data(), compound_out[0].citra_data.size()).value;
    check(compound_out.size() == 1 && compound_secure.payload.size() == 368 &&
              compound_secure.payload.back() == 0xa7 &&
              std::equal(host_word.begin(), host_word.end(), compound_secure.payload.begin() + 340),
          "B314 host compound368 retains both translated messages and heartbeat body");
    periodic[185] ^= 1;
    check(bridge.on_gu_host_proxy(remote, periodic).empty(),
          "B314 periodic roster rejects a foreign secondary descriptor");
    host_compound[344] = 0x55;
    check(bridge.on_gu_host_proxy(remote, host_compound).empty(),
          "B314 host compound rejects unsupported inner route atomically");
    auto session_ack = ack;
    session_ack[5] = 0;
    std::copy(guest_word.begin(), guest_word.end(), session_ack.begin() + 20);
    guest_frame.payload = session_ack;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto session_ack_out = bridge.on_gu_host_guest_game(guest_wifi);
    check(session_ack_out.size() == 1 && session_ack_out[0].proxy_data[5] == 0 &&
              std::equal(session_ack.begin() + 32, session_ack.end(), session_ack_out[0].proxy_data.begin() + 32),
          "B314 native role0 session ACK retains the actual counter");
    heartbeat[5] = reverse_request[33];
    std::copy(guest_word.begin(), guest_word.end(), heartbeat.begin() + 20);
    guest_frame.payload = heartbeat;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto heartbeat_out = bridge.on_gu_host_guest_game(guest_wifi);
    check(heartbeat_out.size() == 1 && heartbeat_out[0].proxy_data.back() == 0xa7,
          "B314 negotiated guest heartbeat preserves native body");
    heartbeat[5] = 0;
    auto compound_guest = heartbeat;
    auto stream_ack = heartbeat;
    stream_ack[24] = 2; stream_ack[25] = 0x10;
    compound_guest.insert(compound_guest.end(), stream_ack.begin() + 12, stream_ack.end());
    compound_guest.insert(compound_guest.end(), heartbeat.begin() + 12, heartbeat.end());
    guest_frame.payload = compound_guest;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto compound_guest_out = bridge.on_gu_host_guest_game(guest_wifi);
    check(compound_guest_out.size() == 1 && compound_guest_out[0].proxy_data.size() == 120 &&
              std::equal(local.begin(), local.end(), compound_guest_out[0].proxy_data.begin() + 56) &&
              std::equal(local.begin(), local.end(), compound_guest_out[0].proxy_data.begin() + 92),
          "B314 native role0 compound120 forwards every heartbeat and stream ACK");
    compound_guest[5] = 0x7e;
    guest_frame.payload = compound_guest;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    check(bridge.on_gu_host_guest_game(guest_wifi).empty(),
          "B314 unknown compound session kind remains rejected");
    citra_room::Bytes stream(188, 0xa5);
    std::copy_n(host_ack.begin(), 32, stream.begin());
    stream[15] = 154; stream[24] = 0x20; stream[5] = native_accept[33];
    std::copy(remote.begin(), remote.end(), stream.begin() + 60); // Coincidental body match.
    const auto stream_out = bridge.on_gu_host_proxy(remote, stream);
    const auto stream_secure = stream_out.empty() ? citra_control::SecureDataFrame{} :
        citra_control::parse_secure_data_frame(stream_out[0].citra_data.data(), stream_out[0].citra_data.size()).value;
    check(stream_out.size() == 1 && stream_secure.header.dest_node_id == 2 &&
              std::equal(stream.begin() + 32, stream.end(), stream_secure.payload.begin() + 32),
          "B311 negotiated native host stream preserves opaque body including IP-like bytes");
    stream[5] ^= 0x55;
    check(bridge.on_gu_host_proxy(remote, stream).empty(),
          "B311 unnegotiated native host stream kind is rejected");
    stream[5] = reverse_request[33];
    std::copy(guest_word.begin(), guest_word.end(), stream.begin() + 20);
    guest_frame.payload = stream;
    guest_wifi.data = citra_control::build_secure_data_frame(guest_frame).value;
    const auto guest_stream_out = bridge.on_gu_host_guest_game(guest_wifi);
    check(guest_stream_out.size() == 1 &&
              std::equal(local.begin(), local.end(), guest_stream_out[0].proxy_data.begin() + 20) &&
              std::equal(stream.begin() + 32, stream.end(), guest_stream_out[0].proxy_data.begin() + 32),
          "B311 guest negotiated stream maps only header identity and preserves the opaque body");
    const auto depart = bridge.on_citra_wifi(wifi, 110);
    check(bridge.on_gu_host_guest_game(guest_wifi).empty(), "B307 reverse requests stop immediately on departure");
    check(!bridge.gu_host_source(remote) && bridge.on_gu_host_proxy(remote, announce).empty(),
          "B306 leaving immediately retires the host source and announcement route");
    check(depart.size() == 2 && depart[0].ldn_type == room_client::LdnType::Disconnect &&
              depart[0].ldn_body.size() == connect[0].ldn_body.size(),
          "B305 leave includes the native NodeInfo required by GU Disconnect handler");
    check(bridge.on_citra_wifi(wifi, 111).empty(), "B305 repeated leave is idempotent");
    wifi.type = citra_room::FrameType::Authentication;
    wifi.data = citra_control::build_authentication_frame({}).value;
    check(bridge.on_citra_wifi(wifi, 112).size() == 2, "B305 same guest can start a fresh association");
    const auto timeout = bridge.tick(5113);
    check(std::any_of(timeout.begin(), timeout.end(), [](const auto& e) {
              return e.citra_type == citra_room::FrameType::Deauthentication && e.to_citra;
          }), "B305 stalled reverse association deauthenticates and releases pending identity");
    citra_gateway::ControlBridge cleaner(options, local, guest);
    cleaner.start(); cleaner.tick(100);
    auto stale_packet = packet;
    stale_packet.type = room_client::LdnType::ScanResponse;
    stale_packet.data = citra_control::serialize_ldn_network_info(network).value;
    const auto stale_cleanup = cleaner.on_ldn(stale_packet, {});
    check(stale_cleanup.accepted && stale_cleanup.emissions.size() == 1 &&
              stale_cleanup.emissions[0].ldn_type == room_client::LdnType::Disconnect &&
              !stale_cleanup.emissions[0].to_citra,
          "B313 stale local membership triggers native Disconnect before any beacon or Connect");
    auto auth_wifi = wifi;
    check(cleaner.on_citra_wifi(auth_wifi, 101).empty(),
          "B313 stale hall cannot admit another duplicate local member");
    auto duplicate_network = network;
    duplicate_network.ldn.nodes[2] = duplicate_network.ldn.nodes[1];
    duplicate_network.ldn.nodes[2].node_id = 2;
    duplicate_network.ldn.node_count = 3;
    stale_packet.data = citra_control::serialize_ldn_network_info(duplicate_network).value;
    const auto duplicate_cleanup = cleaner.on_ldn(stale_packet, {});
    check(duplicate_cleanup.emissions.size() == 1 &&
              duplicate_cleanup.emissions[0].ldn_type == room_client::LdnType::Disconnect,
          "B313 duplicate stale slots are removed by native host responses without count fabrication");
    auto clean_network = network;
    clean_network.ldn.nodes[1].is_connected = 0;
    clean_network.ldn.node_count = 1;
    stale_packet.data = citra_control::serialize_ldn_network_info(clean_network).value;
    const auto clean_scan = cleaner.on_ldn(stale_packet, {});
    check(clean_scan.accepted && clean_scan.emissions.size() == 1 &&
              clean_scan.emissions[0].citra_type == citra_room::FrameType::Beacon &&
              cleaner.on_citra_wifi(auth_wifi, 102).size() == 2,
          "B313 native clean scan restores discoverability and admission");
    const auto arm = [&](std::uint64_t now, bool confirm) {
        bridge.tick(now);
        network.ldn.node_count = 1;
        network.ldn.nodes[1] = {};
        packet.type = room_client::LdnType::ScanResponse;
        packet.local_ip = remote;
        packet.remote_ip = local;
        packet.broadcast = false;
        packet.data = citra_control::serialize_ldn_network_info(network).value;
        bridge.on_ldn(packet, {});
        wifi.type = citra_room::FrameType::Authentication;
        wifi.data = citra_control::build_authentication_frame({}).value;
        bridge.on_citra_wifi(wifi, now + 1);
        wifi.type = citra_room::FrameType::Data;
        wifi.data = citra_control::build_eapol_start_frame(start).value;
        const auto request = bridge.on_citra_wifi(wifi, now + 2);
        if (confirm) {
            network.ldn.node_count = 2;
            network.ldn.nodes[1] = node.value;
            network.ldn.nodes[1].node_id = 1;
            packet.type = room_client::LdnType::SyncNetwork;
            packet.data = citra_control::serialize_ldn_network_info(network).value;
            bridge.on_ldn(packet, {});
        }
        return request;
    };
    check(arm(6000, false).size() == 1, "B305 expired attempt permits a fresh native Connect");
    const auto sync_timeout = bridge.tick(11003);
    check(std::any_of(sync_timeout.begin(), sync_timeout.end(), [](const auto& e) {
              return !e.to_citra && e.ldn_type == room_client::LdnType::Disconnect && !e.ldn_body.empty();
          }), "B305 unanswered native Connect is explicitly withdrawn on timeout");
    arm(12000, true);
    const auto transport_leave = bridge.on_transport_departure();
    check(transport_leave.size() == 1 && !transport_leave[0].to_citra &&
              transport_leave[0].ldn_type == room_client::LdnType::Disconnect,
          "B305 room transport departure releases GU membership before closing");
    check(bridge.on_transport_departure().empty(), "B305 transport cleanup is idempotent");
    arm(13000, true);
    network.ldn.nodes[1] = {};
    network.ldn.node_count = 1;
    packet.data = citra_control::serialize_ldn_network_info(network).value;
    const auto evict = bridge.on_ldn(packet, {});
    check(evict.accepted && evict.emissions.size() == 1 && evict.emissions[0].to_citra &&
              evict.emissions[0].citra_type == citra_room::FrameType::Deauthentication,
          "B305 GU eviction clears XX association without a redundant Disconnect");
    arm(14000, true);
    packet.type = room_client::LdnType::DestroyNetwork;
    packet.data.clear();
    packet.broadcast = true;
    packet.local_ip = local;
    check(bridge.on_ldn(packet, {}).emissions.empty(), "B305 foreign destroy cannot remove selected GU membership");
    packet.local_ip = remote;
    const auto destroy = bridge.on_ldn(packet, {});
    check(destroy.accepted && destroy.emissions.size() == 1 && destroy.emissions[0].to_citra,
          "B305 selected host destruction terminates XX association");
    arm(15000, true);
    const auto silent = bridge.tick(20003);
    check(std::any_of(silent.begin(), silent.end(), [](const auto& e) {
              return e.to_citra && e.citra_type == citra_room::FrameType::Deauthentication;
          }), "B305 prolonged host silence clears connected membership");
}

void group_b303_reverse_advertise() {
    citra_room::Bytes gu(200, 0);
    gu[8] = gu[0x1c] = gu[0x20] = 1;
    gu[0] = 0x7a;
    std::fill(gu.begin() + 0x14, gu.begin() + 0x1c, 0xa5);
    for (std::size_t i = 0x34; i < 0x50; ++i) gu[i] = static_cast<std::uint8_t>(i);
    for (std::size_t i = 0x58; i < 0x60; ++i) gu[i] = static_cast<std::uint8_t>(i + 1);
    for (std::size_t i = 0x64; i < 0xc2; ++i) gu[i] = static_cast<std::uint8_t>(i + 3);
    const auto original = gu;
    const auto xx = citra_gateway::convert_gu_hall_advertise(gu);
    check(xx && xx->size() == 200 && gu == original && (*xx)[0] == gu[0],
          "B303 reverse hall conversion preserves session identity and source bytes");
    check(xx && std::equal(gu.begin() + 0x34, gu.begin() + 0x50, xx->begin() + 0x34) &&
              std::equal(gu.begin() + 0x58, gu.begin() + 0x60, xx->begin() + 0x50),
          "B303 reverse hall conversion places name and password in XX slots");
    check(xx && std::equal(gu.begin() + 0x64, gu.begin() + 0xc2, xx->begin() + 0x5c),
          "B303 reverse hall conversion preserves all four players and trailer");
    check(xx && std::all_of(xx->begin() + 0x0c, xx->begin() + 0x1c,
                           [](std::uint8_t value) { return value == 0; }),
          "B303 GU-only host identifier does not leak into XX reserved fields");
    gu.pop_back();
    check(!citra_gateway::convert_gu_hall_advertise(gu),
          "B303 reverse hall conversion rejects a truncated advertisement");
    gu = original;
    gu[8] = 2;
    check(!citra_gateway::convert_gu_hall_advertise(gu),
          "B303 reverse hall conversion rejects unknown format markers");
}

// V-277: the MHGU join request must reach MHXX with the requester's endpoint
// first in an 80-byte body, and MHXX's 112-byte accept must reach MHGU in its
// own 120-byte layout (v276: .verify-r26/g4/v276-mhxx-kind0/REPORT.md,
// docs/mhgu-join-response-static-evidence.json).  Byte-level conversion only;
// no Citra, no Yuzu and no game participate.
void group_b18_join_conversion() {
    const citra_room::MacAddress citra_mac{2, 0, 0, 0, 0, 40};
    const citra_room::MacAddress station_mac{2, 0, 0, 0, 0, 41};
    const citra_room::Bytes assoc_ok = bytes_from_hex("3104000001c000083030303030303030");
    const auto admit = [](citra_gateway::ControlBridge& bridge,
                          const citra_room::MacAddress& mac, const room_client::IPv4& ip) {
        citra_gateway::LdnContext ctx;
        ctx.have_mapped_mac = true;
        ctx.mapped_mac = mac;
        room_client::LdnPacket scan;
        scan.type = room_client::LdnType::Scan;
        scan.local_ip = ip;
        (void)bridge.on_ldn(scan, ctx);
        room_client::LdnPacket connect;
        connect.type = room_client::LdnType::Connect;
        connect.local_ip = ip;
        connect.data.assign(64, 0);
        return bridge.on_ldn(connect, ctx);
    };
    const auto beacon = [&](const citra_room::MacAddress& mac) {
        citra_room::WifiPacket wifi;
        wifi.type = citra_room::FrameType::Beacon;
        wifi.channel = 11;
        wifi.transmitter = mac;
        wifi.destination = citra_room::broadcast_mac;
        wifi.data.assign(64, 0x00);
        return wifi;
    };
    const auto logoff = [&]() {
        citra_control::EapolLogoffPacket packet;
        packet.assigned_node_id = 2;
        packet.client_mac_address = station_mac;
        packet.connected_nodes = 2;
        packet.max_nodes = 4;
        packet.nodes[0].network_node_id = 1;
        packet.nodes[1].network_node_id = 2;
        packet.nodes[1].username[0] = 'S';
        return citra_control::build_eapol_logoff_frame(packet);
    }();

    const auto citra_wifi = [&](citra_room::FrameType type, const citra_room::Bytes& data) {
        citra_room::WifiPacket wifi;
        wifi.type = type;
        wifi.channel = 11;
        wifi.transmitter = citra_mac;
        wifi.destination = station_mac;
        wifi.data = data;
        return wifi;
    };
    const std::array<std::uint8_t, 4> xx_host{1, 2, 3, 4};
    const room_client::IPv4 session_ip{10, 83, 1, 40};
    const room_client::IPv4 station_ip{10, 83, 1, 41};
    const std::array<std::uint8_t, 4> station_word{station_ip[0], station_ip[1], station_ip[2],
                                                   station_ip[3]};
    const std::array<std::uint8_t, 4> guest_word =
        citra_gateway::mhxx_identity_word_from_seed(citra_gateway::kGuestDeclaredSeed);

    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b18-join-conversion";
    options.ldn_guest_inject = true;
    options.ldn_announce_forward = true;
    options.ldn_game_return = true;
    options.ldn_identity_pairs.push_back({xx_host, session_ip});
    citra_gateway::ControlBridge bridge(options, session_ip, citra_mac);
    bridge.start();
    (void)bridge.on_citra_wifi(beacon(citra_mac), 10);
    (void)admit(bridge, station_mac, station_ip);
    (void)bridge.on_citra_wifi(
        citra_wifi(citra_room::FrameType::AssociationResponse, assoc_ok), 20);
    (void)bridge.on_citra_eapol(logoff.value, 30);
    check(bridge.stations()[0].guest_inject_state ==
                  citra_gateway::GuestInjectionState::Done &&
              bridge.stations()[0].have_guest_identity_word,
          "B18 the fixture completes the injection cycle");

    // The measured MHGU join-request shape (v275 live capture structure, tags
    // replaced with fixture values): host endpoint +4, host short id +10, self
    // endpoints +12/+18, self id +24, self word +30, counter +82.
    citra_room::Bytes request(120, 0x00);
    const std::array<std::uint8_t, 12> request_head = {
        0x32, 0xab, 0x98, 0x64, 0x01, 0x01, 0x00, 0x00, 0x23, 0x46, 0x9f, 0xfe};
    std::copy(request_head.begin(), request_head.end(), request.begin());
    request[12] = 0x00; request[13] = 0xfd;
    request[14] = 0x00; request[15] = 86;
    request[24] = 0x01; request[25] = 0x00; request[26] = 0x00; request[27] = 0x00;
    request[32] = 0x01; request[33] = 0x2f; request[34] = 0x07; request[35] = 0x00;
    for (std::size_t i = 0; i < 4; ++i) {
        request[36 + i] = session_ip[i];    // host endpoint word  (+4)
        request[44 + i] = station_word[i];  // self endpoint word  (+12)
        request[50 + i] = station_word[i];  // self endpoint word  (+18)
        request[62 + i] = station_word[i];  // self word           (+30)
    }
    request[40] = 0x30; request[41] = 0x39;  // host port
    request[42] = 0xff; request[43] = 0xe2;  // host short id
    request[48] = 0x30; request[49] = 0x39;  // self port (+16)
    request[54] = 0x30; request[55] = 0x39;  // self port (+22)
    request[56] = 0x39; request[57] = 0xa9;  // self id u32 (+24)
    request[58] = 0xca; request[59] = 0xa0;
    request[60] = 0x39; request[61] = 0xa9;  // self id u16 (+28)
    request[114] = 0xca; request[115] = 0xa7; request[116] = 0x48; request[117] = 0x84;
    const citra_room::Bytes request_copy = request;

    const auto translated_request = bridge.translate_game_return(request);
    check(translated_request.has_value() && translated_request->size() == 112,
          "B18 the MHGU join request is restructured to the 112-byte MHXX shape");
    check(translated_request->at(14) == 0x00 && translated_request->at(15) == 78,
          "B18 the restructured request carries the 78-byte payload length");
    check(translated_request->at(32) == 0x01 && translated_request->at(33) == 0x2f &&
              translated_request->at(34) == 0x07 && translated_request->at(35) == 0x00,
          "B18 the family bytes and the per-station tag survive the restructure");
    bool self_block_ok = true;
    for (std::size_t i = 0; i < 4; ++i) {
        self_block_ok = self_block_ok && translated_request->at(36 + i) == guest_word[i];
    }
    check(self_block_ok,
          "B18 the requester word opens the descriptor and is mapped to the injected word");
    check(translated_request->at(40) == 0x30 && translated_request->at(41) == 0x39,
          "B18 the kept endpoint carries port 12345");
    bool zeros_ok = true;
    for (std::size_t i = 42; i <= 105; ++i) {
        const bool identity = (i >= 42 && i < 50) || (i >= 77 && i < 85);
        const bool endpoint = (i >= 65 && i < 77) || (i >= 100 && i < 106);
        const bool embedded = (i >= 54 && i < 58) || (i >= 89 && i < 93);
        if (!identity && !endpoint && !embedded) {
            zeros_ok = zeros_ok && translated_request->at(i) == 0x00;
        }
    }
    check(zeros_ok,
          "B18 fields outside canonical identities, endpoints and registry keys remain zero");
    std::array<std::uint8_t, 8> expected_identity{};
    std::copy(guest_word.begin(), guest_word.end(), expected_identity.begin());
    expected_identity[4] = 0x30; expected_identity[5] = 0x39;
    expected_identity[6] = 0x39; expected_identity[7] = 0xa9;
    check(std::equal(expected_identity.begin(), expected_identity.end(), translated_request->begin() + 42) &&
              std::equal(expected_identity.begin(), expected_identity.end(), translated_request->begin() + 77),
          "B18 both descriptor identities carry the mapped endpoint and original GU short id");
    check(std::equal(translated_request->begin() + 36, translated_request->begin() + 42,
                     translated_request->begin() + 65) &&
              std::equal(translated_request->begin() + 36, translated_request->begin() + 42,
                         translated_request->begin() + 71) &&
              std::equal(translated_request->begin() + 36, translated_request->begin() + 42,
                         translated_request->begin() + 100),
          "B18 both descriptors and their secondary endpoints identify the same guest");
    check(translated_request->at(106) == 0xca && translated_request->at(107) == 0xa7 &&
              translated_request->at(108) == 0x48 && translated_request->at(109) == 0x84 &&
              translated_request->at(110) == 0x00 && translated_request->at(111) == 0x00,
          "B18 the counter moves to +74 and the two-byte trailer follows");
    check(bridge.counters().at("join_request_restructured") == 1,
          "B18 the restructure is counted once");
    check(bridge.counters_json().find("\"join_request_restructured\":1") != std::string::npos,
          "B18 the restructure counter appears in the counters JSON schema");
    check(request == request_copy, "B18 the input request is left untouched");
    // Sender field: MHGU join requests carry zeros; nothing may invent a word.
    check(translated_request->at(20) == 0x00 && translated_request->at(21) == 0x00 &&
              translated_request->at(22) == 0x00 && translated_request->at(23) == 0x00,
          "B18 the zero sender field stays zero");

    // A mismatched self block is not the measured join shape and must pass
    // through unrestructured.
    citra_room::Bytes mismatched = request_copy;
    mismatched[50] = 0x7f;
    const auto untranslated = bridge.translate_game_return(mismatched);
    check(untranslated.has_value() && untranslated->size() == 120 &&
              bridge.counters().at("join_request_restructured") == 1,
          "B18 a request without the consistent self block passes through untouched");

    // MHXX's 112-byte accept (host word at the sender field and inside the
    // body) must reach MHGU as its own 120-byte family-01 accept.
    citra_room::Bytes accept(112, 0x00);
    const std::array<std::uint8_t, 12> accept_head = {
        0x32, 0xab, 0x98, 0x64, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x33, 0x23, 0x48};
    std::copy(accept_head.begin(), accept_head.end(), accept.begin());
    accept[14] = 0x00; accept[15] = 78;
    accept[24] = 0x01; accept[25] = 0x00; accept[26] = 0x00; accept[27] = 0x00;
    accept[32] = 0x01; accept[33] = 0x5d; accept[34] = 0x07; accept[35] = 0x01;
    for (std::size_t i = 0; i < 4; ++i) {
        accept[20 + i] = xx_host[i];
        accept[36 + i] = xx_host[i];
        accept[42 + i] = xx_host[i];
        accept[54 + i] = xx_host[i];
    }
    accept[40] = 0x30; accept[41] = 0x39;
    accept[46] = 0x30; accept[47] = 0x39;
    accept[48] = 0x1e; accept[49] = 0xfb; accept[50] = 0x91; accept[51] = 0x89;
    accept[52] = 0x1e; accept[53] = 0xfb;
    accept[106] = 0xca; accept[107] = 0xa7; accept[108] = 0x48; accept[109] = 0x84;
    const auto accept_out = bridge.on_citra_game_payload(accept);
    check(accept_out.size() == 1 && accept_out[0].room_proxy &&
              accept_out[0].proxy_data.size() == 120,
          "B18 the MHXX accept is expanded to the 120-byte MHGU layout");
    if (accept_out.size() == 1 && accept_out[0].proxy_data.size() == 120) {
        const auto& out = accept_out[0].proxy_data;
        check(out[14] == 0x00 && out[15] == 86,
              "B18 the expanded accept carries the 86-byte payload length");
        check(out[32] == 0x01 && out[33] == 0x5d && out[34] == 0x07 && out[35] == 0x01,
              "B18 the accept family bytes survive the expansion");
        bool gu_ep_ok = true;
        for (std::size_t i = 0; i < 4; ++i) {
            gu_ep_ok = gu_ep_ok && out[36 + i] == station_ip[i];
        }
        check(gu_ep_ok && out[40] == 0x30 && out[41] == 0x39,
              "B18 the requester endpoint opens the expanded body");
        check(out[42] == 0x39 && out[43] == 0xa9,
              "B18 the requester short id lands at +10");
        bool host_words_ok = true;
        for (std::size_t i = 0; i < 4; ++i) {
            host_words_ok = host_words_ok && out[44 + i] == session_ip[i] &&
                            out[50 + i] == session_ip[i] && out[62 + i] == session_ip[i];
        }
        check(host_words_ok && out[48] == 0x30 && out[49] == 0x39 &&
                  out[54] == 0x30 && out[55] == 0x39,
              "B18 both host endpoints carry the mapped host word and port 12345");
        check(out[56] == 0x1e && out[57] == 0xfb && out[58] == 0x91 && out[59] == 0x89 &&
                  out[60] == 0x1e && out[61] == 0xfb,
              "B18 the host six-byte id lands at +24");
        check(out[20] == session_ip[0] && out[21] == session_ip[1] &&
                  out[22] == session_ip[2] && out[23] == session_ip[3],
              "B18 the sender field maps the host word for the MHGU side");
        check(out[114] == 0xca && out[115] == 0xa7 && out[116] == 0x48 &&
                  out[117] == 0x84 && out[118] == 0x00 && out[119] == 0x00,
              "B18 the counter echo moves to +82 and the trailer follows");
        bool zeros_ok = true;
        for (std::size_t i = 66; i <= 113; ++i) {
            zeros_ok = zeros_ok && out[i] == 0x00;
        }
        check(zeros_ok, "B18 the expanded padding stays zeroed");
    }
    check(bridge.counters().at("join_accept_expanded") == 1,
          "B18 the accept expansion is counted once");
    check(bridge.counters_json().find("\"join_accept_expanded\":1") != std::string::npos,
          "B18 the expansion counter appears in the counters JSON schema");

    // Without a stashed request the 112-byte accept must pass through
    // unexpanded: inventing requester fields would be guesswork.
    citra_gateway::ControlBridge cold(options, session_ip, citra_mac);
    cold.start();
    (void)cold.on_citra_wifi(beacon(citra_mac), 10);
    (void)admit(cold, station_mac, station_ip);
    (void)cold.on_citra_game_payload(accept);
    check(cold.counters().at("join_accept_expanded") == 0,
          "B18 no accept expansion happens without a restructured request");
}

// V-279: the three XX→GU structure converters under --ldn-game-return —
// member table 176B→140B, session blob 268B→828B, advertise 200B layout shift
// (.verify-r26/g4/v278-member-table §5, v278-advertise-blob §1.3/§2.4).
// Byte-level only; no Citra, no Yuzu and no game participate.
void group_b19_join_structures() {
    const citra_room::MacAddress citra_mac{2, 0, 0, 0, 0, 40};
    const citra_room::MacAddress station_mac{2, 0, 0, 0, 0, 41};
    const citra_room::Bytes assoc_ok = bytes_from_hex("3104000001c000083030303030303030");
    const auto admit = [](citra_gateway::ControlBridge& bridge,
                          const citra_room::MacAddress& mac, const room_client::IPv4& ip) {
        citra_gateway::LdnContext ctx;
        ctx.have_mapped_mac = true;
        ctx.mapped_mac = mac;
        room_client::LdnPacket scan;
        scan.type = room_client::LdnType::Scan;
        scan.local_ip = ip;
        (void)bridge.on_ldn(scan, ctx);
        room_client::LdnPacket connect;
        connect.type = room_client::LdnType::Connect;
        connect.local_ip = ip;
        connect.data.assign(64, 0);
        return bridge.on_ldn(connect, ctx);
    };
    const auto beacon = [&](const citra_room::MacAddress& mac) {
        citra_room::WifiPacket wifi;
        wifi.type = citra_room::FrameType::Beacon;
        wifi.channel = 11;
        wifi.transmitter = mac;
        wifi.destination = citra_room::broadcast_mac;
        wifi.data.assign(64, 0x00);
        return wifi;
    };
    const auto logoff = [&]() {
        citra_control::EapolLogoffPacket packet;
        packet.assigned_node_id = 2;
        packet.client_mac_address = station_mac;
        packet.connected_nodes = 2;
        packet.max_nodes = 4;
        packet.nodes[0].network_node_id = 1;
        packet.nodes[1].network_node_id = 2;
        packet.nodes[1].username[0] = 'S';
        return citra_control::build_eapol_logoff_frame(packet);
    }();

    const std::array<std::uint8_t, 4> xx_host{1, 2, 3, 4};
    const room_client::IPv4 session_ip{10, 83, 1, 40};
    const room_client::IPv4 station_ip{10, 83, 1, 41};
    const std::array<std::uint8_t, 4> guest_word =
        citra_gateway::mhxx_identity_word_from_seed(citra_gateway::kGuestDeclaredSeed);

    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b19-join-structures";
    options.ldn_guest_inject = true;
    options.ldn_announce_forward = true;
    options.ldn_game_return = true;
    options.ldn_identity_pairs.push_back({xx_host, session_ip});
    const std::array<std::uint8_t, 4> xx_second{0xb3, 0x5e, 0xe2, 0x7f};
    const room_client::IPv4 gu_second{10, 83, 1, 42};
    options.ldn_identity_pairs.push_back({xx_second, gu_second});
    citra_gateway::ControlBridge bridge(options, session_ip, citra_mac);
    bridge.start();
    (void)bridge.on_citra_wifi(beacon(citra_mac), 10);
    (void)admit(bridge, station_mac, station_ip);
    (void)bridge.on_citra_wifi(
        [&] {
            citra_room::WifiPacket wifi = beacon(citra_mac);
            wifi.type = citra_room::FrameType::AssociationResponse;
            wifi.transmitter = citra_mac;
            wifi.destination = station_mac;
            wifi.data = assoc_ok;
            return wifi;
        }(),
        20);
    (void)bridge.on_citra_eapol(logoff.value, 30);
    check(bridge.stations()[0].guest_inject_state == citra_gateway::GuestInjectionState::Done,
          "B19 the fixture completes the injection cycle");

    // --- member table 176B -> 140B ------------------------------------------
    citra_room::Bytes table(176, 0x00);
    table[0] = 0x32; table[1] = 0xab; table[2] = 0x98; table[3] = 0x64;
    table[4] = 0x01; table[5] = 0x00;
    table[8] = 0xa0; table[9] = 0x33;                       // time
    table[12] = 0x08; table[13] = 0x00;                     // kind0 flags
    table[14] = 0x00; table[15] = 141;                      // len = 12*9+33
    table[20] = xx_host[0]; table[21] = xx_host[1]; table[22] = xx_host[2]; table[23] = xx_host[3];
    table[24] = 0x03; table[25] = 0x00; table[26] = 0x30; table[27] = 0x39;
    table[32] = 0x01; table[33] = 0x11;                     // body type 0111
    table[34] = 109;                                        // bodylen LE
    table[44] = 2;                                          // count = 2
    table[48] = 0x62; table[49] = 0x51;                     // A/B word pair (passthrough)
    table[50] = 0xcc; table[51] = 0x04; table[52] = 0xff; table[53] = 0x79;
    table[54] = 0xee; table[55] = 0x06;
    table[56] = 1;                                          // body[24] = 1
    // slot 0: host word, port, XX tail 00 01 00
    table[64] = xx_host[0]; table[65] = xx_host[1]; table[66] = xx_host[2]; table[67] = xx_host[3];
    table[68] = 0x30; table[69] = 0x39;
    table[70] = 0x00; table[71] = 0x01; table[72] = 0x00;
    // slot 1: injected guest word, XX tail 00 02 01
    table[73] = guest_word[0]; table[74] = guest_word[1]; table[75] = guest_word[2];
    table[76] = guest_word[3];
    table[77] = 0x30; table[78] = 0x39;
    table[79] = 0x00; table[80] = 0x02; table[81] = 0x01;
    for (std::size_t k = 2; k < 12; ++k) {
        table[64 + 9 * k + 8] = 0xff;  // empty slots: 00*8 + ff
    }
    const auto table_out = bridge.on_citra_game_payload(table);
    check(table_out.size() == 1 && table_out[0].room_proxy &&
              table_out[0].proxy_data.size() == 140,
          "B19 the XX member table is converted to the 140-byte GU shape");
    if (table_out.size() == 1 && table_out[0].proxy_data.size() == 140) {
        const auto& out = table_out[0].proxy_data;
        check(out[14] == 0x00 && out[15] == 105,
              "B19 the converted table carries the GU payload length 105");
        check(out[34] == 73 && out[35] == 0x00,
              "B19 the converted body length is 73");
        check(out[44] == 2, "B19 the member count passes through");
        check(out[20] == session_ip[0] && out[21] == session_ip[1] &&
                  out[22] == session_ip[2] && out[23] == session_ip[3],
              "B19 the sender field maps the host word");
        bool slot0_ok = out[64] == session_ip[0] && out[65] == session_ip[1] &&
                        out[66] == session_ip[2] && out[67] == session_ip[3] &&
                        out[68] == 0x30 && out[69] == 0x39 &&
                        out[70] == 0x00 && out[71] == 0x00 && out[72] == 0x00;
        check(slot0_ok, "B19 slot 0 carries the mapped host word and the GU-native tail 00 00 00");
        bool slot1_ok = out[73] == station_ip[0] && out[74] == station_ip[1] &&
                        out[75] == station_ip[2] && out[76] == station_ip[3] &&
                        out[77] == 0x30 && out[78] == 0x39 &&
                        out[79] == 0x00 && out[80] == 0x00 && out[81] == 0x01;
        check(slot1_ok, "B19 slot 1 carries the station fake IP and the GU slot index");
        bool empties_ok = true;
        for (std::size_t k = 2; k < 8; ++k) {
            for (std::size_t j = 0; j < 8; ++j) {
                empties_ok = empties_ok && out[64 + 9 * k + j] == 0x00;
            }
            empties_ok = empties_ok && out[64 + 9 * k + 8] == 0xff;
        }
        check(empties_ok, "B19 the dropped XX slots 8..11 leave six GU empty slots");
        check(out[48] == 0x62 && out[49] == 0x51 && out[50] == 0xcc && out[51] == 0x04 &&
                  out[52] == 0xff && out[53] == 0x79 && out[54] == 0xee && out[55] == 0x06,
              "B19 the A/B word pair passes through untouched");
        check(out[56] == 1, "B19 the body[24] constant passes through");
        check(out[136] == 0 && out[137] == 0 && out[138] == 0 && out[139] == 0,
              "B19 the count-occupied tail passes through");
    }
    check(bridge.counters().at("member_table_converted") == 1,
          "B19 the member table conversion is counted once");

    // --- session blob 268B -> 828B ------------------------------------------
    citra_room::Bytes blob(268, 0x00);
    blob[0] = 0x32; blob[1] = 0xab; blob[2] = 0x98; blob[3] = 0x64;
    blob[4] = 0x01; blob[5] = 0x00;
    blob[8] = 0xe7; blob[9] = 0xbc;
    blob[14] = 0x00; blob[15] = 235;                       // len = 268-33
    blob[20] = xx_host[0]; blob[21] = xx_host[1]; blob[22] = xx_host[2]; blob[23] = xx_host[3];
    blob[24] = 0x01; blob[25] = 0x00; blob[26] = 0x00; blob[27] = 0x00;
    blob[32] = 0x02; blob[33] = 0x00; blob[34] = 0x07; blob[35] = 0x02;
    blob[0x45] = 0xef; blob[0x46] = 0x2c; blob[0x47] = 0xb2; blob[0x48] = 0x41;  // session id
    blob[0x49] = 0x01; blob[0x4a] = 0x01; blob[0x4b] = 0x01;
    blob[0x4c] = 0x00;                                      // UTF-16 flag byte
    blob[0x4d] = 'C'; blob[0x4e] = 0x00; blob[0x4f] = 'N'; blob[0x50] = 0x00;
    blob[0x51] = 0x00;                                      // name terminator
    blob[0x9c] = 0x02; blob[0x9d] = 0x00;                   // width 2 prefix
    blob[0x107] = 0xac; blob[0x108] = 0x91; blob[0x109] = 0xc6; blob[0x10a] = 0xf0;  // tail counter
    const auto blob_out = bridge.on_citra_game_payload(blob);
    check(blob_out.size() == 1 && blob_out[0].room_proxy &&
              blob_out[0].proxy_data.size() == 828,
          "B19 the XX session blob is expanded to the 828-byte GU shape");
    if (blob_out.size() == 1 && blob_out[0].proxy_data.size() == 828) {
        const auto& out = blob_out[0].proxy_data;
        check(out[14] == 0x03 && out[15] == 0x1c,
              "B19 the expanded blob carries the GU payload length 796");
        check(out[32] == 0x02 && out[33] == 0x00 && out[34] == 0x07 && out[35] == 0x04,
              "B19 the body head switches to the GU dialect subcode 04");
        check(out[0x25] == 0xc6 && out[0x26] == 0x23 && out[0x27] == 0xab && out[0x28] == 0x25 &&
                  out[0x29] == 0x3e && out[0x2a] == 0x0e && out[0x2b] == 0xe0 && out[0x2c] == 0xa6,
              "B19 the GU-only 8-byte host id is written at 0x25");
        check(out[0x45] == 0xef && out[0x46] == 0x2c && out[0x47] == 0xb2 && out[0x48] == 0x41,
              "B19 the session id is copied byte for byte");
        check(out[0x4c] == 'C' && out[0x4d] == 'N' && out[0x4e] == 0x00,
              "B19 the UTF-16 name is re-encoded as UTF-8 in slot 1");
        check(out[0x9c] == 0x01 && out[0x9d] == 'C' && out[0x9e] == 'N' && out[0x9f] == 0x00,
              "B19 slot 2 carries the single-byte width prefix and the name");
        check(out[0xc5] == 0x01 && out[0xc6] == 0x01,
              "B19 the second width flag pair is written");
        check(out[0x338] == 0xac && out[0x339] == 0x91 && out[0x33a] == 0xc6 && out[0x33b] == 0xf0,
              "B19 the tail counter lands at 0x338");
        check(out[20] == session_ip[0] && out[21] == session_ip[1] &&
                  out[22] == session_ip[2] && out[23] == session_ip[3],
              "B19 the sender field maps the host word");
    }
    check(bridge.counters().at("session_blob_expanded") == 1,
          "B19 the blob expansion is counted once");

    // --- advertise 200B layout shift ----------------------------------------
    citra_room::Bytes appdata(200, 0);
    appdata[0] = 0x41; appdata[1] = 0xb2; appdata[2] = 0x2c; appdata[3] = 0xef;  // session id
    appdata[8] = 0x01;                                                                     // u32 = 1
    appdata[0x0c] = 0xea; appdata[0x0d] = 0xb3;  // XX per-beacon churn word (GU drops it)
    appdata[0x1c] = 0x01; appdata[0x20] = 0x01;
    appdata[0x34] = 'V'; appdata[0x35] = 0x00; appdata[0x36] = '2'; appdata[0x37] = 0x00;  // hall name
    appdata[0x50] = 0x01; appdata[0x51] = 0x00; appdata[0x52] = 0xe7; appdata[0x53] = 0x03;  // password
    appdata[0x5c] = 0x01;                                     // per-player u8
    appdata[0x60] = 0xa9; appdata[0x61] = 0x00;               // HR 169
    appdata[0x68] = 0x0f; appdata[0x69] = 0x5c; appdata[0x6a] = 0xc6; appdata[0x6b] = 0x5f;  // 小忆
    appdata[0xb8] = 0xff; appdata[0xb9] = 0xff;
    citra_control::BeaconParams params;
    params.network_info.host_mac_address = citra_mac;
    params.network_info.channel = 11;
    params.network_info.initialized = 1;
    params.network_info.wlan_comm_id = 0x00197110;
    params.network_info.network_id = 1;
    params.network_info.attributes = 0x8000;
    params.network_info.total_nodes = 1;
    params.network_info.max_nodes = 4;
    params.appdata_size = 200;
    std::copy_n(appdata.begin(), 200, params.appdata.begin());
    params.source_mac = citra_mac;
    params.nodes.assign(4, citra_control::BeaconNodeInfo{});
    const auto beacon_frame = citra_control::build_beacon_frame(params);
    check(beacon_frame.ok(), "B19 the fixture builds a Citra Beacon carrying 200 appdata bytes");
    citra_room::WifiPacket beacon_wifi;
    beacon_wifi.type = citra_room::FrameType::Beacon;
    beacon_wifi.channel = 11;
    beacon_wifi.transmitter = citra_mac;
    beacon_wifi.destination = citra_room::broadcast_mac;
    beacon_wifi.data = beacon_frame.value;
    (void)bridge.on_citra_wifi(beacon_wifi, 100);
    citra_gateway::LdnContext scan_ctx;
    scan_ctx.have_mapped_mac = true;
    scan_ctx.mapped_mac = station_mac;
    room_client::LdnPacket scan;
    scan.type = room_client::LdnType::Scan;
    scan.local_ip = station_ip;
    const auto scan_out = bridge.on_ldn(scan, scan_ctx).emissions;
    const citra_gateway::ControlEmission* scan_resp = nullptr;
    for (const auto& emission : scan_out) {
        if (emission.kind == "room.scan_resp") {
            scan_resp = &emission;
        }
    }
    check(scan_resp != nullptr && scan_resp->ldn_body.size() >
                                       citra_control::kLdnAdvertiseDataOffset + 200,
          "B19 the Scan is answered with a ScanResp carrying 200 advertise bytes");
    if (scan_resp != nullptr && scan_resp->ldn_body.size() >
                                     citra_control::kLdnAdvertiseDataOffset + 200) {
        const auto& adv = scan_resp->ldn_body;
        const std::size_t base = citra_control::kLdnAdvertiseDataOffset;
        auto word_at = [&](std::size_t off) {
            return (static_cast<unsigned>(adv[base + off]) << 24) |
                   (static_cast<unsigned>(adv[base + off + 1]) << 16) |
                   (static_cast<unsigned>(adv[base + off + 2]) << 8) |
                   static_cast<unsigned>(adv[base + off + 3]);
        };
        check(adv[base + 0] == 0x41 && adv[base + 1] == 0xb2 && adv[base + 2] == 0x2c &&
                  adv[base + 3] == 0xef,
              "B19 the session id keeps its position");
        check(word_at(0x0c) == 0 && adv[base + 0x14] == 0xc6 && adv[base + 0x15] == 0x23 &&
                  adv[base + 0x16] == 0xab && adv[base + 0x17] == 0x25,
              "B19 the churn word is dropped and the GU host id is written at 0x14");
        check(adv[base + 0x34] == 'V' && adv[base + 0x35] == 0x00 && adv[base + 0x36] == '2',
              "B19 the hall name stays in its slot");
        check(adv[base + 0x50] == 0x00 && adv[base + 0x58] == 0x01 && adv[base + 0x59] == 0x00 &&
                  adv[base + 0x5a] == 0xe7 && adv[base + 0x5b] == 0x03,
              "B19 the password slot moves from 0x50 to 0x58 and GU 0x50 reads zero");
        check(adv[base + 0x64] == 0x01 && adv[base + 0x68] == 0xa9 && adv[base + 0x69] == 0x00,
              "B19 the per-player byte and the HR move to 0x64/0x68");
        check(adv[base + 0x70] == 0x0f && adv[base + 0x71] == 0x5c && adv[base + 0x72] == 0xc6 &&
                  adv[base + 0x73] == 0x5f,
              "B19 the hunter name moves to 0x70");
        check(adv[base + 0xc0] == 0xff && adv[base + 0xc1] == 0xff,
              "B19 the ffff marker moves to 0xc0");
    }
    check(bridge.counters().at("advertise_gu_converted") == 1,
          "B19 the advertise conversion is counted once");
    check(bridge.counters().at("advertise_from_citra") == 1,
          "B19 the live appdata path was taken exactly once");

    // --- GU blob 828B -> XX 268B (V-281: unlocks the XX bulk pump) ----------
    citra_room::Bytes gu_blob(828, 0x00);
    gu_blob[0] = 0x32; gu_blob[1] = 0xab; gu_blob[2] = 0x98; gu_blob[3] = 0x64;
    gu_blob[4] = 0x01; gu_blob[5] = 0x01;
    gu_blob[8] = 0xe7; gu_blob[9] = 0xbc;
    gu_blob[14] = 0x03; gu_blob[15] = 0x1c;                 // len = 828-32
    gu_blob[24] = 0x01; gu_blob[25] = 0x00; gu_blob[26] = 0x00; gu_blob[27] = 0x00;
    gu_blob[32] = 0x02; gu_blob[33] = 0x00; gu_blob[34] = 0x07; gu_blob[35] = 0x04;
    gu_blob[0x45] = 0xef; gu_blob[0x46] = 0x2c; gu_blob[0x47] = 0xb2; gu_blob[0x48] = 0x41;
    gu_blob[0x49] = 0x01; gu_blob[0x4a] = 0x01; gu_blob[0x4b] = 0x01;
    gu_blob[0x4c] = 'X'; gu_blob[0x4d] = 'i'; gu_blob[0x4e] = 0x00;   // UTF-8 name
    gu_blob[0x9c] = 0x01; gu_blob[0x9d] = 'X'; gu_blob[0x9e] = 'i'; gu_blob[0x9f] = 0x00;
    gu_blob[0xc5] = 0x01; gu_blob[0xc6] = 0x01;
    gu_blob[0x338] = 0xac; gu_blob[0x339] = 0x91; gu_blob[0x33a] = 0xc6; gu_blob[0x33b] = 0xf0;
    // MHGU announced its counter first so the XX-dialect tail can be built.
    citra_room::Bytes gu_announce(40, 0x00);
    gu_announce[0] = 0x32; gu_announce[1] = 0xab; gu_announce[2] = 0x98; gu_announce[3] = 0x64;
    gu_announce[4] = 0x01; gu_announce[5] = 0x01;
    gu_announce[24] = 0x01; gu_announce[25] = 0x00; gu_announce[26] = 0x00; gu_announce[27] = 0x00;
    gu_announce[32] = 0x05; gu_announce[36] = 0x1a; gu_announce[37] = 0xfe;
    gu_announce[38] = 0xd8; gu_announce[39] = 0xbe;
    const auto gu_announce_back = bridge.translate_game_return(gu_announce);
    check(gu_announce_back.has_value(), "B19 the MHGU announce passes through the return path");
    const auto xx_blob_out = bridge.translate_game_return(gu_blob);
    check(xx_blob_out.has_value() && xx_blob_out->size() == 268,
          "B19 the GU session blob is converted to the 268-byte XX shape");
    if (xx_blob_out.has_value() && xx_blob_out->size() == 268) {
        const auto& out = *xx_blob_out;
        check(out[5] == 0x01 && out[14] == 0x00 && out[15] == 235 &&
                  out[20] == 0x00 && out[21] == 0x00 && out[22] == 0x00 && out[23] == 0x00,
              "B19 the converted blob keeps the guest form (kind 1, zero sender)");
        check(out[32] == 0x02 && out[33] == 0x00 && out[34] == 0x07 && out[35] == 0x02,
              "B19 the body head switches to the XX dialect subcode 02");
        check(out[0x45] == 0xef && out[0x46] == 0x2c && out[0x47] == 0xb2 && out[0x48] == 0x41,
              "B19 the session id is copied byte for byte");
        check(out[0x49] == 0x01 && out[0x4a] == 0x01 && out[0x4b] == 0x01,
              "B19 the three flags survive");
        check(out[0x4c] == 0x00 && out[0x4d] == 'X' && out[0x4e] == 0x00 && out[0x4f] == 'i' &&
                  out[0x50] == 0x00 && out[0x51] == 0x00,
              "B19 the UTF-8 name is re-encoded as UTF-16LE behind the 00 flag byte");
        check(out[0x9c] == 0x02 && out[0x9d] == 0x00 && out[0x9e] == 'X' && out[0x9f] == 0x00,
              "B19 slot 2 carries the width-2 prefix and the UTF-16 name");
        check(out[0xc5] == 0x02 && out[0xc6] == 0x01,
              "B19 the second width flag pair is 02 01");
        check(std::equal(gu_blob.begin() + 0x338, gu_blob.begin() + 0x33c,
                         out.begin() + 0x107),
              "B19 the GU blob receiver token survives independently of the sender announce counter");
        bool zeros_ok = out[0x25] == 0 && out[0x26] == 0;
        for (std::size_t i = 0x10b; i < 268; ++i) {
            zeros_ok = zeros_ok && out[i] == 0x00;
        }
        check(zeros_ok, "B19 the host-id slot stays zero and the tail region is zeroed");
    }
    check(bridge.counters().at("session_blob_xx_converted") == 1,
          "B19 the GU-to-XX blob conversion is counted once");

    // V-285: the request identity lost during XX restructuring must survive
    // in GU-facing roster entries, without overwriting native descriptors.
    citra_room::Bytes roster = gu_announce;
    roster.resize(196, 0);
    roster[5] = 0; roster[14] = 0; roster[15] = 164;
    std::copy(xx_host.begin(), xx_host.end(), roster.begin() + 20);
    roster[24] = 2; roster[32] = 2; roster[33] = 2;
    std::copy(guest_word.begin(), guest_word.end(), roster.begin() + 120);
    roster[124] = 0x30; roster[125] = 0x39;
    auto before_join = bridge.on_citra_game_payload(roster);
    check(before_join.size() == 1 && before_join[0].proxy_data[126] == 0,
          "B19 roster identity is not invented before a GU request is learned");

    citra_room::Bytes join = gu_announce;
    join.resize(120, 0);
    join[14] = 0; join[15] = 86;
    join[32] = 1; join[33] = 0xfd; join[34] = 7; join[35] = 0;
    std::copy(session_ip.begin(), session_ip.end(), join.begin() + 36);
    for (const auto offset : {44, 50, 62}) {
        std::copy(station_ip.begin(), station_ip.end(), join.begin() + offset);
    }
    join[48] = 0x30; join[49] = 0x39;
    const std::array<std::uint8_t, 6> learned_id{0x31, 0x42, 0x53, 0x64, 0x31, 0x42};
    std::copy(learned_id.begin(), learned_id.end(), join.begin() + 56);
    check(bridge.translate_game_return(join).has_value(), "B19 GU roster identity request is admitted");
    const auto completed = bridge.on_citra_game_payload(roster);
    check(completed.size() == 1, "B19 incomplete roster remains forwardable");
    if (completed.size() == 1) {
        const auto& p = completed[0].proxy_data;
        check(std::equal(station_ip.begin(), station_ip.end(), p.begin() + 126) &&
                  p[130] == 0x30 && p[131] == 0x39 &&
                  std::equal(learned_id.begin(), learned_id.end(), p.begin() + 132) &&
                  std::equal(station_ip.begin(), station_ip.end(), p.begin() + 138),
              "B19 roster restores the exact endpoint and six-byte ID learned from GU");
    }
    // V301: GU compares BOTH 35-byte descriptor subrecords. V300 restored
    // only the first 22 bytes and leaked the canonical secondary identity.
    auto full_canonical = roster;
    const auto write_canonical = [&](citra_room::Bytes& packet, std::size_t entry) {
        std::fill_n(packet.begin() + entry, 70, 0);
        for (const auto sub : {entry, entry + 35}) {
            for (const auto endpoint : {sub, sub + 6, sub + 29}) {
                std::copy(guest_word.begin(), guest_word.end(), packet.begin() + endpoint);
                packet[endpoint + 4] = 0x30; packet[endpoint + 5] = 0x39;
            }
            std::copy_n(learned_id.begin(), 2, packet.begin() + sub + 12);
            std::copy(guest_word.begin(), guest_word.end(), packet.begin() + sub + 18);
        }
    };
    write_canonical(full_canonical, 120);
    const auto full_out = bridge.on_citra_game_payload(full_canonical);
    check(full_out.size() == 1 &&
              std::equal(join.begin() + 44, join.begin() + 114,
                         full_out[0].proxy_data.begin() + 120),
          "B19 full canonical roster restores both original GU descriptor subrecords");
    for (const auto size : {332, 368}) {
        auto full_periodic = full_canonical;
        full_periodic.resize(size, 0);
        full_periodic[14] = static_cast<std::uint8_t>((size - 32) >> 8);
        full_periodic[15] = static_cast<std::uint8_t>(size - 32);
        full_periodic[32] = 0x20;
        write_canonical(full_periodic, 116);
        const auto result = bridge.on_citra_game_payload(full_periodic);
        check(result.size() == 1 &&
                  std::equal(join.begin() + 44, join.begin() + 114,
                             result[0].proxy_data.begin() + 116),
              "B19 periodic full descriptor restores both GU subrecords");
    }
    // V324: a native Citra joins a hall containing an injected GU member.
    // Keep the original GU descriptor in every supported occupied slot.
    for (const std::size_t count : {2u, 3u, 4u}) {
        for (std::size_t gu_slot = 1; gu_slot < count; ++gu_slot) {
            for (const bool periodic : {false, true}) {
                auto mixed = full_canonical;
                mixed.resize(periodic ? 332 : 52 + count * 72, 0);
                mixed[14] = static_cast<std::uint8_t>((mixed.size() - 32) >> 8);
                mixed[15] = static_cast<std::uint8_t>(mixed.size() - 32);
                mixed[32] = periodic ? 0x20 : 0x02;
                mixed[33] = static_cast<std::uint8_t>(count);
                const std::size_t first = periodic ? 44 : 48;
                for (std::size_t slot = 1; slot < count; ++slot) {
                    std::fill_n(mixed.begin() + first + slot * 72, 70,
                                static_cast<std::uint8_t>(0xa0 + slot));
                }
                const auto entry = first + gu_slot * 72;
                write_canonical(mixed, entry);
                const auto expected = mixed;
                const auto converted = bridge.on_citra_game_payload(mixed);
                check(converted.size() == 1 &&
                      std::equal(join.begin() + 44, join.begin() + 114,
                                 converted[0].proxy_data.begin() + entry),
                      "B324 mixed Citra/GU roster retains complete original GU descriptor");
                if (converted.size() == 1) {
                    for (std::size_t slot = 1; slot < count; ++slot) {
                        if (slot == gu_slot) continue;
                        const auto local_entry = first + slot * 72;
                        check(std::equal(expected.begin() + local_entry,
                                         expected.begin() + local_entry + 70,
                                         converted[0].proxy_data.begin() + local_entry),
                              "B324 restoring GU descriptor preserves other Citra records");
                    }
                }
                auto unknown = mixed;
                unknown[entry + 55] = 0x42;
                const auto rejected = bridge.on_citra_game_payload(unknown);
                check(rejected.size() == 1 && rejected[0].proxy_data[entry + 55] == 0x42,
                      "B324 unknown secondary descriptor is not overwritten in larger rosters");
            }
        }
    }
    // V325: a real local XX guest must handshake directly with the injected
    // GU guest, without replacing the existing host/GU codec negotiation.
    citra_gateway::CitraHostPeerIdentity local_peer;
    local_peer.mac = {2, 0, 0, 0, 0, 99};
    local_peer.ip = {10, 83, 1, 99};
    local_peer.node.friend_code_seed = 0xabcdef9876543210ULL;
    local_peer.node.username[0] = 'L';
    local_peer.assigned_node_id = 3;
    local_peer.node.network_node_id = 3;
    const auto member_sync = bridge.register_citra_host_peer(local_peer);
    check(member_sync.size()==1 && member_sync[0].ldn_type==room_client::LdnType::SyncNetwork &&
          member_sync[0].ldn_remote_ip==station_ip,
          "B333 local Citra admission immediately synchronizes existing native guest");
    if(member_sync.size()==1) {
        const auto n=citra_control::parse_ldn_network_info(member_sync[0].ldn_body.data(),member_sync[0].ldn_body.size());
        auto ip=local_peer.ip;std::reverse(ip.begin(),ip.end());
        check(n.ok() && n.value.ldn.node_count==3 && n.value.ldn.nodes[1].mac_address==station_mac &&
              n.value.ldn.nodes[2].mac_address==local_peer.mac && n.value.ldn.nodes[2].is_connected &&
              n.value.ldn.nodes[2].ipv4_address==ip && n.value.ldn.nodes[2].node_id==2,
              "B333 network snapshot contains all three actual endpoints in stable slots");
    }
    check(bridge.register_citra_host_peer(local_peer).empty(),"B333 duplicate host Logoff does not resynchronize or reset peers");
    auto colliding_local=local_peer;colliding_local.mac[5]^=0x40;colliding_local.ip[3]^=0x40;
    check(bridge.register_citra_host_peer(colliding_local).empty(),"B333 local Citra cannot replace another occupied node slot");
    {
        citra_gateway::ControlBridge local_first(options,session_ip,citra_mac);
        local_first.start();local_first.on_citra_wifi(beacon(citra_mac),10);
        auto first_local=local_peer;first_local.assigned_node_id=first_local.node.network_node_id=2;
        local_first.register_citra_host_peer(first_local);
        admit(local_first,station_mac,station_ip);
        check(local_first.station_count()==1 && local_first.stations()[0].node_id==2,
              "B333 native guest skips the slot already assigned to a local Citra");
        auto next_local=local_peer;next_local.mac[5]=101;next_local.ip[3]=101;
        next_local.assigned_node_id=next_local.node.network_node_id=4;
        check(local_first.register_citra_host_peer(next_local).size()==1,
              "B333 one local and one native guest leave exactly one slot");
        auto excess=next_local;excess.mac[5]=102;excess.ip[3]=102;
        check(local_first.register_citra_host_peer(excess).empty(),"B333 full mixed hall rejects a conflicting local member");
        admit(local_first,{2,0,0,0,0,103},{10,83,1,103});
        check(local_first.station_count()==1,"B333 native admission includes local members in hall capacity");
    }
    const auto local_word = citra_gateway::mhxx_identity_word_from_seed(local_peer.node.friend_code_seed);
    citra_room::Bytes peer_request(join.begin(), join.begin() + 36);
    peer_request.insert(peer_request.end(), join.begin() + 44, join.end());
    peer_request[5] = peer_request[33];peer_request[15] = 78;
    std::copy(local_word.begin(), local_word.end(), peer_request.begin() + 20);
    for (const auto offset : {36, 42, 54})
        std::copy(local_word.begin(), local_word.end(), peer_request.begin() + offset);
    peer_request[46] = 0x30;peer_request[47] = 0x39;
    peer_request[48] = 0x12;peer_request[49] = 0x34;
    citra_control::SecureDataFrame peer_secure;
    peer_secure.header.src_node_id = 3;peer_secure.header.dest_node_id = 2;
    peer_secure.header.data_channel = 243;peer_secure.payload = peer_request;
    citra_room::WifiPacket peer_wifi;peer_wifi.type = citra_room::FrameType::Data;
    peer_wifi.transmitter = local_peer.mac;peer_wifi.destination = station_mac;
    peer_wifi.data = citra_control::build_secure_data_frame(peer_secure).value;
    const auto peer_out = bridge.on_citra_host_peer_game(peer_wifi, local_peer, 110);
    check(peer_out.size() == 1 && !peer_out[0].proxy_broadcast &&
          peer_out[0].proxy_remote_ip == station_ip && peer_out[0].proxy_data.size() == 120 &&
          peer_out[0].proxy_data[5] == peer_request[33] &&
          std::equal(station_ip.begin(), station_ip.end(), peer_out[0].proxy_data.begin() + 36) &&
          std::equal(local_peer.ip.begin(), local_peer.ip.end(), peer_out[0].proxy_data.begin() + 44),
          "B325 local XX guest request reaches the authenticated GU member as native request120");
    auto native_peer_ack = join;
    native_peer_ack.resize(40);native_peer_ack[5]=0;native_peer_ack[14]=0;native_peer_ack[15]=8;
    native_peer_ack[32]=5;native_peer_ack[33]=native_peer_ack[34]=native_peer_ack[35]=0;
    std::copy(station_ip.begin(),station_ip.end(),native_peer_ack.begin()+20);
    check(bridge.on_citra_host_peer_proxy(station_ip,native_peer_ack,local_peer,110).size()==1,
          "B326 native peer ACK is delivered before negotiated-kind accept");
    auto peer_accept = join;
    peer_accept[5] = peer_accept[33] = 0x95;
    peer_accept[35] = 1;
    std::copy(station_ip.begin(), station_ip.end(), peer_accept.begin() + 20);
    std::copy(local_peer.ip.begin(), local_peer.ip.end(), peer_accept.begin() + 36);
    peer_accept[40] = 0x30;peer_accept[41] = 0x39;peer_accept[42] = 0x12;peer_accept[43] = 0x34;
    const auto peer_reply = bridge.on_citra_host_peer_proxy(station_ip, peer_accept, local_peer, 111);
    check(peer_reply.size() == 1 && peer_reply[0].citra_destination == local_peer.mac &&
          peer_reply[0].citra_transmitter == station_mac,
          "B325 GU response reaches only the local Citra guest using real peer MACs");
    if (peer_reply.size() == 1) {
        const auto decoded = citra_control::parse_secure_data_frame(
            peer_reply[0].citra_data.data(), peer_reply[0].citra_data.size());
        check(decoded.ok() && decoded.value.header.src_node_id == 2 &&
              decoded.value.header.dest_node_id == 3 && decoded.value.payload.size() == 112 &&
              decoded.value.payload[5] == 0x95 && decoded.value.payload[33] == 0x95 &&
              std::equal(guest_word.begin(), guest_word.end(), decoded.value.payload.begin() + 36),
              "B325 peer accept restores GU's actual UDS node2 and local guest node3");
    }
    if (peer_reply.size() == 1) {
        const auto decoded = citra_control::parse_secure_data_frame(
            peer_reply[0].citra_data.data(), peer_reply[0].citra_data.size());
        check(decoded.ok() && decoded.value.payload.size() == 112 &&
              std::equal(full_canonical.begin() + 120, full_canonical.begin() + 190,
                         decoded.value.payload.begin() + 36),
              "B327 direct peer reply matches all 70 bytes installed in the host roster");
    }
    // Actual V329 local Citra peer traffic switches to role0 after accept.
    // Its repeated family02 blob must advance the pair beyond the handshake.
    auto peer_blob = blob;
    std::copy(local_word.begin(), local_word.end(), peer_blob.begin() + 20);
    peer_secure.payload = peer_blob;
    auto blob_wifi = peer_wifi;
    blob_wifi.data = citra_control::build_secure_data_frame(peer_secure).value;
    const auto peer_blob_out = bridge.on_citra_host_peer_game(blob_wifi, local_peer, 111);
    check(peer_blob_out.size() == 1 && peer_blob_out[0].proxy_data.size() == 828 &&
          peer_blob_out[0].proxy_data[5] == 0 &&
          !peer_blob_out[0].proxy_broadcast && peer_blob_out[0].proxy_remote_ip == station_ip &&
          std::equal(local_peer.ip.begin(), local_peer.ip.end(), peer_blob_out[0].proxy_data.begin() + 20),
          "B330 post-accept role0 peer blob expands and reaches its authenticated GU peer");
    auto unrelated_blob = peer_blob;
    unrelated_blob[5] = static_cast<std::uint8_t>(peer_request[33] ^ 0x80);
    if (unrelated_blob[5] == 1) unrelated_blob[5] = 2;
    peer_secure.payload = unrelated_blob;
    blob_wifi.data = citra_control::build_secure_data_frame(peer_secure).value;
    check(bridge.on_citra_host_peer_game(blob_wifi, local_peer, 111).empty(),
          "B330 post-accept blob rejects unrelated stream kind");
    peer_secure.payload = peer_request;
    auto peer_keepalive = peer_accept;
    peer_keepalive.resize(48);peer_keepalive[14]=0;peer_keepalive[15]=16;
    peer_keepalive[24]=6;peer_keepalive[25]=peer_keepalive[26]=peer_keepalive[27]=0;
    std::fill(peer_keepalive.begin()+32,peer_keepalive.end(),0);peer_keepalive[35]=1;
    const auto keepalive_out=bridge.on_citra_host_peer_proxy(station_ip,peer_keepalive,local_peer,111);
    check(keepalive_out.size()==1,
          "B331 negotiated-kind GU peer keepalive reaches local Citra after accept");
    if(keepalive_out.size()==1) {
        const auto f=citra_control::parse_secure_data_frame(keepalive_out[0].citra_data.data(),keepalive_out[0].citra_data.size());
        check(f.ok() && f.value.header.src_node_id==2 && f.value.header.dest_node_id==3 &&
              f.value.payload[5]==0x95 &&
              std::equal(guest_word.begin(),guest_word.end(),f.value.payload.begin()+20),
              "B331 peer keepalive preserves negotiated kind and maps only sender identity");
    }
    peer_keepalive[5]=0x96;
    check(bridge.on_citra_host_peer_proxy(station_ip,peer_keepalive,local_peer,111).empty(),
          "B331 unrelated GU peer keepalive kind remains rejected");
    auto foreign_descriptor=peer_accept;foreign_descriptor[100]^=1;
    check(bridge.on_citra_host_peer_proxy(station_ip,foreign_descriptor,local_peer,111).empty(),
          "B327 different native GU secondary descriptor cannot borrow the admitted identity");
    auto wrong_kind_accept=peer_accept;wrong_kind_accept[5]=0x96;
    check(bridge.on_citra_host_peer_proxy(station_ip,wrong_kind_accept,local_peer,111).empty(),
          "B326 unrelated outer peer kind is rejected rather than normalized");
    auto wrong_short_accept=peer_accept;wrong_short_accept[42]^=1;
    check(bridge.on_citra_host_peer_proxy(station_ip,wrong_short_accept,local_peer,111).empty(),
          "B326 negotiated-kind reply must match the requesting local Citra short identity");
    auto peer_ack = peer_request;
    peer_ack.resize(40);peer_ack[14]=0;peer_ack[15]=8;
    peer_ack[32]=5;peer_ack[33]=peer_ack[34]=peer_ack[35]=0;
    auto broadcast_peer=peer_wifi;
    broadcast_peer.destination=citra_room::broadcast_mac;
    peer_secure.payload=peer_ack;peer_secure.header.dest_node_id=0xffff;
    broadcast_peer.data=citra_control::build_secure_data_frame(peer_secure).value;
    const auto broadcast_out=bridge.on_citra_host_peer_game(broadcast_peer,local_peer,112);
    check(broadcast_out.size()==1 && !broadcast_out[0].proxy_broadcast &&
          broadcast_out[0].proxy_remote_ip==station_ip && broadcast_out[0].proxy_data.size()==40,
          "B325 mixed guest broadcast ACK reaches only authenticated same-hall GU peer");
    peer_secure.payload=peer_request;
    auto spoof_peer = peer_wifi;
    spoof_peer.transmitter = citra_mac;
    check(bridge.on_citra_host_peer_game(spoof_peer, local_peer, 112).empty(),
          "B325 mixed peer rejects spoofed source MAC");
    peer_secure.header.src_node_id = 4;
    spoof_peer = peer_wifi;spoof_peer.data = citra_control::build_secure_data_frame(peer_secure).value;
    check(bridge.on_citra_host_peer_game(spoof_peer, local_peer, 112).empty(),
          "B325 mixed peer rejects wrong source node");
    peer_secure.header.src_node_id = 3;peer_secure.header.dest_node_id = 4;
    spoof_peer.data = citra_control::build_secure_data_frame(peer_secure).value;
    check(bridge.on_citra_host_peer_game(spoof_peer, local_peer, 112).empty(),
          "B325 mixed peer rejects wrong authenticated target node");
    check(bridge.on_citra_host_peer_proxy({10, 83, 9, 9}, peer_accept, local_peer, 112).empty(),
          "B325 mixed peer rejects a foreign native room member");
    const auto host_still_admitted = bridge.on_citra_game_payload(full_canonical);
    check(host_still_admitted.size() == 1 &&
          std::equal(join.begin() + 44, join.begin() + 114,
                     host_still_admitted[0].proxy_data.begin() + 120),
          "B325 mixed peer handshake preserves the existing host/GU full descriptor");
    auto mixed_table=table;mixed_table[44]=3;
    std::copy(local_word.begin(),local_word.end(),mixed_table.begin()+82);
    mixed_table[86]=0x30;mixed_table[87]=0x39;mixed_table[88]=0;mixed_table[89]=3;mixed_table[90]=2;
    const auto mixed_advert=bridge.on_citra_game_payload(mixed_table);
    check(mixed_advert.size()==1 && mixed_advert[0].proxy_data.size()==140 &&
          std::equal(local_peer.ip.begin(),local_peer.ip.end(),mixed_advert[0].proxy_data.begin()+82),
          "B325 host advertisement maps its authenticated local Citra peer to the same native room IP");
    auto local_four=local_peer;local_four.mac[5]=100;local_four.ip[3]=100;
    local_four.assigned_node_id=4;local_four.node.friend_code_seed=0xabcdef9876543211ULL;
    const auto fourth_word=citra_gateway::mhxx_identity_word_from_seed(local_four.node.friend_code_seed);
    auto fourth_request=peer_request;
    for(const auto offset:{20,36,42,54})std::copy(fourth_word.begin(),fourth_word.end(),fourth_request.begin()+offset);
    fourth_request[48]=0x56;fourth_request[49]=0x78;
    peer_secure.header.src_node_id=4;peer_secure.header.dest_node_id=2;peer_secure.payload=fourth_request;
    auto fourth_wifi=peer_wifi;fourth_wifi.transmitter=local_four.mac;
    fourth_wifi.data=citra_control::build_secure_data_frame(peer_secure).value;
    check(bridge.on_citra_host_peer_game(fourth_wifi,local_four,113).size()==1,
          "B325 fourth node independently opens its own GU peer codec");
    auto fourth_accept=peer_accept;
    std::copy(local_four.ip.begin(),local_four.ip.end(),fourth_accept.begin()+36);
    fourth_accept[42]=0x56;fourth_accept[43]=0x78;
    const auto fourth_reply=bridge.on_citra_host_peer_proxy(station_ip,fourth_accept,local_four,114);
    check(fourth_reply.size()==1 && bridge.on_citra_host_peer_proxy(station_ip,peer_accept,local_peer,114).size()==1,
          "B325 both local Citra/GU peer negotiations remain active independently");
    if(fourth_reply.size()==1) {
        const auto d=citra_control::parse_secure_data_frame(fourth_reply[0].citra_data.data(),fourth_reply[0].citra_data.size());
        check(d.ok() && d.value.header.src_node_id==2 && d.value.header.dest_node_id==4,
              "B325 fourth-node response retains its actual UDS destination");
    }
    check(bridge.on_citra_host_peer_proxy(station_ip,fourth_accept,local_peer,114).empty(),
          "B325 one local Citra cannot consume another local Citra's GU reply");
    const auto removal_sync=bridge.forget_citra_host_peer(local_peer.mac);
    check(removal_sync.size()==1,"B333 local departure synchronizes existing native guest");
    if(removal_sync.size()==1) {
        const auto n=citra_control::parse_ldn_network_info(removal_sync[0].ldn_body.data(),removal_sync[0].ldn_body.size());
        check(n.ok() && n.value.ldn.node_count==3 && !n.value.ldn.nodes[2].is_connected &&
              n.value.ldn.nodes[3].mac_address==local_four.mac && n.value.ldn.nodes[3].is_connected,
              "B333 local departure preserves remaining node4 without compacting slots");
    }
    check(bridge.on_citra_host_peer_proxy(station_ip,peer_accept,local_peer,115).empty() &&
          bridge.on_citra_host_peer_proxy(station_ip,fourth_accept,local_four,115).size()==1,
          "B325 departing local Citra clears only its own mixed peer codecs");
    auto unknown_secondary = full_canonical;
    unknown_secondary[120 + 35 + 20] = 0x42;
    const auto secondary_out = bridge.on_citra_game_payload(unknown_secondary);
    check(secondary_out.size() == 1 && secondary_out[0].proxy_data[175] == 0x42 &&
              secondary_out[0].proxy_data[132] == learned_id[0] &&
              secondary_out[0].proxy_data[134] == 0,
          "B19 noncanonical secondary descriptor is preserved without partial restoration");
    auto native_roster = roster;
    auto canonical_roster = roster;
    std::copy(guest_word.begin(), guest_word.end(), canonical_roster.begin() + 126);
    canonical_roster[130] = 0x30; canonical_roster[131] = 0x39;
    std::copy_n(learned_id.begin(), 2, canonical_roster.begin() + 132);
    const auto canonical_out = bridge.on_citra_game_payload(canonical_roster);
    check(canonical_out.size() == 1 && completed.size() == 1 &&
              canonical_out[0].proxy_data == completed[0].proxy_data,
          "B19 our canonical nonzero XX roster identity restores the exact original GU layout");
    canonical_roster[134] = 1;
    const auto unknown_out = bridge.on_citra_game_payload(canonical_roster);
    check(unknown_out.size() == 1 && unknown_out[0].proxy_data[134] == 1,
          "B19 canonical-looking native roster with extra fields is preserved");
    native_roster[126] = 0x7b;
    const auto native_out = bridge.on_citra_game_payload(native_roster);
    check(native_out.size() == 1 && native_out[0].proxy_data[126] == 0x7b &&
              native_out[0].proxy_data[132] == 0,
          "B19 nonempty native roster identity is preserved");
    auto periodic = roster;
    periodic.resize(332, 0);
    periodic[14] = 1; periodic[15] = 44; periodic[32] = 0x20;
    std::fill(periodic.begin() + 116, periodic.begin() + 142, 0);
    std::copy(guest_word.begin(), guest_word.end(), periodic.begin() + 116);
    periodic[120] = 0x30; periodic[121] = 0x39;
    const auto periodic_out = bridge.on_citra_game_payload(periodic);
    check(periodic_out.size() == 1 &&
              std::equal(learned_id.begin(), learned_id.end(), periodic_out[0].proxy_data.begin() + 128),
          "B19 periodic roster uses its four-byte-earlier entry offset");

    // V-286: admit only the negotiated opaque stream routes after the game
    // dialects have supplied their body tag.  Endpoint-looking bytes inside
    // these bodies are payload and must not be identity-scanned or rewritten.
    const auto make_stream_packet = [](std::uint32_t route, std::uint8_t header_kind,
                                       std::uint8_t body_tag,
                                       const std::array<std::uint8_t, 4>& sender) {
        citra_room::Bytes packet(64, 0);
        const std::array<std::uint8_t, 5> magic{0x32, 0xab, 0x98, 0x64, 0x01};
        std::copy(magic.begin(), magic.end(), packet.begin());
        packet[5] = header_kind;
        packet[14] = 0;
        packet[15] = static_cast<std::uint8_t>(packet.size() - 32);
        std::copy(sender.begin(), sender.end(), packet.begin() + 20);
        packet[24] = static_cast<std::uint8_t>(route >> 24);
        packet[25] = static_cast<std::uint8_t>(route >> 16);
        packet[26] = static_cast<std::uint8_t>(route >> 8);
        packet[27] = static_cast<std::uint8_t>(route);
        packet[32] = 0x02;
        packet[33] = body_tag;
        packet[34] = 0x07;
        packet[35] = 0x01;
        return packet;
    };
    auto gu_bulk = make_stream_packet(0x20000000u, 0xfd, 0x98, station_ip);
    std::copy(session_ip.begin(), session_ip.end(), gu_bulk.begin() + 40);
    std::copy(guest_word.begin(), guest_word.end(), gu_bulk.begin() + 48);
    const auto gu_bulk_out = bridge.translate_game_return(gu_bulk);
    check(gu_bulk_out.has_value() &&
              std::equal(guest_word.begin(), guest_word.end(), gu_bulk_out->begin() + 20) &&
              std::equal(gu_bulk.begin() + 32, gu_bulk.end(), gu_bulk_out->begin() + 32),
          "B19 negotiated GU bulk maps only the sender and preserves opaque endpoint-like body bytes");
    auto wrong_tag_bulk = gu_bulk;
    wrong_tag_bulk[5] = 0xfc;
    check(!bridge.translate_game_return(wrong_tag_bulk).has_value(),
          "B19 GU stream with a nonnegotiated header kind is rejected");
    auto wrong_sender_bulk = gu_bulk;
    wrong_sender_bulk[23] = 0x63;
    check(!bridge.translate_game_return(wrong_sender_bulk).has_value(),
          "B19 GU stream from a sender other than the admitted station is rejected");
    auto unknown_route_bulk = gu_bulk;
    unknown_route_bulk[27] = 0x02;
    check(!bridge.translate_game_return(unknown_route_bulk).has_value(),
          "B19 unknown GU stream route is rejected");

    citra_room::Bytes xx_accept(112, 0);
    const std::array<std::uint8_t, 12> xx_accept_head = {
        0x32, 0xab, 0x98, 0x64, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x33, 0x23, 0x48};
    std::copy(xx_accept_head.begin(), xx_accept_head.end(), xx_accept.begin());
    xx_accept[15] = 78;
    xx_accept[24] = 0x01;
    xx_accept[32] = 0x01; xx_accept[33] = 0xa9; xx_accept[34] = 0x07; xx_accept[35] = 0x01;
    for (std::size_t i = 0; i < 4; ++i) {
        xx_accept[20 + i] = xx_host[i];
        xx_accept[36 + i] = xx_host[i];
        xx_accept[42 + i] = xx_host[i];
        xx_accept[54 + i] = xx_host[i];
    }
    xx_accept[40] = 0x30; xx_accept[41] = 0x39;
    xx_accept[46] = 0x30; xx_accept[47] = 0x39;
    xx_accept[48] = 0x1e; xx_accept[49] = 0xfb; xx_accept[50] = 0x91; xx_accept[51] = 0x89;
    xx_accept[52] = 0x1e; xx_accept[53] = 0xfb;
    xx_accept[106] = 0xca; xx_accept[107] = 0xa7;
    xx_accept[108] = 0x48; xx_accept[109] = 0x84;
    const auto xx_accept_out = bridge.on_citra_game_payload(xx_accept);
    check(xx_accept_out.size() == 1 && xx_accept_out[0].proxy_data.size() == 120,
          "B19 XX accept with negotiated body tag is expanded before stream admission");

    auto xx_bulk = make_stream_packet(0x20000000u, 0xa9, 0x98, xx_host);
    std::copy(station_ip.begin(), station_ip.end(), xx_bulk.begin() + 40);
    std::copy(guest_word.begin(), guest_word.end(), xx_bulk.begin() + 48);
    std::copy(xx_second.begin(), xx_second.end(), xx_bulk.begin() + 52);
    const auto xx_bulk_out = bridge.on_citra_game_payload(xx_bulk);
    check(xx_bulk_out.size() == 1 && xx_bulk_out[0].room_proxy &&
              std::equal(session_ip.begin(), session_ip.end(), xx_bulk_out[0].proxy_data.begin() + 20) &&
              std::equal(xx_bulk.begin() + 32, xx_bulk.end(), xx_bulk_out[0].proxy_data.begin() + 32),
          "B19 negotiated XX stream maps only the sender and preserves opaque body bytes");

    auto xx_bulk_second = make_stream_packet(0x02100000u, 0xa9, 0x98, xx_second);
    std::copy(xx_host.begin(), xx_host.end(), xx_bulk_second.begin() + 40);
    std::copy(guest_word.begin(), guest_word.end(), xx_bulk_second.begin() + 48);
    citra_room::Bytes compound(xx_bulk.begin(), xx_bulk.begin() + 12);
    compound.insert(compound.end(), xx_bulk.begin() + 12, xx_bulk.end());
    compound.insert(compound.end(), xx_bulk_second.begin() + 12, xx_bulk_second.end());
    const auto compound_out = bridge.on_citra_game_payload(compound);
    check(compound_out.size() == 1 && compound_out[0].room_proxy &&
              compound_out[0].proxy_data.size() == compound.size() &&
              std::equal(session_ip.begin(), session_ip.end(), compound_out[0].proxy_data.begin() + 20) &&
              std::equal(gu_second.begin(), gu_second.end(), compound_out[0].proxy_data.begin() + xx_bulk.size() - 12 + 20) &&
              std::equal(xx_bulk.begin() + 32, xx_bulk.end(), compound_out[0].proxy_data.begin() + 32) &&
              std::equal(xx_bulk_second.begin() + 32, xx_bulk_second.end(),
                         compound_out[0].proxy_data.begin() + xx_bulk.size() - 12 + 32),
          "B19 compound XX messages map each sender and preserve opaque bulk bytes in one datagram");

    citra_room::Bytes malformed_compound(xx_bulk.begin(), xx_bulk.begin() + 12);
    malformed_compound.insert(malformed_compound.end(), xx_bulk.begin() + 12, xx_bulk.end());
    auto truncated_inner = xx_bulk_second;
    truncated_inner[14] = 0x01;
    truncated_inner[15] = 0x00;
    malformed_compound.insert(malformed_compound.end(), truncated_inner.begin() + 12,
                              truncated_inner.begin() + 32);
    const auto malformed_out = bridge.on_citra_game_payload(malformed_compound);
    check(malformed_out.empty(), "B19 malformed second inner header rejects the whole compound datagram");

    auto unsupported_inner = xx_bulk_second;
    unsupported_inner[24] = 0xde;
    unsupported_inner[25] = 0xad;
    unsupported_inner[26] = 0xbe;
    unsupported_inner[27] = 0xef;
    citra_room::Bytes mixed_compound(xx_bulk.begin(), xx_bulk.begin() + 12);
    mixed_compound.insert(mixed_compound.end(), xx_bulk.begin() + 12, xx_bulk.end());
    mixed_compound.insert(mixed_compound.end(), unsupported_inner.begin() + 12,
                          unsupported_inner.end());
    const auto mixed_out = bridge.on_citra_game_payload(mixed_compound);
    check(mixed_out.size() == 1 && mixed_out[0].room_proxy &&
              mixed_out[0].proxy_data.size() == xx_bulk.size() &&
              std::equal(session_ip.begin(), session_ip.end(), mixed_out[0].proxy_data.begin() + 20),
          "B19 unsupported compound route is skipped while supported inner messages stay in one datagram");

    auto gu_first = make_stream_packet(0x06000000u, 0x01, 0, session_ip);
    auto gu_second_packet = make_stream_packet(0x06000000u, 0x01, 0, gu_second);
    citra_room::Bytes return_compound(gu_first.begin(), gu_first.begin() + 12);
    return_compound.insert(return_compound.end(), gu_first.begin() + 12, gu_first.end());
    return_compound.insert(return_compound.end(), gu_second_packet.begin() + 12,
                           gu_second_packet.end());
    const auto return_compound_out = bridge.translate_game_return(return_compound);
    check(return_compound_out.has_value() && return_compound_out->size() == return_compound.size() &&
              std::equal(xx_host.begin(), xx_host.end(), return_compound_out->begin() + 20) &&
              std::equal(xx_second.begin(), xx_second.end(),
                         return_compound_out->begin() + gu_first.size() - 12 + 20),
          "B19 compound GU return maps both identities and preserves one physical datagram");
    citra_room::Bytes resized_compound = gu_blob;
    resized_compound.insert(resized_compound.end(), gu_first.begin() + 12, gu_first.end());
    const auto resized_out = bridge.translate_game_return(resized_compound);
    check(resized_out.has_value() && resized_out->size() == 268 + gu_first.size() - 12 &&
              (*resized_out)[14] == 0 && (*resized_out)[15] == 235 &&
              std::equal(xx_host.begin(), xx_host.end(), resized_out->begin() + 268 + 8),
          "B19 shrinking a compound blob repositions and translates the following inner header");
    auto xx_heartbeat = make_stream_packet(0x02100000u, 0xa9, 0x98, xx_host);
    xx_heartbeat[32] = 0x03;
    const auto xx_heartbeat_out = bridge.on_citra_game_payload(xx_heartbeat);
    check(xx_heartbeat_out.size() == 1 && xx_heartbeat_out[0].room_proxy,
          "B19 negotiated XX heartbeat route remains forwardable");
    bridge.invalidate_game_return_admission();
    const auto invalidated_out = bridge.on_citra_game_payload(roster);
    check(invalidated_out.empty() || invalidated_out[0].proxy_data[126] == 0,
          "B19 departed admission cannot reuse cached roster identity");
    check(!bridge.translate_game_return(gu_bulk).has_value() &&
              bridge.on_citra_game_payload(xx_bulk).empty(),
          "B19 stream directions stop forwarding after admission invalidation");
}

// V-267: the LDN advertise_data of ScanResp/SyncNetwork follows the Citra
// peer's *live* Beacon application data -- the 200 byte MHXX structure whose
// hall name sits at offset 52 as 24 UTF-16LE code units -- instead of the
// static --ldn-advertise-hex template, so the Yuzu scan list shows the hall the
// Citra side really advertises.  Structural only: the Beacon is built by the
// same citra-control encoder a real host uses and handed to ControlBridge in
// process; no Citra, no Yuzu, no game and no wire participate.
void group_b15_live_advertise() {
    const citra_room::MacAddress citra_mac{2, 0, 0, 0, 0, 50};
    const citra_room::MacAddress station_mac{2, 0, 0, 0, 0, 51};
    const room_client::IPv4 guest_ip{10, 84, 0, 51};
    const citra_room::Bytes cli_template{0x43, 0x7f, 0xe9, 0x4d, 0x00, 0x11};
    const std::string hall_name = "MHXX-HALL-77";

    // 200 bytes of MHXX application data: a deterministic pattern everywhere,
    // with the hall name written as UTF-16LE at offset 52 (the layout a real
    // MHXX host advertises).
    citra_room::Bytes appdata(200, 0);
    for (std::size_t i = 0; i < appdata.size(); ++i) {
        appdata[i] = static_cast<std::uint8_t>((i * 7u + 3u) % 251u);
    }
    for (std::size_t i = 0; i < hall_name.size() && i < 24; ++i) {
        appdata[52 + i * 2] = static_cast<std::uint8_t>(hall_name[i]);
        appdata[53 + i * 2] = 0;
    }
    // The 24 code unit name field is NUL terminated, unused units stay zero --
    // exactly how a real MHXX host lays the hall name out.
    for (std::size_t i = hall_name.size(); i < 24; ++i) {
        appdata[52 + i * 2] = 0;
        appdata[53 + i * 2] = 0;
    }

    const auto build_citra_beacon = [&](const citra_room::Bytes& data) {
        citra_control::BeaconParams params;
        params.network_info.host_mac_address = citra_mac;
        params.network_info.channel = 11;
        params.network_info.initialized = 1;
        params.network_info.wlan_comm_id = 0x00197110u;
        params.network_info.attributes = 0x8000;
        params.network_info.total_nodes = 1;
        params.network_info.max_nodes = 4;
        params.appdata_size =
            static_cast<std::uint8_t>(std::min<std::size_t>(data.size(), params.appdata.size()));
        std::copy_n(data.begin(), params.appdata_size, params.appdata.begin());
        params.source_mac = citra_mac;
        params.nodes.assign(4, citra_control::BeaconNodeInfo{});
        return citra_control::build_beacon_frame(params);
    };
    const auto beacon_wifi = [&](const citra_room::Bytes& frame) {
        citra_room::WifiPacket wifi;
        wifi.type = citra_room::FrameType::Beacon;
        wifi.channel = 11;
        wifi.transmitter = citra_mac;
        wifi.destination = citra_room::broadcast_mac;
        wifi.data = frame;
        return wifi;
    };
    // The advertised structure of one LDN emission: size at
    // kLdnAdvertiseDataSizeOffset (u16le), bytes at kLdnAdvertiseDataOffset.
    const auto advertise_of = [](const citra_gateway::ControlEmission& emission) {
        citra_room::Bytes out;
        if (emission.ldn_body.size() < citra_control::kLdnAdvertiseDataOffset + 1) {
            return out;
        }
        const std::size_t size =
            static_cast<std::size_t>(
                emission.ldn_body[citra_control::kLdnAdvertiseDataSizeOffset]) |
            (static_cast<std::size_t>(
                 emission.ldn_body[citra_control::kLdnAdvertiseDataSizeOffset + 1])
             << 8);
        for (std::size_t i = 0; i < size && citra_control::kLdnAdvertiseDataOffset + i <
                                                     emission.ldn_body.size();
             ++i) {
            out.push_back(emission.ldn_body[citra_control::kLdnAdvertiseDataOffset + i]);
        }
        return out;
    };
    struct SeenBody {
        bool found = false;
        citra_room::Bytes advertise;
        std::string body_hex;
    };
    const auto emission_of_kind = [&](const std::vector<citra_gateway::ControlEmission>& emissions,
                                      const std::string& kind) {
        SeenBody seen;
        for (const auto& emission : emissions) {
            if (emission.kind != kind) {
                continue;
            }
            seen.found = true;
            seen.advertise = advertise_of(emission);
            seen.body_hex = hex_of(emission.ldn_body);
            break;
        }
        return seen;
    };
    const auto scan_emissions = [&](citra_gateway::ControlBridge& bridge) {
        citra_gateway::LdnContext ctx;
        ctx.have_mapped_mac = true;
        ctx.mapped_mac = station_mac;
        room_client::LdnPacket scan;
        scan.type = room_client::LdnType::Scan;
        scan.local_ip = guest_ip;
        return bridge.on_ldn(scan, ctx).emissions;
    };
    const auto connect_emissions = [&](citra_gateway::ControlBridge& bridge) {
        citra_gateway::LdnContext ctx;
        ctx.have_mapped_mac = true;
        ctx.mapped_mac = station_mac;
        room_client::LdnPacket connect;
        connect.type = room_client::LdnType::Connect;
        connect.local_ip = guest_ip;
        connect.data.assign(64, 0);
        return bridge.on_ldn(connect, ctx).emissions;
    };

    // --- live appdata wins over the CLI template (the gate defaults to on) ---
    {
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b15-live";
        options.ldn_advertise_data = cli_template;
        citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 84, 0, 50}, citra_mac);
        bridge.start();
        const auto frame = build_citra_beacon(appdata);
        check(frame.ok(), "B15 the fixture builds a Citra Beacon carrying 200 appdata bytes");
        (void)bridge.on_citra_wifi(beacon_wifi(frame.value), 100);
        check(bridge.counters().at("citra_beacon_seen") == 1 &&
                  bridge.counters().at("advertise_citra_received") == 1 &&
                  bridge.counters().at("advertise_citra_rejected") == 0,
              "B15 one valid Beacon stores its appdata and is counted");
        const auto scan_seen = emission_of_kind(scan_emissions(bridge), "room.scan_resp");
        check(scan_seen.found, "B15 the Scan is answered with a room.scan_resp");
        check(scan_seen.advertise == appdata,
              "B15 the ScanResp advertise_data equals the Citra appdata, byte for byte");
        check(bridge.citra_advertise_appdata() == appdata &&
                  bridge.citra_advertise_source_mac() == citra_mac,
              "B15 the stored appdata keeps its size and the Beacon's source MAC");
        check(scan_seen.advertise.size() == 200,
              "B15 the ScanResp carries all 200 advertised bytes");
        std::string seen_name;
        for (std::size_t i = 0; i < 24 && 52 + i * 2 + 1 < scan_seen.advertise.size(); ++i) {
            const std::uint8_t low = scan_seen.advertise[52 + i * 2];
            const std::uint8_t high = scan_seen.advertise[53 + i * 2];
            if (low == 0 && high == 0) {
                break;
            }
            seen_name.push_back(static_cast<char>(low));
        }
        check(seen_name == hall_name,
              "B15 the hall name at offset 52 is advertised as UTF-16LE");
        check(bridge.counters().at("advertise_from_citra") == 1 &&
                  bridge.counters().at("advertise_from_cli") == 0 &&
                  bridge.counters().at("advertise_empty") == 0,
              "B15 the first LDN body is counted as advertise_from_citra");
        const auto sync_seen = emission_of_kind(connect_emissions(bridge), "room.sync_network");
        check(sync_seen.found && sync_seen.advertise == appdata,
              "B15 the SyncNetwork advertise_data carries the same live appdata");
        check(bridge.counters().at("advertise_from_citra") == 2,
              "B15 the SyncNetwork counts a second advertise_from_citra");
    }

    // V300 live-hall policy: no template hall before hosting, after an empty
    // beacon, or after expiry; a fresh beacon makes discovery work again.
    {
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b15-live-only";
        options.ldn_advertise_data = cli_template;
        options.ldn_require_live_hall = true;
        citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 84, 0, 50}, citra_mac);
        bridge.start();
        check(scan_emissions(bridge).empty() && connect_emissions(bridge).empty() &&
                  bridge.stations().empty(),
              "B15 live-only mode neither advertises a template nor admits a cached hall before hosting");
        (void)bridge.on_citra_wifi(beacon_wifi(citra_room::Bytes(64, 0)), 10);
        check(scan_emissions(bridge).empty(), "B15 malformed beacon cannot expose a template hall");
        bridge.on_citra_beacon_appdata(appdata, citra_mac, 100);
        check(emission_of_kind(scan_emissions(bridge), "room.scan_resp").advertise == appdata,
              "B15 creating a real Citra hall enables discovery");
        check(emission_of_kind(connect_emissions(bridge), "room.sync_network").advertise == appdata,
              "B15 a fresh real Citra hall admits the guest with live data");
        bridge.on_citra_beacon_appdata({}, citra_mac, 101);
        check(scan_emissions(bridge).empty() && connect_emissions(bridge).empty(),
              "B15 explicit empty beacon withdraws a previously visible live hall");
        bridge.on_citra_beacon_appdata(appdata, citra_mac, 200);
        (void)bridge.tick(200 + citra_gateway::kCitraAppdataMaxAgeMs);
        check(emission_of_kind(scan_emissions(bridge), "room.scan_resp").found,
              "B15 live-only hall remains visible at the exact freshness boundary");
        (void)bridge.tick(201 + citra_gateway::kCitraAppdataMaxAgeMs);
        check(scan_emissions(bridge).empty() && connect_emissions(bridge).empty() &&
                  bridge.counters().at("advertise_citra_expired") == 1 &&
                  bridge.counters().at("advertise_from_cli") == 0,
              "B15 stale Citra hall stops discovery and admission without template fallback");
        bridge.on_citra_beacon_appdata(appdata, citra_mac, 1800);
        check(emission_of_kind(scan_emissions(bridge), "room.scan_resp").found,
              "B15 reopening the Citra hall restores live discovery");
    }

    // --- no usable Beacon: the CLI template, unchanged ----------------------
    {
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b15-cli";
        options.ldn_advertise_data = cli_template;
        citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 84, 0, 50}, citra_mac);
        bridge.start();
        // A Beacon that does not decode: the gateway must not adopt garbage, and
        // the frame keeps its historical wrong-direction drop.
        (void)bridge.on_citra_wifi(beacon_wifi(citra_room::Bytes(64, 0x00)), 10);
        check(bridge.counters().at("advertise_beacon_unparsed") == 1 &&
                  bridge.counters().at("advertise_citra_received") == 0,
              "B15 an undecodable Beacon is counted and stores nothing");
        const auto seen = emission_of_kind(scan_emissions(bridge), "room.scan_resp");
        check(seen.found && seen.advertise == cli_template,
              "B15 without a usable Beacon the ScanResp falls back to the CLI template");
        check(bridge.counters().at("advertise_from_cli") == 1 &&
                  bridge.counters().at("advertise_from_citra") == 0 &&
                  bridge.counters().at("advertise_empty") == 0,
              "B15 the fallback body is counted as advertise_from_cli");
    }

    // --- gate off: the pre-V-267 behaviour, byte for byte -------------------
    {
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b15-off";
        options.ldn_advertise_data = cli_template;
        options.ldn_live_advertise = false;
        citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 84, 0, 50}, citra_mac);
        bridge.start();
        const auto frame = build_citra_beacon(appdata);
        check(frame.ok(), "B15 the gate-off fixture builds a Beacon with appdata");
        (void)bridge.on_citra_wifi(beacon_wifi(frame.value), 100);
        check(bridge.counters().at("advertise_live_disabled") == 1 &&
                  bridge.counters().at("advertise_citra_received") == 0,
              "B15 with --no-ldn-live-advertise a Beacon appdata is recorded, never adopted");
        const auto off_seen = emission_of_kind(scan_emissions(bridge), "room.scan_resp");
        check(off_seen.found && off_seen.advertise == cli_template &&
                  bridge.counters().at("advertise_from_citra") == 0,
              "B15 with the gate off the ScanResp carries the CLI template again");
        citra_gateway::ControlOptions reference_options;
        reference_options.room_name = "synthetic-b15-off";
        reference_options.ldn_advertise_data = cli_template;
        citra_gateway::ControlBridge reference(reference_options,
                                               room_client::IPv4{10, 84, 0, 50}, citra_mac);
        reference.start();
        const auto reference_seen =
            emission_of_kind(scan_emissions(reference), "room.scan_resp");
        check(off_seen.found && reference_seen.found &&
                  off_seen.body_hex == reference_seen.body_hex,
              "B15 with the gate off the whole ScanResp body is the pre-V-267 body");
    }

    // --- length gate: 0 and > 0x180 are never adopted -----------------------
    {
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b15-length";
        options.ldn_advertise_data = cli_template;
        citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 84, 0, 50}, citra_mac);
        bridge.start();
        bridge.on_citra_beacon_appdata({}, citra_mac, 10);
        check(bridge.counters().at("advertise_citra_rejected") == 1,
              "B15 an empty appdata is refused and counted (it names no hall)");
        const citra_room::Bytes oversize(citra_control::kLdnAdvertiseDataSizeMax + 1, 0x5a);
        bridge.on_citra_beacon_appdata(oversize, citra_mac, 11);
        check(bridge.counters().at("advertise_citra_rejected") == 2 &&
                  bridge.counters().at("advertise_citra_received") == 0,
              "B15 an appdata above 0x180 bytes is refused and counted");
        const auto empty_frame = build_citra_beacon({});
        check(empty_frame.ok(), "B15 the fixture builds a Beacon with appdata_size 0");
        (void)bridge.on_citra_wifi(beacon_wifi(empty_frame.value), 12);
        check(bridge.counters().at("advertise_citra_rejected") == 3 &&
                  bridge.counters().at("advertise_citra_received") == 0,
              "B15 a real Beacon whose appdata_size is 0 goes through the same length gate");
        const auto seen = emission_of_kind(scan_emissions(bridge), "room.scan_resp");
        check(seen.found && seen.advertise == cli_template,
              "B15 after a rejected appdata the CLI template is still advertised");
    }

    // --- staleness: a hall description no Beacon repeats is retired ---------
    {
        citra_gateway::ControlOptions options;
        options.room_name = "synthetic-b15-stale";
        options.ldn_advertise_data = cli_template;
        citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 84, 0, 50}, citra_mac);
        bridge.start();
        const auto frame = build_citra_beacon(appdata);
        check(frame.ok(), "B15 the staleness fixture builds a Beacon with appdata");
        (void)bridge.on_citra_wifi(beacon_wifi(frame.value), 1000);
        (void)bridge.tick(1000);
        check(emission_of_kind(scan_emissions(bridge), "room.scan_resp").advertise == appdata,
              "B15 the freshly stored appdata is advertised right away");
        (void)bridge.tick(1000 + citra_gateway::kCitraAppdataMaxAgeMs);
        check(emission_of_kind(scan_emissions(bridge), "room.scan_resp").advertise == appdata &&
                  bridge.counters().at("advertise_citra_expired") == 0,
              "B15 the appdata is still live exactly one window after it arrived");
        (void)bridge.tick(1001 + citra_gateway::kCitraAppdataMaxAgeMs);
        const auto stale_seen = emission_of_kind(scan_emissions(bridge), "room.scan_resp");
        check(stale_seen.found && stale_seen.advertise == cli_template &&
                  bridge.counters().at("advertise_citra_expired") == 1,
              "B15 a hall description no Beacon repeats is retired after the window");
    }
}

// V-268: the member table the Citra side broadcasts carries one 4-byte identity
// endpoint per member.  V-267 proved the first (host) slot is already translated
// by --ldn-identity-pair, and that the second slot carried 6522df69 -- the word
// MHXX derives for the guest this gateway injects -- which no Yuzu peer
// recognised as itself.  This group covers the two rules that replace it: the
// derived word (a) and the member slot position (b), plus the paths that must
// not change: the host slot, a non-member-table body, an unclaimable slot, and
// a count byte that promises more slots than the frame holds.  Everything is
// synthetic: the frames are built by the same encoders and byte layouts the
// bridge already uses, in this process.  No Citra, no Yuzu, no game, no wire.
void group_b16_member_endpoints() {
    const std::array<std::uint8_t, 4> xx_host{0xb3, 0x5e, 0xe2, 0x7f};   // measured XX host
    const std::array<std::uint8_t, 4> gu_host{0xc0, 0xa8, 0x02, 0x2f};   // measured GU host
    // V-267 measured: the word in the member table slot Citra filled with the
    // guest this gateway injected through --ldn-guest-inject.
    const std::array<std::uint8_t, 4> injected_word{0x65, 0x22, 0xdf, 0x69};
    const citra_room::MacAddress citra_mac{2, 0, 0, 0, 0, 60};
    // Successful AssociationResponse, exactly the bytes B14 uses.
    const citra_room::Bytes assoc_ok = bytes_from_hex("3104000001c000083030303030303030");

    // --- the derivation, checked against the offline model ------------------
    // MHXX turns the eight NodeInfo seed bytes into its endpoint word with
    // CRC-32/ISO-HDLC (tools/mhxx-endpoint.mjs, whose goldens were computed
    // independently with zlib).  The seed this bridge declares for an injected
    // guest is zero, which is exactly the V-267 measured word.
    check(citra_gateway::mhxx_identity_word_from_seed(0) == injected_word,
          "B16 a zero seed derives the 6522df69 word V-267 measured");
    check(citra_gateway::mhxx_identity_word_from_seed(0x0807060504030201ull) ==
              std::array<std::uint8_t, 4>({0x3f, 0xca, 0x88, 0xc5}) &&
              citra_gateway::mhxx_identity_word_from_seed(0x3837363534333231ull) ==
                  std::array<std::uint8_t, 4>({0x9a, 0xe0, 0xda, 0xaf}) &&
              citra_gateway::mhxx_identity_word_from_seed(0xFFFFFFFFFFFFFFFFull) ==
                  std::array<std::uint8_t, 4>({0x21, 0x44, 0xdf, 0x1c}),
          "B16 the derivation reproduces all four offline seed goldens");

    // --- the frame ----------------------------------------------------------
    // The 198 byte V-267 member table, cut down to two members and two empty
    // slots; the field offsets are the measured ones (count at body + 12, the
    // nine byte slots from body + 32).
    const citra_room::Bytes two_member_body = bytes_from_hex(
        "01116d000000000000000000"
        "02"
        "000000"
        "887c9714fb1e8991"
        "01"
        "00000000000000"
        "b35ee27f3039000100"
        "6522df693039000201"
        "ff0000000000000000"
        "ff0000000000000000");
    check(two_member_body.size() == 68 && two_member_body[12] == 2 &&
              two_member_body[0] == 0x01 && two_member_body[1] == 0x11,
          "B16 the fixture is a 68 byte two member 0x0111 table");
    const auto host_payload = [&](std::uint32_t route, const citra_room::Bytes& body) {
        citra_room::Bytes packet{0x32, 0xab, 0x98, 0x64, 0x01, 0x01, 0x00, 0x00,
                                 0x11, 0x2e, 0x00, 0x00,
                                 0x08, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x00, 0x00};
        packet.insert(packet.end(), xx_host.begin(), xx_host.end());
        packet.push_back(static_cast<std::uint8_t>((route >> 24) & 0xff));
        packet.push_back(static_cast<std::uint8_t>((route >> 16) & 0xff));
        packet.push_back(static_cast<std::uint8_t>((route >> 8) & 0xff));
        packet.push_back(static_cast<std::uint8_t>(route & 0xff));
        packet.insert(packet.end(), 4, 0x00);
        packet.insert(packet.end(), body.begin(), body.end());
        citra_room::Bytes frame(22, 0x00);
        frame[0] = 0xaa; frame[1] = 0xaa; frame[2] = 0x03; frame[6] = 0x87; frame[7] = 0x6d;
        frame.insert(frame.end(), packet.begin(), packet.end());
        return frame;
    };

    // --- a bridge with N admitted Yuzu stations, optionally injected --------
    const auto make_bridge = [&](const std::string& name, bool inject, std::size_t guests) {
        citra_gateway::ControlOptions options;
        options.room_name = name;
        options.ldn_announce_forward = true;
        options.ldn_identity_pairs.push_back({xx_host, gu_host});
        options.ldn_guest_inject = inject;
        auto bridge = std::make_unique<citra_gateway::ControlBridge>(
            options, room_client::IPv4{10, 85, 0, 60}, citra_mac);
        bridge->start();
        // A Citra Beacon is the only evidence that Citra hosts the UDS network.
        citra_room::WifiPacket beacon;
        beacon.type = citra_room::FrameType::Beacon;
        beacon.channel = 11;
        beacon.transmitter = citra_mac;
        beacon.destination = citra_room::broadcast_mac;
        beacon.data.assign(64, 0x00);
        (void)bridge->on_citra_wifi(beacon, 10);
        for (std::size_t i = 0; i < guests; ++i) {
            const citra_room::MacAddress station_mac{2, 0, 0, 0, 0,
                                                     static_cast<std::uint8_t>(61 + i)};
            // The GU identity word of a station is its fake IP in octet order
            // (measured: host c0a8022f = 192.168.2.47), so 10.85.0.62 is 0a 55 00 3e.
            const room_client::IPv4 station_ip{10, 85, 0, static_cast<std::uint8_t>(61 + i)};
            citra_gateway::LdnContext ctx;
            ctx.have_mapped_mac = true;
            ctx.mapped_mac = station_mac;
            room_client::LdnPacket scan;
            scan.type = room_client::LdnType::Scan;
            scan.local_ip = station_ip;
            (void)bridge->on_ldn(scan, ctx);
            room_client::LdnPacket connect;
            connect.type = room_client::LdnType::Connect;
            connect.local_ip = station_ip;
            connect.data.assign(64, 0);
            (void)bridge->on_ldn(connect, ctx);
            if (!inject) {
                continue;
            }
            // Citra answers the injected SEQ1 with a successful association,
            // then its own EAPoL-Logoff hands out the node id it assigned.
            citra_room::WifiPacket assoc;
            assoc.type = citra_room::FrameType::AssociationResponse;
            assoc.channel = 11;
            assoc.transmitter = citra_mac;
            assoc.destination = station_mac;
            assoc.data = assoc_ok;
            (void)bridge->on_citra_wifi(assoc, 20);
            citra_control::EapolLogoffPacket logoff;
            logoff.assigned_node_id = static_cast<std::uint16_t>(2 + i);
            logoff.client_mac_address = station_mac;
            logoff.connected_nodes = static_cast<std::uint8_t>(2 + guests);
            logoff.max_nodes = 4;
            logoff.nodes[0].network_node_id = 1;
            const auto built = citra_control::build_eapol_logoff_frame(logoff);
            if (built.ok()) {
                (void)bridge->on_citra_eapol(built.value, 30);
            }
        }
        return bridge;
    };
    const auto forwarded_hex = [](const std::vector<citra_gateway::ControlEmission>& out) {
        return out.empty() ? std::string() : hex_of(out[0].proxy_data);
    };

    // --- (a) the derived word, one guest ------------------------------------
    {
        auto bridge = make_bridge("synthetic-b16-word", true, 1);
        check(bridge->station_count() == 1 && bridge->stations()[0].have_uds_node_id &&
                  bridge->stations()[0].uds_node_id == 2 &&
                  bridge->stations()[0].have_guest_identity_word &&
                  bridge->stations()[0].guest_identity_word == injected_word,
              "B16 the injected station knows its node id and its derived word");
        const auto payload = host_payload(0x03003039u, two_member_body);
        const auto out = bridge->on_citra_game_payload(payload);
        const std::string forwarded = forwarded_hex(out);
        check(out.size() == 1 && !out[0].to_citra && out[0].room_proxy && out[0].proxy_broadcast,
              "B16 a member table still leaves as one broadcast room Proxy emission");
        check(forwarded.size() == hex_of(payload).size() - 44,
              "B16 the substitution is in place: the forwarded frame keeps its length");
        check(hex_slice(forwarded, 64, 4) == "c0a8022f",
              "B16 the host slot is still translated by --ldn-identity-pair");
        check(hex_slice(forwarded, 73, 4) == "0a55003d",
              "B16 the injected guest word becomes the station own fake IP word");
        check(hex_slice(forwarded, 77, 5) == "3039000201",
              "B16 the port and the slot flags next to the rewritten word survive");
        check(forwarded.substr(86).find("6522df69") == std::string::npos,
              "B16 the injected word does not survive anywhere behind the host slot");
        check(hex_slice(forwarded, 82, 9) == "ff0000000000000000",
              "B16 an unused 0xff slot is never touched");
        check(bridge->counters().at("announce_guest_word_replaced") == 1 &&
                  bridge->counters().at("announce_guest_slot_replaced") == 0 &&
                  bridge->counters().at("announce_guest_word_unmatched") == 0 &&
                  bridge->counters().at("announce_forwarded") == 1 &&
                  bridge->counters().at("announce_word_replacements_total") == 1,
              "B16 the derived-word substitution is counted exactly once");
    }

    // --- (b) the slot position, when the word is not what we derived --------
    // This is the rule that must not fail: it never looks at the word, only at
    // the member order and the node id Citra assigned.
    {
        auto bridge = make_bridge("synthetic-b16-slot", true, 1);
        citra_room::Bytes body = two_member_body;
        // Slot 1 carries a word no station derives (a different seed, a
        // different game build, or a derivation nobody has proven).
        const citra_room::Bytes mystery = bytes_from_hex("abcd1234");
        std::copy(mystery.begin(), mystery.end(), body.begin() + 32 + 9);
        const auto payload = host_payload(0x03003039u, body);
        const std::string forwarded = forwarded_hex(bridge->on_citra_game_payload(payload));
        check(hex_slice(forwarded, 73, 4) == "0a55003d",
              "B16 an unproven guest word is still replaced by its member slot position");
        check(hex_slice(forwarded, 77, 2) == "3039" && forwarded.size() == hex_of(payload).size() - 44,
              "B16 the slot rewrite keeps the port and the frame length");
        check(bridge->counters().at("announce_guest_slot_replaced") == 1 &&
                  bridge->counters().at("announce_guest_word_replaced") == 0 &&
                  bridge->counters().at("announce_guest_word_unmatched") == 0,
              "B16 the slot-position substitution is counted under its own key");
    }

    // --- an unclaimable slot: counted, and not rewritten --------------------
    // Without the reverse injection the bridge has no node id for the station,
    // so the position rule cannot fire either; the slot must survive byte for
    // byte rather than be guessed at.
    {
        auto bridge = make_bridge("synthetic-b16-unmatched", false, 1);
        check(bridge->station_count() == 1 && !bridge->stations()[0].have_uds_node_id &&
                  !bridge->stations()[0].have_guest_identity_word,
              "B16 without the injection a station has no node id and no derived word");
        citra_room::Bytes body = two_member_body;
        const citra_room::Bytes mystery = bytes_from_hex("abcd1234");
        std::copy(mystery.begin(), mystery.end(), body.begin() + 32 + 9);
        const auto payload = host_payload(0x03003039u, body);
        const std::string forwarded = forwarded_hex(bridge->on_citra_game_payload(payload));
        check(hex_slice(forwarded, 73, 4) == "abcd1234",
              "B16 an unclaimable member slot is left byte for byte");
        check(bridge->counters().at("announce_guest_word_unmatched") == 1 &&
                  bridge->counters().at("announce_guest_word_replaced") == 0 &&
                  bridge->counters().at("announce_guest_slot_replaced") == 0 &&
                  bridge->counters().at("announce_forwarded") == 1,
              "B16 the unclaimed slot is counted as unmatched, not silently skipped");
    }

    // --- two guests: the identical derived word cannot disambiguate ---------
    // Every injected station declares the same seed, so both slots carry
    // 6522df69; only the slot position names the right station.
    {
        auto bridge = make_bridge("synthetic-b16-two", true, 2);
        check(bridge->station_count() == 2 && bridge->stations()[0].uds_node_id == 2 &&
                  bridge->stations()[1].uds_node_id == 3 &&
                  bridge->stations()[0].guest_identity_word !=
                      bridge->stations()[1].guest_identity_word,
              "B328 injected stations have distinct declared identities and node IDs");
        const citra_room::Bytes three_body = bytes_from_hex(
            "01116d000000000000000000"
            "03"
            "000000"
            "887c9714fb1e8991"
            "01"
            "00000000000000"
            "b35ee27f3039000100"
            "6522df693039000201"
            "6522df693039000301");
        auto payload = host_payload(0x03003039u, three_body);
        std::copy(bridge->stations()[1].guest_identity_word.begin(),
                  bridge->stations()[1].guest_identity_word.end(), payload.begin()+22+82);
        const std::string forwarded = forwarded_hex(bridge->on_citra_game_payload(payload));
        check(hex_slice(forwarded, 73, 4) == "0a55003d" &&
                  hex_slice(forwarded, 82, 4) == "0a55003e",
              "B328 each unique guest word resolves to its own native endpoint");
        check(bridge->counters().at("announce_guest_slot_replaced") == 0 &&
                  bridge->counters().at("announce_guest_word_replaced") == 2 &&
                  bridge->counters().at("announce_guest_word_unmatched") == 0,
              "B328 distinct guest identities map without positional ambiguity");
    }

    // --- a body that is not a member table stays alone ----------------------
    // Requirement: only 0x0111 endpoint tables are touched.  A 0x01000000 body
    // (counter + word) keeps the plain V-249 substitution and gains no guest
    // rewrite -- even when a station slot would match its bytes.
    {
        auto bridge = make_bridge("synthetic-b16-other", true, 1);
        // 32 bytes of a non-member body, then the same two nine byte entries at
        // the same offsets as the member table above.
        const citra_room::Bytes other = bytes_from_hex(
            std::string(64, '0') + "b35ee27f3039000000" + "6522df693039000000");
        const auto payload = host_payload(0x01000000u, other);
        const auto out = bridge->on_citra_game_payload(payload);
        const std::string forwarded = forwarded_hex(out);
        // V-281: outside member tables the scan also maps the injected guest
        // word (the V-280 live defect: rosters reached MHGU with the raw
        // 6522df69), so both words now carry their GU-side values.
        check(out.size() == 1 && hex_slice(forwarded, 64, 4) == "c0a8022f" &&
                  hex_slice(forwarded, 73, 4) == "0a55003d",
              "B16 a non member-table body maps the pair word and the injected word");
        check(bridge->counters().at("announce_guest_word_replaced") == 0 &&
                  bridge->counters().at("announce_guest_slot_replaced") == 0 &&
                  bridge->counters().at("announce_guest_word_unmatched") == 0,
              "B16 a non member-table body touches no guest counter");
    }

    // --- a count byte that promises more slots than the frame holds ---------
    // The translator must decline instead of reading past the frame, and the
    // host slot must still be translated.
    {
        auto bridge = make_bridge("synthetic-b16-bounds", true, 1);
        citra_room::Bytes body = two_member_body;
        body[12] = 0xff;
        const auto payload = host_payload(0x03003039u, body);
        const auto out = bridge->on_citra_game_payload(payload);
        const std::string forwarded = forwarded_hex(out);
        check(out.size() == 1 && forwarded.size() == hex_of(payload).size() - 44 &&
                  hex_slice(forwarded, 64, 4) == "c0a8022f" &&
                  hex_slice(forwarded, 73, 4) == "6522df69",
              "B16 an impossible count declines the table instead of reading past it");
        check(bridge->counters().at("announce_guest_word_unmatched") == 0,
              "B16 a declined table counts nothing as unmatched");
        // A count that fits the header but not the frame is declined the same way.
        citra_room::Bytes short_body = bytes_from_hex(
            "01116d000000000000000000"
            "02"
            "000000"
            "887c9714fb1e8991"
            "01"
            "00000000000000"
            "b35ee27f3039000100");
        const auto short_payload = host_payload(0x03003039u, short_body);
        const auto short_out = bridge->on_citra_game_payload(short_payload);
        check(short_out.size() == 1 &&
                  forwarded_hex(short_out).size() == hex_of(short_payload).size() - 44 &&
                  bridge->station_count() == 1,
              "B16 a truncated slot table is declined without touching the frame");
    }
}
// V-263: the Citra side is the UDS host when it creates the hall (measured:
// MHXX hall, SecureData src_node_id 1, kind 1, bare MH packet behind a 22 byte
// UDS prefix).  Such a payload is translated and forwarded to the admitted Yuzu
// members without the guest-side association gate.
void group_b12_host_payload_forward() {
    const std::array<std::uint8_t, 4> xx_host{0xb3, 0x5e, 0xe2, 0x7f};
    const std::array<std::uint8_t, 4> gu_host{0xc0, 0xa8, 0x02, 0x2f};
    const citra_room::MacAddress mac{2, 0, 0, 0, 0, 32};
    const citra_room::Bytes body = bytes_from_hex(
        "01114900000000000000000002000000"
        "e6147194d33f87880100000000000000"
        "b35ee27f3039000000"
        "deadbeef30390001");
    const auto make_packet = [&](std::uint32_t route, std::uint8_t kind,
                                 const citra_room::Bytes& payload) {
        citra_room::Bytes packet{0x32, 0xab, 0x98, 0x64, 0x01, kind, 0x00, 0x00,
                                 0x11, 0x2e, 0x00, 0x00,
                                 0x08, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x00, 0x00};
        packet.insert(packet.end(), xx_host.begin(), xx_host.end());
        packet.push_back(static_cast<std::uint8_t>((route >> 24) & 0xff));
        packet.push_back(static_cast<std::uint8_t>((route >> 16) & 0xff));
        packet.push_back(static_cast<std::uint8_t>((route >> 8) & 0xff));
        packet.push_back(static_cast<std::uint8_t>(route & 0xff));
        packet.insert(packet.end(), 4, 0x00);
        packet.insert(packet.end(), payload.begin(), payload.end());
        return packet;
    };
    // Measured secure-data prefix: LLC 8 bytes (EtherType 0x876D) plus the 14
    // byte SecureDataHeader.  Only the length is contractual on this path.
    citra_room::Bytes secure_head(22, 0x00);
    secure_head[0] = 0xaa;
    secure_head[1] = 0xaa;
    secure_head[2] = 0x03;
    secure_head[3] = 0x00;
    secure_head[6] = 0x87;
    secure_head[7] = 0x6d;
    const auto host_payload = [&](const citra_room::Bytes& packet) {
        citra_room::Bytes payload = secure_head;
        payload.insert(payload.end(), packet.begin(), packet.end());
        return payload;
    };
    // Admit one Yuzu member: Scan plus Connect is all the host path needs.
    const auto admit_station = [&](citra_gateway::ControlBridge& bridge) {
        citra_gateway::LdnContext ctx;
        ctx.have_mapped_mac = true;
        ctx.mapped_mac = citra_room::MacAddress{2, 0, 0, 0, 0, 33};
        room_client::LdnPacket scan;
        scan.type = room_client::LdnType::Scan;
        scan.local_ip = room_client::IPv4{10, 83, 0, 33};
        (void)bridge.on_ldn(scan, ctx);
        room_client::LdnPacket connect;
        connect.type = room_client::LdnType::Connect;
        connect.local_ip = room_client::IPv4{10, 83, 0, 33};
        connect.data.assign(64, 0);
        (void)bridge.on_ldn(connect, ctx);
    };
    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b12";
    options.ldn_announce_forward = true;
    options.ldn_identity_pairs.push_back({xx_host, gu_host});
    citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 83, 0, 32}, mac);
    bridge.start();
    admit_station(bridge);
    check(bridge.station_count() == 1, "B12 the fixture admits one Yuzu station");

    // Kind 1 is the measured host shape (the guest path only ever saw kind 0).
    const auto emissions = bridge.on_citra_game_payload(host_payload(make_packet(0x03003039u, 1, body)));
    check(emissions.size() == 1 && !emissions[0].to_citra && emissions[0].room_proxy,
          "B12 a kind-1 host payload leaves as one room proxy emission");
    check(emissions.size() == 1 && emissions[0].kind == "room.proxy.announce.host",
          "B12 the host emission carries its own kind");
    check(emissions.size() == 1 && emissions[0].proxy_broadcast,
          "B12 the host emission is broadcast to the room members");
    const std::string forwarded =
        emissions.empty() ? std::string() : hex_of(emissions[0].proxy_data);
    // V-272: the room proxy channel carries the bare MH packet.  Measured on the
    // proven relay path (two Yuzu MHGU clients): every ProxyPacket plain payload
    // starts at 32ab9864 and the 22 byte LLC + SecureData prefix never appears
    // there, so the translator strips the prefix instead of forwarding it.
    check(hex_slice(forwarded, 0, 4) == "32ab9864",
          "B12 the bare MH packet is what the room proxy carries");
    check(hex_slice(forwarded, 20, 4) == "b35ee27f",
          "B12 the message header sender word is left byte for byte");
    check(hex_slice(forwarded, 64, 4) == "c0a8022f",
          "B12 the body identity word is substituted to the GU host word");
    check(forwarded.substr(86).find("b35ee27f") == std::string::npos,
          "B12 no XX identity word survives behind the message header");
    check(hex_slice(forwarded, 73, 4) == "deadbeef" && hex_slice(forwarded, 77, 2) == "3039",
          "B12 unmatched member entries and their port survive unchanged");
    check(bridge.counters().at("announce_host_payloads") == 1 &&
              bridge.counters().at("announce_forwarded") == 1 &&
              bridge.counters().at("announce_host_rejected") == 0,
          "B12 the host payload and the forward are counted");

    // An unknown route is not a session packet.
    const auto bad_route =
        bridge.on_citra_game_payload(host_payload(make_packet(0xdeadbeefu, 1, body)));
    check(bad_route.empty() && bridge.counters().at("announce_route_rejected") == 1 &&
              bridge.counters().at("announce_host_rejected") == 1,
          "B12 an unknown route is rejected and counted");
    // No identity word anywhere in the body.
    const citra_room::Bytes no_word_body = bytes_from_hex("00000000");
    const auto no_word =
        bridge.on_citra_game_payload(host_payload(make_packet(0x03003039u, 1, no_word_body)));
    check(no_word.empty() && bridge.counters().at("announce_no_identity_word") == 1,
          "B12 a payload without an identity word is not forwarded");

    // Gate off: nothing is translated and nothing is counted as a payload.
    citra_gateway::ControlOptions off_options;
    off_options.room_name = "synthetic-b12-off";
    citra_gateway::ControlBridge off_bridge(off_options, room_client::IPv4{10, 83, 0, 34}, mac);
    off_bridge.start();
    admit_station(off_bridge);
    check(off_bridge.on_citra_game_payload(host_payload(make_packet(0x03003039u, 1, body))).empty() &&
              off_bridge.counters().at("announce_host_payloads") == 0,
          "B12 the gate stays off by default for host payloads too");

    // No admitted station: the packet has no destination yet.
    citra_gateway::ControlOptions lonely_options;
    lonely_options.room_name = "synthetic-b12-lonely";
    lonely_options.ldn_announce_forward = true;
    lonely_options.ldn_identity_pairs.push_back({xx_host, gu_host});
    citra_gateway::ControlBridge lonely(lonely_options, room_client::IPv4{10, 83, 0, 35}, mac);
    lonely.start();
    check(lonely.on_citra_game_payload(host_payload(make_packet(0x03003039u, 1, body))).empty() &&
              lonely.counters().at("announce_prereq_rejected") == 1,
          "B12 a host payload without an admitted station is rejected");
}
// V-259: cross-game announce forward -- the first data-plane integration.
// A kind-0 session announce from the associated Citra peer gets its 4-byte
// identity words substituted per the V-249 primitive and leaves as a room Proxy
// packet towards the admitted Yuzu member.  The gate is opt-in; every rejection
// path keeps its own counter so a live run can be diagnosed without a capture.
void group_b11_announce_forward() {
    const std::array<std::uint8_t, 4> xx_host{0xb3, 0x5e, 0xe2, 0x7f};  // measured XX host
    const std::array<std::uint8_t, 4> gu_host{0xc0, 0xa8, 0x02, 0x2f};  // measured GU host
    const citra_room::MacAddress mac{2, 0, 0, 0, 0, 30};
    // 32 bytes of body control/counter words, then two member entries in the
    // measured 0x03003039 shape (identity word + port 0x3039): one carries the
    // XX host word, the second a decoy no pair matches and that must survive.
    const citra_room::Bytes body = bytes_from_hex(
        "01114900000000000000000002000000"
        "e6147194d33f87880100000000000000"
        "b35ee27f3039000000"
        "deadbeef30390001");
    // 12B MH header (magic, mode 1, kind) + 20B message header (ctrl group at
    // 12, len at 16, sender at 20, route at 24, reserved word at 28) + body at
    // 32 -- the V-249 packet layout.
    const auto make_packet = [&](std::uint32_t route, std::uint8_t kind,
                                 const citra_room::Bytes& payload) {
        citra_room::Bytes packet{0x32, 0xab, 0x98, 0x64, 0x01, kind, 0x00, 0x00,
                                 0x11, 0x2e, 0x00, 0x00,
                                 0x08, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x00, 0x00};
        packet.insert(packet.end(), xx_host.begin(), xx_host.end());
        packet.push_back(static_cast<std::uint8_t>((route >> 24) & 0xff));
        packet.push_back(static_cast<std::uint8_t>((route >> 16) & 0xff));
        packet.push_back(static_cast<std::uint8_t>((route >> 8) & 0xff));
        packet.push_back(static_cast<std::uint8_t>(route & 0xff));
        packet.insert(packet.end(), 4, 0x00);
        packet.insert(packet.end(), payload.begin(), payload.end());
        return packet;
    };
    // V-254: the real XX UDS Data payload is a 41 byte encapsulation head plus
    // the MH packet.  Only the offset is contractual here; the head bytes are
    // opaque to the announce path.
    citra_room::Bytes uds_head(41, 0x00);
    uds_head[0] = 0xaa;
    uds_head[1] = 0xaa;
    uds_head[2] = 0x03;
    uds_head[3] = 0x00;

    const citra_room::Bytes eapol_start =
        bytes_from_hex(fixture_hex("../citra-control/fixtures/uds_eapol_start.hex", "frame"));
    // Admit one Yuzu member (Scan + Connect) and fold the Citra guest's
    // association (Authentication SEQ1 + EAPoL-Start).
    const auto admit = [&](citra_gateway::ControlBridge& bridge) {
        citra_gateway::LdnContext ctx;
        ctx.have_mapped_mac = true;
        ctx.mapped_mac = citra_room::MacAddress{2, 0, 0, 0, 0, 31};
        room_client::LdnPacket scan;
        scan.type = room_client::LdnType::Scan;
        scan.local_ip = room_client::IPv4{10, 83, 0, 31};
        (void)bridge.on_ldn(scan, ctx);
        room_client::LdnPacket connect;
        connect.type = room_client::LdnType::Connect;
        connect.local_ip = room_client::IPv4{10, 83, 0, 31};
        connect.data.assign(64, 0);
        (void)bridge.on_ldn(connect, ctx);
        citra_room::WifiPacket auth;
        auth.type = citra_room::FrameType::Authentication;
        auth.channel = 6;
        auth.transmitter = mac;
        auth.destination = citra_room::broadcast_mac;
        auth.data = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        (void)bridge.on_citra_wifi(auth, 0);
        (void)bridge.on_citra_eapol(eapol_start, 0);
    };
    const auto data_frame = [&](const citra_room::Bytes& packet) {
        citra_room::WifiPacket wifi;
        wifi.type = citra_room::FrameType::Data;
        wifi.channel = 11;
        wifi.transmitter = mac;
        wifi.destination = citra_room::broadcast_mac;
        wifi.data = uds_head;
        wifi.data.insert(wifi.data.end(), packet.begin(), packet.end());
        return wifi;
    };

    citra_gateway::ControlOptions options;
    options.room_name = "synthetic-b11";
    options.ldn_announce_forward = true;
    options.ldn_identity_pairs.push_back({xx_host, gu_host});
    citra_gateway::ControlBridge bridge(options, room_client::IPv4{10, 83, 0, 30}, mac);
    bridge.start();
    admit(bridge);
    check(bridge.counters().at("eapol_start_accepted") == 1 &&
              bridge.counters().at("ldn_connect_accepted") == 1 && bridge.station_count() == 1,
          "B11 the fixture admits one station and one associated Citra peer");

    const citra_room::Bytes announce = make_packet(0x03003039u, 0, body);
    const auto emissions = bridge.on_citra_wifi(data_frame(announce), 1000);
    check(emissions.size() == 1 && !emissions[0].to_citra && emissions[0].room_proxy &&
              emissions[0].kind == "room.proxy.announce" && emissions[0].proxy_broadcast,
          "B11 the kind-0 announce becomes one broadcast room Proxy emission");
    const std::string forwarded =
        emissions.empty() ? std::string() : hex_of(emissions[0].proxy_data);
    check(forwarded.size() == announce.size() * 2 && hex_slice(forwarded, 0, 4) == "32ab9864",
          "B11 the forwarded proxy starts at the MH magic (41 byte head stripped)");
    // Packet layout: 12 byte MH header, 20 byte message header, body at 32.
    // The body identity word sits at 64, the message-header sender at 20, and
    // the decoy word at 73 followed by the port at 77 (V-249 parity).
    check(hex_slice(forwarded, 64, 4) == "c0a8022f",
          "B11 the XX host word is rewritten to the GU host word");
    check(forwarded.size() >= 128 && forwarded.substr(128).find("b35ee27f") == std::string::npos,
          "B11 no XX host word survives beyond the message header");
    check(hex_slice(forwarded, 20, 4) == "b35ee27f",
          "B11 the message-header sender word is preserved (V-249 parity)");
    check(hex_slice(forwarded, 73, 4) == "deadbeef" &&
              hex_slice(forwarded, 77, 2) == "3039",
          "B11 the unmatched decoy word and the port word are preserved");
    check(bridge.counters().at("announce_forwarded") == 1 &&
              bridge.counters().at("announce_word_replacements") == 1 &&
              bridge.counters().at("announce_word_replacements_total") == 1,
          "B11 the forward and its single word replacement are counted");
    check(bridge.counters().at("citra_wrong_direction") == 0,
          "B11 a forwarded announce is no longer counted as a wrong-direction drop");

    // A route outside the V-249 whitelist is not a session announce.
    const auto before_route = bridge.counters().at("citra_wrong_direction");
    const auto bad_route = bridge.on_citra_wifi(
        data_frame(make_packet(0xdeadbeefu, 0, body)), 1001);
    check(bad_route.empty() && bridge.counters().at("announce_route_rejected") == 1 &&
              bridge.counters().at("citra_wrong_direction") == before_route + 1 &&
              bridge.counters().at("announce_forwarded") == 1,
          "B11 an unmeasured route is rejected and counted, never forwarded");

    // kind 1 is heartbeat traffic, not an announce.
    const auto before_kind = bridge.counters().at("citra_wrong_direction");
    const auto kind1 = bridge.on_citra_wifi(data_frame(make_packet(0x03003039u, 1, body)), 1002);
    check(kind1.empty() && bridge.counters().at("citra_wrong_direction") == before_kind + 1 &&
              bridge.counters().at("announce_forwarded") == 1,
          "B11 a kind-1 packet is not an announce and stays out of the forward path");

    // A kind-0 announce with no matching identity word is not forwarded.
    const citra_room::Bytes other_body = bytes_from_hex(
        "01114900000000000000000002000000"
        "e6147194d33f87880100000000000000"
        "111111113039000000"
        "deadbeef30390001");
    const auto no_word =
        bridge.on_citra_wifi(data_frame(make_packet(0x03003039u, 0, other_body)), 1003);
    check(no_word.empty() && bridge.counters().at("announce_no_identity_word") == 1 &&
              bridge.counters().at("announce_forwarded") == 1,
          "B11 a body with no known identity word is not forwarded");

    // The default remains the historical drop: gate off => no proxy emission.
    {
        citra_gateway::ControlOptions off_options;
        off_options.room_name = "synthetic-b11-off";
        off_options.ldn_identity_pairs.push_back({xx_host, gu_host});
        citra_gateway::ControlBridge off(off_options, room_client::IPv4{10, 83, 0, 32}, mac);
        off.start();
        admit(off);
        const auto dropped = off.on_citra_wifi(data_frame(announce), 1000);
        check(dropped.empty() && off.counters().at("announce_forwarded") == 0 &&
                  off.counters().at("citra_wrong_direction") == 1,
              "B11 with the gate off the announce is still a counted wrong-direction drop");
    }

    // Forwarding needs a Yuzu member to forward to: a Citra-only room keeps
    // the announce on the drop path and says why.
    {
        citra_gateway::ControlOptions lonely_options;
        lonely_options.room_name = "synthetic-b11-lonely";
        lonely_options.ldn_announce_forward = true;
        lonely_options.ldn_identity_pairs.push_back({xx_host, gu_host});
        citra_gateway::ControlBridge lonely(lonely_options, room_client::IPv4{10, 83, 0, 33}, mac);
        lonely.start();
        citra_room::WifiPacket auth;
        auth.type = citra_room::FrameType::Authentication;
        auth.channel = 6;
        auth.transmitter = mac;
        auth.destination = citra_room::broadcast_mac;
        auth.data = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        (void)lonely.on_citra_wifi(auth, 0);
        (void)lonely.on_citra_eapol(eapol_start, 0);
        const auto no_member = lonely.on_citra_wifi(data_frame(announce), 1000);
        check(no_member.empty() && lonely.counters().at("announce_prereq_rejected") == 1 &&
                  lonely.counters().at("announce_forwarded") == 0,
              "B11 without an admitted station the announce is not forwarded");
    }

    // An ambiguous pair table is refused at construction, exactly like the
    // V-249 primitive: a word mapped onto itself can never translate.
    {
        citra_gateway::ControlOptions bad_options;
        bad_options.room_name = "synthetic-b11-badpair";
        bad_options.ldn_announce_forward = true;
        bad_options.ldn_identity_pairs.push_back({xx_host, xx_host});
        citra_gateway::ControlBridge bad(bad_options, room_client::IPv4{10, 83, 0, 34}, mac);
        check(bad.counters().at("announce_pair_rejected") == 1 &&
                  bad.counters().at("announce_forwarded") == 0,
              "B11 a self-mapped identity pair is rejected instead of half-translating");
    }
}

void group_b7_game_script() {
    const std::string step0_hex =
        std::string("aaaa03000000876d000f0000000b0021012cffff0001") + "aa";
    const std::string step1_hex =
        std::string("aaaa03000000876d000f0000000b0021012dffff0002") + "bb";
    const auto make_step = [](std::uint32_t after, std::uint32_t delay, bool broadcast,
                              const std::string& hex, const std::string& label) {
        citra_gateway::Options::GameScriptStep step;
        step.after_guest_frames = after;
        step.delay_ms = delay;
        step.broadcast = broadcast;
        step.payload = bytes_from_hex(hex);
        step.label = label;
        return step;
    };
    const auto received_payload = [](CitraPeer& peer, const std::string& want) {
        for (const auto& message : peer.messages()) {
            if (const auto* wifi = std::get_if<citra_room::WifiPacket>(&message)) {
                if (hex_of(wifi->data) == want) {
                    return wifi;
                }
            }
        }
        return static_cast<const citra_room::WifiPacket*>(nullptr);
    };
    const std::string eapol_hex =
        fixture_hex("../citra-control/fixtures/uds_eapol_start.hex", "frame");
    // The guest's own legal game-layer frame (protocol size 15, SecureData size
    // 11, channel 33, broadcast destination, associated source node 2).
    const citra_room::Bytes guest_game =
        bytes_from_hex("aaaa03000000876d000f0000000b0021012cffff000211");

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Options options = gateway_options(gw_port, room);
        options.control_plane_enabled = true;
        options.game_script = {make_step(0, 0, true, step0_hex, "step0"),
                               make_step(1, 0, false, step1_hex, "step1")};
        citra_gateway::Gateway gateway(options);
        gateway.open();

        CitraPeer alpha;
        alpha.connect(gw_port);
        verify(join_peer(gateway, alpha, "alpha-game", "console-game"),
               "B7 alpha joins through the gateway");
        const std::uint64_t alpha_id = client_id_for(gateway, "alpha-game");
        verify(alpha_id != 0, "B7 alpha appears in the client table");
        const auto alpha_mac = alpha.assigned_mac();
        verify(alpha_mac.has_value(), "B7 alpha received an assigned MAC");

        // Joining the room is not the association: no step may fire yet.
        drive(gateway, {&alpha}, [] { return false; }, 200);
        check(json_counter(gateway.counters_json(), "game_script_frames_sent") == 0 &&
                  emitted_of_kind(gateway, "citra.game_script").empty(),
              "B7 the script stays inert until the guest's association completes");

        // The association has to complete first: a bare EAPoL-Start on an
        // unassociated MAC is refused by the control bridge.
        const citra_room::Bytes auth_seq1{0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, auth_seq1,
                                              frame_type_byte(citra_room::FrameType::Authentication)));
        verify(control_counter(gateway, "auth_seq1_accepted") == 1,
               "B7 the Authentication SEQ1 fold completes the handshake");
        const citra_room::Bytes eapol_start = bytes_from_hex(eapol_hex);
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, eapol_start,
                                              frame_type_byte(citra_room::FrameType::Data)));
        verify(control_counter(gateway, "eapol_start_accepted") == 1,
               "B7 the EAPoL fold completes the UDS association");

        // V-131: gc6's gateway-only room has no Yuzu peer, so the room side
        // never reports Connected and the script used to stay inert forever.
        // Arming is now keyed to the Citra association alone, so no room-side
        // LDN Connect may be injected here.
        verify(control_counter(gateway, "ldn_connect_accepted") == 0,
               "B7 the script arms with no room-side LDN Connect at all");

        // Step 0 is anchored to the fold (after_guest_frames == 0): it must
        // reach the guest on the very next tick, byte for byte.
        check(drive(gateway, {&alpha},
                    [&] { return emitted_of_kind(gateway, "citra.game_script").size() >= 1; }, 2000),
              "B7 step 0 fires once the association is complete");
        const auto* got0 = received_payload(alpha, step0_hex);
        check(got0 != nullptr && got0->type == citra_room::FrameType::Data &&
                  got0->destination == citra_room::broadcast_mac,
              "B7 step 0 is a broadcast Citra Data frame carrying the replayed payload");
        const auto emitted0 = emitted_of_kind(gateway, "citra.game_script");
        check(emitted0.size() == 1 && emitted0[0].client_id == alpha_id &&
                  emitted0[0].hex == step0_hex &&
                  emitted0[0].bytes == bytes_from_hex(step0_hex).size(),
              "B7 step 0 is recorded byte for byte on the emitted ledger");
        check(json_counter(gateway.counters_json(), "game_script_frames_sent") == 1,
              "B7 the game script counter reports the one frame sent");

        // Step 1 is anchored to the guest's first game-layer frame: it must wait.
        drive(gateway, {&alpha}, [] { return false; }, 200);
        check(emitted_of_kind(gateway, "citra.game_script").size() == 1 &&
                  json_counter(gateway.counters_json(), "game_script_frames_sent") == 1,
              "B7 a step anchored to a guest frame waits for that frame");

        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, guest_game,
                                              frame_type_byte(citra_room::FrameType::Data)));
        check(control_counter(gateway, "citra_data_accepted") == 1,
              "B7 the guest's game-layer frame is admitted by the control plane");
        check(drive(gateway, {&alpha},
                    [&] { return emitted_of_kind(gateway, "citra.game_script").size() >= 2; }, 2000),
              "B7 step 1 fires after the guest's first game-layer frame");
        const auto* got1 = received_payload(alpha, step1_hex);
        check(got1 != nullptr && got1->type == citra_room::FrameType::Data &&
                  got1->destination == *alpha_mac,
              "B7 step 1 is a unicast Citra Data frame addressed to the guest");
        check(json_counter(gateway.counters_json(), "game_script_frames_sent") == 2,
              "B7 the game script counter reports both frames");
        gateway.close();
    }

    {
        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Options options = gateway_options(gw_port, room);
        options.control_plane_enabled = true;
        verify(options.game_script.empty(), "B7 the default game script is empty");
        citra_gateway::Gateway gateway(options);
        gateway.open();

        CitraPeer alpha;
        alpha.connect(gw_port);
        verify(join_peer(gateway, alpha, "alpha-plain", "console-plain"),
               "B7 alpha joins a gateway with no game script");
        const std::uint64_t alpha_id = client_id_for(gateway, "alpha-plain");
        const auto alpha_mac = alpha.assigned_mac();
        verify(alpha_mac.has_value(), "B7 alpha received an assigned MAC");
        // The association has to complete first: a bare EAPoL-Start on an
        // unassociated MAC is refused by the control bridge.
        const citra_room::Bytes auth_seq1{0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, auth_seq1,
                                              frame_type_byte(citra_room::FrameType::Authentication)));
        verify(control_counter(gateway, "auth_seq1_accepted") == 1,
               "B7 the Authentication SEQ1 fold completes the handshake");
        const citra_room::Bytes eapol_start = bytes_from_hex(eapol_hex);
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, eapol_start,
                                              frame_type_byte(citra_room::FrameType::Data)));
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, guest_game,
                                              frame_type_byte(citra_room::FrameType::Data)));
        drive(gateway, {&alpha}, [] { return false; }, 200);
        check(control_counter(gateway, "eapol_start_accepted") == 1 &&
                  control_counter(gateway, "citra_data_accepted") == 1 &&
                  json_counter(gateway.counters_json(), "game_script_frames_sent") == 0 &&
                  emitted_of_kind(gateway, "citra.game_script").empty(),
              "B7 an empty script sends nothing and keeps the gateway byte for byte unchanged");
        gateway.close();
    }

    {
        // V-132: MHXX's guest picks its own 32 bit nonce family value and the
        // real host echoes that live value.  A byte-for-byte replay carries the
        // captured session's value instead (gc8 echoed c9c93d03 while its guest
        // had announced 9409deb8, and the join collapsed 266 ms after WakeUp), so
        // the gateway substitutes the live value and, because no real host can
        // echo a value it has not received yet, holds such a step until the guest
        // announces it.
        const auto make_guest_secure = [](const std::size_t game_bytes,
                                          const std::size_t nonce_offset,
                                          const std::uint32_t nonce) {
            citra_room::Bytes frame(22 + game_bytes, 0);
            const std::uint8_t llc[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x87, 0x6d};
            for (std::size_t i = 0; i < 8; ++i) {
                frame[i] = llc[i];
            }
            const auto protocol_size = static_cast<std::uint16_t>(game_bytes + 14);
            const auto securedata_size = static_cast<std::uint16_t>(game_bytes + 10);
            frame[8] = static_cast<std::uint8_t>(protocol_size >> 8);
            frame[9] = static_cast<std::uint8_t>(protocol_size & 0xFFu);
            frame[12] = static_cast<std::uint8_t>(securedata_size >> 8);
            frame[13] = static_cast<std::uint8_t>(securedata_size & 0xFFu);
            frame[15] = 33;  // the game's data channel, already bound by the guest
            frame[18] = 0xFF;
            frame[19] = 0xFF;  // broadcast destination
            frame[21] = 2;     // the directly associated guest is node 2
            frame[nonce_offset] = static_cast<std::uint8_t>((nonce >> 24) & 0xFFu);
            frame[nonce_offset + 1] = static_cast<std::uint8_t>((nonce >> 16) & 0xFFu);
            frame[nonce_offset + 2] = static_cast<std::uint8_t>((nonce >> 8) & 0xFFu);
            frame[nonce_offset + 3] = static_cast<std::uint8_t>(nonce & 0xFFu);
            return frame;
        };
        constexpr std::uint32_t kCapturedNonce = 0xc9c93d03u;
        constexpr std::uint32_t kLiveNonce = 0x9409deb8u;
        // A 62 byte UDS echo frame whose last four bytes are the captured value,
        // exactly where the real host puts it (offset 58).
        citra_room::Bytes echo_step(62, 0);
        echo_step[58] = 0xc9;
        echo_step[59] = 0xc9;
        echo_step[60] = 0x3d;
        echo_step[61] = 0x03;
        citra_room::Bytes echo_want = echo_step;
        echo_want[58] = 0x94;
        echo_want[59] = 0x09;
        echo_want[60] = 0xde;
        echo_want[61] = 0xb8;

        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Options options = gateway_options(gw_port, room);
        options.control_plane_enabled = true;
        options.have_game_nonce_ref = true;
        options.game_nonce_ref = kCapturedNonce;
        options.game_script = {make_step(0, 0, false, hex_of(echo_step), "echo")};
        citra_gateway::Gateway gateway(options);
        gateway.open();

        CitraPeer alpha;
        alpha.connect(gw_port);
        verify(join_peer(gateway, alpha, "alpha-nonce", "console-nonce"),
               "B7 the nonce case joins through the gateway");
        const std::uint64_t alpha_id = client_id_for(gateway, "alpha-nonce");
        const auto alpha_mac = alpha.assigned_mac();
        verify(alpha_mac.has_value(), "B7 the nonce case received an assigned MAC");
        const citra_room::Bytes auth_seq1{0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, auth_seq1,
                                              frame_type_byte(citra_room::FrameType::Authentication)));
        const citra_room::Bytes eapol = bytes_from_hex(eapol_hex);
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, eapol,
                                              frame_type_byte(citra_room::FrameType::Data)));
        verify(control_counter(gateway, "eapol_start_accepted") == 1,
               "B7 the nonce case completes the association fold");
        drive(gateway, {&alpha}, [] { return false; }, 200);
        check(json_counter(gateway.counters_json(), "game_script_nonce_waits") == 1 &&
                  json_counter(gateway.counters_json(), "game_script_frames_sent") == 0 &&
                  emitted_of_kind(gateway, "citra.game_script").empty(),
              "B7 a step that echoes the captured nonce waits for the guest's own value");

        const citra_room::Bytes guest_nonce_frame = make_guest_secure(112, 128, kLiveNonce);
        check(guest_nonce_frame.size() == 134,
              "B7 the guest announces its nonce in the 134 byte payload");
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac,
                                              guest_nonce_frame,
                                              frame_type_byte(citra_room::FrameType::Data)));
        check(control_counter(gateway, "citra_data_accepted") == 1,
              "B7 the nonce carrying guest frame is admitted by the control plane");
        check(drive(gateway, {&alpha},
                    [&] { return emitted_of_kind(gateway, "citra.game_script").size() >= 1; }, 2000),
              "B7 the held step fires once the guest announced its nonce");
        const auto* got_nonce = received_payload(alpha, hex_of(echo_want));
        check(got_nonce != nullptr && got_nonce->destination == *alpha_mac,
              "B7 the replayed echo carries the live guest nonce at offset 58");
        const auto emitted_nonce = emitted_of_kind(gateway, "citra.game_script");
        check(emitted_nonce.size() == 1 && emitted_nonce[0].hex == hex_of(echo_want),
              "B7 the patched frame is what the ledger recorded");
        check(json_counter(gateway.counters_json(), "game_script_nonce_learned") == 1 &&
                  json_counter(gateway.counters_json(), "game_script_frames_patched") == 1 &&
                  json_counter(gateway.counters_json(), "game_script_frames_sent") == 1,
              "B7 the nonce counters report one learned value and one patched frame");

        // A second guest frame that announces the next value must be echoed with
        // the newest value, not the first one.
        const citra_room::Bytes guest_nonce_two = make_guest_secure(112, 128, kLiveNonce + 1u);
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, guest_nonce_two,
                                              frame_type_byte(citra_room::FrameType::Data)));
        check(json_counter(gateway.counters_json(), "game_script_nonce_learned") == 2,
              "B7 a newer live nonce is learned as the guest advances");
        gateway.close();
    }

    {
        // V-133: the guest also chooses the C and D session tokens and the real
        // host echoes those live values (gc9's guest announced 6e23a8c1 for C,
        // the replay echoed the captured e4d5c9a7, and the guest abandoned the
        // join 18 ms later without sending its phase transition frame).  The same
        // learn-then-rewrite rule covers them, including the captured
        // <value><value >> 16> suffix encoding.
        const auto make_guest_secure = [](const std::size_t game_bytes,
                                          const std::size_t offset,
                                          const std::uint32_t value) {
            citra_room::Bytes frame(22 + game_bytes, 0);
            const std::uint8_t llc[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x87, 0x6d};
            for (std::size_t i = 0; i < 8; ++i) {
                frame[i] = llc[i];
            }
            const auto protocol_size = static_cast<std::uint16_t>(game_bytes + 14);
            const auto securedata_size = static_cast<std::uint16_t>(game_bytes + 10);
            frame[8] = static_cast<std::uint8_t>(protocol_size >> 8);
            frame[9] = static_cast<std::uint8_t>(protocol_size & 0xFFu);
            frame[12] = static_cast<std::uint8_t>(securedata_size >> 8);
            frame[13] = static_cast<std::uint8_t>(securedata_size & 0xFFu);
            frame[15] = 33;  // the game's data channel, already bound by the guest
            frame[18] = 0xFF;
            frame[19] = 0xFF;  // broadcast destination
            frame[21] = 2;     // the directly associated guest is node 2
            frame[offset] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
            frame[offset + 1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
            frame[offset + 2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
            frame[offset + 3] = static_cast<std::uint8_t>(value & 0xFFu);
            return frame;
        };
        constexpr std::uint32_t kCapturedC = 0xe4d5c9a7u;
        constexpr std::uint32_t kLiveC = 0x6e23a8c1u;
        constexpr std::uint32_t kCapturedD = 0x8b8e8603u;
        constexpr std::uint32_t kLiveD = 0x1a2b3c4du;
        // Captured host frames: C at game offset 132 of a 196 byte game payload
        // (payload offset 154) followed by its own 16 bit suffix, D at game
        // offset 69 of a 268 byte one (payload offset 91, no suffix).
        citra_room::Bytes c_step(218, 0);
        const std::uint8_t c_captured[6] = {0xe4, 0xd5, 0xc9, 0xa7, 0xe4, 0xd5};
        for (std::size_t i = 0; i < 6; ++i) {
            c_step[154 + i] = c_captured[i];
        }
        citra_room::Bytes c_want = c_step;
        const std::uint8_t c_live[6] = {0x6e, 0x23, 0xa8, 0xc1, 0x6e, 0x23};
        for (std::size_t i = 0; i < 6; ++i) {
            c_want[154 + i] = c_live[i];
        }
        citra_room::Bytes d_step(290, 0);
        const std::uint8_t d_captured[4] = {0x8b, 0x8e, 0x86, 0x03};
        for (std::size_t i = 0; i < 4; ++i) {
            d_step[91 + i] = d_captured[i];
        }
        citra_room::Bytes d_want = d_step;
        const std::uint8_t d_live[4] = {0x1a, 0x2b, 0x3c, 0x4d};
        for (std::size_t i = 0; i < 4; ++i) {
            d_want[91 + i] = d_live[i];
        }

        const auto room_port = take_port();
        const auto gw_port = take_port();
        RoomGuard room(room_port, 4);
        citra_gateway::Options options = gateway_options(gw_port, room);
        options.control_plane_enabled = true;
        citra_gateway::Options::GameTokenRef c_token;
        c_token.ref = kCapturedC;
        c_token.learn_sites.emplace_back(112, 48);
        citra_gateway::Options::GameTokenRef d_token;
        d_token.ref = kCapturedD;
        d_token.learn_sites.emplace_back(268, 69);
        options.game_token_refs = {c_token, d_token};
        options.game_script = {make_step(0, 0, false, hex_of(c_step), "c-echo"),
                               make_step(0, 0, false, hex_of(d_step), "d-echo")};
        citra_gateway::Gateway gateway(options);
        gateway.open();

        CitraPeer alpha;
        alpha.connect(gw_port);
        verify(join_peer(gateway, alpha, "alpha-token", "console-token"),
               "B7 the token case joins through the gateway");
        const std::uint64_t alpha_id = client_id_for(gateway, "alpha-token");
        const auto alpha_mac = alpha.assigned_mac();
        verify(alpha_mac.has_value(), "B7 the token case received an assigned MAC");
        const citra_room::Bytes auth_seq1{0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, auth_seq1,
                                              frame_type_byte(citra_room::FrameType::Authentication)));
        const citra_room::Bytes eapol = bytes_from_hex(eapol_hex);
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, eapol,
                                              frame_type_byte(citra_room::FrameType::Data)));
        verify(control_counter(gateway, "eapol_start_accepted") == 1,
               "B7 the token case completes the association fold");
        drive(gateway, {&alpha}, [] { return false; }, 200);
        check(json_counter(gateway.counters_json(), "game_script_token_waits") == 1 &&
                  json_counter(gateway.counters_json(), "game_script_frames_sent") == 0 &&
                  emitted_of_kind(gateway, "citra.game_script").empty(),
              "B7 a step that echoes the captured C token waits for the guest's own value");

        // The guest announces C in its 134 byte frame (game offset 48).
        const citra_room::Bytes guest_c = make_guest_secure(112, 48 + 22, kLiveC);
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, guest_c,
                                              frame_type_byte(citra_room::FrameType::Data)));
        check(control_counter(gateway, "citra_data_accepted") == 1,
              "B7 the C carrying guest frame is admitted by the control plane");
        check(drive(gateway, {&alpha},
                    [&] { return emitted_of_kind(gateway, "citra.game_script").size() >= 1; }, 2000),
              "B7 the held C step fires once the guest announced its token");
        const auto* got_c = received_payload(alpha, hex_of(c_want));
        check(got_c != nullptr && got_c->destination == *alpha_mac,
              "B7 the replayed C echo carries the live value and its suffix");
        check(json_counter(gateway.counters_json(), "game_script_tokens_learned") == 1 &&
                  json_counter(gateway.counters_json(), "game_script_token_frames_patched") == 1 &&
                  json_counter(gateway.counters_json(), "game_script_frames_patched") == 1,
              "B7 one token was learned and one frame patched for C");

        // The next step carries D: it waits in turn, then fires with the live D.
        drive(gateway, {&alpha}, [] { return false; }, 200);
        check(json_counter(gateway.counters_json(), "game_script_token_waits") == 2 &&
                  json_counter(gateway.counters_json(), "game_script_frames_sent") == 1,
              "B7 the D step waits for its own token too");
        const citra_room::Bytes guest_d = make_guest_secure(268, 69 + 22, kLiveD);
        gateway.inject_citra_frame_for_test(
            alpha_id, citra_wifi_frame_manual(*alpha_mac, citra_room::broadcast_mac, guest_d,
                                              frame_type_byte(citra_room::FrameType::Data)));
        check(drive(gateway, {&alpha},
                    [&] { return emitted_of_kind(gateway, "citra.game_script").size() >= 2; }, 2000),
              "B7 the held D step fires once the guest announced its token");
        const auto* got_d = received_payload(alpha, hex_of(d_want));
        check(got_d != nullptr && got_d->destination == *alpha_mac,
              "B7 the replayed D echo carries the live value");
        check(json_counter(gateway.counters_json(), "game_script_tokens_learned") == 2 &&
                  json_counter(gateway.counters_json(), "game_script_token_frames_patched") == 2 &&
                  json_counter(gateway.counters_json(), "game_script_frames_patched") == 2 &&
                  json_counter(gateway.counters_json(), "game_script_frames_sent") == 2,
              "B7 the token counters report two learned values and two patched frames");
        gateway.close();
    }
}

#include "game_return_runtime.inc"

} // namespace


int main(int argc, char** argv) {
    if (argc > 1) {
        g_evidence_dir = argv[1];
    }
    std::cout << "G-b/G-b'/G-c gateway acceptance harness (Citra side ENet/UDP delivery plus a "
                 "harness-only TCP transport, tier A structural evidence only)\n";
    std::cout << "evidence directory: " << g_evidence_dir << "\n";
    room_transport::Runtime runtime;
    const std::size_t baseline_threads = thread_count();

    run_group("A1_members", group_a1_members);
    run_group("A2_handshake_version", group_a2_handshake);
    run_group("A3_error_mappings", group_a3_mappings);
    run_group("A3b_room_goldens", group_a3_room_goldens);
    run_group("A3c_order", group_a3c_order);
    run_group("A4_payload_hex", group_a4_payload);
    run_group("A5_fail_closed", group_a5_fail_closed);
    run_group("A6_negative", group_a6_negative);
    run_group("A7_release_regression", group_a7_release);
    run_group("A8_isolation_bounds", group_a8_isolation);
    run_group("A10_general", group_a10_general);
    run_group("A11_peer_relay", group_a11_peer_relay);
    run_group("B1_control", group_b1_control);
    run_group("B2_control_loopback", group_b2_control_loopback);
    run_group("B3_citra_enet", group_b3_citra_enet);
    run_group("B4_session_ledger", group_b4_session_ledger);
    run_group("B5_early_game_info", group_b5_early_game_info);
    run_group("B20_room_ui", group_b20_room_ui);
    run_group("B6_invalid_node_state", group_b6_invalid_node_state);
    run_group("B7_game_script", group_b7_game_script);
    run_group("B8_ldn_identity_override", group_b8_ldn_identity_override);
    run_group("B9_heartbeat_learner", group_b9_heartbeat_learner);
    run_group("B10_sync_fanout", group_b10_sync_fanout);
    run_group("B11_announce_forward", group_b11_announce_forward);
    run_group("B12_host_payload_forward", group_b12_host_payload_forward);
    run_group("B13_pending_host_flush", group_b13_pending_host_flush);
    run_group("B14_guest_inject", group_b14_guest_inject);
    run_group("B302_guest_departure", group_b302_guest_departure);
    run_group("B303_reverse_advertise", group_b303_reverse_advertise);
    run_group("B304_reverse_discovery", group_b304_reverse_discovery);
    run_group("B318_reverse_multi_discovery", group_b318_reverse_multi_discovery);
    run_group("B319_shared_guest_identities", group_b319_shared_guest_identities);
    run_group("B321_four_player_rosters", group_b321_four_player_rosters);
    run_group("B328_native_gu_guests", group_b328_native_gu_guests);
    run_group("B328_citra_host_multi_gu", group_b328_citra_host_multi_gu);
    run_group("B322_gateway_peer_mesh", [] { group_b322_gateway_peer_mesh(); });
    run_group("B323_dual_reverse_mesh", [] { group_b322_gateway_peer_mesh(true); });
    run_group("B323_dual_host_roles", group_b323_dual_host_roles);
    run_group("B323_independent_halls", group_b323_independent_halls);
        run_group("B305_reverse_association", group_b305_reverse_association);
    run_group("B15_live_advertise", group_b15_live_advertise);
    run_group("B16_member_endpoints", group_b16_member_endpoints);
    run_group("B17_game_return_runtime", group_b17_game_return_runtime);
    run_group("B18_join_conversion", group_b18_join_conversion);
    run_group("B19_join_structures", group_b19_join_structures);
    run_group("T1_trace", group_t1_trace);

    check(room_transport::Transport::live_hosts() == 0,
          "A10 every room transport host was released");
    check(thread_count() == baseline_threads,
          "A10 the gateway produced no background worker thread");

    for (const auto& [key, value] : g_notes) {
        std::cout << "NOTE " << key << "=" << value << "\n";
    }
    for (const auto& failure : g_failures) {
        std::cout << "FAILED " << failure << "\n";
    }
    std::cout << "RESULT cases=" << g_cases << " failed=" << g_failed << " groups=" << g_groups
              << " exit=" << (g_failed == 0 ? 0 : 1) << "\n";
    return g_failed == 0 ? 0 : 1;
}
