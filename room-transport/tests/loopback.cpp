// SPDX-License-Identifier: GPL-2.0-or-later
// Own synthetic clients only; unchanged original Room sources, no fake server.
#include "room_transport/transport.hpp"
#include "network/room.h"
#include <enet/enet.h>
#include <zstd.h>
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

namespace rc = room_client;
namespace rt = room_transport;
using Clock = std::chrono::steady_clock;
int cases = 0;
void check(bool yes, const std::string& name) {
    if (!yes) throw std::runtime_error(name);
    ++cases; std::cout << "PASS " << cases << " " << name << std::endl;
}
std::size_t threads() {
    HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("thread snapshot failed");
    THREADENTRY32 entry{}; entry.dwSize = sizeof(entry); std::size_t n = 0;
    if (Thread32First(handle, &entry)) do {
        if (entry.th32OwnerProcessID == GetCurrentProcessId()) ++n;
    } while (Thread32Next(handle, &entry));
    CloseHandle(handle); return n;
}
struct RoomGuard {
    Network::Room room;
    bool open = false;
    RoomGuard(std::uint16_t port, std::uint32_t capacity, std::string password = {}) {
        open = room.Create("M2-source-loopback", "synthetic only", "127.0.0.1", port,
            password, capacity, "", Network::GameInfo{"Envelope test", 0, ""},
            std::make_unique<Network::VerifyUser::NullBackend>(), {}, false);
        if (!open) throw std::runtime_error("original Room::Create failed; port in use?");
    }
    void close() { if (open) { room.Destroy(); open = false; } }
    ~RoomGuard() { close(); }
};
struct Client {
    rt::Transport transport;
    std::vector<rc::Message> messages;
    explicit Client(rt::Options options = {}) : transport(options) {}
    void tick(std::uint32_t wait = 1, bool consume = true) {
        transport.poll(wait);
        if (consume) while (auto m = transport.pop()) {
            if (messages.size() >= 512) throw std::runtime_error("test inbox bound exceeded");
            messages.push_back(std::move(*m));
        }
    }
    void clear() { messages.clear(); while (transport.pop()) {} }
    std::size_t count(rc::MessageId id) const {
        return std::count_if(messages.begin(), messages.end(), [id](const auto& m) { return rc::message_id(m) == id; });
    }
};
void until(const std::function<bool()>& done, const std::vector<Client*>& clients,
           const std::string& label, std::uint32_t bound = 2500, bool consume = true) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(bound);
    while (!done() && Clock::now() < deadline) for (auto* c : clients) c->tick(2, consume);
    if (!done()) {
        std::string info;
        for (auto* c : clients) info += " [" + rt::state_name(c->transport.snapshot().state) + ": " + c->transport.snapshot().failure + "]";
        throw std::runtime_error("bounded wait: " + label + info);
    }
}
void window(const std::vector<Client*>& clients, std::uint32_t duration = 100) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(duration);
    do { for (auto* c : clients) c->tick(2); } while (Clock::now() < deadline);
}
rc::JoinRequest join_request(const std::string& name, rc::IPv4 ip = rc::no_preferred_ip, std::string password = {}) {
    return {name, ip, 1, std::move(password), ""};
}
rt::Options options(std::uint16_t port) { rt::Options o; o.port = port; return o; }
void join(Client& client, const rc::JoinRequest& request, const std::vector<Client*>& pump) {
    client.transport.start(request);
    check(client.transport.snapshot().state == rt::State::Connecting, request.nickname + " enters Connecting");
    until([&] { return client.transport.snapshot().state == rt::State::Joined || client.transport.snapshot().state == rt::State::Failed; }, pump, "join " + request.nickname);
    check(client.transport.snapshot().state == rt::State::Joined, request.nickname + " enters Joined via M1 core");
    auto first_info = std::find_if(client.messages.begin(), client.messages.end(), [](const auto& m) { return std::holds_alternative<rc::RoomInformation>(m); });
    auto first_success = std::find_if(client.messages.begin(), client.messages.end(), [](const auto& m) { return std::holds_alternative<rc::JoinSuccess>(m); });
    check(first_info != client.messages.end() && first_success != client.messages.end() && first_info < first_success,
          request.nickname + " RoomInformation precedes JoinSuccess");
}
// Test-only raw version-rejection path. Normal Transport intentionally forbids
// version !=1; this bypass only uses the bounded M1 codec and original Room.
rc::ServerError wrong_version(std::uint16_t port) {
    struct HostDelete { void operator()(ENetHost* h) const { enet_host_destroy(h); } };
    std::unique_ptr<ENetHost, HostDelete> host(enet_host_create(nullptr, 1, 1, 0, 0));
    if (!host) throw std::runtime_error("raw host create");
    host->maximumPacketSize = 65536; host->maximumWaitingData = 262144;
    ENetAddress address{}; enet_address_set_host_ip(&address, "127.0.0.1"); address.port = port;
    ENetPeer* peer = enet_host_connect(host.get(), &address, 1, 0);
    if (!peer) throw std::runtime_error("raw connect");
    const auto deadline = Clock::now() + std::chrono::seconds(2);
    while (Clock::now() < deadline) {
        ENetEvent e{}; if (enet_host_service(host.get(), &e, 5) <= 0) continue;
        if (e.type == ENET_EVENT_TYPE_CONNECT) {
            auto request = join_request("VersionCase"); request.version = 2;
            const auto bytes = rc::encode(request, rc::Direction::ClientToServer);
            ENetPacket* p = enet_packet_create(bytes.data(), bytes.size(), ENET_PACKET_FLAG_RELIABLE);
            if (!p) throw std::bad_alloc();
            if (enet_peer_send(peer, 0, p) != 0) { enet_packet_destroy(p); throw std::runtime_error("raw send"); }
            enet_host_flush(host.get());
        } else if (e.type == ENET_EVENT_TYPE_RECEIVE) {
            const rc::Bytes bytes(e.packet->data, e.packet->data + e.packet->dataLength);
            enet_packet_destroy(e.packet);
            auto message = rc::decode(bytes, rc::Direction::ServerToClient);
            if (auto* error = std::get_if<rc::ServerError>(&message)) {
                enet_peer_disconnect_now(peer, 0); return *error;
            }
        }
    }
    enet_peer_disconnect_now(peer, 0); throw std::runtime_error("raw version deadline");
}
void reject(std::uint16_t port, rc::JoinRequest request, rc::MessageId id, const std::vector<Client*>& others) {
    Client client(options(port)); client.transport.start(request);
    auto pump = others; pump.push_back(&client);
    until([&] { return client.transport.snapshot().state == rt::State::Failed; }, pump, "reject " + request.nickname);
    const auto s = client.transport.snapshot();
    check(s.server_error == id && !s.room && !s.assigned_ip && !s.host_live, "original Room rejection " + rc::message_name(id));
    client.transport.stop();
    check(client.transport.snapshot().state == rt::State::Idle && client.transport.snapshot().outstanding_packets == 0,
          "rejected client bounded stop releases packets");
    window(others, 25);
}
rc::Bytes compressed() {
    const std::string plain = "M2 isolated legal zstd frame; not gameplay";
    rc::Bytes frame(ZSTD_compressBound(plain.size()));
    auto n = ZSTD_compress(frame.data(), frame.size(), plain.data(), plain.size(), 1);
    if (ZSTD_isError(n)) throw std::runtime_error("ZSTD_compress"); frame.resize(n); return frame;
}
void decompress(const rc::ProxyPacket& p) {
    const std::string plain = "M2 isolated legal zstd frame; not gameplay";
    char out[128]{}; const auto n = ZSTD_decompress(out, sizeof(out), p.data.data(), p.data.size());
    check(!ZSTD_isError(n) && std::string(out, n) == plain, "Proxy legal Zstd frame decompresses to exact synthetic bytes");
}
template <class F>
bool throws_invalid(F&& f) {
    try { f(); } catch (const std::invalid_argument&) { return true; } catch (...) { return false; }
    return false;
}
rc::Bytes zstd_frame(const rc::Bytes& plain, int level = 1) {
    rc::Bytes frame(ZSTD_compressBound(plain.size()));
    const auto n = ZSTD_compress(frame.data(), frame.size(), plain.data(), plain.size(), level);
    if (ZSTD_isError(n)) throw std::runtime_error("ZSTD_compress failed");
    frame.resize(n); return frame;
}
rc::Bytes zstd_unknown_size(const rc::Bytes& plain) {
    struct CtxDelete { void operator()(ZSTD_CCtx* c) const { ZSTD_freeCCtx(c); } };
    std::unique_ptr<ZSTD_CCtx, CtxDelete> ctx(ZSTD_createCCtx());
    if (!ctx) throw std::bad_alloc();
    if (ZSTD_isError(ZSTD_CCtx_setParameter(ctx.get(), ZSTD_c_contentSizeFlag, 0)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(ctx.get(), ZSTD_c_compressionLevel, 1)))
        throw std::runtime_error("ZSTD_CCtx_setParameter failed");
    rc::Bytes frame(ZSTD_compressBound(plain.size()));
    const auto n = ZSTD_compress2(ctx.get(), frame.data(), frame.size(), plain.data(), plain.size());
    if (ZSTD_isError(n)) throw std::runtime_error("ZSTD_compress2 failed");
    frame.resize(n); return frame;
}
rc::Bytes concat(rc::Bytes first, const rc::Bytes& second) {
    first.insert(first.end(), second.begin(), second.end()); return first;
}
void routing(Client& a, Client& b, Client& c, bool proxy, bool broadcast, bool unknown) {
    window({&a,&b,&c}, 20); a.clear(); b.clear(); c.clear();
    const auto local = *a.transport.snapshot().assigned_ip;
    const auto target = unknown ? rc::IPv4{10,99,99,99} : *b.transport.snapshot().assigned_ip;
    const auto id = proxy ? rc::MessageId::Proxy : rc::MessageId::Ldn;
    rc::Message message;
    if (proxy) message = rc::ProxyPacket{{rc::Domain::Inet,local,1234},{rc::Domain::Inet,target,5678},rc::SocketProtocol::Udp,broadcast,compressed()};
    else message = rc::LdnPacket{rc::LdnType::Scan,local,target,broadcast,{}}; // Known Scan empty control payload.
    check(a.transport.send(message), std::string(proxy ? "Proxy" : "LDN Scan") + " accepted only while Joined");
    if (unknown) window({&a,&b,&c}, 120);
    else {
        until([&] { return b.count(id) == 1 && (!broadcast || c.count(id) == 1); }, {&a,&b,&c}, "route");
        window({&a,&b,&c}, 75);
    }
    const std::string mode = unknown ? "unknown receiver dropped" : broadcast ? "broadcast exact non-sender set" : "unicast exact target only";
    check(a.count(id) == 0 && b.count(id) == (unknown ? 0U : 1U) && c.count(id) == ((!unknown && broadcast) ? 1U : 0U),
          std::string(proxy ? "Proxy " : "LDN ") + mode + "; no sender echo");
    if (!unknown) {
        for (auto* client : broadcast ? std::vector<Client*>{&b,&c} : std::vector<Client*>{&b}) {
            const auto found = std::find_if(client->messages.begin(), client->messages.end(), [id](const auto& m) { return rc::message_id(m) == id; });
            check(*found == message, "original Room preserves entire envelope bytes/fields");
            if (proxy) decompress(std::get<rc::ProxyPacket>(*found));
        }
    }
}
int main() {
    std::cout << "M2a original-source Room harness; M2b/M4-M6 NOT TESTED" << std::endl;
    try {
        rt::Runtime runtime;
        const auto baseline_threads = threads();
        constexpr std::uint16_t port = 39472;
        {
            RoomGuard room(port, 3);
            check(room.room.GetState() == Network::Room::State::Open, "unchanged original Room::Create + original NullBackend");
            Client a(options(port)), b(options(port)), c(options(port));
            bool refused = false; try { a.transport.send(rc::GameInfo{}); } catch (const std::logic_error&) { refused = true; }
            check(refused, "transport blocks pre-join application data");
            join(a, join_request("AlphaClient"), {&a});
            const auto ai = *a.transport.snapshot().assigned_ip;
            check(ai[0] == 192 && ai[1] == 168 && ai[2] >= 1 && ai[2] <= 254 && ai[3] >= 1 && ai[3] <= 254,
                  "FFFFFFFF automatic fake IPv4 follows original allocation range");
            const rc::IPv4 fixed{192,168,42,99};
            join(b, join_request("BravoClient",fixed), {&a,&b});
            check(b.transport.snapshot().assigned_ip == fixed, "specified fake IPv4 returned raw unchanged");
            until([&] { auto s=a.transport.snapshot(); return s.room && s.room->members.size()==2; }, {&a,&b}, "two members");
            check(a.transport.snapshot().room->members == b.transport.snapshot().room->members && room.room.GetRoomMemberList().size() == 2,
                  "two independent ENet clients and original Room agree on membership");
            check(std::any_of(a.messages.begin(),a.messages.end(),[](const auto& m){ auto* s=std::get_if<rc::StatusMessage>(&m);return s && s->type==rc::StatusType::MemberJoin && s->nickname=="BravoClient";}),
                  "existing member receives member-join status");
            const rc::GameInfo game{"Synthetic title",0xFEDCBA9876543210ULL,"m2-v1.2.3"};
            check(a.transport.send(game), "setGameInfo queued");
            until([&] { const auto s=b.transport.snapshot(); return s.room && std::any_of(s.room->members.begin(),s.room->members.end(),[&](const auto& m){return m.nickname=="AlphaClient" && m.game==game;}); }, {&a,&b}, "game info");
            const auto list = room.room.GetRoomMemberList();
            check(std::any_of(list.begin(),list.end(),[&](const auto& m){return m.nickname=="AlphaClient" && m.game.id==game.id && m.game.version==game.version;}),
                  "original Room preserves high-bit u64 game ID and version");
            reject(port,join_request("AlphaClient"),rc::MessageId::NameCollision,{&a,&b});
            reject(port,join_request("IpCollision",fixed),rc::MessageId::IpCollision,{&a,&b});
            const auto error = wrong_version(port);
            check(error.id==rc::MessageId::VersionMismatch && error.server_version==1,"source-framed version2 rejected with server network_version1");
            window({&a,&b},50);
            join(c,join_request("CharlieClient"),{&a,&b,&c});
            until([&] { return a.transport.snapshot().room->members.size()==3 && b.transport.snapshot().room->members.size()==3; },{&a,&b,&c},"three members");
            reject(port,join_request("FullRoomCase"),rc::MessageId::RoomFull,{&a,&b,&c});
            routing(a,b,c,false,false,false); routing(a,b,c,false,true,false); routing(a,b,c,false,false,true);
            routing(a,b,c,true,false,false); routing(a,b,c,true,true,false); routing(a,b,c,true,false,true);
            // Concurrent API access is serialized without any transport worker.
            std::atomic_bool reader_ok{true};
            std::thread reader([&]{for(int i=0;i<200;++i){auto s=a.transport.snapshot();if(s.state!=rt::State::Joined)reader_ok=false;}});
            for(int i=0;i<50;++i) a.transport.poll(0);
            reader.join(); check(reader_ok,"concurrent snapshot and poll serialized; self-owned test thread joined");
            c.transport.leave(); check(c.transport.snapshot().state==rt::State::Leaving && !c.transport.snapshot().assigned_ip,"Leaving clears core identity immediately");
            until([&]{auto s=a.transport.snapshot();return c.transport.snapshot().state==rt::State::Idle && s.room && s.room->members.size()==2;},{&a,&b,&c},"member leave");
            check(std::any_of(a.messages.begin(),a.messages.end(),[](const auto& m){auto* s=std::get_if<rc::StatusMessage>(&m);return s&&s->type==rc::StatusType::MemberLeave&&s->nickname=="CharlieClient";}),"member-leave status and RoomInformation updated");
            const auto start = Clock::now(); room.close();
            check(Clock::now()-start < std::chrono::seconds(1),"original Room::Destroy joins its server thread bounded");
            until([&]{return a.transport.snapshot().state==rt::State::Failed && b.transport.snapshot().state==rt::State::Failed;},{&a,&b},"room close",2500);
            check(a.transport.snapshot().server_error==rc::MessageId::CloseRoom && b.transport.snapshot().server_error==rc::MessageId::CloseRoom,
                  "original close-room notification observed by both clients");
            check(!a.transport.snapshot().assigned_ip && !a.transport.snapshot().room && !a.transport.snapshot().host_live,"server close clears identity and destroys native host");
            a.transport.stop(); b.transport.stop(); c.transport.stop();
            check(rt::Transport::live_hosts()==0 && a.transport.snapshot().outstanding_packets==0 && b.transport.snapshot().outstanding_bytes==0,"all client hosts and outstanding packet budgets zero after close");
        }
        {
            RoomGuard room(port,1,"local-secret");
            reject(port,join_request("PasswordCase",rc::no_preferred_ip,"incorrect"),rc::MessageId::WrongPassword,{});
            // Regression: a rejected peer's slot must be released promptly, not after ENet's
            // multi-second timeout, so a fresh client can join the capacity-1 room at once.
            const auto release_start = Clock::now();
            Client good(options(port)); join(good,join_request("PasswordGood",rc::no_preferred_ip,"local-secret"),{&good});
            const auto release_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-release_start).count();
            check(release_ms <= 1000, "capacity-1 room frees rejected peer slot; fresh client joins within 1s (" + std::to_string(release_ms) + " ms)");
            good.transport.stop();
            check(good.transport.snapshot().state==rt::State::Idle,"correct password client graceful bounded stop");
        }
        {
            RoomGuard room(port, 3);
            Client a(options(port)), b(options(port));
            join(a, join_request("BoundaryAlpha"), {&a});
            join(b, join_request("BoundaryBravo"), {&a,&b});
            auto cap_options = options(port); cap_options.proxy_compressed_bytes = 16; cap_options.proxy_decompressed_bytes = 65536;
            Client cap(cap_options);
            join(cap, join_request("BoundaryCap"), {&a,&b,&cap});
            until([&]{ auto s=a.transport.snapshot(); return s.room && s.room->members.size()==3; }, {&a,&b,&cap}, "three boundary members");
            const auto self = *a.transport.snapshot().assigned_ip;
            const auto other = *b.transport.snapshot().assigned_ip;
            const auto cap_self = *cap.transport.snapshot().assigned_ip;
            const auto stable = [&]{ const auto s=a.transport.snapshot(); return s.state==rt::State::Joined && s.assigned_ip && *s.assigned_ip==self && s.room && s.room->members.size()==3; };
            const auto outbound = [&](const rc::Message& m){
                while (a.transport.pop()) {}
                const auto before = a.transport.snapshot().outstanding_packets;
                const bool threw = throws_invalid([&]{ (void)a.transport.send(m); });
                return threw && stable() && a.transport.snapshot().outstanding_packets == before;
            };
            const auto inject = [&](const rc::Message& m){ return a.transport.inject_inbound_for_test(rc::encode(m, rc::Direction::ServerToClient)); };
            const auto reject_in = [&](const rc::Message& m, const std::string& name){
                while (a.transport.pop()) {}
                const auto before = a.transport.snapshot();
                const bool accepted = inject(m);
                const auto after = a.transport.snapshot();
                check(!accepted && after.boundary_rejections == before.boundary_rejections + 1 &&
                      after.queued_packets == 0 && stable(), name);
            };
            const auto proxy = [&](rc::IPv4 local, rc::IPv4 remote, rc::Bytes data, bool broadcast = false){
                return rc::ProxyPacket{{rc::Domain::Inet,local,1},{rc::Domain::Inet,remote,2},rc::SocketProtocol::Udp,broadcast,std::move(data)};
            };
            const auto ldn = [&](rc::LdnType type, rc::IPv4 local, rc::IPv4 remote, rc::Bytes data, bool broadcast = false){
                return rc::LdnPacket{type,local,remote,broadcast,std::move(data)};
            };
            const auto good_frame = compressed();
            // Positive controls: a known member, not self, broadcast ignores target; unicast to self.
            check(inject(ldn(rc::LdnType::Scan,other,rc::IPv4{10,99,99,99},{},true)), "inbound member broadcast accepted; target field ignored");
            check(a.transport.snapshot().boundary_rejections==0 && a.transport.snapshot().queued_packets==1, "accepted broadcast not counted as a boundary rejection");
            (void)a.transport.pop();
            check(inject(ldn(rc::LdnType::Scan,other,self,{})), "inbound member unicast addressed to self accepted");
            (void)a.transport.pop();
            check(inject(proxy(other,self,good_frame)), "inbound member Proxy frame addressed to self accepted");
            (void)a.transport.pop();
            // Outbound fail-closed structural gate: throws before the M1 codec or any socket write.
            check(outbound(ldn(rc::LdnType::Scan,self,other,{0x00})), "outbound LDN Scan with a body rejected; identity/state unchanged");
            check(outbound(ldn(rc::LdnType::Connect,self,other,{})), "outbound LDN Connect empty body rejected (0x40 required)");
            check(outbound(ldn(static_cast<rc::LdnType>(0x7F),self,other,{})), "outbound unknown LDN type rejected before the codec");
            check(outbound(ldn(rc::LdnType::ScanResponse,self,other,rc::Bytes(0x47,0))), "outbound LDN ScanResponse wrong length rejected (0x480 required)");
            check(outbound(proxy(self,other,{0x00,0x01,0x02,0x03})), "outbound Proxy non-Zstd magic rejected");
            check(outbound(proxy(self,other,zstd_unknown_size(rc::Bytes(64,'A')))), "outbound Proxy UNKNOWN content size rejected");
            check(outbound(proxy(self,other,concat(good_frame,{0x00}))), "outbound Proxy trailing byte rejected");
            check(outbound(proxy(self,other,concat(good_frame,good_frame))), "outbound Proxy concatenated frames rejected");
            {
                const auto before = cap.transport.snapshot();
                const bool threw = throws_invalid([&]{ (void)cap.transport.send(proxy(other,cap_self,good_frame)); });
                check(threw && cap.transport.snapshot().state==rt::State::Joined && cap.transport.snapshot().boundary_rejections==before.boundary_rejections,
                      "outbound Proxy over the M2 compressed cap rejected though the M1 data ceiling would allow it");
            }
            // Inbound structural gate: drop + count, never mutate identity or state.
            reject_in(ldn(rc::LdnType::Scan,other,self,{0x00}), "inbound LDN Scan with a body rejected; identity/state unchanged");
            check(a.transport.snapshot().boundary_reason=="LDN body length", "recorded boundary reason for diagnosis");
            reject_in(ldn(rc::LdnType::Connect,other,self,{}), "inbound LDN Connect empty body rejected");
            reject_in(ldn(rc::LdnType::SyncNetwork,other,self,rc::Bytes(0x40,0)), "inbound LDN SyncNetwork wrong length rejected");
            reject_in(ldn(rc::LdnType::DestroyNetwork,other,self,{0x00}), "inbound LDN DestroyNetwork non-empty body rejected");
            reject_in(ldn(rc::LdnType::Scan,rc::IPv4{10,1,2,3},self,{}), "inbound LDN non-member source rejected");
            reject_in(ldn(rc::LdnType::Scan,self,other,{}), "inbound LDN self echo rejected");
            reject_in(ldn(rc::LdnType::Scan,other,rc::IPv4{10,1,2,3},{}), "inbound LDN unicast to non-self destination rejected");
            reject_in(proxy(other,self,{0x00,0x01,0x02,0x03}), "inbound Proxy non-Zstd magic rejected");
            reject_in(proxy(other,self,{0x28,0xB5,0x2F,0xFD,0xC0,0x00}), "inbound Proxy malformed frame rejected");
            reject_in(proxy(other,self,zstd_unknown_size(rc::Bytes(64,'A'))), "inbound Proxy UNKNOWN content size rejected");
            reject_in(proxy(other,self,concat(good_frame,{0x00})), "inbound Proxy trailing byte rejected");
            reject_in(proxy(other,self,concat(good_frame,good_frame)), "inbound Proxy concatenated frames rejected");
            reject_in(proxy(other,self,zstd_frame(rc::Bytes(70000,0))), "inbound Proxy over decompressed cap rejected");
            reject_in(proxy(rc::IPv4{10,1,2,3},self,good_frame), "inbound Proxy non-member source rejected");
            reject_in(proxy(other,rc::IPv4{10,1,2,3},good_frame), "inbound Proxy unicast to non-self destination rejected");
            check(a.transport.snapshot().boundary_rejections==15, "all fifteen inbound boundary rejections counted without state change");
            {
                const auto before = cap.transport.snapshot();
                const bool accepted = cap.transport.inject_inbound_for_test(rc::encode(proxy(other,cap_self,good_frame), rc::Direction::ServerToClient));
                const auto after = cap.transport.snapshot();
                check(!accepted && after.boundary_rejections==before.boundary_rejections+1 && after.state==rt::State::Joined,
                      "inbound Proxy over the M2 compressed cap rejected though the M1 data ceiling would allow it");
            }
            a.transport.stop(); b.transport.stop(); cap.transport.stop();
            check(rt::Transport::live_hosts()==0, "boundary room clients release all hosts on bounded stop");
            a.clear(); join(a, join_request("BoundaryAgain"), {&a});
            a.transport.stop();
            check(a.transport.snapshot().state==rt::State::Idle && rt::Transport::live_hosts()==0, "identity reset after stop permits a clean rejoin cycle");
        }
        {
            auto o=options(port); o.connect_timeout_ms=100;
            Client absent(o); absent.transport.start(join_request("AbsentRoom"));
            until([&]{return absent.transport.snapshot().state==rt::State::Failed;},{&absent},"connect timeout",750);
            check(absent.transport.snapshot().failure=="connect timeout" && !absent.transport.snapshot().host_live,"unbound loopback connect timeout frees host");
            absent.transport.stop(); absent.transport.stop(); check(rt::Transport::live_hosts()==0,"repeated stop is idempotent");
        }
        {
            RoomGuard room(port,1);
            auto o=options(port); o.session.join_timeout_ms=1;
            Client deadline(o); deadline.transport.start(join_request("JoinDeadline"));
            until([&]{return deadline.transport.snapshot().state==rt::State::Joining || deadline.transport.snapshot().state==rt::State::Failed;},{&deadline},"enter Joining");
            // Deliberate bounded delay services no client, so M1 join deadline expires.
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); deadline.tick();
            check(deadline.transport.snapshot().state==rt::State::Failed && !deadline.transport.snapshot().host_live,"join deadline enforced and native resources released");
            deadline.transport.stop();
        }
        {
            RoomGuard room(port,1);
            auto o=options(port); o.outgoing_packets=1;
            Client bounded(o); join(bounded,join_request("BudgetClient"),{&bounded}); window({&bounded},30);
            check(bounded.transport.send(rc::GameInfo{"one",1,""}) && !bounded.transport.send(rc::GameInfo{"two",2,""}),"outgoing cap includes ENet unacknowledged packets, applies backpressure");
            bounded.transport.stop(); check(bounded.transport.snapshot().outstanding_packets==0,"stop releases unacknowledged outbound packet callback tickets");
        }
        {
            RoomGuard room(port,1);
            auto o=options(port); o.queue_packets=1;
            Client overflow(o); overflow.transport.start(join_request("InboundLimit"));
            until([&]{return overflow.transport.snapshot().state==rt::State::Failed;},{&overflow},"inbound queue cap",2500,false);
            check(overflow.transport.snapshot().failure=="inbound queue limit" && !overflow.transport.snapshot().host_live,"unconsumed inbound queue over cap fails closed");
            overflow.transport.stop();
        }
        {
            bool remote=false, wait=false;
            try { auto o=options(port);o.address="192.0.2.1";rt::Transport t(o); } catch(const std::invalid_argument&){remote=true;}
            rt::Transport idle(options(port)); try{idle.poll(6);}catch(const std::invalid_argument&){wait=true;}
            check(remote&&wait,"remote endpoints and unbounded poll waits refused locally");
            for(int i=0;i<5;++i){RoomGuard room(port,1);Client c(options(port));join(c,join_request("RepeatClient"),{&c});c.transport.stop();}
            check(rt::Transport::live_hosts()==0,"five repeated create-join-stop-destroy cycles leave zero hosts");
        }
        check(threads()==baseline_threads,"OS thread count returns to pre-Room baseline; no background workers");
        check(rt::Transport::live_hosts()==0,"final transport host count zero");
        std::cout << "RESULT cases=" << cases << " failed=0 exit=0 ENet=" << ENET_VERSION_MAJOR << '.' << ENET_VERSION_MINOR << '.' << ENET_VERSION_PATCH << " Zstd=" << ZSTD_versionString() << std::endl;
        return 0;
    } catch(const std::exception& e) {
        std::cerr << "FAIL after=" << cases << " " << e.what() << std::endl;
        std::cerr << "RESULT failed=1 exit=1 live_hosts=" << rt::Transport::live_hosts() << std::endl; return 1;
    }
}
