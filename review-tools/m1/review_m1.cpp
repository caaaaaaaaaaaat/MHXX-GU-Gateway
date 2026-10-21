// SPDX-License-Identifier: GPL-2.0-or-later
// Independent reviewer probe. Compiles the original Yuzu Packet unit read-only;
// it does not instantiate ENet, Room, an emulator, GUI, socket, or game.
#include "room_client/session.hpp"
#include "network/packet.h"
#include <cstdlib>
#include <functional>
#include <iostream>
#include <limits>
#include <new>
#include <string>
#include <type_traits>
using namespace room_client;
namespace allocation_probe { bool enabled = false; std::size_t largest = 0; }
void* operator new(std::size_t n) {
    if (allocation_probe::enabled && n > allocation_probe::largest) allocation_probe::largest = n;
    if (auto* p = std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
namespace {
std::size_t checks = 0;
void check(bool b, const char* label) { ++checks; if (!b) throw std::runtime_error(label); }
template<class F> void reject(F fn, ErrorCode code, const char* label) {
    bool caught = false;
    try { fn(); } catch (const ProtocolError& e) { caught = true; check(e.code() == code, label); }
    check(caught, label);
}
Bytes bytes(const Network::Packet& p) {
    const auto* b = static_cast<const std::uint8_t*>(p.GetData());
    return {b, b + p.GetDataSize()};
}
void original_game(Network::Packet& p, const GameInfo& g) { p.Write(g.name); p.Write(g.id); p.Write(g.version); }
void original_endpoint(Network::Packet& p, const Endpoint& e) {
    p.Write(static_cast<u8>(e.family)); p.Write(e.ip); p.Write(e.port);
}
Bytes original_wire(const Message& m) {
    Network::Packet p; p.Write(static_cast<u8>(message_id(m)));
    std::visit([&](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, JoinRequest>) {
            p.Write(v.nickname); p.Write(v.preferred_ip); p.Write(v.version); p.Write(v.password); p.Write(v.token);
        } else if constexpr (std::is_same_v<T, JoinSuccess>) p.Write(v.assigned_ip);
        else if constexpr (std::is_same_v<T, RoomInformation>) {
            p.Write(v.name); p.Write(v.description); p.Write(v.member_slots); p.Write(v.port);
            p.Write(v.preferred_game_name); p.Write(v.host_username); p.Write(static_cast<u32>(v.members.size()));
            for (const auto& member : v.members) {
                p.Write(member.nickname); p.Write(member.fake_ip); original_game(p, member.game);
                p.Write(member.username); p.Write(member.display_name); p.Write(member.avatar_url);
            }
        } else if constexpr (std::is_same_v<T, GameInfo>) original_game(p, v);
        else if constexpr (std::is_same_v<T, ProxyPacket>) {
            original_endpoint(p, v.local); original_endpoint(p, v.remote);
            p.Write(static_cast<u8>(v.protocol)); p.Write(v.broadcast); p.Write(v.data);
        } else if constexpr (std::is_same_v<T, LdnPacket>) {
            p.Write(static_cast<u8>(v.type)); p.Write(v.local_ip); p.Write(v.remote_ip); p.Write(v.broadcast); p.Write(v.data);
        } else if constexpr (std::is_same_v<T, ChatRequest>) p.Write(v.message);
        else if constexpr (std::is_same_v<T, ChatMessage>) { p.Write(v.nickname); p.Write(v.username); p.Write(v.message); }
        else if constexpr (std::is_same_v<T, StatusMessage>) { p.Write(static_cast<u8>(v.type)); p.Write(v.nickname); p.Write(v.username); }
        else if (v.id == MessageId::VersionMismatch) p.Write(v.server_version);
    }, m);
    return bytes(p);
}
void differential(const Message& m, Direction d) {
    const auto expected = original_wire(m);
    check(encode(m,d) == expected, "M1 bytes differ from original Packet writer");
    check(decode(expected,d) == m, "M1 reader differs from original-writer values");
}
RoomInformation room() {
    return {"Review", "", 4, 24872, "GU", "", {{"Test", {192,168,1,2}, {"GU",0x0102030405060708ULL,"1"}, "", "", ""}}};
}
void join(Session& s, std::uint64_t t = 0) {
    (void)s.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""}, t);
    (void)s.receive(original_wire(room()), t+1);
    (void)s.receive(original_wire(JoinSuccess{{192,168,1,2},false}), t+2);
}
void allocation_reject(Bytes b, ErrorCode error) {
    allocation_probe::largest = 0; allocation_probe::enabled = true;
    try { reject([&]{ (void)decode(b,Direction::ServerToClient); },error,"bounded rejection"); }
    catch (...) { allocation_probe::enabled = false; throw; }
    allocation_probe::enabled = false;
    check(allocation_probe::largest < 4096,"declared size allocated before validation");
}
void run() {
    const auto c=Direction::ClientToServer, s=Direction::ServerToClient;
    for (unsigned i=0;i<96;++i) {
        auto ip=IPv4{static_cast<u8>(i),128,254,255};
        std::string raw("x\0",2); raw += static_cast<char>(0xc3); raw += static_cast<char>(0xa9);
        differential(JoinRequest{std::string(i%21,'N'),ip,i,raw,std::string(i%11,'t')},c);
        differential(GameInfo{raw,0xFEDCBA9876543210ULL+i,std::string(i%13,'v')},c);
        ProxyPacket p{{static_cast<Domain>(i%2),ip,static_cast<u16>(i*257)},
                      {Domain::Inet,{192,168,1,2},static_cast<u16>(65535-i)},
                      static_cast<SocketProtocol>(i%4),(i%2)==1,Bytes(i%23,static_cast<u8>(i))};
        differential(p,c); differential(p,s);
        const auto type=static_cast<LdnType>(i%6);
        const auto len=(i%6==1||i%6==3)?1152U:(i%6==2||i%6==4)?64U:0U;
        LdnPacket l{type,ip,{192,168,1,2},(i%2)==1,Bytes(len,static_cast<u8>(i))};
        differential(l,c); differential(l,s);
    }
    differential(room(),s);
    differential(JoinSuccess{{192,168,1,2},false},s);
    differential(JoinSuccess{{192,168,1,2},true},s);
    differential(ChatRequest{std::string("A\0B",3)},c);
    differential(ChatMessage{"Test","",std::string("A\0B",3)},s);
    for (unsigned t=1;t<=5;++t) differential(StatusMessage{static_cast<StatusType>(t),"Test",""},s);
    for (auto id:{8,9,10,11,12,13,15,16,22,23}) differential(ServerError{static_cast<MessageId>(id),id==10?7U:0U},s);
    // Declared vector/string/count limits and short payloads: observe no large allocation.
    allocation_reject(Bytes{6,2,0,0,0,0,0,0,0,0,0,255,255,255,255},ErrorCode::LimitExceeded);
    allocation_reject(Bytes{6,2,0,0,0,0,0,0,0,0,0,0,0,234,96},ErrorCode::Truncated);
    allocation_reject(Bytes{3,255,255,255,255},ErrorCode::LimitExceeded);
    allocation_reject(Bytes{3,0,0,16,0},ErrorCode::Truncated);
    auto table=original_wire(room());
    // Find the last count prefix before the known first nickname string.
    std::size_t count=1+4+6+4+4+2+4+2+4;
    for (std::size_t i=0;i<4;++i) table[count+i]=255;
    allocation_reject(table,ErrorCode::LimitExceeded);
    for (auto bad:{0,25,255}) reject([&]{(void)decode(Bytes{static_cast<u8>(bad)},s);},ErrorCode::UnknownMessage,"unknown ID");
    for (auto bad:{17,18,19,20,21}) reject([&]{(void)decode(Bytes{static_cast<u8>(bad)},s);},ErrorCode::UnsupportedMessage,"unsupported ID");
    reject([&]{(void)decode(original_wire(JoinSuccess{{192,168,1,2},false}),c);},ErrorCode::WrongDirection,"direction");
    // Canonical bool equals original output; permissive source parser accepts 2,
    // while M1 deliberately rejects it (strict profile, not fully permissive).
    Network::Packet b; b.Write(static_cast<u8>(2)); bool permissive=false; b.Read(permissive);
    check(permissive,"original noncanonical bool semantics");
    auto noncanonical=original_wire(LdnPacket{LdnType::Scan,{1,2,3,4},{},false,{}}); noncanonical[10]=2;
    reject([&]{(void)decode(noncanonical,s);},ErrorCode::InvalidBoolean,"strict bool");
    Session state; join(state);
    const auto retained=state.room(); const auto identity=state.assigned_ip();
    reject([&]{(void)state.receive(noncanonical,3);},ErrorCode::InvalidBoolean,"joined bad bool");
    check(state.state()==SessionState::Joined&&state.room()==retained&&state.assigned_ip()==identity,"bad receive cache/identity");
    reject([&]{(void)state.receive(original_wire(GameInfo{"",0,""}),4);},ErrorCode::WrongDirection,"joined wrong direction");
    check(state.room()==retained&&state.assigned_ip()==identity,"wrong direction cache/identity");
    reject([&]{(void)state.send(LdnPacket{LdnType::Scan,{1,2,3,4},{},true,{}},4);},ErrorCode::InvalidState,"spoof sender");
    (void)state.send(LdnPacket{LdnType::Scan,*identity,{},true,{}},4);
    reject([&]{(void)state.receive(original_wire(room()),3);},ErrorCode::InvalidArgument,"backward receive clock");
    check(state.room()==retained&&state.assigned_ip()==identity,"backward clock cache/identity");
    // Boundary using UINT64_MAX, no start+timeout overflow and reject clock reversal.
    Session high; const auto max=std::numeric_limits<std::uint64_t>::max();
    (void)high.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},max-5);
    check(!high.advance(max),"remaining representable time is below timeout");
    reject([&]{(void)high.advance(0);},ErrorCode::InvalidArgument,"clock wrap rejected");
    Session timed; (void)timed.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},max-5000);
    check(timed.advance(max)&&timed.state()==SessionState::Failed&&timed.timed_out(),"exact maximum deadline");
    for (auto id:{8,9,10,11,12,13,15,16}) {
        Session rejected; (void)rejected.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},0);
        (void)rejected.receive(original_wire(room()),1);
        (void)rejected.receive(original_wire(ServerError{static_cast<MessageId>(id),id==10?7U:0U}),2);
        check(rejected.state()==SessionState::Failed&&!rejected.room()&&!rejected.assigned_ip()&&rejected.last_server_error()==static_cast<MessageId>(id),"rejection reason+cleanup");
    }
    for (auto id:{12,15,16}) {
        Session closed; join(closed); (void)closed.receive(Bytes{static_cast<u8>(id)},3);
        check(closed.state()==SessionState::Failed&&!closed.room()&&!closed.assigned_ip()&&closed.last_server_error()==static_cast<MessageId>(id),"joined close cleanup");
        closed.disconnected(4);
        check(!closed.last_server_error()&&closed.state()==SessionState::Idle,"OBS disconnect erases terminal reason");
    }
    Session leaving; join(leaving); leaving.begin_leave(3);
    check(leaving.state()==SessionState::Leaving&&!leaving.room()&&!leaving.assigned_ip(),"leave cleanup");
    reject([&]{(void)leaving.receive(Bytes{12},4);},ErrorCode::InvalidState,"OBS receive during Leaving rejected");
    leaving.disconnected(5); check(leaving.state()==SessionState::Idle,"leave disconnected");
    Session metadata; (void)metadata.begin_join(JoinRequest{"Test",no_preferred_ip,1,"",""},0);
    reject([&]{(void)metadata.send(GameInfo{"GU",0,""},1);},ErrorCode::InvalidState,"OBS stock immediate SetGameInfo sequence unavailable");
    // These observations intentionally PASS when the current opaque-envelope scope
    // is confirmed; they are NOT interoperability/safety acceptance tests.
    Session opaque; join(opaque);
    const auto short_ldn=opaque.send(LdnPacket{LdnType::Connect,*opaque.assigned_ip(),{},false,{1,2,3}},3);
    check(short_ldn.size()==18,"OBS Session allows short LDN Connect inner data");
    const auto raw_proxy=opaque.send(ProxyPacket{{Domain::Inet,*opaque.assigned_ip(),1},{Domain::Inet,{1,2,3,4},2},SocketProtocol::Udp,false,{1,2,3}},3);
    check(raw_proxy.size()==24,"OBS Session allows raw/non-Zstd Proxy inner data");
    auto incoming=original_wire(LdnPacket{LdnType::ScanResponse,{9,9,9,9},{8,8,8,8},false,{}});
    (void)opaque.receive(incoming,4);
    check(opaque.state()==SessionState::Joined,"OBS no inbound membership/destination validation");
    std::cout<<"OBS: noncanonical bool rejected; terminal reason erased by disconnect; Leaving receive rejected; Joining SetGameInfo rejected; LDN/Proxy inner safety and inbound endpoint checks deferred.\n";
}
}
int main() {
    try { run(); std::cout<<"PASS "<<checks<<" independent checks (including explicitly labelled gap observations)\n"; return 0; }
    catch(const std::exception& e) { std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<'\n'; return 1; }
}
