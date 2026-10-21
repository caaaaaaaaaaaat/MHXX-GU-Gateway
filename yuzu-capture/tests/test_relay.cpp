// SPDX-License-Identifier: GPL-3.0-or-later
#include "yuzu_capture/relay.hpp"
#include "yuzu_room/protocol.hpp"
#include "network/room.h"
#include "network/verify_user.h"
#include <enet/enet.h>
#include <zstd.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif

namespace {
using Bytes=yuzu_room::Bytes;
using Clock=std::chrono::steady_clock;
unsigned checks=0;
void check(bool ok,const char* label) {
    ++checks;
    if (!ok) throw std::runtime_error(label);
    std::cout<<"PASS "<<checks<<" "<<label<<'\n';
}
struct Client {
    ENetHost* host=nullptr;
    ENetPeer* peer=nullptr;
    bool connected=false,disconnected=false;
    std::vector<Bytes> received;
    explicit Client(std::uint16_t port) {
        ENetAddress local{}; enet_address_set_host_ip(&local,"127.0.0.1");
        host=enet_host_create(&local,1,1,0,0);
        if (!host) throw std::runtime_error("client host create");
        ENetAddress address=local; address.port=port;
        peer=enet_host_connect(host,&address,1,0);
        if (!peer) { enet_host_destroy(host); throw std::runtime_error("client connect"); }
    }
    ~Client() { if (peer) enet_peer_disconnect_now(peer,0); if (host) enet_host_destroy(host); }
    void tick() {
        ENetEvent event{};
        for (unsigned i=0;i<32 && enet_host_service(host,&event,0)>0;++i) {
            if (event.type==ENET_EVENT_TYPE_CONNECT) connected=true;
            else if (event.type==ENET_EVENT_TYPE_DISCONNECT) disconnected=true;
            else if (event.type==ENET_EVENT_TYPE_RECEIVE) {
                received.emplace_back(event.packet->data,event.packet->data+event.packet->dataLength);
                enet_packet_destroy(event.packet);
            }
        }
        enet_host_flush(host);
    }
    void send(const Bytes& data) {
        auto* packet=enet_packet_create(data.data(),data.size(),ENET_PACKET_FLAG_RELIABLE);
        if (!packet || enet_peer_send(peer,0,packet)<0) { if(packet) enet_packet_destroy(packet); throw std::runtime_error("client send"); }
        enet_host_flush(host);
    }
    std::optional<yuzu_room::JoinSuccess> joined() const {
        for (const auto& bytes:received) if (!bytes.empty() && (bytes[0]==2||bytes[0]==24))
            return std::get<yuzu_room::JoinSuccess>(yuzu_room::decode(bytes,yuzu_room::Direction::ServerToClient));
        return {};
    }
    bool contains(const Bytes& data) const { return std::find(received.begin(),received.end(),data)!=received.end(); }
};
void pump(yuzu_capture::Relay& relay,const std::vector<Client*>& clients,const std::function<bool()>& done,unsigned ms=3000) {
    const auto deadline=Clock::now()+std::chrono::milliseconds(ms);
    do {
        relay.tick(); for (auto* client:clients) client->tick();
        if (done()) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (Clock::now()<deadline);
    if (!done()) throw std::runtime_error("bounded wait expired");
}
Bytes join(const std::string& nick,std::uint32_t version=1,std::string password="pw",std::string token="") {
    return yuzu_room::encode(yuzu_room::JoinRequest{nick,yuzu_room::no_preferred_ip,version,std::move(password),std::move(token)},yuzu_room::Direction::ClientToServer);
}
std::uint16_t free_port() {
    ENetAddress address{}; enet_address_set_host_ip(&address,"127.0.0.1");
    auto* host=enet_host_create(&address,1,1,0,0);
    if (!host) throw std::runtime_error("free port");
    const auto port=host->address.port; enet_host_destroy(host); return port;
}
struct Room {
    Network::Room room;
    std::uint16_t port=free_port();
    Room() {
        if (!room.Create("capture-test","synthetic only","127.0.0.1",port,"pw",4,"",
            Network::GameInfo{"Capture",0,""},std::make_unique<Network::VerifyUser::NullBackend>(),{},false))
            throw std::runtime_error("original room create");
    }
    ~Room() { room.Destroy(); }
};

void run(const std::filesystem::path& evidence,std::uint16_t external_port=0) {
    std::unique_ptr<Room> local_room;
    if(!external_port) local_room=std::make_unique<Room>();
    const auto room_port=external_port?external_port:local_room->port;
    yuzu_capture::Options options;
    options.listen_port=0; options.room_port=room_port;
    options.trace_path=(evidence/"relay.jsonl").string(); options.trace_raw=true;
    options.identity={"synthetic-capture","capture-test","B","yuzu","synthetic","observer","join"};
    options.stage_file=(evidence/"stage.txt").string();
    { std::ofstream stage(options.stage_file); stage<<"initial\n"; }
    yuzu_capture::Relay relay(options); relay.open();
    check(relay.port()!=0,"relay binds an assigned loopback port");
    // The very first Join may arrive while the upstream ENet handshake is pending.
    Client a(relay.port()),b(relay.port());
    pump(relay,{&a,&b},[&]{return a.connected&&b.connected;});
    a.send(join("capture-alpha")); b.send(join("capture-beta"));
    pump(relay,{&a,&b},[&]{return a.joined().has_value()&&b.joined().has_value();});
    const auto aip=a.joined()->assigned_fake_ip,bip=b.joined()->assigned_fake_ip;
    check(aip!=bip,"two downstream clients retain independent assigned IPs");
    check(relay.stats().active==2,"two independent upstream sessions exist");
    check(a.contains(yuzu_room::encode(*a.joined(),yuzu_room::Direction::ServerToClient)),"JoinSuccess wire bytes reach the source client");
    bool members=false;
    pump(relay,{&a,&b},[&]{
        for(const auto& bytes:a.received) if(bytes[0]==3) {
            const auto info=std::get<yuzu_room::RoomInformation>(yuzu_room::decode(bytes,yuzu_room::Direction::ServerToClient));
            if(info.members.size()==2) members=true;
        }
        return members;
    });
    check(members,"original room advertises both distinct members");

    a.send(yuzu_room::encode(yuzu_room::GameInfo{"synthetic-one",111,"1"},yuzu_room::Direction::ClientToServer));
    b.send(yuzu_room::encode(yuzu_room::GameInfo{"synthetic-two",222,"2"},yuzu_room::Direction::ClientToServer));
    bool different_games=false;
    pump(relay,{&a,&b},[&]{
        for(const auto& bytes:a.received) if(!bytes.empty()&&bytes[0]==3) {
            const auto info=std::get<yuzu_room::RoomInformation>(yuzu_room::decode(bytes,yuzu_room::Direction::ServerToClient));
            bool first=false,second=false;
            for(const auto& member:info.members){first|=member.game_id==111;second|=member.game_id==222;}
            if(first&&second) different_games=true;
        }
        return different_games;
    });
    check(different_games,"different game IDs coexist despite the preferred room game");

    yuzu_room::LdnPacket scan;
    scan.local_ip=aip; scan.broadcast=true;
    const auto scan_bytes=yuzu_room::encode(scan,yuzu_room::Direction::ClientToServer);
    a.send(scan_bytes); pump(relay,{&a,&b},[&]{return b.contains(scan_bytes);});
    check(!a.contains(scan_bytes),"LDN broadcast excludes its sender");
    check(b.contains(scan_bytes),"LDN Scan is forwarded byte for byte");
    check(different_games&&b.contains(scan_bytes),"room LDN routing does not filter by advertised game ID");
    scan.type=yuzu_room::LdnPacketType::Connect; scan.data=Bytes(64,0x3c); scan.remote_ip=bip; scan.broadcast=false;
    const auto connect_bytes=yuzu_room::encode(scan,yuzu_room::Direction::ClientToServer);
    a.send(connect_bytes); pump(relay,{&a,&b},[&]{return b.contains(connect_bytes);});
    check(b.contains(connect_bytes),"LDN unicast preserves exact body and endpoints");
    // Independently hand-laid NetworkInfo offsets from the upstream ABI, not
    // the production encoder. No username, SSID or advertise bytes are logged.
    scan.type=yuzu_room::LdnPacketType::ScanResp; scan.data=Bytes(0x480);
    const std::uint8_t comm_id[]={0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
    std::copy(std::begin(comm_id),std::end(comm_id),scan.data.begin());
    scan.data[0x0a]=2; scan.data[0x10]=0xfe; scan.data[0x17]=0x80;
    scan.data[0x20]=2; scan.data[0x25]=0x99; scan.data[0x26]=1; scan.data[0x27]='S';
    scan.data[0x48]=11; scan.data[0x4b]=2; scan.data[0x66]=8; scan.data[0x67]=2;
    scan.data[0x68]=1; scan.data[0x69]=2; scan.data[0x6a]=3; scan.data[0x6b]=4;
    scan.data[0x6c]=2; scan.data[0x71]=0x55; scan.data[0x73]=1;
    scan.data[0x228]=9; scan.data[0x22b]=7; // node 7 beyond node_count=2
    scan.data[0x232]=7; scan.data[0x233]=1;
    const std::string private_name="synthetic-private-name";
    std::copy(private_name.begin(),private_name.end(),scan.data.begin()+0x74);
    scan.data[0x26a]=3; scan.data[0x26c]=0xaa; scan.data[0x26d]=0xbb; scan.data[0x26e]=0xcc;
    const auto network_bytes=yuzu_room::encode(scan,yuzu_room::Direction::ClientToServer);
    a.send(network_bytes); pump(relay,{&a,&b},[&]{return b.contains(network_bytes);});
    check(b.contains(network_bytes),"NetworkInfo observation preserves every original body byte");
    scan.type=yuzu_room::LdnPacketType::Connect;
    scan.data=Bytes(scan.data.begin()+0x68,scan.data.begin()+0xa8);
    const auto node_bytes=yuzu_room::encode(scan,yuzu_room::Direction::ClientToServer);
    a.send(node_bytes);pump(relay,{&a,&b},[&]{return b.contains(node_bytes);});
    check(b.contains(node_bytes),"NodeInfo observation preserves every original body byte");
    scan.data=Bytes(1200,0x71);
    const auto large_ldn=yuzu_room::encode(scan,yuzu_room::Direction::ClientToServer);
    a.send(large_ldn); pump(relay,{&a,&b},[&]{return relay.stats().rejected==1;});
    check(!b.contains(large_ldn),"nonstandard LDN size is recorded but blocked before reaching the room");

    Bytes plain(4096); for(std::size_t i=0;i<plain.size();++i) plain[i]=static_cast<std::uint8_t>(i);
    Bytes compressed(ZSTD_compressBound(plain.size()));
    const auto count=ZSTD_compress(compressed.data(),compressed.size(),plain.data(),plain.size(),1);
    if(ZSTD_isError(count)) throw std::runtime_error("test compression");
    compressed.resize(count);
    yuzu_room::ProxyPacket proxy;
    proxy.local_endpoint={1,aip,19001}; proxy.remote_endpoint={1,bip,19002}; proxy.protocol=3; proxy.data=compressed;
    const auto proxy_bytes=yuzu_room::encode(proxy,yuzu_room::Direction::ClientToServer);
    a.send(proxy_bytes); pump(relay,{&a,&b},[&]{return b.contains(proxy_bytes);});
    check(b.contains(proxy_bytes),"Proxy family/protocol opaque values and compressed bytes survive");
    proxy.local_endpoint={0,bip,29001};proxy.remote_endpoint={0,aip,29002};proxy.protocol=2;
    const auto reverse_bytes=yuzu_room::encode(proxy,yuzu_room::Direction::ClientToServer);
    b.send(reverse_bytes); pump(relay,{&a,&b},[&]{return a.contains(reverse_bytes);});
    check(a.contains(reverse_bytes),"reverse Proxy unicast preserves endpoints");
    proxy.data={0x00};
    const auto invalid_zstd=yuzu_room::encode(proxy,yuzu_room::Direction::ClientToServer);
    b.send(invalid_zstd); pump(relay,{&a,&b},[&]{return relay.stats().rejected==2;});
    check(!a.contains(invalid_zstd),"invalid compressed frame is blocked without rewriting");
    proxy.data=compressed; proxy.data.insert(proxy.data.end(),compressed.begin(),compressed.end());
    const auto concatenated=yuzu_room::encode(proxy,yuzu_room::Direction::ClientToServer);
    b.send(concatenated); pump(relay,{&a,&b},[&]{return relay.stats().rejected==3;});
    check(!a.contains(concatenated),"concatenated compressed frames are blocked");
    Bytes oversized_plain(65536,0x5a);
    proxy.data.resize(ZSTD_compressBound(oversized_plain.size()));
    const auto oversized_n=ZSTD_compress(proxy.data.data(),proxy.data.size(),oversized_plain.data(),oversized_plain.size(),1);
    if(ZSTD_isError(oversized_n)) throw std::runtime_error("oversize test compression");
    proxy.data.resize(oversized_n);
    const auto oversized=yuzu_room::encode(proxy,yuzu_room::Direction::ClientToServer);
    b.send(oversized); pump(relay,{&a,&b},[&]{return relay.stats().rejected==4;});
    check(!a.contains(oversized),"oversize declared decompression is blocked without allocating its output");
    a.send(yuzu_room::encode(yuzu_room::ChatRequest{"synthetic hello"},yuzu_room::Direction::ClientToServer));
    bool chat=false;
    pump(relay,{&a,&b},[&]{for(const auto& bytes:b.received) if(bytes[0]==7) chat=true; return chat;});
    check(chat,"original room chat response passes through");

    // Original Room only sends VersionMismatch; it does not disconnect the
    // peer. The observer must preserve the ability to retry on that connection.
    Client wrong(relay.port()); pump(relay,{&a,&b,&wrong},[&]{return wrong.connected;});
    wrong.send(join("capture-wrong",2));
    pump(relay,{&a,&b,&wrong},[&]{return std::any_of(wrong.received.begin(),wrong.received.end(),[](const Bytes& v){return v[0]==10;});});
    const auto version_error=yuzu_room::encode(yuzu_room::ServerError{yuzu_room::MessageId::VersionMismatch,1},yuzu_room::Direction::ServerToClient);
    check(wrong.contains(version_error),"version error is delivered intact");
    check(!wrong.disconnected,"version error does not invent an upstream disconnect");
    wrong.send(join("capture-correct",1,"pw","synthetic-invalid-token"));
    pump(relay,{&a,&b,&wrong},[&]{return wrong.joined().has_value();});
    check(wrong.joined().has_value(),"a version-rejected peer can retry on its existing connection");
    check(wrong.joined().has_value(),"local no-web dedicated room accepts an opaque synthetic token");
    enet_peer_disconnect(wrong.peer,0);
    pump(relay,{&a,&b,&wrong},[&]{return relay.stats().active==2;});
    check(relay.stats().active==2,"downstream departure releases its upstream session");

    { std::ofstream stage(options.stage_file); stage<<"hall\r\n"; }
    const auto stage_deadline=Clock::now()+std::chrono::milliseconds(150);
    pump(relay,{&a,&b},[&]{return Clock::now()>=stage_deadline;},500);
    relay.close();
    check(relay.stats().active==0,"close releases all connection sessions");
    check(!relay.failed(),"capture recorder remains healthy");
    check(relay.stats().decode_failures>=2,"invalid LDN sizes are explicitly counted undecoded");
    std::ifstream trace(options.trace_path);
    const std::string content((std::istreambuf_iterator<char>(trace)),{});
    check(content.find("\"local_port\":19001")!=std::string::npos,"trace captures original sender port");
    check(content.find("\"remote_port\":19002")!=std::string::npos,"trace captures original receiver port");
    check(content.find("\"zstd_verified\":true")!=std::string::npos,"trace verifies bounded Zstd frame");
    check(content.find("\"zstd_verified\":false")!=std::string::npos,"trace rejects invalid concatenated and oversized Zstd metadata");
    check(content.find("\"ldn_size_verified\":false")!=std::string::npos,"trace labels invalid exact LDN body size");
    check(content.find("\"stage\":\"hall\"")!=std::string::npos,"stage file changes create trace markers");
    check(content.find("\"channel\":\"B\"")!=std::string::npos,"trace channel B remains a stable identity");
    check(content.find("\"local_communication_id_hex\":\"0x1122334455667788\"")!=std::string::npos,"LDN communication ID is retained as exact 64-bit hex");
    check(content.find("\"session_id_high_hex\":\"0x80000000000000fe\"")!=std::string::npos,"LDN session ID retains bits above the JSON integer precision limit");
    check(content.find("\"node_0_ipv4_raw\":\"1.2.3.4\"")!=std::string::npos && content.find("\"node_count\":2")!=std::string::npos,"LDN node identity and count are captured without guessing IPv4 byte order");
    check(content.find("\"node_slots\":8")!=std::string::npos && content.find("\"node_7_ipv4_raw\":\"9.0.0.7\"")!=std::string::npos && content.find("\"node_7_connected\":true")!=std::string::npos,"sparse node 7 is captured even when only two nodes are connected");
    check(content.find(private_name)==std::string::npos,"LDN username is excluded from structured metadata");
    check(content.find("\"node_ipv4_raw\":\"1.2.3.4\"")!=std::string::npos,"standalone LDN NodeInfo identity is recorded");

    // No trace: default capture must not write payloads or require a file.
    options.trace_path.clear(); options.trace_raw=false; options.stage_file.clear();
    options.room_port=free_port(); options.connect_timeout_ms=80; options.drain_timeout_ms=80;
    yuzu_capture::Relay timeout(options); timeout.open();
    Client lonely(timeout.port()); pump(timeout,{&lonely},[&]{return lonely.connected;});
    lonely.send(join("lonely"));
    pump(timeout,{&lonely},[&]{return timeout.stats().timeouts==1;});
    check(timeout.stats().timeouts==1,"unavailable upstream is bounded by deadline");
    timeout.close();

    options.trace_raw=true;
    bool refused=false;
    try { yuzu_capture::Relay raw(options);raw.open(); } catch(...) {refused=true;}
    check(refused,"raw requires an explicit trace path before bind");
    options.trace_raw=false; options.trace_path=(evidence/"missing"/"trace.jsonl").string();
    refused=false;
    try { yuzu_capture::Relay bad(options);bad.open(); } catch(...) {refused=true;}
    check(refused,"unwritable trace fails before listener bind");

    options.trace_path.clear(); options.room_port=room_port;
    options.connect_timeout_ms=2000; options.join_timeout_ms=80;
    yuzu_capture::Relay idle(options); idle.open();
    Client nojoin(idle.port());
    pump(idle,{&nojoin},[&]{return idle.stats().timeouts==1;});
    check(idle.stats().timeouts==1,"connected but unjoined session has a separate deadline");
    idle.close();

    options.room_port=free_port(); options.join_timeout_ms=15000;
    options.queue_packets=1; options.connect_timeout_ms=3000;
    yuzu_capture::Relay bounded(options); bounded.open();
    Client flood(bounded.port()); pump(bounded,{&flood},[&]{return flood.connected;});
    flood.send(join("flood-a")); flood.send(join("flood-b"));
    pump(bounded,{&flood},[&]{return bounded.stats().rejected>0;});
    check(bounded.stats().rejected==1,"pre-connect queue packet budget is enforced");
    bounded.close();

    options.queue_packets=64; options.max_peers=1;
    yuzu_capture::Relay capacity(options); capacity.open();
    Client one(capacity.port()); pump(capacity,{&one},[&]{return one.connected;});
    Client two(capacity.port());
    const auto wait_capacity=Clock::now()+std::chrono::milliseconds(100);
    pump(capacity,{&one,&two},[&]{return Clock::now()>=wait_capacity;},500);
    check(capacity.stats().active==1 && !two.connected,"listener capacity cannot create an extra upstream session");
    options.listen_port=capacity.port();
    refused=false;
    try {yuzu_capture::Relay collision(options);collision.open();} catch(...) {refused=true;}
    check(refused,"occupied listener port fails explicitly");
    capacity.close(); options.listen_port=0; options.max_peers=4;

    // Exercise the other boundary using a synthetic server only. Commercial
    // emulators must never receive these short/oversize network bodies.
    {
        ENetAddress address{}; enet_address_set_host_ip(&address,"127.0.0.1");
        const auto destroy_server=[](ENetHost* host){enet_host_destroy(host);};
        std::unique_ptr<ENetHost,decltype(destroy_server)> server(enet_host_create(&address,1,1,0,0),destroy_server);
        if(!server) throw std::runtime_error("guard server create");
        options.room_port=server->address.port;
        yuzu_capture::Relay guarded(options); guarded.open();
        Client receiver(guarded.port());
        std::vector<Bytes> valid,invalid;
        const unsigned sizes[]={0,0x480,0x40,0x480,0x40,0};
        for(unsigned type=0;type<6;++type) {
            yuzu_room::LdnPacket ldn;
            ldn.type=static_cast<yuzu_room::LdnPacketType>(type); ldn.data=Bytes(sizes[type],0x37);
            valid.push_back(yuzu_room::encode(ldn,yuzu_room::Direction::ServerToClient));
            ldn.data.push_back(0); invalid.push_back(yuzu_room::encode(ldn,yuzu_room::Direction::ServerToClient));
            if(sizes[type]) {ldn.data.resize(sizes[type]-1);invalid.push_back(yuzu_room::encode(ldn,yuzu_room::Direction::ServerToClient));}
        }
        invalid.push_back(invalid_zstd); invalid.push_back(concatenated); invalid.push_back(oversized);
        invalid.push_back(Bytes{6}); invalid.push_back(Bytes{5});
        auto unknown=valid.front(); unknown[1]=255; invalid.push_back(unknown);
        const auto sentinel=yuzu_room::encode(yuzu_room::ServerError{yuzu_room::MessageId::WrongPassword,0},yuzu_room::Direction::ServerToClient);
        pump(guarded,{&receiver},[&]{
            ENetEvent event{};
            while(enet_host_service(server.get(),&event,0)>0) {
                if(event.type==ENET_EVENT_TYPE_CONNECT) {
                    for(const auto* group:{&invalid,&valid}) for(const auto& bytes:*group) {
                        auto* packet=enet_packet_create(bytes.data(),bytes.size(),ENET_PACKET_FLAG_RELIABLE);
                        if(!packet || enet_peer_send(event.peer,0,packet)<0) throw std::runtime_error("guard send");
                    }
                    auto* packet=enet_packet_create(sentinel.data(),sentinel.size(),ENET_PACKET_FLAG_RELIABLE);
                    if(!packet || enet_peer_send(event.peer,0,packet)<0) throw std::runtime_error("guard sentinel");
                } else if(event.type==ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(event.packet);
            }
            enet_host_flush(server.get()); return receiver.contains(sentinel);
        });
        check(guarded.stats().rejected==invalid.size(),"all malformed upstream LDN and Proxy frames are rejected independently of tracing");
        check(std::none_of(invalid.begin(),invalid.end(),[&](const Bytes& bytes){return receiver.contains(bytes);}),"malformed upstream bodies never reach the downstream client");
        check(std::all_of(valid.begin(),valid.end(),[&](const Bytes& bytes){return receiver.contains(bytes);}),"all six exact LDN bodies still pass byte for byte after rejection");
        guarded.close();
    }

    // A synthetic ENet server sends a final error and immediately requests
    // graceful disconnect. The relay must drain that error to its client.
    ENetAddress fake_address{}; enet_address_set_host_ip(&fake_address,"127.0.0.1");
    const auto destroy=[](ENetHost* host){enet_host_destroy(host);};
    std::unique_ptr<ENetHost,decltype(destroy)> fake(enet_host_create(&fake_address,1,1,0,0),destroy);
    if(!fake) throw std::runtime_error("fake server create");
    options.room_port=fake->address.port;
    yuzu_capture::Relay draining(options);draining.open();
    Client final_client(draining.port());
    bool sent=false;
    const auto final_error=yuzu_room::encode(yuzu_room::ServerError{yuzu_room::MessageId::WrongPassword,0},yuzu_room::Direction::ServerToClient);
    pump(draining,{&final_client},[&]{
        ENetEvent event{};
        while(enet_host_service(fake.get(),&event,0)>0) {
            if(event.type==ENET_EVENT_TYPE_CONNECT) {
                auto* packet=enet_packet_create(final_error.data(),final_error.size(),ENET_PACKET_FLAG_RELIABLE);
                if(!packet || enet_peer_send(event.peer,0,packet)<0) throw std::runtime_error("fake send");
                enet_peer_disconnect_later(event.peer,0);sent=true;
            } else if(event.type==ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(event.packet);
        }
        enet_host_flush(fake.get());
        return sent && final_client.disconnected;
    });
    check(final_client.contains(final_error),"final upstream error is drained before downstream disconnect");
    check(final_client.disconnected,"upstream graceful disconnect reaches the original client");
    draining.close();

    // Finish the upstream connect, then withhold all server ACKs. Two frames
    // arriving in one client burst must not outgrow the outstanding budget.
    options.queue_packets=1;
    yuzu_capture::Relay ack_bounded(options); ack_bounded.open();
    Client ack_client(ack_bounded.port());
    bool fake_connected=false;
    pump(ack_bounded,{&ack_client},[&]{
        ENetEvent event{};
        while(enet_host_service(fake.get(),&event,0)>0) {
            if(event.type==ENET_EVENT_TYPE_CONNECT) fake_connected=true;
            if(event.type==ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(event.packet);
        }
        enet_host_flush(fake.get());
        return fake_connected && ack_client.connected;
    });
    // One extra relay turn processes the connect ACK before enqueueing data.
    ack_bounded.tick();
    ack_client.send(join("ack-first")); ack_client.send(join("ack-second"));
    pump(ack_bounded,{&ack_client},[&]{return ack_bounded.stats().rejected==1;});
    check(ack_bounded.stats().forwarded_up==1 && ack_bounded.stats().rejected==1,
          "outgoing packets remain budgeted until ACK, not merely until flush");
    ack_bounded.close(); options.queue_packets=64;

    options.trace_path=(evidence/"write-fault.jsonl").string();
    unsigned writes=0;
    options.trace_write_gate=[&]{return ++writes<3;};
    yuzu_capture::Relay write_fault(options);write_fault.open();
    Client fault_client(write_fault.port());
    pump(write_fault,{&fault_client},[&]{return fault_client.connected;});
    fault_client.send(join("fault-client"));
    pump(write_fault,{&fault_client},[&]{return write_fault.failed();});
    check(write_fault.stats().trace_failures>0,"injected trace write failure makes capture visibly fail");
    check(write_fault.stats().forwarded_up==0,"failed trace write cannot be presented as captured forwarding");
    write_fault.close();options.trace_write_gate={};options.trace_path.clear();

#ifdef _WIN32
    DWORD before=0,after=0;
    if(!GetProcessHandleCount(GetCurrentProcess(),&before)) throw std::runtime_error("handle count");
#endif
    for(unsigned cycle=0;cycle<20;++cycle) {
        yuzu_capture::Relay repeated(options);repeated.open();
        Client client(repeated.port());
        pump(repeated,{&client},[&]{return client.connected;});
        repeated.close();
        if(repeated.stats().active!=0) throw std::runtime_error("repeat active session leak");
    }
    check(true,"twenty connect-close cycles leave no active sessions");
#ifdef _WIN32
    if(!GetProcessHandleCount(GetCurrentProcess(),&after)) throw std::runtime_error("handle count");
    check(after==before,"twenty connect-close cycles return OS handles to baseline");
#endif
}
} // namespace
int main(int argc,char** argv) {
    if(enet_initialize()!=0) return 2;
    int code=0;
    try {
        const std::filesystem::path evidence=argc>1?argv[1]:".build-direct/evidence";
        std::filesystem::create_directories(evidence);
        std::uint16_t external_port=0;
        if(argc>2) {
            const std::string text=argv[2];std::size_t used=0;
            const auto port=std::stoul(text,&used);
            if(used!=text.size()||port<1||port>65535) throw std::runtime_error("invalid external room port");
            external_port=static_cast<std::uint16_t>(port);
        }
        run(evidence,external_port);
        std::cout<<"RESULT checks="<<checks<<" failed=0\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';code=1;}
    enet_deinitialize(); return code;
}
