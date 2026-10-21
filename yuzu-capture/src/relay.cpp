// SPDX-License-Identifier: GPL-3.0-or-later
#include "yuzu_capture/relay.hpp"
#include "yuzu_room/protocol.hpp"
#include "citra_control/ldn_ctrl.hpp"
#include <enet/enet.h>
#include <zstd.h>
#include <algorithm>
#include <chrono>
#include <deque>
#include <fstream>
#include <map>
#include <stdexcept>
#include <utility>
#include <vector>

namespace yuzu_capture {
namespace {
using Bytes = yuzu_room::Bytes;
using Clock = std::chrono::steady_clock;
std::uint64_t now() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count());
}
std::string ip_text(const yuzu_room::IPv4Address& ip) {
    return std::to_string(ip[0])+"."+std::to_string(ip[1])+"."+std::to_string(ip[2])+"."+std::to_string(ip[3]);
}
std::string hex_u64(std::uint64_t value) {
    std::array<std::uint8_t,8> bytes{};
    for(unsigned i=0;i<8;++i) bytes[7-i]=static_cast<std::uint8_t>(value>>(8*i));
    return "0x"+citra_control::to_hex(bytes);
}
struct HostDelete { void operator()(ENetHost* h) const { if (h) enet_host_destroy(h); } };
using Host = std::unique_ptr<ENetHost, HostDelete>;
struct Budget { std::size_t packets = 0, bytes = 0; };
struct Ticket { std::shared_ptr<Budget> budget; std::size_t bytes; };
void ENET_CALLBACK release_packet(ENetPacket* packet) {
    auto* ticket = static_cast<Ticket*>(packet->userData);
    --ticket->budget->packets;
    ticket->budget->bytes -= ticket->bytes;
    delete ticket;
}
void bound_host(ENetHost* host) {
    host->maximumPacketSize = 65536;
    host->maximumWaitingData = 262144;
}
} // namespace

struct Relay::Impl {
    struct Frame { Bytes data; enet_uint32 flags; enet_uint8 channel; };
    struct Session {
        std::uint64_t id = 0, started = 0, drain_started = 0;
        ENetPeer* downstream = nullptr;
        Host upstream;
        ENetPeer* remote = nullptr;
        bool ready = false, joined = false, closing = false;
        std::deque<Frame> pending;
        std::size_t pending_bytes = 0;
        std::shared_ptr<Budget> budget = std::make_shared<Budget>();
    };
    Options options;
    Stats counters;
    Host downstream;
    std::map<ENetPeer*, std::unique_ptr<Session>> sessions;
    std::uint64_t next_id = 1, last_stage_poll = 0;
    citra_gateway::TraceSink sink;
    bool fatal = false;

    explicit Impl(Options value) : options(std::move(value)) {}
    void write(const char* event, const char* direction, Session* session, const Bytes& raw,
               citra_gateway::TraceStructure structure) {
        if (!sink.enabled()) return;
        if (session) structure.fields.push_back(citra_gateway::trace_field_u64("peer_id",session->id));
        const auto record = citra_gateway::trace_make_record(options.identity, event, direction,
            {citra_gateway::trace_utc_now(),now()}, raw.data(),raw.size(),structure,options.trace_raw);
        std::string why;
        if ((options.trace_write_gate && !options.trace_write_gate()) || !sink.write(record,&why)) {
            ++counters.trace_failures; fatal=true;
        }
    }
    void marker(const char* event, Session* session = nullptr, const std::string& reason = {}) {
        citra_gateway::TraceStructure structure;
        structure.name="marker"; structure.decoded=true;
        if (!reason.empty()) structure.fields.push_back(citra_gateway::trace_field_string("reason",reason));
        write(event,"n/a",session,{},std::move(structure));
    }
    void stage() {
        if (options.stage_file.empty() || now()-last_stage_poll<100) return;
        last_stage_poll=now();
        std::ifstream file(citra_gateway::trace_path_from_narrow(options.stage_file),std::ios::binary);
        if (!file) return;
        std::string value;
        char ch;
        while (value.size()<256 && file.get(ch)) value.push_back(ch);
        if (file.get(ch)) return; // bounded stage label; never ingest an arbitrary file
        while (!value.empty() && (value.back()=='\r'||value.back()=='\n')) value.pop_back();
        if (!value.empty() && value!=options.identity.stage) {
            options.identity.stage=std::move(value); marker("stage.begin");
        }
    }
    bool observe(Session& session, const Frame& frame, bool upstream_direction) {
        using namespace citra_gateway;
        TraceStructure structure;
        structure.name="yuzu_room_message"; structure.decoded=true;
        bool forwardable=true;
        structure.fields.push_back(trace_field_u64("enet_channel",frame.channel));
        structure.fields.push_back(trace_field_u64("enet_flags",frame.flags));
        try {
            const auto message=yuzu_room::decode(frame.data,upstream_direction ?
                yuzu_room::Direction::ClientToServer : yuzu_room::Direction::ServerToClient);
            structure.fields.push_back(trace_field_string("message",yuzu_room::message_name(yuzu_room::message_id(message))));
            if (const auto* join=std::get_if<yuzu_room::JoinSuccess>(&message)) {
                session.joined=true;
                structure.fields.push_back(trace_field_string("assigned_ip",ip_text(join->assigned_fake_ip)));
            }
            if (const auto* info=std::get_if<yuzu_room::RoomInformation>(&message))
                structure.fields.push_back(trace_field_u64("member_count",info->members.size()));
            if (const auto* proxy=std::get_if<yuzu_room::ProxyPacket>(&message)) {
                structure.name="yuzu_room_proxy";
                const auto endpoint=[&](const char* prefix,const yuzu_room::SockAddrIn& address) {
                    structure.fields.push_back(trace_field_u64(std::string(prefix)+"_family",address.family));
                    structure.fields.push_back(trace_field_string(std::string(prefix)+"_ip",ip_text(address.ip)));
                    structure.fields.push_back(trace_field_u64(std::string(prefix)+"_port",address.port));
                };
                endpoint("local",proxy->local_endpoint); endpoint("remote",proxy->remote_endpoint);
                structure.fields.push_back(trace_field_u64("protocol",proxy->protocol));
                structure.fields.push_back(trace_field_bool("broadcast",proxy->broadcast));
                structure.fields.push_back(trace_field_u64("compressed_length",proxy->data.size()));
                const auto size=ZSTD_getFrameContentSize(proxy->data.data(),proxy->data.size());
                const auto compressed_size=ZSTD_findFrameCompressedSize(proxy->data.data(),proxy->data.size());
                const bool bounded=size!=ZSTD_CONTENTSIZE_ERROR && size!=ZSTD_CONTENTSIZE_UNKNOWN && size<=60000 &&
                    !ZSTD_isError(compressed_size) && compressed_size==proxy->data.size();
                bool valid=false;
                if (bounded) {
                    Bytes plain(static_cast<std::size_t>(size));
                    const auto written=ZSTD_decompress(plain.data(),plain.size(),proxy->data.data(),proxy->data.size());
                    valid=!ZSTD_isError(written) && written==plain.size();
                    if (valid) structure.fields.push_back(trace_field_string("plain_sha256",trace_sha256_hex(plain)));
                    structure.fields.push_back(trace_field_u64("plain_length",size));
                }
                structure.fields.push_back(trace_field_bool("zstd_verified",valid));
                if (!valid) { forwardable=false; structure.decoded=false; structure.reason="invalid_unknown_or_oversize_zstd"; }
            } else if (const auto* ldn=std::get_if<yuzu_room::LdnPacket>(&message)) {
                structure.name="yuzu_room_ldn";
                structure.fields.push_back(trace_field_u64("ldn_type",static_cast<std::uint8_t>(ldn->type)));
                structure.fields.push_back(trace_field_string("local_ip",ip_text(ldn->local_ip)));
                structure.fields.push_back(trace_field_string("remote_ip",ip_text(ldn->remote_ip)));
                structure.fields.push_back(trace_field_bool("broadcast",ldn->broadcast));
                structure.fields.push_back(trace_field_u64("body_length",ldn->data.size()));
                const auto expected=citra_control::ldn_body_size(static_cast<citra_control::LdnPacketType>(ldn->type));
                const bool valid=ldn->data.size()==expected;
                structure.fields.push_back(trace_field_u64("expected_body_length",expected));
                structure.fields.push_back(trace_field_bool("ldn_size_verified",valid));
                if (!valid) { forwardable=false; structure.decoded=false; structure.reason="ldn_body_size_mismatch"; }
                if (valid) {
                    const auto body=citra_control::parse_ldn_body(static_cast<citra_control::LdnPacketType>(ldn->type),ldn->data.data(),ldn->data.size());
                    structure.fields.push_back(trace_field_bool("ldn_body_decoded",body.ok()));
                    if (!body.ok()) {
                        // Semantic observation is independent of the memory-safety
                        // size gate. Do not rewrite an exact-size unknown profile.
                        structure.fields.push_back(trace_field_string("ldn_body_decode_reason",citra_control::err_name(body.err)));
                    } else {
                        const auto node_fields=[&](const std::string& prefix,const citra_control::LdnNodeInfo& node) {
                            structure.fields.push_back(trace_field_string(prefix+"ipv4_raw",ip_text(node.ipv4_address)));
                            structure.fields.push_back(trace_field_string(prefix+"mac",citra_control::to_hex(node.mac_address)));
                            structure.fields.push_back(trace_field_string(prefix+"id",std::to_string(node.node_id)));
                            structure.fields.push_back(trace_field_bool(prefix+"connected",node.is_connected!=0));
                            structure.fields.push_back(trace_field_string(prefix+"communication_version",std::to_string(node.local_communication_version)));
                        };
                        if (body.value.kind==citra_control::LdnBodyKind::NodeInfo) node_fields("node_",body.value.node);
                        if (body.value.kind==citra_control::LdnBodyKind::NetworkInfo) {
                            const auto& network=body.value.network;
                            // Hex strings retain all 64 bits in JSON/JavaScript.
                            structure.fields.push_back(trace_field_string("local_communication_id_hex",hex_u64(network.network_id.intent_id.local_communication_id)));
                            structure.fields.push_back(trace_field_u64("scene_id",network.network_id.intent_id.scene_id));
                            structure.fields.push_back(trace_field_string("session_id_high_hex",hex_u64(network.network_id.session_id.high)));
                            structure.fields.push_back(trace_field_string("session_id_low_hex",hex_u64(network.network_id.session_id.low)));
                            structure.fields.push_back(trace_field_string("network_bssid",citra_control::to_hex(network.common.bssid)));
                            structure.fields.push_back(trace_field_u64("network_type",network.common.network_type));
                            structure.fields.push_back(trace_field_u64("wifi_channel",network.common.channel));
                            structure.fields.push_back(trace_field_u64("node_count",network.ldn.node_count));
                            structure.fields.push_back(trace_field_u64("node_count_max",network.ldn.node_count_max));
                            structure.fields.push_back(trace_field_u64("advertise_length",network.ldn.advertise_data_size));
                            structure.fields.push_back(trace_field_string("advertise_sha256",trace_sha256_hex(network.ldn.advertise_data.data(),network.ldn.advertise_data_size)));
                            structure.fields.push_back(trace_field_u64("node_slots",network.ldn.nodes.size()));
                            for(unsigned i=0;i<network.ldn.nodes.size();++i) node_fields("node_"+std::to_string(i)+"_",network.ldn.nodes[i]);
                        }
                    }
                }
            }
        } catch (const yuzu_room::ProtocolError& error) {
            structure.decoded=false; structure.reason=yuzu_room::error_code_name(error.code());
            // These payloads reach unchecked emulator parsers. An invalid
            // network envelope must not bypass the exact-size/Zstd gate.
            if (!frame.data.empty() && (frame.data[0]==5 || frame.data[0]==6)) forwardable=false;
        }
        structure.fields.push_back(trace_field_bool("forwarding_allowed",forwardable));
        if (!structure.decoded) ++counters.decode_failures;
        write(upstream_direction?"room.c2s":"room.s2c",upstream_direction?"client->room":"room->client",
              &session,frame.data,std::move(structure));
        return forwardable;
    }
    bool send(Session& session, ENetPeer* target, const Frame& frame) {
        auto budget=session.budget;
        if (budget->packets>=options.queue_packets || frame.data.size()>options.queue_bytes-budget->bytes) return false;
        auto ticket=std::make_unique<Ticket>(Ticket{budget,frame.data.size()});
        ENetPacket* packet=enet_packet_create(frame.data.data(),frame.data.size(),frame.flags);
        if (!packet) return false;
        ++budget->packets; budget->bytes+=frame.data.size();
        packet->userData=ticket.release(); packet->freeCallback=release_packet;
        if (enet_peer_send(target,frame.channel,packet)<0) { enet_packet_destroy(packet); return false; }
        return true;
    }
    void terminate(Session& session, const std::string& reason) {
        if (session.closing) return;
        session.closing=true; session.drain_started=now();
        marker("peer.closing",&session,reason);
        session.pending.clear(); session.pending_bytes=0;
        if (session.remote && session.upstream) {
            enet_peer_disconnect_now(session.remote,0); enet_host_flush(session.upstream.get());
        }
        session.remote=nullptr; session.upstream.reset();
        enet_peer_disconnect_later(session.downstream,0);
    }
    void remove(ENetPeer* peer) {
        const auto it=sessions.find(peer);
        if (it==sessions.end()) return;
        terminate(*it->second,"downstream_disconnected");
        marker("peer.closed",it->second.get());
        enet_peer_reset(peer);
        sessions.erase(it); ++counters.disconnected;
    }
    void receive(Session& session, const ENetEvent& event, bool to_room) {
        const auto* packet=event.packet;
        if (packet->dataLength>65536 || event.channelID!=0) {
            enet_packet_destroy(event.packet); ++counters.rejected; terminate(session,"packet_limit"); return;
        }
        Frame frame{Bytes(packet->data,packet->data+packet->dataLength),
            packet->flags & (ENET_PACKET_FLAG_RELIABLE|ENET_PACKET_FLAG_UNSEQUENCED),event.channelID};
        enet_packet_destroy(event.packet);
        if (session.closing) return;
        const bool forwardable=observe(session,frame,to_room);
        if (fatal) { terminate(session,"trace_failed"); return; }
        if (!forwardable) {
            ++counters.rejected; marker("frame.rejected",&session,"unsafe_network_payload"); return;
        }
        if (to_room && !session.ready) {
            if (session.pending.size()+session.budget->packets>=options.queue_packets ||
                frame.data.size()>options.queue_bytes-session.pending_bytes-session.budget->bytes) {
                ++counters.rejected; terminate(session,"pending_limit"); return;
            }
            session.pending_bytes+=frame.data.size(); session.pending.push_back(std::move(frame)); return;
        }
        if (!send(session,to_room?session.remote:session.downstream,frame)) {
            ++counters.rejected; terminate(session,"outgoing_limit"); return;
        }
        if (to_room) ++counters.forwarded_up; else ++counters.forwarded_down;
    }
    void accept(ENetPeer* peer) {
        if (sessions.size()>=options.max_peers || peer->address.host!=loopback().host) {
            enet_peer_disconnect_now(peer,0); ++counters.rejected; return;
        }
        auto session=std::make_unique<Session>();
        session->id=next_id++; session->started=now(); session->downstream=peer;
        auto local=loopback(); local.port=0;
        session->upstream.reset(enet_host_create(&local,1,1,0,0));
        if (!session->upstream) { enet_peer_disconnect_now(peer,0); ++counters.rejected; return; }
        bound_host(session->upstream.get());
        auto remote=loopback(); remote.port=options.room_port;
        session->remote=enet_host_connect(session->upstream.get(),&remote,1,0);
        if (!session->remote) { enet_peer_disconnect_now(peer,0); ++counters.rejected; return; }
        marker("peer.connected",session.get());
        sessions.emplace(peer,std::move(session)); ++counters.connected;
    }
    static ENetAddress loopback() {
        ENetAddress address{}; enet_address_set_host_ip(&address,"127.0.0.1"); return address;
    }
};

Relay::Relay(Options options) : impl_(std::make_unique<Impl>(std::move(options))) {}
Relay::~Relay() { close(); }
void Relay::open() {
    auto& p=*impl_;
    if (p.downstream) throw std::runtime_error("capture already open");
    if (p.options.max_peers<1 || p.options.max_peers>16 || p.options.room_port==0 ||
        (p.options.listen_port!=0 && p.options.listen_port==p.options.room_port) ||
        p.options.queue_packets<1 || p.options.queue_packets>1024 ||
        p.options.queue_bytes<65536 || p.options.queue_bytes>4194304 ||
        p.options.connect_timeout_ms<1 || p.options.join_timeout_ms<1 || p.options.drain_timeout_ms<1)
        throw std::runtime_error("invalid capture limits or ports");
    p.options.identity.channel="B";
    if (p.options.trace_raw && p.options.trace_path.empty()) throw std::runtime_error("raw capture requires trace path");
    if (!p.options.trace_path.empty()) {
        std::string why;
        if (!p.sink.open(p.options.trace_path,p.options.trace_raw,&why)) throw std::runtime_error("trace open failed");
        p.marker("run.begin");
        if (p.fatal) throw std::runtime_error("trace begin failed");
    }
    auto address=Impl::loopback(); address.port=p.options.listen_port;
    p.downstream.reset(enet_host_create(&address,p.options.max_peers,1,0,0));
    if (!p.downstream) { p.sink.close(); throw std::runtime_error("capture bind failed"); }
    bound_host(p.downstream.get());
}
void Relay::tick() {
    auto& p=*impl_;
    if (!p.downstream || p.fatal) return;
    p.stage();
    ENetEvent event{};
    for (unsigned i=0;i<64 && enet_host_service(p.downstream.get(),&event,0)>0;++i) {
        if (event.type==ENET_EVENT_TYPE_CONNECT) p.accept(event.peer);
        else if (event.type==ENET_EVENT_TYPE_DISCONNECT) p.remove(event.peer);
        else if (event.type==ENET_EVENT_TYPE_RECEIVE) {
            const auto it=p.sessions.find(event.peer);
            if (it!=p.sessions.end()) p.receive(*it->second,event,true);
            else enet_packet_destroy(event.packet);
        }
    }
    std::vector<ENetPeer*> expired;
    for (auto& [peer,value]:p.sessions) {
        auto& session=*value;
        for (unsigned i=0;session.upstream && i<32;++i) {
            const int result=enet_host_service(session.upstream.get(),&event,0);
            if (result<=0) break;
            if (event.type==ENET_EVENT_TYPE_CONNECT) {
                session.ready=true; p.marker("upstream.connected",&session);
                while (!session.pending.empty() && !session.closing) {
                    auto frame=std::move(session.pending.front()); session.pending.pop_front();
                    session.pending_bytes-=frame.data.size();
                    if (!p.send(session,session.remote,frame)) { ++p.counters.rejected; p.terminate(session,"outgoing_limit"); break; }
                    ++p.counters.forwarded_up;
                }
            } else if (event.type==ENET_EVENT_TYPE_RECEIVE) p.receive(session,event,false);
            else if (event.type==ENET_EVENT_TYPE_DISCONNECT) p.terminate(session,"upstream_disconnected");
        }
        if (session.upstream) enet_host_flush(session.upstream.get());
        const auto elapsed=now()-session.started;
        if (!session.closing && ((!session.ready && elapsed>=p.options.connect_timeout_ms) ||
            (session.ready && !session.joined && elapsed>=p.options.join_timeout_ms))) {
            ++p.counters.timeouts; p.terminate(session,"deadline");
        }
        if (session.closing && now()-session.drain_started>=p.options.drain_timeout_ms) expired.push_back(peer);
    }
    for (auto* peer:expired) p.remove(peer);
    enet_host_flush(p.downstream.get());
}
void Relay::close() noexcept {
    auto& p=*impl_;
    try {
        for (auto& [peer,session]:p.sessions) {
            if (session->remote) enet_peer_disconnect_now(session->remote,0);
            if (session->upstream) enet_host_flush(session->upstream.get());
            enet_peer_disconnect_now(peer,0);
        }
        p.sessions.clear();
        if (p.downstream) enet_host_flush(p.downstream.get());
        p.downstream.reset();
        if (p.sink.enabled()) p.marker("run.end");
        p.sink.close();
    } catch (...) { p.fatal=true; p.downstream.reset(); p.sink.close(); }
}
std::uint16_t Relay::port() const { return impl_->downstream?impl_->downstream->address.port:0; }
Stats Relay::stats() const { auto result=impl_->counters; result.active=impl_->sessions.size(); return result; }
bool Relay::failed() const { return impl_->fatal; }
} // namespace yuzu_capture
