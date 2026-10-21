// SPDX-License-Identifier: GPL-2.0-or-later
// Helper + denied-open tests: no Runtime, successful open, file or socket calls.
// API negative cases use an invalid IP as a second no-network safety fence.
#include "citra_gateway/gateway.hpp"
#include <zstd.h>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
int checks = 0, failures = 0;
void check(bool ok, const char* name) {
    ++checks;
    std::cout << (ok ? "PASS " : "FAIL ") << checks << " " << name << std::endl;
    if (!ok) ++failures;
}
void codec_tests() {
    using namespace citra_gateway;
    const citra_room::Bytes plain{0x32,0xab,0x98,0x64,1,2,3,4};
    room_client::Bytes compressed;
    std::string why;
    check(compress_proxy_frame(plain,65536,3,compressed,&why),"compress real gateway helper");
    citra_room::Bytes decoded;
    check(decompress_proxy_frame(compressed,60000,decoded,&why) && decoded==plain,"decode preserves opaque bytes, not MH conversion");
    check(!compress_proxy_frame({},65536,3,compressed,&why),"existing outbound empty payload policy");
    check(!compress_proxy_frame(plain,1,3,compressed,&why),"compression bound cap");
    check(compress_proxy_frame(plain,65536,3,compressed,&why),"fresh frame");
    const auto original=compressed;
    check(!valid_proxy_frame(compressed,compressed.size()-1,60000,&why),"compressed cap");
    check(!valid_proxy_frame(compressed,65536,plain.size()-1,&why),"content size cap");
    auto trailing=compressed;trailing.push_back(0);
    check(!valid_proxy_frame(trailing,65536,60000,&why),"trailing byte");
    trailing=compressed;trailing.insert(trailing.end(),compressed.begin(),compressed.end());
    check(!valid_proxy_frame(trailing,65536,60000,&why),"concatenated frames");
    for(std::size_t n=0;n<compressed.size();++n) {
        const room_client::Bytes cut(compressed.begin(),compressed.begin()+n);
        check(!decompress_proxy_frame(cut,60000,decoded,&why),"every truncation rejected");
    }
    check(compressed==original,"input frame preserved");
    // Independent raw-block fixtures, no encoder-generated expected result.
    const room_client::Bytes empty{0x28,0xb5,0x2f,0xfd,0x20,0,1,0,0};
    check(decompress_proxy_frame(empty,60000,decoded,&why) && decoded.empty(),"valid empty zstd is decoded");
    const room_client::Bytes empty_checksum{0x28,0xb5,0x2f,0xfd,0x24,0,1,0,0,0x99,0xe9,0xd8,0x51};
    check(decompress_proxy_frame(empty_checksum,60000,decoded,&why) && decoded.empty(),"valid empty checksum still accepted");
    // FCS=0 with a nonempty raw block: framing exists, semantic decoding must fail.
    const room_client::Bytes false_empty{0x28,0xb5,0x2f,0xfd,0x20,0,9,0,0,0x41};
    check(valid_proxy_frame(false_empty,65536,60000,&why),"frame-only predicate is not a content validator");
    check(!decompress_proxy_frame(false_empty,60000,decoded,&why),"zero-FCS must not bypass decoder");
    const room_client::Bytes bad_checksum{0x28,0xb5,0x2f,0xfd,0x24,0,1,0,0,0,0,0,0};
    check(valid_proxy_frame(bad_checksum,65536,60000,&why),"checksum fixture has complete framing");
    check(!decompress_proxy_frame(bad_checksum,60000,decoded,&why),"zero-FCS must verify checksum");
}
void profile_tests() {
    using namespace room_client;
    ProxyPacket p;p.local.ip={192,0,2,1};p.remote.ip={192,0,2,2};p.local.port=12345;p.remote.port=23456;p.data={0x11,0x22,0x33};
    for(const auto direction:{Direction::ClientToServer,Direction::ServerToClient}) {
        const auto bytes=encode(p,direction);
        check(bytes.size()==24 && bytes[0]==5 && bytes[1]==1 && bytes[8]==1 && bytes[15]==3,"current C++ codec uses mirror 1/3 profile");
        check(bytes[6]==0x30 && bytes[7]==0x39 && bytes[17]==0 && bytes[18]==0 && bytes[19]==0 && bytes[20]==3,"BE port and data vector size");
        check(std::get<ProxyPacket>(decode(bytes,direction))==p,"room envelope roundtrip opaque data");
        auto historical=bytes;historical[1]=0;historical[8]=0;historical[15]=2;
        // It may parse as other enum members, but is NOT automatically 2022 UDP.
        bool normalized=false;
        try {const auto q=std::get<ProxyPacket>(decode(historical,direction));normalized=q.local.family==Domain::Inet && q.remote.family==Domain::Inet && q.protocol==SocketProtocol::Udp;}
        catch(const ProtocolError&) {}
        check(!normalized,"no implicit 2022 enum profile translation");
    }
}
void capability_tests() {
    using namespace citra_gateway;
    Options defaults;
    check(defaults.application_mode==ApplicationMode::LegacyTransport && defaults.proxy_wire_profile==ProxyWireProfile::Mirror01052024,"legacy defaults preserved");
    check(gateway_capability_error(defaults.application_mode,defaults.proxy_wire_profile)==nullptr,"legacy mirror request supported, not crossplay");
    Options legacy;legacy.citra_peer_relay=true;legacy.have_game_nonce_ref=true;
    check(gateway_capability_error(legacy.application_mode,legacy.proxy_wire_profile)==nullptr,"legacy relay and nonce experiment are not reclassified as MH crossplay");
    for(int i=0;i<9;++i){
        Options o;o.listen_address="not-an-ip";o.trace_path="nonexistent-parent/must-not-create.jsonl";
        if(i==0) o.application_mode=ApplicationMode::MhxxMhgu;
        if(i==1) o.proxy_wire_profile=ProxyWireProfile::Yuzu2022;
        if(i==2){o.application_mode=ApplicationMode::MhxxMhgu;o.proxy_wire_profile=ProxyWireProfile::Yuzu2022;}
        if(i==3) o.application_mode=static_cast<ApplicationMode>(-1);
        if(i==4) o.proxy_wire_profile=static_cast<ProxyWireProfile>(-1);
        if(i==5) o.application_mode=static_cast<ApplicationMode>(2);
        if(i==6) o.proxy_wire_profile=static_cast<ProxyWireProfile>(2);
        if(i==7) o.application_mode=static_cast<ApplicationMode>(255);
        if(i==8) o.proxy_wire_profile=static_cast<ProxyWireProfile>(255);
        const char* expected=(i==1 || i==4 || i==6 || i==8) ? "gateway_proxy_profile_unavailable" : "gateway_application_mode_unavailable";
        const char* actual=gateway_capability_error(o.application_mode,o.proxy_wire_profile);
        check(actual && std::string(actual)==expected,"independent diagnostic fixture for unsupported or unknown enum");
        bool rejected=false;Gateway gateway(o);
        try{gateway.open();}catch(const std::runtime_error& e){rejected=expected && std::string(e.what())==expected;}
        check(rejected,"API denies capability before address, trace or network");
        check(!gateway.is_open(),"denied gateway remains closed");
    }
}
}
int main() {
    try {codec_tests();profile_tests();capability_tests();}
    catch(const std::exception& e){std::cerr << "unexpected: " << e.what() << std::endl;return 2;}
    std::cout << "offline checks=" << checks << " failures=" << failures << std::endl;
    return failures ? 1 : 0;
}
