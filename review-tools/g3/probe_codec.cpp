// Independent G3 falsification probe. Built by the reviewer; does NOT call the author's test suite.
// Compares the codec against (a) direct zstd ZSTD_CLEVEL_DEFAULT calls, (b) bytes constructed from the
// TRUE Citra/Yuzu struct layouts measured by oracle_citra.cpp / oracle_yuzu.cpp, (c) committed fixtures.
#include "lan_codecs.h"
#include <zstd.h>
#include <zstd_errors.h>
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace lan_codec;
static std::size_t checks = 0, failures = 0;
static constexpr std::size_t NOPOS = static_cast<std::size_t>(-1);
static std::size_t section_last = 0;
static void section_end(const char* name){ std::printf("  [%s: %zu checks]\n", name, checks - section_last); section_last = checks; }

static void put16be(Bytes& b, std::size_t p, std::uint16_t v){ b[p]=Byte(v>>8); b[p+1]=Byte(v); }
static void put16le(Bytes& b, std::size_t p, std::uint16_t v){ b[p]=Byte(v); b[p+1]=Byte(v>>8); }
static void put64le(Bytes& b, std::size_t p, std::uint64_t v){ for(int i=0;i<8;i++) b[p+std::size_t(i)]=Byte(v>>(8*i)); }

template<class T> bool expect_err(const char* label, const Result<T>& r, Error want, std::size_t wantoff = NOPOS){
    ++checks;
    const bool ok = r.error==want && (wantoff==NOPOS || r.offset==wantoff);
    if(!ok){ ++failures; std::printf("[FAIL] %-54s got %s@0x%zX want %s@0x%zX\n", label, error_name(r.error), r.offset, error_name(want), wantoff); }
    return ok;
}
template<class T> bool expect_ok(const char* label, const Result<T>& r){
    ++checks;
    if(!r){ ++failures; std::printf("[FAIL] %-54s unexpected %s@0x%zX\n", label, error_name(r.error), r.offset); return false; }
    return true;
}
static void expect_true(const char* label, bool ok){ ++checks; if(!ok){ ++failures; std::printf("[FAIL] %s\n", label);} }
static void expect_bytes(const char* label, const Bytes& a, const Bytes& b){
    ++checks;
    if(a.size()!=b.size()){ ++failures; std::printf("[FAIL] %-54s size %zu vs %zu\n", label, a.size(), b.size()); return; }
    for(std::size_t i=0;i<a.size();++i) if(a[i]!=b[i]){ ++failures; std::printf("[FAIL] %-54s first diff @0x%zX: %02x vs %02x\n", label, i, a[i], b[i]); return; }
}

static Bytes load_hex(const char* path){
    std::ifstream f(path);
    if(!f){ std::printf("[FATAL] cannot open %s\n", path); std::exit(2); }
    auto hv=[](char c)->int{ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; };
    Bytes out; std::string tok;
    while(f>>tok){
        if(tok[0]=='#'){ std::getline(f,tok); continue; }
        for(std::size_t i=0;i+1<tok.size();i+=2){ int hi=hv(tok[i]),lo=hv(tok[i+1]); if(hi<0||lo<0) continue; out.push_back(Byte(hi*16+lo)); }
    }
    return out;
}
static std::string hexof(const Bytes& b){
    static const char* d="0123456789abcdef"; std::string s;
    for(Byte x:b){ s+=d[x>>4]; s+=d[x&15]; }
    return s;
}

// --- constructors from the TRUE measured layouts -------------------------------------------
static Bytes uds_bytes(std::size_t applen, Byte channel, std::uint16_t dest, std::uint16_t src, std::uint16_t seq){
    Bytes b(22+applen, 0);
    const Byte llc[8]={0xAA,0xAA,0x03,0,0,0,0x87,0x6D};
    std::copy(llc,llc+8,b.begin());
    put16be(b,8, std::uint16_t(14+applen));
    put16be(b,12, std::uint16_t(10+applen));
    b[14]=0; b[15]=channel;
    put16be(b,16,seq); put16be(b,18,dest); put16be(b,20,src);
    for(std::size_t i=0;i<applen;i++) b[22+i]=Byte(i*7+1);
    return b;
}
static void write_node_at(Bytes& b, std::size_t p, int node_id, Byte connected, Byte ip0){
    b[p+0]=ip0; b[p+1]=2; b[p+2]=3; b[p+3]=4;                    // ipv4_address @0
    const Byte mac[6]={0x02,0xAA,0xBB,0xCC,0xDD,Byte(0xE0+connected)};   // mac_address @4
    std::copy(mac,mac+6,b.begin()+std::ptrdiff_t(p+4));
    b[p+10]=Byte(node_id);                                        // node_id @0xA
    b[p+11]=connected;                                            // is_connected @0xB
    b[p+12]=Byte('N'); b[p+13]=Byte('0'+ (node_id<0?0:node_id));  // user_name @0xC
    b[p+45]=0x00;                                                 // reserved_2d @0x2D
    put16le(b,p+46,0x1234);                                       // local_communication_version @0x2E
    for(std::size_t i=0;i<16;i++) b[p+48+i]=Byte(0xF0+i);         // reserved_30 @0x30
}
static Bytes node_bytes(int node_id, Byte connected){ Bytes b(0x40,0); write_node_at(b,0,node_id,connected,1); return b; }
static Bytes net_bytes(Byte node_count_max, Byte node_count){
    Bytes b(0x480,0);
    put64le(b,0,0x0807060504030201ULL); b[8]=0xA1; b[9]=0xA2; put16le(b,10,0x1234); b[12]=0xB1; b[13]=0xB2; b[14]=0xB3; b[15]=0xB4;
    put64le(b,16,0x1817161514131211ULL); put64le(b,24,0x2827262524232221ULL);
    const Byte bssid[6]={0x02,0x10,0x20,0x30,0x40,0x50}; std::copy(bssid,bssid+6,b.begin()+32);
    b[38]=3; b[39]=Byte('L'); b[40]=Byte('A'); b[41]=Byte('B');
    put16le(b,0x48,6); b[0x4A]=2; b[0x4B]=2; b[0x4C]=0xC1; b[0x4D]=0xC2; b[0x4E]=0xC3; b[0x4F]=0xC4;
    for(std::size_t i=0;i<16;i++) b[0x50+i]=Byte(0xD0+i);
    put16le(b,0x60,1); b[0x62]=3; b[0x63]=0x7F; b[0x64]=0xE1; b[0x65]=0xE2;
    b[0x66]=node_count_max; b[0x67]=node_count;
    for(std::size_t i=0;i<8;i++) write_node_at(b,0x68+0x40*i,int(i), i<node_count?Byte(1):Byte(0), Byte(1+i));
    b[0x268]=0; b[0x269]=0; put16le(b,0x26A,4); b[0x26C]=0xDE; b[0x26D]=0xAD; b[0x26E]=0xBE; b[0x26F]=0xEF;
    put64le(b,0x478,0x3837363534333231ULL);
    return b;
}

int main(){
    std::printf("== environment ==\nZSTD_versionString=%s ZSTD_VERSION_NUMBER=%d ZSTD_CLEVEL_DEFAULT=%d\n\n", ZSTD_versionString(), ZSTD_VERSION_NUMBER, ZSTD_CLEVEL_DEFAULT);

    // ============ PART 1: zstd profile byte comparison ============
    std::printf("== PART 1: encode_zstd_default vs direct ZSTD_compress(ZSTD_CLEVEL_DEFAULT) ==\n");
    std::vector<std::vector<Byte>> inputs;
    inputs.push_back({});
    inputs.push_back({0x61});
    inputs.push_back({'a','b','c'});
    { auto v=Bytes(100); for(std::size_t i=0;i<v.size();++i) v[i]=Byte(i*13+7); inputs.push_back(v); }
    { auto v=Bytes(4096); for(std::size_t i=0;i<v.size();++i) v[i]=Byte((i%251)); inputs.push_back(v); }
    { auto v=Bytes(65536); for(std::size_t i=0;i<v.size();++i) v[i]=Byte((i*31)%256); inputs.push_back(v); }
    for(std::size_t k=0;k<inputs.size();++k){
        const auto& in=inputs[k];
        auto enc=encode_zstd_default(in);
        char lbl[96]; std::snprintf(lbl,sizeof lbl,"zstd size=%zu enc ok && equals decode-back",in.size());
        if(!expect_ok(lbl,enc)) continue;
        // direct profile
        std::size_t bound=ZSTD_compressBound(in.size());
        std::vector<Byte> direct(bound);
        const void* sp = in.empty()? static_cast<const void*>("") : static_cast<const void*>(in.data());
        std::size_t w=ZSTD_compress(direct.data(),bound,sp,in.size(),ZSTD_CLEVEL_DEFAULT);
        direct.resize(w);
        std::snprintf(lbl,sizeof lbl,"zstd size=%zu bytes == direct ZSTD_compress",in.size());
        expect_bytes(lbl, enc.value, direct);
        auto back=decode_zstd_single(enc.value);
        if(expect_ok("zstd roundtrip decode", back)) expect_bytes("zstd roundtrip payload", back.value, in);
    }

    section_end("PART 1 zstd-profile byte-compare");
    // ============ PART 2: hostile / rejected frames ============
    std::printf("\n== PART 2: claimed rejections ==\n");
    { Bytes f={0x28,0xB5,0x2F}; expect_err("frame<4 -> incomplete_frame", decode_zstd_single(f), Error::incomplete_frame); }
    { Bytes f={0x50,0x2A,0x4D,0x18,0,0,0,0}; expect_err("skippable magic -> invalid_zstd", decode_zstd_single(f), Error::invalid_zstd); }
    { Bytes f={0x28,0xB5,0x2F,0xFE,0,0,0,0}; expect_err("bad standard magic -> invalid_zstd", decode_zstd_single(f), Error::invalid_zstd); }
    { // unknown content size
      Bytes in(200); for(std::size_t i=0;i<in.size();++i) in[i]=Byte(i*5+1);
      ZSTD_CCtx* c=ZSTD_createCCtx();
      ZSTD_CCtx_setParameter(c,ZSTD_c_contentSizeFlag,0);
      std::vector<Byte> out(ZSTD_compressBound(in.size()));
      std::size_t w=ZSTD_compress2(c,out.data(),out.size(),in.data(),in.size());
      ZSTD_freeCCtx(c); out.resize(w);
      expect_true("synthesized frame really has UNKNOWN content size", ZSTD_getFrameContentSize(out.data(),out.size())==ZSTD_CONTENTSIZE_UNKNOWN);
      expect_err("unknown content size -> unknown_content_size", decode_zstd_single(out), Error::unknown_content_size);
    }
    { auto enc=encode_zstd_default(std::vector<Byte>{'a','b','c'});
      Bytes cat=enc.value; cat.insert(cat.end(), enc.value.begin(), enc.value.end());
      expect_err("two concatenated frames -> trailing_data", decode_zstd_single(cat), Error::trailing_data); }
    { auto enc=encode_zstd_default(std::vector<Byte>{'a','b','c'});
      Bytes tj=enc.value; tj.push_back(0x00);
      expect_err("one trailing junk byte -> trailing_data", decode_zstd_single(tj), Error::trailing_data); }
    { Bytes in(1000,0x5A); auto enc=encode_zstd_default(in);
      ZstdLimits l; l.decompressed=100;
      expect_err("declared content>decompressed limit -> limit_exceeded", decode_zstd_single(enc.value,l), Error::limit_exceeded); }
    { Bytes in(1000,0x5A); auto enc=encode_zstd_default(in);
      ZstdLimits l; l.compressed=4;
      expect_err("frame>compressed limit -> limit_exceeded", decode_zstd_single(enc.value,l), Error::limit_exceeded); }
    { Bytes in(10,1); auto enc=encode_zstd_default(in);
      ZstdLimits l; l.compressed=hard_resource_cap+1;
      expect_err("limits>hard_resource_cap -> limit_exceeded", decode_zstd_single(enc.value,l), Error::limit_exceeded); }
    { // truncated valid frame
      auto enc=encode_zstd_default(Bytes(50,7));
      Bytes t(enc.value.begin(), enc.value.end()-1);
      auto r=decode_zstd_single(t);
      expect_err("truncated frame rejected (any error)", r, r.error==Error::none?Error::invalid_zstd:r.error);
      expect_true("truncated frame is NOT accepted", !r); }

    section_end("PART 2 claimed rejections");
    // ============ PART 3: Citra UDS reverse falsify ============
    std::printf("\n== PART 3: Citra UDS bytes built from true LLCHeader(8)+SecureDataHeader(14) ==\n");
    { Bytes b=uds_bytes(0,7,0xFFFF,1,0x1234);
      auto r=decode_uds(b);
      if(expect_ok("UDS app=0 dest=0xFFFF src=1", r)){
        expect_true("UDS channel", r.value.channel==7);
        expect_true("UDS sequence", r.value.sequence==0x1234);
        expect_true("UDS destination", r.value.destination==0xFFFF);
        expect_true("UDS source", r.value.source==1);
        expect_true("UDS app empty", r.value.application.empty());
        auto e=encode_uds(r.value); if(expect_ok("UDS re-encode", e)) expect_bytes("UDS roundtrip bytes", e.value, b);
      } }
    { Bytes b=uds_bytes(uds_application_max,1,2,1,0);
      auto r=decode_uds(b);
      if(expect_ok("UDS app=0x5C6 (max) accepted", r)) expect_true("UDS app size 0x5C6", r.value.application.size()==uds_application_max); }
    { Bytes b=uds_bytes(uds_application_max+1,1,2,1,0);
      expect_err("UDS app=0x5C7 -> limit_exceeded@22", decode_uds(b), Error::limit_exceeded, 22); }
    { Bytes b=uds_bytes(4,7,0,1,0); expect_err("UDS dest=0 -> invalid_field@18", decode_uds(b), Error::invalid_field, 18); }
    { Bytes b=uds_bytes(4,7,2,0,0); expect_err("UDS src=0 -> invalid_field@20", decode_uds(b), Error::invalid_field, 20); }
    { Bytes b=uds_bytes(4,7,5,5,0); expect_err("UDS dest==src -> invalid_field@20", decode_uds(b), Error::invalid_field, 20); }
    { Bytes b=uds_bytes(4,7,2,1,0); b[6]=0x88; expect_err("UDS wrong EtherType -> invalid_header@6", decode_uds(b), Error::invalid_header, 6); }
    { Bytes b=uds_bytes(4,7,2,1,0); b[10]=1; expect_err("UDS pad byte b[10]!=0 -> invalid_header@10", decode_uds(b), Error::invalid_header, 10); }
    { Bytes b=uds_bytes(4,7,2,1,0); b[11]=1; expect_err("UDS pad byte b[11]!=0 -> invalid_header@11", decode_uds(b), Error::invalid_header, 11); }
    { Bytes b=uds_bytes(4,7,2,1,0); b[14]=1; expect_err("UDS is_management b[14]!=0 -> invalid_header@14", decode_uds(b), Error::invalid_header, 14); }
    { Bytes b=uds_bytes(4,7,2,1,0); put16be(b,12,9); expect_err("UDS secure!=protocol-4 -> size_mismatch@8", decode_uds(b), Error::size_mismatch, 8); }
    { Bytes b=uds_bytes(4,7,2,1,0); b.resize(b.size()-1); expect_err("UDS size != 8+protocol -> size_mismatch@8", decode_uds(b), Error::size_mismatch, 8); }
    { Bytes b=uds_bytes(0,7,2,1,0); b.resize(21); expect_err("UDS size 21 -> truncated@21", decode_uds(b), Error::truncated, 21); }
    { Bytes fx=load_hex("crossplay/lan-codecs/fixtures/uds-golden.hex");
      std::printf("  fixture uds-golden.hex = %s (%zu B)\n", hexof(fx).c_str(), fx.size());
      auto r=decode_uds(fx);
      if(expect_ok("fixture uds-golden decodes", r)){
        expect_true("fixture channel==7", r.value.channel==7);
        expect_true("fixture seq==0x1234", r.value.sequence==0x1234);
        expect_true("fixture dest==0xFFFF", r.value.destination==0xFFFF);
        expect_true("fixture src==1", r.value.source==1);
        expect_true("fixture app==deadbeef", r.value.application==Bytes{0xDE,0xAD,0xBE,0xEF});
        auto e=encode_uds(r.value); if(expect_ok("fixture re-encode", e)) expect_bytes("fixture re-encode == file", e.value, fx);
      } }

    section_end("PART 3 Citra UDS");
    // ============ PART 4: Yuzu NodeInfo reverse falsify ============
    std::printf("\n== PART 4: Yuzu NodeInfo (sizeof 0x40, measured offsets) ==\n");
    { Bytes b=node_bytes(3,1);
      auto r=decode_node(b);
      if(expect_ok("NodeInfo node_id=3 connected=1", r)){
        expect_true("node ipv4", r.value.node_ipv4==Ipv4Bytes{1,2,3,4});
        expect_true("node mac", (r.value.mac==std::array<Byte,6>{0x02,0xAA,0xBB,0xCC,0xDD,0xE1}));
        expect_true("node id", r.value.node_id==3);
        expect_true("node connected", r.value.is_connected==1);
        expect_true("node comm_version LE", r.value.communication_version==0x1234);
        auto e=encode_node(r.value); if(expect_ok("NodeInfo re-encode", e)) expect_bytes("NodeInfo roundtrip", e.value, b);
      } }
    { expect_err("node_id=8 -> invalid_field@10", decode_node(node_bytes(8,1)), Error::invalid_field, 10); }
    { expect_err("node_id=-1 -> invalid_field@10", decode_node(node_bytes(-1,1)), Error::invalid_field, 10); }
    { expect_err("is_connected=2 -> invalid_field@11", decode_node(node_bytes(3,2)), Error::invalid_field, 11); }
    { Bytes b=node_bytes(3,1); b.resize(0x3F); expect_err("NodeInfo size 0x3F -> truncated@0x3F", decode_node(b), Error::truncated, 0x3F); }
    { Bytes b=node_bytes(3,1); b.push_back(0); expect_err("NodeInfo size 0x41 -> oversized@0x40", decode_node(b), Error::oversized, 0x40); }
    { Bytes fx=load_hex("crossplay/lan-codecs/fixtures/nodeinfo-golden.hex");
      std::printf("  fixture nodeinfo-golden.hex = %zu B\n", fx.size());
      auto r=decode_node(fx);
      if(expect_ok("fixture nodeinfo decodes", r)){
        expect_true("fixture node ipv4 01 02 03 04", r.value.node_ipv4==Ipv4Bytes{1,2,3,4});
        expect_true("fixture node mac 02 aa bb cc dd ee", (r.value.mac==std::array<Byte,6>{0x02,0xAA,0xBB,0xCC,0xDD,0xEE}));
        expect_true("fixture node_id 3", r.value.node_id==3);
        expect_true("fixture is_connected 1", r.value.is_connected==1);
        expect_true("fixture user_name SYNTH", std::string(reinterpret_cast<const char*>(r.value.user_name.data()))=="SYNTH");
        expect_true("fixture comm_version 0x1234", r.value.communication_version==0x1234);
        expect_true("fixture reserved_2d 0xA5", r.value.reserved_2d==0xA5);
        auto e=encode_node(r.value); if(expect_ok("fixture node re-encode", e)) expect_bytes("fixture node re-encode == file", e.value, fx);
      } }
    { expect_true("node_ipv4_from_room_bytes reverses", node_ipv4_from_room_bytes(Ipv4Bytes{1,2,3,4})==Ipv4Bytes{4,3,2,1}); }

    section_end("PART 4 Yuzu NodeInfo");
    // ============ PART 5: Yuzu NetworkInfo reverse falsify ============
    std::printf("\n== PART 5: Yuzu NetworkInfo (sizeof 0x480, measured offsets) ==\n");
    { Bytes b=net_bytes(8,2);
      auto r=decode_network(b);
      if(expect_ok("NetworkInfo valid constructed", r)){
        expect_true("local_comm LE", r.value.local_communication_id==0x0807060504030201ULL);
        expect_true("scene_id LE", r.value.scene_id==0x1234);
        expect_true("session_high LE", r.value.session_high==0x1817161514131211ULL);
        expect_true("session_low LE", r.value.session_low==0x2827262524232221ULL);
        expect_true("bssid", (r.value.bssid==std::array<Byte,6>{0x02,0x10,0x20,0x30,0x40,0x50}));
        expect_true("ssid_length", r.value.ssid_length==3);
        expect_true("ssid LAB", std::string(reinterpret_cast<const char*>(r.value.ssid.data()),3)=="LAB");
        expect_true("channel 6", r.value.channel==6);
        expect_true("link_level 2", r.value.link_level==2);
        expect_true("network_type 2", r.value.network_type==2);
        expect_true("security_mode 1", r.value.security_mode==1);
        expect_true("accept_policy 3", r.value.accept_policy==3);
        expect_true("has_action_frame 0x7F", r.value.has_action_frame==0x7F);
        expect_true("node_count_max 8", r.value.node_count_max==8);
        expect_true("node_count 2", r.value.node_count==2);
        expect_true("advertise_size 4", r.value.advertise_size==4);
        expect_true("advertise DEADBEEF", (r.value.advertise[0]==0xDE&&r.value.advertise[1]==0xAD&&r.value.advertise[2]==0xBE&&r.value.advertise[3]==0xEF));
        expect_true("auth id LE", r.value.authentication_id==0x3837363534333231ULL);
        auto e=encode_network(r.value); if(expect_ok("NetworkInfo re-encode", e)) expect_bytes("NetworkInfo roundtrip", e.value, b);
      } }
    { Bytes b=net_bytes(8,2); b[38]=33; expect_err("ssid_length=33 -> invalid_field@0x26", decode_network(b), Error::invalid_field, 0x26); }
    { Bytes b=net_bytes(8,2); put16le(b,0x48,5); expect_err("channel=5 -> invalid_enum@0x48", decode_network(b), Error::invalid_enum, 0x48); }
    { Bytes b=net_bytes(8,2); b[0x4A]=4; expect_err("link_level=4 -> invalid_enum@0x4A", decode_network(b), Error::invalid_enum, 0x4A); }
    { Bytes b=net_bytes(8,2); b[0x4B]=4; expect_err("network_type=4 -> invalid_enum@0x4B", decode_network(b), Error::invalid_enum, 0x4B); }
    { Bytes b=net_bytes(8,2); put16le(b,0x60,3); expect_err("security_mode=3 -> invalid_enum@0x60", decode_network(b), Error::invalid_enum, 0x60); }
    { Bytes b=net_bytes(8,2); b[0x62]=4; expect_err("accept_policy=4 -> invalid_enum@0x62", decode_network(b), Error::invalid_enum, 0x62); }
    { Bytes b=net_bytes(8,2); b[0x66]=0; expect_err("node_count_max=0 -> invalid_field@0x66", decode_network(b), Error::invalid_field, 0x66); }
    { Bytes b=net_bytes(8,2); b[0x66]=9; expect_err("node_count_max=9 -> invalid_field@0x66", decode_network(b), Error::invalid_field, 0x66); }
    { Bytes b=net_bytes(8,2); b[0x67]=0; expect_err("node_count=0 -> invalid_field@0x67", decode_network(b), Error::invalid_field, 0x67); }
    { Bytes b=net_bytes(8,2); b[0x67]=3; expect_err("node_count>connected -> invalid_field@0x67", decode_network(b), Error::invalid_field, 0x67); }
    { Bytes b=net_bytes(8,2); b[0x68+3*0x40+10]=5; expect_err("slot3 node_id=5 -> invalid_field@0x132", decode_network(b), Error::invalid_field, 0x132); }
    { Bytes b=net_bytes(8,2); b[0x68+11]=0; expect_err("slot0 disconnected -> invalid_field@0x67", decode_network(b), Error::invalid_field, 0x67); }
    { Bytes b=net_bytes(8,2); put16le(b,0x26A,385); expect_err("advertise_size=385 -> invalid_field@0x26A", decode_network(b), Error::invalid_field, 0x26A); }
    { Bytes b=net_bytes(8,2); b.resize(0x47F); expect_err("NetworkInfo size 0x47F -> truncated@0x47F", decode_network(b), Error::truncated, 0x47F); }
    { Bytes b=net_bytes(8,2); b.push_back(0); expect_err("NetworkInfo size 0x481 -> oversized@0x480", decode_network(b), Error::oversized, 0x480); }
    { Bytes fx=load_hex("crossplay/lan-codecs/fixtures/networkinfo-golden.hex");
      std::printf("  fixture networkinfo-golden.hex = %zu B\n", fx.size());
      auto r=decode_network(fx);
      if(expect_ok("fixture networkinfo decodes", r)){
        expect_true("fixture ssid LAB", r.value.ssid_length==3);
        expect_true("fixture channel 6", r.value.channel==6);
        expect_true("fixture node_count 2", r.value.node_count==2);
        expect_true("fixture node_count_max 8", r.value.node_count_max==8);
        expect_true("fixture advertise_size 4", r.value.advertise_size==4);
        auto e=encode_network(r.value); if(expect_ok("fixture network re-encode", e)) expect_bytes("fixture network re-encode == file", e.value, fx);
      } }

    section_end("PART 5 Yuzu NetworkInfo");
    // ============ PART 6: LDN type -> body map (lan_discovery.cpp:478-560) ============
    std::printf("\n== PART 6: LDN raw type -> body size map ==\n");
    { const std::size_t map[6]={0,0x480,0x40,0x480,0x40,0};  // Scan,ScanResp,Connect,Sync,Disconnect,Destroy
      for(Byte t=0;t<6;++t){
        Bytes body(map[t],0);
        if(t==2||t==4) body=node_bytes(1,1);
        if(t==1||t==3) body=net_bytes(8,1);
        auto r=decode_ldn(t,body);
        char lbl[64]; std::snprintf(lbl,sizeof lbl,"decode_ldn type=%u body=0x%zX",t,map[t]);
        if(expect_ok(lbl,r)) expect_true("ldn decoded type matches", static_cast<Byte>(r.value.type)==t);
        auto e=encode_ldn(r.value);
        if(expect_ok("ldn re-encode",e)) expect_bytes("ldn body roundtrip", e.value, body);
      }
      expect_err("raw type 6 -> invalid_enum", decode_ldn(6,Bytes{}), Error::invalid_enum);
      expect_err("type 0 with non-empty body -> oversized@0", decode_ldn(0,Bytes{1}), Error::oversized, 0);
      expect_err("type 2 with empty body -> truncated@0", decode_ldn(2,Bytes{}), Error::truncated, 0);
      expect_err("type 1 with 0x40 body -> truncated@0x40", decode_ldn(1,node_bytes(1,1)), Error::truncated, 0x40);
    }

    section_end("PART 6 LDN type->body map");
    std::printf("\n== SUMMARY checks=%zu failures=%zu ==\n", checks, failures);
    return failures==0?0:1;
}
