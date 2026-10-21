// Independent M1 review probe (reviewer-owned). Scratch only: crossplay/review-tools/m1/reverify/.
#include "room_client/protocol.hpp"
#include "room_client/session.hpp"
#include "network/packet.h"
#include "golden.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

using namespace room_client;

// ---------- reviewer instrumentation: global allocation tracking ----------
static bool g_track = false;
static std::size_t g_count = 0;
static std::size_t g_max = 0;
void* operator new(std::size_t n) {
    if (g_track) { ++g_count; if (n > g_max) g_max = n; }
    void* p = std::malloc(n ? n : 1);
    if (!p) { throw std::bad_alloc(); }
    return p;
}
void* operator new[](std::size_t n) {
    if (g_track) { ++g_count; if (n > g_max) g_max = n; }
    void* p = std::malloc(n ? n : 1);
    if (!p) { throw std::bad_alloc(); }
    return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

static int g_checks = 0;
static int g_fails = 0;
static void chk(bool ok, const std::string& name) {
    ++g_checks;
    if (!ok) { ++g_fails; std::printf("FAIL: %s\n", name.c_str()); }
}
struct AllocResult { bool threw = false; ErrorCode code = ErrorCode::Truncated; std::size_t max_alloc = 0; std::size_t allocs = 0; };
template <class F>
static AllocResult probe_alloc(F&& f) {
    AllocResult r;
    g_max = 0; g_count = 0; g_track = true;
    try { f(); }
    catch (const ProtocolError& e) { r.threw = true; r.code = e.code(); }
    catch (...) { r.threw = true; }
    g_track = false;
    r.max_alloc = g_max; r.allocs = g_count;
    return r;
}
static AllocResult decode_alloc(const Bytes& b, Direction d) {
    return probe_alloc([&] { (void)decode(b, d); });
}

// ---------- compile-time frozen-API checks ----------
static_assert(std::is_same_v<std::remove_cvref_t<decltype(encode(std::declval<const Message&>(), Direction::ClientToServer, Limits{}))>, Bytes>, "encode signature");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(decode(std::declval<const Bytes&>(), Direction::ClientToServer, Limits{}))>, Message>, "decode signature");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(parse_hex(std::declval<std::string_view>(), Limits{}))>, Bytes>, "parse_hex signature");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(to_hex(std::declval<const Bytes&>()))>, std::string>, "to_hex signature");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(message_id(std::declval<const Message&>()))>, MessageId>, "message_id signature");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(message_name(MessageId::Ldn))>, std::string>, "message_name signature");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::declval<const Session&>().state())>, SessionState>, "Session::state type");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::declval<const Session&>().room())>, std::optional<RoomInformation>>, "Session::room type");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::declval<const Session&>().assigned_ip())>, std::optional<IPv4>>, "Session::assigned_ip type");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::declval<const Session&>().last_server_error())>, std::optional<MessageId>>, "Session::last_server_error type");
static_assert(std::is_same_v<std::remove_cvref_t<decltype(std::declval<const Session&>().timed_out())>, bool>, "Session::timed_out type");
static_assert(network_version == 1 && enet_channel == 0, "constants");
static_assert(no_preferred_ip == IPv4{255, 255, 255, 255}, "no_preferred_ip");
static_assert(Limits{}.packet_bytes == 65536 && Limits{}.string_bytes == 4096 && Limits{}.members == 254 && Limits{}.data_bytes == 60000 && Limits{}.chat_bytes == 500, "documented caps");
static_assert(static_cast<int>(MessageId::JoinRequest) == 1 && static_cast<int>(MessageId::JoinSuccessAsModerator) == 24, "message ids");
static_assert(static_cast<int>(LdnType::DestroyNetwork) == 5 && static_cast<int>(SocketProtocol::Udp) == 3 && static_cast<int>(StatusType::AddressUnbanned) == 5, "enum wire values");

// ---------- original Packet oracle ----------
static Bytes to_bytes(const Network::Packet& p) {
    const auto* d = static_cast<const std::uint8_t*>(p.GetData());
    return Bytes(d, d + p.GetDataSize());
}
static void ow_ip(Network::Packet& p, const IPv4& ip) {
    p.Write(std::array<std::uint8_t, 4>{ip[0], ip[1], ip[2], ip[3]});
}
static Bytes orig_join(const std::string& nick, const std::string& pass, const std::string& token, std::uint32_t ver, const IPv4& pref) {
    Network::Packet p;
    p.Write(static_cast<std::uint8_t>(1)); p.Write(nick); ow_ip(p, pref); p.Write(ver); p.Write(pass); p.Write(token);
    return to_bytes(p);
}
static Bytes orig_game(const GameInfo& g) {
    Network::Packet p;
    p.Write(static_cast<std::uint8_t>(4)); p.Write(g.name); p.Write(g.id); p.Write(g.version);
    return to_bytes(p);
}
static Bytes orig_proxy(const ProxyPacket& m) {
    Network::Packet p;
    p.Write(static_cast<std::uint8_t>(5));
    p.Write(static_cast<std::uint8_t>(m.local.family)); ow_ip(p, m.local.ip); p.Write(m.local.port);
    p.Write(static_cast<std::uint8_t>(m.remote.family)); ow_ip(p, m.remote.ip); p.Write(m.remote.port);
    p.Write(static_cast<std::uint8_t>(m.protocol)); p.Write(m.broadcast); p.Write(m.data);
    return to_bytes(p);
}
static Bytes orig_ldn(const LdnPacket& m) {
    Network::Packet p;
    p.Write(static_cast<std::uint8_t>(6)); p.Write(static_cast<std::uint8_t>(m.type));
    ow_ip(p, m.local_ip); ow_ip(p, m.remote_ip); p.Write(m.broadcast); p.Write(m.data);
    return to_bytes(p);
}
static Bytes orig_room(const RoomInformation& r) {
    Network::Packet p;
    p.Write(static_cast<std::uint8_t>(3));
    p.Write(r.name); p.Write(r.description); p.Write(r.member_slots); p.Write(r.port);
    p.Write(r.preferred_game_name); p.Write(r.host_username);
    p.Write(static_cast<std::uint32_t>(r.members.size()));
    for (const auto& m : r.members) {
        p.Write(m.nickname); ow_ip(p, m.fake_ip);
        p.Write(m.game.name); p.Write(m.game.id); p.Write(m.game.version);
        p.Write(m.username); p.Write(m.display_name); p.Write(m.avatar_url);
    }
    return to_bytes(p);
}
static Bytes orig_success(const JoinSuccess& s, bool mod) {
    Network::Packet p;
    p.Write(static_cast<std::uint8_t>(mod ? 24 : 2)); ow_ip(p, s.assigned_ip);
    return to_bytes(p);
}
static Bytes orig_chat_request(const ChatRequest& c) {
    Network::Packet p; p.Write(static_cast<std::uint8_t>(7)); p.Write(c.message); return to_bytes(p);
}
static Bytes orig_chat_message(const ChatMessage& c) {
    Network::Packet p; p.Write(static_cast<std::uint8_t>(7)); p.Write(c.nickname); p.Write(c.username); p.Write(c.message); return to_bytes(p);
}
static Bytes orig_status(const StatusMessage& s) {
    Network::Packet p; p.Write(static_cast<std::uint8_t>(14)); p.Write(static_cast<std::uint8_t>(s.type)); p.Write(s.nickname); p.Write(s.username); return to_bytes(p);
}
static Bytes orig_error_id(int id) { Network::Packet p; p.Write(static_cast<std::uint8_t>(id)); return to_bytes(p); }
static Bytes orig_version_mismatch(std::uint32_t v) { Network::Packet p; p.Write(static_cast<std::uint8_t>(10)); p.Write(v); return to_bytes(p); }

// ---------- helpers ----------
static bool decode_err(const Bytes& b, Direction d, ErrorCode want, const Limits& l = Limits{}) {
    try { (void)decode(b, d, l); } catch (const ProtocolError& e) { return e.code() == want; } catch (...) { return false; }
    return false;
}
static bool encode_err(const Message& m, Direction d, ErrorCode want, const Limits& l = Limits{}) {
    try { (void)encode(m, d, l); } catch (const ProtocolError& e) { return e.code() == want; } catch (...) { return false; }
    return false;
}
static void diff(const char* name, const Message& m, Direction d, const Bytes& orig, bool expect_wrong_dir) {
    Bytes enc;
    try { enc = encode(m, d); }
    catch (const ProtocolError& e) { chk(false, std::string(name) + " M1 encode threw: " + e.what()); return; }
    chk(enc == orig, std::string(name) + " wire mismatch got=" + to_hex(enc) + " want=" + to_hex(orig));
    try { chk(decode(orig, d) == m, std::string(name) + " original wire does not decode to M1 value"); }
    catch (const ProtocolError& e) { chk(false, std::string(name) + " M1 decode of original wire threw: " + e.what()); }
    if (expect_wrong_dir) {
        const auto opposite = (d == Direction::ClientToServer) ? Direction::ServerToClient : Direction::ClientToServer;
        chk(encode_err(m, opposite, ErrorCode::WrongDirection), std::string(name) + " wrong outgoing direction not rejected");
        chk(decode_err(orig, opposite, ErrorCode::WrongDirection), std::string(name) + " wrong incoming direction not rejected");
    }
}
static RoomInformation make_room(std::size_t n, std::size_t nick_len) {
    RoomInformation r;
    r.name = "R"; r.description = ""; r.member_slots = static_cast<std::uint32_t>(n); r.port = 0x6128;
    r.preferred_game_name = "G"; r.host_username = "h";
    for (std::size_t i = 0; i < n; ++i) {
        Member m;
        m.nickname = std::string(nick_len, static_cast<char>('a' + static_cast<int>(i % 26)));
        m.fake_ip = IPv4{192, 168, 1, static_cast<std::uint8_t>(i & 0xff)};
        m.game = GameInfo{"GU", 0x0102030405060708ULL, "1"};
        m.username = "u"; m.display_name = "D"; m.avatar_url = "";
        r.members.push_back(std::move(m));
    }
    return r;
}
static RoomInformation self_room(const std::string& self_nick, const IPv4& self_ip) {
    RoomInformation r = make_room(2, 4);
    r.members[0].nickname = self_nick; r.members[0].fake_ip = self_ip;
    r.members[1].nickname = "Else"; r.members[1].fake_ip = IPv4{192, 168, 1, 3};
    r.member_slots = 4;
    return r;
}

int main() {
    const auto c = Direction::ClientToServer, s = Direction::ServerToClient;

    // ============ Section A: direction-specific wire schema vs original packet.cpp ============
    {
        JoinRequest jr; jr.nickname = "Test"; jr.preferred_ip = no_preferred_ip; jr.version = 1; jr.password = ""; jr.token = "";
        diff("join_request", Message{jr}, c, orig_join("Test", "", "", 1, no_preferred_ip), true);
        JoinRequest jr2; jr2.nickname = "\x54\x65\x73\x74\x00\x41"; jr2.password = "p\xff\x01"; jr2.token = "tok";
        diff("join_request_binary", Message{jr2}, c, orig_join(jr2.nickname, jr2.password, jr2.token, 1, no_preferred_ip), true);

        GameInfo gi{"GU", 0x0102030405060708ULL, "1"};
        diff("set_game_info", Message{gi}, c, orig_game(gi), true);

        ProxyPacket px; px.local = Endpoint{Domain::Inet, IPv4{1,2,3,4}, 0x1234};
        px.remote = Endpoint{Domain::Inet, IPv4{0xfe,0xdc,0xba,0x98}, 0xabcd};
        px.protocol = SocketProtocol::Udp; px.broadcast = false;
        px.data = Bytes{0x28,0xb5,0x2f,0xfd,0x20,0x00,0x01,0x00,0x00};
        diff("proxy_c2s", Message{px}, c, orig_proxy(px), false);

        LdnPacket ld; ld.type = LdnType::Connect; ld.local_ip = IPv4{1,2,3,4}; ld.remote_ip = IPv4{0xfe,0xdc,0xba,0x98};
        ld.broadcast = true; ld.data = Bytes{0xaa,0xbb,0xcc};
        diff("ldn_c2s", Message{ld}, c, orig_ldn(ld), false);

        ChatRequest cr{"hello"};
        diff("chat_request", Message{cr}, c, orig_chat_request(cr), false);

        RoomInformation room = self_room("Test", IPv4{192,168,1,2});
        diff("room_information", Message{room}, s, orig_room(room), true);

        JoinSuccess js{IPv4{192,168,1,2}, false};
        diff("join_success", Message{js}, s, orig_success(js, false), true);
        JoinSuccess jm{IPv4{192,168,1,2}, true};
        diff("join_success_moderator", Message{jm}, s, orig_success(jm, true), true);

        ChatMessage cm{"nick", "user", "hello"};
        diff("chat_message", Message{cm}, s, orig_chat_message(cm), false);

        StatusMessage st{static_cast<StatusType>(1), "nick", "user"};
        diff("status", Message{st}, s, orig_status(st), true);

        ServerError vm{MessageId::VersionMismatch, 1};
        diff("version_mismatch", Message{vm}, s, orig_version_mismatch(1), true);

        for (int id : {8, 9, 11, 12, 13, 15, 16, 22, 23}) {
            ServerError er{static_cast<MessageId>(id), 0};
            diff((std::string("error_") + std::to_string(id)).c_str(), Message{er}, s, orig_error_id(id), true);
        }
        // server->client envelope copies (original relays them verbatim in both directions)
        diff("proxy_s2c", Message{px}, s, orig_proxy(px), false);
        diff("ldn_s2c", Message{ld}, s, orig_ldn(ld), false);
        std::printf("SECTION A: original-Packet differential done\n");
    }

    // ============ Section B: golden fixtures + every proper prefix ============
    {
        auto fixtures = golden::fixtures();
        std::size_t prefix_total = 0, trailing_total = 0;
        for (const auto& f : fixtures) {
            const Bytes bytes = parse_hex(f.hex);
            chk(encode(f.expected, f.direction) == bytes, f.name + " encode golden");
            chk(decode(bytes, f.direction) == f.expected, f.name + " decode golden");
            chk(decode(encode(f.expected, f.direction), f.direction) == f.expected, f.name + " roundtrip");
            for (std::size_t n = 0; n < bytes.size(); ++n) {
                Bytes p(bytes.begin(), bytes.begin() + static_cast<Bytes::difference_type>(n));
                chk(decode_err(p, f.direction, ErrorCode::Truncated), f.name + " prefix " + std::to_string(n) + " not Truncated");
                ++prefix_total;
            }
            Bytes tr = bytes; tr.push_back(0);
            chk(decode_err(tr, f.direction, ErrorCode::TrailingBytes), f.name + " trailing not rejected");
            ++trailing_total;
        }
        std::printf("SECTION B: %zu fixtures, %zu proper prefixes, %zu trailing-byte cases\n", fixtures.size(), prefix_total, trailing_total);
    }

    // ============ Section C: exact 65536-byte positive boundary (delivered tests lack it) ============
    {
        const std::size_t target = Limits{}.packet_bytes;
        RoomInformation big = make_room(254, 4);
        {
            const Bytes base_enc = encode(big, s);
            chk(base_enc.size() < target, "254-member base room is under the packet cap");
            std::size_t deficit = target - base_enc.size();
            for (std::size_t i = 0; i < big.members.size() && deficit > 0; ++i) {
                const std::size_t take = std::min<std::size_t>(deficit, Limits{}.string_bytes);
                big.members[i].avatar_url.assign(take, 'v');
                deficit -= take;
            }
            chk(deficit == 0, "65536-byte room achievable by filling avatar_url within per-string cap");
        }
        Bytes enc = encode(big, s);
        chk(enc.size() == target, "a valid packet of exactly 65536 bytes exists and encodes to " + std::to_string(enc.size()));
        chk(decode(enc, s) == Message{big}, "exactly-65536 packet decodes");
        RoomInformation over = big; over.members.back().nickname.push_back('z');
        chk(encode_err(Message{over}, s, ErrorCode::LimitExceeded), "65537-byte valid packet rejected on encode");
        Limits tight; tight.packet_bytes = target - 1;
        chk(decode_err(enc, s, ErrorCode::LimitExceeded, tight), "65536 packet rejected under cap 65535");
        chk(decode_err(Bytes(target + 1, 0), s, ErrorCode::LimitExceeded), "65537 raw input rejected");
        std::printf("SECTION C: exact-65536 valid packet encoded/decoded (%zu bytes)\n", enc.size());
    }

    // ============ Section D: caps precedence relative to allocation ============
    {
        // D1 oversized input rejected before the id byte is even read: offset 0.
        {
            Bytes b(Limits{}.packet_bytes + 1, 0xff);
            bool ok = false;
            try { (void)decode(b, s); } catch (const ProtocolError& e) { ok = (e.code() == ErrorCode::LimitExceeded && e.offset() == 0); }
            chk(ok, "oversized input rejected at offset 0 before id");
        }
        // D2 declared string length 0xffffffff -> LimitExceeded, no big allocation.
        {
            Bytes b{1, 0xff, 0xff, 0xff, 0xff};
            auto r = decode_alloc(b, c);
            chk(r.threw && r.code == ErrorCode::LimitExceeded, "declared huge string rejected");
            chk(r.max_alloc < 1024, "declared huge string allocated " + std::to_string(r.max_alloc) + " bytes");
        }
        // D3 declared data length 0xffffffff -> LimitExceeded, no big allocation.
        {
            Bytes b = parse_hex(golden::ldn);
            for (int i = 0; i < 4; ++i) b.at(11 + static_cast<std::size_t>(i)) = 0xff;
            auto r = decode_alloc(b, c);
            chk(r.threw && r.code == ErrorCode::LimitExceeded, "declared huge data rejected");
            chk(r.max_alloc < 1024, "declared huge data allocated " + std::to_string(r.max_alloc) + " bytes");
        }
        // D4 declared member count 0xffffffff -> check_members LimitExceeded before reserve.
        {
            Bytes b = parse_hex(golden::room);
            for (int i = 0; i < 4; ++i) b.at(26 + static_cast<std::size_t>(i)) = 0xff;
            auto r = decode_alloc(b, s);
            chk(r.threw && r.code == ErrorCode::LimitExceeded, "declared huge member count rejected");
            chk(r.max_alloc < 1024, "huge member count allocated " + std::to_string(r.max_alloc) + " bytes");
        }
        // D5 member count within cap but more than remaining/36 -> Truncated before reserve.
        {
            // hand-built RoomInformation header: id,name,desc,slots=254,port,pg,host,count=254, no member bytes
            Bytes b{0x03, 0,0,0,0, 0,0,0,0, 0,0,0,0xfe, 0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0xfe};
            auto r = decode_alloc(b, s);
            chk(r.threw && r.code == ErrorCode::Truncated, "count>remaining rejected as Truncated");
            chk(r.max_alloc < 1024, "count>remaining allocated " + std::to_string(r.max_alloc) + " bytes");
        }
        // D6 in-limit declared string longer than remaining -> Truncated, no big allocation.
        {
            Bytes b{1, 0x00, 0x00, 0x10, 0x00}; // declared 4096, zero bytes follow
            auto r = decode_alloc(b, c);
            chk(r.threw && r.code == ErrorCode::Truncated, "in-limit string longer than buffer not Truncated");
            chk(r.max_alloc < 1024, "in-limit short buffer allocated " + std::to_string(r.max_alloc) + " bytes");
        }
        // D7 Limits validation precedes id/direction interpretation.
        {
            Limits bad; bad.packet_bytes = 0;
            chk(decode_err(Bytes{255}, s, ErrorCode::InvalidArgument, bad), "invalid limits not checked before unknown id");
            chk(encode_err(Message{JoinSuccess{}}, s, ErrorCode::InvalidArgument, bad), "invalid limits not checked before encode direction");
            chk(decode_err(parse_hex(golden::success), s, ErrorCode::InvalidArgument, bad), "invalid limits not checked before decode");
            Limits bad2; bad2.members = 255;
            chk(decode_err(parse_hex(golden::success), s, ErrorCode::InvalidArgument, bad2), "member cap above ceiling accepted");
            Limits bad3; bad3.string_bytes = 0;
            chk(encode_err(Message{JoinSuccess{}}, s, ErrorCode::InvalidArgument, bad3), "zero string cap rejected");
            Limits bad4; bad4.packet_bytes = Limits{}.packet_bytes + 1;
            chk(encode_err(Message{JoinSuccess{}}, s, ErrorCode::InvalidArgument, bad4), "packet cap above ceiling rejected");
        }
        // D8 whole-packet consumption: every type, both where legal.
        {
            const std::vector<Message> msgs{
                JoinRequest{"Test", no_preferred_ip, 1, "", ""},
                GameInfo{"GU", 1, "1"},
                ProxyPacket{Endpoint{Domain::Inet, IPv4{1,2,3,4}, 0x1234}, Endpoint{Domain::Inet, IPv4{5,6,7,8}, 0xabcd}, SocketProtocol::Tcp, true, Bytes{1,2}},
                LdnPacket{LdnType::DestroyNetwork, IPv4{1,2,3,4}, IPv4{5,6,7,8}, false, Bytes{3,4}},
                ChatRequest{"hi"},
            };
            const std::vector<Message> smsgs{
                JoinSuccess{IPv4{192,168,1,2}, false},
                RoomInformation{self_room("Test", IPv4{192,168,1,2})},
                ChatMessage{"n","u","m"},
                StatusMessage{static_cast<StatusType>(5), "n", "u"},
                ServerError{MessageId::HostBanned, 0},
                ServerError{MessageId::VersionMismatch, 7},
            };
            for (const auto& m : msgs) {
                Bytes b = encode(m, c); b.push_back(0);
                chk(decode_err(b, c, ErrorCode::TrailingBytes), "c2s trailing byte accepted for " + message_name(message_id(m)));
            }
            for (const auto& m : smsgs) {
                Bytes b = encode(m, s); b.push_back(0);
                chk(decode_err(b, s, ErrorCode::TrailingBytes), "s2c trailing byte accepted for " + message_name(message_id(m)));
            }
        }
        std::printf("SECTION D: caps/allocation precedence probes done\n");
    }

    // ============ Section E: state/identity invariants on every legal prefix (fresh Joining session) ============
    {
        JoinRequest jr{"Test", no_preferred_ip, 1, "", ""};
        const RoomInformation live = self_room("Test", IPv4{192,168,1,2});
        std::vector<Bytes> s2c_stream{
            encode(RoomInformation{live}, s),
            encode(JoinSuccess{IPv4{192,168,1,2}, false}, s),
            encode(JoinSuccess{IPv4{192,168,1,2}, true}, s),
            encode(ChatMessage{"n", "u", "m"}, s),
            encode(StatusMessage{static_cast<StatusType>(1), "n", "u"}, s),
            encode(ServerError{MessageId::VersionMismatch, 1}, s),
            encode(ServerError{MessageId::WrongPassword, 0}, s),
            encode(LdnPacket{LdnType::Connect, IPv4{1,2,3,4}, IPv4{5,6,7,8}, true, Bytes{1,2,3}}, s),
            encode(ProxyPacket{Endpoint{Domain::Inet, IPv4{1,2,3,4}, 1}, Endpoint{Domain::Inet, IPv4{5,6,7,8}, 2}, SocketProtocol::Udp, false, Bytes{9}}, s),
        };
        std::size_t attempted = 0;
        for (const auto& full : s2c_stream) {
            for (std::size_t n = 0; n < full.size(); ++n) {
                Session sess;
                (void)sess.begin_join(jr, 0);
                Bytes p(full.begin(), full.begin() + static_cast<Bytes::difference_type>(n));
                bool threw = false; ErrorCode code = ErrorCode::Truncated;
                try { (void)sess.receive(p, 1); }
                catch (const ProtocolError& e) { threw = true; code = e.code(); }
                catch (...) { threw = true; code = ErrorCode::InvalidArgument; }
                chk(threw, "prefix not rejected (" + std::to_string(n) + ")");
                chk(code == ErrorCode::Truncated, "prefix not Truncated (" + std::to_string(n) + ")");
                chk(sess.state() == SessionState::Joining, "prefix changed state");
                chk(!sess.room() && !sess.assigned_ip() && !sess.last_server_error() && !sess.timed_out(), "prefix mutated identity");
                ++attempted;
            }
        }
        // Joined-state mutation safety: prefixes and semantically-invalid updates.
        Session sess;
        (void)sess.begin_join(jr, 0);
        (void)sess.receive(encode(RoomInformation{live}, s), 1);
        (void)sess.receive(encode(JoinSuccess{IPv4{192,168,1,2}, false}, s), 2);
        chk(sess.state() == SessionState::Joined, "join sequence did not reach Joined");
        const auto room0 = sess.room(); const auto ip0 = sess.assigned_ip(); const auto st0 = sess.state();
        const Bytes room_bytes = encode(RoomInformation{live}, s);
        for (std::size_t n = 0; n < room_bytes.size(); ++n) {
            Bytes p(room_bytes.begin(), room_bytes.begin() + static_cast<Bytes::difference_type>(n));
            bool threw = false; ErrorCode code = ErrorCode::Truncated;
            try { (void)sess.receive(p, 3); } catch (const ProtocolError& e) { threw = true; code = e.code(); }
            chk(threw && code == ErrorCode::Truncated, "joined room prefix not Truncated");
            chk(sess.state() == st0 && sess.room() == room0 && sess.assigned_ip() == ip0, "joined room prefix mutated identity");
            ++attempted;
        }
        { // update losing self
            RoomInformation lost = live; lost.members[0].nickname = "Gone";
            bool threw = false;
            try { (void)sess.receive(encode(RoomInformation{lost}, s), 4); } catch (const ProtocolError&) { threw = true; }
            chk(threw && sess.room() == room0 && sess.state() == st0 && sess.assigned_ip() == ip0, "losing-self update mutated identity");
        }
        { // duplicate identity
            RoomInformation dup = live; dup.members[1] = dup.members[0];
            bool threw = false;
            try { (void)sess.receive(encode(RoomInformation{dup}, s), 4); } catch (const ProtocolError&) { threw = true; }
            chk(threw && sess.room() == room0 && sess.state() == st0, "duplicate-identity update mutated state");
        }
        { // malformed bool in a server message while Joined
            Bytes bb = parse_hex(golden::ldn); bb[10] = 2;
            bool threw = false; ErrorCode code = ErrorCode::Truncated;
            try { (void)sess.receive(bb, 4); } catch (const ProtocolError& e) { threw = true; code = e.code(); }
            chk(threw && code == ErrorCode::InvalidBoolean && sess.room() == room0 && sess.assigned_ip() == ip0, "bad bool mutated joined identity");
        }
        std::printf("SECTION E: %zu prefix cases, joined-state invariants checked\n", attempted);
    }

    // ============ Section F: documented limit boundaries from both sides ============
    {
        Limits L{};
        chk(L.packet_bytes == 65536 && L.string_bytes == 4096 && L.members == 254 && L.data_bytes == 60000 && L.chat_bytes == 500, "Limits defaults");
        JoinRequest j; j.nickname.assign(L.string_bytes, 'x');
        chk(encode(j, c).size() > 0, "string at cap accepted");
        j.nickname.push_back('x');
        chk(encode_err(Message{j}, c, ErrorCode::LimitExceeded), "string over cap rejected");
        LdnPacket l; l.data.assign(L.data_bytes, 0xaa);
        chk(encode(Message{l}, c).size() > 0, "data at cap accepted");
        l.data.push_back(0);
        chk(encode_err(Message{l}, c, ErrorCode::LimitExceeded), "data over cap rejected");
        RoomInformation r = make_room(L.members, 1);
        chk(encode(Message{r}, s).size() > 0, "members at cap accepted");
        r.members.resize(L.members + 1);
        chk(encode_err(Message{r}, s, ErrorCode::LimitExceeded), "members over cap rejected");
        ChatRequest cr{std::string(L.chat_bytes, 'h')};
        chk(encode(Message{cr}, c).size() > 0, "chat at cap accepted");
        cr.message.push_back('h');
        chk(encode_err(Message{cr}, c, ErrorCode::LimitExceeded), "chat over cap rejected");
        // zero slots rejected
        RoomInformation z = make_room(0, 1); z.member_slots = 0;
        chk(encode_err(Message{z}, s, ErrorCode::LimitExceeded), "zero slots rejected");
        // parse_hex / to_hex caps
        chk(decode_err(Bytes(L.packet_bytes + 1, 0), s, ErrorCode::LimitExceeded), "input over packet cap rejected");
        bool caught = false;
        try { (void)parse_hex(std::string(L.packet_bytes * 2 + 2, 'a')); } catch (const ProtocolError& e) { caught = (e.code() == ErrorCode::LimitExceeded); }
        chk(caught, "hex text over cap rejected");
        caught = false;
        try { (void)to_hex(Bytes(L.packet_bytes + 1, 0)); } catch (const ProtocolError& e) { caught = (e.code() == ErrorCode::LimitExceeded); }
        chk(caught, "to_hex over cap rejected");
        std::printf("SECTION F: documented cap boundaries done\n");
    }

    std::printf("TOTAL %d checks, %d failures\n", g_checks, g_fails);
    std::printf("%s independent M1 review probe\n", g_fails == 0 ? "PASS" : "FAIL");
    return g_fails == 0 ? 0 : 1;
}
