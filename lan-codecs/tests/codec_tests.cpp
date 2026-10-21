// SPDX-FileCopyrightText: Copyright 2026 LAN codec contributors
// SPDX-License-Identifier: GPL-3.0-or-later
#include "lan_codecs.h"
#include "hex_io.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <zstd.h>
using namespace lan_codec;
namespace {
std::size_t checks = 0, cases = 0;
void expect(bool ok, const std::string& detail) { ++checks; if (!ok) throw std::runtime_error(detail); }
template<class T> void ok(const Result<T>& r, const std::string& detail) {
    expect(bool(r), detail + ": " + error_name(r.error));
}
template<class T> void error(const Result<T>& r, Error e, const std::string& detail) {
    expect(!r && r.error == e, detail + ": got " + error_name(r.error));
}
void run(const std::string& name, const std::function<void()>& fn) {
    const auto start = checks; fn(); ++cases;
    std::cout << "PASS " << name << " checks=" << checks - start << '\n';
}
Bytes fixture(const char* name) { return hex_io::load(std::string("@fixtures/") + name); }
// Independent normal reference call matches Yuzu snapshot's clamped-default one-shot function.
Bytes yuzu_reference(Input input) {
    Bytes out(ZSTD_compressBound(input.size()));
    const int level = std::clamp(ZSTD_CLEVEL_DEFAULT, 1, ZSTD_maxCLevel());
    const auto size = ZSTD_compress(out.data(), out.size(), input.data(), input.size(), level);
    if (ZSTD_isError(size)) throw std::runtime_error("reference compression failed");
    out.resize(size); return out;
}
Bytes advanced_frame(Input input, bool content_size, bool checksum) {
    ZSTD_CCtx* ctx = ZSTD_createCCtx(); if (!ctx) throw std::runtime_error("test CCtx allocation failed");
    auto a = ZSTD_CCtx_setParameter(ctx, ZSTD_c_contentSizeFlag, content_size ? 1 : 0);
    auto b = ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, checksum ? 1 : 0);
    Bytes out(ZSTD_compressBound(input.size()));
    const auto size = ZSTD_compress2(ctx, out.data(), out.size(), input.data(), input.size());
    ZSTD_freeCCtx(ctx);
    if (ZSTD_isError(a) || ZSTD_isError(b) || ZSTD_isError(size)) throw std::runtime_error("advanced fixture generation failed");
    out.resize(size); return out;
}
}
int main() {
    try {
        std::cout << "Synthetic offline test suite; no emulator/network/game data.\nZstd runtime=" << ZSTD_versionString() << '\n';
        const auto uds = fixture("uds-golden.hex"), node = fixture("nodeinfo-golden.hex"), net = fixture("networkinfo-golden.hex");
        const auto abc = fixture("zstd-raw-abc.hex");
        run("UDS independent golden", [&] {
            expect(uds.size() == 26, "UDS golden size"); const auto r = decode_uds(uds); ok(r, "UDS decode");
            expect(r.value.channel == 7 && r.value.destination == 65535 && r.value.source == 1 && r.value.sequence == 0x1234, "UDS hand field expectations");
            expect(r.value.application == Bytes({0xDE, 0xAD, 0xBE, 0xEF}), "UDS opaque payload");
            const UdsData expected{7, 65535, 1, 0x1234, {0xDE, 0xAD, 0xBE, 0xEF}};
            auto e = encode_uds(expected); ok(e, "UDS encode"); expect(e.value == uds, "UDS encoder vs independent wire");
        });
        run("UDS every prefix truncation", [&] {
            for (std::size_t p = 0; p < uds.size(); ++p) expect(!decode_uds(Input(uds).first(p)), "UDS prefix " + std::to_string(p));
        });
        run("UDS bounds lengths and strict subset", [&] {
            UdsData d{0, 2, 1, 0, {}}; auto empty = encode_uds(d); ok(empty, "UDS empty");
            expect(empty.value.size() == 22 && empty.value[9] == 14 && empty.value[13] == 10, "UDS zero size length arithmetic");
            ok(decode_uds(empty.value), "UDS empty decode accepts SendTo channel0 without inferring bindability");
            d.application.assign(uds_application_max, 0xAB); auto boundary = encode_uds(d); ok(boundary, "UDS max");
            expect(boundary.value.size() == 1500 && boundary.value[8] == 5 && boundary.value[9] == 0xD4 && boundary.value[12] == 5 && boundary.value[13] == 0xD0, "UDS max exact BE lengths");
            auto round = decode_uds(boundary.value); ok(round, "UDS max decode"); expect(round.value == d, "UDS max exact opaque bytes");
            d.application.push_back(0); error(encode_uds(d), Error::limit_exceeded, "UDS max+1");
            auto too_big = boundary.value; too_big.push_back(0); error(decode_uds(too_big), Error::limit_exceeded, "UDS incoming oversize");
            for (const auto at : {8, 9, 12, 13}) { auto b = uds; b[static_cast<std::size_t>(at)] ^= 1; error(decode_uds(b), Error::size_mismatch, "declared length mismatch"); }
            auto low = uds; low[8] = 0; low[9] = 13; error(decode_uds(low), Error::size_mismatch, "protocol underflow");
            auto low_secure = uds; low_secure[12] = 0; low_secure[13] = 9; error(decode_uds(low_secure), Error::size_mismatch, "secure underflow");
            auto over = uds; over[8] = 0xFF; over[9] = 0xFF; over[12] = 0xFF; over[13] = 0xFB;
            error(decode_uds(over), Error::limit_exceeded, "large internally consistent declared payload");
            auto trailing = uds; trailing.push_back(0); error(decode_uds(trailing), Error::size_mismatch, "UDS trailing bytes");
            for (std::size_t at = 0; at < 8; ++at) { auto b = uds; b[at] ^= 1; error(decode_uds(b), Error::invalid_header, "LLC constant"); }
            for (const auto at : {10, 11, 14}) { auto b = uds; b[static_cast<std::size_t>(at)] = 1; error(decode_uds(b), Error::invalid_header, "reserved/management subset"); }
            d.application.clear(); d.destination = 0; error(encode_uds(d), Error::invalid_field, "UDS dest0");
            d.destination = 1; error(encode_uds(d), Error::invalid_field, "UDS self");
            d.destination = 2; d.source = 0; error(encode_uds(d), Error::invalid_field, "UDS source0 strict policy");
            auto zero_dest = uds; zero_dest[18] = 0; zero_dest[19] = 0; error(decode_uds(zero_dest), Error::invalid_field, "decode dest0");
            auto zero_source = uds; zero_source[20] = 0; zero_source[21] = 0; error(decode_uds(zero_source), Error::invalid_field, "decode source0");
        });
        run("NodeInfo independent golden and byte order", [&] {
            expect(node.size() == 64, "Node golden size"); auto r = decode_node(node); ok(r, "Node decode");
            expect(r.value.node_ipv4 == Ipv4Bytes({1,2,3,4}), "Node raw IPv4 is not auto-normalized");
            expect(node_ipv4_from_room_bytes({4,3,2,1}) == r.value.node_ipv4, "Source documented room->Node byte reversal");
            expect(r.value.mac == std::array<Byte,6>({2,0xAA,0xBB,0xCC,0xDD,0xEE}) && r.value.node_id == 3 && r.value.is_connected == 1, "Node explicit fields");
            expect(r.value.user_name[0] == 'S' && r.value.user_name[4] == 'H' && r.value.user_name[32] == 0, "Node bounded username");
            expect(r.value.communication_version == 0x1234 && r.value.reserved_2d == 0xA5 && r.value.reserved_30.front() == 0xF0 && r.value.reserved_30.back() == 0xFF, "Node LE and reserved preservation");
            auto encoded = encode_node(r.value); ok(encoded, "Node encode"); expect(encoded.value == node, "Node all64 bytes independent golden");
        });
        run("NodeInfo every prefix lengths and domains", [&] {
            for (std::size_t p = 0; p < node.size(); ++p) error(decode_node(Input(node).first(p)), Error::truncated, "Node prefix");
            auto long_node = node; long_node.push_back(0); error(decode_node(long_node), Error::oversized, "Node trailing");
            for (Byte id : {Byte(8), Byte(0xFF), Byte(0x80)}) { auto b = node; b[10] = id; error(decode_node(b), Error::invalid_field, "Node signed ID domain"); }
            auto b = node; b[11] = 2; error(decode_node(b), Error::invalid_field, "connected domain");
            b = node; b[46] = 0xFF; b[47] = 0xFF; auto negative = decode_node(b); ok(negative, "signed communication version not guessed"); expect(negative.value.communication_version == -1, "version signed LE");
            auto n = decode_node(node).value; n.user_name.fill(0xFF); auto e = encode_node(n); ok(e, "username not required NUL"); ok(decode_node(e.value), "bounded array without string scan");
        });
        run("NetworkInfo independent offset golden", [&] {
            expect(net.size() == 0x480, "Network golden size"); auto r = decode_network(net); ok(r, "Network decode"); const auto& n = r.value;
            expect(n.local_communication_id == 0x0807060504030201ULL && n.scene_id == 0x1234 && n.session_high == 0x1817161514131211ULL && n.session_low == 0x2827262524232221ULL, "LE NetworkId offsets");
            expect(n.bssid == std::array<Byte,6>({2,0x10,0x20,0x30,0x40,0x50}) && n.ssid_length == 3 && n.ssid[0] == 'L' && n.ssid[2] == 'B', "Common offsets");
            expect(n.channel == 6 && n.link_level == 2 && n.network_type == 2 && n.security_mode == 1 && n.accept_policy == 3 && n.has_action_frame == 0x7F, "typed enum offsets; unknown action byte preserved");
            expect(n.node_count == 2 && n.node_count_max == 8 && n.nodes[7].node_id == 7 && n.nodes[7].communication_version == 0x1234, "Node array offset/stride");
            expect(n.advertise_size == 4 && n.advertise[0] == 0xDE && n.advertise[3] == 0xEF && n.authentication_id == 0x3837363534333231ULL, "Advertise/auth offsets");
            expect(n.reserved_08[0] == 0xA1 && n.reserved_0c[3] == 0xB4 && n.reserved_4c[3] == 0xC4 && n.reserved_64[1] == 0xE2 && n.reserved_268[1] == 0xE4 && n.reserved_3ec.front() == 0xA9 && n.reserved_3ec.back() == 0xB9, "all reserved ranges preserved");
            auto e = encode_network(n); ok(e, "Network encode"); expect(e.value == net, "Network all1152 bytes vs independent wire");
        });
        run("NetworkInfo every prefix and long body", [&] {
            for (std::size_t p = 0; p < net.size(); ++p) error(decode_network(Input(net).first(p)), Error::truncated, "Network prefix");
            auto b = net; b.push_back(0); error(decode_network(b), Error::oversized, "Network oversized");
        });
        run("Network enums counts array limits", [&] {
            for (const auto at : {0x48,0x4A,0x4B,0x60,0x62}) { auto b = net; b[static_cast<std::size_t>(at)] = 0xFF; error(decode_network(b), Error::invalid_enum, "known enum out-of-domain"); }
            for (Byte max : {Byte(0),Byte(9),Byte(255)}) { auto b = net; b[0x66] = max; error(decode_network(b), Error::invalid_field, "max node domain"); }
            for (Byte count : {Byte(0),Byte(9),Byte(255),Byte(1)}) { auto b = net; b[0x67] = count; error(decode_network(b), Error::invalid_field, "count/active consistency"); }
            auto b = net; b[0x66] = 1; error(decode_network(b), Error::invalid_field, "count exceeds max");
            b = net; b[0x26] = 33; error(decode_network(b), Error::invalid_field, "SSID max+1");
            b = net; b[0x26A] = 0x81; b[0x26B] = 1; error(decode_network(b), Error::invalid_field, "advertise385");
            b = net; b[0x68 + 11] = 0; error(decode_network(b), Error::invalid_field, "host must be active");
            b = net; b[0x68 + 0x40 + 10] = 0; error(decode_network(b), Error::invalid_field, "slot/ID consistency policy");
            b = net; b[0x68 + 0x40 + 11] = 2; error(decode_network(b), Error::invalid_field, "node connected enum");
            auto n = decode_network(net).value; n.advertise_size = 384; n.ssid_length = 32; n.ssid.fill(0xFF); auto e = encode_network(n); ok(e, "max arrays without C string assumption"); ok(decode_network(e.value), "max array decode");
            n.advertise_size = 385; error(encode_network(n), Error::invalid_field, "encode advertise limit");
            for (std::int16_t c : {std::int16_t(0),std::int16_t(1),std::int16_t(6),std::int16_t(11),std::int16_t(36),std::int16_t(40),std::int16_t(44),std::int16_t(48)}) {
                n = decode_network(net).value; n.channel = c; ok(encode_network(n), "all source WifiChannel values");
            }
        });
        run("LDN six exact body types all prefixes", [&] {
            for (Byte type = 0; type < 6; ++type) {
                const auto& bytes = (type == 0 || type == 5) ? Bytes{} : (type == 2 || type == 4) ? node : net;
                auto r = decode_ldn(type, bytes); ok(r, "LDN type valid"); auto e = encode_ldn(r.value); ok(e, "LDN type encode"); expect(e.value == bytes, "LDN exact body");
                for (std::size_t p = 0; p < bytes.size(); ++p) expect(!decode_ldn(type, Input(bytes).first(p)), "LDN every prefix");
                auto extra = bytes; extra.push_back(0); error(decode_ldn(type, extra), Error::oversized, "LDN trailing exact-size");
            }
            for (unsigned type = 6; type <= 255; ++type) error(decode_ldn(static_cast<Byte>(type), {}), Error::invalid_enum, "unknown LDN type");
            LdnBody invalid; invalid.type = static_cast<LdnType>(255); error(encode_ldn(invalid), Error::invalid_enum, "encode unknown type");
        });
        run("Zstd independent hand raw frame and empty", [&] {
            auto d = decode_zstd_single(abc); ok(d, "hand raw zstd frame"); expect(d.value == Bytes({'a','b','c'}), "raw block golden decoded bytes");
            const auto empty = hex_io::parse("28 b5 2f fd 20 00 01 00 00"); auto e = decode_zstd_single(empty); ok(e, "valid empty distinct from error"); expect(e.value.empty(), "empty frame payload");
            auto own_empty = encode_zstd_default({}); ok(own_empty, "empty encode"); ok(decode_zstd_single(own_empty.value), "empty own decode");
        });
        run("Zstd Yuzu default call profile exact compatibility", [&] {
            std::mt19937 rng(0x13579); Bytes random(4096); for (auto& b : random) b = static_cast<Byte>(rng());
            for (const auto& payload : {Bytes{}, Bytes({'a','b','c'}), Bytes(65536, 0), random}) {
                const auto reference = yuzu_reference(payload); auto enc = encode_zstd_default(payload); ok(enc, "bounded encoder");
                expect(enc.value == reference, "byte-exact default encoder vs independent Yuzu-call reference on local zstd");
                auto dec = decode_zstd_single(reference); ok(dec, "accept Yuzu-call frame"); expect(dec.value == payload, "reference opaque bytes exact");
                for (std::size_t p = 0; p < reference.size(); ++p) expect(!decode_zstd_single(Input(reference).first(p)), "default frame every prefix");
            }
        });
        run("Zstd hostile frames and expansion limits", [&] {
            for (std::size_t p = 0; p < abc.size(); ++p) expect(!decode_zstd_single(Input(abc).first(p)), "raw frame every prefix");
            error(decode_zstd_single(hex_io::parse("00 00 00 00")), Error::invalid_zstd, "invalid magic");
            error(decode_zstd_single(hex_io::parse("28 b5 2f fd 20")), Error::invalid_zstd, "content size error");
            auto unknown = advanced_frame(Bytes({'a','b','c'}), false, false);
            expect(ZSTD_getFrameContentSize(unknown.data(), unknown.size()) == ZSTD_CONTENTSIZE_UNKNOWN, "independent unknown-size fixture verified");
            error(decode_zstd_single(unknown), Error::unknown_content_size, "unknown-size frame fail closed");
            error(decode_zstd_single(hex_io::parse("50 2a 4d 18 00 00 00 00")), Error::invalid_zstd, "skippable frame rejected");
            error(decode_zstd_single(hex_io::parse("28 b5 2f fd e0 00 00 00 00 00 01 00 00 01 00 00")), Error::limit_exceeded, "64bit declared content cap before allocation");
            const auto huge = yuzu_reference(Bytes(65537, 0)); error(decode_zstd_single(huge), Error::limit_exceeded, "small compressed frame expands max+1");
            error(decode_zstd_single(abc, {abc.size()-1, 64}), Error::limit_exceeded, "compressed cap");
            error(decode_zstd_single(abc, {64, 2}), Error::limit_exceeded, "decompressed cap");
            ok(decode_zstd_single(abc, {abc.size(), 3}), "exact resource boundaries");
            error(decode_zstd_single(abc, {hard_resource_cap+1, 3}), Error::limit_exceeded, "hard configurable cap");
            auto trailing = abc; trailing.push_back(0); error(decode_zstd_single(trailing), Error::trailing_data, "trailing junk");
            auto concatenated = abc; concatenated.insert(concatenated.end(), abc.begin(), abc.end()); error(decode_zstd_single(concatenated), Error::trailing_data, "multi-frame rejection");
            auto wrong_size = abc; wrong_size[5] = 2; expect(!decode_zstd_single(wrong_size), "mismatched frame content size");
            auto checksum = advanced_frame(Bytes({'a','b','c'}), true, true); ok(decode_zstd_single(checksum), "valid checksum frame"); checksum.back() ^= 1; error(decode_zstd_single(checksum), Error::invalid_zstd, "checksum error");
            error(encode_zstd_default(Bytes(65537, 0)), Error::limit_exceeded, "encoder input cap");
            error(encode_zstd_default(Bytes({'a'}), {0,64}), Error::limit_exceeded, "encoder compressed cap");
            error(encode_zstd_default({}, {hard_resource_cap+1,64}), Error::limit_exceeded, "encoder hard cap");
        });
        run("Hex input strict bounds", [&] {
            expect(hex_io::parse("aA 00\nff") == Bytes({0xAA,0,0xFF}), "hex whitespace/case");
            for (const auto& text : {std::string("a"),std::string("0x00"),std::string("gg")}) {
                bool threw = false; try { (void)hex_io::parse(text); } catch (const std::runtime_error&) { threw = true; } expect(threw, "malformed hex");
            }
            bool threw = false; try { (void)hex_io::parse("0001", 1); } catch (const std::runtime_error&) { threw = true; } expect(threw, "hex decoded cap");
        });
        run("Deterministic bounded parser mutations", [&] {
            std::mt19937 rng(0x4753); // Reproducible smoke-fuzz; not exhaustive, not a game trace.
            for (std::size_t i = 0; i < 5000; ++i) {
                auto b = net; const std::size_t at = rng() % b.size(); b[at] ^= static_cast<Byte>(1 + rng() % 255);
                auto d = decode_network(b); ++checks;
                if (d) { auto e = encode_network(d.value); ok(e, "accepted mutation encode"); expect(e.value == b, "accepted mutation preserves every byte"); }
            }
            for (std::size_t i = 0; i < 5000; ++i) {
                Bytes b(rng() % 1600); for (auto& x : b) x = static_cast<Byte>(rng());
                const auto u = decode_uds(b); const auto n = decode_node(b); const auto w = decode_network(b); const auto z = decode_zstd_single(b);
                expect(!u && !n && !w && !z, "seeded arbitrary input rejects all profiles");
            }
        });
        std::cout << "RESULT PASS cases=" << cases << " checks=" << checks << "\n"; return 0;
    } catch (const std::exception& e) {
        std::cerr << "RESULT FAIL completed_cases=" << cases << " checks=" << checks << " reason=" << e.what() << '\n'; return 1;
    }
}
