// SPDX-License-Identifier: GPL-2.0-or-later
// citra-gateway: G-b loopback gateway CLI.
//
// This program is a structural bridge only. It never claims that a real Yuzu
// client receives data or that a game is playable; see README.md and
// docs/citra-gateway-report.md for the three evidence tiers (A/B/C).
#include "citra_gateway/gateway.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <windows.h>

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) {
    g_stop.store(true);
}

// A Windows orchestrator that tears a run down with Stop-Process (TerminateProcess)
// cannot deliver SIGINT/SIGTERM, so it requests the same graceful exit by creating a
// stop file instead. Existence is the whole signal: a missing file is the normal case
// and must never be reported as an error or end the run.
bool stop_file_present(const std::string& path) {
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// D4: the host record identity a real MHXX host beacon advertises.  The captured
// reference beacon (docs/G4-UDS-BEACON-PROFILE-SPEC.md section 2.5) decodes UDS
// node 1 as seed 0x856d00022c01afe1 with the name "CITRA"; the before-D4 bridge
// published a present but anonymous host record.
citra_control::Username mhxx_host_username() {
    citra_control::Username name{};
    const char* text = "CITRA";
    for (std::size_t k = 0; k < name.size() && text[k] != '\0'; ++k) {
        name[k] = static_cast<std::uint16_t>(static_cast<unsigned char>(text[k]));
    }
    return name;
}

void usage() {
    std::cout
        << "citra-gateway - G-b/G-b' gateway (Citra v4 over ENet/UDP <-> Yuzu v1 room)\n"
        << "\n"
        << "usage: citra-gateway [options]\n"
        << "  --capabilities       standalone offline build-capability JSON (not runtime proof)\n"
        << "  --application-mode <legacy-transport|mhxx-mhgu> (MH mode unavailable)\n"
        << "  --proxy-profile <yuzu-mirror-01052024|yuzu-2022-7edc31be2> (2022 unavailable)\n"
        << "  --listen <ipv4>      loopback listen address (default 127.0.0.1)\n"
        << "  --listen-port <n>    ENet/UDP listen port for the Citra side (default 24873)\n"
        << "  --room <ipv4>        Yuzu room address (default 127.0.0.1)\n"
        << "  --room-port <n>      Yuzu room port (default 24872)\n"
        << "  --password <text>    room password (enforced locally, forwarded to the room)\n"
        << "  --room-capacity <n>  known member_slots for the local room-full check (0=unknown)\n"
        << "  --seconds <n>        run for n seconds then dump and exit (default 5)\n"
        << "  --max-clients <n>    accept at most n Citra ENet/UDP peers (default 254)\n"
        << "  --max-inbound-citra <n>\n"
        << "                       pre decode Citra frame cap in bytes (default 65536 = the\n"
        << "                       frozen codec packet_bytes). This is NOT Network::\n"
        << "                       MaxMessageSize; that 500 byte constant only bounds chat\n"
        << "                       bodies, and the codec enforces data_bytes=60000 itself.\n"
        << "  --dump <dir>         write counters/clients/identities/captures/events/emitted/\n"
        << "                       snapshot json into dir\n"
        << "  --stop-file <path>   exit gracefully (dump + snapshot) as soon as path exists;\n"
        << "                       polled once per tick, absent file is silently ignored.\n"
        << "                       Needed on Windows, where Stop-Process cannot deliver SIGINT.\n"
        << "  --ldn-dual-host      select Citra-host or GU-host role per live session;\n"
        << "                       requires control plane, full UDS profile and proxy port.\n"
        << "  --control-plane      enable the G-b' LDN/UDS control plane (one bridge per\n"
        << "                       joined Citra session; see docs/M4-CONTROL-PLANE.md 7)\n"
        << "  --ldn-comm-id <hex>  V-239: advertise this IntentId.local_communication_id\n"
        << "                       in LDN ScanResp/SyncNetwork instead of the derived\n"
        << "                       mix32 value.  A real Yuzu client filters ScanResp on\n"
        << "                       it (its own game id, e.g. 0100770008dd8000 for MHGU);\n"
        << "                       0 (default) keeps the derived value.\n"
        << "  --ldn-session <hex>  V-239: stable LDN session for the override path\n"
        << "                       (0 derives a non-zero per-room value; a zero session\n"
        << "                       never appears on a real AP).\n"
        << "  --ldn-advertise-hex <hex>\n"
        << "                       V-239: game advertise data carried in ScanResp/\n"
        << "                       SyncNetwork (at most 0x180 bytes).  MHGU lists a\n"
        << "                       hall only when this private structure is present;\n"
        << "                       measured template lives in\n"
        << "                       docs/MH-GU-REAL-TRAFFIC-MAPPING.md.\n"
        << "  --ldn-live-advertise / --no-ldn-live-advertise\n"
        << "  --ldn-gu-host-discovery Scan GU hosts and expose fresh XX hall beacons;\n"
        << "                       discovery only, no game admission yet.\n"
        << "  --ldn-gu-host-admission Enable reverse UDS/LDN association (requires\n"
        << "                       discovery); game protocol translation is separate.\n"
        << "  --ldn-require-live-hall  Hide the LDN hall until Citra advertises it;\n"
        << "                       no template fallback, reject stale hall connects.\n"
        << "                       V-267: carry the Citra peer's LIVE UDS beacon\n"
        << "                       application_data (the MHXX hall description; the\n"
        << "                       hall name sits at offset 52 as UTF-16LE) in LDN\n"
        << "                       ScanResp/SyncNetwork, so the Yuzu scan list shows\n"
        << "                       the hall MHXX really advertises instead of the\n"
        << "                       fixed --ldn-advertise-hex template.  On by\n"
        << "                       default; the template is only the fallback (no\n"
        << "                       decodable beacon yet, or none within\n"
        << "                       kCitraAppdataMaxAgeMs = 1500 ms).\n"
        << "                       --no-ldn-live-advertise keeps the pre-V-267\n"
        << "                       byte-for-byte behaviour.  The source of every LDN\n"
        << "                       body is counted (advertise_from_citra /\n"
        << "                       advertise_from_cli / advertise_empty).\n"
        << "  --ldn-announce-forward\n"
        << "                       V-259: translate the Citra peer's game-layer kind-0\n"
        << "                       session announce (MHXX hall advertisement) into the\n"
        << "                       Yuzu side word space and emit it as a room Proxy\n"
        << "                       packet, so MHGU can list the MHXX hall (V-258 root\n"
        << "                       cause).  Off by default; needs --control-plane, a\n"
        << "                       joined Citra peer, an admitted station and at least\n"
        << "                       one --ldn-identity-pair.  Rejections are counted\n"
        << "                       (announce_route_rejected / announce_no_identity_word\n"
        << "                       / announce_prereq_rejected / announce_pair_rejected).\n"
        << "  --ldn-game-return   experimental admitted-station MH return -> UDS\n"
        << "                       requires announce-forward, guest-inject and proxy-port\n"
        << "  --ldn-guest-inject\n"
        << "                       V-266: reverse UDS association injection.  After a\n"
        << "                       Yuzu station is admitted, present it to Citra as a\n"
        << "                       joining UDS guest (Authentication SEQ1, then\n"
        << "                       EAPoL-Start once Citra's AssociationResponse is\n"
        << "                       successful) and record the node id Citra assigns in\n"
        << "                       its EAPoL-Logoff, so Citra's nwm_uds node_map gains\n"
        << "                       the entry MHXX needs before it produces Pia bytes.\n"
        << "                       Off by default; needs --control-plane, and only arms\n"
        << "                       after the Citra peer beacons (evidence that it hosts\n"
        << "                       the UDS network).  Every advance and failure is\n"
        << "                       counted (guest_inject_*).\n"
        << "  --ldn-identity-pair <xxword:guword>\n"
        << "                       V-259: 8+8 hex digit identity word pair used by the\n"
        << "                       announce forward (e.g. b35ee27f:c0a8022f, the measured\n"
        << "                       MHXX host word and MHGU host word).  Repeatable, at\n"
        << "                       most four pairs; a self-mapped or duplicated source\n"
        << "                       word is a usage error.\n"
        << "  --ldn-proxy-port <port>\n"
        << "                       V-272: UDP port stamped on every translated Proxy\n"
        << "                       packet.  The Yuzu ProxySocket drops a packet whose\n"
        << "                       remote port differs from its own local port, and\n"
        << "                       MHGU binds 12345.  Default 0 keeps the old\n"
        << "                       placeholder behaviour.\n"
        << "  --citra-peer-relay   V-047/V-048: transport-only passthrough for Citra<->Citra\n"
        << "                       sessions. Forward every Citra WifiPacket type unchanged\n"
        << "                       (Beacon/Authentication/NodeMap included), like the dumb\n"
        << "                       citra-room.exe relay instead of dropping non-Data frames.\n"
        << "                       Mutually exclusive with --control-plane.\n"
        << "  --emitted-limit <n>  cap on the G-b' emitted frame log (default 256)\n"
        << "  --uds-profile <name> V-111 UDS beacon identity profile for the synthesized\n"
        << "                       Citra Beacon. 'mhxx' = what a real MHXX host advertises:\n"
        << "                       wlan-comm-id 00197110, id 00, attributes 8000,\n"
        << "                       network-id 00000000, tag-word 0001, wifi-channel 11.\n"
        << "                       Off by default; without it the beacon bytes are exactly\n"
        << "                       what G3/D2/D3 recorded.\n"
        << "  --uds-wlan-comm-id <hex>  --uds-id <hex>  --uds-attributes <hex>\n"
        << "  --uds-network-id <hex>    --uds-tag-word <hex>  --uds-wifi-channel <n>\n"
        << "                       single field overrides of the profile above (hex values)\n"
        << "  --uds-appdata <hex>  beacon application data (<=200 bytes), or\n"
        << "  --uds-appdata-file <path>  the same read as hex text from a file\n"
        << "  --uds-host-seed <hex>  --uds-host-username <ascii>\n"
        << "                       identity the synthesized host record (UDS node 1)\n"
        << "                       advertises; the 'mhxx' profile sets the captured\n"
        << "                       values (seed 856d00022c01afe1, name CITRA)\n"
        << "  --game-script <path>  V-112 synthetic-host game-layer replay. One step per\n"
        << "                       line: <after_guest_frames> <delay_ms> <bc|guest> <hex>,\n"
        << "                       where the hex is the UDS payload of a captured host\n"
        << "                       frame (LLC + Nintendo SecureData header + payload,\n"
        << "                       without Citra's 19 byte room header). after_guest_frames\n"
        << "                       is 0 for 'after the guest is Connected' or N for 'after\n"
        << "                       the N-th game-layer frame from the guest'. A '# nonce-ref\n"
        << "                       <8 hex>' header records the guest nonce the captured\n"
        << "                       session used, so the replay can echo the live guest's own\n"
        << "                       value instead (V-132). Repeatable '# token-ref <8 hex>\n"
        << "                       <game_length>:<offset>...' headers cover the other\n"
        << "                       guest-chosen session tokens: a site names a guest frame in\n"
        << "                       which the guest announces its live value, and every step\n"
        << "                       carrying the captured value waits for it (V-133).\n"
        << "                       Empty/off by default; see\n"
        << "                       docs/G4-UDS-BEACON-PROFILE-SPEC.md section 4.\n"
        << "  --trace-out <path>   write the G2 trace (channels A/B/C) as JSON Lines to path\n"
        << "                       (keep it outside the repo); off by default; the run refuses\n"
        << "                       to start if the file cannot be opened. A run with zero\n"
        << "                       frames still writes one self-describing run.begin record.\n"
        << "  --trace-raw          also embed each frame's raw bytes as hex in the trace\n"
        << "  --trace-channel <c>  A, B or C run channel in the trace identity (default C)\n"
        << "  --trace-manifest <s> manifest_id in every trace line (default citra-gateway)\n"
        << "  --trace-build <s>    build_id in every trace line (default citra-gateway/g2-trace-1)\n"
        << "  --trace-role <r>     host or client in every trace line (default host)\n"
        << "  --trace-stage-file <f>\n"
        << "                       scenario stage file: read at open and once per tick; a content\n"
        << "                       change appends one stage.begin marker and stamps later lines.\n"
        << "                       The effective trace identity is printed on stdout.\n"
        << "  --quiet              do not print per-second status\n"
        << "  --self-check         run the offline structural self checks and exit\n"
        << "  --help               print this text\n"
        << "\n"
        << "Citra side transport: the gateway is an ENet/UDP server on --listen/--listen-port\n"
        << "with one channel, exactly like a real room server (V-027/V-028). Each packet is\n"
        << "one raw citra_room v4 message (data[0] is the message id, no length prefix). The\n"
        << "old TCP + 4-byte length-prefix framing is reachable only from the acceptance\n"
        << "test harness, never from this binary.\n"
        << "\n"
        << "exit codes: 0 ok, 2 usage error, 3 open failure (port conflict / non loopback)\n";
}

bool take_value(const std::vector<std::string>& args, std::size_t& i, const char* name,
                std::string& out) {
    if (i + 1 >= args.size()) {
        std::cerr << "missing value for " << name << "\n";
        return false;
    }
    out = args[++i];
    return true;
}

std::uint64_t parse_u64(const std::string& text, bool& ok) {
    ok = false;
    if (text.empty()) {
        return 0;
    }
    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            return 0;
        }
        value = value * 10 + static_cast<std::uint64_t>(c - '0');
    }
    ok = true;
    return value;
}

// V-111: the UDS beacon profile values are copied out of captures, so they are
// read as plain hex (no 0x prefix, at most 16 digits).  Nothing here accepts a
// decimal value: every field is a wire byte pattern, not a quantity.
std::uint64_t parse_hex_u64(const std::string& text, bool& ok) {
    ok = false;
    if (text.empty() || text.size() > 16) {
        return 0;
    }
    std::uint64_t value = 0;
    for (const char c : text) {
        int digit = -1;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            digit = c - 'A' + 10;
        } else {
            return 0;
        }
        value = (value << 4) | static_cast<std::uint64_t>(digit);
    }
    ok = true;
    return value;
}

// Even-length hex (whitespace and line breaks allowed) into bytes.
bool parse_hex_bytes(const std::string& text, std::vector<std::uint8_t>& out) {
    std::string clean;
    for (const char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }
        clean.push_back(c);
    }
    if (clean.size() % 2 != 0) {
        return false;
    }
    out.clear();
    for (std::size_t i = 0; i < clean.size(); i += 2) {
        bool ok = false;
        const std::uint64_t byte = parse_hex_u64(clean.substr(i, 2), ok);
        if (!ok) {
            return false;
        }
        out.push_back(static_cast<std::uint8_t>(byte));
    }
    return true;
}

int self_check() {
    using citra_gateway::Options;
    int cases = 0;
    int failed = 0;
    const auto check = [&](bool ok, const char* name) {
        ++cases;
        if (!ok) {
            ++failed;
            std::cout << "FAIL " << name << "\n";
        } else {
            std::cout << "PASS " << cases << " " << name << "\n";
        }
    };

    const citra_room::MacAddress sentinel{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const citra_room::MacAddress nintendo{0x00, 0x1F, 0x32, 0x11, 0x22, 0x33};
    check(citra_gateway::is_sentinel_mac(sentinel), "sentinel mac detected");
    check(!citra_gateway::is_sentinel_mac(nintendo), "normal mac is not a sentinel");
    check(citra_gateway::is_valid_mac_address(nintendo), "nintendo oui accepted by the oui test");
    check(!citra_gateway::is_valid_mac_address(sentinel), "sentinel mac fails the oui test");
    check(citra_gateway::is_sentinel_ip(room_client::no_preferred_ip), "sentinel ip detected");
    check(citra_gateway::mac_to_string(nintendo) == "00:1f:32:11:22:33", "mac formatting");
    check(citra_gateway::ip_to_string(room_client::IPv4{192, 168, 1, 7}) == "192.168.1.7",
          "ip formatting");

    citra_gateway::IdentityTable table;
    const auto first_ip = table.next_free_fake_ip();
    check(first_ip.has_value() && citra_gateway::ip_to_string(*first_ip) == "192.168.1.1",
          "first generated fake ip");
    check(table.insert(nintendo, *first_ip, "Alpha"), "identity insert");
    check(table.insert(nintendo, *first_ip, "Alpha") == false, "duplicate mac rejected");
    check(table.has_ip(*first_ip) && table.mac_for_ip(*first_ip).has_value() &&
              citra_gateway::mac_to_string(*table.mac_for_ip(*first_ip)) == "00:1f:32:11:22:33",
          "identity reverse lookup");
    check(!table.insert(sentinel, room_client::IPv4{192, 168, 1, 9}, "X"),
          "sentinel mac never enters the table");
    table.erase_mac(nintendo);
    check(table.empty(), "identity erase");

    const citra_room::Bytes plain{'G', 'a', 't', 'e', 'w', 'a', 'y', ' ', 'o', 'p', 'a', 'q', 'u',
                                  'e'};
    room_client::Bytes frame;
    std::string why;
    check(citra_gateway::compress_proxy_frame(plain, 65536, 1, frame, &why),
          "zstd compress single frame");
    check(citra_gateway::valid_proxy_frame(frame, 65536, 65536, &why),
          "compressed frame passes the fail-closed gate");
    citra_room::Bytes back;
    check(citra_gateway::decompress_proxy_frame(frame, 65536, back, &why) && back == plain,
          "round trip byte identical");
    room_client::Bytes raw{'n', 'o', 't', 'z', 's', 't', 'd'};
    check(!citra_gateway::valid_proxy_frame(raw, 65536, 65536, &why), "non zstd frame rejected");
    room_client::Bytes truncated(frame.begin(), frame.end() - 1);
    check(!citra_gateway::valid_proxy_frame(truncated, 65536, 65536, &why),
          "truncated zstd frame rejected");
    room_client::Bytes concatenated = frame;
    concatenated.insert(concatenated.end(), frame.begin(), frame.end());
    check(!citra_gateway::valid_proxy_frame(concatenated, 65536, 65536, &why),
          "concatenated zstd frames rejected");
    check(!citra_gateway::valid_proxy_frame(frame, 4, 65536, &why), "compressed cap enforced");
    check(!citra_gateway::valid_proxy_frame(frame, 65536, 2, &why), "decompressed cap enforced");

    std::cout << "RESULT self-check cases=" << cases << " failed=" << failed << "\n";
    return failed == 0 ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (std::find(args.begin(), args.end(), "--capabilities") != args.end()) {
        if (args.size() != 1) {
            std::cerr << "--capabilities must be used alone\n";
            return 2;
        }
        std::cout << citra_gateway::gateway_capabilities_json << "\n";
        return 0;
    }
    citra_gateway::Options options;
    bool application_mode_seen = false;
    bool proxy_profile_seen = false;
    std::string password;
    std::string dump_dir;
    std::string stop_file;
    std::string trace_channel;
    std::string trace_manifest;
    std::string trace_build;
    std::string trace_role;
    unsigned seconds = 5;
    bool quiet = false;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "--help" || a == "-h") {
            usage();
            return 0;
        }
        if (a == "--self-check") {
            return self_check();
        }
        if (a == "--application-mode") {
            std::string value;
            if (application_mode_seen || !take_value(args, i, "--application-mode", value)) return 2;
            application_mode_seen = true;
            if (value == "legacy-transport") options.application_mode = citra_gateway::ApplicationMode::LegacyTransport;
            else if (value == "mhxx-mhgu") options.application_mode = citra_gateway::ApplicationMode::MhxxMhgu;
            else { std::cerr << "unknown application mode\n"; return 2; }
            continue;
        }
        if (a == "--proxy-profile") {
            std::string value;
            if (proxy_profile_seen || !take_value(args, i, "--proxy-profile", value)) return 2;
            proxy_profile_seen = true;
            if (value == "yuzu-mirror-01052024") options.proxy_wire_profile = citra_gateway::ProxyWireProfile::Mirror01052024;
            else if (value == "yuzu-2022-7edc31be2") options.proxy_wire_profile = citra_gateway::ProxyWireProfile::Yuzu2022;
            else { std::cerr << "unknown proxy profile\n"; return 2; }
            continue;
        }
        if (a == "--quiet") {
            quiet = true;
            continue;
        }
        if (a == "--control-plane") {
            options.control_plane_enabled = true;
            continue;
        }
        if (a == "--ldn-live-advertise") {
            options.ldn_live_advertise = true;
            continue;
        }
        if (a == "--no-ldn-live-advertise") {
            options.ldn_live_advertise = false;
            continue;
        }
        if (a == "--ldn-require-live-hall") {
            options.ldn_require_live_hall = true;
            continue;
        }
        if (a == "--ldn-dual-host") {
            options.ldn_dual_host = true;
            continue;
        }
        if (a == "--ldn-gu-host-discovery") {
            options.ldn_gu_host_discovery = true;
            continue;
        }
        if (a == "--ldn-gu-host-admission") {
            options.ldn_gu_host_admission = true;
            continue;
        }
        if (a == "--ldn-announce-forward") {
            options.ldn_announce_forward = true;
            continue;
        }
        if (a == "--ldn-game-return") {
            options.ldn_game_return = true;
            continue;
        }
        if (a == "--ldn-guest-inject") {
            options.ldn_guest_inject = true;
            continue;
        }
        if (a == "--ldn-proxy-port") {
            std::string raw;
            if (!take_value(args, i, a.c_str(), raw)) {
                return 2;
            }
            std::uint32_t value = 0;
            bool valid = !raw.empty();
            for (const char c : raw) {
                if (c < '0' || c > '9') {
                    valid = false;
                    break;
                }
                // Each previous step is <=65535, so this cannot overflow.
                value = value * 10 + static_cast<std::uint32_t>(c - '0');
                if (value > 65535) {
                    valid = false;
                    break;
                }
            }
            if (!valid || value == 0) {
                std::cerr << "--ldn-proxy-port must be ASCII decimal digits in 1..65535\n";
                return 2;
            }
            options.proxy_udp_port = static_cast<std::uint16_t>(value);
            continue;
        }
        if (a == "--ldn-identity-pair") {
            std::string raw;
            if (!take_value(args, i, a.c_str(), raw)) {
                return 2;
            }
            const std::size_t colon = raw.find(':');
            if (colon == std::string::npos || raw.size() - colon - 1 != 8 || colon != 8) {
                std::cerr << "identity pair must be xxword:guword (8+8 hex digits)";
                return 2;
            }
            bool hex_ok = false;
            const std::uint64_t xx = parse_hex_u64(raw.substr(0, 8), hex_ok);
            if (!hex_ok) { std::cerr << "bad xx word"; return 2; }
            const std::uint64_t gu = parse_hex_u64(raw.substr(9, 8), hex_ok);
            if (!hex_ok) { std::cerr << "bad gu word"; return 2; }
            citra_gateway::Options::LdnIdentityPair pair{};
            pair.xx_word = {static_cast<std::uint8_t>((xx >> 24) & 0xff),
                            static_cast<std::uint8_t>((xx >> 16) & 0xff),
                            static_cast<std::uint8_t>((xx >> 8) & 0xff),
                            static_cast<std::uint8_t>(xx & 0xff)};
            pair.gu_word = {static_cast<std::uint8_t>((gu >> 24) & 0xff),
                            static_cast<std::uint8_t>((gu >> 16) & 0xff),
                            static_cast<std::uint8_t>((gu >> 8) & 0xff),
                            static_cast<std::uint8_t>(gu & 0xff)};
            // V-259: the V-249 primitive refuses an ambiguous table, so the CLI
            // must too -- a pair that maps a word onto itself, or a second pair
            // reusing the same "from" word, is a usage error, not a warning.
            if (pair.xx_word == pair.gu_word) {
                std::cerr << "identity pair must differ: " << raw << "\n";
                return 2;
            }
            for (const auto& existing : options.ldn_identity_pairs) {
                if (existing.xx_word == pair.xx_word) {
                    std::cerr << "duplicate identity pair source: " << raw << "\n";
                    return 2;
                }
            }
            options.ldn_identity_pairs.push_back(pair);
            continue;
        }
        if (a == "--ldn-comm-id" || a == "--ldn-session") {
            std::string raw;
            if (!take_value(args, i, a.c_str(), raw)) {
                return 2;
            }
            bool hex_ok = false;
            const std::uint64_t parsed = parse_hex_u64(raw, hex_ok);
            if (!hex_ok) {
                std::cerr << "not a hex value: " << raw << "\n";
                return 2;
            }
            if (a == "--ldn-comm-id") {
                options.ldn_comm_id_override = parsed;
            } else {
                options.ldn_session_id = parsed;
            }
            continue;
        }
        if (a == "--ldn-advertise-hex") {
            std::string raw;
            if (!take_value(args, i, a.c_str(), raw)) {
                return 2;
            }
            if (raw.size() % 2 != 0 || raw.size() > 2 * 0x180) {
                std::cerr << "ldn advertise hex must be even and at most 768 digits\n";
                return 2;
            }
            std::vector<std::uint8_t> ad;
            for (std::size_t pos = 0; pos < raw.size(); pos += 2) {
                const std::string byte = raw.substr(pos, 2);
                ad.push_back(static_cast<std::uint8_t>(std::stoul(byte, nullptr, 16)));
            }
            options.ldn_advertise_data = std::move(ad);
            continue;
        }
        if (a == "--citra-peer-relay") {
            options.citra_peer_relay = true;
            continue;
        }
        if (a == "--listen") {
            if (!take_value(args, i, "--listen", options.listen_address)) {
                return 2;
            }
            continue;
        }
        if (a == "--room") {
            if (!take_value(args, i, "--room", options.room_address)) {
                return 2;
            }
            continue;
        }
        if (a == "--password") {
            if (!take_value(args, i, "--password", password)) {
                return 2;
            }
            continue;
        }
        if (a == "--dump") {
            if (!take_value(args, i, "--dump", dump_dir)) {
                return 2;
            }
            continue;
        }
        if (a == "--stop-file") {
            if (!take_value(args, i, "--stop-file", stop_file)) {
                return 2;
            }
            if (stop_file.empty()) {
                std::cerr << "empty --stop-file path\n";
                return 2;
            }
            continue;
        }
        if (a == "--trace-out") {
            if (!take_value(args, i, "--trace-out", options.trace_path)) {
                return 2;
            }
            if (options.trace_path.empty()) {
                std::cerr << "empty --trace-out path\n";
                return 2;
            }
            continue;
        }
        if (a == "--trace-raw") {
            options.trace_raw = true;
            continue;
        }
        if (a == "--trace-channel") {
            if (!take_value(args, i, "--trace-channel", trace_channel)) {
                return 2;
            }
            if (trace_channel != "A" && trace_channel != "B" && trace_channel != "C") {
                std::cerr << "--trace-channel must be A, B or C\n";
                return 2;
            }
            continue;
        }
        if (a == "--trace-manifest") {
            if (!take_value(args, i, "--trace-manifest", trace_manifest) ||
                trace_manifest.empty()) {
                std::cerr << "empty --trace-manifest value\n";
                return 2;
            }
            continue;
        }
        if (a == "--trace-build") {
            if (!take_value(args, i, "--trace-build", trace_build) || trace_build.empty()) {
                std::cerr << "empty --trace-build value\n";
                return 2;
            }
            continue;
        }
        if (a == "--trace-role") {
            if (!take_value(args, i, "--trace-role", trace_role)) {
                return 2;
            }
            if (trace_role != "host" && trace_role != "client") {
                std::cerr << "--trace-role must be host or client\n";
                return 2;
            }
            continue;
        }
        if (a == "--trace-stage-file") {
            if (!take_value(args, i, "--trace-stage-file", options.trace_stage_file) ||
                options.trace_stage_file.empty()) {
                std::cerr << "empty --trace-stage-file path\n";
                return 2;
            }
            continue;
        }
        if (a == "--uds-profile") {
            std::string name;
            if (!take_value(args, i, "--uds-profile", name) || name.empty()) {
                return 2;
            }
            if (name != "mhxx") {
                std::cerr << "unknown --uds-profile: " << name << " (known: mhxx)\n";
                return 2;
            }
            // Every value below is the constant a real MHXX host beacon carries
            // (V-111, docs/G4-UDS-BEACON-PROFILE-SPEC.md, section 2).
            options.uds_wlan_comm_id = 0x00197110u;
            options.have_uds_wlan_comm_id = true;
            options.uds_beacon_id = 0;
            options.have_uds_beacon_id = true;
            options.uds_attributes = 0x8000;
            options.have_uds_attributes = true;
            options.uds_network_id = 0;
            options.have_uds_network_id = true;
            options.uds_tag_word = 0x0001;
            options.have_uds_tag_word = true;
            options.uds_wifi_channel = 11;
            options.have_uds_wifi_channel = true;
            // D4: the host record's advertised identity, captured from a real
            // MHXX host beacon (spec section 2.5).
            options.uds_host_seed = 0x856d00022c01afe1ull;
            options.have_uds_host_seed = true;
            options.uds_host_username = mhxx_host_username();
            options.have_uds_host_username = true;
            continue;
        }
        if (a == "--uds-appdata" || a == "--uds-appdata-file") {
            std::string raw;
            if (!take_value(args, i, a.c_str(), raw)) {
                return 2;
            }
            std::string text = raw;
            if (a == "--uds-appdata-file") {
                std::ifstream file(raw, std::ios::binary);
                if (!file) {
                    std::cerr << "cannot read --uds-appdata-file: " << raw << "\n";
                    return 2;
                }
                text.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
            }
            std::vector<std::uint8_t> bytes;
            if (!parse_hex_bytes(text, bytes) ||
                bytes.size() > citra_control::kApplicationDataSize) {
                std::cerr << "bad UDS appdata (even length hex, at most "
                          << citra_control::kApplicationDataSize << " bytes)\n";
                return 2;
            }
            options.uds_appdata = bytes;
            options.have_uds_appdata = true;
            continue;
        }
        if (a == "--uds-host-seed" || a == "--uds-host-username") {
            std::string raw;
            if (!take_value(args, i, a.c_str(), raw)) {
                return 2;
            }
            if (a == "--uds-host-seed") {
                bool hex_ok = false;
                const std::uint64_t parsed = parse_hex_u64(raw, hex_ok);
                if (!hex_ok) {
                    std::cerr << "not a hex value: " << raw << "\n";
                    return 2;
                }
                options.uds_host_seed = parsed;
                options.have_uds_host_seed = true;
            } else {
                citra_control::Username name{};
                if (raw.empty() || raw.size() > name.size()) {
                    std::cerr << "--uds-host-username takes 1.."
                              << name.size() << " characters\n";
                    return 2;
                }
                for (std::size_t k = 0; k < raw.size(); ++k) {
                    const unsigned char ch = static_cast<unsigned char>(raw[k]);
                    if (ch < 0x20 || ch > 0x7E) {
                        std::cerr << "--uds-host-username must be printable ASCII\n";
                        return 2;
                    }
                    name[k] = static_cast<std::uint16_t>(ch);
                }
                options.uds_host_username = name;
                options.have_uds_host_username = true;
            }
            continue;
        }
        if (a == "--game-script") {
            std::string path;
            if (!take_value(args, i, "--game-script", path) || path.empty()) {
                std::cerr << "empty --game-script path\n";
                return 2;
            }
            std::ifstream file(path);
            if (!file) {
                std::cerr << "cannot read --game-script: " << path << "\n";
                return 2;
            }
            const auto parse_dec = [](const std::string& text, std::uint64_t& out) {
                if (text.empty()) {
                    return false;
                }
                std::uint64_t value = 0;
                for (const char c : text) {
                    if (c < '0' || c > '9') {
                        return false;
                    }
                    value = value * 10 + static_cast<std::uint64_t>(c - '0');
                    if (value > 0xFFFFFFFFull) {
                        return false;
                    }
                }
                out = value;
                return true;
            };
            bool have_nonce_ref = false;
            std::uint32_t nonce_ref = 0;
            std::vector<citra_gateway::Options::GameTokenRef> token_refs;
            std::string line;
            std::size_t line_no = 0;
            while (std::getline(file, line)) {
                ++line_no;
                const std::size_t comment = line.find('#');
                if (comment != std::string::npos) {
                    // V-132: "# nonce-ref <8 hex>" is a directive, not a plain
                    // comment: it records the guest-chosen nonce family value the
                    // captured session echoed, so the replay can substitute the
                    // live guest's value.
                    std::istringstream directive(line.substr(comment + 1));
                    std::string word;
                    // V-133a: read the directive keyword exactly once.  The old
                    // code re-read it for the second directive, so a "# token-ref"
                    // line compared the *value* against the keyword and was then
                    // silently treated as a plain comment (gc10 found this on the
                    // live run: game_script_tokens_learned stayed 0).
                    const bool have_word = static_cast<bool>(directive >> word);
                    if (have_word && word == "nonce-ref") {
                        std::string value_text;
                        std::vector<std::uint8_t> value_bytes;
                        if (!(directive >> value_text) ||
                            !parse_hex_bytes(value_text, value_bytes) ||
                            value_bytes.size() != 4) {
                            std::cerr << "--game-script line " << line_no
                                      << ": '# nonce-ref' needs 8 hexadecimal digits\n";
                            return 2;
                        }
                        nonce_ref = (static_cast<std::uint32_t>(value_bytes[0]) << 24) |
                                    (static_cast<std::uint32_t>(value_bytes[1]) << 16) |
                                    (static_cast<std::uint32_t>(value_bytes[2]) << 8) |
                                    static_cast<std::uint32_t>(value_bytes[3]);
                        have_nonce_ref = true;
                        continue;
                    }
                    // V-133: "# token-ref <8 hex> <game_length>:<offset> ..." names
                    // another captured guest-chosen session token (C, D) and the
                    // guest-frame sites that announce its live value.
                    if (have_word && word == "token-ref") {
                        std::string token_text;
                        std::vector<std::uint8_t> token_bytes;
                        if (!(directive >> token_text) ||
                            !parse_hex_bytes(token_text, token_bytes) ||
                            token_bytes.size() != 4) {
                            std::cerr << "--game-script line " << line_no
                                      << ": '# token-ref' needs 8 hexadecimal digits\n";
                            return 2;
                        }
                        citra_gateway::Options::GameTokenRef token;
                        token.ref = (static_cast<std::uint32_t>(token_bytes[0]) << 24) |
                                    (static_cast<std::uint32_t>(token_bytes[1]) << 16) |
                                    (static_cast<std::uint32_t>(token_bytes[2]) << 8) |
                                    static_cast<std::uint32_t>(token_bytes[3]);
                        std::string site_text;
                        while (directive >> site_text) {
                            const std::size_t colon = site_text.find(':');
                            std::uint64_t game_length = 0;
                            std::uint64_t site_offset = 0;
                            if (colon == std::string::npos ||
                                !parse_dec(site_text.substr(0, colon), game_length) ||
                                !parse_dec(site_text.substr(colon + 1), site_offset) ||
                                game_length > 0xFFFFull || site_offset + 4 > game_length) {
                                std::cerr
                                    << "--game-script line " << line_no
                                    << ": '# token-ref' learn site must be "
                                       "<game_length>:<offset> with offset + 4 <= game_length\n";
                                return 2;
                            }
                            token.learn_sites.emplace_back(
                                static_cast<std::size_t>(game_length),
                                static_cast<std::size_t>(site_offset));
                        }
                        if (token.learn_sites.empty()) {
                            std::cerr << "--game-script line " << line_no
                                      << ": '# token-ref' needs at least one "
                                         "<game_length>:<offset> learn site\n";
                            return 2;
                        }
                        token_refs.push_back(token);
                        continue;
                    }
                    line.erase(comment);
                }
                std::istringstream fields(line);
                std::string trigger_text;
                if (!(fields >> trigger_text)) {
                    continue; // blank line
                }
                std::string delay_text;
                std::string dest;
                std::string hex;
                if (!(fields >> delay_text >> dest >> hex)) {
                    std::cerr << "--game-script line " << line_no
                              << ": expected <after_guest_frames> <delay_ms> <bc|guest> <hex>\n";
                    return 2;
                }
                citra_gateway::Options::GameScriptStep step;
                std::uint64_t trigger = 0;
                std::uint64_t delay = 0;
                if (!parse_dec(trigger_text, trigger) || !parse_dec(delay_text, delay)) {
                    std::cerr << "--game-script line " << line_no
                              << ": trigger and delay are decimal integers\n";
                    return 2;
                }
                if (dest == "bc" || dest == "broadcast") {
                    step.broadcast = true;
                } else if (dest == "guest" || dest == "client") {
                    step.broadcast = false;
                } else {
                    std::cerr << "--game-script line " << line_no
                              << ": destination must be bc or guest\n";
                    return 2;
                }
                if (!parse_hex_bytes(hex, step.payload) || step.payload.empty()) {
                    std::cerr << "--game-script line " << line_no
                              << ": payload must be non-empty even-length hex\n";
                    return 2;
                }
                step.after_guest_frames = static_cast<std::uint32_t>(trigger);
                step.delay_ms = static_cast<std::uint32_t>(delay);
                step.label = std::to_string(line_no) + "@" + dest + ":" +
                             std::to_string(step.payload.size());
                options.game_script.push_back(step);
            }
            if (options.game_script.empty()) {
                std::cerr << "--game-script has no steps: " << path << "\n";
                return 2;
            }
            options.have_game_nonce_ref = have_nonce_ref;
            options.game_nonce_ref = nonce_ref;
            options.game_token_refs = token_refs;
            continue;
        }
        if (a == "--uds-wlan-comm-id" || a == "--uds-id" || a == "--uds-attributes" ||
            a == "--uds-network-id" || a == "--uds-tag-word" || a == "--uds-wifi-channel") {
            std::string raw;
            if (!take_value(args, i, a.c_str(), raw)) {
                return 2;
            }
            bool hex_ok = false;
            const std::uint64_t parsed = parse_hex_u64(raw, hex_ok);
            if (!hex_ok) {
                std::cerr << "not a hex value: " << raw << "\n";
                return 2;
            }
            if (a == "--uds-wlan-comm-id") {
                if (parsed > 0xFFFFFFFFull) {
                    std::cerr << "uds wlan comm id out of range: " << raw << "\n";
                    return 2;
                }
                options.uds_wlan_comm_id = static_cast<std::uint32_t>(parsed);
                options.have_uds_wlan_comm_id = true;
            } else if (a == "--uds-id") {
                if (parsed > 0xFF) {
                    std::cerr << "uds id out of range: " << raw << "\n";
                    return 2;
                }
                options.uds_beacon_id = static_cast<std::uint8_t>(parsed);
                options.have_uds_beacon_id = true;
            } else if (a == "--uds-attributes" || a == "--uds-tag-word") {
                if (parsed > 0xFFFF) {
                    std::cerr << a << " out of range: " << raw << "\n";
                    return 2;
                }
                if (a == "--uds-attributes") {
                    options.uds_attributes = static_cast<std::uint16_t>(parsed);
                    options.have_uds_attributes = true;
                } else {
                    options.uds_tag_word = static_cast<std::uint16_t>(parsed);
                    options.have_uds_tag_word = true;
                }
            } else if (a == "--uds-network-id") {
                if (parsed > 0xFFFFFFFFull) {
                    std::cerr << "uds network id out of range: " << raw << "\n";
                    return 2;
                }
                options.uds_network_id = static_cast<std::uint32_t>(parsed);
                options.have_uds_network_id = true;
            } else {
                if (parsed > 255) {
                    std::cerr << "uds wifi channel out of range: " << raw << "\n";
                    return 2;
                }
                options.uds_wifi_channel = static_cast<std::uint16_t>(parsed);
                options.have_uds_wifi_channel = true;
            }
            continue;
        }
        bool number_ok = false;
        std::string value;
        if (a == "--listen-port" || a == "--room-port" || a == "--seconds" ||
            a == "--max-clients" || a == "--room-capacity" || a == "--max-inbound-citra" ||
            a == "--emitted-limit") {
            if (!take_value(args, i, a.c_str(), value)) {
                return 2;
            }
            const std::uint64_t parsed = parse_u64(value, number_ok);
            if (!number_ok) {
                std::cerr << "not a number: " << value << "\n";
                return 2;
            }
            if (a == "--listen-port") {
                if (parsed == 0 || parsed > 65535) {
                    std::cerr << "listen port out of range: " << value << "\n";
                    return 2;
                }
                options.listen_port = static_cast<std::uint16_t>(parsed);
            } else if (a == "--room-port") {
                if (parsed == 0 || parsed > 65535) {
                    std::cerr << "room port out of range: " << value << "\n";
                    return 2;
                }
                options.room_port = static_cast<std::uint16_t>(parsed);
            } else if (a == "--seconds") {
                seconds = static_cast<unsigned>(parsed);
            } else if (a == "--room-capacity") {
                if (parsed > 65535) {
                    std::cerr << "room capacity out of range: " << value << "\n";
                    return 2;
                }
                options.room_capacity = static_cast<std::uint32_t>(parsed);
            } else if (a == "--emitted-limit") {
                if (parsed == 0 || parsed > 65536) {
                    std::cerr << "emitted limit out of range (1..65536): " << value << "\n";
                    return 2;
                }
                options.emitted_limit = static_cast<std::size_t>(parsed);
            } else if (a == "--max-inbound-citra") {
                if (parsed == 0 || parsed > 65536) {
                    std::cerr << "max inbound citra frame out of range (1..65536): " << value
                              << "\n";
                    return 2;
                }
                options.max_inbound_citra_bytes = static_cast<std::size_t>(parsed);
            } else {
                options.max_clients = static_cast<std::size_t>(parsed);
            }
            continue;
        }
        std::cerr << "unknown argument: " << a << "\n";
        usage();
        return 2;
    }

    if (const char* error = citra_gateway::gateway_capability_error(options.application_mode, options.proxy_wire_profile)) {
        std::cerr << error << "\n";
        return 2;
    }

    // V-016l: the gateway enforces the room password itself (same order as the
    // Citra server). The parsed value is still forwarded in the v1 join request.
    options.room_password = password;

    if (options.trace_raw && options.trace_path.empty()) {
        std::cerr << "--trace-raw requires --trace-out\n";
        return 2;
    }

    if (options.ldn_dual_host) {
        if (!options.control_plane_enabled || options.ldn_comm_id_override == 0 ||
            !options.have_uds_wlan_comm_id || !options.have_uds_beacon_id ||
            !options.have_uds_attributes || !options.have_uds_network_id ||
            !options.have_uds_tag_word || options.proxy_udp_port == 0) {
            std::cerr << "--ldn-dual-host requires --control-plane, --ldn-comm-id, full UDS identity profile and --ldn-proxy-port\n";
            return 2;
        }
        options.ldn_gu_host_discovery = options.ldn_gu_host_admission = true;
        options.ldn_require_live_hall = options.ldn_announce_forward = true;
        options.ldn_guest_inject = options.ldn_game_return = true;
    }

    // Peer relay and the control plane describe two different topologies: the
    // relay forwards the peer control plane verbatim for Citra<->Citra, while
    // --control-plane terminates it in a per-session bridge for Citra<->Yuzu.
    // Running both at once has no defined meaning, so refuse it as a usage error.
    if (options.citra_peer_relay && options.control_plane_enabled) {
        std::cerr << "--citra-peer-relay and --control-plane are mutually exclusive\n";
        return 2;
    }

    // V-260: the announce forward is implemented inside the control-plane
    // bridge, so without --control-plane it would simply never run and leave
    // announce_forwarded at zero -- indistinguishable from "translation failed"
    // in a real run. Refuse the combination instead of failing silently.
    if (options.ldn_announce_forward && !options.control_plane_enabled) {
        std::cerr << "--ldn-announce-forward requires --control-plane\n";
        return 2;
    }
    if (!options.ldn_identity_pairs.empty() && !options.ldn_announce_forward) {
        std::cerr << "--ldn-identity-pair requires --ldn-announce-forward\n";
        return 2;
    }
    if (options.ldn_announce_forward && options.ldn_identity_pairs.empty() && !options.ldn_dual_host) {
        // An empty table would turn every announce into announce_no_identity_word,
        // which reads like a translation failure. It is a usage error instead.
        std::cerr << "--ldn-announce-forward requires at least one --ldn-identity-pair\n";
        return 2;
    }
    // V-266: the reverse UDS association injection lives inside the control-plane
    // bridge. Without --control-plane it could never run, and a run whose
    // guest_inject_* counters are all zero would read like "Citra refused the
    // guest" instead of "the injection was never armed". Refuse the combination.
    if (options.ldn_guest_inject && !options.control_plane_enabled) {
        std::cerr << "--ldn-guest-inject requires --control-plane\n";
        return 2;
    }

    if (options.ldn_gu_host_admission && !options.ldn_gu_host_discovery) {
        std::cerr << "--ldn-gu-host-admission requires --ldn-gu-host-discovery\n";
        return 2;
    }
    if (options.ldn_gu_host_discovery &&
        (!options.control_plane_enabled || options.ldn_comm_id_override == 0 ||
         !options.have_uds_wlan_comm_id || !options.have_uds_beacon_id ||
         !options.have_uds_attributes || !options.have_uds_network_id ||
         !options.have_uds_tag_word || (!options.ldn_dual_host &&
         (options.ldn_guest_inject || options.ldn_game_return ||
          options.ldn_require_live_hall || options.ldn_announce_forward)))) {
        std::cerr << "--ldn-gu-host-discovery requires --control-plane, --ldn-comm-id and "
                     "the full UDS identity profile, and excludes Citra-host options\n";
        return 2;
    }
    if (options.ldn_game_return &&
        (!options.ldn_announce_forward || !options.ldn_guest_inject || options.proxy_udp_port == 0)) {
        std::cerr << "--ldn-game-return requires --ldn-announce-forward, --ldn-guest-inject and --ldn-proxy-port\n";
        return 2;
    }

    if (!options.trace_path.empty()) {
        // G2 run identity. Read once here; the record builder never reads a clock.
        // Every field is overridable from the CLI so one build can record
        // channel A, B or C runs and be attributed in an audit.
        options.trace_context.manifest_id =
            trace_manifest.empty() ? "citra-gateway" : trace_manifest;
        options.trace_context.run_id = citra_gateway::trace_utc_now() + "-" +
                                       std::to_string(citra_gateway::trace_monotonic_ms());
        options.trace_context.channel = trace_channel.empty() ? "C" : trace_channel;
        options.trace_context.platform = "windows-x86_64";
        options.trace_context.build_id =
            trace_build.empty() ? "citra-gateway/g2-trace-1" : trace_build;
        options.trace_context.role = trace_role.empty() ? "host" : trace_role;
        options.trace_context.stage = "unspecified";
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    citra_gateway::Gateway gateway(options);
    try {
        gateway.open();
    } catch (const std::exception& error) {
        std::cerr << "OPEN-FAILED: " << error.what() << "\n";
        return 3;
    }

    std::cout << "gateway listening on " << options.listen_address << ":" << gateway.port()
              << " -> room " << options.room_address << ":" << options.room_port << "\n";
    if (gateway.trace_enabled()) {
        // Effective G2 identity, one line on stdout, so a run can be attributed
        // (and a zero-frame trace explained) without parsing the trace file.
        std::cout << "trace " << gateway.trace_json() << "\n";
    }

    const auto start = std::chrono::steady_clock::now();
    const auto deadline = start + std::chrono::seconds(seconds);
    unsigned last_report = 0;
    while (!g_stop.load() && std::chrono::steady_clock::now() < deadline) {
        gateway.tick(1);
        if (!stop_file.empty() && stop_file_present(stop_file)) {
            // Break instead of returning, so the SIGINT path (the snapshot and the
            // --dump writes below) is shared by a stop file triggered shutdown.
            std::cout << "stop-file observed, shutting down\n";
            break;
        }
        if (!quiet) {
            const auto counters = gateway.counters();
            const auto elapsed = static_cast<unsigned>(
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() -
                                                                 start)
                    .count());
            if (elapsed != last_report) {
                last_report = elapsed;
                std::cout << "t=" << elapsed << "s clients=" << gateway.client_count()
                          << " accepted=" << counters.clients_accepted
                          << " joined=" << counters.clients_joined
                          << " frames_in=" << counters.frames_in
                          << " forwarded=" << counters.payload_forwarded
                          << " rejected=" << counters.frames_rejected << "\n";
            }
        }
    }

    // Snapshot the machine readable evidence before close() clears client state.
    const std::string counters_json = gateway.counters_json();
    const std::string clients_json = gateway.clients_json();
    const std::string identities_json = gateway.identities_json();
    const std::string captures_json = gateway.captures_json();
    const std::string events_json = gateway.events_json();
    const std::string snapshot_json = gateway.snapshot_json();
    // G-b' control-plane emission log (hex of every frame handed to a side).
    const std::string emitted_json = gateway.emitted_json();
    // V-261: control counters and the bounded Data frame samples.  Without this
    // file a real run cannot say why the announce forward did not fire.
    const std::string diag_text = gateway.diag_text();
    // V-262: per-frame-type census and bounded raw samples of the Citra wire.
    const std::string inbound_json = gateway.inbound_json();
    const bool trace_was_enabled = gateway.trace_enabled();
    const std::string trace_json = gateway.trace_json();
    gateway.close();

    if (!dump_dir.empty()) {
        // V-263: the dump directory is created when missing.  A missing
        // directory used to make every write fail with exit code 3 and lose
        // the whole run (measured: 1269 frames discarded).
        std::error_code dir_ec;
        std::filesystem::create_directories(std::filesystem::path(dump_dir), dir_ec);
        if (dir_ec) {
            std::cerr << "cannot create " << dump_dir << ": " << dir_ec.message() << "\n";
            return 3;
        }
        std::vector<std::pair<std::string, std::string>> files = {
            {"counters.json", counters_json},     {"clients.json", clients_json},
            {"identities.json", identities_json}, {"captures.json", captures_json},
            {"events.json", events_json},         {"snapshot.json", snapshot_json},
            {"emitted.json", emitted_json},   {"diag.json", diag_text},
            {"inbound.json", inbound_json},
        };
        if (trace_was_enabled) {
            files.push_back({"trace.json", trace_json});
        }
        for (const auto& file : files) {
            const std::string path = dump_dir + "/" + file.first;
            std::ofstream out(path, std::ios::binary);
            if (!out) {
                std::cerr << "cannot write " << path << "\n";
                return 3;
            }
            out << file.second << "\n";
            std::cout << "wrote " << path << " (" << file.second.size() << " bytes)\n";
        }
    }
    return 0;
}
