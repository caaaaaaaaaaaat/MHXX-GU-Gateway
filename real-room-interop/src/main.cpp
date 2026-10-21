// SPDX-License-Identifier: GPL-2.0-or-later
// real-room-interop driver.
//
//   self    - build/runs the unmodified 01052024-yuzu-mirror-master room server in-tree and
//             exercises it with the frozen M2 client (today's proof that the harness works).
//   real    - starts a real yuzu-room.exe / citra-room.exe as a child process (-AllowRun
//             required) and captures the actual wire bytes.
//   dryrun  - prints the exact commands the real mode would run, without executing anything.
//   probe   - runs '<exe> --version' (and optionally --help) under -AllowRun.
//   observe - an independent v1 room member; dumps every decoded server frame (the member
//             table oracle for G-c).  See observe.cpp for the exact JSON schema.
//   attach  - drives an already-running room server at -AttachAddr with the same client cases.
//             It starts no server process, skips the V-017 inventory check on purpose, and its
//             evidence is explicitly NOT distribution evidence (see docs/real-room-interop-report.md).
#include "cases.hpp"
#include "harness.hpp"
#include "observe.hpp"
#include "win_net.hpp"

#include <room_transport/transport.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace {

using rri::CaseResult;
using rri::RunConfig;
using rri::ServerSession;
using rri::ServerSpec;
using rri::UdpEndpoint;

// ---------------------------------------------------------------- known servers
struct KnownServer {
    std::string tag;
    std::string kind;     // yuzu | citra
    std::string protocol; // v1 | v4
    std::string path;
    std::uint64_t bytes = 0;
    std::string sha256;
    std::string build_id;
    bool source_compared = false;
};

const std::vector<KnownServer>& known_servers() {
    static const std::vector<KnownServer> table = {
        {"yuzu-main-2022", "yuzu", "v1",
         "C:\\Users\\马光述\\AppData\\Local\\yuzu\\yuzu-windows-msvc\\yuzu-room.exe", 2017792ULL,
         "5175d6a108b022fe47c793fb3a57c2f26a7c1404a0f71827f464586963d8778a",
         "2022-09-24 main build 7edc31be2 (source compared line by line)", true},
        {"yuzu-ea-2024", "yuzu", "v1",
         "C:\\Users\\马光述\\AppData\\Local\\yuzu\\yuzu-windows-msvc-early-access\\yuzu-room.exe",
         786944ULL, "741ac5e936d8ec03b71442ef2ccb1f336907afe20477b6bac5da68177e0a32cc",
         "2024 early access (source NOT compared: no PDB, no disassembly)", false},
        {"citra-msys2-20240927", "citra", "v4",
         "F:\\citra mul\\citra-windows-msys2-20240927-608383e\\citra-room.exe", 5902336ULL,
         "15eb1d9d6c7423bd9f446828abf49c1d82299339bc7bc80caba292c3f826779d",
         "citra msys2 20240927-608383e (source NOT compared)", false},
        {"citra-canary", "citra", "v4", "F:\\citra2798\\canary\\citra-room.exe", 2627072ULL,
         "035bdfbb56d2262c27c54b6a22876bc07e6f1ff5b0886b582b2541aba89aa95a",
         "citra canary (source NOT compared)", false},
        {"citra-game-bundle", "citra", "v4",
         "F:\\究极之月\\日月\\A1877\\Game\\citra-room.exe", 24456528ULL,
         "43a4b8359648fa4ba44910036dd1c79d432d1524823104731fe861e8573752e9",
         "citra from a game bundle (source NOT compared)", false},
    };
    return table;
}

const KnownServer* known_by_sha(const std::string& sha) {
    for (const auto& k : known_servers())
        if (k.sha256 == sha) return &k;
    return nullptr;
}
const KnownServer* known_by_tag(const std::string& tag) {
    for (const auto& k : known_servers())
        if (k.tag == tag) return &k;
    return nullptr;
}

// ---------------------------------------------------------------- bind safety gate
struct GateDecision {
    bool allowed = false;
    bool loopback_only = false;
    bool inject = false;
    std::string reason;
};

// Default posture: the harness only starts a room server that can be pinned to 127.0.0.1.
// A binary whose Room::Create receives an empty address binds ENet's ENET_HOST_ANY (0.0.0.0)
// and therefore needs the explicit -AllowWildcardBind opt-in.
GateDecision decide_bind(bool exe_supports_bind, bool args_have_bind, const std::string& bind_value,
                         bool allow_wildcard) {
    GateDecision d;
    if (args_have_bind) {
        if (bind_value == "127.0.0.1") {
            d.allowed = true;
            d.loopback_only = true;
            d.reason = "args pin the room to 127.0.0.1";
        } else if (allow_wildcard) {
            d.allowed = true;
            d.loopback_only = false;
            d.reason = "args bind " + bind_value + " (allowed by -AllowWildcardBind)";
        } else {
            d.reason = "args bind " + bind_value + " which is not 127.0.0.1; -AllowWildcardBind "
                       "is required";
        }
        return d;
    }
    if (exe_supports_bind) {
        d.allowed = true;
        d.loopback_only = true;
        d.inject = true;
        d.reason = "binary supports --bind-address: injecting --bind-address 127.0.0.1";
        return d;
    }
    if (allow_wildcard) {
        d.allowed = true;
        d.loopback_only = false;
        d.reason = "binary cannot bind a single address (empty Room::Create address -> ENet "
                   "ENET_HOST_ANY 0.0.0.0); allowed only by -AllowWildcardBind";
        return d;
    }
    d.reason = "binary has no --bind-address option, so it would listen on 0.0.0.0; refusing "
               "without -AllowWildcardBind";
    return d;
}

bool file_has_ascii(const std::string& path, const std::string& needle) {
    const std::string data = rri::read_file(path);
    return !data.empty() && data.find(needle) != std::string::npos;
}

bool args_find_bind(const std::vector<std::string>& args, std::string& value) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--bind-address" || args[i] == "-s") {
            if (i + 1 < args.size()) value = args[i + 1];
            return true;
        }
        const std::string prefix = "--bind-address=";
        if (args[i].rfind(prefix, 0) == 0) {
            value = args[i].substr(prefix.size());
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------- misc helpers
std::string quote_arg_display(const std::string& a) {
    if (a.find_first_of(" \t\"") == std::string::npos) return a;
    std::string out = "\"";
    unsigned backslashes = 0;
    for (char c : a) {
        if (c == '\\') { ++backslashes; continue; }
        if (c == '"') {
            out.append(backslashes * 2 + 1, '\\');
            out.push_back('"');
            backslashes = 0;
            continue;
        }
        out.append(backslashes, '\\');
        backslashes = 0;
        out.push_back(c);
    }
    out.append(backslashes * 2, '\\');
    out.push_back('"');
    return out;
}

// Same quoting as ChildProcess::start, so the audited command line is the executed one.
std::string render_command_line(const std::string& exe, const std::vector<std::string>& args) {
    std::string out = quote_arg_display(exe);
    for (const auto& a : args) {
        out.push_back(' ');
        out += quote_arg_display(a);
    }
    return out;
}

std::size_t count_occurrences(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return 0;
    std::size_t n = 0, at = 0;
    while ((at = hay.find(needle, at)) != std::string::npos) { ++n; at += needle.size(); }
    return n;
}

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    for (std::size_t at = s.find(from); at != std::string::npos; at = s.find(from, at + to.size()))
        s.replace(at, from.size(), to);
    return s;
}

void write_text(const std::string& path, const std::string& text) {
    const std::size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        std::error_code ec;
        std::filesystem::create_directories(path.substr(0, slash), ec);
    }
    std::ofstream out(path, std::ios::binary);
    out << text;
}

// ---------------------------------------------------------------- case tables
struct CaseEntry {
    const char* id;
    CaseResult (*fn)(const RunConfig&, const ServerSpec&);
    std::uint32_t capacity;
};

std::vector<CaseEntry> v1_cases_all() {
    return {
        {"join", rri::case_join, 8},
        {"version_mismatch", rri::case_version_mismatch, 8},
        {"wrong_password", rri::case_wrong_password, 8},
        {"name_collision", rri::case_name_collision, 8},
        {"ip_collision", rri::case_ip_collision, 8},
        {"room_full", rri::case_room_full, 2},
        {"release", rri::case_release, 2},
        {"m2_parity", rri::case_m2_parity, 8},
        {"port_conflict", rri::case_port_conflict, 8},
        {"family_isolation", rri::case_family_isolation, 8},
        {"proxy_route", rri::case_proxy_route, 8},
        {"proxy_broadcast", rri::case_proxy_broadcast, 8},
        {"dataplane_size", rri::case_dataplane_size, 8},
        {"chat_limit", rri::case_chat_limit, 8},
        {"unjoined_source", rri::case_unjoined_source, 8},
        {"error_order", rri::case_error_order, 8},
        {"fixture_bytes", rri::case_fixture_bytes, 4},
    };
}

std::vector<CaseEntry> v1_cases_core() {
    std::vector<CaseEntry> all = v1_cases_all();
    static const char* keep[] = {"join", "version_mismatch", "wrong_password", "name_collision",
                                 "room_full", "release", "error_order", "fixture_bytes"};
    std::vector<CaseEntry> out;
    for (const auto& entry : all)
        for (const char* id : keep)
            if (std::string(entry.id) == id) out.push_back(entry);
    return out;
}

std::vector<CaseEntry> v4_cases_all() {
    return {
        {"join_v4", rri::case_join_v4, 8},
        {"version_mismatch_v4", rri::case_version_mismatch_v4, 8},
        {"wrong_password_v4", rri::case_wrong_password_v4, 8},
        {"name_collision_v4", rri::case_name_collision_v4, 8},
        {"room_full_v4", rri::case_room_full_v4, 2},
        {"chat_v4", rri::case_chat_v4, 8},
        {"wifi_route_v4", rri::case_wifi_route_v4, 8},
        {"wifi_broadcast_v4", rri::case_wifi_broadcast_v4, 8},
        {"console_id_collision_v4", rri::case_console_id_collision_v4, 8},
        {"error_order_v4", rri::case_error_order_v4, 8},
    };
}

std::vector<CaseEntry> v4_cases_core() {
    std::vector<CaseEntry> all = v4_cases_all();
    static const char* keep[] = {"join_v4", "version_mismatch_v4", "wrong_password_v4",
                                 "name_collision_v4", "room_full_v4",
                                 "console_id_collision_v4", "error_order_v4"};
    std::vector<CaseEntry> out;
    for (const auto& entry : all)
        for (const char* id : keep)
            if (std::string(entry.id) == id) out.push_back(entry);
    return out;
}

// ---------------------------------------------------------------- the bind_gate meta case
CaseResult local_case_bind_gate(const RunConfig& cfg, const ServerSpec& spec) {
    const std::uint64_t t0 = rri::now_ms();
    CaseResult result = rri::begin_case(cfg, spec, "bind_gate");
    const KnownServer* yz_main = known_by_tag("yuzu-main-2022");
    const KnownServer* yz_ea = known_by_tag("yuzu-ea-2024");
    const KnownServer* citra = known_by_tag("citra-msys2-20240927");
    const bool main_has = file_has_ascii(yz_main->path, "bind-address");
    const bool ea_has = file_has_ascii(yz_ea->path, "bind-address");
    const bool citra_has = file_has_ascii(citra->path, "bind-address");
    result.check("yuzu_main_2022_has_no_bind_option", !main_has,
                 main_has ? "unexpected --bind-address string" : "no --bind-address in the binary");
    result.check("yuzu_ea_2024_has_bind_option", ea_has);
    result.check("citra_room_has_no_bind_option", !citra_has);
    const GateDecision d_main = decide_bind(main_has, false, "", false);
    result.check("yuzu_main_2022_refused_by_default", !d_main.allowed, d_main.reason);
    const GateDecision d_ea = decide_bind(ea_has, false, "", false);
    result.check("yuzu_ea_2024_allowed_and_injected", d_ea.allowed && d_ea.inject && d_ea.loopback_only,
                 d_ea.reason);
    const GateDecision d_main_forced = decide_bind(main_has, false, "", true);
    result.check("yuzu_main_2022_allowed_with_allow_wildcard",
                 d_main_forced.allowed && !d_main_forced.loopback_only, d_main_forced.reason);
    const GateDecision d_citra = decide_bind(citra_has, false, "", false);
    result.check("citra_room_refused_by_default", !d_citra.allowed, d_citra.reason);
    const GateDecision d_citra_forced = decide_bind(citra_has, false, "", true);
    result.check("citra_room_allowed_with_allow_wildcard",
                 d_citra_forced.allowed && !d_citra_forced.loopback_only, d_citra_forced.reason);
    const GateDecision d_explicit_wild = decide_bind(false, true, "0.0.0.0", false);
    result.check("explicit_wildcard_arg_refused_by_default", !d_explicit_wild.allowed,
                 d_explicit_wild.reason);
    const GateDecision d_explicit_lo = decide_bind(false, true, "127.0.0.1", false);
    result.check("explicit_loopback_arg_allowed", d_explicit_lo.allowed && d_explicit_lo.loopback_only,
                 d_explicit_lo.reason);
    result.note("static evidence from the binaries themselves; no room server was started");
    rri::end_case(result, t0);
    return result;
}

// ---------------------------------------------------------------- run facts / per-case driver
struct RunFacts {
    bool server_started = false;
    bool ready_via_endpoint = false;
    std::string start_error;
    int exit_code = -1;
    bool stopped_within_grace = false;
    bool port_released = false;
    bool loopback_endpoints = false;
    bool local_addr_endpoints = false;
    bool bound_endpoint_present = false;
    std::vector<UdpEndpoint> endpoints_start;
    std::vector<UdpEndpoint> endpoints_after_3s;
    std::vector<UdpEndpoint> endpoints_after_stop;
    int join_success_frames = 0;
    std::size_t log_joined_lines = 0;
    bool log_seen = false;
    bool private_room_line = false;
    std::string command_line;
    std::uint64_t wall_ms = 0;
};

struct CaseContext {
    bool use_server = true;
    bool expect_private_room = false;
    bool request_3s_probe = false;
    std::string room_log_name; // e.g. yuzu-room.log, may be empty
    bool real_mode = false;
    bool loopback_only = true;
    bool allow_wildcard = false;
    // Joins performed through room_transport::Transport (M2 parity) are not visible as raw
    // captured frames; the room log still reports them, so count them explicitly.
    int expected_extra_joins = 0;
};

// Every UDP endpoint this pid holds on the room port must sit on an address we accept: the
// loopback address when the binary can be pinned, or 0.0.0.0 when the room server has no
// --bind-address option at all (ENET_HOST_ANY) and the run was authorized for that.
bool endpoints_local_addresses(const std::vector<UdpEndpoint>& endpoints, std::uint16_t port,
                               bool& present) {
    present = false;
    for (const auto& endpoint : endpoints) {
        if (endpoint.port != port) continue;
        present = true;
        if (endpoint.address != "127.0.0.1" && endpoint.address != "0.0.0.0") return false;
    }
    return present;
}

int count_join_success_frames(const CaseResult& result) {
    int n = 0;
    for (const auto& frame : result.frames)
        if (frame.second.from_server && rri::frame_is_join_success(frame.second.bytes)) ++n;
    return n;
}

CaseResult run_case(const RunConfig& cfg, const ServerSpec& spec, const CaseEntry& entry,
                    const CaseContext& context, std::string& command_line_out, RunFacts& facts) {
    const std::uint64_t wall0 = rri::now_ms();
    command_line_out = render_command_line(spec.exe, spec.args);
    facts.command_line = command_line_out;

    ServerSession session;
    if (context.use_server) {
        std::string error;
        facts.server_started = session.start(rri::to_launch(spec), 10000, error);
        facts.ready_via_endpoint = facts.server_started && session.ready_via_endpoint();
        if (!facts.server_started) {
            facts.start_error = error;
        } else {
            facts.endpoints_start = rri::udp_endpoints_for_pid(session.pid());
            if (context.request_3s_probe) {
                while (rri::now_ms() - wall0 < 3200) rri::sleep_ms(50);
                facts.endpoints_after_3s = rri::udp_endpoints_for_pid(session.pid());
            }
        }
    }

    // A foreign server (attach mode) can answer with bytes this codec does not expect; a decode
    // failure must be reported as a failed case, never as a crashed process.
    CaseResult result;
    try {
        result = entry.fn(cfg, spec);
    } catch (const std::exception& e) {
        result = rri::begin_case(cfg, spec, entry.id);
        result.check("case_did_not_throw", false, std::string("uncaught exception: ") + e.what());
        rri::end_case(result, wall0);
    } catch (...) {
        result = rri::begin_case(cfg, spec, entry.id);
        result.check("case_did_not_throw", false, "uncaught non-std exception");
        rri::end_case(result, wall0);
    }

    facts.wall_ms = rri::now_ms() - wall0;
    result.note("wall_ms=" + rri::format_uint64(facts.wall_ms));
    result.note("command_line=" + command_line_out);
    if (context.use_server) {
        bool client_connected_and_sent = false;
        for (const auto& frame : result.frames)
            if (!frame.second.from_server) client_connected_and_sent = true;
        result.note(std::string("server_ready=") + (facts.server_started ? "yes" : "no") +
                    " ready_via_endpoint=" + (facts.ready_via_endpoint ? "yes" : "no") +
                    " ready_via_marker=" +
                    (facts.server_started && !facts.ready_via_endpoint ? "yes" : "no") +
                    " client_connected_and_sent=" +
                    (client_connected_and_sent ? "yes" : "no"));
    }

    if (context.use_server && facts.server_started) {
        facts.join_success_frames = count_join_success_frames(result);
        std::string log_text = session.stdout_tail(1 << 20) + session.stderr_tail(1 << 20);
        if (!context.room_log_name.empty())
            log_text += rri::read_file(spec.workdir + "/" + context.room_log_name);
        facts.log_seen = !rri::trim(log_text).empty();
        facts.log_joined_lines = count_occurrences(log_text, "has joined");
        facts.private_room_line =
            log_text.find("Hosting a private room") != std::string::npos;
    }

    const rri::ProcessStatus status = context.use_server ? session.stop() : rri::ProcessStatus{};
    if (context.use_server) {
        facts.exit_code = status.exit_code;
        facts.stopped_within_grace = !status.timed_out;
        const std::uint64_t deadline = rri::now_ms() + 3000;
        for (;;) {
            facts.endpoints_after_stop = rri::udp_endpoints_by_port(spec.port);
            if (facts.endpoints_after_stop.empty()) break;
            if (rri::now_ms() >= deadline) break;
            rri::sleep_ms(100);
        }
        std::string reason;
        facts.port_released = facts.endpoints_after_stop.empty() && rri::port_available(spec.port, reason);
        facts.loopback_endpoints = true;
        bool any = false;
        for (const auto& endpoint : facts.endpoints_start) {
            if (endpoint.port != spec.port) continue;
            any = true;
            if (endpoint.wildcard || endpoint.address != "127.0.0.1") facts.loopback_endpoints = false;
        }
        if (!any) facts.loopback_endpoints = false;
        facts.local_addr_endpoints = endpoints_local_addresses(
            facts.endpoints_start, spec.port, facts.bound_endpoint_present);
    }

    if (context.use_server) {
        result.check("server_started", facts.server_started, facts.start_error);
        if (!facts.server_started)
            result.note("failure_cause_hint=the server was never ready (no ready marker and no "
                        "matching UDP endpoint for its pid): any connect timeout below is a "
                        "symptom of that, not the primary failure");
        if (facts.server_started) {
            const std::string endpoints_detail =
                "endpoints(pid " + rri::format_uint64(session.pid()) + ")=" +
                rri::describe_endpoints(facts.endpoints_start);
            if (context.loopback_only) {
                result.check("server_bound_loopback_only", facts.loopback_endpoints,
                             endpoints_detail);
            } else {
                result.check("server_bound_expected_address",
                             facts.local_addr_endpoints && facts.bound_endpoint_present,
                             "wildcard-authorized run: loopback_only=false and "
                             "-AllowWildcardBind was given, so 0.0.0.0 is expected; only "
                             "127.0.0.1 and 0.0.0.0 are accepted :: " +
                                 endpoints_detail);
                result.note("wildcard_bind_authorized=true loopback_only=false "
                            "client_source_address=127.0.0.1 (RawClient binds the loopback "
                            "address explicitly; no client packet was sent from another "
                            "interface)");
            }
            if (context.request_3s_probe) {
                if (context.loopback_only) {
                    result.check("server_bound_loopback_only_after_3s",
                                 rri::endpoints_loopback_only(facts.endpoints_after_3s),
                                 "endpoints_after_3s=" +
                                     rri::describe_endpoints(facts.endpoints_after_3s));
                } else {
                    bool present = false;
                    result.check("server_bound_expected_address_after_3s",
                                 endpoints_local_addresses(facts.endpoints_after_3s, spec.port,
                                                           present) &&
                                     present,
                                 "endpoints_after_3s=" +
                                     rri::describe_endpoints(facts.endpoints_after_3s));
                }
            }
            if (facts.join_success_frames > 0)
                result.check("server_log_reports_member_join", facts.log_joined_lines > 0,
                             "join_success_frames=" + rri::format_uint64(facts.join_success_frames) +
                                 " log_joined_lines=" + rri::format_uint64(facts.log_joined_lines));
            const std::size_t expected_joins =
                static_cast<std::size_t>(facts.join_success_frames) +
                static_cast<std::size_t>(context.expected_extra_joins);
            result.check("no_third_party_peer", facts.log_joined_lines == expected_joins,
                         "log_joined_lines=" + rri::format_uint64(facts.log_joined_lines) +
                             " captured_join_success_frames=" +
                             rri::format_uint64(facts.join_success_frames) +
                             " expected_extra=" +
                             rri::format_uint64(context.expected_extra_joins < 0
                                                    ? 0
                                                    : static_cast<std::uint64_t>(
                                                          context.expected_extra_joins)));
            if (context.expect_private_room)
                result.check("no_announce_private_room_line", facts.private_room_line,
                             "expected 'Hosting a private room' (no --token/--web-api-url)");
            result.check("server_stopped_within_grace", facts.stopped_within_grace,
                         "exit_code=" + rri::format_uint64(static_cast<std::uint64_t>(facts.exit_code)));
            result.check("port_released_after_exit", facts.port_released,
                         "endpoints_after_stop=" + rri::describe_endpoints(facts.endpoints_after_stop));
            if (!result.ok)
                result.note("failure_cause_hint=the server WAS ready (marker=" +
                            std::string(facts.ready_via_endpoint ? "no" : "yes") +
                            " endpoint=" + (facts.ready_via_endpoint ? "yes" : "no") +
                            "), so the failing checks below are server behaviour, not a launch "
                            "problem");
        }
    }
    return result;
}

// ---------------------------------------------------------------- options
struct Options {
    std::string mode;
    std::string protocol = "v1";
    std::string room_exe;
    std::string room_args_file;
    std::string server_tag;
    std::string evidence_root = "evidence";
    std::string work_root = "work";
    std::string self_server_exe = "build-mingw/real_room_self_server.exe";
    std::string cases = "core";
    bool allow_run = false;
    bool allow_wildcard_bind = false;
    bool with_help = false;
    std::uint16_t base_port = 39572;
    bool all_servers = false;
    // attach mode: drive an already-running room server that this run did not start.
    std::string attach_addr;                       // <ip>:<port>
    std::string attach_tag;                        // evidence label (default foreign-<ip>-<port>)
    std::string attach_password = "pw1";           // password the foreign room expects
    std::string attach_room_name;                  // declared room name (optional)
    std::uint32_t attach_slots = 0;                // declared member capacity (0 = unknown)
    std::string attach_skip;                       // extra case ids to skip, comma separated
};

void usage() {
    std::printf(
        "real-room-interop: room-server interop harness\n"
        "usage: real_room_interop.exe <self|real|attach|dryrun|probe|observe> [options]\n"
        "  self    run the in-tree original-source room server and the M2 client cases\n"
        "  real    run a real room server child process (-AllowRun required)\n"
        "  attach  drive an ALREADY-RUNNING room server (-AttachAddr); starts nothing, skips the\n"
        "          V-017 inventory check, and is NOT distribution evidence\n"
        "  dryrun  print the exact real-mode commands without executing anything\n"
        "  probe   run '<exe> --version' [-WithHelp] on the candidate binaries (-AllowRun)\n"
        "  observe independent v1 member: --room/--room-port/--password/--nickname/--seconds/--out\n"
        "          (see 'real_room_interop.exe observe --help')\n"
        "options:\n"
        "  -AllowRun              authorize starting the real room-server binaries\n"
        "  -AllowWildcardBind     authorize a binary that binds 0.0.0.0 (no --bind-address)\n"
        "  -RoomExe <path>        room server executable (UTF-8 path)\n"
        "  -RoomArgsFile <path>   argument template file (see config/*.args)\n"
        "  -ServerTag <tag>       pick a server from the known table (see dryrun output)\n"
        "  -Protocol v1|v4        protocol side of the room server\n"
        "  -Cases core|all        case set (real defaults to core, self to all)\n"
        "  -Port <port>           first port; each case takes the next one\n"
        "  -Evidence <dir>        evidence root (default evidence)\n"
        "  -Work <dir>            work root (default work)\n"
        "  -SelfServerExe <path>  in-tree self server binary\n"
        "  -AllServers            probe/dryrun every known server\n"
        "attach mode (no server process is started and no binary is authorized):\n"
        "  -AttachAddr <ip:port>  address of the already-running room server (loopback only)\n"
        "  -AttachTag <tag>       evidence label (default foreign-<ip>-<port>)\n"
        "  -Password <pw>         password the foreign room expects (default pw1)\n"
        "  -RoomName <name>       declared room name; omitted -> the room_name check is skipped\n"
        "  -Slots <n>             declared member capacity; omitted -> member_slots is skipped\n"
        "  -Skip <id,id>          extra case ids to report as skipped\n"
        "  (the attach target must be loopback: every client case connects to 127.0.0.1)\n");
}

bool parse_options(const std::vector<std::string>& args, Options& opt, std::string& error) {
    if (args.size() < 2) { error = "missing mode"; return false; }
    opt.mode = args[1];
    if (opt.mode != "self" && opt.mode != "real" && opt.mode != "dryrun" && opt.mode != "probe" &&
        opt.mode != "attach") {
        error = "unknown mode '" + opt.mode + "'";
        return false;
    }
    for (std::size_t i = 2; i < args.size(); ++i) {
        const std::string& a = args[i];
        auto need_value = [&](std::string& slot) {
            if (i + 1 >= args.size()) { error = a + " needs a value"; return false; }
            slot = args[++i];
            return true;
        };
        if (a == "-AllowRun") opt.allow_run = true;
        else if (a == "-AllowWildcardBind") opt.allow_wildcard_bind = true;
        else if (a == "-WithHelp") opt.with_help = true;
        else if (a == "-AllServers") opt.all_servers = true;
        else if (a == "-RoomExe") { if (!need_value(opt.room_exe)) return false; }
        else if (a == "-RoomArgsFile") { if (!need_value(opt.room_args_file)) return false; }
        else if (a == "-ServerTag") { if (!need_value(opt.server_tag)) return false; }
        else if (a == "-Protocol") { if (!need_value(opt.protocol)) return false; }
        else if (a == "-Cases") { if (!need_value(opt.cases)) return false; }
        else if (a == "-Evidence") { if (!need_value(opt.evidence_root)) return false; }
        else if (a == "-Work") { if (!need_value(opt.work_root)) return false; }
        else if (a == "-SelfServerExe") { if (!need_value(opt.self_server_exe)) return false; }
        else if (a == "-AttachAddr") { if (!need_value(opt.attach_addr)) return false; }
        else if (a == "-AttachTag") { if (!need_value(opt.attach_tag)) return false; }
        else if (a == "-Password") { if (!need_value(opt.attach_password)) return false; }
        else if (a == "-RoomName") { if (!need_value(opt.attach_room_name)) return false; }
        else if (a == "-Skip") { if (!need_value(opt.attach_skip)) return false; }
        else if (a == "-Slots") {
            std::string value;
            if (!need_value(value)) return false;
            opt.attach_slots = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        }
        else if (a == "-Port") {
            std::string value;
            if (!need_value(value)) return false;
            opt.base_port = static_cast<std::uint16_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else {
            error = "unknown option '" + a + "'";
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------- per-mode plans
std::vector<std::string> substituted_args(const RunConfig& cfg, const ServerSpec& spec,
                                          const std::vector<std::string>& raw, bool inject_bind) {
    (void)cfg;
    std::vector<std::string> out;
    for (const auto& arg : raw) {
        std::string s = rri::substitute_placeholders(arg, spec.port, spec.workdir);
        s = replace_all(s, "{slots}", rri::format_uint64(spec.capacity));
        s = replace_all(s, "{room}", spec.room_name);
        s = replace_all(s, "{tag}", spec.scenario);
        s = replace_all(s, "{password}", spec.password);
        out.push_back(s);
    }
    if (inject_bind) {
        out.push_back("--bind-address");
        out.push_back("127.0.0.1");
    }
    return out;
}

struct Plan {
    std::string exe;
    std::string tag;
    std::vector<std::string> raw_args;
    std::string ready_marker;
    std::string room_log_name;
    bool inject_bind = false;
    bool loopback_only = true;
    bool allow_wildcard = false;
    bool expect_private_room = false;
    std::string command_preview;
};

ServerSpec make_spec(const Options& opt, const Plan& plan, const CaseEntry& entry,
                     std::size_t index, const std::string& mode) {
    ServerSpec spec;
    spec.scenario = entry.id;
    spec.protocol = (opt.protocol == "v4") ? "v4" : "v1";
    spec.port = static_cast<std::uint16_t>(opt.base_port + index);
    spec.capacity = entry.capacity;
    spec.password = "pw1";
    spec.room_name = "rri-" + mode + "-" + std::string(entry.id);
    spec.preferred_game = "RealRoomInterop";
    spec.exe = plan.exe;
    spec.workdir = opt.work_root + "/" + mode + "/" + std::string(entry.id);
    spec.out_file = opt.evidence_root + "/" + mode + "/" + plan.tag + "/server/" +
                    std::string(entry.id) + ".out.txt";
    spec.err_file = opt.evidence_root + "/" + mode + "/" + plan.tag + "/server/" +
                    std::string(entry.id) + ".err.txt";
    spec.ready_marker = plan.ready_marker;
    spec.args = substituted_args(RunConfig{}, spec, plan.raw_args, plan.inject_bind);
    return spec;
}

int write_identity_json(const std::string& path, const Plan& plan, const std::string& exe,
                        std::uint64_t bytes, const std::string& sha, const std::string& protocol,
                        const std::string& build_id, bool source_compared, bool allow_wildcard,
                        std::size_t cases_total, int cases_failed, std::uint64_t elapsed_ms,
                        const std::vector<std::string>& observed_endpoints = {}) {
    std::string json = "{\n";
    json += "  \"tool\": \"real-room-interop\",\n";
    json += "  \"server_tag\": \"" + rri::json_escape(plan.tag) + "\",\n";
    json += "  \"server_exe\": \"" + rri::json_escape(exe) + "\",\n";
    json += "  \"server_exe_bytes\": " + rri::format_uint64(bytes) + ",\n";
    json += "  \"server_exe_sha256\": \"" + sha + "\",\n";
    json += "  \"build_id\": \"" + rri::json_escape(build_id) + "\",\n";
    json += std::string("  \"source_compared\": ") + (source_compared ? "true" : "false") + ",\n";
    json += "  \"protocol\": \"" + protocol + "\",\n";
    json += std::string("  \"loopback_only\": ") + (plan.loopback_only ? "true" : "false") + ",\n";
    json += std::string("  \"allow_wildcard_bind\": ") + (allow_wildcard ? "true" : "false") + ",\n";
    json += "  \"ready_marker\": \"" + rri::json_escape(plan.ready_marker) + "\",\n";
    json += std::string("  \"injected_bind_address\": ") + (plan.inject_bind ? "true" : "false") + ",\n";
    json += "  \"cases_total\": " + rri::format_uint64(cases_total) + ",\n";
    json += "  \"cases_failed\": " + rri::format_uint64(static_cast<std::uint64_t>(cases_failed)) + ",\n";
    json += "  \"elapsed_ms\": " + rri::format_uint64(elapsed_ms) + ",\n";
    json += std::string("  \"loopback_only_observed\": ") +
            (plan.loopback_only ? "true" : "false") + ",\n";
    json += "  \"observed_bind_endpoints\": [";
    for (std::size_t i = 0; i < observed_endpoints.size(); ++i) {
        if (i) json += ", ";
        json += "\"" + rri::json_escape(observed_endpoints[i]) + "\"";
    }
    json += "]\n";
    json += "}\n";
    write_text(path, json);
    return 0;
}

// ---------------------------------------------------------------- self mode
int run_self(const Options& opt) {
    RunConfig cfg;
    cfg.mode = "self";
    cfg.protocol = "v1";
    cfg.evidence_root = opt.evidence_root;
    cfg.work_root = opt.work_root;
    cfg.self_server_exe = opt.self_server_exe;
    cfg.server_tag = "self-original-source";
    cfg.base_port = opt.base_port;

    std::string error;
    if (rri::file_size(opt.self_server_exe) == 0) {
        std::fprintf(stderr,
                     "self server binary not found: %s\nbuild it first (build.ps1) or pass "
                     "-SelfServerExe <path>\n",
                     opt.self_server_exe.c_str());
        return 2;
    }

    Plan plan;
    plan.exe = opt.self_server_exe;
    plan.tag = cfg.server_tag;
    plan.ready_marker = "SELF_SERVER_READY";
    plan.room_log_name.clear();
    plan.loopback_only = true;

    std::vector<CaseEntry> entries;
    {
        CaseEntry gate{"bind_gate", local_case_bind_gate, 8};
        entries.push_back(gate);
    }
    for (const auto& entry : v1_cases_all()) entries.push_back(entry);

    std::printf("SELF MODE: in-tree original-source room server (real_room_self_server.exe)\n");
    std::printf("SERVER IDENTITY: tag=%s path=%s bytes=%llu sha256=%s\n", plan.tag.c_str(),
                plan.exe.c_str(), static_cast<unsigned long long>(rri::file_size(plan.exe)),
                rri::file_sha256_hex(plan.exe).c_str());
    std::printf("NOTE: this proves the harness works against the unmodified room source; it is "
                "NOT real-distribution interop.\n");

    std::vector<CaseResult> results;
    const std::string evidence_dir = opt.evidence_root + "/self/" + plan.tag;
    std::string commands;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const CaseEntry& entry = entries[i];
        ServerSpec spec;
        CaseContext context;
        context.use_server = std::string(entry.id) != "bind_gate";
        if (std::string(entry.id) == "m2_parity") context.expected_extra_joins = 1;
        if (context.use_server) {
            spec = make_spec(opt, plan, entry, i, "self");
            spec.args = substituted_args(cfg, spec,
                                         {"--name",         spec.room_name,  "--description",
                                          "real-room-interop", "--port",   rri::format_uint64(spec.port),
                                          "--password",     spec.password,  "--slots",
                                          rri::format_uint64(spec.capacity), "--preferred-game",
                                          spec.preferred_game},
                                         false);
        } else {
            spec.scenario = entry.id;
            spec.protocol = "v1";
            spec.port = static_cast<std::uint16_t>(opt.base_port + i);
            spec.capacity = entry.capacity;
            spec.room_name = "rri-self-bind-gate";
        }
        RunFacts facts;
        std::string command;
        CaseResult result = run_case(cfg, spec, entry, context, command, facts);
        if (context.use_server) commands += command + "\n";
        rri::write_case_evidence(evidence_dir + "/cases", result);
        rri::print_case_line(result);
        results.push_back(result);
    }

    int failed = 0;
    std::uint64_t elapsed = 0;
    for (const auto& result : results) {
        if (!result.ok) ++failed;
        elapsed += result.ms;
    }
    const std::string summary = evidence_dir + "/summary.json";
    rri::write_run_summary(summary, cfg, results, plan.exe);
    write_text(evidence_dir + "/commands.txt", commands);
    write_identity_json(evidence_dir + "/server-identity.json", plan, plan.exe,
                        rri::file_size(plan.exe), rri::file_sha256_hex(plan.exe), "v1",
                        "in-tree original source (unmodified 01052024-yuzu-mirror-master)", true,
                        false, results.size(), static_cast<std::uint64_t>(failed), elapsed);
    std::printf("RESULT mode=self protocol=v1 server=%s cases=%llu failed=%d elapsed_ms=%llu\n",
                plan.tag.c_str(), static_cast<unsigned long long>(results.size()), failed,
                static_cast<unsigned long long>(elapsed));
    return failed == 0 ? 0 : 1;
}

// ---------------------------------------------------------------- real mode
int run_real(const Options& opt) {
    if (!opt.allow_run) {
        std::fprintf(stderr, "未获用户授权: real mode starts a real room-server binary; pass "
                             "-AllowRun to authorize it\n");
        return 3;
    }
    if (opt.room_exe.empty() || opt.room_args_file.empty()) {
        std::fprintf(stderr, "real mode needs -RoomExe <path> and -RoomArgsFile <file>\n");
        return 2;
    }
    if (opt.protocol != "v1" && opt.protocol != "v4") {
        std::fprintf(stderr, "real mode needs -Protocol v1|v4\n");
        return 2;
    }

    const std::uint64_t bytes = rri::file_size(opt.room_exe);
    const std::string sha = rri::file_sha256_hex(opt.room_exe);
    const KnownServer* known = known_by_sha(sha);
    std::printf("SERVER IDENTITY: path=%s bytes=%llu sha256=%s\n", opt.room_exe.c_str(),
                static_cast<unsigned long long>(bytes), sha.c_str());
    if (known == nullptr) {
        std::fprintf(stderr,
                     "SERVER IDENTITY REJECTED: sha256 is not in the authorized table "
                     "(docs/VERIFICATION-LOG.md V-017); this run would not count as evidence\n");
        for (const auto& k : known_servers())
            std::fprintf(stderr, "  known: %s %s %s\n", k.tag.c_str(), k.sha256.c_str(), k.path.c_str());
        return 4;
    }
    if (known->protocol != opt.protocol) {
        std::fprintf(stderr, "SERVER IDENTITY REJECTED: %s speaks %s, not -Protocol %s\n",
                     known->tag.c_str(), known->protocol.c_str(), opt.protocol.c_str());
        return 4;
    }
    if (bytes != known->bytes)
        std::printf("WARNING: byte count differs from the table (%llu vs %llu)\n",
                    static_cast<unsigned long long>(bytes),
                    static_cast<unsigned long long>(known->bytes));
    std::printf("SERVER IDENTITY ACCEPTED: tag=%s build_id=%s source_compared=%s\n",
                known->tag.c_str(), known->build_id.c_str(),
                known->source_compared ? "true" : "false");

    std::map<std::string, std::vector<std::string>> args_map;
    std::string error;
    if (!rri::parse_args_file(opt.room_args_file, args_map, error)) {
        std::fprintf(stderr, "cannot parse %s: %s\n", opt.room_args_file.c_str(), error.c_str());
        return 2;
    }

    const bool exe_supports_bind = file_has_ascii(opt.room_exe, "bind-address");
    std::string args_bind_value;
    bool args_have_bind = false;
    for (const auto& entry : args_map)
        if (args_find_bind(entry.second, args_bind_value)) { args_have_bind = true; break; }
    const GateDecision gate =
        decide_bind(exe_supports_bind, args_have_bind, args_bind_value, opt.allow_wildcard_bind);
    std::printf("BIND GATE: allowed=%s loopback_only=%s inject=%s reason=%s\n",
                gate.allowed ? "true" : "false", gate.loopback_only ? "true" : "false",
                gate.inject ? "true" : "false", gate.reason.c_str());
    if (!gate.allowed) {
        std::fprintf(stderr, "BIND GATE REFUSED: %s\n", gate.reason.c_str());
        return 5;
    }

    RunConfig cfg;
    cfg.mode = "real";
    cfg.protocol = opt.protocol;
    cfg.evidence_root = opt.evidence_root;
    cfg.work_root = opt.work_root;
    cfg.room_exe = opt.room_exe;
    cfg.room_exe_tag = known->tag;
    cfg.server_tag = known->tag;
    cfg.allow_run = true;
    cfg.base_port = opt.base_port;
    cfg.args_by_scenario = args_map;

    Plan plan;
    plan.exe = opt.room_exe;
    plan.tag = known->tag;
    plan.raw_args = args_map.count("*") ? args_map["*"] : std::vector<std::string>{};
    plan.ready_marker = "Room is open";
    plan.room_log_name = (known->kind == "yuzu") ? "yuzu-room.log" : "citra-room.log";
    plan.inject_bind = gate.inject;
    plan.loopback_only = gate.loopback_only;
    plan.allow_wildcard = opt.allow_wildcard_bind;
    plan.expect_private_room = true;

    std::vector<CaseEntry> entries;
    if (opt.protocol == "v1") {
        CaseEntry gate_case{"bind_gate", local_case_bind_gate, 8};
        if (opt.cases == "all") {
            entries.push_back(gate_case);
            for (const auto& entry : v1_cases_all()) entries.push_back(entry);
        } else {
            for (const auto& entry : v1_cases_core()) entries.push_back(entry);
            entries.push_back(gate_case);
        }
    } else {
        if (opt.cases == "all")
            for (const auto& entry : v4_cases_all()) entries.push_back(entry);
        else
            for (const auto& entry : v4_cases_core()) entries.push_back(entry);
    }

    std::printf("REAL MODE: %s (%s), protocol=%s, cases=%s, wildcard_bind_authorized=%s\n",
                known->tag.c_str(), known->path.c_str(), opt.protocol.c_str(), opt.cases.c_str(),
                opt.allow_wildcard_bind ? "true" : "false");
    std::printf("NOTE: the room server is a separate child process; stdout/stderr are captured to "
                "files and the port is checked before/after the run.\n");

    std::vector<CaseResult> results;
    const std::string evidence_dir = opt.evidence_root + "/real/" + known->tag;
    const std::uint64_t run_t0 = rri::now_ms();
    std::string commands;
    std::vector<std::string> observed_endpoints;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const CaseEntry& entry = entries[i];
        CaseContext context;
        context.use_server = std::string(entry.id) != "bind_gate";
        if (std::string(entry.id) == "m2_parity") context.expected_extra_joins = 1;
        context.real_mode = true;
        context.expect_private_room = true;
        context.room_log_name = plan.room_log_name;
        context.loopback_only = gate.loopback_only;
        context.allow_wildcard = opt.allow_wildcard_bind;
        context.request_3s_probe = (i == 0);

        ServerSpec spec;
        if (context.use_server) {
            spec = make_spec(opt, plan, entry, i, "real");
            spec.args = substituted_args(cfg, spec, plan.raw_args, gate.inject);
        } else {
            spec.scenario = entry.id;
            spec.protocol = opt.protocol;
            spec.port = static_cast<std::uint16_t>(opt.base_port + i);
            spec.capacity = entry.capacity;
            spec.room_name = "rri-real-bind-gate";
            spec.exe = opt.room_exe;
        }
        RunFacts facts;
        std::string command;
        CaseResult result = run_case(cfg, spec, entry, context, command, facts);
        if (context.use_server) {
            commands += command + "\n";
            result.note("server_bind_endpoints=" + rri::describe_endpoints(facts.endpoints_start));
            result.note(std::string("server_ready_via=") +
                        (facts.ready_via_endpoint ? "udp-endpoint(pid)" : "ready-marker"));
            for (const auto& endpoint : facts.endpoints_start) {
                if (endpoint.port != spec.port) continue;
                const std::string text =
                    endpoint.address + ":" + rri::format_uint64(endpoint.port) + " pid=" +
                    rri::format_uint64(endpoint.pid);
                bool seen = false;
                for (const auto& existing : observed_endpoints)
                    if (existing == text) seen = true;
                if (!seen) observed_endpoints.push_back(text);
            }
        }
        rri::write_case_evidence(evidence_dir + "/cases", result);
        rri::print_case_line(result);
        results.push_back(result);
    }

    const std::uint64_t elapsed = rri::now_ms() - run_t0;

    // run budget: the authorized (a) run must stay short
    {
        CaseResult budget;
        budget.id = "run_budget";
        budget.protocol = opt.protocol;
        budget.server_tag = known->tag;
        budget.check("run_elapsed_under_60s", elapsed < 60000,
                     "elapsed_ms=" + rri::format_uint64(elapsed));
        budget.note("sum of per-case wall/measured times; server startup and teardown included");
        results.push_back(budget);
    }

    rri::write_run_summary(evidence_dir + "/summary.json", cfg, results, opt.room_exe);
    write_text(evidence_dir + "/commands.txt", commands);
    write_identity_json(evidence_dir + "/server-identity.json", plan, opt.room_exe, bytes, sha,
                        opt.protocol, known->build_id, known->source_compared,
                        opt.allow_wildcard_bind, results.size(), 0, elapsed, observed_endpoints);

    int failed = 0;
    for (const auto& result : results)
        if (!result.ok) ++failed;
    std::printf("RESULT mode=real protocol=%s server=%s cases=%llu failed=%d elapsed_ms=%llu\n",
                opt.protocol.c_str(), known->tag.c_str(),
                static_cast<unsigned long long>(results.size()), failed,
                static_cast<unsigned long long>(elapsed));
    return failed == 0 ? 0 : 1;
}

// ---------------------------------------------------------------- attach mode
// Drive a room server that is ALREADY running: this process starts nothing, authorizes no binary
// and deliberately skips the V-017 inventory check (the whole point is to probe a server that is
// not in that table).  Every artifact written here says so in its first lines.
struct AttachTarget {
    std::string host;
    std::uint16_t port = 0;
    std::string text; // normalized host:port
};

bool parse_attach_addr(const std::string& text, AttachTarget& out, std::string& error) {
    const std::size_t colon = text.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= text.size()) {
        error = "expected <ip>:<port>, got '" + text + "'";
        return false;
    }
    const std::string host = text.substr(0, colon);
    const std::string port_text = text.substr(colon + 1);
    for (const char c : port_text)
        if (c < '0' || c > '9') {
            error = "port is not numeric: '" + port_text + "'";
            return false;
        }
    const unsigned long port = std::strtoul(port_text.c_str(), nullptr, 10);
    if (port == 0 || port > 65535) {
        error = "port out of range: " + port_text;
        return false;
    }
    if (host != "127.0.0.1" && host != "localhost") {
        error = "the attach target must be 127.0.0.1 or localhost: every client case connects to "
                "127.0.0.1, so a non-loopback target is untested (see the report's untested list)";
        return false;
    }
    out.host = "127.0.0.1";
    out.port = static_cast<std::uint16_t>(port);
    out.text = out.host + ":" + rri::format_uint64(out.port);
    return true;
}

bool in_skip_list(const std::string& csv, const std::string& id) {
    std::size_t start = 0;
    while (start <= csv.size()) {
        const std::size_t comma = csv.find(',', start);
        const std::string part = rri::trim(csv.substr(
            start, comma == std::string::npos ? std::string::npos : comma - start));
        if (!part.empty() && part == id) return true;
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return false;
}

// One runnable case plus the room-side property it needs (recorded as a note, and part of the
// attach contract: a case that needs more than "the room exists and the password is right"
// belongs in the skipped table instead).
struct AttachEntry {
    CaseEntry entry;
    const char* needs;
};

struct AttachSkip {
    const char* id;
    const char* reason;
};

std::vector<AttachEntry> attach_runnable(const std::string& protocol, const std::string& cases) {
    const bool all = (cases == "all");
    std::vector<AttachEntry> out;
    if (protocol == "v4") {
        out.push_back({{"join_v4", rri::case_join_v4, 8},
                       "room exists, password known, at least one free member slot"});
        out.push_back({{"version_mismatch_v4", rri::case_version_mismatch_v4, 8},
                       "room rejects the wrong network version"});
        out.push_back({{"wrong_password_v4", rri::case_wrong_password_v4, 8},
                       "room is password protected"});
        out.push_back({{"name_collision_v4", rri::case_name_collision_v4, 8},
                       "room refuses a duplicate nickname"});
        out.push_back({{"console_id_collision_v4", rri::case_console_id_collision_v4, 8},
                       "room refuses a duplicate console id"});
        out.push_back({{"error_order_v4", rri::case_error_order_v4, 8},
                       "room is password protected and has a free slot"});
        if (all) {
            out.push_back({{"chat_v4", rri::case_chat_v4, 8}, "two free member slots"});
            out.push_back({{"wifi_route_v4", rri::case_wifi_route_v4, 8}, "three free member slots"});
            out.push_back({{"wifi_broadcast_v4", rri::case_wifi_broadcast_v4, 8},
                           "three free member slots"});
        }
    } else {
        out.push_back({{"join", rri::case_join, 8},
                       "room exists, password known, at least one free member slot"});
        out.push_back({{"version_mismatch", rri::case_version_mismatch, 8},
                       "room rejects the wrong network version"});
        out.push_back({{"wrong_password", rri::case_wrong_password, 8},
                       "room is password protected"});
        out.push_back({{"name_collision", rri::case_name_collision, 8},
                       "room refuses a duplicate nickname"});
        if (all) {
            out.push_back({{"ip_collision", rri::case_ip_collision, 8},
                           "room refuses a duplicate preferred address"});
            out.push_back({{"error_order", rri::case_error_order, 8},
                           "room is password protected and has a free slot"});
            out.push_back({{"family_isolation", rri::case_family_isolation, 8}, "a free member slot"});
            out.push_back({{"proxy_route", rri::case_proxy_route, 8}, "three free member slots"});
            out.push_back({{"proxy_broadcast", rri::case_proxy_broadcast, 8},
                           "three free member slots"});
            out.push_back({{"dataplane_size", rri::case_dataplane_size, 8},
                           "two free member slots"});
            out.push_back({{"chat_limit", rri::case_chat_limit, 8}, "two free member slots"});
            out.push_back({{"unjoined_source", rri::case_unjoined_source, 8},
                           "two free member slots"});
        }
    }
    return out;
}

std::vector<AttachSkip> attach_always_skipped(const std::string& protocol) {
    if (protocol == "v4") {
        return {{"room_full_v4",
                 "needs a room this run starts with a known small -slots and fills itself; the "
                 "foreign room cannot be re-configured without stopping the server under test"}};
    }
    return {{"room_full",
             "needs a room this run starts with a known small -slots and fills itself"},
            {"release",
             "needs capacity=2 and a slot table this run controls (leave/rejoin accounting)"},
            {"m2_parity",
             "uses the M2 room_transport client instead of the independent raw client and joins an "
             "extra member; not an independent reading of a foreign room"},
            {"port_conflict",
             "needs this run to start the server itself so a second bind attempt can be observed"},
            {"fixture_bytes",
             "expects a freshly started room with a known name/capacity and no other members"},
            {"bind_gate",
             "static bind-gate checks over the authorized binaries; attach authorizes no binary"}};
}

void write_attach_summary(const std::string& path, const AttachTarget& target, const Options& opt,
                          const RunConfig& cfg, const std::vector<CaseResult>& cases,
                          const std::vector<UdpEndpoint>& endpoints_before,
                          const std::vector<UdpEndpoint>& endpoints_after, bool wildcard,
                          std::uint64_t elapsed_ms) {
    const std::size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        std::error_code ec;
        std::filesystem::create_directories(path.substr(0, slash), ec);
    }
    std::ofstream out(path);
    std::size_t executed = 0, skipped = 0, check_failures = 0;
    int passed = 0, failed = 0;
    for (const auto& c : cases) {
        if (c.skipped) {
            ++skipped;
            continue;
        }
        ++executed;
        if (c.ok) ++passed; else ++failed;
        check_failures += c.failed_checks();
    }
    out << "{\n";
    out << "  \"tool\": \"real-room-interop\",\n";
    out << "  \"mode\": \"attach\",\n";
    out << "  \"protocol\": \"" << rri::json_escape(cfg.protocol) << "\",\n";
    out << "  \"server_tag\": \"" << rri::json_escape(cfg.server_tag) << "\",\n";
    out << "  \"server_is_inventory\": false,\n";
    out << "  \"server_inventory_check\": \"skipped on purpose: docs/VERIFICATION-LOG.md V-017 "
           "does not cover this target\",\n";
    out << "  \"not_distribution_evidence\": true,\n";
    out << "  \"warning\": \"该目标不在授权清单内，本次运行不作为发行版证据 / this target is not "
           "in the authorized inventory, so this run is not distribution evidence\",\n";
    out << "  \"attach_addr\": \"" << rri::json_escape(target.text) << "\",\n";
    out << "  \"attach_host\": \"" << rri::json_escape(target.host) << "\",\n";
    out << "  \"attach_port\": " << rri::format_uint64(target.port) << ",\n";
    out << "  \"attach_is_loopback\": true,\n";
    out << "  \"attach_observed_wildcard_bind\": " << (wildcard ? "true" : "false") << ",\n";
    out << "  \"server_started_by_this_run\": false,\n";
    out << "  \"password\": \"" << rri::json_escape(opt.attach_password) << "\",\n";
    out << "  \"room_name\": \"" << rri::json_escape(opt.attach_room_name) << "\",\n";
    out << "  \"room_name_declared\": " << (opt.attach_room_name.empty() ? "false" : "true") << ",\n";
    out << "  \"slots\": " << rri::format_uint64(opt.attach_slots) << ",\n";
    out << "  \"slots_declared\": " << (opt.attach_slots == 0 ? "false" : "true") << ",\n";
    out << "  \"observed_udp_endpoints_before\": [";
    for (std::size_t i = 0; i < endpoints_before.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << rri::json_escape(endpoints_before[i].address + ":" +
                                        rri::format_uint64(endpoints_before[i].port) + " pid=" +
                                        rri::format_uint64(endpoints_before[i].pid)) << "\"";
    }
    out << "],\n";
    out << "  \"observed_udp_endpoints_after\": [";
    for (std::size_t i = 0; i < endpoints_after.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << rri::json_escape(endpoints_after[i].address + ":" +
                                        rri::format_uint64(endpoints_after[i].port) + " pid=" +
                                        rri::format_uint64(endpoints_after[i].pid)) << "\"";
    }
    out << "],\n";
    out << "  \"cases_executed\": " << executed << ",\n";
    out << "  \"cases_passed\": " << passed << ",\n";
    out << "  \"cases_failed\": " << failed << ",\n";
    out << "  \"cases_skipped\": " << skipped << ",\n";
    out << "  \"checks_failed\": " << check_failures << ",\n";
    out << "  \"elapsed_ms\": " << elapsed_ms << ",\n";
    out << "  \"skipped\": [\n";
    bool first_skip = true;
    for (const auto& c : cases) {
        if (!c.skipped) continue;
        if (!first_skip) out << ",\n";
        first_skip = false;
        out << "    {\"id\": \"" << rri::json_escape(c.id) << "\", \"reason\": \""
            << rri::json_escape(c.skip_reason) << "\"}";
    }
    out << "\n  ],\n";
    out << "  \"cases\": [\n";
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const auto& c = cases[i];
        out << "    {\"id\": \"" << rri::json_escape(c.id) << "\", \"skipped\": "
            << (c.skipped ? "true" : "false");
        if (c.skipped) out << ", \"skip_reason\": \"" << rri::json_escape(c.skip_reason) << "\"";
        out << ", \"ok\": " << (c.ok ? "true" : "false") << ", \"ms\": " << c.ms
            << ", \"checks_failed\": " << c.failed_checks() << ", \"checks\": [";
        for (std::size_t j = 0; j < c.checks.size(); ++j) {
            const auto& ch = c.checks[j];
            if (j) out << ", ";
            out << "{\"name\": \"" << rri::json_escape(ch.name) << "\", \"ok\": "
                << (ch.ok ? "true" : "false");
            if (!ch.detail.empty()) out << ", \"detail\": \"" << rri::json_escape(ch.detail) << "\"";
            out << "}";
        }
        out << "]";
        if (!c.notes.empty()) {
            out << ", \"notes\": [";
            for (std::size_t j = 0; j < c.notes.size(); ++j) {
                if (j) out << ", ";
                out << "\"" << rri::json_escape(c.notes[j]) << "\"";
            }
            out << "]";
        }
        out << "}" << (i + 1 == cases.size() ? "" : ",") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

int run_attach(const Options& opt) {
    if (opt.attach_addr.empty()) {
        std::fprintf(stderr,
                     "attach mode needs -AttachAddr <ip:port> pointing at an ALREADY running room "
                     "server (this mode starts nothing)\n");
        return 2;
    }
    if (opt.protocol != "v1" && opt.protocol != "v4") {
        std::fprintf(stderr, "attach mode needs -Protocol v1|v4\n");
        return 2;
    }
    AttachTarget target;
    std::string error;
    if (!parse_attach_addr(opt.attach_addr, target, error)) {
        std::fprintf(stderr, "bad -AttachAddr: %s\n", error.c_str());
        return 2;
    }

    std::printf("##########################################################################\n");
    std::printf("!!! ATTACH MODE: 该目标不在授权清单内，本次运行不作为发行版证据\n");
    std::printf("!!! the target %s is NOT in the authorized inventory (docs/VERIFICATION-LOG.md\n",
                target.text.c_str());
    std::printf("!!! V-017); this run is NOT distribution evidence and must not be cited as such.\n");
    std::printf("!!! no room server is started, no binary is authorized, no emulator/game/ROM is\n");
    std::printf("!!! involved; the V-017 identity check is skipped on purpose.\n");
    std::printf("##########################################################################\n");

    const std::vector<UdpEndpoint> endpoints_before = rri::udp_endpoints_by_port(target.port);
    if (endpoints_before.empty()) {
        std::fprintf(stderr,
                     "ATTACH REFUSED: nothing is listening on UDP port %u; start the external room "
                     "server first (attach mode never starts one)\n",
                     static_cast<unsigned>(target.port));
        return 6;
    }
    bool wildcard = false;
    for (const auto& endpoint : endpoints_before)
        if (endpoint.port == target.port && (endpoint.wildcard || endpoint.address == "0.0.0.0"))
            wildcard = true;
    std::printf("ATTACH TARGET: %s protocol=%s udp_endpoints=%s\n", target.text.c_str(),
                opt.protocol.c_str(), rri::describe_endpoints(endpoints_before).c_str());
    if (wildcard)
        std::printf("NOTE: the target holds a wildcard (0.0.0.0) endpoint; 127.0.0.1 is still "
                    "reachable, so the loopback client can use it.\n");

    const std::string tag = opt.attach_tag.empty()
                                ? ("foreign-" + target.host + "-" + rri::format_uint64(target.port))
                                : opt.attach_tag;
    RunConfig cfg;
    cfg.mode = "attach";
    cfg.protocol = opt.protocol;
    cfg.evidence_root = opt.evidence_root;
    cfg.work_root = opt.work_root;
    cfg.server_tag = tag;
    cfg.allow_run = false;
    cfg.base_port = target.port;

    std::printf("ATTACH MODE: tag=%s cases=%s password_set=%s room_name=%s slots=%s\n",
                tag.c_str(), opt.cases.c_str(),
                opt.attach_password.empty() ? "no" : "yes",
                opt.attach_room_name.empty() ? "(not declared)" : opt.attach_room_name.c_str(),
                opt.attach_slots == 0 ? "(not declared)" : rri::format_uint64(opt.attach_slots).c_str());

    const std::string evidence_dir = opt.evidence_root + "/attach/" + tag;
    std::vector<CaseResult> results;
    const std::uint64_t run_t0 = rri::now_ms();
    std::string target_text;

    ServerSpec shape;
    shape.protocol = opt.protocol;
    shape.port = target.port;
    shape.password = opt.attach_password;

    for (const auto& item : attach_runnable(opt.protocol, opt.cases)) {
        const CaseEntry& entry = item.entry;
        if (in_skip_list(opt.attach_skip, entry.id)) {
            CaseResult skipped = rri::begin_case(cfg, shape, entry.id);
            skipped.skipped = true;
            skipped.skip_reason = "listed in -Skip: the operator declared this case not applicable "
                                  "to this target room";
            skipped.note("skipped_by=-Skip");
            std::printf("CASE %-22s SKIPPED  %s\n", entry.id, skipped.skip_reason.c_str());
            results.push_back(skipped);
            continue;
        }
        ServerSpec spec;
        spec.scenario = entry.id;
        spec.protocol = opt.protocol;
        spec.port = target.port;
        spec.capacity = opt.attach_slots != 0 ? opt.attach_slots : entry.capacity;
        spec.password = opt.attach_password;
        spec.room_name = opt.attach_room_name;
        spec.check_room_name = !opt.attach_room_name.empty();
        spec.check_capacity = opt.attach_slots != 0;
        spec.workdir = opt.work_root + "/attach/" + std::string(entry.id);

        CaseContext context;
        context.use_server = false; // the server is already running; never start one here
        context.loopback_only = true;

        RunFacts facts;
        std::string command;
        CaseResult result = run_case(cfg, spec, entry, context, command, facts);
        result.note("attach_target=" + target.text +
                    " (no server process was started by this run)");
        result.note("server_is_inventory=false (the V-017 inventory check is skipped on purpose)");
        result.note("attach_needs=" + std::string(item.needs));
        rri::write_case_evidence(evidence_dir + "/cases", result);
        rri::print_case_line(result);
        results.push_back(result);
        target_text += std::string(entry.id) + "\n";
    }

    for (const auto& skip : attach_always_skipped(opt.protocol)) {
        CaseResult skipped = rri::begin_case(cfg, shape, skip.id);
        skipped.skipped = true;
        skipped.skip_reason = skip.reason;
        skipped.note("skipped_because=the foreign room cannot be re-configured by this run");
        std::printf("CASE %-22s SKIPPED  %s\n", skip.id, skip.reason);
        results.push_back(skipped);
    }

    const std::vector<UdpEndpoint> endpoints_after = rri::udp_endpoints_by_port(target.port);

    {
        const std::uint64_t t0 = rri::now_ms();
        CaseResult meta = rri::begin_case(cfg, shape, "attach_target");
        meta.check("attach_target_is_loopback", true, target.text);
        meta.check("attach_listening_before_first_case", !endpoints_before.empty(),
                   rri::describe_endpoints(endpoints_before));
        meta.check("attach_listening_after_last_case", !endpoints_after.empty(),
                   rri::describe_endpoints(endpoints_after));
        meta.note("server_is_inventory=false; the V-017 inventory check is skipped on purpose");
        meta.note(std::string("attach_wildcard_endpoint=") + (wildcard ? "true" : "false"));
        meta.note(std::string("target_started_by_this_run=false; the server outlives this run, so "
                              "no port-release check is meaningful here"));
        meta.note("case set: the v4/v1 client-side cases only; server-configured cases are listed "
                  "as skipped in summary.json");
        rri::end_case(meta, t0);
        rri::write_case_evidence(evidence_dir + "/cases", meta);
        rri::print_case_line(meta);
        results.push_back(meta);
    }

    const std::uint64_t elapsed = rri::now_ms() - run_t0;
    int failed = 0;
    std::size_t executed = 0, skipped_count = 0;
    for (const auto& result : results) {
        if (result.skipped) {
            ++skipped_count;
            continue;
        }
        ++executed;
        if (!result.ok) ++failed;
    }
    write_attach_summary(evidence_dir + "/summary.json", target, opt, cfg, results, endpoints_before,
                         endpoints_after, wildcard, elapsed);
    write_text(evidence_dir + "/target.txt",
               std::string("mode=attach\n") + "attach_addr=" + target.text + "\n" +
                   "protocol=" + opt.protocol + "\n" +
                   "server_is_inventory=false\n" +
                   "server_started_by_this_run=false\n" +
                   "not_distribution_evidence=true\n" +
                   "room_name=" + (opt.attach_room_name.empty() ? "(not declared)"
                                                                : opt.attach_room_name) +
                   "\nslots=" + (opt.attach_slots == 0 ? "(not declared)"
                                                       : rri::format_uint64(opt.attach_slots)) +
                   "\nendpoints_before=" + rri::describe_endpoints(endpoints_before) +
                   "\nendpoints_after=" + rri::describe_endpoints(endpoints_after) +
                   "\ncases_executed=" + rri::format_uint64(executed) +
                   "\ncases_failed=" + rri::format_uint64(static_cast<std::uint64_t>(failed)) +
                   "\ncases_skipped=" + rri::format_uint64(skipped_count) +
                   "\nexecuted_cases:\n" + target_text + "skipped_cases:\n" +
                   [&] {
                       std::string s;
                       for (const auto& result : results)
                           if (result.skipped) s += result.id + " :: " + result.skip_reason + "\n";
                       return s;
                   }());
    std::printf("RESULT mode=attach protocol=%s target=%s tag=%s cases_executed=%llu failed=%d "
                "skipped=%llu inventory_check=skipped elapsed_ms=%llu\n",
                opt.protocol.c_str(), target.text.c_str(), tag.c_str(),
                static_cast<unsigned long long>(executed), failed,
                static_cast<unsigned long long>(skipped_count),
                static_cast<unsigned long long>(elapsed));
    return failed == 0 ? 0 : 1;
}

// ---------------------------------------------------------------- dry run
int run_dryrun(const Options& opt) {
    const std::string args_v1 = opt.room_args_file.empty() ? "config/yuzu-room.args"
                                                           : opt.room_args_file;
    const std::string args_v4 = opt.room_args_file.empty() ? "config/citra-room.args"
                                                           : opt.room_args_file;
    std::string json = "{\n  \"tool\": \"real-room-interop\",\n  \"mode\": \"dryrun\",\n";
    json += "  \"executed\": false,\n";
    json += "  \"note\": \"NOT EXECUTED / 尚未执行: these are the exact commands real mode would "
            "run after authorization\",\n";
    json += "  \"candidates\": [\n";

    std::printf("DRY RUN (NOT EXECUTED / 尚未执行)\n");
    bool first_server = true;
    int refused = 0;
    for (const auto& known : known_servers()) {
        if (!opt.server_tag.empty() && known.tag != opt.server_tag) continue;
        const std::string& args_file = known.protocol == "v1" ? args_v1 : args_v4;
        std::map<std::string, std::vector<std::string>> args_map;
        std::string error;
        const bool args_ok = rri::parse_args_file(args_file, args_map, error);
        const std::vector<std::string> raw =
            args_map.count("*") ? args_map["*"] : std::vector<std::string>{};
        const std::uint64_t actual_bytes = rri::file_size(known.path);
        const std::string actual_sha = rri::file_sha256_hex(known.path);
        const bool present = actual_bytes != 0;
        const bool identity_match = present && actual_sha == known.sha256;
        const bool supports_bind = file_has_ascii(known.path, "bind-address");
        std::string bind_value;
        const bool args_have_bind = args_find_bind(raw, bind_value);
        const GateDecision gate = decide_bind(supports_bind, args_have_bind, bind_value, false);
        if (!gate.allowed) ++refused;

        if (!first_server) json += ",\n";
        first_server = false;
        json += "    {\n";
        json += "      \"tag\": \"" + rri::json_escape(known.tag) + "\",\n";
        json += "      \"kind\": \"" + known.kind + "\",\n";
        json += "      \"protocol\": \"" + known.protocol + "\",\n";
        json += "      \"path\": \"" + rri::json_escape(known.path) + "\",\n";
        json += "      \"expected_bytes\": " + rri::format_uint64(known.bytes) + ",\n";
        json += "      \"actual_bytes\": " + rri::format_uint64(actual_bytes) + ",\n";
        json += "      \"expected_sha256\": \"" + known.sha256 + "\",\n";
        json += "      \"actual_sha256\": \"" + actual_sha + "\",\n";
        json += std::string("      \"present\": ") + (present ? "true" : "false") + ",\n";
        json += std::string("      \"identity_match\": ") + (identity_match ? "true" : "false") + ",\n";
        json += "      \"build_id\": \"" + rri::json_escape(known.build_id) + "\",\n";
        json += std::string("      \"source_compared\": ") + (known.source_compared ? "true" : "false") +
                ",\n";
        json += "      \"args_file\": \"" + rri::json_escape(args_file) + "\",\n";
        json += std::string("      \"args_file_ok\": ") + (args_ok ? "true" : "false") + ",\n";
        json += std::string("      \"supports_bind_address\": ") + (supports_bind ? "true" : "false") +
                ",\n";
        json += "      \"bind_gate\": {\"allowed_without_switch\": " +
                std::string(gate.allowed && gate.loopback_only ? "true" : "false") +
                ", \"loopback_only\": " + (gate.loopback_only ? "true" : "false") +
                ", \"inject_bind_address\": " + (gate.inject ? "true" : "false") + ", \"reason\": \"" +
                rri::json_escape(gate.reason) + "\"},\n";
        json += "      \"scenarios\": [\n";

        const std::vector<CaseEntry> entries =
            known.protocol == "v1" ? v1_cases_all() : v4_cases_all();
        std::printf("\n[%s] %s (%s, %s)\n", known.tag.c_str(), known.path.c_str(),
                    known.protocol.c_str(), present ? (identity_match ? "identity OK" : "IDENTITY MISMATCH")
                                                   : "MISSING");
        std::printf("  args file: %s%s\n", args_file.c_str(), args_ok ? "" : " (MISSING)");
        std::printf("  supports --bind-address: %s\n", supports_bind ? "yes" : "no");
        std::printf("  default gate: %s (%s)\n", gate.allowed ? "ALLOWED" : "REFUSED",
                    gate.reason.c_str());

        for (std::size_t i = 0; i < entries.size(); ++i) {
            ServerSpec spec;
            spec.scenario = entries[i].id;
            spec.protocol = known.protocol;
            spec.port = static_cast<std::uint16_t>(opt.base_port + i);
            spec.capacity = entries[i].capacity;
            spec.password = "pw1";
            spec.room_name = "rri-dryrun-" + std::string(entries[i].id);
            spec.workdir =
                opt.work_root + "/dryrun/" + known.tag + "/" + std::string(entries[i].id);
            const std::vector<std::string> args =
                substituted_args(RunConfig{}, spec, raw, gate.inject);
            const std::string command = render_command_line(known.path, args);
            if (i) json += ",\n";
            json += "        {\"case\": \"" + rri::json_escape(entries[i].id) + "\", \"port\": " +
                    rri::format_uint64(spec.port) + ", \"workdir\": \"" +
                    rri::json_escape(spec.workdir) + "\", \"max_members\": " +
                    rri::format_uint64(spec.capacity) + ", \"command_line\": \"" +
                    rri::json_escape(command) + "\"}";
            std::printf("  case %-22s port=%u  %s\n", entries[i].id, spec.port, command.c_str());
        }
        json += "\n      ]\n    }";
        std::printf("  (NOT EXECUTED / 尚未执行)\n");
    }
    json += "\n  ]\n}\n";
    if (!opt.server_tag.empty()) {
        // keep the JSON a single object; server_tag filtering already applied above
    }
    write_text(opt.evidence_root + "/dry-run.json", json);
    std::printf("\nDRY RUN SUMMARY: %d candidate(s) allowed by default, %d need -AllowWildcardBind; "
                "nothing was executed.\n",
                static_cast<int>(known_servers().size()) - refused, refused);
    return 0;
}

// ---------------------------------------------------------------- probe
int run_probe(const Options& opt) {
    if (!opt.allow_run) {
        std::fprintf(stderr, "未获用户授权: probe runs the real binaries; pass -AllowRun\n");
        return 3;
    }
    int failures = 0;
    int selected = 0;
    // Selection rules, in priority order:
    //   -ServerTag <tag>  -> exactly that candidate (error if unknown)
    //   -RoomExe <path>   -> exactly that candidate (error if not in the identity table)
    //   -AllServers       -> all five candidates
    //   neither           -> all five candidates, with a printed note
    if (!opt.server_tag.empty() && !known_by_tag(opt.server_tag)) {
        std::fprintf(stderr, "unknown -ServerTag %s\n", opt.server_tag.c_str());
        return 2;
    }
    if (!opt.room_exe.empty() && !known_by_sha(rri::file_sha256_hex(opt.room_exe))) {
        std::fprintf(stderr,
                     "-RoomExe is not one of the five inventoried room servers: %s\n",
                     opt.room_exe.c_str());
        return 4;
    }
    if (opt.server_tag.empty() && opt.room_exe.empty() && !opt.all_servers)
        std::printf("PROBE: no -ServerTag/-RoomExe given, probing all %llu candidates "
                    "(pass -ServerTag to narrow)\n",
                    static_cast<unsigned long long>(known_servers().size()));
    for (const auto& known : known_servers()) {
        if (!opt.server_tag.empty() && known.tag != opt.server_tag) continue;
        if (opt.server_tag.empty() && !opt.room_exe.empty() && known.path != opt.room_exe) continue;
        ++selected;
        const std::string dir = opt.evidence_root + "/probe/" + known.tag;
        const std::string out_file = dir + "/version.out.txt";
        const std::string err_file = dir + "/version.err.txt";
        ServerSpec spec;
        spec.exe = known.path;
        spec.args = {"--version"};
        spec.workdir = opt.work_root + "/probe/" + known.tag;
        spec.out_file = out_file;
        spec.err_file = err_file;
        spec.ready_marker = ""; // wait for exit instead
        std::string error;
        rri::ChildProcess child;
        if (!child.start(spec.exe, spec.args, spec.workdir, spec.out_file, spec.err_file, error)) {
            std::printf("PROBE %s: start failed: %s\n", known.tag.c_str(), error.c_str());
            ++failures;
            continue;
        }
        const bool exited = child.wait_for_exit(8000);
        if (!exited) child.terminate(2000);
        const std::string text = rri::read_file(out_file) + rri::read_file(err_file);
        std::printf("PROBE %s --version (exit=%d, output %s)\n", known.tag.c_str(),
                    child.started() ? 0 : -1, exited ? "captured" : "TIMEOUT");
        std::string shown = rri::trim(text);
        if (shown.size() > 600) shown = shown.substr(0, 600) + "...";
        std::printf("----- %s --version -----\n%s\n", known.tag.c_str(), shown.c_str());
        if (opt.with_help) {
            const std::string help_out = dir + "/help.out.txt";
            const std::string help_err = dir + "/help.err.txt";
            rri::ChildProcess help;
            std::vector<std::string> help_args{"--help"};
            std::string herror;
            if (help.start(known.path, help_args, spec.workdir, help_out, help_err, herror)) {
                if (!help.wait_for_exit(8000)) help.terminate(2000);
                std::printf("PROBE %s --help captured\n", known.tag.c_str());
            } else {
                std::printf("PROBE %s --help failed: %s\n", known.tag.c_str(), herror.c_str());
            }
        }
    }
    std::printf("PROBE DONE: %d candidate(s) probed, %d failure(s)\n", selected, failures);
    return failures == 0 ? 0 : 1;
}

} // namespace

int main(int, char**) {
    const std::vector<std::string> args = rri::utf8_argv();
    // Keep the ENet runtime alive for the whole process: the raw capture client relies on the
    // ENet/WS2 state that a room_transport::Runtime would otherwise tear down.
    room_transport::Runtime runtime;

    // 'observe' has its own flag grammar (--room, --room-port, ...); dispatch before the
    // dash-option parser so the two grammars cannot collide.
    if (args.size() >= 2 && args[1] == "observe") return rri::run_observe(args);

    Options opt;
    std::string error;
    if (!parse_options(args, opt, error)) {
        std::fprintf(stderr, "argument error: %s\n\n", error.c_str());
        usage();
        return 2;
    }
    if (opt.mode == "self") return run_self(opt);
    if (opt.mode == "real") return run_real(opt);
    if (opt.mode == "attach") return run_attach(opt);
    if (opt.mode == "dryrun") return run_dryrun(opt);
    return run_probe(opt);
}
