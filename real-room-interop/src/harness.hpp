// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
// Test-case bookkeeping, evidence files and the bounded room-server launcher.
#include "raw_client.hpp"
#include "subprocess.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace rri {

struct Check {
    std::string name;
    bool ok = false;
    std::string detail;
};

struct CaseResult {
    std::string id;
    std::string protocol;
    std::string server_tag;
    bool ok = true;
    // Attach mode only: the case needs a server-side configuration this run cannot set up, so
    // it was not executed. A skipped case is neither a pass nor a failure and writes no
    // wire/checks files of its own.
    bool skipped = false;
    std::string skip_reason;
    std::uint64_t ms = 0;
    std::vector<Check> checks;
    std::vector<std::string> notes;
    std::vector<std::pair<std::string, WireFrame>> frames; // (role, frame)
    void check(const std::string& name, bool ok, const std::string& detail = std::string());
    void note(const std::string& text) { notes.push_back(text); }
    void capture(const std::string& role, const RawClient& client);
    int failed_checks() const;
};

struct ServerSpec {
    std::string scenario;
    std::string protocol = "v1";
    std::uint16_t port = 39572;
    std::uint32_t capacity = 8;
    std::string password = "pw1";
    std::string room_name;
    std::string preferred_game;
    // Launch description of the primary room server for this scenario (filled by main).
    // Cases receive it so that they can start additional servers (e.g. the port-conflict probe).
    std::string exe;
    std::vector<std::string> args;
    std::string workdir;
    std::string out_file;
    std::string err_file;
    std::string ready_marker;
    // Attach mode: the room shape (name, capacity) is a property of the foreign server and may
    // be unknown; when it is not declared the corresponding join checks are reported as skipped
    // instead of being asserted against a guess.
    bool check_room_name = true;
    bool check_capacity = true;
};

struct RunConfig {
    std::string mode = "self";    // self | real
    std::string protocol = "v1";  // v1 | v4
    std::string evidence_root = "evidence";
    std::string work_root = "work";
    std::string self_server_exe;
    std::string room_exe;
    std::string room_exe_tag = "room";
    std::string server_tag;
    bool allow_run = false;
    std::uint16_t base_port = 39572;
    std::map<std::string, std::vector<std::string>> args_by_scenario; // real mode
};

struct ServerLaunch {
    std::string exe;
    std::string tag;
    std::vector<std::string> args;
    std::string workdir;
    std::string out_file;
    std::string err_file;
    std::string ready_marker;
};

class ServerSession {
public:
    bool start(const ServerLaunch& launch, std::uint32_t ready_timeout_ms, std::string& error);
    ProcessStatus stop();
    int exit_code() const { return status_.exit_code; }
    std::uint32_t pid() const { return proc_.pid(); }
    bool timed_out() const { return status_.timed_out; }
    const std::string& out_file() const { return launch_.out_file; }
    const ServerLaunch& launch() const { return launch_; }
    std::string stdout_tail(std::size_t max_bytes) const;
    std::string stderr_tail(std::size_t max_bytes) const;
    bool stdout_contains(const std::string& needle) const;
    // The room log shim writes through fprintf(stderr), so member-join/game lines land on
    // the child's stderr: search both streams.
    bool output_contains(const std::string& needle) const;
    const std::string& err_file() const { return launch_.err_file; }
    // True when readiness came from the pid's UDP endpoint instead of the marker text
    // (the real binaries' console log can still be buffered).
    bool ready_via_endpoint() const { return ready_via_endpoint_; }

private:
    ServerLaunch launch_;
    ChildProcess proc_;
    ProcessStatus status_;
    bool started_ = false;
    bool ready_via_endpoint_ = false;
};

// 'key = arg arg ...' lines; '*' is the default; '#' comments; blank lines ignored.
bool parse_args_file(const std::string& path,
                     std::map<std::string, std::vector<std::string>>& out, std::string& error);

std::string substitute_placeholders(const std::string& arg, std::uint16_t port,
                                    const std::string& workdir);

std::vector<std::string> effective_args(const RunConfig& cfg, const std::string& scenario);

ServerLaunch to_launch(const ServerSpec& spec);

std::string read_file(const std::string& path);
std::string file_sha256_hex(const std::string& path);
std::uint64_t file_size(const std::string& path);

void write_case_evidence(const std::string& root, const CaseResult& result);
void write_run_summary(const std::string& path, const RunConfig& cfg,
                       const std::vector<CaseResult>& cases, const std::string& server_exe);
void print_case_line(const CaseResult& result);

} // namespace rri
