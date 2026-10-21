// SPDX-License-Identifier: GPL-2.0-or-later
#include "harness.hpp"

#include "sha256.hpp"
#include "util.hpp"
#include "win_net.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace rri {

void CaseResult::check(const std::string& name, bool value, const std::string& detail) {
    checks.push_back(Check{name, value, detail});
    if (!value) ok = false;
}

int CaseResult::failed_checks() const {
    int n = 0;
    for (const auto& c : checks)
        if (!c.ok) ++n;
    return n;
}

void CaseResult::capture(const std::string& role, const RawClient& client) {
    for (const auto& f : client.frames()) frames.emplace_back(role, f);
}

namespace {
// Non-ASCII (e.g. Chinese) directory names appear in the candidate server paths, so
// every file access goes through the UTF-8 -> UTF-16 conversion of util.hpp.
std::FILE* open_utf8(const std::string& path) {
#ifdef _WIN32
    return _wfopen(utf8_to_wide(path).c_str(), L"rb");
#else
    return std::fopen(path.c_str(), "rb");
#endif
}
} // namespace

std::string read_file(const std::string& path) {
    std::FILE* f = open_utf8(path);
    if (!f) return {};
    std::string out;
    char buf[65536];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    std::fclose(f);
    return out;
}

std::uint64_t file_size(const std::string& path) {
    std::FILE* f = open_utf8(path);
    if (!f) return 0;
    std::fseek(f, 0, SEEK_END);
    const long long n = _ftelli64(f);
    std::fclose(f);
    return n < 0 ? 0 : static_cast<std::uint64_t>(n);
}

std::string file_sha256_hex(const std::string& path) {
    std::FILE* f = open_utf8(path);
    if (!f) return {};
    sha256_impl::Ctx ctx;
    sha256_impl::init(ctx);
    std::vector<char> buf(1 << 20);
    for (;;) {
        const std::size_t got = std::fread(buf.data(), 1, buf.size(), f);
        if (got > 0)
            sha256_impl::update(ctx, reinterpret_cast<const unsigned char*>(buf.data()), got);
        if (got < buf.size()) break;
    }
    std::fclose(f);
    unsigned char digest[32];
    sha256_impl::finish(ctx, digest);
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (unsigned char b : digest) {
        out.push_back(d[(b >> 4) & 0xF]);
        out.push_back(d[b & 0xF]);
    }
    return out;
}

bool parse_args_file(const std::string& path,
                     std::map<std::string, std::vector<std::string>>& out, std::string& error) {
    std::ifstream in(path);
    if (!in) {
        error = "cannot open args file: " + path;
        return false;
    }
    std::string line;
    int line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        const auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        line = trim(line);
        if (line.empty()) continue;
        const auto eq = line.find('=');
        if (eq == std::string::npos) {
            error = "args file line " + format_uint64(static_cast<std::uint64_t>(line_no)) +
                    " has no '='";
            return false;
        }
        const std::string key = trim(line.substr(0, eq));
        const std::string value = trim(line.substr(eq + 1));
        if (key.empty()) {
            error = "args file line " + format_uint64(static_cast<std::uint64_t>(line_no)) +
                    " has an empty key";
            return false;
        }
        out[key] = split_ws(value);
    }
    if (out.empty()) {
        error = "args file produced no entries: " + path;
        return false;
    }
    return true;
}

std::string substitute_placeholders(const std::string& arg, std::uint16_t port,
                                    const std::string& workdir) {
    std::string s = arg;
    for (;;) {
        const auto at = s.find("{port}");
        if (at == std::string::npos) break;
        s.replace(at, 6, format_uint64(port));
    }
    for (;;) {
        const auto at = s.find("{work}");
        if (at == std::string::npos) break;
        s.replace(at, 6, workdir);
    }
    return s;
}

std::vector<std::string> effective_args(const RunConfig& cfg, const std::string& scenario) {
    std::vector<std::string> raw;
    const auto star = cfg.args_by_scenario.find("*");
    if (star != cfg.args_by_scenario.end()) raw = star->second;
    const auto per = cfg.args_by_scenario.find(scenario);
    if (per != cfg.args_by_scenario.end()) {
        // Per-scenario line is complete by itself when present (no merge), which keeps
        // the audited command line identical to the one written in the dry run.
        raw = per->second;
    }
    return raw;
}

bool ServerSession::start(const ServerLaunch& launch, std::uint32_t ready_timeout_ms,
                          std::string& error) {
    launch_ = launch;
    ready_via_endpoint_ = false;
    std::error_code ec;
    if (!launch.workdir.empty()) std::filesystem::create_directories(launch.workdir, ec);
    const std::size_t slash = launch.out_file.find_last_of("/\\");
    if (slash != std::string::npos)
        std::filesystem::create_directories(launch.out_file.substr(0, slash), ec);
    if (!proc_.start(launch.exe, launch.args, launch.workdir, launch.out_file, launch.err_file,
                     error))
        return false;
    // The port the child was told to use, parsed from its own command line.
    std::uint16_t wanted_port = 0;
    for (std::size_t i = 0; i + 1 < launch.args.size(); ++i) {
        if (launch.args[i] == "--port" || launch.args[i] == "-p") {
            wanted_port = static_cast<std::uint16_t>(std::strtoul(launch.args[i + 1].c_str(),
                                                                  nullptr, 10));
            break;
        }
    }
    bool ready = false;
    const std::uint64_t deadline = now_ms() + ready_timeout_ms;
    for (;;) {
        if (proc_.wait_for_marker(launch.ready_marker, 200)) { ready = true; break; }
        // Fallback evidence, independent of console buffering: this pid owns a UDP
        // endpoint on the port it was launched with.
        if (wanted_port != 0) {
            for (const auto& endpoint : udp_endpoints_for_pid(proc_.pid()))
                if (endpoint.port == wanted_port) { ready = true; ready_via_endpoint_ = true; break; }
        }
        if (ready) break;
        if (now_ms() >= deadline) break;
    }
    if (!ready) {
        const std::string out_tail = trim(stdout_tail(1024));
        const std::string err_tail = trim(stderr_tail(1024));
        error = "room server did not report '" + launch.ready_marker + "' within " +
                format_uint64(ready_timeout_ms) + " ms; stdout tail: " + out_tail +
                " ; stderr tail: " + err_tail;
        proc_.terminate(2000);
        return false;
    }
    started_ = true;
    return true;
}

ProcessStatus ServerSession::stop() {
    if (!started_) return status_;
    status_ = proc_.stop(2500);
    started_ = false;
    return status_;
}

std::string ServerSession::stdout_tail(std::size_t max_bytes) const {
    const std::string all = read_file(launch_.out_file);
    if (all.size() <= max_bytes) return all;
    return all.substr(all.size() - max_bytes);
}

ServerLaunch to_launch(const ServerSpec& spec) {
    ServerLaunch launch;
    launch.exe = spec.exe;
    launch.tag = spec.scenario;
    launch.args = spec.args;
    launch.workdir = spec.workdir;
    launch.out_file = spec.out_file;
    launch.err_file = spec.err_file;
    launch.ready_marker = spec.ready_marker;
    return launch;
}

std::string ServerSession::stderr_tail(std::size_t max_bytes) const {
    const std::string all = read_file(launch_.err_file);
    if (all.size() <= max_bytes) return all;
    return all.substr(all.size() - max_bytes);
}

bool ServerSession::stdout_contains(const std::string& needle) const {
    return read_file(launch_.out_file).find(needle) != std::string::npos;
}

bool ServerSession::output_contains(const std::string& needle) const {
    return stdout_contains(needle) || read_file(launch_.err_file).find(needle) != std::string::npos;
}

void write_case_evidence(const std::string& root, const CaseResult& result) {
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    const std::string base = root + "/" + result.id;

    {
        std::ofstream out(base + ".wire.txt");
        out << "# scenario=" << result.id << " protocol=" << result.protocol
            << " server=" << result.server_tag << " ok=" << (result.ok ? 1 : 0)
            << " ms=" << result.ms << "\n";
        out << "# role C2S = bytes this harness put on the wire; role S2C = bytes the room sent\n";
        for (const auto& [role, f] : result.frames) {
            const char* dir = f.from_server ? "S2C" : "C2S";
            out << role << " " << dir << " t=" << f.t_ms << " ch=" << static_cast<int>(f.channel)
                << (f.reliable ? " reliable" : " unreliable") << " len=" << f.bytes.size() << " "
                << hex_spaced(f.bytes) << "\n";
        }
    }
    {
        std::ofstream out(base + ".s2c.hex");
        for (const auto& [role, f] : result.frames) {
            if (f.from_server) out << role << " " << hex_spaced(f.bytes) << "\n";
        }
    }
    {
        std::ofstream out(base + ".checks.txt");
        for (const auto& c : result.checks)
            out << (c.ok ? "PASS " : "FAIL ") << c.name
                << (c.detail.empty() ? "" : (" :: " + c.detail)) << "\n";
        for (const auto& n : result.notes) out << "NOTE " << n << "\n";
    }
}

void write_run_summary(const std::string& path, const RunConfig& cfg,
                       const std::vector<CaseResult>& cases, const std::string& server_exe) {
    const std::size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) {
        std::error_code ec;
        std::filesystem::create_directories(path.substr(0, slash), ec);
    }
    std::ofstream out(path);
    int passed = 0, failed = 0, check_failures = 0;
    std::uint64_t total_ms = 0;
    for (const auto& c : cases) {
        if (c.ok) ++passed; else ++failed;
        check_failures += c.failed_checks();
        total_ms += c.ms;
    }
    out << "{\n";
    out << "  \"tool\": \"real-room-interop\",\n";
    out << "  \"mode\": \"" << json_escape(cfg.mode) << "\",\n";
    out << "  \"protocol\": \"" << json_escape(cfg.protocol) << "\",\n";
    out << "  \"server_tag\": \"" << json_escape(cfg.server_tag) << "\",\n";
    out << "  \"server_exe\": \"" << json_escape(server_exe) << "\",\n";
    out << "  \"server_exe_bytes\": " << file_size(server_exe) << ",\n";
    out << "  \"server_exe_sha256\": \"" << file_sha256_hex(server_exe) << "\",\n";
    out << "  \"cases_total\": " << cases.size() << ",\n";
    out << "  \"cases_passed\": " << passed << ",\n";
    out << "  \"cases_failed\": " << failed << ",\n";
    out << "  \"checks_failed\": " << check_failures << ",\n";
    out << "  \"elapsed_ms\": " << total_ms << ",\n";
    out << "  \"cases\": [\n";
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const auto& c = cases[i];
        out << "    {\"id\": \"" << json_escape(c.id) << "\", \"ok\": " << (c.ok ? "true" : "false")
            << ", \"ms\": " << c.ms << ", \"checks_failed\": " << c.failed_checks() << ", \"checks\": [";
        for (std::size_t j = 0; j < c.checks.size(); ++j) {
            const auto& ch = c.checks[j];
            if (j) out << ", ";
            out << "{\"name\": \"" << json_escape(ch.name) << "\", \"ok\": "
                << (ch.ok ? "true" : "false");
            if (!ch.detail.empty()) out << ", \"detail\": \"" << json_escape(ch.detail) << "\"";
            out << "}";
        }
        out << "]";
        if (!c.notes.empty()) {
            out << ", \"notes\": [";
            for (std::size_t j = 0; j < c.notes.size(); ++j) {
                if (j) out << ", ";
                out << "\"" << json_escape(c.notes[j]) << "\"";
            }
            out << "]";
        }
        out << "}" << (i + 1 == cases.size() ? "" : ",") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

void print_case_line(const CaseResult& result) {
    std::printf("CASE %-22s protocol=%s server=%-24s checks=%d failed=%d ms=%llu %s\n",
                result.id.c_str(), result.protocol.c_str(), result.server_tag.c_str(),
                static_cast<int>(result.checks.size()), result.failed_checks(),
                static_cast<unsigned long long>(result.ms), result.ok ? "PASS" : "FAIL");
    for (const auto& c : result.checks) {
        if (!c.ok) std::printf("    FAIL %s%s%s\n", c.name.c_str(), c.detail.empty() ? "" : " :: ",
                               c.detail.c_str());
    }
    for (const auto& n : result.notes) std::printf("    NOTE %s\n", n.c_str());
    std::fflush(stdout);
}

} // namespace rri
