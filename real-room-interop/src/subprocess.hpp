// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
// Bounded child-process launcher for the room servers (Windows).
// No windows.h here: the implementation owns the platform types.
#include <cstdint>
#include <string>
#include <vector>

namespace rri {

struct ProcessStatus {
    bool running = false;
    bool exited = false;
    int exit_code = -1;
    bool timed_out = false;
};

class ChildProcess {
public:
    ChildProcess() = default;
    ~ChildProcess();
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    // exe/args are UTF-8; workdir may be empty (inherit). stdout/stderr are
    // redirected to the two files (UTF-8 paths).
    bool start(const std::string& exe, const std::vector<std::string>& args,
               const std::string& workdir, const std::string& out_file,
               const std::string& err_file, std::string& error);
    // Wait until the stdout OR stderr file contains 'marker' (e.g. SELF_SERVER_READY
    // for the in-tree server, "Room is open" for the real yuzu/citra room binaries;
    // yuzu-room logs to stderr) or the process exits, or timeout. Returns true only
    // when the marker appeared.
    bool wait_for_marker(const std::string& marker, std::uint32_t timeout_ms);
    bool wait_for_exit(std::uint32_t timeout_ms);
    // Idle request: send one character + newline on the child's stdin.
    bool request_stop();
    ProcessStatus stop(std::uint32_t grace_ms);
    void terminate(std::uint32_t wait_ms);
    std::uint32_t pid() const { return pid_; }
    int exit_code() const { return exit_code_; }
    bool started() const { return pid_ != 0; }

private:
    void* process_ = nullptr;  // HANDLE
    void* stdin_write_ = nullptr;
    std::uint32_t pid_ = 0;
    std::string out_file_;
    std::string err_file_;
    bool finished_ = false;
    int exit_code_ = -1;
};

// Best-effort 127.0.0.1 port availability probe (explicit failure instead of a
// silent port change).
bool port_available(std::uint16_t port, std::string& reason);

} // namespace rri
