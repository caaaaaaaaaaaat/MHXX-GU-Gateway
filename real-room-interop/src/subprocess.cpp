// SPDX-License-Identifier: GPL-2.0-or-later
#include "subprocess.hpp"

#include "util.hpp"
#include "win_net.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>

#include <windows.h>

namespace rri {

namespace {
std::wstring quote_arg(const std::wstring& a) {
    if (a.find_first_of(L" \t\"") == std::wstring::npos) return a;
    std::wstring out = L"\"";
    unsigned backslashes = 0;
    for (wchar_t c : a) {
        if (c == L'\\') { ++backslashes; continue; }
        if (c == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
            backslashes = 0;
            continue;
        }
        out.append(backslashes, L'\\');
        backslashes = 0;
        out.push_back(c);
    }
    out.append(backslashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

bool file_contains(const std::string& path, const std::string& marker) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str().find(marker) != std::string::npos;
}
} // namespace

ChildProcess::~ChildProcess() {
    if (stdin_write_) {
        CloseHandle(static_cast<HANDLE>(stdin_write_));
        stdin_write_ = nullptr;
    }
    if (process_) {
        HANDLE h = static_cast<HANDLE>(process_);
        if (WaitForSingleObject(h, 0) == WAIT_TIMEOUT) {
            TerminateProcess(h, 0xDEAD);
            WaitForSingleObject(h, 3000);
        }
        CloseHandle(h);
        process_ = nullptr;
    }
}

bool ChildProcess::start(const std::string& exe, const std::vector<std::string>& args,
                         const std::string& workdir, const std::string& out_file,
                         const std::string& err_file, std::string& error) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE out = CreateFileW(utf8_to_wide(out_file).c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (out == INVALID_HANDLE_VALUE) { error = "cannot open stdout file: " + out_file; return false; }
    HANDLE err = CreateFileW(utf8_to_wide(err_file).c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (err == INVALID_HANDLE_VALUE) {
        CloseHandle(out);
        error = "cannot open stderr file: " + err_file;
        return false;
    }
    HANDLE in_read = nullptr, in_write = nullptr;
    if (!CreatePipe(&in_read, &in_write, &sa, 0)) {
        CloseHandle(out); CloseHandle(err);
        error = "CreatePipe failed";
        return false;
    }
    SetHandleInformation(in_write, HANDLE_FLAG_INHERIT, 0);

    std::wstring cmdline = quote_arg(utf8_to_wide(exe));
    for (const auto& a : args) {
        cmdline.push_back(L' ');
        cmdline += quote_arg(utf8_to_wide(a));
    }
    std::vector<wchar_t> mutable_cmd(cmdline.begin(), cmdline.end());
    mutable_cmd.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_read;
    si.hStdOutput = out;
    si.hStdError = err;
    PROCESS_INFORMATION pi{};
    std::wstring wdir = utf8_to_wide(workdir);
    const BOOL ok = CreateProcessW(utf8_to_wide(exe).c_str(), mutable_cmd.data(), nullptr, nullptr,
                                   TRUE, CREATE_NO_WINDOW, nullptr,
                                   workdir.empty() ? nullptr : wdir.c_str(), &si, &pi);
    CloseHandle(in_read);
    CloseHandle(out);
    CloseHandle(err);
    if (!ok) {
        const DWORD e = GetLastError();
        CloseHandle(in_write);
        error = "CreateProcessW failed for " + exe + " (GetLastError=" + format_uint64(e) + ")";
        return false;
    }
    CloseHandle(pi.hThread);
    process_ = pi.hProcess;
    stdin_write_ = in_write;
    pid_ = pi.dwProcessId;
    out_file_ = out_file;
    err_file_ = err_file;
    return true;
}

bool ChildProcess::wait_for_marker(const std::string& marker, std::uint32_t timeout_ms) {
    const std::uint64_t deadline = now_ms() + timeout_ms;
    for (;;) {
        // Real yuzu-room logs "Room is open..." through the console backend, which
        // lands on stderr; the in-tree self server writes stdout. Search both.
        if (file_contains(out_file_, marker)) return true;
        if (!err_file_.empty() && file_contains(err_file_, marker)) return true;
        if (stdin_write_) { /* still alive check below */ }
        HANDLE h = static_cast<HANDLE>(process_);
        if (h && WaitForSingleObject(h, 0) == WAIT_OBJECT_0) { finished_ = true; return false; }
        if (now_ms() >= deadline) return false;
        Sleep(25);
    }
}

bool ChildProcess::wait_for_exit(std::uint32_t timeout_ms) {
    HANDLE h = static_cast<HANDLE>(process_);
    if (!h) return true;
    if (WaitForSingleObject(h, timeout_ms) == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(h, &code);
        exit_code_ = static_cast<int>(code);
        finished_ = true;
        return true;
    }
    return false;
}

bool ChildProcess::request_stop() {
    if (!stdin_write_) return false;
    const char msg[] = "q\n";
    DWORD written = 0;
    return WriteFile(static_cast<HANDLE>(stdin_write_), msg, 2, &written, nullptr) != 0;
}

void ChildProcess::terminate(std::uint32_t wait_ms) {
    HANDLE h = static_cast<HANDLE>(process_);
    if (!h) return;
    if (WaitForSingleObject(h, 0) == WAIT_TIMEOUT) {
        TerminateProcess(h, 0);
    }
    WaitForSingleObject(h, wait_ms);
    DWORD code = 0;
    if (GetExitCodeProcess(h, &code)) exit_code_ = static_cast<int>(code);
    finished_ = true;
}

ProcessStatus ChildProcess::stop(std::uint32_t grace_ms) {
    ProcessStatus st;
    HANDLE h = static_cast<HANDLE>(process_);
    if (!h) { st.exited = true; st.exit_code = exit_code_; return st; }
    request_stop();
    if (WaitForSingleObject(h, grace_ms) == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(h, &code);
        exit_code_ = static_cast<int>(code);
    } else {
        st.timed_out = true;
        TerminateProcess(h, 0);
        WaitForSingleObject(h, 3000);
        st.exit_code = -1;
        finished_ = true;
        st.exited = true;
        return st;
    }
    finished_ = true;
    st.exited = true;
    st.exit_code = exit_code_;
    return st;
}

namespace {
bool udp_bind_probe(std::uint16_t port, unsigned long address, std::string& reason) {
    WSADATA wsa{};
    static bool wsa_ready = false;
    if (!wsa_ready) {
        WSAStartup(MAKEWORD(2, 2), &wsa);
        wsa_ready = true;
    }
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { reason = "socket() failed"; return false; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = address;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&opt), sizeof(opt));
    const int rc = bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    const int err = WSAGetLastError();
    closesocket(s);
    if (rc != 0) {
        reason = "UDP bind failed for port " + format_uint64(port) + " (error " +
                 format_uint64(err) + ")";
        return false;
    }
    return true;
}
} // namespace

// The room servers are UDP (ENet) listeners, so a TCP probe would never see them. Two
// independent checks: the IP Helper endpoint table (catches a 0.0.0.0 listener) and an
// exclusive bind probe on both the wildcard and the loopback address.
bool port_available(std::uint16_t port, std::string& reason) {
    const auto bound = udp_endpoints_by_port(port);
    if (!bound.empty()) {
        reason = "port " + format_uint64(port) + " is present in the UDP endpoint table: " +
                 describe_endpoints(bound);
        return false;
    }
    std::string why;
    if (!udp_bind_probe(port, htonl(INADDR_ANY), why)) {
        reason = "0.0.0.0:" + format_uint64(port) + " is already in use: " + why;
        return false;
    }
    if (!udp_bind_probe(port, htonl(INADDR_LOOPBACK), why)) {
        reason = "127.0.0.1:" + format_uint64(port) + " is already in use: " + why;
        return false;
    }
    return true;
}

} // namespace rri
