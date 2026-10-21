// SPDX-License-Identifier: GPL-2.0-or-later
// real-room-interop: shared small utilities (no I/O policy of its own).
#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#endif

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace rri {

using Bytes = std::vector<std::uint8_t>;

inline std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

inline void sleep_ms(std::uint64_t ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

inline std::string hex_spaced(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 3);
    for (std::size_t i = 0; i < b.size(); ++i) {
        if (i != 0) s.push_back(' ');
        s.push_back(d[(b[i] >> 4) & 0xF]);
        s.push_back(d[b[i] & 0xF]);
    }
    return s;
}

inline Bytes from_hex(const std::string& text) {
    Bytes out;
    int hi = -1;
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;
        if (hi < 0) { hi = v; }
        else { out.push_back(static_cast<std::uint8_t>((hi << 4) | v)); hi = -1; }
    }
    return out;
}

inline std::string trim(const std::string& s) {
    std::size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

// Whitespace split with double-quote grouping (so --preferred-game "two words" works).
inline std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quotes = false;
    bool have = false;
    for (char c : s) {
        if (c == '"') { in_quotes = !in_quotes; have = true; continue; }
        if (!in_quotes && (c == ' ' || c == '\t')) {
            if (have) { out.push_back(cur); cur.clear(); have = false; }
            continue;
        }
        cur.push_back(c);
        have = true;
    }
    if (have) out.push_back(cur);
    return out;
}

inline std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                o += buf;
            } else {
                o.push_back(static_cast<char>(c));
            }
        }
    }
    return o;
}

inline std::string to_lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

#ifdef _WIN32
inline std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
    return out;
}

inline std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

// UTF-8 command line, recovered from GetCommandLineW so non-ASCII paths survive
// a narrow main(argc, argv).
inline std::vector<std::string> utf8_argv() {
    int argc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> out;
    if (!wargv) return out;
    out.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) out.push_back(wide_to_utf8(wargv[i]));
    LocalFree(wargv);
    return out;
}
#endif

inline std::string format_uint64(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
    return buf;
}

} // namespace rri
