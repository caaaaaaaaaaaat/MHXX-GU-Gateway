// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - shared helpers for the test suites.
#pragma once

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "citra_control/bytes.hpp"
#include "harness.hpp"

namespace ttx {

inline std::vector<std::uint8_t> hx(const char* s) {
    std::vector<std::uint8_t> v;
    std::string why;
    if (!citra_control::from_hex(s, v, &why)) {
        std::printf("  FAIL bad test hex (%s): %s\n", why.c_str(), s);
    }
    return v;
}

inline std::string hex(const std::vector<std::uint8_t>& v) { return citra_control::to_hex(v.data(), v.size()); }

template <std::size_t N>
inline std::string hex(const std::array<std::uint8_t, N>& a) {
    return citra_control::to_hex(a.data(), N);
}

// Every strict prefix of buf must be rejected by parse.
template <typename Parse>
inline std::size_t all_prefixes_reject(const std::vector<std::uint8_t>& buf, Parse parse) {
    std::size_t bad = 0;
    for (std::size_t n = 0; n < buf.size(); ++n) {
        if (parse(buf.data(), n).ok()) {
            ++bad;
        }
    }
    TT_CHECK(bad == 0);
    return bad;
}

// buf plus one trailing byte must be rejected.
template <typename Parse>
inline bool trailing_byte_rejected(const std::vector<std::uint8_t>& buf, Parse parse) {
    std::vector<std::uint8_t> longer = buf;
    longer.push_back(0x00);
    const bool rejected = !parse(longer.data(), longer.size()).ok();
    TT_CHECK(rejected);
    return rejected;
}

// Compares ignoring whitespace in the expected text (the expected values are
// written grouped for readability).
inline void expect_hex(const std::vector<std::uint8_t>& got, const char* want) {
    std::string w;
    for (const char* p = want; *p != 0; ++p) {
        if (*p != ' ' && *p != '\t' && *p != '\n') {
            w.push_back(*p);
        }
    }
    const std::string g = hex(got);
    if (g != w) {
        std::printf("  FAIL hex mismatch\n    got  %s\n    want %s\n", g.c_str(), w.c_str());
    }
    TT_CHECK(g == w);
}

// Loads a 'key = value' fixture file ('#' starts a comment).  Returns false if
// the file cannot be opened; 'why' receives a human readable reason.
inline bool load_fixture(const std::string& path, std::map<std::string, std::string>& out, std::string* why) {
    std::ifstream in(path.c_str());
    if (!in) {
        if (why != nullptr) {
            *why = "cannot open " + path;
        }
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        const std::size_t hash = line.find('#');
        if (hash != std::string::npos) {
            line = line.substr(0, hash);
        }
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        auto trim = [](std::string s) {
            std::size_t a = 0;
            std::size_t b = s.size();
            while (a < b && std::isspace(static_cast<unsigned char>(s[a])) != 0) {
                ++a;
            }
            while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])) != 0) {
                --b;
            }
            return s.substr(a, b - a);
        };
        k = trim(k);
        v = trim(v);
        if (!k.empty() && !v.empty()) {
            out[k] = v;
        }
    }
    return true;
}

// Fixture bytes as a hex string with whitespace removed, so it can be passed to
// ttx::hx().
inline const char* fx(const std::map<std::string, std::string>& m, const char* key) {
    const auto it = m.find(key);
    if (it == m.end()) {
        std::printf("  FAIL missing fixture key '%s'\n", key);
        TT_CHECK(false);
        return "";
    }
    return it->second.c_str();
}

} // namespace ttx
