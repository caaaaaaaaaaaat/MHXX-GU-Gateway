// SPDX-FileCopyrightText: Copyright 2026 LAN codec contributors
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "lan_codecs.h"
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
namespace lan_codec::hex_io {
inline int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
inline Bytes parse(std::string_view text, std::size_t cap = hard_resource_cap) {
    if (cap > hard_resource_cap || text.size() > 4 * hard_resource_cap) throw std::runtime_error("hex input limit");
    Bytes bytes; int high = -1;
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        const int n = nibble(c); if (n < 0) throw std::runtime_error("invalid hex character");
        if (high < 0) high = n;
        else {
            if (bytes.size() >= cap) throw std::runtime_error("hex decoded limit");
            bytes.push_back(static_cast<Byte>((high << 4) | n)); high = -1;
        }
    }
    if (high >= 0) throw std::runtime_error("odd hex digit count");
    return bytes;
}
inline Bytes load(std::string_view argument, std::size_t cap = hard_resource_cap) {
    if (argument.empty() || argument.front() != '@') return parse(argument, cap);
    std::ifstream f(std::string(argument.substr(1)), std::ios::binary);
    if (!f) throw std::runtime_error("cannot open hex file");
    std::string text; char c;
    while (f.get(c)) {
        if (text.size() >= 4 * hard_resource_cap) throw std::runtime_error("hex file limit");
        text.push_back(c);
    }
    if (!f.eof()) throw std::runtime_error("hex file read failure");
    return parse(text, cap);
}
inline std::string format(Input bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string text; text.reserve(2 * bytes.size());
    for (Byte b : bytes) { text.push_back(digits[b >> 4]); text.push_back(digits[b & 15]); }
    return text;
}
} // namespace lan_codec::hex_io
