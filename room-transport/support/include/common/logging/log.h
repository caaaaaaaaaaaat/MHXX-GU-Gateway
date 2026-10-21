// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
// M2 harness ONLY: replace the emulator-wide logging service, not network logic.
// Real fmt 10.2.1 formats the unchanged Room log statements and direct fmt calls.
#include <cstdio>
#include <mutex>
#include <fmt/format.h>
namespace room_test_support {
template <typename... Args>
void log(const char* level, fmt::format_string<Args...> format, Args&&... args) {
    const auto text = fmt::format(format, std::forward<Args>(args)...);
    static std::mutex mutex;
    const std::lock_guard lock(mutex);
    std::fprintf(stderr, "[%s] %s\n", level, text.c_str());
}
}
#define LOG_INFO(category, ...) ::room_test_support::log("INFO", __VA_ARGS__)
#define LOG_ERROR(category, ...) ::room_test_support::log("ERROR", __VA_ARGS__)
