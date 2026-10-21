// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - tiny self-registering test harness (no external framework).
#pragma once

#include <cstdint>
#include <cstdio>

namespace tt {

struct Suite {
    const char* name = "";
    std::uint64_t cases = 0;
    std::uint64_t checks = 0;
    std::uint64_t failed = 0;
};

using SuiteFn = void (*)();

struct Registry {
    static constexpr int kMax = 32;
    int count = 0;
    const char* names[kMax] = {};
    SuiteFn fns[kMax] = {};
};

Registry& registry();
Suite*& current();

inline void set_current(Suite* s) { current() = s; }
inline void begin_case() { ++current()->cases; }
inline void check_impl(bool ok, const char* what, int line) {
    ++current()->checks;
    if (!ok) {
        ++current()->failed;
        std::printf("  FAIL %s:%d  %s\n", current()->name, line, what);
    }
}

struct Registrar {
    Registrar(const char* name, SuiteFn fn) {
        Registry& r = registry();
        if (r.count < Registry::kMax) {
            r.names[r.count] = name;
            r.fns[r.count] = fn;
            ++r.count;
        }
    }
};

} // namespace tt

#define TT_CHECK(cond) ::tt::check_impl((cond), #cond, __LINE__)
#define TT_CASE() ::tt::begin_case()
#define TT_SUITE(name)                                                  \
    static void tt_suite_##name();                                      \
    static ::tt::Registrar tt_registrar_##name(#name, &tt_suite_##name); \
    static void tt_suite_##name()
