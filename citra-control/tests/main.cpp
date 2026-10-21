// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - test runner.  Prints one GROUP line per suite and a final
// machine-readable RESULT line; exit code is non-zero if any check failed.
#include "harness.hpp"

namespace tt {
Registry& registry() {
    static Registry r;
    return r;
}
Suite*& current() {
    static Suite* s = nullptr;
    return s;
}
} // namespace tt

int main() {
    tt::Registry& r = tt::registry();
    std::uint64_t total_cases = 0;
    std::uint64_t total_checks = 0;
    std::uint64_t total_failed = 0;
    for (int i = 0; i < r.count; ++i) {
        tt::Suite s{r.names[i], 0, 0, 0};
        tt::set_current(&s);
        r.fns[i]();
        std::printf("GROUP %s cases=%llu checks=%llu failed=%llu\n", s.name,
                    static_cast<unsigned long long>(s.cases), static_cast<unsigned long long>(s.checks),
                    static_cast<unsigned long long>(s.failed));
        total_cases += s.cases;
        total_checks += s.checks;
        total_failed += s.failed;
    }
    std::printf("RESULT cases=%llu checks=%llu failed=%llu\n", static_cast<unsigned long long>(total_cases),
                static_cast<unsigned long long>(total_checks), static_cast<unsigned long long>(total_failed));
    return total_failed == 0 ? 0 : 1;
}
