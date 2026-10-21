// SPDX-License-Identifier: GPL-2.0-or-later
// real-room-interop: 'observe' mode entry point.
#pragma once

#include <string>
#include <vector>

namespace rri {

// Independent v1 room member ("member-table oracle" for G-c).  Parses its own
// command line (--room/--room-port/--password/--nickname/--seconds/--out) and
// returns a process exit code: 0 observed, 2 usage, 3 non-loopback refused,
// 4 could not connect/complete the join, 5 the server rejected the join.
int run_observe(const std::vector<std::string>& args);

} // namespace rri
