// V-242/V-245: offline heartbeat-pair learner, C++ port of the measured
// signature (docs/MH-XXGU-MINIMAL-CONVERSION-TABLE.md, V-242).  Kinds are
// PER-SESSION values on both wires -- static kind tables are invalid by
// construction.  Pure metadata aggregation; never a compatibility verdict.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace citra_control {

struct HeartbeatObservation {
    std::uint8_t kind = 0;
    std::array<std::uint8_t, 4> sender{};
    std::uint16_t seq = 0;
    std::uint16_t rel_time = 0;
    std::uint16_t time_echo = 0;
};

struct HeartbeatLearnerOptions {
    double min_share = 0.10;         // frames of the kind / all observations
    std::size_t min_frames = 20;     // floor per candidate kind
    double min_time_entropy = 0.30;  // min distinct-ratio of rel_time AND time_echo
};

struct HeartbeatCandidate {
    std::uint8_t kind = 0;
    std::array<std::uint8_t, 4> sender{};
    std::size_t frames = 0;
    double share = 0.0;
    double rel_time_entropy = 0.0;
    double time_echo_entropy = 0.0;
};

struct HeartbeatPairResult {
    bool learned = false;
    std::size_t total_packets = 0;
    std::size_t distinct_kinds = 0;
    std::vector<HeartbeatCandidate> candidates;
};

// Learns the mirrored heartbeat pair: exactly two candidate kinds (single
// sender each, above the share/frame floors, time fields above the entropy
// floor) bound to DIFFERENT senders.  Throws std::invalid_argument on malformed
// input; never returns a partial pair.
HeartbeatPairResult learn_heartbeat_pair(const std::vector<HeartbeatObservation>& packets,
                                         const HeartbeatLearnerOptions& options);

} // namespace citra_control
