// SPDX-License-Identifier: GPL-3.0-or-later
#include "citra_control/heartbeat.hpp"

#include <map>
#include <set>
#include <stdexcept>
#include <string>

namespace citra_control {
namespace {

double distinct_ratio(const std::vector<std::uint16_t>& values) {
    if (values.empty()) {
        return 0.0;
    }
    const std::set<std::uint16_t> unique(values.begin(), values.end());
    return static_cast<double>(unique.size()) / static_cast<double>(values.size());
}

} // namespace

HeartbeatPairResult learn_heartbeat_pair(const std::vector<HeartbeatObservation>& packets,
                                         const HeartbeatLearnerOptions& options) {
    if (packets.size() < 1 || packets.size() > 200000) {
        throw std::invalid_argument("heartbeat_observations");
    }
    if (!(options.min_share > 0.0 && options.min_share < 1.0) || options.min_frames < 1
        || !(options.min_time_entropy > 0.0 && options.min_time_entropy < 1.0)) {
        throw std::invalid_argument("heartbeat_options");
    }
    HeartbeatPairResult result;
    result.total_packets = packets.size();

    struct Bucket {
        std::size_t frames = 0;
        std::set<std::array<std::uint8_t, 4>> senders;
        std::vector<std::uint16_t> rel_time;
        std::vector<std::uint16_t> time_echo;
    };
    std::map<std::uint8_t, Bucket> by_kind;
    for (const HeartbeatObservation& p : packets) {
        auto& bucket = by_kind[p.kind];
        ++bucket.frames;
        bucket.senders.insert(p.sender);
        bucket.rel_time.push_back(p.rel_time);
        bucket.time_echo.push_back(p.time_echo);
    }
    result.distinct_kinds = by_kind.size();

    for (const auto& [kind, bucket] : by_kind) {
        const double share = static_cast<double>(bucket.frames) / static_cast<double>(packets.size());
        if (share < options.min_share || bucket.frames < options.min_frames) {
            continue;
        }
        // V-242 signature: a heartbeat kind has exactly ONE sender.  A kind seen
        // from several senders is ordinary data, never a heartbeat.
        if (bucket.senders.size() != 1) {
            continue;
        }
        HeartbeatCandidate candidate;
        candidate.kind = kind;
        candidate.sender = *bucket.senders.begin();
        candidate.frames = bucket.frames;
        candidate.share = share;
        candidate.rel_time_entropy = distinct_ratio(bucket.rel_time);
        candidate.time_echo_entropy = distinct_ratio(bucket.time_echo);
        if (std::min(candidate.rel_time_entropy, candidate.time_echo_entropy) < options.min_time_entropy) {
            continue;
        }
        result.candidates.push_back(candidate);
    }

    if (result.candidates.size() == 2
        && result.candidates[0].sender != result.candidates[1].sender) {
        result.learned = true;
    }
    return result;
}

} // namespace citra_control
