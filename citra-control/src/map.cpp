// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - control-plane mapping layer.
#include "citra_control/map.hpp"

#include "citra_control/uds_frames.hpp"

namespace citra_control {

namespace {

constexpr MacAddress kZeroMac = {0, 0, 0, 0, 0, 0};

bool is_zero_mac(const MacAddress& mac) {
    return mac == kZeroMac;
}

} // namespace

void SessionMap::clear() noexcept {
    entries_.clear();
}

Res<NodeBinding> SessionMap::bind(const MacAddress& mac, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("session_map.bind", e);
        }
        return fail<NodeBinding>(e);
    };
    if (is_zero_mac(mac) || mac == kBroadcastMac) {
        if (diag != nullptr) {
            ++diag->c.mac_map_misses;
        }
        return rej(Err::BadMac);
    }
    for (const NodeBinding& b : entries_) {
        if (b.mac == mac) {
            if (diag != nullptr) {
                diag->note_event("session_map.bind", "rebind: stable binding reused");
            }
            return ok(b);
        }
    }
    // Removing an entry leaves a hole, so the table size is not a free ID.
    // Preserve live bindings and reuse the lowest available positive s8 ID.
    long long candidate = 1;
    for (; candidate <= 127; ++candidate) {
        bool occupied = false;
        for (const NodeBinding& b : entries_) {
            if (b.node_id == candidate) {
                occupied = true;
                break;
            }
        }
        if (!occupied) {
            break;
        }
    }
    const Res<std::int8_t> node_id = check_node_id(candidate, diag);
    if (!node_id.ok()) {
        return rej(node_id.err);
    }
    NodeBinding b;
    b.mac = mac;
    b.ipv4 = {subnet_[0], subnet_[1], subnet_[2], static_cast<std::uint8_t>(candidate)};
    b.node_id = node_id.value;
    entries_.push_back(b);
    if (diag != nullptr) {
        ++diag->c.mac_map_inserts;
        ++diag->c.node_id_assigned;
        diag->note_ok("session_map.bind", "assigned");
    }
    return ok(b);
}

bool SessionMap::remove(const MacAddress& mac, Diag* diag) {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].mac == mac) {
            entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
            if (diag != nullptr) {
                ++diag->c.mac_map_removes;
                diag->note_event("session_map.remove", "removed");
            }
            return true;
        }
    }
    if (diag != nullptr) {
        ++diag->c.mac_map_misses;
        diag->note_reject("session_map.remove", Err::NotFound);
    }
    return false;
}

Res<NodeBinding> SessionMap::lookup_mac(const MacAddress& mac, Diag* diag) const {
    for (const NodeBinding& b : entries_) {
        if (b.mac == mac) {
            return ok(b);
        }
    }
    if (diag != nullptr) {
        ++diag->c.mac_map_misses;
        diag->note_reject("session_map.lookup_mac", Err::NotFound);
    }
    return fail<NodeBinding>(Err::NotFound);
}

Res<MacAddress> SessionMap::lookup_ipv4(const std::array<std::uint8_t, 4>& ipv4, Diag* diag) const {
    for (const NodeBinding& b : entries_) {
        if (b.ipv4 == ipv4) {
            return ok(b.mac);
        }
    }
    if (diag != nullptr) {
        ++diag->c.mac_map_misses;
        diag->note_reject("session_map.lookup_ipv4", Err::NotFound);
    }
    return fail<MacAddress>(Err::NotFound);
}

Res<NodeBinding> SessionMap::lookup_node_id(std::int8_t node_id, Diag* diag) const {
    for (const NodeBinding& b : entries_) {
        if (b.node_id == node_id) {
            return ok(b);
        }
    }
    if (diag != nullptr) {
        ++diag->c.mac_map_misses;
        diag->note_reject("session_map.lookup_node_id", Err::NotFound);
    }
    return fail<NodeBinding>(Err::NotFound);
}

Res<std::int8_t> check_node_id(long long value, Diag* diag) {
    if (value < -128 || value > 127) {
        if (diag != nullptr) {
            ++diag->c.node_id_out_of_range;
            diag->note_reject("check_node_id", Err::Range);
        }
        return fail<std::int8_t>(Err::Range);
    }
    return ok(static_cast<std::int8_t>(value));
}

std::uint32_t mix32(std::uint32_t x) noexcept {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
}

Res<UdsNetworkIds> derive_uds_network_ids(std::uint32_t seed, Diag* diag) {
    UdsNetworkIds ids;
    ids.wlan_comm_id = mix32(seed ^ 0x4E574D00u);
    ids.network_id = mix32(seed ^ 0x55445331u);
    if (diag != nullptr) {
        ++diag->c.netid_derived;
        diag->note_ok("derive_uds_network_ids", "derived from caller seed");
    }
    return ok(ids);
}

Res<NetworkId> derive_ldn_network_id(std::uint32_t seed, std::uint16_t scene_id, const SessionId& session,
                                     Diag* diag) {
    NetworkId id;
    id.intent_id.local_communication_id = static_cast<std::uint64_t>(mix32(seed ^ 0x4C444E00u));
    id.intent_id.scene_id = scene_id;
    id.session_id = session;
    if (diag != nullptr) {
        ++diag->c.netid_derived;
        diag->note_ok("derive_ldn_network_id", "derived from caller seed");
    }
    return ok(id);
}

Res<std::uint32_t> recover_seed_from_uds(const UdsNetworkIds& ids, Diag* diag) {
    (void)ids;
    if (diag != nullptr) {
        ++diag->c.netid_irreversible_refused;
        diag->note_reject("recover_seed_from_uds", Err::Irreversible);
    }
    return fail<std::uint32_t>(Err::Irreversible);
}

Res<std::uint32_t> recover_seed_from_ldn(const NetworkId& id, Diag* diag) {
    (void)id;
    if (diag != nullptr) {
        ++diag->c.netid_irreversible_refused;
        diag->note_reject("recover_seed_from_ldn", Err::Irreversible);
    }
    return fail<std::uint32_t>(Err::Irreversible);
}

Res<Ssid> ssid_from_room_name(const std::string& room_name, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            diag->note_reject("ssid_from_room_name", e);
        }
        return fail<Ssid>(e);
    };
    if (room_name.empty()) {
        return rej(Err::BadSsid);
    }
    if (room_name.size() > kLdnSsidLengthMax) {
        return rej(Err::Range);
    }
    for (char ch : room_name) {
        const unsigned char u = static_cast<unsigned char>(ch);
        if (u < 0x20 || u == 0x7F) {
            return rej(Err::Encoding);
        }
    }
    Ssid ssid;
    ssid.length = static_cast<std::uint8_t>(room_name.size());
    for (std::size_t i = 0; i < room_name.size(); ++i) {
        ssid.raw[i] = static_cast<std::uint8_t>(room_name[i]);
    }
    if (diag != nullptr) {
        ++diag->c.ssid_derived;
        diag->note_ok("ssid_from_room_name", "deterministic");
    }
    return ok(ssid);
}

Res<std::string> room_name_from_ssid(const Ssid& ssid, Diag* diag) {
    (void)ssid;
    if (diag != nullptr) {
        ++diag->c.ssid_irreversible_refused;
        diag->note_reject("room_name_from_ssid", Err::Irreversible);
    }
    return fail<std::string>(Err::Irreversible);
}

Res<Username> username_from_bytes(const UserNameBytes& name, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            ++diag->c.username_rejected;
            diag->note_reject("username_from_bytes", e);
        }
        return fail<Username>(e);
    };
    std::size_t len = 0;
    while (len < name.size() && name[len] != 0) {
        ++len;
    }
    if (len == name.size()) {
        return rej(Err::Encoding); // no NUL terminator inside user_name[33]
    }
    if (len > 10) {
        return rej(Err::Range); // overlong for the 10 x u16 3DS field
    }
    Username out{};
    for (std::size_t i = 0; i < len; ++i) {
        if (name[i] < 0x20 || name[i] > 0x7E) {
            return rej(Err::Encoding);
        }
        out[i] = static_cast<std::uint16_t>(name[i]);
    }
    if (diag != nullptr) {
        ++diag->c.username_ok;
        diag->note_ok("username_from_bytes", "converted");
    }
    return ok(out);
}

Res<UserNameBytes> username_to_bytes(const Username& name, Diag* diag) {
    auto rej = [&](Err e) {
        if (diag != nullptr) {
            ++diag->c.username_rejected;
            diag->note_reject("username_to_bytes", e);
        }
        return fail<UserNameBytes>(e);
    };
    std::size_t len = 0;
    while (len < name.size() && name[len] != 0) {
        ++len;
    }
    for (std::size_t i = len; i < name.size(); ++i) {
        if (name[i] != 0) {
            return rej(Err::Encoding); // a NUL before real characters cannot round-trip
        }
    }
    UserNameBytes out{};
    for (std::size_t i = 0; i < len; ++i) {
        if (name[i] < 0x20 || name[i] > 0x7E) {
            return rej(Err::Encoding);
        }
        out[i] = static_cast<std::uint8_t>(name[i]);
    }
    if (diag != nullptr) {
        ++diag->c.username_ok;
        diag->note_ok("username_to_bytes", "converted");
    }
    return ok(out);
}

std::uint64_t friend_code_to_ldn(std::uint64_t wire_friend_code_seed, Diag* diag) {
    (void)wire_friend_code_seed;
    if (diag != nullptr) {
        ++diag->c.invented_fields;
        diag->note_event("friend_code_to_ldn", "zeroed: no Yuzu field, not recovered");
    }
    return 0;
}

std::uint64_t friend_code_from_ldn(Diag* diag) {
    if (diag != nullptr) {
        ++diag->c.undefined_fields;
        diag->note_event("friend_code_from_ldn", "undefined: no Yuzu field");
    }
    return 0;
}

Res<std::size_t> check_advertise_size(AdvertiseDirection direction, std::size_t size, Diag* diag) {
    if (direction == AdvertiseDirection::UdsToLdn) {
        if (size > kApplicationDataSize) {
            if (diag != nullptr) {
                diag->note_reject("check_advertise_size", Err::Oversize);
            }
            return fail<std::size_t>(Err::Oversize);
        }
        return ok(size);
    }
    if (size > kApplicationDataSize) {
        if (diag != nullptr) {
            ++diag->c.oversize_rejected;
            diag->note_reject("check_advertise_size", Err::Capacity);
        }
        return fail<std::size_t>(Err::Capacity);
    }
    return ok(size);
}

} // namespace citra_control
