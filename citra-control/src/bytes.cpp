// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - byte layer utilities.
#include "citra_control/bytes.hpp"

#include <cstdio>

namespace citra_control {

const char* err_name(Err e) noexcept {
    switch (e) {
    case Err::Ok: return "Ok";
    case Err::Short: return "Short";
    case Err::Trailing: return "Trailing";
    case Err::Oversize: return "Oversize";
    case Err::BadMagic: return "BadMagic";
    case Err::BadTag: return "BadTag";
    case Err::BadEnum: return "BadEnum";
    case Err::BadLength: return "BadLength";
    case Err::BadSentinel: return "BadSentinel";
    case Err::Capacity: return "Capacity";
    case Err::NotMultipleOf16: return "NotMultipleOf16";
    case Err::Range: return "Range";
    case Err::Encoding: return "Encoding";
    case Err::Irreversible: return "Irreversible";
    case Err::IllegalState: return "IllegalState";
    case Err::BadMac: return "BadMac";
    case Err::BadSsid: return "BadSsid";
    case Err::NotImplemented: return "NotImplemented";
    case Err::BadDigest: return "BadDigest";
    case Err::Unsafe: return "Unsafe";
    case Err::BadHex: return "BadHex";
    case Err::NotFound: return "NotFound";
    }
    return "Unknown";
}

namespace {

void emit(std::string& out, const char* name, std::uint64_t v) {
    if (v == 0) {
        return;
    }
    out += name;
    out += '=';
    out += std::to_string(v);
    out += '\n';
}

} // namespace

std::string Diag::counters_text() const {
    std::string out;
    for (std::size_t i = 0; i < kErrCount; ++i) {
        if (c.err[i] == 0) {
            continue;
        }
        out += "err.";
        out += err_name(static_cast<Err>(i));
        out += '=';
        out += std::to_string(c.err[i]);
        out += '\n';
    }
    emit(out, "decode_ok", c.decode_ok);
    emit(out, "decode_reject", c.decode_reject);
    emit(out, "frames_parsed", c.frames_parsed);
    emit(out, "frames_serialized", c.frames_serialized);
    emit(out, "uds_beacon_ok", c.uds_beacon_ok);
    emit(out, "uds_eapol_start_ok", c.uds_eapol_start_ok);
    emit(out, "uds_eapol_logoff_ok", c.uds_eapol_logoff_ok);
    emit(out, "uds_connection_status_ok", c.uds_connection_status_ok);
    emit(out, "uds_eapol_nodeinfo_ok", c.uds_eapol_nodeinfo_ok);
    emit(out, "uds_guest_netinfo_ok", c.uds_guest_netinfo_ok);
    emit(out, "uds_guest_nodeinfo_ok", c.uds_guest_nodeinfo_ok);
    emit(out, "uds_auth_ok", c.uds_auth_ok);
    emit(out, "uds_assoc_ok", c.uds_assoc_ok);
    emit(out, "uds_secure_data_ok", c.uds_secure_data_ok);
    emit(out, "uds_deauth_ok", c.uds_deauth_ok);
    emit(out, "uds_nodemap_ok", c.uds_nodemap_ok);
    for (std::size_t i = 0; i < 6; ++i) {
        if (c.ldn_body_ok[i] == 0) {
            continue;
        }
        out += "ldn_body_ok[";
        out += std::to_string(i);
        out += "]=";
        out += std::to_string(c.ldn_body_ok[i]);
        out += '\n';
    }
    emit(out, "ldn_size_reject", c.ldn_size_reject);
    emit(out, "unsafe_assoc_blocked", c.unsafe_assoc_blocked);
    emit(out, "secure_data_management_rejected", c.secure_data_management_rejected);
    emit(out, "md5_verify_fail", c.md5_verify_fail);
    emit(out, "sha1_verify_fail", c.sha1_verify_fail);
    emit(out, "beacon_node_reject", c.beacon_node_reject);
    emit(out, "oversize_rejected", c.oversize_rejected);
    emit(out, "invented_fields", c.invented_fields);
    emit(out, "undefined_fields", c.undefined_fields);
    emit(out, "node_id_assigned", c.node_id_assigned);
    emit(out, "node_id_out_of_range", c.node_id_out_of_range);
    emit(out, "node_id_conflict", c.node_id_conflict);
    emit(out, "mac_map_inserts", c.mac_map_inserts);
    emit(out, "mac_map_removes", c.mac_map_removes);
    emit(out, "mac_map_collisions", c.mac_map_collisions);
    emit(out, "mac_map_misses", c.mac_map_misses);
    emit(out, "username_ok", c.username_ok);
    emit(out, "username_rejected", c.username_rejected);
    emit(out, "netid_derived", c.netid_derived);
    emit(out, "netid_irreversible_refused", c.netid_irreversible_refused);
    emit(out, "ssid_derived", c.ssid_derived);
    emit(out, "ssid_irreversible_refused", c.ssid_irreversible_refused);
    emit(out, "channel_rejected", c.channel_rejected);
    emit(out, "state_transitions", c.state_transitions);
    emit(out, "state_illegal", c.state_illegal);
    emit(out, "cross_side_leak_blocked", c.cross_side_leak_blocked);
    emit(out, "ap_transitions", c.ap_transitions);
    emit(out, "scan_resp_no_ap", c.scan_resp_no_ap);
    emit(out, "connect_no_ap", c.connect_no_ap);
    emit(out, "crypto_md5", c.crypto_md5);
    emit(out, "crypto_sha1", c.crypto_sha1);
    emit(out, "crypto_aes_block", c.crypto_aes_block);
    emit(out, "crypto_aes_ctr", c.crypto_aes_ctr);
    emit(out, "crypto_ctr_partial_blocks", c.crypto_ctr_partial_blocks);
    emit(out, "crypto_reject", c.crypto_reject);
    emit(out, "event_lines", static_cast<std::uint64_t>(log.lines.size()));
    emit(out, "event_dropped", log.dropped);
    return out;
}

std::string to_hex(const std::uint8_t* data, std::size_t size) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(digits[(data[i] >> 4) & 0x0F]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

bool from_hex(const std::string& text, std::vector<std::uint8_t>& out, std::string* why) {
    out.clear();
    int hi = -1;
    std::size_t line = 1;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char ch = text[i];
        if (ch == '\n') {
            if (hi >= 0) {
                if (why != nullptr) {
                    *why = "odd number of hex digits on line " + std::to_string(line);
                }
                return false;
            }
            ++line;
            continue;
        }
        if (ch == '#') {
            while (i < text.size() && text[i] != '\n') {
                ++i;
            }
            --i;
            continue;
        }
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == ',' || ch == '_') {
            continue;
        }
        int v = -1;
        if (ch >= '0' && ch <= '9') {
            v = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            v = ch - 'a' + 10;
        } else if (ch >= 'A' && ch <= 'F') {
            v = ch - 'A' + 10;
        } else {
            if (why != nullptr) {
                *why = std::string("invalid character '") + ch + "' at line " + std::to_string(line);
            }
            return false;
        }
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<std::uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    if (hi >= 0) {
        if (why != nullptr) {
            *why = "odd number of hex digits at end of input";
        }
        return false;
    }
    return true;
}

} // namespace citra_control
