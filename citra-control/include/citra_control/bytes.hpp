// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - offline control-plane mapping library (UDS/802.11 <-> Yuzu LDN).
//
// Byte layer.  Every field is converted explicitly with the field's own
// endianness; a whole block is never memcpy'ed into a struct and reinterpreted.
// Layouts are derived from the Citra (GPLv2-or-later) and yuzu
// (GPL-3.0-or-later) sources listed in NOTICE.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace citra_control {

// Error taxonomy.  Every decode failure returns one of these; nothing throws
// and nothing reads out of bounds.
enum class Err : std::uint16_t {
    Ok = 0,
    Short,           // input ended before the structure did
    Trailing,        // input had bytes left over after the structure
    Oversize,        // a length is larger than the container can hold
    BadMagic,        // a fixed magic/sentinel field is wrong
    BadTag,          // tag id / OUI / OUI type mismatch
    BadEnum,         // an enum field holds an unspecified value
    BadLength,       // an internal self-describing length is inconsistent
    BadSentinel,     // a reserved/illegal value was seen
    Capacity,        // asymmetric capacity gate (0x180 vs 0xC8)
    NotMultipleOf16, // AES-CTR block-alignment gate
    Range,           // numeric value outside the representable range
    Encoding,        // text is not representable without guessing
    Irreversible,    // the API refuses to invert a one-way derivation
    IllegalState,    // state-machine transition is not allowed
    BadMac,          // MAC address is a forbidden sentinel
    BadSsid,         // SSID is empty or too long
    NotImplemented,  // explicitly unmapped frame/field
    BadDigest,       // MD5/SHA-1 self-check failed
    Unsafe,          // would make a real Citra client hit ASSERT (V-016k)
    BadHex,          // fixture text is not valid hex
    NotFound,        // session mapping has no entry for this key
};
constexpr std::size_t kErrCount = 22;

const char* err_name(Err e) noexcept;

// Minimal result type; no exceptions anywhere in this library.
template <typename T>
struct Res {
    Err err{Err::Ok};
    T value{};
    bool ok() const noexcept { return err == Err::Ok; }
};

template <typename T>
Res<T> ok(T v) {
    Res<T> r;
    r.value = std::move(v);
    return r;
}

template <typename T>
Res<T> fail(Err e) {
    Res<T> r;
    r.err = e;
    return r;
}

using MacAddress = std::array<std::uint8_t, 6>;
using Username = std::array<std::uint16_t, 10>;

// ---------------------------------------------------------------------------
// Counters and event log.  The caller owns the Diag; the library keeps no
// global mutable state, so every function is re-entrant.
// ---------------------------------------------------------------------------
struct Counters {
    std::uint64_t decode_ok = 0;
    std::uint64_t decode_reject = 0;
    std::uint64_t err[kErrCount] = {};

    std::uint64_t frames_parsed = 0;
    std::uint64_t frames_serialized = 0;

    // Citra (UDS / 802.11) side
    std::uint64_t uds_beacon_ok = 0;
    std::uint64_t uds_eapol_start_ok = 0;
    std::uint64_t uds_eapol_logoff_ok = 0;
    std::uint64_t uds_connection_status_ok = 0;
    std::uint64_t uds_eapol_nodeinfo_ok = 0;
    std::uint64_t uds_guest_netinfo_ok = 0;
    std::uint64_t uds_guest_nodeinfo_ok = 0;
    std::uint64_t uds_auth_ok = 0;
    std::uint64_t uds_assoc_ok = 0;
    std::uint64_t uds_secure_data_ok = 0;
    std::uint64_t uds_deauth_ok = 0;
    std::uint64_t uds_nodemap_ok = 0;

    // Yuzu (LDN) side
    std::uint64_t ldn_body_ok[6] = {};
    std::uint64_t ldn_size_reject = 0;

    // V-016k gates: frames/fields that would abort a real Citra client
    std::uint64_t unsafe_assoc_blocked = 0;
    std::uint64_t secure_data_management_rejected = 0;
    std::uint64_t md5_verify_fail = 0;
    std::uint64_t sha1_verify_fail = 0;
    std::uint64_t beacon_node_reject = 0;

    // Mapping layer
    std::uint64_t oversize_rejected = 0;
    std::uint64_t invented_fields = 0;
    std::uint64_t undefined_fields = 0;
    std::uint64_t node_id_assigned = 0;
    std::uint64_t node_id_out_of_range = 0;
    std::uint64_t node_id_conflict = 0;
    std::uint64_t mac_map_inserts = 0;
    std::uint64_t mac_map_removes = 0;
    std::uint64_t mac_map_collisions = 0;
    std::uint64_t mac_map_misses = 0;
    std::uint64_t username_ok = 0;
    std::uint64_t username_rejected = 0;
    std::uint64_t netid_derived = 0;
    std::uint64_t netid_irreversible_refused = 0;
    std::uint64_t ssid_derived = 0;
    std::uint64_t ssid_irreversible_refused = 0;
    std::uint64_t channel_rejected = 0;

    // State machine
    std::uint64_t state_transitions = 0;
    std::uint64_t state_illegal = 0;
    std::uint64_t cross_side_leak_blocked = 0;
    // V-016o: AP-established gate and AP lifetime.
    std::uint64_t ap_transitions = 0;
    std::uint64_t scan_resp_no_ap = 0;
    std::uint64_t connect_no_ap = 0;

    // Crypto
    std::uint64_t crypto_md5 = 0;
    std::uint64_t crypto_sha1 = 0;
    std::uint64_t crypto_aes_block = 0;
    std::uint64_t crypto_aes_ctr = 0;
    std::uint64_t crypto_ctr_partial_blocks = 0;
    std::uint64_t crypto_reject = 0;
};

struct EventLog {
    static constexpr std::size_t kMaxLines = 2048;
    std::vector<std::string> lines;
    std::uint64_t dropped = 0;
    void push(std::string s) {
        if (lines.size() >= kMaxLines) {
            ++dropped;
            return;
        }
        lines.push_back(std::move(s));
    }
};

struct Diag {
    Counters c;
    EventLog log;
    bool events_enabled = true;

    void note_ok(const char* where, const char* what) {
        ++c.decode_ok;
        if (events_enabled) {
            std::string s = "OK ";
            s += where;
            s += " ";
            s += what;
            log.push(std::move(s));
        }
    }
    void note_reject(const char* where, Err e, const std::string& detail = std::string()) {
        ++c.decode_reject;
        const std::size_t idx = static_cast<std::size_t>(e);
        if (idx < kErrCount) {
            ++c.err[idx];
        }
        if (events_enabled) {
            std::string s = "REJECT ";
            s += where;
            s += " reason=";
            s += err_name(e);
            if (!detail.empty()) {
                s += " ";
                s += detail;
            }
            log.push(std::move(s));
        }
    }
    void note_event(const char* where, const std::string& detail) {
        if (events_enabled) {
            std::string s = "EVENT ";
            s += where;
            if (!detail.empty()) {
                s += " ";
                s += detail;
            }
            log.push(std::move(s));
        }
    }
    std::string counters_text() const;
};

// ---------------------------------------------------------------------------
// Explicit byte-order load/store helpers.
// ---------------------------------------------------------------------------
inline std::uint16_t load_u16le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                      static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8));
}
inline std::uint16_t load_u16be(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) << 8) |
                                      static_cast<std::uint16_t>(p[1]));
}
inline std::uint32_t load_u32le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
inline std::uint32_t load_u32be(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}
inline std::uint64_t load_u64le(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | static_cast<std::uint64_t>(p[i]);
    }
    return v;
}
inline std::uint64_t load_u64be(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<std::uint64_t>(p[i]);
    }
    return v;
}
inline void store_u16le(std::uint8_t* p, std::uint16_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v & 0xFFu);
    p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
}
inline void store_u16be(std::uint8_t* p, std::uint16_t v) noexcept {
    p[0] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    p[1] = static_cast<std::uint8_t>(v & 0xFFu);
}
inline void store_u32le(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v & 0xFFu);
    p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    p[2] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
    p[3] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
}
inline void store_u32be(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
    p[1] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
    p[2] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
    p[3] = static_cast<std::uint8_t>(v & 0xFFu);
}
inline void store_u64le(std::uint8_t* p, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    }
}
inline void store_u64be(std::uint8_t* p, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>((v >> (8 * (7 - i))) & 0xFFu);
    }
}

// ---------------------------------------------------------------------------
// Bounds-checked sequential reader.  Every accessor returns 0 after the first
// failure and latches the error, so a truncated buffer can never be read past
// its end.
// ---------------------------------------------------------------------------
class Reader {
public:
    Reader(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}
    explicit Reader(const std::vector<std::uint8_t>& v) noexcept : data_(v.data()), size_(v.size()) {}

    std::size_t pos() const noexcept { return pos_; }
    std::size_t size() const noexcept { return size_; }
    std::size_t remaining() const noexcept { return size_ - pos_; }
    bool at_end() const noexcept { return pos_ == size_; }
    Err err() const noexcept { return err_; }
    bool ok() const noexcept { return err_ == Err::Ok; }
    void set_err(Err e) noexcept {
        if (err_ == Err::Ok) {
            err_ = e;
        }
    }
    bool skip(std::size_t n) noexcept {
        if (!need(n)) {
            return false;
        }
        pos_ += n;
        return true;
    }

    std::uint8_t u8() noexcept {
        if (!need(1)) {
            return 0;
        }
        return data_[pos_++];
    }
    std::int8_t s8() noexcept { return static_cast<std::int8_t>(u8()); }
    std::uint16_t u16le() noexcept {
        if (!need(2)) {
            return 0;
        }
        const std::uint16_t v = load_u16le(data_ + pos_);
        pos_ += 2;
        return v;
    }
    std::uint16_t u16be() noexcept {
        if (!need(2)) {
            return 0;
        }
        const std::uint16_t v = load_u16be(data_ + pos_);
        pos_ += 2;
        return v;
    }
    std::int16_t s16le() noexcept { return static_cast<std::int16_t>(u16le()); }
    std::int16_t s16be() noexcept { return static_cast<std::int16_t>(u16be()); }
    std::uint32_t u32le() noexcept {
        if (!need(4)) {
            return 0;
        }
        const std::uint32_t v = load_u32le(data_ + pos_);
        pos_ += 4;
        return v;
    }
    std::uint32_t u32be() noexcept {
        if (!need(4)) {
            return 0;
        }
        const std::uint32_t v = load_u32be(data_ + pos_);
        pos_ += 4;
        return v;
    }
    std::uint64_t u64le() noexcept {
        if (!need(8)) {
            return 0;
        }
        const std::uint64_t v = load_u64le(data_ + pos_);
        pos_ += 8;
        return v;
    }
    std::uint64_t u64be() noexcept {
        if (!need(8)) {
            return 0;
        }
        const std::uint64_t v = load_u64be(data_ + pos_);
        pos_ += 8;
        return v;
    }
    // Borrowed pointer to n bytes without copying.
    const std::uint8_t* raw(std::size_t n) noexcept {
        if (!need(n)) {
            return nullptr;
        }
        const std::uint8_t* p = data_ + pos_;
        pos_ += n;
        return p;
    }
    void copy_to(std::uint8_t* dst, std::size_t n) noexcept {
        if (!need(n)) {
            return;
        }
        for (std::size_t i = 0; i < n; ++i) {
            dst[i] = data_[pos_ + i];
        }
        pos_ += n;
    }
    std::vector<std::uint8_t> vec(std::size_t n) {
        std::vector<std::uint8_t> out;
        if (!need(n)) {
            return out;
        }
        out.assign(data_ + pos_, data_ + pos_ + n);
        pos_ += n;
        return out;
    }
    bool seek(std::size_t p) noexcept {
        if (p > size_) {
            set_err(Err::Short);
            return false;
        }
        pos_ = p;
        return true;
    }

private:
    bool need(std::size_t n) noexcept {
        if (n > size_ - pos_) {
            set_err(Err::Short);
            return false;
        }
        return true;
    }
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t pos_ = 0;
    Err err_ = Err::Ok;
};

// ---------------------------------------------------------------------------
// Append-only writer with explicit endianness.
// ---------------------------------------------------------------------------
class Writer {
public:
    std::vector<std::uint8_t> buf;

    std::size_t size() const noexcept { return buf.size(); }
    void u8(std::uint8_t v) { buf.push_back(v); }
    void s8(std::int8_t v) { buf.push_back(static_cast<std::uint8_t>(v)); }
    void u16le(std::uint16_t v) {
        std::uint8_t b[2];
        store_u16le(b, v);
        buf.insert(buf.end(), b, b + 2);
    }
    void u16be(std::uint16_t v) {
        std::uint8_t b[2];
        store_u16be(b, v);
        buf.insert(buf.end(), b, b + 2);
    }
    void u32le(std::uint32_t v) {
        std::uint8_t b[4];
        store_u32le(b, v);
        buf.insert(buf.end(), b, b + 4);
    }
    void u32be(std::uint32_t v) {
        std::uint8_t b[4];
        store_u32be(b, v);
        buf.insert(buf.end(), b, b + 4);
    }
    void u64le(std::uint64_t v) {
        std::uint8_t b[8];
        store_u64le(b, v);
        buf.insert(buf.end(), b, b + 8);
    }
    void u64be(std::uint64_t v) {
        std::uint8_t b[8];
        store_u64be(b, v);
        buf.insert(buf.end(), b, b + 8);
    }
    void bytes(const std::uint8_t* p, std::size_t n) { buf.insert(buf.end(), p, p + n); }
    template <std::size_t N>
    void bytes(const std::array<std::uint8_t, N>& a) {
        bytes(a.data(), N);
    }
    void zeros(std::size_t n) { buf.insert(buf.end(), n, static_cast<std::uint8_t>(0)); }
    void patch_u8(std::size_t off, std::uint8_t v) {
        if (off < buf.size()) {
            buf[off] = v;
        }
    }
};

// ---------------------------------------------------------------------------
// Hex helpers (fixtures are hand-written hex text, never packet captures).
// ---------------------------------------------------------------------------
std::string to_hex(const std::uint8_t* data, std::size_t size);
inline std::string to_hex(const std::vector<std::uint8_t>& v) { return to_hex(v.data(), v.size()); }
template <std::size_t N>
inline std::string to_hex(const std::array<std::uint8_t, N>& a) {
    return to_hex(a.data(), N);
}
// Accepts optional whitespace and '#' line comments; returns false on odd
// digits or non-hex characters.
bool from_hex(const std::string& text, std::vector<std::uint8_t>& out, std::string* why);

} // namespace citra_control
