// SPDX-License-Identifier: GPL-2.0-or-later
// G2 trace recorder (channels A/B/C). See include/citra_gateway/trace.hpp.

#include "citra_gateway/trace.hpp"

#include <zstd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#endif

#include "citra_control/ldn_ctrl.hpp"
#include "citra_control/uds_frames.hpp"

namespace citra_gateway {
namespace {

// ---------------------------------------------------------------------------
// JSON escaping / rendering helpers.
// ---------------------------------------------------------------------------

const char* kHexDigits = "0123456789abcdef";

void append_hex(std::string& out, const std::uint8_t* data, std::size_t size) {
    out.reserve(out.size() + size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kHexDigits[(data[i] >> 4) & 0x0F]);
        out.push_back(kHexDigits[data[i] & 0x0F]);
    }
}

// Escapes one UTF-8 string into a JSON string literal, including the quotes.
std::string quote(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 2);
    out.push_back('"');
    for (unsigned char c : text) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20) {
                out += "\\u00";
                out.push_back(kHexDigits[(c >> 4) & 0x0F]);
                out.push_back(kHexDigits[c & 0x0F]);
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    out.push_back('"');
    return out;
}

// Renders fields in insertion order with a leading comma for every entry but
// the first, which keeps the field order stable and explicit.
class ObjectWriter {
public:
    void string_field(const char* name, const std::string& value) {
        key(name);
        out_ += quote(value);
    }
    void raw_field(const char* name, const std::string& json) {
        key(name);
        out_ += json;
    }
    void u64_field(const char* name, std::uint64_t value) {
        key(name);
        out_ += std::to_string(value);
    }
    std::string finish() {
        out_.push_back('}');
        return std::move(out_);
    }

private:
    void key(const char* name) {
        if (!first_) {
            out_.push_back(',');
        }
        first_ = false;
        out_.push_back('"');
        out_ += name;
        out_ += "\":";
    }
    std::string out_ = "{";
    bool first_ = true;
};

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). Local copy so the gateway does not depend on another
// project's translation unit.
// ---------------------------------------------------------------------------

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

inline std::uint32_t rotr32(std::uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

class Sha256 {
public:
    Sha256() { reset(); }

    void update(const std::uint8_t* data, std::size_t size) {
        total_ += size;
        while (size > 0) {
            const std::size_t take = std::min<std::size_t>(64 - idx_, size);
            std::memcpy(buf_.data() + idx_, data, take);
            idx_ += take;
            data += take;
            size -= take;
            if (idx_ == 64) {
                block(buf_.data());
                idx_ = 0;
            }
        }
    }

    std::array<std::uint8_t, 32> finish() {
        const std::uint64_t bits = total_ * 8;
        std::array<std::uint8_t, 72> pad{};
        const std::size_t pad_len = (idx_ < 56) ? (56 - idx_) : (120 - idx_);
        pad[0] = 0x80;
        update(pad.data(), pad_len);
        std::array<std::uint8_t, 8> length{};
        for (int i = 0; i < 8; ++i) {
            length[static_cast<std::size_t>(i)] =
                static_cast<std::uint8_t>((bits >> (8 * (7 - i))) & 0xFFu);
        }
        update(length.data(), length.size());
        std::array<std::uint8_t, 32> out{};
        for (std::size_t i = 0; i < 8; ++i) {
            out[i * 4] = static_cast<std::uint8_t>((h_[i] >> 24) & 0xFFu);
            out[i * 4 + 1] = static_cast<std::uint8_t>((h_[i] >> 16) & 0xFFu);
            out[i * 4 + 2] = static_cast<std::uint8_t>((h_[i] >> 8) & 0xFFu);
            out[i * 4 + 3] = static_cast<std::uint8_t>(h_[i] & 0xFFu);
        }
        return out;
    }

private:
    void reset() {
        h_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        total_ = 0;
        idx_ = 0;
        buf_.fill(0);
    }

    void block(const std::uint8_t* p) {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(p[i * 4]) << 24) |
                   (static_cast<std::uint32_t>(p[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(p[i * 4 + 2]) << 8) |
                   static_cast<std::uint32_t>(p[i * 4 + 3]);
        }
        for (std::size_t i = 16; i < 64; ++i) {
            const std::uint32_t s0 =
                rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 =
                rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        std::uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t t1 = hh + s1 + ch + kSha256K[i] + w[i];
            const std::uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = s0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
        h_[5] += f;
        h_[6] += g;
        h_[7] += hh;
    }

    std::array<std::uint32_t, 8> h_{};
    std::array<std::uint8_t, 64> buf_{};
    std::uint64_t total_ = 0;
    std::size_t idx_ = 0;
};

// The literal recorded for every structure field of a frame that could not be
// decoded. Never guessed.
const char* kUndecoded = "undecoded";

TraceStructure undecoded_structure(const std::string& name, const std::string& reason,
                                   std::initializer_list<const char*> field_names) {
    TraceStructure structure;
    structure.name = name;
    structure.decoded = false;
    structure.reason = reason;
    structure.fields.reserve(field_names.size());
    for (const char* field_name : field_names) {
        structure.fields.push_back({field_name, quote(kUndecoded)});
    }
    return structure;
}

TraceStructure decoded_structure(const std::string& name) {
    TraceStructure structure;
    structure.name = name;
    structure.decoded = true;
    return structure;
}

} // namespace

// ---------------------------------------------------------------------------
// Field helpers.
// ---------------------------------------------------------------------------

TraceField trace_field_string(const std::string& name, const std::string& value) {
    return {name, quote(value)};
}

TraceField trace_field_u64(const std::string& name, std::uint64_t value) {
    return {name, std::to_string(value)};
}

TraceField trace_field_bool(const std::string& name, bool value) {
    return {name, value ? "true" : "false"};
}

TraceField trace_field_undecoded(const std::string& name) {
    return {name, quote(kUndecoded)};
}

// ---------------------------------------------------------------------------
// SHA-256.
// ---------------------------------------------------------------------------

std::string trace_sha256_hex(const std::uint8_t* data, std::size_t size) {
    Sha256 state;
    if (data != nullptr && size > 0) {
        state.update(data, size);
    }
    const std::array<std::uint8_t, 32> digest = state.finish();
    std::string hex;
    append_hex(hex, digest.data(), digest.size());
    return hex;
}

std::string trace_sha256_hex(const std::vector<std::uint8_t>& data) {
    return trace_sha256_hex(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// Real clocks: only the CLI/Options wiring calls these.
// ---------------------------------------------------------------------------

std::string trace_utc_now() {
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
    const std::tm* converted = std::gmtime(&now);
    if (converted != nullptr) {
        utc = *converted;
    }
    std::ostringstream text;
    text << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return text.str();
}

std::uint64_t trace_monotonic_ms() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::chrono::steady_clock::now().time_since_epoch())
                                          .count());
}

// ---------------------------------------------------------------------------
// Citra channel: LLC + SecureData header fields.
// ---------------------------------------------------------------------------

TraceStructure trace_decode_citra_secure_data(const std::uint8_t* data, std::size_t size) {
    const char* const kFields[] = {"src_node_id",     "dest_node_id",  "data_channel",
                                   "is_management",   "seqno",         "payload_bytes"};
    const auto frame = citra_control::parse_secure_data_frame(data, size, nullptr);
    if (!frame.ok()) {
        return undecoded_structure("citra_secure_data",
                                   std::string("secure_data:") + citra_control::err_name(frame.err),
                                   {kFields[0], kFields[1], kFields[2],
                                    kFields[3], kFields[4], kFields[5]});
    }
    TraceStructure structure = decoded_structure("citra_secure_data");
    const citra_control::SecureDataHeader& header = frame.value.header;
    structure.fields.push_back(trace_field_u64("src_node_id", header.src_node_id));
    structure.fields.push_back(trace_field_u64("dest_node_id", header.dest_node_id));
    structure.fields.push_back(trace_field_u64("data_channel", header.data_channel));
    // A successful parse guarantees is_management == 0 (Err::Unsafe otherwise),
    // so this is decoded, not assumed.
    structure.fields.push_back(trace_field_u64("is_management", 0));
    structure.fields.push_back(trace_field_u64("seqno", header.sequence_number));
    structure.fields.push_back(trace_field_u64("payload_bytes", frame.value.payload.size()));
    return structure;
}

// ---------------------------------------------------------------------------
// Yuzu channel: Proxy compressed/uncompressed length + Zstd frame check.
// ---------------------------------------------------------------------------

TraceStructure trace_decode_yuzu_proxy(const std::uint8_t* compressed, std::size_t compressed_size,
                                       const std::uint8_t* plain, std::size_t plain_size,
                                       bool plain_available) {
    const char* const kFields[] = {"compressed_bytes", "decompressed_bytes", "zstd_frame_ok",
                                   "zstd_content_size"};
    auto undecoded = [&](const std::string& reason) {
        return undecoded_structure("yuzu_proxy", reason,
                                   {kFields[0], kFields[1], kFields[2], kFields[3]});
    };

    if (compressed == nullptr || compressed_size == 0) {
        return undecoded("proxy_empty");
    }
    const std::size_t frame_size = ZSTD_findFrameCompressedSize(compressed, compressed_size);
    if (ZSTD_isError(frame_size)) {
        return undecoded(std::string("zstd:") + ZSTD_getErrorName(frame_size));
    }
    const unsigned long long content = ZSTD_getFrameContentSize(compressed, compressed_size);
    if (content == ZSTD_CONTENTSIZE_ERROR) {
        return undecoded("zstd_content_size_error");
    }
    if (content == ZSTD_CONTENTSIZE_UNKNOWN) {
        return undecoded("zstd_content_size_unknown");
    }
    if (frame_size != compressed_size) {
        return undecoded("zstd_frame_trailing_bytes");
    }
    if (!plain_available) {
        return undecoded("proxy_plain_unavailable");
    }
    if (content != plain_size) {
        return undecoded("zstd_size_mismatch");
    }
    TraceStructure structure = decoded_structure("yuzu_proxy");
    structure.fields.push_back(trace_field_u64("compressed_bytes", compressed_size));
    structure.fields.push_back(trace_field_u64("decompressed_bytes", plain_size));
    structure.fields.push_back(trace_field_bool("zstd_frame_ok", true));
    structure.fields.push_back(trace_field_u64("zstd_content_size", content));
    (void)plain;
    return structure;
}

// ---------------------------------------------------------------------------
// Yuzu channel: LDN packet type + exact body size.
// ---------------------------------------------------------------------------

TraceStructure trace_decode_yuzu_ldn(std::uint8_t ldn_type, const std::uint8_t* body,
                                     std::size_t body_size) {
    const char* const kFields[] = {"ldn_type", "ldn_body_bytes", "ldn_expected_body_bytes",
                                   "ldn_size_ok"};
    (void)body;
    if (ldn_type > 5) {
        return undecoded_structure("yuzu_ldn", "ldn_type_out_of_range",
                                   {kFields[0], kFields[1], kFields[2], kFields[3]});
    }
    const std::size_t expected =
        citra_control::ldn_body_size(static_cast<citra_control::LdnPacketType>(ldn_type));
    TraceStructure structure = decoded_structure("yuzu_ldn");
    structure.fields.push_back(trace_field_u64("ldn_type", ldn_type));
    structure.fields.push_back(trace_field_u64("ldn_body_bytes", body_size));
    structure.fields.push_back(trace_field_u64("ldn_expected_body_bytes", expected));
    structure.fields.push_back(trace_field_bool("ldn_size_ok", body_size == expected));
    return structure;
}

// ---------------------------------------------------------------------------
// Record building and rendering.
// ---------------------------------------------------------------------------

TraceRecord trace_make_record(const TraceContext& context, const std::string& event_label,
                              const std::string& direction, const TraceStamp& stamp,
                              const std::uint8_t* data, std::size_t size,
                              const TraceStructure& structure, bool include_raw) {
    TraceRecord record;
    record.context = context;
    record.event_label = event_label;
    record.direction = direction;
    record.stamp = stamp;
    record.length = size;
    record.sha256 = trace_sha256_hex(data, size);
    record.structure = structure;
    if (include_raw && data != nullptr && size > 0) {
        record.raw.assign(data, data + size);
    }
    return record;
}

TraceRecord trace_make_marker(const TraceContext& context, const std::string& event_label,
                              const TraceStamp& stamp) {
    TraceRecord record;
    record.context = context;
    record.event_label = event_label;
    record.direction = "n/a";
    record.stamp = stamp;
    record.length = 0;
    record.sha256 = trace_sha256_hex(nullptr, 0);
    record.structure.name = "marker";
    record.structure.decoded = true;
    return record;
}

std::string TraceSink::render(const TraceRecord& record) {
    ObjectWriter json;
    json.string_field("manifest_id", record.context.manifest_id);
    json.string_field("run_id", record.context.run_id);
    json.string_field("channel", record.context.channel);
    json.string_field("platform", record.context.platform);
    json.string_field("build_id", record.context.build_id);
    json.string_field("role", record.context.role);
    json.string_field("event_label", record.event_label);
    json.string_field("stage", record.context.stage);
    json.string_field("direction", record.direction);
    json.string_field("utc", record.stamp.utc);
    json.u64_field("monotonic_ms", record.stamp.monotonic_ms);
    json.u64_field("length", record.length);
    json.string_field("sha256", record.sha256);
    json.string_field("structure", record.structure.name);
    json.raw_field("decoded", record.structure.decoded ? "true" : "false");
    if (!record.structure.decoded) {
        json.string_field("undecoded_reason", record.structure.reason);
    }
    for (const TraceField& field : record.structure.fields) {
        json.raw_field(field.name.c_str(), field.value);
    }
    if (!record.raw.empty()) {
        std::string hex;
        append_hex(hex, record.raw.data(), record.raw.size());
        json.string_field("raw_hex", hex);
    }
    return json.finish();
}

// ---------------------------------------------------------------------------
// TraceSink.
// ---------------------------------------------------------------------------

TraceSink::~TraceSink() {
    close();
}

std::filesystem::path trace_path_from_narrow(const std::string& path) {
#ifdef _WIN32
    if (!path.empty()) {
        const int count = static_cast<int>(path.size());
        const int wide_count = ::MultiByteToWideChar(CP_ACP, 0, path.c_str(), count, nullptr, 0);
        if (wide_count > 0) {
            std::wstring wide(static_cast<std::size_t>(wide_count), L'\0');
            if (::MultiByteToWideChar(CP_ACP, 0, path.c_str(), count, wide.data(), wide_count) == wide_count) {
                try {
                    return std::filesystem::path(wide);
                } catch (...) {
                }
            }
        }
    }
#endif
    try {
        return std::filesystem::path(path);
    } catch (...) {
        return std::filesystem::path();
    }
}

bool TraceSink::open(const std::string& path, bool raw_enabled, std::string* why) {
    close();
    if (path.empty()) {
        if (why != nullptr) {
            *why = "trace path is empty";
        }
        return false;
    }
    // Trace files live outside the repo, possibly under a non-ASCII directory,
    // so the narrow path is decoded explicitly and never allowed to throw.
    const std::filesystem::path fs_path = trace_path_from_narrow(path);
    if (fs_path.empty()) {
        if (why != nullptr) {
            *why = "cannot decode trace path: " + path;
        }
        return false;
    }
    try {
        out_.open(fs_path, std::ios::out | std::ios::trunc | std::ios::binary);
    } catch (...) {
        out_.clear();
    }
    if (!out_.is_open()) {
        if (why != nullptr) {
            *why = "cannot open trace file: " + path;
        }
        out_.clear();
        return false;
    }
    path_ = path;
    raw_enabled_ = raw_enabled;
    enabled_ = true;
    return true;
}

void TraceSink::close() noexcept {
    if (out_.is_open()) {
        out_.flush();
        out_.close();
    }
    out_.clear();
    enabled_ = false;
    raw_enabled_ = false;
}

bool TraceSink::write(const TraceRecord& record, std::string* why) {
    if (!enabled_) {
        return true;
    }
    out_ << render(record) << '\n';
    out_.flush();
    if (!out_.good()) {
        if (why != nullptr) {
            *why = "trace write failed: " + path_;
        }
        return false;
    }
    return true;
}

} // namespace citra_gateway
