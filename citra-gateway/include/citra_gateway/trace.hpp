// SPDX-License-Identifier: GPL-2.0-or-later
// G2 trace recorder (channels A/B/C) (docs/G2-PROCEDURE.md section 3).
//
// Every frame that crosses the gateway can be recorded to an out-of-repo JSON
// Lines file: one JSON object per line, stable field order, no wall-clock
// dependence inside the record builder (the caller injects the UTC text and the
// monotonic millisecond counter). A frame whose channel structure cannot be
// decoded is recorded with every structure field set to the literal string
// "undecoded" plus a reason; no field is ever guessed.
//
// The recorder is opt-in: with an empty Options::trace_path the gateway is
// byte-for-byte unchanged. Raw frame bytes are only embedded with --trace-raw.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace citra_gateway {

// Fixed identity copied into every record of one run. All values are injected.
struct TraceContext {
    std::string manifest_id = "unset";
    std::string run_id = "unset";
    std::string channel = "C";
    std::string platform = "unset";
    std::string build_id = "unset";
    std::string role = "unset";
    std::string stage = "unspecified";
};

// Injected time. The builder never reads a clock; the caller supplies both the
// UTC text and the monotonic millisecond counter.
struct TraceStamp {
    std::string utc;                 // ISO-8601 UTC text, e.g. 2026-10-15T04:05:06Z
    std::uint64_t monotonic_ms = 0;  // caller-supplied monotonic milliseconds
};

// One structure field, rendered in list order. `value` is already the JSON
// scalar text (a number, or a quoted string produced by the helpers below).
struct TraceField {
    std::string name;
    std::string value;
};

// Result of decoding one frame on its native channel. decoded == false keeps
// `reason` and fills every field with the literal "undecoded".
struct TraceStructure {
    std::string name = "undecoded";
    bool decoded = false;
    std::string reason;
    std::vector<TraceField> fields;
};

// One trace line. All members are public so tests can build a record directly.
struct TraceRecord {
    TraceContext context;
    std::string event_label;
    std::string direction;
    TraceStamp stamp;
    std::size_t length = 0;
    std::string sha256;
    TraceStructure structure;
    std::vector<std::uint8_t> raw;  // empty unless raw tracing was requested
};

// JSON scalar helpers for hand-built structures.
TraceField trace_field_string(const std::string& name, const std::string& value);
TraceField trace_field_u64(const std::string& name, std::uint64_t value);
TraceField trace_field_bool(const std::string& name, bool value);
TraceField trace_field_undecoded(const std::string& name);

// FIPS 180-4 SHA-256, lower-case hex. Pure and stable.
std::string trace_sha256_hex(const std::uint8_t* data, std::size_t size);
std::string trace_sha256_hex(const std::vector<std::uint8_t>& data);

// Real clocks. Called only by the CLI/Options wiring, never by the builder, so
// unit tests can stay deterministic by injecting a TraceStamp instead.
std::string trace_utc_now();
std::uint64_t trace_monotonic_ms();

// Pure per-channel decoders: no IO, no clock, no global state.
// Citra side: LLC + SecureData header fields (src/dest node id, data_channel,
// is_management, seqno). `data` is the full LLC+SecureData frame.
TraceStructure trace_decode_citra_secure_data(const std::uint8_t* data, std::size_t size);

// Yuzu side: one Proxy frame's compressed/uncompressed length and the Zstd
// frame verification result. `plain` is the decompressed application bytes.
TraceStructure trace_decode_yuzu_proxy(const std::uint8_t* compressed, std::size_t compressed_size,
                                       const std::uint8_t* plain, std::size_t plain_size,
                                       bool plain_available);

// Yuzu side: LDN packet type and the exact body size against the frozen table.
TraceStructure trace_decode_yuzu_ldn(std::uint8_t ldn_type, const std::uint8_t* body,
                                     std::size_t body_size);

// Builds a record from raw bytes and a decoder result; the caller supplies the
// stamp. Hashes `data` and copies it only when include_raw is true.
TraceRecord trace_make_record(const TraceContext& context, const std::string& event_label,
                              const std::string& direction, const TraceStamp& stamp,
                              const std::uint8_t* data, std::size_t size,
                              const TraceStructure& structure, bool include_raw);

// Builds a self-describing marker record: direction "n/a", length 0, the
// SHA-256 of the empty input and the "marker" structure. Used for run.begin
// and stage.begin so that a run with zero frames still identifies itself.
TraceRecord trace_make_marker(const TraceContext& context, const std::string& event_label,
                              const TraceStamp& stamp);

// Builds a filesystem path from a narrow process-argument string. On Windows
// the argument bytes use the active code page (not UTF-8), while libstdc++
// converts a narrow std::filesystem::path as if it were UTF-8 and throws on
// such bytes; decoding explicitly makes a non-ASCII trace path work. Never
// throws: an undecodable path yields an empty path.
std::filesystem::path trace_path_from_narrow(const std::string& path);

// Opt-in JSON Lines writer. Disabled until open() succeeds. A failed open()
// reports why and leaves the sink disabled; a failed write() reports why so the
// caller can stop tracing without changing any protocol behaviour.
class TraceSink {
public:
    TraceSink() = default;
    ~TraceSink();
    TraceSink(const TraceSink&) = delete;
    TraceSink& operator=(const TraceSink&) = delete;

    // Truncates/creates `path`. Empty path is an error.
    bool open(const std::string& path, bool raw_enabled, std::string* why);
    void close() noexcept;
    bool enabled() const noexcept { return enabled_; }
    bool raw_enabled() const noexcept { return raw_enabled_; }
    const std::string& path() const noexcept { return path_; }

    // Renders one record as a single JSON line (no trailing newline). Pure.
    static std::string render(const TraceRecord& record);

    // Appends render(record) + "\n" and flushes. No-op (true) while disabled.
    bool write(const TraceRecord& record, std::string* why);

private:
    std::ofstream out_;
    std::string path_;
    bool enabled_ = false;
    bool raw_enabled_ = false;
};

} // namespace citra_gateway
