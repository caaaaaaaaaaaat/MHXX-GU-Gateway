// SPDX-FileCopyrightText: Copyright 2019 yuzu Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 LAN codec contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Normal encoder reproduces the ZSTD_compress(..., ZSTD_CLEVEL_DEFAULT) call profile.
#include "lan_codecs.h"
#include <algorithm>
#include <limits>
#include <new>
#include <zstd.h>
#include <zstd_errors.h>

namespace lan_codec {
namespace {
Result<Bytes> fail(Error e) { return {e, 0, {}}; }
bool valid_limits(ZstdLimits l) { return l.compressed <= hard_resource_cap && l.decompressed <= hard_resource_cap; }
}
Result<Bytes> decode_zstd_single(Input frame, ZstdLimits l) {
    if (!valid_limits(l) || frame.size() > l.compressed) return fail(Error::limit_exceeded);
    if (frame.size() < 4) return fail(Error::incomplete_frame);
    // Standard magic only: skippable frames do not carry application data in this profile.
    if (frame[0] != 0x28 || frame[1] != 0xB5 || frame[2] != 0x2F || frame[3] != 0xFD) return fail(Error::invalid_zstd);
    const auto content = ZSTD_getFrameContentSize(frame.data(), frame.size());
    if (content == ZSTD_CONTENTSIZE_ERROR) return fail(Error::invalid_zstd);
    if (content == ZSTD_CONTENTSIZE_UNKNOWN) return fail(Error::unknown_content_size);
    if (content > l.decompressed || content > std::numeric_limits<std::size_t>::max()) return fail(Error::limit_exceeded);
    const auto frame_size = ZSTD_findFrameCompressedSize(frame.data(), frame.size());
    if (ZSTD_isError(frame_size)) return fail(Error::incomplete_frame);
    if (frame_size != frame.size()) return fail(Error::trailing_data); // Includes concatenated frames.
    try {
        Bytes out(static_cast<std::size_t>(content));
        const auto written = ZSTD_decompress(out.data(), out.size(), frame.data(), frame.size());
        if (ZSTD_isError(written) || written != out.size()) return fail(Error::invalid_zstd);
        return {Error::none, 0, std::move(out)};
    } catch (const std::bad_alloc&) { return fail(Error::memory_failure); }
}
Result<Bytes> encode_zstd_default(Input application, ZstdLimits l) {
    if (!valid_limits(l) || application.size() > l.decompressed) return fail(Error::limit_exceeded);
    const auto bound = ZSTD_compressBound(application.size());
    if (ZSTD_isError(bound)) return fail(Error::invalid_zstd);
    try {
        Bytes out(std::min(bound, l.compressed));
        const auto written = ZSTD_compress(out.data(), out.size(), application.data(), application.size(), ZSTD_CLEVEL_DEFAULT);
        if (ZSTD_isError(written)) {
            return fail(ZSTD_getErrorCode(written) == ZSTD_error_dstSize_tooSmall ? Error::limit_exceeded : Error::invalid_zstd);
        }
        out.resize(written);
        return {Error::none, 0, std::move(out)};
    } catch (const std::bad_alloc&) { return fail(Error::memory_failure); }
}
} // namespace lan_codec
