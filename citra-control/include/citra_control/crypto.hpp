// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - from-scratch MD5, SHA-1 and AES-128-CTR.
//
// These primitives are implemented here rather than taken from a library so the
// library stays dependency-free and so the tests can pin them to the published
// FIPS-197 / RFC 1321 / FIPS 180-4 known-answer vectors (independent oracle).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "citra_control/bytes.hpp"

namespace citra_control {

using Md5Digest = std::array<std::uint8_t, 16>;
using Sha1Digest = std::array<std::uint8_t, 20>;
using AesBlock = std::array<std::uint8_t, 16>;

Md5Digest md5(const std::uint8_t* data, std::size_t size) noexcept;
inline Md5Digest md5(const std::vector<std::uint8_t>& v) noexcept { return md5(v.data(), v.size()); }

Sha1Digest sha1(const std::uint8_t* data, std::size_t size) noexcept;
inline Sha1Digest sha1(const std::vector<std::uint8_t>& v) noexcept { return sha1(v.data(), v.size()); }

// Expanded AES-128 key schedule (11 round keys x 4 words).
class Aes128 {
public:
    Aes128() noexcept = default;
    explicit Aes128(const std::uint8_t key[16]) noexcept { expand(key); }
    void expand(const std::uint8_t key[16]) noexcept;
    void encrypt_block(const std::uint8_t in[16], std::uint8_t out[16]) const noexcept;

private:
    std::uint32_t rk_[44] = {};
};

// Big-endian increment of the whole 16-byte block (matches CryptoPP CTR_Mode
// and the NIST SP 800-38A counter convention).
void ctr_increment(AesBlock& counter) noexcept;

// Strict CTR: the plaintext/ciphertext length MUST be a multiple of 16,
// otherwise Err::NotMultipleOf16 is returned, crypto_reject is bumped and the
// data is left untouched.
Err aes128_ctr_xcrypt(const Aes128& key, const AesBlock& counter, std::uint8_t* data, std::size_t size,
                      Diag* diag = nullptr) noexcept;

// CryptoPP-compatible CTR for arbitrary lengths (the real beacon plaintext is
// 0x12 + N*0x1E bytes, which is not always block aligned).  Partial final
// blocks are counted in crypto_ctr_partial_blocks.
Err aes128_ctr_xcrypt_stream(const Aes128& key, const AesBlock& counter, std::uint8_t* data, std::size_t size,
                             Diag* diag = nullptr) noexcept;

inline Err aes128_ctr_xcrypt(const std::uint8_t key[16], const AesBlock& counter, std::uint8_t* data,
                             std::size_t size, Diag* diag = nullptr) noexcept {
    const Aes128 k(key);
    return aes128_ctr_xcrypt(k, counter, data, size, diag);
}
inline Err aes128_ctr_xcrypt_stream(const std::uint8_t key[16], const AesBlock& counter, std::uint8_t* data,
                                    std::size_t size, Diag* diag = nullptr) noexcept {
    const Aes128 k(key);
    return aes128_ctr_xcrypt_stream(k, counter, data, size, diag);
}

} // namespace citra_control
