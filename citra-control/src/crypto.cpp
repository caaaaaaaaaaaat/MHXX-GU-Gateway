// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - from-scratch MD5 (RFC 1321), SHA-1 (FIPS 180-4) and
// AES-128 (FIPS-197) in CTR mode.
#include "citra_control/crypto.hpp"

#include <cstring>

namespace citra_control {

namespace {

inline std::uint32_t rotl32(std::uint32_t v, unsigned n) noexcept {
    return (v << n) | (v >> (32u - n));
}

// ---------------------------------------------------------------------- MD5
const std::uint32_t kMd5K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};

const std::uint8_t kMd5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9,  14, 20, 5, 9,
                                14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

void md5_block(const std::uint8_t* p, std::uint32_t h[4]) noexcept {
    std::uint32_t m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] = load_u32le(p + 4 * i);
    }
    std::uint32_t a = h[0];
    std::uint32_t b = h[1];
    std::uint32_t c = h[2];
    std::uint32_t d = h[3];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t f = 0;
        int g = 0;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) & 15;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) & 15;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) & 15;
        }
        const std::uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + kMd5K[i] + m[g], kMd5S[i]);
        a = tmp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

// --------------------------------------------------------------------- SHA-1
void sha1_block(const std::uint8_t* p, std::uint32_t h[5]) noexcept {
    std::uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = load_u32be(p + 4 * i);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    std::uint32_t a = h[0];
    std::uint32_t b = h[1];
    std::uint32_t c = h[2];
    std::uint32_t d = h[3];
    std::uint32_t e = h[4];
    for (int i = 0; i < 80; ++i) {
        std::uint32_t f = 0;
        std::uint32_t k = 0;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        const std::uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = tmp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

// ----------------------------------------------------------------------- AES
const std::uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
    0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
    0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
    0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
    0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
    0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

inline std::uint8_t xtime(std::uint8_t x) noexcept {
    return static_cast<std::uint8_t>((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0x00u));
}

inline std::uint32_t sub_word(std::uint32_t w) noexcept {
    return (static_cast<std::uint32_t>(kSbox[(w >> 24) & 0xffu]) << 24) |
           (static_cast<std::uint32_t>(kSbox[(w >> 16) & 0xffu]) << 16) |
           (static_cast<std::uint32_t>(kSbox[(w >> 8) & 0xffu]) << 8) |
           static_cast<std::uint32_t>(kSbox[w & 0xffu]);
}

inline std::uint32_t rot_word(std::uint32_t w) noexcept {
    return (w << 8) | (w >> 24);
}

void add_round_key(std::uint8_t s[16], const std::uint32_t* rk, int round) noexcept {
    for (int c = 0; c < 4; ++c) {
        const std::uint32_t w = rk[round * 4 + c];
        s[c * 4 + 0] ^= static_cast<std::uint8_t>((w >> 24) & 0xffu);
        s[c * 4 + 1] ^= static_cast<std::uint8_t>((w >> 16) & 0xffu);
        s[c * 4 + 2] ^= static_cast<std::uint8_t>((w >> 8) & 0xffu);
        s[c * 4 + 3] ^= static_cast<std::uint8_t>(w & 0xffu);
    }
}

void sub_bytes(std::uint8_t s[16]) noexcept {
    for (int i = 0; i < 16; ++i) {
        s[i] = kSbox[s[i]];
    }
}

void shift_rows(std::uint8_t s[16]) noexcept {
    std::uint8_t t[16];
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            t[r + 4 * c] = s[r + 4 * ((c + r) & 3)];
        }
    }
    for (int i = 0; i < 16; ++i) {
        s[i] = t[i];
    }
}

void mix_columns(std::uint8_t s[16]) noexcept {
    for (int c = 0; c < 4; ++c) {
        const std::uint8_t a0 = s[4 * c + 0];
        const std::uint8_t a1 = s[4 * c + 1];
        const std::uint8_t a2 = s[4 * c + 2];
        const std::uint8_t a3 = s[4 * c + 3];
        s[4 * c + 0] = static_cast<std::uint8_t>(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        s[4 * c + 1] = static_cast<std::uint8_t>(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        s[4 * c + 2] = static_cast<std::uint8_t>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        s[4 * c + 3] = static_cast<std::uint8_t>((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

} // namespace

Md5Digest md5(const std::uint8_t* data, std::size_t size) noexcept {
    std::uint32_t h[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    const std::size_t full = size / 64u * 64u;
    for (std::size_t off = 0; off < full; off += 64) {
        md5_block(data + off, h);
    }
    const std::size_t rem = size - full;
    std::uint8_t tail[128];
    for (std::size_t i = 0; i < sizeof(tail); ++i) {
        tail[i] = 0;
    }
    for (std::size_t i = 0; i < rem; ++i) {
        tail[i] = data[full + i];
    }
    tail[rem] = 0x80u;
    const std::size_t total = (rem + 1u <= 56u) ? 64u : 128u;
    const std::uint64_t bits = static_cast<std::uint64_t>(size) * 8u;
    store_u64le(tail + total - 8u, bits);
    md5_block(tail, h);
    if (total == 128u) {
        md5_block(tail + 64, h);
    }
    Md5Digest out{};
    for (int i = 0; i < 4; ++i) {
        store_u32le(out.data() + 4 * i, h[i]);
    }
    return out;
}

Sha1Digest sha1(const std::uint8_t* data, std::size_t size) noexcept {
    std::uint32_t h[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
    const std::size_t full = size / 64u * 64u;
    for (std::size_t off = 0; off < full; off += 64) {
        sha1_block(data + off, h);
    }
    const std::size_t rem = size - full;
    std::uint8_t tail[128];
    for (std::size_t i = 0; i < sizeof(tail); ++i) {
        tail[i] = 0;
    }
    for (std::size_t i = 0; i < rem; ++i) {
        tail[i] = data[full + i];
    }
    tail[rem] = 0x80u;
    const std::size_t total = (rem + 1u <= 56u) ? 64u : 128u;
    const std::uint64_t bits = static_cast<std::uint64_t>(size) * 8u;
    store_u64be(tail + total - 8u, bits);
    sha1_block(tail, h);
    if (total == 128u) {
        sha1_block(tail + 64, h);
    }
    Sha1Digest out{};
    for (int i = 0; i < 5; ++i) {
        store_u32be(out.data() + 4 * i, h[i]);
    }
    return out;
}

void Aes128::expand(const std::uint8_t key[16]) noexcept {
    for (int i = 0; i < 4; ++i) {
        rk_[i] = load_u32be(key + 4 * i);
    }
    std::uint8_t rcon = 0x01u;
    for (int i = 4; i < 44; ++i) {
        std::uint32_t t = rk_[i - 1];
        if (i % 4 == 0) {
            t = sub_word(rot_word(t)) ^ (static_cast<std::uint32_t>(rcon) << 24);
            rcon = xtime(rcon);
        }
        rk_[i] = rk_[i - 4] ^ t;
    }
}

void Aes128::encrypt_block(const std::uint8_t in[16], std::uint8_t out[16]) const noexcept {
    std::uint8_t s[16];
    for (int i = 0; i < 16; ++i) {
        s[i] = in[i];
    }
    add_round_key(s, rk_, 0);
    for (int round = 1; round < 10; ++round) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, rk_, round);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, rk_, 10);
    for (int i = 0; i < 16; ++i) {
        out[i] = s[i];
    }
}

void ctr_increment(AesBlock& counter) noexcept {
    for (int i = 15; i >= 0; --i) {
        counter[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(counter[static_cast<std::size_t>(i)] + 1u);
        if (counter[static_cast<std::size_t>(i)] != 0u) {
            break;
        }
    }
}

Err aes128_ctr_xcrypt(const Aes128& key, const AesBlock& counter, std::uint8_t* data, std::size_t size,
                      Diag* diag) noexcept {
    if (size % 16u != 0u) {
        if (diag != nullptr) {
            ++diag->c.crypto_reject;
            diag->note_reject("aes128_ctr", Err::NotMultipleOf16, "size=" + std::to_string(size));
        }
        return Err::NotMultipleOf16;
    }
    AesBlock ctr = counter;
    std::uint8_t ks[16];
    for (std::size_t off = 0; off < size; off += 16) {
        key.encrypt_block(ctr.data(), ks);
        for (std::size_t i = 0; i < 16; ++i) {
            data[off + i] ^= ks[i];
        }
        ctr_increment(ctr);
        if (diag != nullptr) {
            ++diag->c.crypto_aes_ctr;
        }
    }
    return Err::Ok;
}

Err aes128_ctr_xcrypt_stream(const Aes128& key, const AesBlock& counter, std::uint8_t* data, std::size_t size,
                             Diag* diag) noexcept {
    AesBlock ctr = counter;
    std::uint8_t ks[16];
    std::size_t off = 0;
    while (off < size) {
        const std::size_t n = (size - off < 16u) ? (size - off) : 16u;
        key.encrypt_block(ctr.data(), ks);
        for (std::size_t i = 0; i < n; ++i) {
            data[off + i] ^= ks[i];
        }
        if (n != 16u && diag != nullptr) {
            ++diag->c.crypto_ctr_partial_blocks;
        }
        ctr_increment(ctr);
        off += n;
        if (diag != nullptr) {
            ++diag->c.crypto_aes_ctr;
        }
    }
    return Err::Ok;
}

} // namespace citra_control
