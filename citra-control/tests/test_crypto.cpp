// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - crypto known-answer tests.
//
// The expected digests/ciphertexts below are the published standard vectors
// (RFC 1321 A.5, FIPS 180-4, FIPS-197 C.1, NIST SP 800-38A F.1.1).  They are an
// independent oracle: they were not produced by this implementation.
#include <cstring>
#include <string>
#include <vector>

#include "citra_control/bytes.hpp"
#include "citra_control/crypto.hpp"
#include "harness.hpp"

using namespace citra_control;

namespace {

std::vector<std::uint8_t> hx(const char* s) {
    std::vector<std::uint8_t> v;
    std::string why;
    if (!from_hex(s, v, &why)) {
        std::printf("  FAIL bad test hex: %s\n", why.c_str());
    }
    return v;
}

std::string hx_str(const std::uint8_t* p, std::size_t n) { return to_hex(p, n); }

} // namespace

TT_SUITE(crypto) {
    // --- MD5, RFC 1321 Appendix A.5 -------------------------------------
    struct Md5Case {
        const char* input;
        const char* digest;
    };
    static const Md5Case md5_cases[] = {
        {"", "d41d8cd98f00b204e9800998ecf8427e"},
        {"a", "0cc175b9c0f1b6a831c399e269772661"},
        {"abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "57edf4a22be3c955ac49da2e2107b67a"},
    };
    TT_CASE();
    for (const Md5Case& c : md5_cases) {
        const Md5Digest d = md5(reinterpret_cast<const std::uint8_t*>(c.input), std::strlen(c.input));
        TT_CHECK(hx_str(d.data(), d.size()) == c.digest);
    }
    // 56/57/64/128-byte boundary vectors: the padding branch must be exercised.
    TT_CASE();
    {
        const std::string a55(55, 'a');
        const std::string a56(56, 'a');
        const std::string a64(64, 'a');
        const std::string a65(65, 'a');
        const Md5Digest d55 = md5(reinterpret_cast<const std::uint8_t*>(a55.data()), a55.size());
        const Md5Digest d56 = md5(reinterpret_cast<const std::uint8_t*>(a56.data()), a56.size());
        const Md5Digest d64 = md5(reinterpret_cast<const std::uint8_t*>(a64.data()), a64.size());
        const Md5Digest d65 = md5(reinterpret_cast<const std::uint8_t*>(a65.data()), a65.size());
        // Independent oracle values from `openssl dgst -md5` on the same synthetic inputs.
        TT_CHECK(hx_str(d55.data(), 16) == "ef1772b6dff9a122358552954ad0df65");
        TT_CHECK(hx_str(d56.data(), 16) == "3b0c8ac703f828b04c6c197006d17218");
        TT_CHECK(hx_str(d64.data(), 16) == "014842d480b571495a4a0363793f7367");
        TT_CHECK(hx_str(d65.data(), 16) == "c743a45e0d2e6a95cb859adae0248435");
    }

    // --- SHA-1, FIPS 180-4 examples -------------------------------------
    struct Sha1Case {
        const char* input;
        const char* digest;
    };
    static const Sha1Case sha1_cases[] = {
        {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {"The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
    };
    TT_CASE();
    for (const Sha1Case& c : sha1_cases) {
        const Sha1Digest d = sha1(reinterpret_cast<const std::uint8_t*>(c.input), std::strlen(c.input));
        TT_CHECK(hx_str(d.data(), d.size()) == c.digest);
    }
    TT_CASE();
    {
        std::vector<std::uint8_t> million(1000000u, static_cast<std::uint8_t>('a'));
        const Sha1Digest d = sha1(million.data(), million.size());
        TT_CHECK(hx_str(d.data(), d.size()) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    // --- AES-128 block, FIPS-197 Appendix C.1 ---------------------------
    TT_CASE();
    {
        const std::vector<std::uint8_t> key = hx("000102030405060708090a0b0c0d0e0f");
        const std::vector<std::uint8_t> pt = hx("00112233445566778899aabbccddeeff");
        Aes128 aes(key.data());
        std::uint8_t out[16];
        aes.encrypt_block(pt.data(), out);
        TT_CHECK(hx_str(out, 16) == "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    // --- AES-128-CTR, NIST SP 800-38A F.1.1 -----------------------------
    TT_CASE();
    {
        const std::vector<std::uint8_t> key = hx("2b7e151628aed2a6abf7158809cf4f3c");
        const std::vector<std::uint8_t> ctr = hx("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const std::vector<std::uint8_t> pt =
            hx("6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710");
        const std::string want =
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee";
        AesBlock c{};
        for (std::size_t i = 0; i < 16; ++i) {
            c[i] = ctr[i];
        }
        std::vector<std::uint8_t> buf = pt;
        Diag diag;
        TT_CHECK(aes128_ctr_xcrypt(Aes128(key.data()), c, buf.data(), buf.size(), &diag) == Err::Ok);
        TT_CHECK(hx_str(buf.data(), buf.size()) == want);
        TT_CHECK(diag.c.crypto_aes_ctr == 4);
        TT_CHECK(diag.c.crypto_ctr_partial_blocks == 0);
        // Decrypting again restores the plaintext (CTR is an involution).
        std::vector<std::uint8_t> back = buf;
        TT_CHECK(aes128_ctr_xcrypt(Aes128(key.data()), c, back.data(), back.size(), nullptr) == Err::Ok);
        TT_CHECK(back == pt);
    }

    // --- CTR partial block (CryptoPP stream semantics) ------------------
    TT_CASE();
    {
        const std::vector<std::uint8_t> key = hx("2b7e151628aed2a6abf7158809cf4f3c");
        const std::vector<std::uint8_t> ctr = hx("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const std::vector<std::uint8_t> pt20 = hx("6bc1bee22e409f96e93d7e117393172aae2d8a57");
        const std::string want20 = "874d6191b620e3261bef6864990db6ce9806f66b";
        AesBlock c{};
        for (std::size_t i = 0; i < 16; ++i) {
            c[i] = ctr[i];
        }
        std::vector<std::uint8_t> buf = pt20;
        Diag diag;
        TT_CHECK(aes128_ctr_xcrypt_stream(Aes128(key.data()), c, buf.data(), buf.size(), &diag) == Err::Ok);
        TT_CHECK(hx_str(buf.data(), buf.size()) == want20);
        TT_CHECK(diag.c.crypto_ctr_partial_blocks == 1);
        TT_CHECK(diag.c.crypto_aes_ctr == 2);
    }

    // --- Strict alignment gate ------------------------------------------
    TT_CASE();
    {
        const std::vector<std::uint8_t> key = hx("000102030405060708090a0b0c0d0e0f");
        AesBlock c{};
        std::vector<std::uint8_t> buf(17, static_cast<std::uint8_t>(0x5A));
        const std::vector<std::uint8_t> before = buf;
        Diag diag;
        TT_CHECK(aes128_ctr_xcrypt(Aes128(key.data()), c, buf.data(), buf.size(), &diag) == Err::NotMultipleOf16);
        TT_CHECK(buf == before); // rejected input must be left untouched
        TT_CHECK(diag.c.crypto_reject == 1);
        TT_CHECK(diag.c.err[static_cast<std::size_t>(Err::NotMultipleOf16)] == 1);
        // 0 bytes is a legal (empty) multiple of 16.
        TT_CHECK(aes128_ctr_xcrypt(Aes128(key.data()), c, buf.data(), 0, nullptr) == Err::Ok);
    }

    // --- Counter increment is big-endian over the whole 16-byte block ----
    TT_CASE();
    {
        AesBlock c{};
        c[15] = 0xFF;
        ctr_increment(c);
        std::uint8_t expect[16] = {};
        expect[14] = 0x01;
        bool same = true;
        for (int i = 0; i < 16; ++i) {
            same = same && (c[static_cast<std::size_t>(i)] == expect[i]);
        }
        TT_CHECK(same);
        for (int i = 0; i < 16; ++i) {
            c[static_cast<std::size_t>(i)] = 0xFF;
        }
        ctr_increment(c);
        bool wrapped = true;
        for (int i = 0; i < 16; ++i) {
            wrapped = wrapped && (c[static_cast<std::size_t>(i)] == 0x00);
        }
        TT_CHECK(wrapped);
    }
}
