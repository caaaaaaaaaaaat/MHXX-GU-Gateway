// SPDX-License-Identifier: GPL-3.0-or-later
// citra-control - byte layer tests.
#include <string>

#include "citra_control/bytes.hpp"
#include "util.hpp"

using namespace citra_control;
using ttx::hx;

TT_SUITE(bytes) {
    TT_CASE();
    {
        Writer w;
        w.u8(0xA1);
        w.u16le(0x1234);
        w.u16be(0x1234);
        w.u32le(0xDEADBEEFu);
        w.u32be(0xDEADBEEFu);
        w.u64le(0x0123456789ABCDEFull);
        w.u64be(0x0123456789ABCDEFull);
        ttx::expect_hex(w.buf, "a1 3412 1234 efbeadde deadbeef efcdab8967452301 0123456789abcdef");
    }
    TT_CASE();
    {
        const std::vector<std::uint8_t> b = hx("a134121234efbeaddedeadbeefefcdab89674523010123456789abcdef");
        Reader r(b);
        TT_CHECK(r.u8() == 0xA1);
        TT_CHECK(r.u16le() == 0x1234);
        TT_CHECK(r.u16be() == 0x1234);
        TT_CHECK(r.u32le() == 0xDEADBEEFu);
        TT_CHECK(r.u32be() == 0xDEADBEEFu);
        TT_CHECK(r.u64le() == 0x0123456789ABCDEFull);
        TT_CHECK(r.u64be() == 0x0123456789ABCDEFull);
        TT_CHECK(r.ok());
        TT_CHECK(r.at_end());
        TT_CHECK(r.remaining() == 0);
    }
    TT_CASE();
    {
        // Reader latches Short and never reads past the end.
        const std::vector<std::uint8_t> b = hx("0102");
        Reader r(b);
        TT_CHECK(r.u16le() == 0x0201);
        TT_CHECK(r.ok());
        TT_CHECK(r.u32le() == 0);
        TT_CHECK(!r.ok());
        TT_CHECK(r.err() == Err::Short);
        TT_CHECK(r.u8() == 0);
        TT_CHECK(r.err() == Err::Short);
        TT_CHECK(r.raw(1) == nullptr);
        TT_CHECK(!r.seek(99));
    }
    TT_CASE();
    {
        // hex round trip through a file-like text with comments and whitespace.
        const std::string text = "# synthetic\n00 11 22\n3344\n";
        std::vector<std::uint8_t> out;
        std::string why;
        TT_CHECK(from_hex(text, out, &why));
        ttx::expect_hex(out, "001122 3344");
        TT_CHECK(to_hex(out) == "0011223344");
    }
    TT_CASE();
    {
        std::vector<std::uint8_t> out;
        std::string why;
        TT_CHECK(!from_hex("abc", out, &why)); // odd
        TT_CHECK(!from_hex("zz", out, &why));  // invalid char
        TT_CHECK(!from_hex("a1b", out, &why));
    }
    TT_CASE();
    {
        Diag d;
        d.events_enabled = false;
        d.note_reject("x", Err::BadTag);
        d.note_reject("x", Err::BadTag);
        d.note_reject("y", Err::Short);
        TT_CHECK(d.c.decode_reject == 3);
        TT_CHECK(d.c.err[static_cast<std::size_t>(Err::BadTag)] == 2);
        TT_CHECK(d.c.err[static_cast<std::size_t>(Err::Short)] == 1);
        TT_CHECK(d.log.lines.empty());
        const std::string t = d.counters_text();
        TT_CHECK(t.find("err.BadTag=2") != std::string::npos);
        TT_CHECK(t.find("decode_reject=3") != std::string::npos);
        err_name(Err::Ok);
        TT_CHECK(std::string(err_name(Err::NotFound)) == "NotFound");
        TT_CHECK(kErrCount == 22);
    }
    TT_CASE();
    {
        Writer w;
        w.zeros(3);
        w.bytes(reinterpret_cast<const std::uint8_t*>("\xAA\xBB"), 2);
        w.patch_u8(0, 7);
        ttx::expect_hex(w.buf, "070000aabb");
        TT_CHECK(w.size() == 5);
    }
}
