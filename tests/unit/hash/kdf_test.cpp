// HMAC/HKDF/PBKDF2 over SHA3-256 against values produced by OpenSSL
// (tests/kat/kdf/generate.py).

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "hash/hkdf.hpp"
#include "hash/hmac.hpp"
#include "hash/pbkdf2.hpp"
#include "pq/error.hpp"
#include "support/kat_reader.hpp"

namespace {

using pq::test::from_hex;
using pq::test::read_rsp;
using pq::test::to_hex;

TEST(HmacSha3_256, OpenSslVectors) {
  const auto records = read_rsp("kdf/hmac_sha3_256.rsp");
  ASSERT_EQ(records.size(), 56U);
  for (const auto& r : records) {
    std::array<uint8_t, 32> mac{};
    pq::hash::hmac_sha3_256(mac, from_hex(r.fields.at("Key")), from_hex(r.fields.at("Msg")));
    EXPECT_EQ(to_hex(mac), r.fields.at("Mac")) << "COUNT=" << r.fields.at("COUNT");
  }
}

TEST(HmacSha3_256, ResetReusesKey) {
  const auto r = read_rsp("kdf/hmac_sha3_256.rsp").at(20);
  pq::hash::HmacSha3_256 mac(from_hex(r.fields.at("Key")));
  std::array<uint8_t, 32> out{};
  mac.update(std::vector<uint8_t>{1, 2, 3});
  mac.finalize(out);
  mac.reset();
  mac.update(from_hex(r.fields.at("Msg")));
  mac.finalize(out);
  EXPECT_EQ(to_hex(out), r.fields.at("Mac"));
}

TEST(HkdfSha3_256, OpenSslVectors) {
  const auto records = read_rsp("kdf/hkdf_sha3_256.rsp");
  ASSERT_EQ(records.size(), 7U);
  for (const auto& r : records) {
    const auto ikm = from_hex(r.fields.at("IKM"));
    const auto salt = from_hex(r.fields.at("Salt"));
    const auto info = from_hex(r.fields.at("Info"));
    std::array<uint8_t, 32> prk{};
    pq::hash::hkdf_sha3_256_extract(prk, salt, ikm);
    EXPECT_EQ(to_hex(prk), r.fields.at("PRK")) << "COUNT=" << r.fields.at("COUNT");

    std::vector<uint8_t> okm(std::stoul(r.fields.at("L")));
    pq::hash::hkdf_sha3_256(okm, ikm, salt, info);
    EXPECT_EQ(to_hex(okm), r.fields.at("OKM")) << "COUNT=" << r.fields.at("COUNT");
  }
}

TEST(HkdfSha3_256, TooLongOutputThrows) {
  std::vector<uint8_t> okm(pq::hash::kHkdfSha3_256MaxOutput + 1);
  const std::array<uint8_t, 32> prk{};
  EXPECT_THROW(pq::hash::hkdf_sha3_256_expand(okm, prk, {}), pq::Error);
}

TEST(Pbkdf2HmacSha3_256, OpenSslVectors) {
  const auto records = read_rsp("kdf/pbkdf2_hmac_sha3_256.rsp");
  ASSERT_EQ(records.size(), 8U);
  for (const auto& r : records) {
    std::vector<uint8_t> dk(std::stoul(r.fields.at("DKLen")));
    pq::hash::pbkdf2_hmac_sha3_256(dk, from_hex(r.fields.at("Password")),
                                   from_hex(r.fields.at("Salt")),
                                   static_cast<uint32_t>(std::stoul(r.fields.at("Iterations"))));
    EXPECT_EQ(to_hex(dk), r.fields.at("DK")) << "COUNT=" << r.fields.at("COUNT");
  }
}

TEST(Pbkdf2HmacSha3_256, ZeroIterationsThrows) {
  std::array<uint8_t, 32> dk{};
  EXPECT_THROW(pq::hash::pbkdf2_hmac_sha3_256(dk, {}, {}, 0), pq::Error);
}

}  // namespace
