#include "mode/gcm.hpp"

#include <gtest/gtest.h>

#include <limits>

#include "pq/ct.hpp"
#include "support/kat_reader.hpp"
#include "support/participant3_registry.hpp"
#include "support/secret_fixture.hpp"

namespace {

class GcmKat : public testing::TestWithParam<uint32_t> {};

TEST_P(GcmKat, EverySupportedOfficialEncryptAndDecryptRecord) {
  const auto registry = pq::test::participant3_registry();
  const auto aead = registry.aead("GCM", "AES-" + std::to_string(GetParam()));
  for (const auto* operation : {"gcmEncryptExtIV", "gcmDecrypt"}) {
    const std::string file = "gcm/" + std::string(operation) + std::to_string(GetParam()) + ".rsp";
    uint32_t count = 0;
    uint32_t failures = 0;
    for (const auto& record : pq::test::read_rsp(file)) {
      if (record.section.at("IVlen") != "96" || record.section.at("Taglen") != "128") continue;
      SCOPED_TRACE(file + ":" + record.fields.at("Count"));
      const auto key = pq::test::secret_fixture(record.fields.at("Key"));
      const auto iv = pq::test::from_hex(record.fields.at("IV"));
      const auto aad = pq::test::from_hex(record.fields.at("AAD"));
      auto ct = pq::test::from_hex(record.fields.at("CT"));
      const auto tag = pq::test::from_hex(record.fields.at("Tag"));
      ct.insert(ct.end(), tag.begin(), tag.end());
      const auto pt = aead->open(key, iv, aad, ct);
      if (record.fields.contains("FAIL")) {
        EXPECT_FALSE(pt);
        EXPECT_FALSE(record.fields.contains("PT"));
        ++failures;
      } else {
        const auto expected = pq::test::secret_fixture(record.fields.at("PT"));
        ASSERT_TRUE(pt);
        EXPECT_TRUE(pq::ct_equal(*pt, expected));
        EXPECT_EQ(aead->seal(key, iv, aad, expected), ct);
      }
      ++count;
    }
    EXPECT_EQ(count, 375U);
    if (std::string_view(operation) == "gcmDecrypt")
      EXPECT_GT(failures, 0U);
    else
      EXPECT_EQ(failures, 0U);
  }
}

INSTANTIATE_TEST_SUITE_P(AllKeySizes, GcmKat, testing::Values(128U, 192U, 256U));

TEST(Gcm, EveryCipherBoundariesAndTampering) {
  const auto registry = pq::test::participant3_registry();
  for (const auto& cipher : registry.list_ciphers()) {
    const auto aead = registry.aead("GCM", cipher);
    EXPECT_EQ(aead->name(), cipher + "-GCM");
    EXPECT_EQ(aead->nonce_size(), 12U);
    EXPECT_EQ(aead->tag_size(), 16U);
    pq::SecureBytes key(aead->key_size());
    pq::Bytes nonce(12);
    pq::Bytes aad(19, 0x42);
    for (const size_t length : {0U, 1U, 15U, 16U, 17U, 63U, 64U, 65U, 257U}) {
      pq::SecureBytes message(length);
      for (size_t i = 0; i < length; ++i) message[i] = static_cast<uint8_t>(i);
      ++nonce[0];
      const auto ct = aead->seal(key, nonce, aad, message);
      const auto result = aead->open(key, nonce, aad, ct);
      ASSERT_TRUE(result);
      EXPECT_TRUE(pq::ct_equal(*result, message));
      // Every bit for short messages; every byte for the larger boundary cases.
      for (size_t bit = 0; bit < ct.size() * 8; bit += (length < 18 ? 1 : 8)) {
        auto changed = ct;
        changed[bit / 8] ^= static_cast<uint8_t>(1U << (bit & 7U));
        EXPECT_FALSE(aead->open(key, nonce, aad, changed));
      }
      aad[0] ^= 1;
      EXPECT_FALSE(aead->open(key, nonce, aad, ct));
      aad[0] ^= 1;
      nonce[0] ^= 128;
      EXPECT_FALSE(aead->open(key, nonce, aad, ct));
      nonce[0] ^= 128;
      key[0] ^= 1;
      EXPECT_FALSE(aead->open(key, nonce, aad, ct));
      key[0] ^= 1;
      EXPECT_FALSE(aead->open(key, nonce, aad, pq::ByteView(ct).first(ct.size() - 1)));
      auto extended = ct;
      extended.push_back(0);
      EXPECT_FALSE(aead->open(key, nonce, aad, extended));
    }
    for (size_t length = 0; length < 16; ++length) {
      EXPECT_FALSE(aead->open(key, nonce, {}, pq::Bytes(length)));
    }
    EXPECT_THROW((void)aead->seal(key.view().first(key.size() - 1), nonce, {}, {}), pq::Error);
    EXPECT_THROW((void)aead->open(key, pq::ByteView(nonce).first(11), {}, {}), pq::Error);
  }
  EXPECT_THROW(pq::mode::Gcm(nullptr), pq::Error);
}

TEST(Gcm, PublicLengthLimitsWithoutLargeAllocations) {
  constexpr uint64_t max_aad = std::numeric_limits<uint64_t>::max() / 8;
  constexpr uint64_t max_message = (UINT64_C(1) << 36) - 32;
  EXPECT_NO_THROW(pq::mode::detail::check_gcm_lengths(max_aad, max_message));
  EXPECT_THROW(pq::mode::detail::check_gcm_lengths(max_aad + 1, 0), pq::Error);
  EXPECT_THROW(pq::mode::detail::check_gcm_lengths(0, max_message + 1), pq::Error);
}
}  // namespace
