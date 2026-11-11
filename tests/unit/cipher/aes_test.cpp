#include "cipher/aes.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "cipher/aes_detail.hpp"
#include "pq/ct.hpp"
#include "pq/error.hpp"
#include "pq/secure_bytes.hpp"
#include "support/kat_reader.hpp"

namespace {

using pq::cipher::Aes;
namespace detail = pq::cipher::detail;

// Hex strings are public, published fixtures; decoded key material is kept in
// SecureBytes so test execution follows the same storage rules as production.
pq::SecureBytes fixture_hex(std::string_view hex) {
  if ((hex.size() & 1U) != 0) {
    throw pq::Error("odd fixture length");
  }
  const auto nibble = [](char ch) -> uint8_t {
    if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
    if (ch >= 'a' && ch <= 'f') return static_cast<uint8_t>(ch - 'a' + 10);
    if (ch >= 'A' && ch <= 'F') return static_cast<uint8_t>(ch - 'A' + 10);
    throw pq::Error("invalid fixture hex");
  };
  pq::SecureBytes bytes(hex.size() / 2);
  for (size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
  }
  return bytes;
}

TEST(AesArithmetic, FieldMultiplicationMatchesPolynomialDefinitionExhaustively) {
  // Independent schoolbook polynomial product/reduction, on public test inputs.
  for (uint32_t lhs = 0; lhs < 256; ++lhs) {
    for (uint32_t rhs = 0; rhs < 256; ++rhs) {
      uint32_t product = 0;
      for (uint32_t bit = 0; bit < 8; ++bit) {
        if (((rhs >> bit) & 1U) != 0) product ^= lhs << bit;
      }
      for (uint32_t bit = 14; bit >= 8; --bit) {
        if (((product >> bit) & 1U) != 0) product ^= 0x11bU << (bit - 8);
      }
      EXPECT_EQ(detail::aes_gf_multiply(static_cast<uint8_t>(lhs), static_cast<uint8_t>(rhs)),
                static_cast<uint8_t>(product));
    }
  }
  // FIPS 197-upd1, Eqs. (4.6) and (4.7).
  EXPECT_EQ(detail::aes_xtime(0x57), 0xae);
  EXPECT_EQ(detail::aes_xtime(0xae), 0x47);
  EXPECT_EQ(detail::aes_gf_multiply(0x57, 0x13), 0xfe);
}

TEST(AesArithmetic, SboxMatchesFieldInverseAndAffineDefinitionForEveryByte) {
  for (uint32_t value = 0; value < 256; ++value) {
    uint8_t inverse = 0;
    for (uint32_t candidate = 1; candidate < 256; ++candidate) {
      if (detail::aes_gf_multiply(static_cast<uint8_t>(value), static_cast<uint8_t>(candidate)) ==
          1) {
        inverse = static_cast<uint8_t>(candidate);
      }
    }
    uint8_t expected = 0x63;
    for (uint32_t bit = 0; bit < 8; ++bit) {
      uint32_t output_bit = (inverse >> bit) & 1U;
      for (uint32_t offset = 4; offset <= 7; ++offset) {
        output_bit ^= (inverse >> ((bit + offset) & 7U)) & 1U;
      }
      expected ^= static_cast<uint8_t>(output_bit << bit);
    }
    EXPECT_EQ(detail::kAesSbox[value], expected);
    EXPECT_EQ(detail::kAesInvSbox[detail::kAesSbox[value]], value);
  }
}

TEST(AesTransforms, Fips197AppendixBFirstRound) {
  const auto input = fixture_hex("3243f6a8885a308d313198a2e0370734");
  const auto key = fixture_hex("2b7e151628aed2a6abf7158809cf4f3c");
  detail::AesBlock state{};
  std::copy(input.begin(), input.end(), state.begin());
  detail::aes_add_round_key(state, std::span<const uint8_t, 16>(key.data(), 16));
  EXPECT_TRUE(pq::ct_equal(state, fixture_hex("193de3bea0f4e22b9ac68d2ae9f84808")));
  detail::aes_sub_bytes(state);
  EXPECT_TRUE(pq::ct_equal(state, fixture_hex("d42711aee0bf98f1b8b45de51e415230")));
  detail::aes_shift_rows(state);
  EXPECT_TRUE(pq::ct_equal(state, fixture_hex("d4bf5d30e0b452aeb84111f11e2798e5")));
  detail::aes_mix_columns(state);
  EXPECT_TRUE(pq::ct_equal(state, fixture_hex("046681e5e0cb199a48f8d37a2806264c")));
  detail::aes_inv_mix_columns(state);
  detail::aes_inv_shift_rows(state);
  detail::aes_inv_sub_bytes(state);
  detail::aes_add_round_key(state, std::span<const uint8_t, 16>(key.data(), 16));
  EXPECT_TRUE(pq::ct_equal(state, input));
  pq::secure_zero(state);
}

TEST(AesTransforms, LinearTransformsInvertAllBasisVectors) {
  detail::AesBlock state{};
  detail::AesBlock original{};
  for (size_t bit = 0; bit < 128; ++bit) {
    original.fill(0);
    original[bit / 8] = static_cast<uint8_t>(1U << (bit & 7U));
    state = original;
    detail::aes_shift_rows(state);
    detail::aes_inv_shift_rows(state);
    EXPECT_TRUE(pq::ct_equal(state, original));
    detail::aes_mix_columns(state);
    detail::aes_inv_mix_columns(state);
    EXPECT_TRUE(pq::ct_equal(state, original));
  }
  pq::secure_zero(state);
  pq::secure_zero(original);
}

TEST(AesKeySchedule, Fips197AppendixAAllKeySizes) {
  constexpr std::array<std::string_view, 3> keys = {
      "2b7e151628aed2a6abf7158809cf4f3c", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"};
  constexpr std::array<std::string_view, 3> first_new_words = {"a0fafe1788542cb123a339392a6c7605",
                                                               "fe0c91f72402f5a5ec12068e6c827f6b",
                                                               "9ba354118e6925afa51a8b5f2067fcde"};
  constexpr std::array<std::string_view, 3> last_round_keys = {"d014f9a8c9ee2589e13f0cc8b6630ca6",
                                                               "e98ba06f448c773c8ecc720401002202",
                                                               "fe4890d1e6188d0b046df344706c631e"};
  for (size_t variant = 0; variant < keys.size(); ++variant) {
    auto key = fixture_hex(keys[variant]);
    pq::SecureBytes expanded(176 + 32 * variant);
    detail::aes_key_expansion(key, expanded.span());
    EXPECT_TRUE(pq::ct_equal(expanded.view().first(key.size()), key));
    EXPECT_TRUE(pq::ct_equal(expanded.view().subspan(key.size(), 16),
                             fixture_hex(first_new_words[variant])));
    EXPECT_TRUE(pq::ct_equal(expanded.view().last(16), fixture_hex(last_round_keys[variant])));
  }
}

TEST(AesKeySchedule, RejectsInvalidInputAndOutputLengthsBeforeWriting) {
  pq::SecureBytes short_key(15);
  pq::SecureBytes key(16);
  pq::SecureBytes expanded(176);
  expanded[0] = 0x5a;
  auto before = expanded.clone();
  EXPECT_THROW(detail::aes_key_expansion(short_key, expanded.span()), pq::Error);
  EXPECT_TRUE(pq::ct_equal(before, expanded));
  EXPECT_THROW(detail::aes_key_expansion(key, expanded.span().first(175)), pq::Error);
  EXPECT_TRUE(pq::ct_equal(before, expanded));
}

class AesKat : public testing::TestWithParam<uint32_t> {};

TEST_P(AesKat, EveryOfficialCavpEcbRecordEncryptsAndDecryptsInPlaceAndSeparately) {
  Aes cipher(GetParam());
  const std::array<std::string, 4> categories = {"GFSbox", "KeySbox", "VarKey", "VarTxt"};
  for (const auto& category : categories) {
    const std::string file = "aes/ECB" + category + std::to_string(GetParam()) + ".rsp";
    SCOPED_TRACE(file);
    const auto records = pq::test::read_rsp(file);
    ASSERT_FALSE(records.empty());
    for (const auto& record : records) {
      SCOPED_TRACE(record.fields.at("COUNT"));
      auto key = fixture_hex(record.fields.at("KEY"));
      const auto plaintext = fixture_hex(record.fields.at("PLAINTEXT"));
      const auto expected = fixture_hex(record.fields.at("CIPHERTEXT"));
      ASSERT_EQ(plaintext.size(), cipher.block_size());
      ASSERT_EQ(expected.size(), cipher.block_size());
      cipher.set_key(key);
      pq::SecureBytes output(16);
      cipher.encrypt_block(plaintext.data(), output.data());
      EXPECT_TRUE(pq::ct_equal(output, expected));
      cipher.decrypt_block(expected.data(), output.data());
      EXPECT_TRUE(pq::ct_equal(output, plaintext));
      auto in_place = plaintext.clone();
      cipher.encrypt_block(in_place.data(), in_place.data());
      EXPECT_TRUE(pq::ct_equal(in_place, expected));
      cipher.decrypt_block(in_place.data(), in_place.data());
      EXPECT_TRUE(pq::ct_equal(in_place, plaintext));
    }
  }
}

TEST_P(AesKat, PartialOverlapAndRekeyMatchOfficialRecords) {
  const auto records = pq::test::read_rsp("aes/ECBVarKey" + std::to_string(GetParam()) + ".rsp");
  ASSERT_GE(records.size(), 2U);
  Aes cipher(GetParam());
  for (size_t index : {size_t{0}, size_t{1}, size_t{0}}) {
    const auto& record = records[index];
    const auto key = fixture_hex(record.fields.at("KEY"));
    const auto plaintext = fixture_hex(record.fields.at("PLAINTEXT"));
    const auto expected = fixture_hex(record.fields.at("CIPHERTEXT"));
    cipher.set_key(key);
    pq::SecureBytes overlap(17);
    std::copy(plaintext.begin(), plaintext.end(), overlap.begin());
    cipher.encrypt_block(overlap.data(), overlap.data() + 1);
    EXPECT_TRUE(pq::ct_equal(overlap.view().subspan(1), expected));
    cipher.decrypt_block(overlap.data() + 1, overlap.data());
    EXPECT_TRUE(pq::ct_equal(overlap.view().first(16), plaintext));
    pq::SecureBytes invalid_key(key.size() - 1);
    EXPECT_THROW(cipher.set_key(invalid_key), pq::Error);
    cipher.encrypt_block(plaintext.data(), overlap.data());
    EXPECT_TRUE(pq::ct_equal(overlap.view().first(16), expected));
  }
}

TEST_P(AesKat, MetadataAndMisuseChecks) {
  Aes cipher(GetParam());
  EXPECT_EQ(cipher.name(), "AES-" + std::to_string(GetParam()));
  EXPECT_EQ(cipher.block_size(), 16U);
  EXPECT_EQ(cipher.key_size(), GetParam() / 8);
  EXPECT_EQ(cipher.rounds(), static_cast<int32_t>(GetParam() / 32 + 6));
  pq::SecureBytes key(cipher.key_size());
  pq::SecureBytes block(16);
  EXPECT_THROW(cipher.encrypt_block(block.data(), block.data()), pq::Error);
  EXPECT_THROW(cipher.decrypt_block(block.data(), block.data()), pq::Error);
  cipher.set_key(key);
  EXPECT_THROW(cipher.encrypt_block(nullptr, block.data()), pq::Error);
  EXPECT_THROW(cipher.encrypt_block(block.data(), nullptr), pq::Error);
  EXPECT_THROW(cipher.decrypt_block(nullptr, block.data()), pq::Error);
  EXPECT_THROW(cipher.decrypt_block(block.data(), nullptr), pq::Error);
  const int32_t rounds = cipher.rounds();
  EXPECT_THROW(cipher.set_rounds(0), pq::Error);
  EXPECT_THROW(cipher.set_rounds(-1), pq::Error);
  EXPECT_THROW(cipher.set_rounds(rounds + 1), pq::Error);
  EXPECT_EQ(cipher.rounds(), rounds);
  EXPECT_NO_THROW(cipher.set_rounds(rounds));
}

INSTANTIATE_TEST_SUITE_P(AllKeySizes, AesKat, testing::Values(128U, 192U, 256U));

TEST(AesApi, RejectsUnsupportedKeyVariants) {
  EXPECT_THROW(Aes(0), pq::Error);
  EXPECT_THROW(Aes(129), pq::Error);
  EXPECT_THROW(Aes(std::numeric_limits<uint32_t>::max()), pq::Error);
}

}  // namespace
