#include "cipher/kuznyechik.hpp"

#include <gtest/gtest.h>

#include <cctype>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "cipher/kuznyechik_detail.hpp"
#include "pq/ct.hpp"
#include "pq/error.hpp"
#include "pq/secure_bytes.hpp"
#include "support/kat_reader.hpp"

namespace {

using namespace pq::cipher::detail;

// Parse the unmodified official document, not a generated set of answers.
std::string rfc_section(std::string_view title, std::string_view next_title) {
  std::ifstream input(pq::test::kat_path("kuznyechik/rfc7801.txt"));
  if (!input) {
    throw std::runtime_error("cannot open RFC 7801");
  }
  const std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  const auto start = text.rfind(title);
  const auto end = text.find(next_title, start);
  if (start == std::string::npos || end == std::string::npos) {
    throw std::runtime_error("cannot find RFC 7801 section");
  }
  return text.substr(start, end - start);
}

pq::SecureBytes hex_secret(std::string_view hex) {
  pq::SecureBytes out(hex.size() / 2);
  const auto nibble = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    throw std::runtime_error("invalid hex in RFC 7801");
  };
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4U) | nibble(hex[2 * i + 1]));
  }
  return out;
}

KuznyechikState state_view(pq::SecureBytes& value) { return KuznyechikState(value.data(), 16); }

using Transform = void (*)(KuznyechikState) noexcept;

std::vector<std::string> hex_blocks(std::string_view text) {
  std::vector<std::string> result;
  size_t pos = 0;
  while (pos < text.size()) {
    const size_t start = pos;
    while (pos < text.size() && std::isxdigit(static_cast<unsigned char>(text[pos]))) ++pos;
    if (pos - start == 32) result.emplace_back(text.substr(start, 32));
    if (pos == start) ++pos;
  }
  return result;
}

pq::SecureBytes value_after(std::string_view text, std::string_view label, size_t bytes) {
  size_t pos = text.find(label);
  if (pos == std::string_view::npos) throw std::runtime_error("missing RFC value label");
  pos += label.size();
  std::string hex;
  while (pos < text.size() && hex.size() < bytes * 2) {
    const auto ch = static_cast<unsigned char>(text[pos++]);
    if (std::isspace(ch)) continue;
    if (!std::isxdigit(ch)) throw std::runtime_error("invalid RFC value text");
    hex += static_cast<char>(ch);
  }
  if (hex.size() != bytes * 2) throw std::runtime_error("short RFC value");
  return hex_secret(hex);
}

void check_transform_vectors(std::string_view title, std::string_view next_title, Transform forward,
                             Transform inverse) {
  const auto values = hex_blocks(rfc_section(title, next_title));
  ASSERT_EQ(values.size(), 8U);
  for (size_t i = 0; i < values.size(); i += 2) {
    auto source = hex_secret(values[i]);
    auto expected = hex_secret(values[i + 1]);
    auto actual = source.clone();
    forward(state_view(actual));
    EXPECT_TRUE(pq::ct_equal(actual, expected));
    inverse(state_view(actual));
    EXPECT_TRUE(pq::ct_equal(actual, source));
  }
}

TEST(KuznyechikTransforms, OfficialSubstitutionExamples) {
  check_transform_vectors("5.1.  Transformation S", "5.2.  Transformation R", kuznyechik_s,
                          kuznyechik_inverse_s);
}

TEST(KuznyechikTransforms, OfficialRExamples) {
  check_transform_vectors("5.2.  Transformation R", "5.3.  Transformation L", kuznyechik_r,
                          kuznyechik_inverse_r);
}

TEST(KuznyechikTransforms, OfficialLExamples) {
  check_transform_vectors("5.3.  Transformation L", "5.4.  Key Schedule", kuznyechik_l,
                          kuznyechik_inverse_l);
}

TEST(KuznyechikTransforms, SubstitutionInverseExhaustive) {
  for (uint32_t i = 0; i < 256; ++i) {
    EXPECT_EQ(kKuznyechikInverseSbox[kKuznyechikSbox[i]], i);
    EXPECT_EQ(kKuznyechikSbox[kKuznyechikInverseSbox[i]], i);
  }
}

TEST(KuznyechikTransforms, LinearInverseAllBasisVectors) {
  for (uint32_t bit = 0; bit < 128; ++bit) {
    pq::SecureBytes input(16);
    input[bit / 8] = static_cast<uint8_t>(1U << (bit % 8));
    auto actual = input.clone();
    kuznyechik_l(state_view(actual));
    kuznyechik_inverse_l(state_view(actual));
    EXPECT_TRUE(pq::ct_equal(actual, input));
    kuznyechik_r(state_view(actual));
    kuznyechik_inverse_r(state_view(actual));
    EXPECT_TRUE(pq::ct_equal(actual, input));
  }
}

TEST(KuznyechikTransforms, FieldProductsMatchPolynomialDivision) {
  // Independent carry-less polynomial product and long division. Operands
  // are public exhaustive test indices, so branches here do not leak secrets.
  for (uint32_t a = 0; a < 256; ++a) {
    for (uint32_t b = 0; b < 256; ++b) {
      uint32_t product = 0;
      for (uint32_t bit = 0; bit < 8; ++bit) {
        if (((b >> bit) & 1U) != 0) product ^= a << bit;
      }
      for (uint32_t bit = 15; bit >= 8; --bit) {
        if (((product >> bit) & 1U) != 0) product ^= 0x1C3U << (bit - 8);
      }
      EXPECT_EQ(kuznyechik_multiply(static_cast<uint8_t>(a), static_cast<uint8_t>(b)), product);
    }
  }
}

pq::SecureBytes official_key() {
  return value_after(rfc_section("5.4.  Key Schedule", "5.5.  Test Encryption"), "K = ", 32);
}

TEST(KuznyechikKeySchedule, OfficialFirstEightConstantsAndFeistelSteps) {
  const auto text = rfc_section("5.4.  Key Schedule", "5.5.  Test Encryption");
  auto key = official_key();
  pq::SecureBytes left(key.view().first(16));
  pq::SecureBytes right(key.view().subspan(16));
  for (uint32_t count = 1; count <= 8; ++count) {
    const auto label = "C_" + std::to_string(count) + " = ";
    const auto start = text.find(label);
    ASSERT_NE(start, std::string::npos);
    const auto end = text.find("C_" + std::to_string(count + 1) + " = ", start + label.size());
    const auto section = text.substr(start, end - start);
    pq::SecureBytes constant(16);
    constant[15] = static_cast<uint8_t>(count);
    kuznyechik_l(state_view(constant));
    EXPECT_TRUE(pq::ct_equal(constant, value_after(section, label, 16)));
    // Result pairs are the only parenthesized 32-hex-byte strings in this section.
    size_t pair = section.find('(');
    while (pair != std::string::npos &&
           (pair + 33 >= section.size() || section[pair + 33] != ',')) {
      pair = section.find('(', pair + 1);
    }
    ASSERT_NE(pair, std::string::npos);
    const auto values = hex_blocks(section.substr(pair, section.find(')', pair) - pair));
    ASSERT_EQ(values.size(), 2U);
    kuznyechik_f(state_view(left), state_view(right), state_view(constant));
    EXPECT_TRUE(pq::ct_equal(left, hex_secret(values[0])));
    EXPECT_TRUE(pq::ct_equal(right, hex_secret(values[1])));
  }
}

TEST(KuznyechikKeySchedule, OfficialTenRoundKeys) {
  const auto text = rfc_section("5.4.  Key Schedule", "5.5.  Test Encryption");
  auto key = official_key();
  pq::SecureBytes keys(160);
  kuznyechik_expand_key(std::span<const uint8_t, 32>(key.data(), 32),
                        std::span<uint8_t, 160>(keys.data(), 160));
  for (uint32_t index = 1; index <= 10; ++index) {
    const auto label = "K_" + std::to_string(index) + " = ";
    const auto position = text.rfind(label);
    ASSERT_NE(position, std::string::npos);
    EXPECT_TRUE(pq::ct_equal(keys.view().subspan((index - 1) * 16, 16),
                             value_after(text.substr(position), label, 16)));
  }
}

pq::SecureBytes official_input(bool ciphertext) {
  if (ciphertext) {
    return value_after(rfc_section("5.6.  Test Decryption", "6.  Security Considerations"),
                       "b = ", 16);
  }
  return value_after(rfc_section("5.5.  Test Encryption", "5.6.  Test Decryption"), "a = ", 16);
}

TEST(Kuznyechik, OfficialEncryptionAndDecryption) {
  pq::cipher::Kuznyechik cipher;
  cipher.set_key(official_key());
  auto plaintext = official_input(false);
  auto ciphertext = official_input(true);
  pq::SecureBytes out(16);
  cipher.encrypt_block(plaintext.data(), out.data());
  EXPECT_TRUE(pq::ct_equal(out, ciphertext));
  cipher.decrypt_block(ciphertext.data(), out.data());
  EXPECT_TRUE(pq::ct_equal(out, plaintext));
  EXPECT_EQ(cipher.name(), "Kuznyechik");
  EXPECT_EQ(cipher.block_size(), 16U);
  EXPECT_EQ(cipher.key_size(), 32U);
  EXPECT_EQ(cipher.rounds(), 10);
}

TEST(Kuznyechik, OfficialEncryptionIntermediateValues) {
  const std::string text = rfc_section("5.5.  Test Encryption", "5.6.  Test Decryption");
  auto key = official_key();
  pq::SecureBytes keys(160);
  kuznyechik_expand_key(std::span<const uint8_t, 32>(key.data(), 32),
                        std::span<uint8_t, 160>(keys.data(), 160));
  auto state = official_input(false);
  std::istringstream lines(text);
  std::string line;
  uint32_t round = 0;
  while (std::getline(lines, line)) {
    if (!line.starts_with("   LSX")) continue;
    ASSERT_LT(round, 9U);
    const auto expected = value_after(line, " = ", 16);
    kuznyechik_x(state_view(state), KuznyechikConstState(keys.data() + 16 * round, 16));
    kuznyechik_s(state_view(state));
    kuznyechik_l(state_view(state));
    EXPECT_TRUE(pq::ct_equal(state, expected));
    ++round;
  }
  EXPECT_EQ(round, 9U);
}

TEST(Kuznyechik, OfficialDecryptionIntermediateValues) {
  const std::string text = rfc_section("5.6.  Test Decryption", "6.  Security Considerations");
  auto key = official_key();
  pq::SecureBytes keys(160);
  kuznyechik_expand_key(std::span<const uint8_t, 32>(key.data(), 32),
                        std::span<uint8_t, 160>(keys.data(), 160));
  const auto values = hex_blocks(text);
  size_t index = 0;
  auto next = [&]() {
    if (index == values.size()) throw std::runtime_error("missing decryption example");
    return hex_secret(values[index++]);
  };
  auto state = next();
  kuznyechik_x(state_view(state), KuznyechikConstState(keys.data() + 144, 16));
  EXPECT_TRUE(pq::ct_equal(state, next()));
  kuznyechik_inverse_l(state_view(state));
  EXPECT_TRUE(pq::ct_equal(state, next()));
  kuznyechik_inverse_s(state_view(state));
  EXPECT_TRUE(pq::ct_equal(state, next()));
  for (uint32_t round = 8; round > 0; --round) {
    kuznyechik_x(state_view(state), KuznyechikConstState(keys.data() + 16 * round, 16));
    kuznyechik_inverse_l(state_view(state));
    kuznyechik_inverse_s(state_view(state));
    EXPECT_TRUE(pq::ct_equal(state, next()));
  }
  kuznyechik_x(state_view(state), KuznyechikConstState(keys.data(), 16));
  EXPECT_TRUE(pq::ct_equal(state, next()));
  EXPECT_EQ(index, values.size());
}

TEST(Kuznyechik, SupportsInPlaceAndPartiallyOverlappingBlocks) {
  pq::cipher::Kuznyechik cipher;
  cipher.set_key(official_key());
  auto plaintext = official_input(false);
  auto ciphertext = official_input(true);
  auto in_place = plaintext.clone();
  cipher.encrypt_block(in_place.data(), in_place.data());
  EXPECT_TRUE(pq::ct_equal(in_place, ciphertext));
  cipher.decrypt_block(in_place.data(), in_place.data());
  EXPECT_TRUE(pq::ct_equal(in_place, plaintext));
  pq::SecureBytes buffer(32);
  for (uint32_t i = 0; i < 16; ++i) buffer[i] = plaintext[i];
  cipher.encrypt_block(buffer.data(), buffer.data() + 1);
  EXPECT_TRUE(pq::ct_equal(buffer.view().subspan(1, 16), ciphertext));
  cipher.decrypt_block(buffer.data() + 1, buffer.data());
  EXPECT_TRUE(pq::ct_equal(buffer.view().first(16), plaintext));
}

TEST(Kuznyechik, RekeyMatchesFreshInstanceAndInvalidRekeyPreservesKey) {
  pq::cipher::Kuznyechik reused;
  pq::cipher::Kuznyechik fresh;
  auto key = official_key();
  auto plaintext = official_input(false);
  reused.set_key(key);
  key[0] ^= 1;
  reused.set_key(key);
  fresh.set_key(key);
  pq::SecureBytes expected(16);
  pq::SecureBytes actual(16);
  fresh.encrypt_block(plaintext.data(), expected.data());
  reused.encrypt_block(plaintext.data(), actual.data());
  EXPECT_TRUE(pq::ct_equal(actual, expected));
  EXPECT_THROW(reused.set_key(key.view().first(31)), pq::Error);
  reused.encrypt_block(plaintext.data(), actual.data());
  EXPECT_TRUE(pq::ct_equal(actual, expected));
}

TEST(Kuznyechik, RejectsInvalidKeyRoundCountAndNullPointers) {
  pq::cipher::Kuznyechik cipher;
  pq::SecureBytes block(16);
  EXPECT_THROW(cipher.encrypt_block(block.data(), block.data()), pq::Error);
  EXPECT_THROW(cipher.decrypt_block(block.data(), block.data()), pq::Error);
  for (uint32_t length : {0U, 16U, 24U, 31U, 33U, 64U}) {
    EXPECT_THROW(cipher.set_key(pq::SecureBytes(length)), pq::Error);
  }
  EXPECT_THROW(cipher.set_rounds(0), pq::Error);
  EXPECT_THROW(cipher.set_rounds(-1), pq::Error);
  EXPECT_THROW(cipher.set_rounds(11), pq::Error);
  EXPECT_EQ(cipher.rounds(), 10);
  cipher.set_rounds(10);
  cipher.set_key(official_key());
  EXPECT_THROW(cipher.encrypt_block(nullptr, block.data()), pq::Error);
  EXPECT_THROW(cipher.encrypt_block(block.data(), nullptr), pq::Error);
  EXPECT_THROW(cipher.decrypt_block(nullptr, block.data()), pq::Error);
  EXPECT_THROW(cipher.decrypt_block(block.data(), nullptr), pq::Error);
}

}  // namespace
