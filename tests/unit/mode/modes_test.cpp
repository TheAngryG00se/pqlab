#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>

#include "pq/ct.hpp"
#include "support/kat_reader.hpp"
#include "support/participant3_registry.hpp"
#include "support/secret_fixture.hpp"

namespace {

std::string official_section(const std::string& section) {
  std::ifstream input(pq::test::kat_path("modes/sp800-38a.txt"));
  if (!input) throw pq::Error("cannot read official SP 800-38A text");
  const std::string text{std::istreambuf_iterator<char>(input), {}};
  const auto start = text.rfind(section + " ");
  if (start == std::string::npos) throw pq::Error("missing official mode example");
  const auto end = text.find("F.", start + section.size());
  return text.substr(start, end - start);
}

pq::SecureBytes field(const std::string& section, const std::string& label,
                      bool multiline = false) {
  std::istringstream lines(section);
  std::string hex, line;
  bool continuation = false;
  while (std::getline(lines, line)) {
    std::replace(line.begin(), line.end(), '\f', ' ');
    line = pq::test::trim(line);
    // A 256-bit key crosses a PDF page boundary in F.2.5. Ignore the
    // blank lines and short page number while waiting for its continuation.
    if (continuation &&
        (line.empty() ||
         (line.size() < 4 &&
          std::all_of(line.begin(), line.end(), [](unsigned char c) { return std::isdigit(c); }))))
      continue;
    if (line.starts_with(label + " ")) {
      hex += pq::test::trim(line.substr(label.size()));
      continuation = multiline;
    } else if (continuation && !line.empty() &&
               std::all_of(line.begin(), line.end(),
                           [](unsigned char c) { return std::isxdigit(c); })) {
      hex += line;
    } else {
      continuation = false;
    }
  }
  if (hex.empty()) throw pq::Error("missing official mode example field");
  return pq::test::secret_fixture(hex);
}

TEST(ModesKat, AllNineSp80038AEncryptionExamples) {
  const auto registry = pq::test::participant3_registry();
  for (const auto& [mode_name, section_number] :
       {std::pair{"ECB", 1}, std::pair{"CBC", 2}, std::pair{"CTR", 5}}) {
    for (uint32_t variant = 0; variant < 3; ++variant) {
      const std::string name = "AES-" + std::to_string(128 + 64 * variant);
      SCOPED_TRACE(std::string(mode_name) + ":" + name);
      const auto text = official_section("F." + std::to_string(section_number) + "." +
                                         std::to_string(1 + 2 * variant));
      auto key = field(text, "Key", true);
      auto pt = field(text, "Plaintext");
      auto expected = field(text, "Ciphertext");
      pq::SecureBytes iv;
      if (section_number == 2) iv = field(text, "IV");
      if (section_number == 5) iv = field(text, "Init. Counter");
      ASSERT_EQ(pt.size(), 64U);
      ASSERT_EQ(expected.size(), 64U);
      const auto mode = registry.cipher_mode(mode_name, name);
      ASSERT_EQ(key.size(), mode->key_size());
      ASSERT_EQ(iv.size(), mode->iv_size());
      const auto actual = mode->encrypt(key, iv, pt);
      ASSERT_GE(actual.size(), expected.size());
      EXPECT_TRUE(pq::ct_equal(pq::ByteView(actual).first(64), expected));
      if (section_number != 2)
        EXPECT_EQ(actual.size(), 64U);
      else
        EXPECT_EQ(actual.size(), 80U);  // PKCS#7 always adds a full block here.
      const auto opened = mode->decrypt(key, iv, actual);
      ASSERT_TRUE(opened);
      EXPECT_TRUE(pq::ct_equal(*opened, pt));
      if (section_number == 5) {
        for (size_t size = 0; size <= 64; ++size) {
          const auto partial = mode->encrypt(key, iv, pt.view().first(size));
          EXPECT_TRUE(pq::ct_equal(partial, expected.view().first(size)));
          const auto back = mode->decrypt(key, iv, partial);
          ASSERT_TRUE(back);
          EXPECT_TRUE(pq::ct_equal(*back, pt.view().first(size)));
        }
      }
    }
  }
}

TEST(Modes, EveryCipherBoundaryLengthsAndRekeying) {
  const auto registry = pq::test::participant3_registry();
  for (const auto& cipher : registry.list_ciphers()) {
    for (const auto& mode_name : registry.list_cipher_modes()) {
      const auto mode = registry.cipher_mode(mode_name, cipher);
      EXPECT_EQ(mode->name(), cipher + "-" + mode_name);
      pq::SecureBytes key(mode->key_size());
      pq::SecureBytes iv(mode->iv_size());
      for (const size_t size : {0U, 1U, 15U, 16U, 17U, 31U, 32U, 64U, 65U, 255U}) {
        if (mode_name == "ECB" && size % 16 != 0) continue;
        pq::SecureBytes message(size);
        for (size_t i = 0; i < size; ++i) message[i] = static_cast<uint8_t>(i);
        for (uint32_t repetition = 0; repetition < 2; ++repetition) {
          key[0] = static_cast<uint8_t>(repetition);
          const auto ct = mode->encrypt(key, iv, message);
          auto back = mode->decrypt(key, iv, ct);
          ASSERT_TRUE(back) << cipher << mode_name << size;
          EXPECT_TRUE(pq::ct_equal(*back, message));
        }
      }
      const pq::SecureBytes message(32);
      EXPECT_THROW((void)mode->encrypt(key.view().first(key.size() - 1), iv, message), pq::Error);
      const pq::SecureBytes wrong_iv(iv.size() + 1);
      EXPECT_THROW((void)mode->encrypt(key, wrong_iv, message), pq::Error);
      EXPECT_THROW((void)mode->decrypt(key, wrong_iv, message), pq::Error);
    }
  }
}

TEST(Modes, BlockLengthErrorsAndInvalidPadding) {
  const auto registry = pq::test::participant3_registry();
  const auto ecb = registry.cipher_mode("ECB", "AES-128");
  const auto cbc = registry.cipher_mode("CBC", "AES-128");
  const pq::SecureBytes key(16);
  pq::SecureBytes iv(16);
  const pq::SecureBytes odd(17);
  EXPECT_THROW((void)ecb->encrypt(key, {}, odd), pq::Error);
  EXPECT_THROW((void)ecb->decrypt(key, {}, odd), pq::Error);
  EXPECT_THROW((void)cbc->decrypt(key, iv, odd), pq::Error);
  EXPECT_THROW((void)cbc->decrypt(key, iv, {}), pq::Error);
  const auto ct = cbc->encrypt(key, iv, {});
  // The empty message is a whole padding block. Altering each IV byte
  // independently corrupts a required padding byte without changing length.
  for (size_t i = 0; i < iv.size(); ++i) {
    iv[i] ^= 1;
    EXPECT_FALSE(cbc->decrypt(key, iv, ct));
    iv[i] ^= 1;
  }
  EXPECT_THROW(pq::mode::Ecb(nullptr), pq::Error);
  EXPECT_THROW(pq::mode::Cbc(nullptr), pq::Error);
  EXPECT_THROW(pq::mode::Ctr(nullptr), pq::Error);
}

TEST(Modes, CtrRejectsWrapBeforeReturningData) {
  const auto registry = pq::test::participant3_registry();
  const auto ctr = registry.cipher_mode("CTR", "AES-128");
  const pq::SecureBytes key(16);
  pq::SecureBytes counter(16);
  std::fill(counter.begin(), counter.end(), uint8_t{255});
  const pq::SecureBytes message(33);
  EXPECT_NO_THROW((void)ctr->encrypt(key, counter, {}));
  EXPECT_NO_THROW((void)ctr->encrypt(key, counter, message.view().first(16)));
  EXPECT_THROW((void)ctr->encrypt(key, counter, message.view().first(17)), pq::Error);
  EXPECT_THROW((void)ctr->decrypt(key, counter, message.view().first(17)), pq::Error);
  counter[15] = 254;
  EXPECT_NO_THROW((void)ctr->encrypt(key, counter, message.view().first(32)));
  EXPECT_THROW((void)ctr->encrypt(key, counter, message), pq::Error);
}
}  // namespace
