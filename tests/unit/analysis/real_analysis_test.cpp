#include <gtest/gtest.h>

#include "analysis/avalanche/experiments.hpp"
#include "analysis/sbox/sbox.hpp"
#include "cipher/aes_detail.hpp"
#include "cipher/kuznyechik_detail.hpp"
#include "support/participant3_registry.hpp"

namespace {
TEST(RealCipherAnalysis, SboxStatisticsAndDirectDdtCounting) {
  // These are mathematical properties of the public substitution tables,
  // not replacement encryption KATs. Verify a DDT row by independent counting.
  const auto aes = pq::analysis::analyze_sbox(pq::cipher::detail::kAesSbox);
  const auto kuz = pq::analysis::analyze_sbox(pq::cipher::detail::kKuznyechikSbox);
  EXPECT_EQ(aes.differential_uniformity, 4);
  EXPECT_EQ(aes.nonlinearity, 112);
  EXPECT_EQ(kuz.differential_uniformity, 8);
  EXPECT_EQ(kuz.nonlinearity, 100);
  for (uint32_t difference = 0; difference < 256; ++difference) {
    uint32_t count = 0;
    for (uint32_t x = 0; x < 256; ++x) {
      count +=
          (pq::cipher::detail::kAesSbox[x] ^ pq::cipher::detail::kAesSbox[x ^ 1]) == difference;
    }
    EXPECT_EQ(aes.ddt[1][difference], count);
  }
}

TEST(RealCipherAnalysis, ModesHaveTheExpectedErrorPropagation) {
  const auto registry = pq::test::participant3_registry();
  const pq::SecureBytes seed(32);
  for (const auto& cipher : registry.list_ciphers()) {
    for (const auto& mode : registry.list_cipher_modes()) {
      pq::DeterministicRng rng(seed);
      const auto result = pq::analysis::mode_propagation(registry, mode, cipher, 64, 128, rng);
      ASSERT_TRUE(result.modified_ciphertext_accepted);
      EXPECT_EQ(result.encryption_changed_bits[0], 0U);
      EXPECT_EQ(result.decryption_changed_bits[0], 0U);
      if (mode == "CTR") {
        EXPECT_EQ(result.encryption_changed_bits, (std::vector<size_t>{0, 1, 0, 0}));
        EXPECT_EQ(result.decryption_changed_bits, (std::vector<size_t>{0, 1, 0, 0}));
      } else if (mode == "ECB") {
        EXPECT_GT(result.encryption_changed_bits[1], 0U);
        EXPECT_EQ(result.encryption_changed_bits[2], 0U);
        EXPECT_EQ(result.decryption_changed_bits[2], 0U);
      } else {
        EXPECT_GT(result.encryption_changed_bits[1], 0U);
        EXPECT_GT(result.encryption_changed_bits[2], 0U);
        EXPECT_GT(result.decryption_changed_bits[1], 0U);
        EXPECT_EQ(result.decryption_changed_bits[2], 1U);
        EXPECT_EQ(result.decryption_changed_bits[3], 0U);
      }
    }
    pq::DeterministicRng rng(seed);
    EXPECT_TRUE(pq::analysis::aead_rejects_change(registry, "GCM", cipher, 64, 128, rng));
  }
}

TEST(RealCipherAnalysis, BothFlipTargetsAndRoundSweepsRemainReproducible) {
  const auto registry = pq::test::participant3_registry();
  const pq::SecureBytes seed(32);
  for (const auto* cipher : {"AES-128", "Kuznyechik"}) {
    for (const auto target : {pq::analysis::FlipTarget::Message, pq::analysis::FlipTarget::Key}) {
      const auto rounds = pq::analysis::cipher_round_avalanche(registry, cipher, target, seed,
                                                               {.samples_per_bit = 2});
      EXPECT_EQ(rounds.size(), 10U);
      pq::DeterministicRng rng(seed);
      const auto full =
          pq::analysis::cipher_avalanche(registry, cipher, target, rng, {.samples_per_bit = 2});
      EXPECT_DOUBLE_EQ(rounds.back().mean, full.mean);
      EXPECT_EQ(rounds.back().pairs, full.pairs);
    }
  }
}
}  // namespace
