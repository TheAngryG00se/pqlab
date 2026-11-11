#include "analysis/avalanche/avalanche.hpp"

#include <gtest/gtest.h>

#include <array>
#include <limits>
#include <memory>
#include <numeric>

#include "analysis/avalanche/experiments.hpp"
#include "pq/error.hpp"
#include "support/stub_aead.hpp"
#include "support/stub_mode.hpp"

namespace pq::analysis {
namespace {

class ExhaustiveByteRng final : public Rng {
 public:
  void fill(MutByteView output) override {
    for (uint8_t& byte : output) {
      byte = next_++;
    }
  }

 private:
  uint8_t next_ = 0;
};

Bytes identity(ByteView input) { return {input.begin(), input.end()}; }

TEST(Avalanche, HammingDistanceCountsBitsAndValidatesLength) {
  const std::array<uint8_t, 3> first = {0x00, 0xAA, 0xF0};
  const std::array<uint8_t, 3> second = {0xFF, 0x55, 0xF1};
  EXPECT_EQ(hamming_distance(first, second), 17);
  EXPECT_THROW((void)hamming_distance(first, ByteView(second).first(2)), Error);
}

TEST(Avalanche, IdentityHasDiagonalSacAndUndefinedBic) {
  ExhaustiveByteRng rng;
  const auto result =
      measure_avalanche(identity, 2, 2, rng, {.samples_per_bit = 32, .compute_bic = true});
  EXPECT_EQ(result.pairs, 512);
  EXPECT_DOUBLE_EQ(result.mean, 1);
  EXPECT_DOUBLE_EQ(result.variance, 0);
  EXPECT_EQ(result.hamming_histogram[1], result.pairs);
  EXPECT_DOUBLE_EQ(result.max_sac_deviation(), 0.5);
  EXPECT_FALSE(result.bic(0, 0, 1).has_value());
  EXPECT_FALSE(result.max_absolute_bic().has_value());
  for (size_t i = 0; i < 16; ++i) {
    for (size_t j = 0; j < 16; ++j) {
      EXPECT_DOUBLE_EQ(result.sac(i, j), i == j ? 1.0 : 0.0);
    }
  }
  EXPECT_THROW((void)result.sac(16, 0), Error);
  EXPECT_THROW((void)result.bic(0, 0, 0), Error);
}

TEST(Avalanche, BicMeasuresEachInputDirectionSeparately) {
  ExhaustiveByteRng rng;
  const auto result = measure_avalanche(
      [](ByteView input) {
        const uint8_t x0 = input[0] & 1U;
        const uint8_t x1 = (input[0] >> 1) & 1U;
        const uint8_t x2 = (input[0] >> 2) & 1U;
        const uint8_t product = x0 & x1;
        return Bytes{static_cast<uint8_t>(product | (product << 1) | ((x0 & (x1 ^ 1U)) << 2) |
                                          ((x0 & x2) << 3))};
      },
      1, 1, rng, {.samples_per_bit = 256, .compute_bic = true});
  EXPECT_DOUBLE_EQ(result.sac(0, 0), 0.5);
  EXPECT_DOUBLE_EQ(result.sac(0, 2), 0.5);
  ASSERT_TRUE(result.bic(0, 0, 1).has_value());
  EXPECT_DOUBLE_EQ(*result.bic(0, 0, 1), 1);
  EXPECT_DOUBLE_EQ(*result.bic(0, 0, 2), -1);
  EXPECT_DOUBLE_EQ(*result.bic(0, 0, 3), 0);
  EXPECT_DOUBLE_EQ(*result.bic(0, 3, 0), 0);
  EXPECT_FALSE(result.bic(4, 0, 1).has_value());
  EXPECT_DOUBLE_EQ(*result.max_absolute_bic(), 1);
}

TEST(Avalanche, OutputLengthMayDifferFromInputLength) {
  ExhaustiveByteRng rng;
  const auto result =
      measure_avalanche([](ByteView input) { return Bytes{input[0], input[0], input[0]}; }, 1, 3,
                        rng, {.samples_per_bit = 2});
  EXPECT_EQ(result.input_bits, 8);
  EXPECT_EQ(result.output_bits, 24);
  EXPECT_DOUBLE_EQ(result.mean, 3);
  EXPECT_TRUE(result.bic_correlations.empty());
  EXPECT_THROW((void)result.bic(0, 0, 1), Error);
}

TEST(Avalanche, RejectsInvalidDimensionsCountsAndFunctionOutput) {
  ExhaustiveByteRng rng;
  EXPECT_THROW((void)measure_avalanche({}, 1, 1, rng), Error);
  EXPECT_THROW((void)measure_avalanche(identity, 0, 1, rng), Error);
  EXPECT_THROW((void)measure_avalanche(identity, 1, 0, rng), Error);
  EXPECT_THROW((void)measure_avalanche(identity, 1, 1, rng, {.samples_per_bit = 0}), Error);
  EXPECT_THROW((void)measure_avalanche(identity, 1, 2, rng), Error);
  EXPECT_THROW((void)measure_avalanche(identity, std::numeric_limits<size_t>::max(), 1, rng),
               Error);
  EXPECT_THROW((void)measure_avalanche(identity, 1, 1, rng,
                                       {.samples_per_bit = std::numeric_limits<uint64_t>::max()}),
               Error);
  EXPECT_THROW((void)measure_avalanche(identity, 16, 16, rng,
                                       {.samples_per_bit = 1, .max_memory_bytes = 100}),
               Error);
  EXPECT_THROW((void)measure_avalanche(
                   identity, 16, 16, rng,
                   {.samples_per_bit = 1, .compute_bic = true, .max_memory_bytes = 1024 * 1024}),
               Error);
}

TEST(Avalanche, ChiSquareMatchesExactBinomialHistogramAndPoolsTails) {
  AvalancheResult result;
  result.output_bits = 8;
  result.pairs = 256;
  // Exact binomial coefficients from Pascal's identity, not cryptographic KAT data.
  result.hamming_histogram.resize(9);
  result.hamming_histogram[0] = 1;
  for (uint64_t k = 1; k <= 8; ++k) {
    result.hamming_histogram[k] = result.hamming_histogram[k - 1] * (9 - k) / k;
  }
  const auto score = binomial_chi_square(result);
  EXPECT_NEAR(score.statistic, 0, 1e-20);
  EXPECT_EQ(score.bins, 7);
  EXPECT_EQ(score.degrees_of_freedom, 6);
  result.hamming_histogram[0] += 2;
  EXPECT_THROW((void)binomial_chi_square(result), Error);
}

Registry test_registry() {
  Registry registry;
  registry.add_cipher("XOR", [] { return std::make_unique<test::XorCipher>("XOR", 16); });
  registry.add_cipher_mode("ECB", [](std::unique_ptr<BlockCipher> cipher) {
    return std::make_unique<test::StubEcb>(std::move(cipher));
  });
  registry.add_aead_mode("GCM", [](std::unique_ptr<BlockCipher> cipher) {
    return std::make_unique<test::StubGcm>(std::move(cipher));
  });
  return registry;
}

TEST(AvalancheExperiments, RegistryBasedDriversAreReproducibleAndCoverBothTargets) {
  const auto registry = test_registry();
  const SecureBytes seed(32);
  DeterministicRng first_rng(seed);
  DeterministicRng second_rng(seed);
  const auto first =
      cipher_avalanche(registry, "XOR", FlipTarget::Message, first_rng, {.samples_per_bit = 2});
  const auto second =
      cipher_avalanche(registry, "XOR", FlipTarget::Key, second_rng, {.samples_per_bit = 2});
  EXPECT_EQ(first.flip_counts, second.flip_counts);
  EXPECT_DOUBLE_EQ(first.mean, 1);
  const auto rounds =
      cipher_round_avalanche(registry, "XOR", FlipTarget::Message, seed, {.samples_per_bit = 2});
  ASSERT_EQ(rounds.size(), 1);
  EXPECT_EQ(rounds[0].rounds, 1);
  EXPECT_DOUBLE_EQ(rounds[0].mean, 1);
  EXPECT_THROW((void)cipher_avalanche(registry, "XOR", FlipTarget::Message, first_rng, {}, -1),
               Error);
  EXPECT_THROW((void)cipher_avalanche(registry, "XOR", FlipTarget::Message, first_rng, {}, 2),
               Error);
}

TEST(AvalancheExperiments, ModeDriversRetainFixedIvAndReleaseOnlyStatistics) {
  const auto registry = test_registry();
  ExhaustiveByteRng rng;
  const auto result = mode_avalanche(registry, "ECB", "XOR", 32, rng, {.samples_per_bit = 1});
  EXPECT_DOUBLE_EQ(result.mean, 1);
  const auto propagation = mode_propagation(registry, "ECB", "XOR", 32, 3, rng);
  EXPECT_EQ(propagation.encryption_changed_bits, (std::vector<size_t>{1, 0}));
  EXPECT_EQ(propagation.decryption_changed_bits, (std::vector<size_t>{1, 0}));
  EXPECT_TRUE(propagation.modified_ciphertext_accepted);
  EXPECT_TRUE(aead_rejects_change(registry, "GCM", "XOR", 32, 4, rng));
  EXPECT_TRUE(aead_rejects_change(registry, "GCM", "XOR", 32, 32 * 8, rng));
  EXPECT_THROW((void)mode_propagation(registry, "ECB", "XOR", 32, 32 * 8, rng), Error);
}

}  // namespace
}  // namespace pq::analysis
