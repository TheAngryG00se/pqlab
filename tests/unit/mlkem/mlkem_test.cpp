// Properties of ML-KEM beyond the official vectors.

#include "kem/mlkem/mlkem.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "hash/shake.hpp"
#include "pq/ct.hpp"
#include "pq/error.hpp"
#include "pq/rng.hpp"

namespace {

// Deterministic byte stream for tests: SHAKE128 of a fixed label.
class TestRng final : public pq::Rng {
 public:
  explicit TestRng(uint8_t label) {
    const std::array<uint8_t, 1> l{label};
    xof_.absorb(l);
  }
  void fill(std::span<uint8_t> out) override { xof_.squeeze(out); }

 private:
  pq::hash::Shake128 xof_;
};

template <typename T>
class MlKemTest : public ::testing::Test {};

using Kems = ::testing::Types<pq::mlkem::MlKem512, pq::mlkem::MlKem768, pq::mlkem::MlKem1024>;
TYPED_TEST_SUITE(MlKemTest, Kems);

TYPED_TEST(MlKemTest, SizesMatchFips203Table3) {
  const TypeParam kem;
  const pq::KemSizes s = kem.sizes();
  const size_t k = TypeParam::Params::kK;
  EXPECT_EQ(s.pk, 384 * k + 32);
  EXPECT_EQ(s.sk, 768 * k + 96);
  EXPECT_EQ(s.ss, 32U);
  EXPECT_EQ(s.keygen_seed, 64U);
  EXPECT_EQ(s.encaps_seed, 32U);
}

// AGENTS.md, section 9: Decaps(Encaps) = K on 10^4 cases per parameter set.
TYPED_TEST(MlKemTest, DecapsRecoversSharedSecret) {
  const TypeParam kem;
  TestRng rng(1);
  constexpr int kKeys = 100;
  constexpr int kEncapsPerKey = 100;
  for (int i = 0; i < kKeys; ++i) {
    const pq::KeyPair kp = kem.keygen(rng);
    ASSERT_EQ(kp.pk.size(), kem.sizes().pk);
    ASSERT_EQ(kp.sk.size(), kem.sizes().sk);
    for (int e = 0; e < kEncapsPerKey; ++e) {
      const pq::Encapsulation enc = kem.encaps(kp.pk, rng);
      ASSERT_EQ(enc.ct.size(), kem.sizes().ct);
      const pq::SecureBytes k = kem.decaps(kp.sk, enc.ct);
      ASSERT_TRUE(pq::ct_equal(k, enc.ss)) << "key " << i << " encaps " << e;
    }
  }
}

TYPED_TEST(MlKemTest, ModifiedCiphertextGivesImplicitRejectionKey) {
  const TypeParam kem;
  TestRng rng(2);
  const pq::KeyPair kp = kem.keygen(rng);
  const pq::Encapsulation enc = kem.encaps(kp.pk, rng);
  const pq::ByteView z = kp.sk.view().last(32);
  for (size_t pos : {size_t{0}, enc.ct.size() / 2, enc.ct.size() - 1}) {
    std::vector<uint8_t> bad = enc.ct;
    bad[pos] ^= 0x01;
    const pq::SecureBytes k = kem.decaps(kp.sk, bad);
    EXPECT_FALSE(pq::ct_equal(k, enc.ss));
    // FIPS 203, Algorithm 18, step 7: K_bar = J(z || c).
    pq::hash::Shake256 j;
    j.absorb(z);
    j.absorb(bad);
    std::array<uint8_t, 32> k_bar{};
    j.squeeze(k_bar);
    EXPECT_TRUE(pq::ct_equal(k, k_bar)) << "pos " << pos;
  }
}

TYPED_TEST(MlKemTest, DeterministicApiMatchesRngWrappers) {
  const TypeParam kem;
  TestRng rng_a(3);
  TestRng rng_b(3);
  const pq::KeyPair kp = kem.keygen(rng_a);
  std::array<uint8_t, 64> seed{};
  rng_b.fill(seed);
  const pq::KeyPair kp2 = kem.keygen_derand(seed);
  EXPECT_EQ(kp.pk, kp2.pk);
  EXPECT_TRUE(pq::ct_equal(kp.sk, kp2.sk));

  const pq::Encapsulation e1 = kem.encaps(kp.pk, rng_a);
  std::array<uint8_t, 32> m{};
  rng_b.fill(m);
  const pq::Encapsulation e2 = kem.encaps_derand(kp.pk, m);
  EXPECT_EQ(e1.ct, e2.ct);
  EXPECT_TRUE(pq::ct_equal(e1.ss, e2.ss));
}

TYPED_TEST(MlKemTest, WrongLengthsThrow) {
  const TypeParam kem;
  TestRng rng(4);
  const pq::KeyPair kp = kem.keygen(rng);
  const pq::Encapsulation enc = kem.encaps(kp.pk, rng);

  EXPECT_THROW((void)kem.keygen_derand(std::vector<uint8_t>(63)), pq::Error);
  EXPECT_THROW((void)kem.encaps_derand(kp.pk, std::vector<uint8_t>(31)), pq::Error);
  std::vector<uint8_t> pk_short(kp.pk.begin(), kp.pk.end() - 1);
  EXPECT_THROW((void)kem.encaps_derand(pk_short, std::vector<uint8_t>(32)), pq::Error);
  std::vector<uint8_t> ct_long = enc.ct;
  ct_long.push_back(0);
  EXPECT_THROW((void)kem.decaps(kp.sk, ct_long), pq::Error);
  EXPECT_THROW((void)kem.decaps(kp.sk.view().first(kp.sk.size() - 1), enc.ct), pq::Error);
}

TYPED_TEST(MlKemTest, CorruptedKeysAreRejected) {
  const TypeParam kem;
  TestRng rng(5);
  const pq::KeyPair kp = kem.keygen(rng);

  // ek coefficient >= q fails the modulus check (FIPS 203, Section 7.2).
  std::vector<uint8_t> ek = kp.pk;
  ek[0] = 0xFF;
  ek[1] |= 0x0F;  // first 12-bit value = 4095
  EXPECT_FALSE(TypeParam::check_encaps_key(ek));
  EXPECT_THROW((void)kem.encaps_derand(ek, std::vector<uint8_t>(32)), pq::Error);

  // Changing the embedded ek in dk fails the hash check (Section 7.3).
  pq::SecureBytes dk = kp.sk.clone();
  dk[384 * TypeParam::Params::kK] ^= 0x01;
  EXPECT_FALSE(TypeParam::check_decaps_key(dk));
  const pq::Encapsulation enc = kem.encaps(kp.pk, rng);
  EXPECT_THROW((void)kem.decaps(dk, enc.ct), pq::Error);
}

TEST(MlKem, ParameterSetIsBoundToSeed) {
  // FIPS 203, Algorithm 13, footnote 1: k is hashed with d, so the same seed
  // gives unrelated rho for different parameter sets.
  std::array<uint8_t, 64> seed{};
  const pq::KeyPair a = pq::mlkem::MlKem512().keygen_derand(seed);
  const pq::KeyPair b = pq::mlkem::MlKem768().keygen_derand(seed);
  EXPECT_FALSE(std::equal(a.pk.end() - 32, a.pk.end(), b.pk.end() - 32));
}

TEST(MlKem, Names) {
  EXPECT_EQ(pq::mlkem::MlKem512().name(), "ML-KEM-512");
  EXPECT_EQ(pq::mlkem::MlKem768().name(), "ML-KEM-768");
  EXPECT_EQ(pq::mlkem::MlKem1024().name(), "ML-KEM-1024");
  EXPECT_EQ(pq::mlkem::MlKem512().security_level(), 1);
  EXPECT_EQ(pq::mlkem::MlKem768().security_level(), 3);
  EXPECT_EQ(pq::mlkem::MlKem1024().security_level(), 5);
}

}  // namespace
