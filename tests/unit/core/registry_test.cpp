#include "pq/registry.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <memory>
#include <numeric>

#include "pq/error.hpp"
#include "support/test_registry.hpp"

namespace {

bool contains(const std::vector<std::string>& v, const std::string& s) {
  return std::find(v.begin(), v.end(), s) != v.end();
}

TEST(Registry, GlobalHasMlKemUnderCanonicalNames) {
  const pq::Registry& r = pq::Registry::global();
  for (const char* name : {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
    EXPECT_TRUE(contains(r.list_kems(), name)) << name;
    EXPECT_EQ(r.kem(name)->name(), name);
  }
}

TEST(Registry, GlobalIsASingleInstance) {
  EXPECT_EQ(&pq::Registry::global(), &pq::Registry::global());
}

TEST(Registry, UnknownNamesThrow) {
  const pq::Registry r = pq::test::make_test_registry();
  EXPECT_THROW((void)r.kem("ML-KEM-999"), pq::Error);
  EXPECT_THROW((void)r.cipher("Magma"), pq::Error);
  EXPECT_THROW((void)r.aead("MGM", "AES-256"), pq::Error);
  EXPECT_THROW((void)r.aead("GCM", "Magma"), pq::Error);
  EXPECT_THROW((void)r.cipher_mode("OFB", "AES-256"), pq::Error);
  EXPECT_THROW((void)r.cipher_mode("ECB", "Magma"), pq::Error);
}

TEST(Registry, DuplicateAndEmptyRegistrationsThrow) {
  pq::Registry r = pq::test::make_test_registry();
  EXPECT_THROW(r.add_kem("Dummy-KEM", [] { return std::make_unique<pq::test::DummyKem>(); }),
               pq::Error);
  EXPECT_THROW(r.add_kem("Empty", pq::Registry::KemFactory{}), pq::Error);
  EXPECT_THROW(r.add_cipher("AES-256", [] { return std::make_unique<pq::test::XorCipher>(); }),
               pq::Error);
}

TEST(Registry, AeadIsBuiltFromModeAndCipher) {
  const pq::Registry r = pq::test::make_test_registry();
  const auto aead = r.aead("GCM", "AES-256");
  EXPECT_EQ(aead->name(), "AES-256-GCM");
  EXPECT_EQ(aead->key_size(), 32U);
  EXPECT_EQ(aead->nonce_size(), 12U);
  EXPECT_EQ(aead->tag_size(), 16U);
  EXPECT_TRUE(contains(r.list_modes(), "GCM"));
  EXPECT_TRUE(contains(r.list_ciphers(), "AES-256"));
}

TEST(Registry, CipherModeIsBuiltFromModeAndCipher) {
  const pq::Registry r = pq::test::make_test_registry();
  const auto mode = r.cipher_mode("ECB", "Kuznyechik");
  EXPECT_EQ(mode->name(), "Kuznyechik-ECB");
  EXPECT_EQ(mode->key_size(), 32U);
  EXPECT_EQ(mode->block_size(), 16U);
  EXPECT_EQ(mode->iv_size(), 0U);
}

// list_modes() keeps meaning "AEAD modes": pqbench calls aead() for every name in it.
TEST(Registry, AeadAndCipherModesAreListedSeparately) {
  const pq::Registry r = pq::test::make_test_registry();
  EXPECT_TRUE(contains(r.list_cipher_modes(), "ECB"));
  EXPECT_FALSE(contains(r.list_cipher_modes(), "GCM"));
  EXPECT_TRUE(contains(r.list_modes(), "GCM"));
  EXPECT_FALSE(contains(r.list_modes(), "ECB"));
  EXPECT_THROW((void)r.aead("ECB", "AES-256"), pq::Error);
  EXPECT_THROW((void)r.cipher_mode("GCM", "AES-256"), pq::Error);
}

TEST(Registry, ModeNamesAreUniqueAcrossAeadAndCipherModes) {
  pq::Registry r = pq::test::make_test_registry();
  const auto ecb = [](std::unique_ptr<pq::BlockCipher> c) {
    return std::make_unique<pq::test::StubEcb>(std::move(c));
  };
  const auto gcm = [](std::unique_ptr<pq::BlockCipher> c) {
    return std::make_unique<pq::test::StubGcm>(std::move(c));
  };
  EXPECT_THROW(r.add_cipher_mode("ECB", ecb), pq::Error);
  EXPECT_THROW(r.add_cipher_mode("GCM", ecb), pq::Error);
  EXPECT_THROW(r.add_aead_mode("ECB", gcm), pq::Error);
  EXPECT_THROW(r.add_cipher_mode("CTR", pq::Registry::CipherModeFactory{}), pq::Error);
}

TEST(Registry, FactoriesReturnIndependentInstances) {
  const pq::Registry r = pq::test::make_test_registry();
  EXPECT_NE(r.kem("Dummy-KEM").get(), r.kem("Dummy-KEM").get());
}

// The stubs stand in for AES-GCM in every service test, so check that they honour the contract.
TEST(StubAead, SealOpenRoundTripAndTamperDetection) {
  const pq::Registry r = pq::test::make_test_registry();
  const auto aead = r.aead("GCM", "AES-256");
  const std::array<uint8_t, 32> key{1, 2, 3};
  const std::array<uint8_t, 12> nonce{4, 5, 6};
  const std::array<uint8_t, 3> aad{7, 8, 9};
  pq::Bytes pt(100);
  std::iota(pt.begin(), pt.end(), uint8_t{0});

  const pq::Bytes ct = aead->seal(key, nonce, aad, pt);
  ASSERT_EQ(ct.size(), pt.size() + 16);
  const auto opened = aead->open(key, nonce, aad, ct);
  ASSERT_TRUE(opened.has_value());
  EXPECT_EQ(pq::Bytes(opened->begin(), opened->end()), pt);

  for (size_t i = 0; i < ct.size(); ++i) {
    pq::Bytes bad = ct;
    bad[i] ^= 1;
    EXPECT_FALSE(aead->open(key, nonce, aad, bad).has_value()) << i;
  }
  const std::array<uint8_t, 3> other_aad{7, 8, 0};
  EXPECT_FALSE(aead->open(key, nonce, other_aad, ct).has_value());
  EXPECT_THROW((void)aead->seal(pq::ByteView(key).first(31), nonce, aad, pt), pq::Error);
}

TEST(StubEcb, RoundTripAndLengthChecks) {
  const pq::Registry r = pq::test::make_test_registry();
  const auto mode = r.cipher_mode("ECB", "AES-256");
  const std::array<uint8_t, 32> key{1, 2, 3};
  pq::Bytes pt(48);
  std::iota(pt.begin(), pt.end(), uint8_t{0});

  const pq::Bytes ct = mode->encrypt(key, {}, pt);
  ASSERT_EQ(ct.size(), pt.size());
  const auto back = mode->decrypt(key, {}, ct);
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(pq::Bytes(back->begin(), back->end()), pt);

  const std::array<uint8_t, 16> iv{};
  EXPECT_THROW((void)mode->encrypt(key, iv, pt), pq::Error);
  EXPECT_THROW((void)mode->encrypt(key, {}, pq::ByteView(pt).first(47)), pq::Error);
  EXPECT_THROW((void)mode->encrypt(pq::ByteView(key).first(16), {}, pt), pq::Error);
}

TEST(DummyKem, EncapsDecapsAgreeAndWrongKeyDisagrees) {
  const pq::test::DummyKem kem;
  const pq::Bytes seed_a(32, 1);
  const pq::Bytes seed_b(32, 2);
  const pq::Bytes m(32, 3);
  const pq::KeyPair a = kem.keygen_derand(seed_a);
  const pq::KeyPair b = kem.keygen_derand(seed_b);
  const pq::Encapsulation e = kem.encaps_derand(a.pk, m);
  EXPECT_EQ(kem.decaps(a.sk, e.ct).view().size(), 32U);
  EXPECT_TRUE(std::equal(e.ss.begin(), e.ss.end(), kem.decaps(a.sk, e.ct).begin()));
  EXPECT_FALSE(std::equal(e.ss.begin(), e.ss.end(), kem.decaps(b.sk, e.ct).begin()));
}

}  // namespace
