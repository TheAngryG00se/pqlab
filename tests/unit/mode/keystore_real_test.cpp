#include <gtest/gtest.h>

#include "hybrid/envelope.hpp"
#include "keystore/rotation.hpp"
#include "pq/ct.hpp"
#include "support/temp_dir.hpp"

namespace {

TEST(RealCipherKeystore, RotatedEnvelopeOpensAfterReopeningTheStore) {
  pq::test::TempDir home;
  pq::keystore::KeystoreOptions options;
  options.home = home.path();
  options.allow_weak_kdf = true;
  options.kdf_iterations = 4;
  pq::SystemRng rng;
  const auto& registry = pq::Registry::global();
  const pq::hybrid::KemDem hybrid;
  pq::SecureBytes password(24);
  pq::SecureBytes plaintext(37);
  rng.fill(password.span());
  rng.fill(plaintext.span());
  pq::Bytes moved;
  {
    pq::keystore::Keystore store(registry, rng, options);
    const auto old_id = store.create_key("ML-KEM-768", "integration", password);
    const auto original = encrypt_to_active(store, hybrid, "ML-KEM-768", "AES-256", plaintext, rng);
    const auto new_id = store.rotate(old_id, password);
    moved = rewrap_to_active(store, hybrid, original, password, "", rng);
    EXPECT_EQ(pq::hybrid::parse_header(moved).b.key_id, new_id);
    store.destroy(old_id);
    EXPECT_THROW((void)decrypt(store, hybrid, original, password), pq::Error);
  }
  pq::keystore::Keystore reopened(registry, rng, options);
  const auto opened = decrypt(reopened, hybrid, moved, password);
  ASSERT_TRUE(opened);
  EXPECT_TRUE(pq::ct_equal(*opened, plaintext));
  moved.back() ^= 1;
  EXPECT_FALSE(decrypt(reopened, hybrid, moved, password));
  EXPECT_TRUE(reopened.verify_audit().ok);
}

}  // namespace
