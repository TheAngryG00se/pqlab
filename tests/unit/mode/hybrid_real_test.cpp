#include <gtest/gtest.h>

#include "hybrid/envelope.hpp"
#include "hybrid/kem_dem.hpp"
#include "pq/ct.hpp"
#include "support/participant3_registry.hpp"

namespace {
TEST(RealCipherHybrid, EveryAvailableKemAndCipherAuthenticatesAndRewraps) {
  auto registry = pq::test::participant3_registry();
  const auto& global = pq::Registry::global();
  for (const auto& kem : global.list_kems()) {
    registry.add_kem(kem, [kem] { return pq::Registry::global().kem(kem); });
  }
  pq::SystemRng rng;
  const pq::hybrid::KemDem hybrid(registry);
  for (const auto& kem_name : registry.list_kems()) {
    const auto kem = registry.kem(kem_name);
    const auto old_keys = kem->keygen(rng);
    const auto new_keys = kem->keygen(rng);
    for (const auto& cipher : registry.list_ciphers()) {
      SCOPED_TRACE(kem_name + ":" + cipher);
      pq::SecureBytes message(79);
      rng.fill(message.span());
      const auto envelope = hybrid.seal(kem_name, old_keys.pk, cipher, message, rng);
      const auto opened = hybrid.open(old_keys.sk, envelope);
      ASSERT_TRUE(opened);
      EXPECT_TRUE(pq::ct_equal(*opened, message));
      EXPECT_FALSE(hybrid.open(new_keys.sk, envelope));
      auto modified = envelope;
      modified.back() ^= 1;
      EXPECT_FALSE(hybrid.open(old_keys.sk, modified));
      const auto rewrapped = hybrid.rewrap(old_keys.sk, kem_name, new_keys.pk, envelope, rng);
      ASSERT_TRUE(rewrapped);
      const auto again = hybrid.open(new_keys.sk, *rewrapped);
      ASSERT_TRUE(again);
      EXPECT_TRUE(pq::ct_equal(*again, message));
      const auto old_header = pq::hybrid::parse_header(envelope);
      const auto new_header = pq::hybrid::parse_header(*rewrapped);
      EXPECT_TRUE(pq::ct_equal(pq::ByteView(envelope).subspan(old_header.size),
                               pq::ByteView(*rewrapped).subspan(new_header.size)));
    }
  }
}

TEST(RealCipherHybrid, AesGcmProtectsFullChunkBoundaries) {
  auto registry = pq::test::participant3_registry();
  registry.add_kem("ML-KEM-512", [] { return pq::Registry::global().kem("ML-KEM-512"); });
  pq::SystemRng rng;
  const auto keys = registry.kem("ML-KEM-512")->keygen(rng);
  const pq::hybrid::KemDem hybrid(registry);
  for (size_t size : {size_t{0}, size_t{65536}, size_t{65537}}) {
    pq::SecureBytes message(size);
    rng.fill(message.span());
    const auto ct = hybrid.seal("ML-KEM-512", keys.pk, "AES-256", message, rng);
    const auto pt = hybrid.open(keys.sk, ct);
    ASSERT_TRUE(pt);
    EXPECT_TRUE(pq::ct_equal(*pt, message));
  }
}
}  // namespace
