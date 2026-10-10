#include "hybrid/kem_dem.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <numeric>
#include <string>

#include "hybrid/envelope.hpp"
#include "hybrid/ids.hpp"
#include "pq/error.hpp"
#include "support/test_registry.hpp"

namespace {

using namespace pq::hybrid;

class KemDemTest : public ::testing::Test {
 protected:
  KemDemTest() : registry_(pq::test::make_test_registry()), kd_(registry_), rng_(seed_bytes(1)) {}

  static pq::Bytes seed_bytes(uint8_t v) { return pq::Bytes(8, v); }

  pq::KeyPair keypair(const std::string& kem, uint8_t tag) {
    const auto k = registry_.kem(kem);
    pq::DeterministicRng r(seed_bytes(tag));
    return k->keygen(r);
  }

  static pq::Bytes data_of(size_t n) {
    pq::Bytes d(n);
    for (size_t i = 0; i < n; ++i) {
      d[i] = static_cast<uint8_t>(i * 7 + i / 251);
    }
    return d;
  }

  static pq::Bytes to_bytes(const std::optional<pq::SecureBytes>& s) {
    return pq::Bytes(s->begin(), s->end());
  }

  // open() must either throw pq::Error or return nullopt, never plaintext.
  bool rejected(pq::ByteView sk, pq::ByteView env) {
    try {
      return !kd_.open(sk, env).has_value();
    } catch (const pq::Error&) {
      return true;
    }
  }

  pq::Registry registry_;
  KemDem kd_;
  pq::DeterministicRng rng_;
};

TEST_F(KemDemTest, RoundTripAcrossChunkBoundaries) {
  const auto kp = keypair("ML-KEM-512", 10);
  for (const size_t n : {size_t{0}, size_t{1}, size_t{15}, kChunkSize - 1, kChunkSize,
                         kChunkSize + 1, 2 * kChunkSize, 2 * kChunkSize + 5, 3 * kChunkSize - 1}) {
    const pq::Bytes pt = data_of(n);
    const pq::Bytes env = kd_.seal("ML-KEM-512", kp.pk, "AES-256", pt, rng_);
    const size_t chunks = std::max<size_t>(1, (n + kChunkSize - 1) / kChunkSize);
    const Header h = parse_header(env);
    EXPECT_EQ(env.size(), h.size + n + chunks * kTagSize) << n;
    const auto out = kd_.open(kp.sk, env);
    ASSERT_TRUE(out.has_value()) << n;
    EXPECT_EQ(to_bytes(out), pt) << n;
  }
}

TEST_F(KemDemTest, RoundTripForEveryKem) {
  const pq::Bytes pt = data_of(1000);
  for (const char* kem : {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
    const auto kp = keypair(kem, 11);
    const pq::Bytes env = kd_.seal(kem, kp.pk, "AES-256", pt, rng_);
    const Header h = parse_header(env);
    EXPECT_EQ(h.b.kem_id, kem_id(kem));
    EXPECT_EQ(h.a.aead_id, aead_id("AES-256-GCM"));
    EXPECT_EQ(h.b.key_id, compute_key_id(kp.pk));
    const auto out = kd_.open(kp.sk, env);
    ASSERT_TRUE(out.has_value()) << kem;
    EXPECT_EQ(to_bytes(out), pt) << kem;
  }
}

TEST_F(KemDemTest, EveryEnvelopeUsesFreshRandomness) {
  const auto kp = keypair("ML-KEM-512", 12);
  const pq::Bytes pt = data_of(64);
  const pq::Bytes e1 = kd_.seal("ML-KEM-512", kp.pk, "AES-256", pt, rng_);
  const pq::Bytes e2 = kd_.seal("ML-KEM-512", kp.pk, "AES-256", pt, rng_);
  const Header h1 = parse_header(e1);
  const Header h2 = parse_header(e2);
  EXPECT_NE(h1.a.nonce_prefix, h2.a.nonce_prefix);
  EXPECT_NE(h1.b.kem_ct, h2.b.kem_ct);
  EXPECT_NE(h1.b.wrapped_dek, h2.b.wrapped_dek);
  EXPECT_NE(pq::Bytes(e1.begin() + h1.size, e1.end()), pq::Bytes(e2.begin() + h2.size, e2.end()));
}

TEST_F(KemDemTest, WrongKeyYieldsNullopt) {
  const auto a = keypair("ML-KEM-512", 20);
  const auto b = keypair("ML-KEM-512", 21);
  const pq::Bytes env = kd_.seal("ML-KEM-512", a.pk, "AES-256", data_of(100), rng_);
  EXPECT_FALSE(kd_.open(b.sk, env).has_value());
  EXPECT_THROW((void)kd_.open(pq::Bytes(10), env), pq::Error);
}

TEST_F(KemDemTest, AnyChangedByteIsRejected) {
  const auto kp = keypair("ML-KEM-512", 22);
  // Two chunks, so that the header, both chunks and both tags are covered.
  const pq::Bytes env = kd_.seal("ML-KEM-512", kp.pk, "AES-256", data_of(kChunkSize + 40), rng_);
  const size_t header = parse_header(env).size;

  // Every header byte, every 997th data byte and the last 40.
  for (size_t i = 0; i < env.size(); ++i) {
    if (i >= header && i % 997 != 0 && i + 40 < env.size()) {
      continue;
    }
    pq::Bytes bad = env;
    bad[i] ^= 0x01;
    EXPECT_TRUE(rejected(kp.sk, bad)) << "byte " << i;
  }
}

TEST_F(KemDemTest, TruncationAndExtensionAreRejected) {
  const auto kp = keypair("ML-KEM-512", 23);
  const pq::Bytes env = kd_.seal("ML-KEM-512", kp.pk, "AES-256", data_of(2 * kChunkSize), rng_);
  const size_t header = parse_header(env).size;
  constexpr size_t kFull = kChunkSize + kTagSize;

  // Cut exactly after the first chunk: the remaining chunk is then "last" with the
  // wrong flag.
  pq::Bytes cut(env.begin(), env.begin() + static_cast<std::ptrdiff_t>(header + kFull));
  EXPECT_TRUE(rejected(kp.sk, cut));
  // Dropping the last byte, or all data.
  cut.assign(env.begin(), env.end() - 1);
  EXPECT_TRUE(rejected(kp.sk, cut));
  cut.assign(env.begin(), env.begin() + static_cast<std::ptrdiff_t>(header));
  EXPECT_TRUE(rejected(kp.sk, cut));
  // Appending a byte or a whole copy of a chunk.
  cut = env;
  cut.push_back(0);
  EXPECT_TRUE(rejected(kp.sk, cut));
  cut.assign(env.begin(), env.end());
  cut.insert(cut.end(), env.begin() + static_cast<std::ptrdiff_t>(header),
             env.begin() + static_cast<std::ptrdiff_t>(header + kFull));
  EXPECT_TRUE(rejected(kp.sk, cut));
}

TEST_F(KemDemTest, ReorderedChunksAreRejected) {
  const auto kp = keypair("ML-KEM-512", 24);
  const pq::Bytes env = kd_.seal("ML-KEM-512", kp.pk, "AES-256", data_of(3 * kChunkSize), rng_);
  const size_t header = parse_header(env).size;
  constexpr size_t kFull = kChunkSize + kTagSize;
  pq::Bytes swapped = env;
  std::swap_ranges(swapped.begin() + static_cast<std::ptrdiff_t>(header),
                   swapped.begin() + static_cast<std::ptrdiff_t>(header + kFull),
                   swapped.begin() + static_cast<std::ptrdiff_t>(header + kFull));
  ASSERT_NE(swapped, env);
  EXPECT_TRUE(rejected(kp.sk, swapped));
}

TEST_F(KemDemTest, GarbageEnvelopesThrowOrReject) {
  const auto kp = keypair("ML-KEM-512", 25);
  EXPECT_THROW((void)kd_.open(kp.sk, {}), pq::Error);
  EXPECT_THROW((void)kd_.open(kp.sk, data_of(100)), pq::Error);
}

TEST_F(KemDemTest, SealRejectsBadInputs) {
  const auto kp = keypair("ML-KEM-512", 26);
  EXPECT_THROW((void)kd_.seal("ML-KEM-512", pq::Bytes(10), "AES-256", {}, rng_), pq::Error);
  EXPECT_THROW((void)kd_.seal("HQC-1", kp.pk, "AES-256", {}, rng_), pq::Error);
  EXPECT_THROW((void)kd_.seal("ML-KEM-512", kp.pk, "Magma", {}, rng_), pq::Error);
  // Dummy-KEM works in the registry but has no id in the envelope format.
  const auto dummy = keypair("Dummy-KEM", 27);
  EXPECT_THROW((void)kd_.seal("Dummy-KEM", dummy.pk, "AES-256", {}, rng_), pq::Error);
}

TEST_F(KemDemTest, RewrapChangesOnlyPartB) {
  const auto old_kp = keypair("ML-KEM-512", 30);
  const auto new_kp = keypair("ML-KEM-768", 31);
  const pq::Bytes pt = data_of(kChunkSize + 123);
  const pq::Bytes env = kd_.seal("ML-KEM-512", old_kp.pk, "AES-256", pt, rng_);

  const auto re = kd_.rewrap(old_kp.sk, "ML-KEM-768", new_kp.pk, env, rng_);
  ASSERT_TRUE(re.has_value());

  const Header h_old = parse_header(env);
  const Header h_new = parse_header(*re);
  // Part A and the data are byte-identical.
  EXPECT_TRUE(std::equal(env.begin(), env.begin() + kPartASize, re->begin()));
  EXPECT_TRUE(std::equal(env.begin() + static_cast<std::ptrdiff_t>(h_old.size), env.end(),
                         re->begin() + static_cast<std::ptrdiff_t>(h_new.size), re->end()));
  // Part B is new.
  EXPECT_EQ(h_new.b.kem_id, kem_id("ML-KEM-768"));
  EXPECT_EQ(h_new.b.key_id, compute_key_id(new_kp.pk));
  EXPECT_NE(h_new.b.key_id, h_old.b.key_id);
  EXPECT_NE(h_new.b.wrap_nonce, h_old.b.wrap_nonce);

  // The new key opens it, the old one no longer does.
  const auto out = kd_.open(new_kp.sk, *re);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(to_bytes(out), pt);
  EXPECT_TRUE(rejected(old_kp.sk, *re));
}

TEST_F(KemDemTest, RewrapKeepsTheSameDek) {
  // Not observable directly; the equal data bytes plus a successful open show it,
  // and a second rewrap must also keep working.
  const auto k1 = keypair("ML-KEM-512", 32);
  const auto k2 = keypair("ML-KEM-512", 33);
  const auto k3 = keypair("ML-KEM-1024", 34);
  const pq::Bytes pt = data_of(500);
  const pq::Bytes e1 = kd_.seal("ML-KEM-512", k1.pk, "AES-256", pt, rng_);
  const auto e2 = kd_.rewrap(k1.sk, "ML-KEM-512", k2.pk, e1, rng_);
  ASSERT_TRUE(e2.has_value());
  const auto e3 = kd_.rewrap(k2.sk, "ML-KEM-1024", k3.pk, *e2, rng_);
  ASSERT_TRUE(e3.has_value());
  EXPECT_EQ(to_bytes(kd_.open(k3.sk, *e3)), pt);
}

TEST_F(KemDemTest, RewrapWithWrongOldKeyFails) {
  const auto a = keypair("ML-KEM-512", 35);
  const auto b = keypair("ML-KEM-512", 36);
  const auto c = keypair("ML-KEM-512", 37);
  const pq::Bytes env = kd_.seal("ML-KEM-512", a.pk, "AES-256", data_of(10), rng_);
  EXPECT_FALSE(kd_.rewrap(b.sk, "ML-KEM-512", c.pk, env, rng_).has_value());
}

TEST_F(KemDemTest, RewrapRejectsTamperedPartB) {
  const auto a = keypair("ML-KEM-512", 38);
  const auto b = keypair("ML-KEM-512", 39);
  const pq::Bytes env = kd_.seal("ML-KEM-512", a.pk, "AES-256", data_of(10), rng_);
  const size_t header = parse_header(env).size;
  for (size_t i = kPartASize; i < header; ++i) {
    pq::Bytes bad = env;
    bad[i] ^= 0x80;
    bool failed = false;
    try {
      failed = !kd_.rewrap(a.sk, "ML-KEM-512", b.pk, bad, rng_).has_value();
    } catch (const pq::Error&) {
      failed = true;
    }
    EXPECT_TRUE(failed) << "byte " << i;
  }
}

TEST_F(KemDemTest, ChangingPartABreaksBothWrapAndData) {
  // AAD of the data is part A only, but part A is also in the wrap AAD, so even a
  // rewrap cannot launder a modified part A.
  const auto a = keypair("ML-KEM-512", 40);
  const auto b = keypair("ML-KEM-512", 41);
  const pq::Bytes env = kd_.seal("ML-KEM-512", a.pk, "AES-256", data_of(10), rng_);
  for (size_t i = 4; i < kPartASize; ++i) {  // magic is checked structurally
    pq::Bytes bad = env;
    bad[i] ^= 0x01;
    bool failed = false;
    try {
      failed = !kd_.rewrap(a.sk, "ML-KEM-512", b.pk, bad, rng_).has_value();
    } catch (const pq::Error&) {
      failed = true;
    }
    EXPECT_TRUE(failed) << "byte " << i;
  }
}

}  // namespace
