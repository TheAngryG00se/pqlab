#include "hybrid/envelope.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>

#include "hash/sha3.hpp"
#include "hybrid/ids.hpp"
#include "pq/error.hpp"

namespace {

using namespace pq::hybrid;

PartA sample_a() {
  PartA a;
  a.aead_id = 3;
  a.nonce_prefix = {1, 2, 3, 4, 5, 6, 7};
  return a;
}

PartB sample_b(size_t ct_len) {
  PartB b;
  b.kem_id = 2;
  b.key_id.fill(0xAA);
  b.kem_ct.assign(ct_len, 0xBB);
  b.wrap_nonce.fill(0xCC);
  b.wrapped_dek.fill(0xDD);
  b.wrap_tag.fill(0xEE);
  return b;
}

TEST(Ids, CanonicalNamesRoundTrip) {
  for (const IdEntry& e : kKemIds) {
    EXPECT_EQ(kem_id(e.name), e.id);
    EXPECT_EQ(kem_name(e.id), e.name);
  }
  for (const IdEntry& e : kAeadIds) {
    EXPECT_EQ(aead_id(e.name), e.id);
    EXPECT_EQ(aead_name(e.id), e.name);
  }
}

TEST(Ids, AreUniqueAndFrozen) {
  // These values are stored in files. Changing one breaks every existing envelope.
  EXPECT_EQ(kem_id("ML-KEM-512"), 1);
  EXPECT_EQ(kem_id("ML-KEM-768"), 2);
  EXPECT_EQ(kem_id("ML-KEM-1024"), 3);
  EXPECT_EQ(kem_id("HQC-1"), 16);
  EXPECT_EQ(kem_id("HQC-3"), 17);
  EXPECT_EQ(kem_id("HQC-5"), 18);
  EXPECT_EQ(aead_id("AES-128-GCM"), 1);
  EXPECT_EQ(aead_id("AES-192-GCM"), 2);
  EXPECT_EQ(aead_id("AES-256-GCM"), 3);
  EXPECT_EQ(aead_id("Kuznyechik-GCM"), 4);
  for (size_t i = 0; i < kKemIds.size(); ++i) {
    for (size_t j = i + 1; j < kKemIds.size(); ++j) {
      EXPECT_NE(kKemIds[i].id, kKemIds[j].id);
    }
  }
}

TEST(Ids, UnknownThrows) {
  EXPECT_THROW((void)kem_id("ML-KEM-999"), pq::Error);
  EXPECT_THROW((void)kem_name(200), pq::Error);
  EXPECT_THROW((void)aead_id("Magma-MGM"), pq::Error);
  EXPECT_THROW((void)aead_name(0), pq::Error);
}

TEST(Envelope, PartAExactBytes) {
  const pq::Bytes a = serialize_part_a(sample_a());
  const pq::Bytes want = {'P', 'Q', 'L', '1', 1, 3, 1, 2, 3, 4, 5, 6, 7};
  EXPECT_EQ(a, want);
  EXPECT_EQ(a.size(), kPartASize);
}

TEST(Envelope, PartBLayout) {
  const pq::Bytes b = serialize_part_b(sample_b(5));
  ASSERT_EQ(b.size(), 1 + 16 + 4 + 5 + 12 + 32 + 16);
  EXPECT_EQ(b[0], 2);
  EXPECT_EQ(b[1], 0xAA);
  // len(ct_kem) is big-endian.
  EXPECT_EQ(b[17], 0);
  EXPECT_EQ(b[20], 5);
  EXPECT_EQ(b[21], 0xBB);
  EXPECT_EQ(b[b.size() - 1], 0xEE);
}

TEST(Envelope, ParseInvertsSerialize) {
  const PartA a = sample_a();
  const PartB b = sample_b(700);
  pq::Bytes env = serialize_part_a(a);
  const pq::Bytes bb = serialize_part_b(b);
  env.insert(env.end(), bb.begin(), bb.end());
  env.insert(env.end(), {9, 9, 9});  // data

  const Header h = parse_header(env);
  EXPECT_EQ(h.size, env.size() - 3);
  EXPECT_EQ(h.a.aead_id, a.aead_id);
  EXPECT_EQ(h.a.nonce_prefix, a.nonce_prefix);
  EXPECT_EQ(h.b.kem_id, b.kem_id);
  EXPECT_EQ(h.b.key_id, b.key_id);
  EXPECT_EQ(h.b.kem_ct, b.kem_ct);
  EXPECT_EQ(h.b.wrap_nonce, b.wrap_nonce);
  EXPECT_EQ(h.b.wrapped_dek, b.wrapped_dek);
  EXPECT_EQ(h.b.wrap_tag, b.wrap_tag);
}

TEST(Envelope, ParseRejectsEveryTruncationOfTheHeader) {
  pq::Bytes env = serialize_part_a(sample_a());
  const pq::Bytes bb = serialize_part_b(sample_b(40));
  env.insert(env.end(), bb.begin(), bb.end());
  for (size_t n = 0; n < env.size(); ++n) {
    EXPECT_THROW((void)parse_header(pq::ByteView(env).first(n)), pq::Error) << n;
  }
  EXPECT_NO_THROW((void)parse_header(env));
}

TEST(Envelope, ParseRejectsBadMagicVersionAndHugeLength) {
  pq::Bytes env = serialize_part_a(sample_a());
  const pq::Bytes bb = serialize_part_b(sample_b(8));
  env.insert(env.end(), bb.begin(), bb.end());

  pq::Bytes bad = env;
  bad[0] = 'X';
  EXPECT_THROW((void)parse_header(bad), pq::Error);

  bad = env;
  bad[4] = 2;
  EXPECT_THROW((void)parse_header(bad), pq::Error);

  // len(ct_kem) = 0xFFFFFFFF must not overflow or allocate.
  bad = env;
  for (size_t i = 0; i < 4; ++i) {
    bad[kPartASize + 17 + i] = 0xFF;
  }
  EXPECT_THROW((void)parse_header(bad), pq::Error);
}

TEST(Envelope, ChunkNonceLayout) {
  const std::array<uint8_t, 7> prefix = {1, 2, 3, 4, 5, 6, 7};
  const auto n = chunk_nonce(prefix, 0x01020304, true);
  const std::array<uint8_t, 12> want = {1, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4, 1};
  EXPECT_EQ(n, want);
  EXPECT_NE(chunk_nonce(prefix, 5, true), chunk_nonce(prefix, 5, false));
  EXPECT_NE(chunk_nonce(prefix, 5, false), chunk_nonce(prefix, 6, false));
}

TEST(Envelope, WrapAadCoversPartAAndPartBHead) {
  const PartA a = sample_a();
  const PartB b = sample_b(6);
  const pq::Bytes aad = wrap_aad(a, b);
  const pq::Bytes full_b = serialize_part_b(b);
  // A, then B without wrapped_dek and wrap_tag.
  EXPECT_EQ(aad.size(), kPartASize + full_b.size() - kDekSize - kTagSize);

  PartB b2 = b;
  b2.wrapped_dek.fill(0);
  b2.wrap_tag.fill(0);
  EXPECT_EQ(wrap_aad(a, b2), aad);
  b2.key_id[0] ^= 1;
  EXPECT_NE(wrap_aad(a, b2), aad);
}

TEST(Envelope, KeyIdIsSha3Prefix) {
  // SHA3-256 itself is verified against CAVP in the hash tests.
  const pq::Bytes pk = {1, 2, 3, 4, 5};
  const auto digest = pq::hash::sha3_256(pk);
  const auto id = compute_key_id(pk);
  EXPECT_TRUE(std::equal(id.begin(), id.end(), digest.begin()));
  EXPECT_NE(id, compute_key_id(pq::Bytes{1, 2, 3, 4, 6}));
}

}  // namespace
