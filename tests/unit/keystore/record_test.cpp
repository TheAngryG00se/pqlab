#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <string>

#include "hybrid/envelope.hpp"
#include "keystore/hex.hpp"
#include "keystore/key_record.hpp"
#include "keystore/policy.hpp"
#include "keystore/seed_seal.hpp"
#include "pq/error.hpp"
#include "support/test_registry.hpp"

namespace {

using namespace pq::keystore;

constexpr uint32_t kIters = 8;  // tests only; the real minimum is 600000

const pq::Bytes kPassword = {'p', 'a', 's', 's'};

KeyRecord sample_record() {
  KeyRecord r;
  r.pk = {1, 2, 3, 4, 5, 6, 7, 8};
  r.key_id = pq::hybrid::compute_key_id(r.pk);
  r.label = "backup key";
  r.kem = "ML-KEM-768";
  r.status = Status::kActive;
  r.created = 1700000000;
  r.status_changed = 1700000000;
  return r;
}

KeyRecord sealed_record(pq::Rng& rng, pq::Aead& aead) {
  KeyRecord r = sample_record();
  const pq::Bytes seed(64, 0x42);
  seal_seed(r, seed, kPassword, kIters, aead, rng);
  return r;
}

TEST(Hex, RoundTripAndRejects) {
  const pq::Bytes b = {0x00, 0x0f, 0xa5, 0xff};
  EXPECT_EQ(to_hex(b), "000fa5ff");
  EXPECT_EQ(from_hex("000fa5ff"), b);
  EXPECT_THROW((void)from_hex("abc"), pq::Error);
  EXPECT_THROW((void)from_hex("zz"), pq::Error);
  EXPECT_THROW((void)from_hex("AB"), pq::Error);  // lowercase only: one spelling per value
}

TEST(Policy, StatusNamesRoundTrip) {
  for (const Status s : {Status::kActive, Status::kRetired, Status::kDestroyed, Status::kRevoked}) {
    EXPECT_EQ(parse_status(to_string(s)), s);
  }
  EXPECT_THROW((void)parse_status("Active"), pq::Error);
}

TEST(Policy, TransitionTable) {
  const Status all[] = {Status::kActive, Status::kRetired, Status::kDestroyed, Status::kRevoked};
  for (const Status from : all) {
    for (const Status to : all) {
      bool expect = false;
      if (from == Status::kActive && to == Status::kRetired) expect = true;
      if (from == Status::kRetired && to == Status::kDestroyed) expect = true;
      if (from == Status::kRevoked && to == Status::kDestroyed) expect = true;
      if (to == Status::kRevoked && from != Status::kRevoked) expect = true;
      EXPECT_EQ(transition_allowed(from, to), expect)
          << to_string(from) << " -> " << to_string(to);
    }
  }
}

TEST(Policy, OnlyActiveEncrypts) {
  EXPECT_TRUE(can_encrypt(Status::kActive));
  EXPECT_FALSE(can_encrypt(Status::kRetired));
  EXPECT_FALSE(can_encrypt(Status::kRevoked));
  EXPECT_FALSE(can_encrypt(Status::kDestroyed));
  EXPECT_TRUE(can_unseal(Status::kRetired));
  EXPECT_TRUE(can_unseal(Status::kRevoked));
  EXPECT_FALSE(can_unseal(Status::kDestroyed));
}

TEST(Policy, RotationDueAfterMaxAge) {
  Policy p;
  p.max_active_age_seconds = 100;
  EXPECT_FALSE(rotation_due(Status::kActive, 1000, 1099, p));
  EXPECT_TRUE(rotation_due(Status::kActive, 1000, 1100, p));
  EXPECT_FALSE(rotation_due(Status::kRetired, 1000, 5000, p));
  EXPECT_EQ(Policy{}.max_active_age_seconds, 90LL * 86400);
}

class RecordTest : public ::testing::Test {
 protected:
  RecordTest()
      : registry_(pq::test::make_test_registry()),
        aead_(registry_.aead("GCM", "AES-256")),
        rng_(pq::Bytes{7}) {}

  pq::Registry registry_;
  std::unique_ptr<pq::Aead> aead_;
  pq::DeterministicRng rng_;
};

TEST_F(RecordTest, JsonRoundTrip) {
  const KeyRecord r = sealed_record(rng_, *aead_);
  const KeyRecord back = parse_record(serialize_record(r));
  EXPECT_EQ(back.key_id, r.key_id);
  EXPECT_EQ(back.label, r.label);
  EXPECT_EQ(back.kem, r.kem);
  EXPECT_EQ(back.status, r.status);
  EXPECT_EQ(back.created, r.created);
  EXPECT_EQ(back.status_changed, r.status_changed);
  EXPECT_EQ(back.pk, r.pk);
  ASSERT_TRUE(back.sealed.has_value());
  EXPECT_EQ(back.sealed->kdf_iterations, kIters);
  EXPECT_EQ(back.sealed->salt, r.sealed->salt);
  EXPECT_EQ(back.sealed->aead, "AES-256-GCM");
  EXPECT_EQ(back.sealed->nonce, r.sealed->nonce);
  EXPECT_EQ(back.sealed->ciphertext, r.sealed->ciphertext);
  EXPECT_EQ(record_aad(back), record_aad(r));
}

TEST_F(RecordTest, SerializedFormHasNoPlainSeed) {
  const KeyRecord r = sealed_record(rng_, *aead_);
  const std::string text = serialize_record(r);
  // The seed is 64 x 0x42; its hex must not appear.
  EXPECT_EQ(text.find(std::string(128, '4')), std::string::npos);
  EXPECT_NE(text.find("\"status\": \"active\""), std::string::npos);
}

TEST_F(RecordTest, ParseRejectsMalformedRecords) {
  const KeyRecord r = sealed_record(rng_, *aead_);
  const nlohmann::json good = nlohmann::json::parse(serialize_record(r));

  EXPECT_THROW((void)parse_record(""), pq::Error);
  EXPECT_THROW((void)parse_record("[1,2]"), pq::Error);
  EXPECT_THROW((void)parse_record("{\"version\":1"), pq::Error);

  auto bad = [&](auto mutate) {
    nlohmann::json j = good;
    mutate(j);
    return j.dump();
  };
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j.erase("kem"); })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["version"] = 2; })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["status"] = "paused"; })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["created"] = "yesterday"; })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["extra"] = 1; })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["sealed"]["extra"] = 1; })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["key_id"] = std::string(32, '0'); })),
               pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["pk"] = "0102"; })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["sealed"]["salt"] = "00"; })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["sealed"]["nonce"] = "00"; })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["sealed"]["ciphertext"] = "00"; })),
               pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["sealed"]["kdf_iterations"] = 0; })),
               pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["sealed"]["kdf"] = "scrypt"; })),
               pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["label"] = std::string(257, 'x'); })),
               pq::Error);
  // An active key must carry a seed; a destroyed key must not.
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j.erase("sealed"); })), pq::Error);
  EXPECT_THROW((void)parse_record(bad([](auto& j) { j["status"] = "destroyed"; })), pq::Error);
}

TEST_F(RecordTest, DestroyedAndRevokedRecordsMayHaveNoSeed) {
  KeyRecord r = sample_record();
  r.status = Status::kDestroyed;
  EXPECT_NO_THROW((void)parse_record(serialize_record(r)));
  r.status = Status::kRevoked;
  EXPECT_NO_THROW((void)parse_record(serialize_record(r)));
  EXPECT_THROW((void)record_aad(r), pq::Error);
}

TEST_F(RecordTest, SealUnsealRoundTrip) {
  const KeyRecord r = sealed_record(rng_, *aead_);
  const auto seed = unseal_seed(r, kPassword, *aead_);
  ASSERT_TRUE(seed.has_value());
  EXPECT_EQ(seed->size(), 64U);
  EXPECT_EQ((*seed)[0], 0x42);
  EXPECT_EQ(r.sealed->ciphertext.size(), 64 + kTagSize);
}

TEST_F(RecordTest, WrongPasswordFails) {
  const KeyRecord r = sealed_record(rng_, *aead_);
  EXPECT_FALSE(unseal_seed(r, pq::Bytes{'x'}, *aead_).has_value());
  EXPECT_THROW((void)unseal_seed(r, {}, *aead_), pq::Error);
}

TEST_F(RecordTest, EveryMetadataFieldIsAuthenticated) {
  const KeyRecord r = sealed_record(rng_, *aead_);
  auto fails = [&](auto mutate) {
    KeyRecord m = r;
    mutate(m);
    return !unseal_seed(m, kPassword, *aead_).has_value();
  };
  EXPECT_TRUE(fails([](KeyRecord& m) { m.label += "x"; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.kem = "ML-KEM-512"; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.status = Status::kRetired; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.created += 1; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.status_changed += 1; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.pk[0] ^= 1; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.key_id[0] ^= 1; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.sealed->salt[0] ^= 1; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.sealed->nonce[0] ^= 1; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.sealed->kdf_iterations += 1; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.sealed->ciphertext[0] ^= 1; }));
  EXPECT_TRUE(fails([](KeyRecord& m) { m.sealed->ciphertext.back() ^= 1; }));
}

TEST_F(RecordTest, AadFieldBoundariesAreUnambiguous) {
  // Moving a byte from the label into the kem name must change the AAD.
  KeyRecord a = sealed_record(rng_, *aead_);
  KeyRecord b = a;
  a.label = "ab";
  a.kem = "c";
  b.label = "a";
  b.kem = "bc";
  EXPECT_NE(record_aad(a), record_aad(b));
}

TEST_F(RecordTest, SealUsesFreshSaltAndNonceEachTime) {
  KeyRecord a = sample_record();
  KeyRecord b = sample_record();
  const pq::Bytes seed(64, 1);
  seal_seed(a, seed, kPassword, kIters, *aead_, rng_);
  seal_seed(b, seed, kPassword, kIters, *aead_, rng_);
  EXPECT_NE(a.sealed->salt, b.sealed->salt);
  EXPECT_NE(a.sealed->nonce, b.sealed->nonce);
  EXPECT_NE(a.sealed->ciphertext, b.sealed->ciphertext);
}

TEST_F(RecordTest, SealRejectsBadArguments) {
  KeyRecord r = sample_record();
  const pq::Bytes seed(64, 1);
  EXPECT_THROW(seal_seed(r, seed, {}, kIters, *aead_, rng_), pq::Error);
  EXPECT_THROW(seal_seed(r, seed, kPassword, 0, *aead_, rng_), pq::Error);
  EXPECT_FALSE(r.sealed.has_value());
}

TEST_F(RecordTest, UnsealRefusesForeignAeadOrMissingSeed) {
  const KeyRecord sealed = sealed_record(rng_, *aead_);
  auto other_ptr = std::make_unique<pq::test::StubGcm>(
      std::make_unique<pq::test::XorCipher>("Other-256", 32));
  EXPECT_THROW((void)unseal_seed(sealed, kPassword, *other_ptr), pq::Error);
  EXPECT_THROW((void)unseal_seed(sample_record(), kPassword, *aead_), pq::Error);
}

}  // namespace
