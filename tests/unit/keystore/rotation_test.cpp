#include "keystore/rotation.hpp"

#include <gtest/gtest.h>

#include <algorithm>

#include "hybrid/envelope.hpp"
#include "hybrid/ids.hpp"
#include "pq/error.hpp"
#include "support/temp_dir.hpp"
#include "support/test_registry.hpp"

namespace {

using namespace pq::keystore;

constexpr uint32_t kIters = 4;
const pq::Bytes kPw = {'p', 'w'};

class RotationTest : public ::testing::Test {
 protected:
  RotationTest()
      : registry_(pq::test::make_test_registry()),
        rng_(pq::Bytes{4, 5, 6}),
        kd_(registry_),
        ks_(registry_, rng_, options()) {}

  KeystoreOptions options() {
    KeystoreOptions o;
    o.home = home_.path();
    o.kdf_iterations = kIters;
    o.allow_weak_kdf = true;
    o.clock = [this] { return now_; };
    return o;
  }

  static pq::Bytes text(const std::string& s) { return pq::Bytes(s.begin(), s.end()); }
  static pq::Bytes to_bytes(const std::optional<pq::SecureBytes>& s) {
    return pq::Bytes(s->begin(), s->end());
  }
  static pq::Bytes data_part(const pq::Bytes& env) {
    const size_t h = pq::hybrid::parse_header(env).size;
    return pq::Bytes(env.begin() + static_cast<std::ptrdiff_t>(h), env.end());
  }

  pq::test::TempDir home_;
  pq::Registry registry_;
  pq::DeterministicRng rng_;
  pq::hybrid::KemDem kd_;
  Keystore ks_;
  int64_t now_ = 1700000000;
};

TEST_F(RotationTest, EncryptToActiveAndDecryptByKeyId) {
  const KeyId id = ks_.create_key("ML-KEM-512", "k", kPw);
  const pq::Bytes pt = text("attack at dawn");
  const pq::Bytes env = encrypt_to_active(ks_, kd_, "ML-KEM-512", "AES-256", pt, rng_);
  EXPECT_EQ(pq::hybrid::parse_header(env).b.key_id, pq::hybrid::compute_key_id(ks_.get(id).pk));
  EXPECT_EQ(to_bytes(decrypt(ks_, kd_, env, kPw)), pt);
  EXPECT_THROW((void)decrypt(ks_, kd_, env, pq::Bytes{'x'}), PasswordError);
  EXPECT_THROW((void)decrypt(ks_, kd_, text("garbage"), kPw), pq::Error);
}

TEST_F(RotationTest, EncryptNeedsAnActiveKey) {
  EXPECT_THROW((void)encrypt_to_active(ks_, kd_, "ML-KEM-512", "AES-256", {}, rng_), pq::Error);
  const KeyId id = ks_.create_key("ML-KEM-512", "k", kPw);
  ks_.retire(id, kPw);
  EXPECT_THROW((void)encrypt_to_active(ks_, kd_, "ML-KEM-512", "AES-256", {}, rng_), pq::Error);
}

TEST_F(RotationTest, DecryptRefusesAnEnvelopeOfAnUnknownKey) {
  const pq::Bytes env = [&] {
    const KeyId id = ks_.create_key("ML-KEM-512", "k", kPw);
    (void)id;
    return encrypt_to_active(ks_, kd_, "ML-KEM-512", "AES-256", text("x"), rng_);
  }();
  pq::test::TempDir other_home;
  KeystoreOptions o = options();
  o.home = other_home.path();
  pq::DeterministicRng other_rng(pq::Bytes{7});
  Keystore other(registry_, other_rng, o);
  EXPECT_THROW((void)decrypt(other, kd_, env, kPw), pq::Error);
}

TEST_F(RotationTest, RotateThenRewrapMovesDataToTheNewKey) {
  const KeyId old_id = ks_.create_key("ML-KEM-512", "k", kPw);
  const pq::Bytes pt = text("long-lived secret");
  const pq::Bytes env = encrypt_to_active(ks_, kd_, "ML-KEM-512", "AES-256", pt, rng_);

  const KeyId new_id = ks_.rotate(old_id, kPw);
  // The old envelope still opens: the retired key stays readable.
  EXPECT_EQ(to_bytes(decrypt(ks_, kd_, env, kPw)), pt);

  const pq::Bytes moved = rewrap_to_active(ks_, kd_, env, kPw, "", rng_);
  EXPECT_EQ(pq::hybrid::parse_header(moved).b.key_id,
            pq::hybrid::compute_key_id(ks_.get(new_id).pk));
  EXPECT_EQ(data_part(moved), data_part(env));
  EXPECT_EQ(to_bytes(decrypt(ks_, kd_, moved, kPw)), pt);

  // Now the old key can go: the moved envelope does not need it, the old one does.
  ks_.destroy(old_id);
  EXPECT_EQ(to_bytes(decrypt(ks_, kd_, moved, kPw)), pt);
  EXPECT_THROW((void)decrypt(ks_, kd_, env, kPw), pq::Error);

  const auto entries = ks_.audit_entries();
  EXPECT_TRUE(std::any_of(entries.begin(), entries.end(),
                          [](const AuditEntry& e) { return e.event == "envelope_rewrapped"; }));
  EXPECT_TRUE(ks_.verify_audit().ok);
}

TEST_F(RotationTest, RewrapCanSwitchTheKem) {
  const KeyId a = ks_.create_key("ML-KEM-512", "a", kPw);
  (void)a;
  const KeyId b = ks_.create_key("ML-KEM-768", "b", kPw);
  const pq::Bytes pt = text("move me");
  const pq::Bytes env = encrypt_to_active(ks_, kd_, "ML-KEM-512", "AES-256", pt, rng_);
  const pq::Bytes moved = rewrap_to_active(ks_, kd_, env, kPw, "ML-KEM-768", rng_);
  const pq::hybrid::Header h = pq::hybrid::parse_header(moved);
  EXPECT_EQ(h.b.kem_id, pq::hybrid::kem_id("ML-KEM-768"));
  EXPECT_EQ(h.b.key_id, pq::hybrid::compute_key_id(ks_.get(b).pk));
  EXPECT_EQ(to_bytes(decrypt(ks_, kd_, moved, kPw)), pt);
}

TEST_F(RotationTest, RewrapIsANoOpForTheActiveKeyAndFailsWithoutOne) {
  const KeyId id = ks_.create_key("ML-KEM-512", "k", kPw);
  const pq::Bytes env = encrypt_to_active(ks_, kd_, "ML-KEM-512", "AES-256", text("x"), rng_);
  EXPECT_EQ(rewrap_to_active(ks_, kd_, env, kPw, "", rng_), env);
  EXPECT_THROW((void)rewrap_to_active(ks_, kd_, env, kPw, "ML-KEM-1024", rng_), pq::Error);
  EXPECT_THROW((void)rewrap_to_active(ks_, kd_, env, pq::Bytes{'x'}, "", rng_), PasswordError);
  ks_.retire(id, kPw);
  EXPECT_THROW((void)rewrap_to_active(ks_, kd_, env, kPw, "", rng_), pq::Error);
}

TEST_F(RotationTest, ChangedPasswordStillOpensOldEnvelopes) {
  (void)ks_.create_key("ML-KEM-512", "k", kPw);
  const pq::Bytes pt = text("data");
  const pq::Bytes env = encrypt_to_active(ks_, kd_, "ML-KEM-512", "AES-256", pt, rng_);
  const pq::Bytes new_pw = {'n', 'e', 'w'};
  ks_.change_password(kPw, new_pw);
  EXPECT_EQ(to_bytes(decrypt(ks_, kd_, env, new_pw)), pt);
  EXPECT_THROW((void)decrypt(ks_, kd_, env, kPw), PasswordError);
}

}  // namespace
