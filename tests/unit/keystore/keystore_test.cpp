#include "keystore/keystore.hpp"

#include <gtest/gtest.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <thread>

#include "keystore/fs_util.hpp"
#include "keystore/hex.hpp"
#include "pq/error.hpp"
#include "support/temp_dir.hpp"
#include "support/test_registry.hpp"

namespace {

using namespace pq::keystore;
namespace stdfs = std::filesystem;

constexpr uint32_t kIters = 4;  // tests only; the real minimum is 600000
const pq::Bytes kPw = {'s', 'e', 'c', 'r', 'e', 't'};
const pq::Bytes kOtherPw = {'o', 't', 'h', 'e', 'r'};

mode_t mode_of(const stdfs::path& p) {
  struct stat st{};
  EXPECT_EQ(::stat(p.c_str(), &st), 0);
  return st.st_mode & 0777;
}

// Contents of every file in a directory, to compare states byte for byte.
std::map<std::string, std::string> snapshot(const stdfs::path& dir) {
  std::map<std::string, std::string> out;
  for (const auto& e : stdfs::directory_iterator(dir)) {
    out[e.path().filename().string()] = fs::read_file(e.path());
  }
  return out;
}

class KeystoreTest : public ::testing::Test {
 protected:
  KeystoreTest() : registry_(pq::test::make_test_registry()), rng_(pq::Bytes{1, 2, 3}) {}

  KeystoreOptions options() {
    KeystoreOptions o;
    o.home = home_.path() / "pqlab";
    o.kdf_iterations = kIters;
    o.allow_weak_kdf = true;
    o.clock = [this] { return now_; };
    return o;
  }

  Keystore make() { return Keystore(registry_, rng_, options()); }

  stdfs::path ks_dir() { return home_.path() / "pqlab" / "keystore"; }
  stdfs::path file_of(const KeyId& id) { return ks_dir() / (key_id_hex(id) + ".json"); }

  static bool has_event(const std::vector<AuditEntry>& log, const std::string& event) {
    return std::any_of(log.begin(), log.end(),
                       [&](const AuditEntry& e) { return e.event == event; });
  }

  pq::test::TempDir home_;
  pq::Registry registry_;
  pq::DeterministicRng rng_;
  int64_t now_ = 1700000000;
};

TEST_F(KeystoreTest, NothingIsCreatedByReading) {
  Keystore ks = make();
  EXPECT_TRUE(ks.list().empty());
  EXPECT_FALSE(ks.active_key("Dummy-KEM").has_value());
  EXPECT_TRUE(ks.audit_entries().empty());
  EXPECT_TRUE(ks.verify_audit().ok);
  EXPECT_FALSE(stdfs::exists(home_.path() / "pqlab"));
  EXPECT_THROW((void)ks.get(KeyId{}), pq::Error);
  EXPECT_THROW((void)ks.unlock(KeyId{}, kPw), pq::Error);
}

TEST_F(KeystoreTest, CreateKeyWritesPrivateRecord) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "first", kPw);

  EXPECT_EQ(mode_of(home_.path() / "pqlab"), 0700U);
  EXPECT_EQ(mode_of(ks_dir()), 0700U);
  EXPECT_EQ(mode_of(file_of(id)), 0600U);
  EXPECT_EQ(mode_of(ks_dir() / "audit.key"), 0600U);
  EXPECT_EQ(mode_of(ks_dir() / "audit.log"), 0600U);

  const KeyRecord rec = ks.get(id);
  EXPECT_EQ(rec.status, Status::kActive);
  EXPECT_EQ(rec.kem, "Dummy-KEM");
  EXPECT_EQ(rec.label, "first");
  EXPECT_EQ(rec.created, now_);
  ASSERT_TRUE(rec.sealed.has_value());
  EXPECT_EQ(rec.sealed->kdf_iterations, kIters);
  EXPECT_EQ(rec.sealed->aead, "AES-256-GCM");
  // 32-byte Dummy-KEM seed + 16-byte tag.
  EXPECT_EQ(rec.sealed->ciphertext.size(), 48U);
  EXPECT_EQ(ks.list().size(), 1U);
  EXPECT_FALSE(stdfs::exists(home_.path() / "pqlab" / "keystore.stage"));
}

TEST_F(KeystoreTest, SecretKeyNeverReachesTheDisk) {
  Keystore ks = make();
  const KeyId id = ks.create_key("ML-KEM-512", "k", kPw);
  const UnlockedKey key = ks.unlock(id, kPw);
  ASSERT_EQ(key.sk.size(), 1632U);
  // Neither the expanded key nor any 32-byte window of it appears in any file.
  const std::string sk_hex = to_hex(key.sk);
  for (const auto& [name, content] : snapshot(ks_dir())) {
    EXPECT_EQ(content.find(sk_hex.substr(0, 64)), std::string::npos) << name;
    EXPECT_EQ(content.find(sk_hex.substr(sk_hex.size() - 64)), std::string::npos) << name;
  }
}

TEST_F(KeystoreTest, UnlockedKeyDecapsulates) {
  Keystore ks = make();
  const KeyId id = ks.create_key("ML-KEM-512", "k", kPw);
  const UnlockedKey key = ks.unlock(id, kPw);
  EXPECT_EQ(key.key_id, id);
  EXPECT_EQ(key.kem, "ML-KEM-512");
  EXPECT_EQ(key.pk, ks.get(id).pk);

  const auto kem = registry_.kem("ML-KEM-512");
  const pq::Encapsulation e = kem->encaps(key.pk, rng_);
  const pq::SecureBytes k = kem->decaps(key.sk, e.ct);
  EXPECT_TRUE(std::equal(k.begin(), k.end(), e.ss.begin(), e.ss.end()));
}

TEST_F(KeystoreTest, WrongPasswordIsRefusedAndAudited) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "k", kPw);
  EXPECT_THROW((void)ks.unlock(id, kOtherPw), PasswordError);
  EXPECT_THROW((void)ks.unlock(id, {}), pq::Error);
  const auto log = ks.audit_entries();
  EXPECT_TRUE(has_event(log, "unlock_failed"));
  EXPECT_FALSE(has_event(log, "key_unlocked"));
}

TEST_F(KeystoreTest, KeysSurviveANewKeystoreObject) {
  KeyId id;
  {
    Keystore ks = make();
    id = ks.create_key("Dummy-KEM", "persistent", kPw);
  }
  pq::DeterministicRng other(pq::Bytes{9});
  Keystore again(registry_, other, options());
  EXPECT_EQ(again.list().size(), 1U);
  EXPECT_NO_THROW((void)again.unlock(id, kPw));
}

TEST_F(KeystoreTest, ListIsOrderedOldestFirstAndActiveKeyIsTheNewest) {
  Keystore ks = make();
  const KeyId a = ks.create_key("Dummy-KEM", "a", kPw);
  now_ += 10;
  const KeyId b = ks.create_key("Dummy-KEM", "b", kPw);
  now_ += 10;
  const KeyId c = ks.create_key("ML-KEM-512", "c", kPw);
  const auto all = ks.list();
  ASSERT_EQ(all.size(), 3U);
  EXPECT_EQ(all[0].key_id, a);
  EXPECT_EQ(all[1].key_id, b);
  EXPECT_EQ(all[2].key_id, c);
  EXPECT_EQ(ks.active_key("Dummy-KEM")->key_id, b);
  EXPECT_EQ(ks.active_key("ML-KEM-512")->key_id, c);
  EXPECT_FALSE(ks.active_key("ML-KEM-768").has_value());
}

TEST_F(KeystoreTest, ResolveAcceptsPrefixes) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  const std::string hex = key_id_hex(id);
  EXPECT_EQ(ks.resolve(hex), id);
  EXPECT_EQ(ks.resolve(hex.substr(0, 6)), id);
  EXPECT_THROW((void)ks.resolve(hex.substr(0, 3)), pq::Error);  // too short
  EXPECT_THROW((void)ks.resolve("ffffffff" + hex.substr(8, 0)), pq::Error);
  EXPECT_THROW((void)ks.resolve(hex + "0"), pq::Error);
}

TEST_F(KeystoreTest, CreateKeyRejectsBadArguments) {
  Keystore ks = make();
  EXPECT_THROW((void)ks.create_key("Dummy-KEM", "x", {}), pq::Error);
  EXPECT_THROW((void)ks.create_key("NoSuchKem", "x", kPw), pq::Error);
  EXPECT_THROW((void)ks.create_key("Dummy-KEM", std::string(257, 'a'), kPw), pq::Error);
  EXPECT_THROW((void)ks.create_key("Dummy-KEM", "line\nbreak", kPw), pq::Error);
  for (const char* bad : {"bad \xff utf8", "overlong \xc0\x80", "surrogate \xed\xa0\x80",
                          "too big \xf4\x90\x80\x80", "cut short \xe2\x82", "stray \x80"}) {
    EXPECT_THROW((void)ks.create_key("Dummy-KEM", bad, kPw), pq::Error) << bad;
  }
  EXPECT_TRUE(ks.list().empty());
  EXPECT_NO_THROW((void)ks.create_key("Dummy-KEM", "€ 𝄞 ключ", kPw));
  EXPECT_NO_THROW((void)ks.create_key("Dummy-KEM", "ключ №1", kPw));
}

TEST_F(KeystoreTest, RetireStopsEncryptionButKeepsTheKeyReadable) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  now_ += 5;
  ks.retire(id, kPw);
  const KeyRecord rec = ks.get(id);
  EXPECT_EQ(rec.status, Status::kRetired);
  EXPECT_EQ(rec.status_changed, now_);
  EXPECT_EQ(rec.created, now_ - 5);
  EXPECT_FALSE(ks.active_key("Dummy-KEM").has_value());
  EXPECT_NO_THROW((void)ks.unlock(id, kPw));    // still opens under the same password
  EXPECT_THROW(ks.retire(id, kPw), pq::Error);  // retired -> retired is not an edge
}

TEST_F(KeystoreTest, StatusChangeNeedsThePassword) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  const auto before = snapshot(ks_dir());
  EXPECT_THROW(ks.retire(id, kOtherPw), PasswordError);
  EXPECT_THROW(ks.revoke(id, kOtherPw), PasswordError);
  EXPECT_EQ(ks.get(id).status, Status::kActive);
  // Only the audit log grew; the key file is untouched.
  const auto after = snapshot(ks_dir());
  EXPECT_EQ(after.at(key_id_hex(id) + ".json"), before.at(key_id_hex(id) + ".json"));
  EXPECT_TRUE(has_event(ks.audit_entries(), "password_failed"));
}

TEST_F(KeystoreTest, DestroyErasesTheSealedSeed) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  EXPECT_THROW(ks.destroy(id), pq::Error);  // must be retired first
  ks.retire(id, kPw);
  const std::string ct_hex = to_hex(ks.get(id).sealed->ciphertext);
  ks.destroy(id);

  const KeyRecord rec = ks.get(id);
  EXPECT_EQ(rec.status, Status::kDestroyed);
  EXPECT_FALSE(rec.sealed.has_value());
  EXPECT_EQ(fs::read_file(file_of(id)).find(ct_hex), std::string::npos);
  EXPECT_THROW((void)ks.unlock(id, kPw), pq::Error);
  EXPECT_THROW(ks.retire(id, kPw), pq::Error);
  EXPECT_TRUE(has_event(ks.audit_entries(), "key_destroyed"));
}

TEST_F(KeystoreTest, RevokeWorksFromEveryStateAndKeepsTheSeedReadable) {
  Keystore ks = make();
  const KeyId a = ks.create_key("Dummy-KEM", "active", kPw);
  const KeyId r = ks.create_key("Dummy-KEM", "retired", kPw);
  ks.retire(r, kPw);
  ks.revoke(a, kPw);
  ks.revoke(r, kPw);
  EXPECT_EQ(ks.get(a).status, Status::kRevoked);
  EXPECT_EQ(ks.get(r).status, Status::kRevoked);
  EXPECT_FALSE(ks.active_key("Dummy-KEM").has_value());
  EXPECT_EQ(ks.unlock(a, kPw).status, Status::kRevoked);  // data can still be moved off it
  EXPECT_THROW(ks.revoke(a, kPw), pq::Error);

  // revoked -> destroyed, then destroyed -> revoked needs no password at all.
  ks.destroy(a);
  EXPECT_NO_THROW(ks.revoke(a, {}));
  EXPECT_EQ(ks.get(a).status, Status::kRevoked);
  EXPECT_FALSE(ks.get(a).sealed.has_value());
}

TEST_F(KeystoreTest, EditedRecordFilesAreRejected) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "label", kPw);
  ks.retire(id, kPw);
  const std::string original = fs::read_file(file_of(id));

  auto edit = [&](const std::string& from, const std::string& to) {
    std::string text = original;
    const auto pos = text.find(from);
    EXPECT_NE(pos, std::string::npos) << from;
    text.replace(pos, from.size(), to);
    fs::write_file_atomic(file_of(id), text);
  };

  // A retired key cannot be made active again by editing the file.
  edit("\"status\": \"retired\"", "\"status\": \"active\"");
  EXPECT_THROW((void)ks.unlock(id, kPw), PasswordError);
  edit("\"label\": \"label\"", "\"label\": \"other\"");
  EXPECT_THROW((void)ks.unlock(id, kPw), PasswordError);
  // The public key is bound to the key id, which names the file.
  edit("\"created\": 1700000000", "\"created\": 1600000000");
  EXPECT_THROW((void)ks.unlock(id, kPw), PasswordError);

  fs::write_file_atomic(file_of(id), original);
  EXPECT_NO_THROW((void)ks.unlock(id, kPw));

  // A file under the wrong name is refused outright.
  stdfs::copy_file(file_of(id), ks_dir() / (std::string(32, '0') + ".json"));
  EXPECT_THROW((void)ks.list(), pq::Error);
}

TEST_F(KeystoreTest, SeedThatDoesNotMatchThePublicKeyIsRefused) {
  // Someone who knows the password re-seals a different seed under the metadata of key A.
  // The AEAD accepts it; only the pk check in unlock() notices.
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  KeyRecord rec = ks.get(id);
  const auto aead = registry_.aead("GCM", "AES-256");
  seal_seed(rec, pq::Bytes(32, 0x77), kPw, kIters, *aead, rng_);
  fs::write_file_atomic(file_of(id), serialize_record(rec));
  try {
    (void)ks.unlock(id, kPw);
    FAIL() << "unlock accepted a seed that does not belong to the public key";
  } catch (const PasswordError&) {
    FAIL() << "the password was right; this is a format error";
  } catch (const pq::Error&) {
  }
}

TEST_F(KeystoreTest, RotateCreatesANewActiveKeyAndRetiresTheOld) {
  Keystore ks = make();
  const KeyId old_id = ks.create_key("ML-KEM-512", "main", kPw);
  now_ += 100;
  const KeyId new_id = ks.rotate(old_id, kPw);

  EXPECT_NE(new_id, old_id);
  const KeyRecord o = ks.get(old_id);
  const KeyRecord n = ks.get(new_id);
  EXPECT_EQ(o.status, Status::kRetired);
  EXPECT_EQ(n.status, Status::kActive);
  EXPECT_EQ(n.kem, o.kem);
  EXPECT_EQ(n.label, o.label);
  EXPECT_EQ(n.created, now_);
  EXPECT_NE(n.pk, o.pk);
  EXPECT_EQ(ks.active_key("ML-KEM-512")->key_id, new_id);
  EXPECT_NO_THROW((void)ks.unlock(old_id, kPw));
  EXPECT_NO_THROW((void)ks.unlock(new_id, kPw));

  const auto log = ks.audit_entries();
  EXPECT_TRUE(has_event(log, "key_rotated"));
  EXPECT_TRUE(ks.verify_audit().ok);
}

TEST_F(KeystoreTest, RotateIsAllOrNothing) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "main", kPw);
  const auto before = snapshot(ks_dir());
  EXPECT_THROW((void)ks.rotate(id, kOtherPw), PasswordError);
  const auto after = snapshot(ks_dir());
  // Same key files; only the audit log gained the failed attempt.
  std::vector<std::string> names_before;
  std::vector<std::string> names_after;
  for (const auto& kv : before) names_before.push_back(kv.first);
  for (const auto& kv : after) names_after.push_back(kv.first);
  EXPECT_EQ(names_before, names_after);
  EXPECT_EQ(after.at(key_id_hex(id) + ".json"), before.at(key_id_hex(id) + ".json"));
  EXPECT_EQ(ks.list().size(), 1U);

  ks.retire(id, kPw);
  EXPECT_THROW((void)ks.rotate(id, kPw), pq::Error);  // only an active key rotates
  EXPECT_EQ(ks.list().size(), 1U);
}

TEST_F(KeystoreTest, RotationDueFollowsThePolicyAge) {
  KeystoreOptions o = options();
  o.policy.max_active_age_seconds = 1000;
  Keystore ks(registry_, rng_, o);
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  EXPECT_TRUE(ks.rotation_due().empty());
  now_ += 999;
  EXPECT_TRUE(ks.rotation_due().empty());
  now_ += 1;
  ASSERT_EQ(ks.rotation_due().size(), 1U);
  EXPECT_EQ(ks.rotation_due()[0], id);
  const KeyId fresh = ks.rotate(id, kPw);
  EXPECT_TRUE(ks.rotation_due().empty());
  (void)fresh;
}

TEST_F(KeystoreTest, ChangePasswordReSealsEveryKey) {
  Keystore ks = make();
  const KeyId a = ks.create_key("Dummy-KEM", "a", kPw);
  const KeyId b = ks.create_key("ML-KEM-512", "b", kPw);
  ks.retire(b, kPw);
  const KeyId c = ks.create_key("Dummy-KEM", "c", kPw);
  ks.retire(c, kPw);
  ks.destroy(c);  // nothing to re-seal for this one
  const KeyRecord a_before = ks.get(a);
  const pq::SecureBytes sk_b = ks.unlock(b, kPw).sk.clone();

  ks.change_password(kPw, kOtherPw);

  EXPECT_THROW((void)ks.unlock(a, kPw), PasswordError);
  EXPECT_THROW((void)ks.unlock(b, kPw), PasswordError);
  EXPECT_NO_THROW((void)ks.unlock(a, kOtherPw));
  const UnlockedKey b_after = ks.unlock(b, kOtherPw);
  EXPECT_TRUE(std::equal(sk_b.begin(), sk_b.end(), b_after.sk.begin(), b_after.sk.end()));

  const KeyRecord a_after = ks.get(a);
  EXPECT_NE(a_after.sealed->salt, a_before.sealed->salt);
  EXPECT_NE(a_after.sealed->nonce, a_before.sealed->nonce);
  EXPECT_NE(a_after.sealed->ciphertext, a_before.sealed->ciphertext);
  EXPECT_EQ(a_after.pk, a_before.pk);
  EXPECT_EQ(a_after.status, a_before.status);
  EXPECT_EQ(a_after.created, a_before.created);
  EXPECT_EQ(ks.get(c).status, Status::kDestroyed);
  EXPECT_TRUE(ks.verify_audit().ok);
  EXPECT_TRUE(has_event(ks.audit_entries(), "password_changed"));
}

TEST_F(KeystoreTest, ChangePasswordIsAllOrNothing) {
  Keystore ks = make();
  const KeyId a = ks.create_key("Dummy-KEM", "a", kPw);
  const KeyId b = ks.create_key("Dummy-KEM", "b", kOtherPw);  // a different password
  (void)a;
  (void)b;
  const auto before = snapshot(ks_dir());
  EXPECT_THROW(ks.change_password(kPw, pq::Bytes{'n', 'e', 'w'}), PasswordError);
  const auto after = snapshot(ks_dir());
  for (const auto& [name, content] : before) {
    if (name == "audit.log") {
      continue;  // the failed attempt is logged
    }
    EXPECT_EQ(after.at(name), content) << name;
  }
  EXPECT_NO_THROW((void)ks.unlock(a, kPw));
  EXPECT_NO_THROW((void)ks.unlock(b, kOtherPw));
  EXPECT_THROW(ks.change_password(kPw, {}), pq::Error);
}

TEST_F(KeystoreTest, AuditLogRecordsTheLifeOfAKey) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  (void)ks.unlock(id, kPw);
  ks.retire(id, kPw);
  ks.destroy(id);
  std::vector<std::string> events;
  for (const AuditEntry& e : ks.audit_entries()) {
    events.push_back(e.event);
    // No secrets: the entries are short fixed texts and hex ids.
    EXPECT_LT(e.detail.size(), 100U);
  }
  const std::vector<std::string> want = {"key_created", "key_unlocked", "key_retired",
                                         "key_destroyed"};
  EXPECT_EQ(events, want);
  const AuditVerdict v = ks.verify_audit();
  EXPECT_TRUE(v.ok);
  EXPECT_EQ(v.entries, 4U);
}

TEST_F(KeystoreTest, TamperedAuditLogIsReported) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  ks.retire(id, kPw);
  std::string log = fs::read_file(ks_dir() / "audit.log");
  const auto pos = log.find("key_created");
  ASSERT_NE(pos, std::string::npos);
  log.replace(pos, 11, "key_deleted");
  fs::write_file_atomic(ks_dir() / "audit.log", log);
  const AuditVerdict v = ks.verify_audit();
  EXPECT_FALSE(v.ok);
  EXPECT_EQ(v.bad_line, 1U);
}

TEST_F(KeystoreTest, LeftoversOfACrashedRunAreIgnored) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  stdfs::create_directories(home_.path() / "pqlab" / "keystore.stage");
  fs::write_file_atomic(home_.path() / "pqlab" / "keystore.stage" / "junk", "x");
  fs::write_file_atomic(ks_dir() / "abc.json.tmp", "half a record");
  EXPECT_EQ(ks.list().size(), 1U);
  const KeyId id2 = ks.create_key("Dummy-KEM", "b", kPw);
  EXPECT_NE(id, id2);
  EXPECT_EQ(ks.list().size(), 2U);
  EXPECT_FALSE(stdfs::exists(home_.path() / "pqlab" / "keystore.stage"));
  EXPECT_FALSE(stdfs::exists(ks_dir() / "junk"));
}

TEST_F(KeystoreTest, ConcurrentWritersDoNotLoseKeys) {
  // Two keystore objects on the same directory, each with its own Rng.
  {
    Keystore warm = make();
    (void)warm.create_key("Dummy-KEM", "warm-up", kPw);
  }
  constexpr int kPerThread = 4;
  auto work = [&](uint8_t seed) {
    pq::DeterministicRng rng(pq::Bytes{seed});
    Keystore ks(registry_, rng, options());
    for (int i = 0; i < kPerThread; ++i) {
      (void)ks.create_key("Dummy-KEM", "t" + std::to_string(seed), kPw);
    }
  };
  std::thread t1(work, 10);
  std::thread t2(work, 20);
  t1.join();
  t2.join();
  Keystore ks = make();
  EXPECT_EQ(ks.list().size(), 1U + 2 * kPerThread);
  const AuditVerdict v = ks.verify_audit();
  EXPECT_TRUE(v.ok) << v.problem;
  EXPECT_EQ(v.entries, 1U + 2 * kPerThread);
}

TEST_F(KeystoreTest, FilesStayPrivateThroughManyOperations) {
  Keystore ks = make();
  const KeyId a = ks.create_key("Dummy-KEM", "a", kPw);
  const KeyId b = ks.rotate(a, kPw);
  ks.change_password(kPw, kOtherPw);
  ks.retire(b, kOtherPw);
  // Copies made while staging must keep 0600, whatever the umask is.
  const mode_t old_umask = ::umask(0);
  (void)ks.create_key("Dummy-KEM", "c", kOtherPw);
  ::umask(old_umask);
  for (const auto& e : stdfs::directory_iterator(ks_dir())) {
    EXPECT_EQ(mode_of(e.path()), 0600U) << e.path();
  }
  EXPECT_EQ(mode_of(ks_dir()), 0700U);
  EXPECT_EQ(mode_of(home_.path() / "pqlab" / "keystore.lock"), 0600U);
}

TEST_F(KeystoreTest, RecoversFromACrashDuringThePortableSwap) {
  KeyId id;
  {
    Keystore ks = make();
    id = ks.create_key("Dummy-KEM", "a", kPw);
  }
  const stdfs::path home = home_.path() / "pqlab";

  // The first rename of the portable swap happened, the second did not.
  stdfs::rename(ks_dir(), home / "keystore.old");
  {
    Keystore ks = make();
    EXPECT_EQ(ks.list().size(), 1U);
    EXPECT_NO_THROW((void)ks.unlock(id, kPw));
    EXPECT_FALSE(stdfs::exists(home / "keystore.old"));
  }

  // Both renames happened, the old state was not yet removed. Writing must not lose data.
  stdfs::create_directories(home / "keystore.old");
  fs::write_file_atomic(home / "keystore.old" / "junk.json", "{}");
  Keystore ks = make();
  (void)ks.create_key("Dummy-KEM", "b", kPw);
  EXPECT_EQ(ks.list().size(), 2U);
  EXPECT_FALSE(stdfs::exists(home / "keystore.old"));
  EXPECT_TRUE(ks.verify_audit().ok);
}

TEST_F(KeystoreTest, EachRecordNamesTheAeadItWasSealedWith) {
  KeyId id;
  {
    Keystore ks = make();  // AES-256-GCM
    id = ks.create_key("Dummy-KEM", "a", kPw);
    EXPECT_EQ(ks.get(id).sealed->aead, "AES-256-GCM");
  }
  KeystoreOptions o = options();
  o.cipher = "Kuznyechik";
  Keystore ks(registry_, rng_, o);
  // Still opens although the keystore now seals with another cipher.
  EXPECT_NO_THROW((void)ks.unlock(id, kPw));
  // Re-sealing moves the record to the configured AEAD.
  ks.retire(id, kPw);
  EXPECT_EQ(ks.get(id).sealed->aead, "Kuznyechik-GCM");
  EXPECT_NO_THROW((void)ks.unlock(id, kPw));
  const KeyId fresh = ks.create_key("Dummy-KEM", "b", kPw);
  EXPECT_EQ(ks.get(fresh).sealed->aead, "Kuznyechik-GCM");

  ks.change_password(kPw, kOtherPw);
  EXPECT_NO_THROW((void)ks.unlock(id, kOtherPw));
  // And the original configuration can read both kinds.
  Keystore back = make();
  EXPECT_NO_THROW((void)back.unlock(id, kOtherPw));
  EXPECT_NO_THROW((void)back.unlock(fresh, kOtherPw));
  EXPECT_TRUE(back.verify_audit().ok);
}

TEST_F(KeystoreTest, UnknownAeadInARecordIsAnErrorNotACrash) {
  Keystore ks = make();
  const KeyId id = ks.create_key("Dummy-KEM", "a", kPw);
  std::string text = fs::read_file(file_of(id));
  const auto pos = text.find("AES-256-GCM");
  ASSERT_NE(pos, std::string::npos);
  text.replace(pos, 11, "AES-256-OCB");
  fs::write_file_atomic(file_of(id), text);
  EXPECT_THROW((void)ks.unlock(id, kPw), pq::Error);
  text.replace(pos, 11, "Magma-256-GCM");
  fs::write_file_atomic(file_of(id), text);
  EXPECT_THROW((void)ks.unlock(id, kPw), pq::Error);
}

TEST_F(KeystoreTest, DefaultsFollowAgentsMd) {
  // AGENTS.md, section 10: at least 600000 PBKDF2 iterations unless a test opts out.
  static_assert(kDefaultKdfIterations >= 600000);
  const KeystoreOptions o;
  EXPECT_EQ(o.kdf_iterations, kDefaultKdfIterations);
  EXPECT_FALSE(o.allow_weak_kdf);
  EXPECT_EQ(o.cipher, "AES-256");
  EXPECT_EQ(o.policy.max_active_age_seconds, 90LL * 86400);
}

TEST_F(KeystoreTest, OptionsAreValidated) {
  KeystoreOptions o = options();
  o.allow_weak_kdf = false;
  EXPECT_THROW(Keystore(registry_, rng_, o), pq::Error);
  o.kdf_iterations = kDefaultKdfIterations;
  EXPECT_NO_THROW(Keystore(registry_, rng_, o));
  o.kdf_iterations = 0;
  EXPECT_THROW(Keystore(registry_, rng_, o), pq::Error);
  o.kdf_iterations = kMaxKdfIterations + 1;
  EXPECT_THROW(Keystore(registry_, rng_, o), pq::Error);
}

TEST_F(KeystoreTest, DefaultHomeFollowsEnvironment) {
  const char* old_pqlab = std::getenv("PQLAB_HOME");
  const char* old_home = std::getenv("HOME");
  const std::string saved_pqlab = old_pqlab != nullptr ? old_pqlab : "";
  const std::string saved_home = old_home != nullptr ? old_home : "";

  ::setenv("PQLAB_HOME", "/tmp/somewhere", 1);
  EXPECT_EQ(Keystore::default_home(), stdfs::path("/tmp/somewhere"));
  ::unsetenv("PQLAB_HOME");
  ::setenv("HOME", "/home/alice", 1);
  EXPECT_EQ(Keystore::default_home(), stdfs::path("/home/alice/.pqlab"));
  ::unsetenv("HOME");
  EXPECT_THROW((void)Keystore::default_home(), pq::Error);

  if (old_pqlab != nullptr) ::setenv("PQLAB_HOME", saved_pqlab.c_str(), 1);
  if (old_home != nullptr) ::setenv("HOME", saved_home.c_str(), 1);
}

}  // namespace
