#pragma once

// Key creation, storage and rotation.
//
//   <home>/keystore/<key_id hex>.json   one record per key (key_record.hpp)
//   <home>/keystore/audit.log           hash-chained event log (audit_log.hpp)
//   <home>/keystore/audit.key           32 random bytes, mode 0600
//   <home>/keystore.lock                flock file serialising every operation
//
// <home> is PQLAB_HOME, or ~/.pqlab. Every operation that writes builds the new state in a
// copy of the keystore directory and swaps it in with one renameat2(RENAME_EXCHANGE), so
// a crash or an error leaves either the old state or the new one, also when several files
// change (rotate, change_password).

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "keystore/audit_log.hpp"
#include "keystore/fs_util.hpp"
#include "keystore/key_record.hpp"
#include "keystore/policy.hpp"
#include "keystore/seed_seal.hpp"
#include "pq/error.hpp"
#include "pq/registry.hpp"
#include "pq/rng.hpp"

namespace pq::keystore {

// Wrong password, or a record that was modified (the two cannot be told apart).
class PasswordError final : public Error {
 public:
  using Error::Error;
};

struct KeystoreOptions {
  std::filesystem::path home;  // empty: Keystore::default_home()
  uint32_t kdf_iterations = kDefaultKdfIterations;
  // Lets kdf_iterations drop below kDefaultKdfIterations. For unit tests only.
  bool allow_weak_kdf = false;
  std::string cipher = "AES-256";  // the seed is sealed with <cipher>-GCM
  Policy policy;
  std::function<int64_t()> clock;  // Unix seconds; empty: system clock
};

// A key whose seed was unsealed. sk is the expanded decapsulation key for Kem::decaps and
// KemDem::open; the seed itself is not kept.
struct UnlockedKey {
  KeyId key_id{};
  std::string kem;
  Status status = Status::kActive;
  Bytes pk;
  SecureBytes sk;
};

class Keystore {
 public:
  // rng must outlive the keystore; production code passes a SystemRng.
  Keystore(const Registry& registry, Rng& rng, KeystoreOptions options = {});

  // $PQLAB_HOME, else $HOME/.pqlab. Throws pq::Error if neither is set.
  [[nodiscard]] static std::filesystem::path default_home();

  [[nodiscard]] const std::filesystem::path& directory() const { return dir_; }

  // New active key of the named KEM, its seed drawn from the rng and sealed under
  // password. Throws pq::Error for an unknown KEM, an empty password or a bad label
  // (over 256 bytes, control characters, invalid UTF-8).
  KeyId create_key(std::string_view kem, std::string_view label, ByteView password);

  // Public metadata of all keys, oldest first.
  [[nodiscard]] std::vector<KeyRecord> list() const;
  // Throws pq::Error if there is no such key.
  [[nodiscard]] KeyRecord get(const KeyId& id) const;
  // Accepts a full id or a unique prefix of at least 4 hex digits.
  [[nodiscard]] KeyId resolve(std::string_view id_or_prefix) const;
  // Newest active key of this KEM, if any. Encrypt to its pk.
  [[nodiscard]] std::optional<KeyRecord> active_key(std::string_view kem) const;

  // Throws PasswordError if the password is wrong (audited as unlock_failed), pq::Error
  // if the key is missing or destroyed.
  [[nodiscard]] UnlockedKey unlock(const KeyId& id, ByteView password);

  // Status changes (policy.hpp). Throw pq::Error for a transition the policy forbids.
  // Because the status is authenticated, retire and revoke re-seal the seed and need the
  // password (PasswordError if wrong). destroy erases the sealed seed and needs none.
  // Revoking a key that is already destroyed needs no password either.
  void retire(const KeyId& id, ByteView password);
  void revoke(const KeyId& id, ByteView password);
  void destroy(const KeyId& id);

  // Key rotation: creates a new active key of the same KEM and label, sealed under the
  // same password, and retires the old one, in one atomic step. The old key must be
  // active. Existing data is moved with rewrap_to_active (rotation.hpp).
  KeyId rotate(const KeyId& id, ByteView password);

  // Re-seals every key that has a seed under new_password, with a fresh salt, nonce and
  // the configured iteration count. All or nothing: if any key does not open under
  // old_password, nothing changes and PasswordError is thrown.
  void change_password(ByteView old_password, ByteView new_password);

  // Active keys older than Policy::max_active_age_seconds.
  [[nodiscard]] std::vector<KeyId> rotation_due() const;

  // Appends an event written by a caller outside this class (e.g. a rewrap).
  void record_event(std::string_view event, const KeyId& id, std::string_view detail);
  [[nodiscard]] std::vector<AuditEntry> audit_entries() const;
  [[nodiscard]] AuditVerdict verify_audit() const;

 private:
  using Mutation = std::function<void(const std::filesystem::path& stage)>;

  void transact(const Mutation& mutation);
  [[nodiscard]] int64_t now() const;
  // AEAD for new seals (options.cipher), and the AEAD an existing record was sealed with.
  [[nodiscard]] std::unique_ptr<Aead> make_aead() const;
  [[nodiscard]] std::unique_ptr<Aead> make_aead_for(const KeyRecord& rec) const;
  // Takes keystore.lock and finishes a directory swap that a crash left half done.
  [[nodiscard]] fs::FileLock acquire() const;
  [[nodiscard]] AuditLog open_audit(const std::filesystem::path& dir) const;

  // These run on a keystore directory (the live one or a stage) with the lock held.
  KeyId create_in(const std::filesystem::path& dir, std::string_view kem, std::string_view label,
                  ByteView password);
  void set_status_in(const std::filesystem::path& dir, const KeyId& id, Status to,
                     ByteView password);

  const Registry& registry_;
  Rng& rng_;
  KeystoreOptions opts_;
  std::filesystem::path home_;
  std::filesystem::path dir_;
};

}  // namespace pq::keystore
