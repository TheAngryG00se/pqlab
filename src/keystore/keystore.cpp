#include "keystore/keystore.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <optional>
#include <system_error>

#include "hybrid/envelope.hpp"
#include "keystore/fs_util.hpp"
#include "keystore/hex.hpp"
#include "pq/ct.hpp"

namespace pq::keystore {

namespace {

namespace stdfs = std::filesystem;

constexpr std::string_view kAuditKeyFile = "audit.key";
constexpr std::string_view kAuditLogFile = "audit.log";

stdfs::path record_path(const stdfs::path& dir, const KeyId& id) {
  return dir / (key_id_hex(id) + ".json");
}

KeyRecord load_record(const stdfs::path& dir, const KeyId& id) {
  const stdfs::path path = record_path(dir, id);
  std::error_code ec;
  if (!stdfs::is_regular_file(path, ec)) {
    throw Error("no such key: " + key_id_hex(id));
  }
  KeyRecord rec = parse_record(fs::read_file(path));
  if (rec.key_id != id) {
    throw Error("key file " + path.filename().string() + " holds a different key id");
  }
  return rec;
}

void write_record(const stdfs::path& dir, const KeyRecord& rec) {
  fs::write_file_atomic(record_path(dir, rec.key_id), serialize_record(rec));
}

std::vector<KeyRecord> load_all(const stdfs::path& dir) {
  std::vector<KeyRecord> out;
  std::error_code ec;
  if (!stdfs::is_directory(dir, ec)) {
    return out;
  }
  for (const auto& entry : stdfs::directory_iterator(dir)) {
    if (!entry.is_regular_file() || entry.path().extension() != ".json") {
      continue;
    }
    KeyRecord rec = parse_record(fs::read_file(entry.path()));
    if (entry.path().stem().string() != key_id_hex(rec.key_id)) {
      throw Error("key file " + entry.path().filename().string() + " holds a different key id");
    }
    out.push_back(std::move(rec));
  }
  std::sort(out.begin(), out.end(), [](const KeyRecord& a, const KeyRecord& b) {
    return a.created != b.created ? a.created < b.created : a.key_id < b.key_id;
  });
  return out;
}

// Strict UTF-8 (RFC 3629): no overlong forms, no surrogates, nothing above U+10FFFF.
bool is_valid_utf8(std::string_view s) {
  size_t i = 0;
  while (i < s.size()) {
    const auto lead = static_cast<uint8_t>(s[i]);
    size_t extra = 0;
    uint32_t cp = 0;
    uint32_t min = 0;
    if (lead < 0x80) {
      ++i;
      continue;
    }
    if ((lead & 0xE0) == 0xC0) {
      extra = 1;
      cp = lead & 0x1FU;
      min = 0x80;
    } else if ((lead & 0xF0) == 0xE0) {
      extra = 2;
      cp = lead & 0x0FU;
      min = 0x800;
    } else if ((lead & 0xF8) == 0xF0) {
      extra = 3;
      cp = lead & 0x07U;
      min = 0x10000;
    } else {
      return false;
    }
    if (i + extra >= s.size()) {
      return false;
    }
    for (size_t k = 1; k <= extra; ++k) {
      const auto c = static_cast<uint8_t>(s[i + k]);
      if ((c & 0xC0) != 0x80) {
        return false;
      }
      cp = (cp << 6) | (c & 0x3FU);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
      return false;
    }
    i += extra + 1;
  }
  return true;
}

void validate_label(std::string_view label) {
  if (label.size() > kMaxLabelSize) {
    throw Error("label is too long");
  }
  if (!is_valid_utf8(label)) {
    throw Error("label is not valid UTF-8");
  }
  for (const char c : label) {
    const auto u = static_cast<uint8_t>(c);
    if (u < 0x20 || u == 0x7F) {
      throw Error("label must not contain control characters");
    }
  }
}

std::string_view as_chars(const SecureBytes& b) {
  return {reinterpret_cast<const char*>(b.data()), b.size()};
}

}  // namespace

Keystore::Keystore(const Registry& registry, Rng& rng, KeystoreOptions options)
    : registry_(registry), rng_(rng), opts_(std::move(options)) {
  if (opts_.kdf_iterations == 0 || opts_.kdf_iterations > kMaxKdfIterations) {
    throw Error("kdf_iterations out of range");
  }
  if (opts_.kdf_iterations < kDefaultKdfIterations && !opts_.allow_weak_kdf) {
    throw Error("kdf_iterations below the minimum of " + std::to_string(kDefaultKdfIterations));
  }
  if (!opts_.clock) {
    opts_.clock = [] {
      return std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch())
          .count();
    };
  }
  home_ = opts_.home.empty() ? default_home() : opts_.home;
  dir_ = home_ / "keystore";
}

stdfs::path Keystore::default_home() {
  if (const char* env = std::getenv("PQLAB_HOME"); env != nullptr && *env != '\0') {
    return env;
  }
  if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
    return stdfs::path(home) / ".pqlab";
  }
  throw Error("neither PQLAB_HOME nor HOME is set");
}

int64_t Keystore::now() const { return opts_.clock(); }

std::unique_ptr<Aead> Keystore::make_aead() const { return registry_.aead("GCM", opts_.cipher); }

// A record names the AEAD it was sealed with ("AES-256-GCM"), so keys sealed under an
// earlier `cipher` option stay readable.
std::unique_ptr<Aead> Keystore::make_aead_for(const KeyRecord& rec) const {
  constexpr std::string_view kSuffix = "-GCM";
  const std::string& name = rec.sealed->aead;
  if (name.size() <= kSuffix.size() ||
      name.compare(name.size() - kSuffix.size(), kSuffix.size(), kSuffix) != 0) {
    throw Error("key record names an unsupported AEAD");
  }
  return registry_.aead("GCM", std::string_view(name).substr(0, name.size() - kSuffix.size()));
}

fs::FileLock Keystore::acquire() const {
  fs::FileLock lock(home_ / "keystore.lock");
  fs::recover_dir(dir_);
  return lock;
}

AuditLog Keystore::open_audit(const stdfs::path& dir) const {
  const SecureBytes key = fs::read_secret_file(dir / kAuditKeyFile);
  if (key.size() != 32) {
    throw Error("audit.key has the wrong size");
  }
  return AuditLog(dir / kAuditLogFile, key);
}

void Keystore::transact(const Mutation& mutation) {
  fs::make_private_dir(home_);
  const fs::FileLock lock = acquire();
  fs::make_private_dir(dir_);

  const stdfs::path key_file = dir_ / kAuditKeyFile;
  std::error_code ec;
  if (!stdfs::exists(key_file, ec)) {
    SecureBytes k(32);
    rng_.fill(k.span());
    fs::write_file_atomic(key_file, as_chars(k));
  }

  const stdfs::path stage = home_ / "keystore.stage";
  stdfs::remove_all(stage, ec);  // left over from a crashed run
  fs::make_private_dir(stage);
  try {
    for (const auto& entry : stdfs::directory_iterator(dir_)) {
      if (entry.is_regular_file() && entry.path().extension() != ".tmp") {
        const stdfs::path copy = stage / entry.path().filename();
        stdfs::copy_file(entry.path(), copy);
        stdfs::permissions(copy, stdfs::perms::owner_read | stdfs::perms::owner_write,
                           stdfs::perm_options::replace);
      }
    }
    mutation(stage);
    for (const auto& entry : stdfs::directory_iterator(stage)) {
      fs::fsync_file(entry.path());
    }
    fs::fsync_dir(stage);
    fs::replace_dir(stage, dir_);
  } catch (...) {
    stdfs::remove_all(stage, ec);
    throw;
  }
  fs::fsync_dir(home_);
}

KeyId Keystore::create_in(const stdfs::path& dir, std::string_view kem_name, std::string_view label,
                          ByteView password) {
  if (password.empty()) {
    throw Error("password must not be empty");
  }
  validate_label(label);
  const std::unique_ptr<Kem> kem = registry_.kem(kem_name);
  const std::unique_ptr<Aead> aead = make_aead();

  SecureBytes seed(kem->sizes().keygen_seed);
  rng_.fill(seed.span());
  const KeyPair kp = kem->keygen_derand(seed);

  KeyRecord rec;
  rec.pk = kp.pk;
  rec.key_id = hybrid::compute_key_id(rec.pk);
  rec.label = std::string(label);
  rec.kem = std::string(kem->name());
  rec.status = Status::kActive;
  rec.created = rec.status_changed = now();
  seal_seed(rec, seed, password, opts_.kdf_iterations, *aead, rng_);

  std::error_code ec;
  if (stdfs::exists(record_path(dir, rec.key_id), ec)) {
    throw Error("a key with this public key already exists");
  }
  write_record(dir, rec);
  open_audit(dir).append(
      now(), "key_created", key_id_hex(rec.key_id),
      "kem=" + rec.kem + " kdf_iterations=" + std::to_string(rec.sealed->kdf_iterations));
  return rec.key_id;
}

void Keystore::set_status_in(const stdfs::path& dir, const KeyId& id, Status to,
                             ByteView password) {
  KeyRecord rec = load_record(dir, id);
  const KeyRecord before = rec;
  const Status from = rec.status;
  if (!transition_allowed(from, to)) {
    throw Error(std::string("a ") + std::string(to_string(from)) + " key cannot become " +
                std::string(to_string(to)));
  }
  rec.status = to;
  rec.status_changed = now();
  if (to == Status::kDestroyed) {
    rec.sealed.reset();
  } else if (rec.sealed) {
    // The status is part of the AAD: unseal under the old record, re-seal under the new.
    const std::unique_ptr<Aead> old_aead = make_aead_for(before);
    const std::optional<SecureBytes> seed = unseal_seed(before, password, *old_aead);
    if (!seed) {
      throw PasswordError("wrong password or modified key record");
    }
    const std::unique_ptr<Aead> aead = make_aead();
    seal_seed(rec, *seed, password, opts_.kdf_iterations, *aead, rng_);
  }
  write_record(dir, rec);
  open_audit(dir).append(now(), "key_" + std::string(to_string(to)), key_id_hex(id),
                         std::string(to_string(from)) + "->" + std::string(to_string(to)));
}

KeyId Keystore::create_key(std::string_view kem, std::string_view label, ByteView password) {
  KeyId id{};
  transact([&](const stdfs::path& stage) { id = create_in(stage, kem, label, password); });
  return id;
}

std::vector<KeyRecord> Keystore::list() const {
  std::error_code ec;
  if (!stdfs::exists(home_, ec)) {
    return {};
  }
  const fs::FileLock lock = acquire();
  return load_all(dir_);
}

KeyRecord Keystore::get(const KeyId& id) const {
  std::error_code ec;
  if (!stdfs::exists(home_, ec)) {
    throw Error("no such key: " + key_id_hex(id));
  }
  const fs::FileLock lock = acquire();
  return load_record(dir_, id);
}

KeyId Keystore::resolve(std::string_view id_or_prefix) const {
  return find_key_id(list(), id_or_prefix);
}

std::optional<KeyRecord> Keystore::active_key(std::string_view kem) const {
  std::optional<KeyRecord> best;
  for (KeyRecord& rec : list()) {
    if (can_encrypt(rec.status) && rec.kem == kem) {
      best = std::move(rec);  // list() is ordered oldest first
    }
  }
  return best;
}

UnlockedKey Keystore::unlock(const KeyId& id, ByteView password) {
  std::error_code ec;
  if (!stdfs::exists(home_, ec)) {
    throw Error("no such key: " + key_id_hex(id));
  }
  KeyRecord rec;
  {
    // The lock is not held during the (slow) key derivation below.
    const fs::FileLock lock = acquire();
    rec = load_record(dir_, id);
  }
  if (!can_unseal(rec.status) || !rec.sealed) {
    throw Error("key " + key_id_hex(id) + " is " + std::string(to_string(rec.status)));
  }
  const std::unique_ptr<Aead> aead = make_aead_for(rec);
  const std::optional<SecureBytes> seed = unseal_seed(rec, password, *aead);
  if (!seed) {
    record_event("unlock_failed", id, "wrong password or modified record");
    throw PasswordError("wrong password or modified key record");
  }
  const std::unique_ptr<Kem> kem = registry_.kem(rec.kem);
  KeyPair kp = kem->keygen_derand(*seed);
  if (!ct_equal(kp.pk, rec.pk)) {
    throw Error("the stored seed does not produce the stored public key");
  }
  record_event("key_unlocked", id, to_string(rec.status));
  return UnlockedKey{id, rec.kem, rec.status, std::move(kp.pk), std::move(kp.sk)};
}

void Keystore::retire(const KeyId& id, ByteView password) {
  try {
    transact(
        [&](const stdfs::path& stage) { set_status_in(stage, id, Status::kRetired, password); });
  } catch (const PasswordError&) {
    record_event("password_failed", id, "retire");
    throw;
  }
}

void Keystore::revoke(const KeyId& id, ByteView password) {
  try {
    transact(
        [&](const stdfs::path& stage) { set_status_in(stage, id, Status::kRevoked, password); });
  } catch (const PasswordError&) {
    record_event("password_failed", id, "revoke");
    throw;
  }
}

void Keystore::destroy(const KeyId& id) {
  transact([&](const stdfs::path& stage) { set_status_in(stage, id, Status::kDestroyed, {}); });
}

KeyId Keystore::rotate(const KeyId& id, ByteView password) {
  KeyId fresh{};
  try {
    transact([&](const stdfs::path& stage) {
      const KeyRecord old = load_record(stage, id);
      if (old.status != Status::kActive) {
        throw Error("only an active key can be rotated");
      }
      // Retiring first checks the password before any new key is generated.
      set_status_in(stage, id, Status::kRetired, password);
      fresh = create_in(stage, old.kem, old.label, password);
      open_audit(stage).append(now(), "key_rotated", key_id_hex(id), "new=" + key_id_hex(fresh));
    });
  } catch (const PasswordError&) {
    record_event("password_failed", id, "rotate");
    throw;
  }
  return fresh;
}

void Keystore::change_password(ByteView old_password, ByteView new_password) {
  if (new_password.empty()) {
    throw Error("password must not be empty");
  }
  try {
    transact([&](const stdfs::path& stage) {
      const std::unique_ptr<Aead> aead = make_aead();
      size_t changed = 0;
      for (KeyRecord& rec : load_all(stage)) {
        if (!rec.sealed) {
          continue;
        }
        const std::unique_ptr<Aead> old_aead = make_aead_for(rec);
        const std::optional<SecureBytes> seed = unseal_seed(rec, old_password, *old_aead);
        if (!seed) {
          throw PasswordError("key " + key_id_hex(rec.key_id) +
                              " does not open with the old password");
        }
        seal_seed(rec, *seed, new_password, opts_.kdf_iterations, *aead, rng_);
        write_record(stage, rec);
        ++changed;
      }
      open_audit(stage).append(now(), "password_changed", "", "keys=" + std::to_string(changed));
    });
  } catch (const PasswordError&) {
    record_event("password_failed", KeyId{}, "change_password");
    throw;
  }
}

std::vector<KeyId> Keystore::rotation_due() const {
  std::vector<KeyId> due;
  const int64_t t = now();
  for (const KeyRecord& rec : list()) {
    if (keystore::rotation_due(rec.status, rec.created, t, opts_.policy)) {
      due.push_back(rec.key_id);
    }
  }
  return due;
}

void Keystore::record_event(std::string_view event, const KeyId& id, std::string_view detail) {
  std::error_code ec;
  if (!stdfs::exists(home_, ec)) {
    return;
  }
  const fs::FileLock lock = acquire();
  if (!stdfs::exists(dir_ / kAuditKeyFile, ec)) {
    return;  // nothing has ever been created here, so there is no log to extend
  }
  const bool no_key = id == KeyId{};
  open_audit(dir_).append(now(), event, no_key ? std::string() : key_id_hex(id), detail);
}

std::vector<AuditEntry> Keystore::audit_entries() const {
  std::error_code ec;
  if (!stdfs::exists(home_, ec)) {
    return {};
  }
  const fs::FileLock lock = acquire();
  if (!stdfs::exists(dir_ / kAuditKeyFile, ec)) {
    return {};
  }
  return open_audit(dir_).read();
}

AuditVerdict Keystore::verify_audit() const {
  std::error_code ec;
  if (!stdfs::exists(home_, ec)) {
    return {};
  }
  const fs::FileLock lock = acquire();
  if (!stdfs::exists(dir_ / kAuditKeyFile, ec)) {
    return {};
  }
  return open_audit(dir_).verify();
}

}  // namespace pq::keystore
