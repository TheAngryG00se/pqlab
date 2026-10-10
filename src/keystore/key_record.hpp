#pragma once

// One key of the keystore = one JSON file `<key_id hex>.json`.
//
// The secret key is stored as its KEM seed (ML-KEM: d || z, 64 bytes), encrypted with
// AES-256-GCM under PBKDF2-HMAC-SHA3-256(password, salt, iterations). The AAD is every
// field of the record except the ciphertext itself (record_aad), so metadata cannot be
// edited without the password.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "keystore/policy.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::keystore {

inline constexpr uint32_t kRecordVersion = 1;
inline constexpr size_t kSaltSize = 16;
inline constexpr size_t kNonceSize = 12;
inline constexpr size_t kTagSize = 16;
inline constexpr size_t kMaxLabelSize = 256;

using KeyId = std::array<uint8_t, 16>;

struct SealedSeed {
  uint32_t kdf_iterations = 0;
  Bytes salt;
  std::string aead;  // "AES-256-GCM"
  Bytes nonce;
  Bytes ciphertext;  // encrypted seed || tag
};

struct KeyRecord {
  uint32_t version = kRecordVersion;
  KeyId key_id{};
  std::string label;
  std::string kem;  // canonical registry name
  Status status = Status::kActive;
  int64_t created = 0;         // Unix seconds
  int64_t status_changed = 0;  // Unix seconds
  Bytes pk;
  // Present for active and retired keys, optional for revoked, absent once destroyed.
  std::optional<SealedSeed> sealed;
};

[[nodiscard]] std::string key_id_hex(const KeyId& id);
// Throws pq::Error unless s is exactly 32 lowercase hex digits.
[[nodiscard]] KeyId parse_key_id(std::string_view s);

// JSON text of the record (pretty-printed, ends with a newline).
[[nodiscard]] std::string serialize_record(const KeyRecord& rec);

// Throws pq::Error for malformed JSON, missing or mistyped fields, wrong sizes, an
// unsupported version, a key_id that is not SHA3-256(pk)[0..16], or a status that
// contradicts the presence of the sealed seed.
[[nodiscard]] KeyRecord parse_record(std::string_view json);

// Canonical binary encoding of everything but the ciphertext. Requires rec.sealed.
[[nodiscard]] Bytes record_aad(const KeyRecord& rec);

}  // namespace pq::keystore
