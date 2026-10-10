#include "keystore/key_record.hpp"

#include <algorithm>
#include <initializer_list>
#include <nlohmann/json.hpp>

#include "core/endian.hpp"
#include "hybrid/envelope.hpp"
#include "keystore/hex.hpp"
#include "pq/error.hpp"

namespace pq::keystore {

namespace {

using Json = nlohmann::json;

constexpr std::string_view kAadMagic = "pqlab-keyrecord-v1";
constexpr std::string_view kKdfName = "PBKDF2-HMAC-SHA3-256";

void put_u32(Bytes& out, uint32_t v) {
  std::array<uint8_t, 4> b{};
  store32_be(b.data(), v);
  out.insert(out.end(), b.begin(), b.end());
}

void put_i64(Bytes& out, int64_t v) {
  std::array<uint8_t, 8> b{};
  store64_be(b.data(), static_cast<uint64_t>(v));
  out.insert(out.end(), b.begin(), b.end());
}

// Length-prefixed field, so that field boundaries are unambiguous.
void put_field(Bytes& out, ByteView v) {
  put_u32(out, static_cast<uint32_t>(v.size()));
  out.insert(out.end(), v.begin(), v.end());
}

void put_field(Bytes& out, std::string_view v) {
  put_field(out, ByteView(reinterpret_cast<const uint8_t*>(v.data()), v.size()));
}

const Json& field(const Json& j, const char* name) {
  const auto it = j.find(name);
  if (it == j.end()) {
    throw Error(std::string("key record: missing field '") + name + "'");
  }
  return *it;
}

std::string str_field(const Json& j, const char* name) {
  const Json& v = field(j, name);
  if (!v.is_string()) {
    throw Error(std::string("key record: field '") + name + "' must be a string");
  }
  return v.get<std::string>();
}

int64_t int_field(const Json& j, const char* name) {
  const Json& v = field(j, name);
  if (!v.is_number_integer()) {
    throw Error(std::string("key record: field '") + name + "' must be an integer");
  }
  return v.get<int64_t>();
}

Bytes hex_field(const Json& j, const char* name, size_t expect_size = 0) {
  Bytes b = from_hex(str_field(j, name));
  if (expect_size != 0 && b.size() != expect_size) {
    throw Error(std::string("key record: field '") + name + "' has the wrong length");
  }
  return b;
}

// Fields outside the AAD would be unauthenticated, so unknown ones are refused.
void require_only(const Json& j, std::initializer_list<std::string_view> allowed,
                  const char* what) {
  for (const auto& item : j.items()) {
    if (std::find(allowed.begin(), allowed.end(), item.key()) == allowed.end()) {
      throw Error(std::string("key record: unknown field in ") + what);
    }
  }
}

SealedSeed parse_sealed(const Json& j) {
  if (!j.is_object()) {
    throw Error("key record: 'sealed' must be an object");
  }
  require_only(j, {"kdf", "kdf_iterations", "salt", "aead", "nonce", "ciphertext"}, "'sealed'");
  if (str_field(j, "kdf") != kKdfName) {
    throw Error("key record: unsupported KDF");
  }
  SealedSeed s;
  const int64_t iters = int_field(j, "kdf_iterations");
  if (iters < 1 || iters > 0xFFFFFFFFLL) {
    throw Error("key record: bad kdf_iterations");
  }
  s.kdf_iterations = static_cast<uint32_t>(iters);
  s.salt = hex_field(j, "salt", kSaltSize);
  s.aead = str_field(j, "aead");
  s.nonce = hex_field(j, "nonce", kNonceSize);
  s.ciphertext = hex_field(j, "ciphertext");
  if (s.ciphertext.size() <= kTagSize) {
    throw Error("key record: ciphertext too short");
  }
  return s;
}

}  // namespace

std::string key_id_hex(const KeyId& id) { return to_hex(id); }

KeyId parse_key_id(std::string_view s) {
  if (s.size() != 2 * std::tuple_size_v<KeyId>) {
    throw Error("key id must be 32 hex digits");
  }
  const Bytes b = from_hex(s);
  KeyId id{};
  std::copy(b.begin(), b.end(), id.begin());
  return id;
}

std::string serialize_record(const KeyRecord& rec) {
  Json j;
  j["version"] = rec.version;
  j["key_id"] = key_id_hex(rec.key_id);
  j["label"] = rec.label;
  j["kem"] = rec.kem;
  j["status"] = std::string(to_string(rec.status));
  j["created"] = rec.created;
  j["status_changed"] = rec.status_changed;
  j["pk"] = to_hex(rec.pk);
  if (rec.sealed) {
    Json s;
    s["kdf"] = std::string(kKdfName);
    s["kdf_iterations"] = rec.sealed->kdf_iterations;
    s["salt"] = to_hex(rec.sealed->salt);
    s["aead"] = rec.sealed->aead;
    s["nonce"] = to_hex(rec.sealed->nonce);
    s["ciphertext"] = to_hex(rec.sealed->ciphertext);
    j["sealed"] = std::move(s);
  }
  return j.dump(2) + "\n";
}

KeyRecord parse_record(std::string_view text) {
  Json j = Json::parse(text, nullptr, /*allow_exceptions=*/false);
  if (j.is_discarded() || !j.is_object()) {
    throw Error("key record: not a JSON object");
  }
  require_only(j, {"version", "key_id", "label", "kem", "status", "created", "status_changed", "pk",
                   "sealed"},
               "record");
  KeyRecord rec;
  const int64_t version = int_field(j, "version");
  if (version != kRecordVersion) {
    throw Error("key record: unsupported version");
  }
  rec.version = kRecordVersion;
  rec.key_id = parse_key_id(str_field(j, "key_id"));
  rec.label = str_field(j, "label");
  if (rec.label.size() > kMaxLabelSize) {
    throw Error("key record: label too long");
  }
  rec.kem = str_field(j, "kem");
  rec.status = parse_status(str_field(j, "status"));
  rec.created = int_field(j, "created");
  rec.status_changed = int_field(j, "status_changed");
  rec.pk = hex_field(j, "pk");
  if (rec.pk.empty() || hybrid::compute_key_id(rec.pk) != rec.key_id) {
    throw Error("key record: key_id does not match pk");
  }
  if (j.contains("sealed")) {
    rec.sealed = parse_sealed(j["sealed"]);
  }

  const bool needs_seed = rec.status == Status::kActive || rec.status == Status::kRetired;
  if ((needs_seed && !rec.sealed) || (rec.status == Status::kDestroyed && rec.sealed)) {
    throw Error("key record: status contradicts the sealed seed");
  }
  return rec;
}

Bytes record_aad(const KeyRecord& rec) {
  if (!rec.sealed) {
    throw Error("record_aad: record has no sealed seed");
  }
  Bytes out;
  put_field(out, kAadMagic);
  put_u32(out, rec.version);
  put_field(out, rec.key_id);
  put_field(out, rec.label);
  put_field(out, rec.kem);
  put_field(out, to_string(rec.status));
  put_i64(out, rec.created);
  put_i64(out, rec.status_changed);
  put_field(out, rec.pk);
  put_u32(out, rec.sealed->kdf_iterations);
  put_field(out, rec.sealed->salt);
  put_field(out, rec.sealed->aead);
  put_field(out, rec.sealed->nonce);
  return out;
}

}  // namespace pq::keystore
