#include "keystore/rotation.hpp"

#include "hybrid/envelope.hpp"
#include "pq/error.hpp"

namespace pq::keystore {

Bytes encrypt_to_active(const Keystore& ks, const hybrid::KemDem& kd, std::string_view kem,
                        std::string_view cipher, ByteView plaintext, Rng& rng) {
  const std::optional<KeyRecord> key = ks.active_key(kem);
  if (!key) {
    throw Error("no active key for " + std::string(kem));
  }
  return kd.seal(key->kem, key->pk, cipher, plaintext, rng);
}

std::optional<SecureBytes> decrypt(Keystore& ks, const hybrid::KemDem& kd, ByteView envelope,
                                   ByteView password) {
  const hybrid::Header h = hybrid::parse_header(envelope);
  const UnlockedKey key = ks.unlock(h.b.key_id, password);
  return kd.open(key.sk, envelope);
}

Bytes rewrap_to_active(Keystore& ks, const hybrid::KemDem& kd, ByteView envelope, ByteView password,
                       std::string_view target_kem, Rng& rng) {
  const hybrid::Header h = hybrid::parse_header(envelope);
  const UnlockedKey old_key = ks.unlock(h.b.key_id, password);
  const std::string_view kem = target_kem.empty() ? std::string_view(old_key.kem) : target_kem;
  const std::optional<KeyRecord> target = ks.active_key(kem);
  if (!target) {
    throw Error("no active key for " + std::string(kem));
  }
  if (target->key_id == old_key.key_id) {
    return Bytes(envelope.begin(), envelope.end());
  }
  const std::optional<Bytes> moved = kd.rewrap(old_key.sk, target->kem, target->pk, envelope, rng);
  if (!moved) {
    throw Error("the envelope does not open with the key it names");
  }
  ks.record_event("envelope_rewrapped", old_key.key_id, "to=" + key_id_hex(target->key_id));
  return *moved;
}

}  // namespace pq::keystore
