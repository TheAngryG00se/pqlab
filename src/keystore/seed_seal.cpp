#include "keystore/seed_seal.hpp"

#include <string>
#include <utility>

#include "hash/pbkdf2.hpp"
#include "pq/error.hpp"

namespace pq::keystore {

namespace {

SecureBytes derive_key(ByteView password, ByteView salt, uint32_t iterations, const Aead& aead) {
  if (password.empty()) {
    throw Error("password must not be empty");
  }
  SecureBytes key(aead.key_size());
  hash::pbkdf2_hmac_sha3_256(key.span(), password, salt, iterations);
  return key;
}

}  // namespace

void seal_seed(KeyRecord& rec, ByteView seed, ByteView password, uint32_t iterations, Aead& aead,
               Rng& rng) {
  if (iterations == 0) {
    throw Error("kdf iterations must be positive");
  }
  if (aead.key_size() != 32 || aead.nonce_size() != kNonceSize || aead.tag_size() != kTagSize) {
    throw Error("keystore needs a 256-bit key AEAD with a 12-byte nonce and a 16-byte tag");
  }
  SealedSeed s;
  s.kdf_iterations = iterations;
  s.salt.resize(kSaltSize);
  rng.fill(s.salt);
  s.aead = std::string(aead.name());
  s.nonce.resize(kNonceSize);
  rng.fill(s.nonce);

  const SecureBytes key = derive_key(password, s.salt, iterations, aead);
  rec.sealed = std::move(s);
  rec.sealed->ciphertext = aead.seal(key, rec.sealed->nonce, record_aad(rec), seed);
}

std::optional<SecureBytes> unseal_seed(const KeyRecord& rec, ByteView password, Aead& aead) {
  if (!rec.sealed) {
    throw Error("key has no sealed seed");
  }
  const SealedSeed& s = *rec.sealed;
  if (s.aead != aead.name()) {
    throw Error("key was sealed with a different AEAD");
  }
  const SecureBytes key = derive_key(password, s.salt, s.kdf_iterations, aead);
  return aead.open(key, s.nonce, record_aad(rec), s.ciphertext);
}

}  // namespace pq::keystore
