#pragma once

// Password-based encryption of a KEM seed inside a KeyRecord:
//   key = PBKDF2-HMAC-SHA3-256(password, salt[16], iterations)   (32 bytes)
//   ciphertext = AEAD(key, nonce[12], AAD = record_aad(rec), seed)

#include <cstdint>
#include <optional>

#include "keystore/key_record.hpp"
#include "pq/aead.hpp"
#include "pq/rng.hpp"

namespace pq::keystore {

inline constexpr uint32_t kDefaultKdfIterations = 600000;
// A record asking for more is refused, so that a crafted file cannot hang the process.
inline constexpr uint32_t kMaxKdfIterations = 100000000;

// Throws pq::Error for an empty password, zero iterations or an AEAD whose key is not
// 32 bytes. Draws a fresh salt and nonce from rng. All metadata of rec must already be
// final, because it is authenticated; changing any of it afterwards invalidates the seal.
void seal_seed(KeyRecord& rec, ByteView seed, ByteView password, uint32_t iterations, Aead& aead,
               Rng& rng);

// std::nullopt on a wrong password or any modification of the record. Throws pq::Error
// if rec has no sealed seed or was sealed with a different AEAD than the one given.
[[nodiscard]] std::optional<SecureBytes> unseal_seed(const KeyRecord& rec, ByteView password,
                                                     Aead& aead);

}  // namespace pq::keystore
