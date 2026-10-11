#pragma once

// Hybrid encryption (KEM-DEM) with a separate data key, in the PQL1 envelope
// format (see envelope.hpp and AGENTS.md, section 10).
//
//   seal:   (K, ct_kem) = Encaps(pk);  KEK = HKDF(K, salt = ct_kem, info);
//           DEK random, wrapped under KEK; data encrypted under DEK in 64 KiB chunks.
//   rewrap: DEK = unwrap(Decaps(old sk)); new Encaps; new part B. Part A and the data
//           stay byte for byte the same.

#include <optional>
#include <string_view>

#include "pq/registry.hpp"
#include "pq/rng.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::hybrid {

class KemDem {
 public:
  // Algorithms come from the registry only. The AEAD is always "<cipher>-GCM".
  explicit KemDem(const Registry& registry = Registry::global()) : registry_(registry) {}

  // Throws pq::Error for unknown algorithms, a pk that fails the KEM input checks,
  // or an AEAD that does not fit the format (12-byte nonce, 16-byte tag, key <= 32).
  [[nodiscard]] Bytes seal(std::string_view kem, ByteView pk, std::string_view cipher,
                           ByteView plaintext, Rng& rng) const;

  // sk is the expanded decapsulation key of the KEM named in the envelope.
  // Throws pq::Error if the envelope is malformed or sk has the wrong length.
  // Returns std::nullopt if anything fails authentication: wrong key (the KEM
  // rejects implicitly, so the KEK is wrong), modified header or data, a
  // reordered, truncated or extended chunk sequence.
  [[nodiscard]] std::optional<SecureBytes> open(ByteView sk, ByteView envelope) const;

  // New envelope for the new recipient; the data part is copied unchanged.
  // std::nullopt if old_sk does not unwrap the DEK. Does not check the data tags.
  [[nodiscard]] std::optional<Bytes> rewrap(ByteView old_sk, std::string_view new_kem,
                                            ByteView new_pk, ByteView envelope, Rng& rng) const;

 private:
  const Registry& registry_;
};

}  // namespace pq::hybrid
