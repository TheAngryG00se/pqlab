#pragma once

#include <cstddef>
#include <string_view>

#include "pq/rng.hpp"
#include "pq/secure_bytes.hpp"

namespace pq {

struct KemSizes {
  size_t pk;           // public (encapsulation) key
  size_t sk;           // expanded secret (decapsulation) key
  size_t ct;           // ciphertext
  size_t ss;           // shared secret K
  size_t keygen_seed;  // randomness consumed by keygen_derand (ML-KEM: d || z = 64)
  size_t encaps_seed;  // randomness consumed by encaps_derand (ML-KEM: m = 32)
};

struct KeyPair {
  Bytes pk;
  SecureBytes sk;
};

struct Encapsulation {
  Bytes ct;
  SecureBytes ss;
};

class Kem {
 public:
  virtual ~Kem() = default;

  [[nodiscard]] virtual std::string_view name() const = 0;  // "ML-KEM-768", "HQC-1"
  [[nodiscard]] virtual int security_level() const = 0;     // NIST category 1/3/5
  [[nodiscard]] virtual KemSizes sizes() const = 0;

  // Deterministic API: KAT, avalanche analysis, keystore (sk is stored as seed).
  // Throw pq::Error if a buffer length is wrong or pk fails the input checks.
  [[nodiscard]] virtual KeyPair keygen_derand(ByteView seed) const = 0;
  [[nodiscard]] virtual Encapsulation encaps_derand(ByteView pk, ByteView m) const = 0;

  // Throws pq::Error on wrong lengths or a malformed sk. A ciphertext that fails
  // re-encryption is NOT an error: a pseudorandom K is returned (implicit rejection).
  [[nodiscard]] virtual SecureBytes decaps(ByteView sk, ByteView ct) const = 0;

  // Thin wrappers that draw the seed from rng.
  [[nodiscard]] KeyPair keygen(Rng& rng) const {
    SecureBytes seed(sizes().keygen_seed);
    rng.fill(seed.span());
    return keygen_derand(seed);
  }

  [[nodiscard]] Encapsulation encaps(ByteView pk, Rng& rng) const {
    SecureBytes m(sizes().encaps_seed);
    rng.fill(m.span());
    return encaps_derand(pk, m);
  }
};

}  // namespace pq
