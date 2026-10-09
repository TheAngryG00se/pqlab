#pragma once

#include <stdexcept>
#include <string>

namespace pq {

// Format errors and API misuse: wrong key length, failed ML-KEM ek modulus
// check, corrupted keystore file. The message must never contain secrets.
//
// Not used for: an invalid AEAD tag (Aead::open returns std::nullopt) and KEM
// decapsulation failure (implicit rejection returns a pseudorandom key).
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

}  // namespace pq
