#pragma once

#include <cstdint>
#include <span>
#include <string_view>

#include "kem/mlkem/params.hpp"
#include "pq/kem.hpp"

namespace pq::mlkem {

// ML-KEM (FIPS 203). sk is the expanded decapsulation key dk (768k + 96 bytes);
// keygen_derand takes the 64-byte seed d || z.
template <typename P>
class MlKem final : public Kem {
 public:
  using Params = P;
  using S = Sizes<P>;

  [[nodiscard]] std::string_view name() const override { return P::kName; }
  [[nodiscard]] int security_level() const override { return P::kSecurityLevel; }
  [[nodiscard]] KemSizes sizes() const override {
    return {S::kEk, S::kDk, S::kCt, S::kSs, S::kSeed, S::kMsg};
  }

  // FIPS 203, Algorithm 16 on seed = d || z. Throws pq::Error on a wrong length.
  [[nodiscard]] KeyPair keygen_derand(ByteView seed) const override;

  // FIPS 203, Algorithm 17 after the encapsulation key check of Section 7.2.
  // Throws pq::Error if pk fails the check or m is not 32 bytes.
  [[nodiscard]] Encapsulation encaps_derand(ByteView pk, ByteView m) const override;

  // FIPS 203, Algorithm 18 after the input checks of Section 7.3. Throws
  // pq::Error on wrong lengths or a failed hash check of dk. An invalid
  // ciphertext yields the implicit-rejection key J(z || c).
  [[nodiscard]] SecureBytes decaps(ByteView sk, ByteView ct) const override;

  // FIPS 203, Section 7.2 (type and modulus check).
  [[nodiscard]] static bool check_encaps_key(ByteView ek);
  // FIPS 203, Section 7.3, checks 2-3 (type and hash check).
  [[nodiscard]] static bool check_decaps_key(ByteView dk);
};

using MlKem512 = MlKem<MlKem512Params>;
using MlKem768 = MlKem<MlKem768Params>;
using MlKem1024 = MlKem<MlKem1024Params>;

extern template class MlKem<MlKem512Params>;
extern template class MlKem<MlKem768Params>;
extern template class MlKem<MlKem1024Params>;

}  // namespace pq::mlkem
