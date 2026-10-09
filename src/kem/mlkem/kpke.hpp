#pragma once

// K-PKE (FIPS 203, Section 5). Not a standalone scheme: used by ML-KEM and,
// without the FO transform, by the attack demonstrations in analysis/attacks/.

#include <cstdint>
#include <span>

#include "kem/mlkem/params.hpp"

namespace pq::mlkem::detail {

// FIPS 203, Algorithm 13 (K-PKE.KeyGen).
template <typename P>
void k_pke_keygen(std::span<uint8_t, Sizes<P>::kEk> ek, std::span<uint8_t, Sizes<P>::kDkPke> dk,
                  std::span<const uint8_t, 32> d);

// FIPS 203, Algorithm 14 (K-PKE.Encrypt).
template <typename P>
void k_pke_encrypt(std::span<uint8_t, Sizes<P>::kCt> c, std::span<const uint8_t, Sizes<P>::kEk> ek,
                   std::span<const uint8_t, 32> m, std::span<const uint8_t, 32> r);

// FIPS 203, Algorithm 15 (K-PKE.Decrypt).
template <typename P>
void k_pke_decrypt(std::span<uint8_t, 32> m, std::span<const uint8_t, Sizes<P>::kDkPke> dk,
                   std::span<const uint8_t, Sizes<P>::kCt> c);

}  // namespace pq::mlkem::detail
