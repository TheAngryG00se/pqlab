#include "mlkem_keygen.hpp"

#include "avalanche.hpp"
#include "pq/error.hpp"

namespace pq::analysis {

// FIPS 203, Algorithm 16. Compare d and z using the same input pairs and bit positions.
KeygenAvalanche mlkem_keygen_avalanche(const Kem& kem, uint32_t samples) {
  if (samples == 0) {
    throw Error("ML-KEM avalanche requires at least one pair");
  }
  constexpr uint32_t kHalfBytes = 32;
  constexpr uint32_t kHalfBits = kHalfBytes * 8;
  // Public replay label, exclusively for this experiment.
  constexpr std::string_view label = "pqlab/mlkem-keygen-avalanche/v1";
  const pq::Bytes replay_label(label.begin(), label.end());
  pq::DeterministicRng rng(replay_label);
  const auto sizes = kem.sizes();
  if (sizes.keygen_seed != 2 * kHalfBytes) {
    throw pq::Error("unexpected ML-KEM keygen seed size");
  }
  pq::SecureBytes seed(sizes.keygen_seed);
  KeygenAvalanche result;
  for (uint32_t sample = 0; sample < samples; ++sample) {
    rng.fill(seed.span());
    const auto reference = kem.keygen_derand(seed);
    const uint32_t bit = sample % kHalfBits;
    const auto mask = static_cast<uint8_t>(1U << (bit % 8));
    for (size_t half = 0; half < 2; ++half) {
      auto& byte = seed[half * kHalfBytes + bit / 8];
      byte ^= mask;
      const auto changed = kem.keygen_derand(seed);
      byte ^= mask;
      result[half].pk_bits += hamming_distance(reference.pk, changed.pk);
      result[half].dk_bits += hamming_distance(reference.sk, changed.sk);
    }
  }
  return result;
}

}  // namespace pq::analysis
