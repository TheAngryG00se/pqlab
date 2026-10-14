#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "pq/rng.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::analysis {

using AvalancheFunction = std::function<Bytes(ByteView)>;

struct AvalancheOptions {
  uint64_t samples_per_bit = 1024;
  bool compute_bic = false;
  size_t max_memory_bytes = 64 * 1024 * 1024;
};

struct ChiSquare {
  double statistic = 0;
  size_t degrees_of_freedom = 0;
  size_t bins = 0;
};

struct AvalancheResult {
  size_t input_bits = 0;
  size_t output_bits = 0;
  uint64_t samples_per_bit = 0;
  uint64_t pairs = 0;
  double mean = 0;
  double variance = 0;
  std::vector<uint64_t> hamming_histogram;
  // Input-major: [input_bit * output_bits + output_bit].
  std::vector<uint64_t> flip_counts;
  // Input-major upper triangles, j < k. NaN means a constant avalanche variable.
  // Empty unless compute_bic was requested. Use bic() for checked access.
  std::vector<double> bic_correlations;

  [[nodiscard]] double sac(size_t input_bit, size_t output_bit) const;
  [[nodiscard]] double max_sac_deviation() const;
  [[nodiscard]] std::optional<double> bic(size_t input_bit, size_t first, size_t second) const;
  [[nodiscard]] std::optional<double> max_absolute_bic() const;
};

// Numbering: byte 0 least-significant bit is bit 0, then bit 1, ..., byte 1 bit 0.
// Each pair uses a fresh random input. The function must be deterministic and return
// public observations (ciphertexts, public keys), never secret keys/shared secrets.
// Captured keys, IVs and coins must stay fixed throughout the experiment.
[[nodiscard]] AvalancheResult measure_avalanche(const AvalancheFunction& function,
                                                size_t input_bytes, size_t output_bytes, Rng& rng,
                                                const AvalancheOptions& options = {});

[[nodiscard]] size_t hamming_distance(ByteView first, ByteView second);

// Descriptive comparison to Binomial(output_bits, 1/2). Adjacent bins are pooled
// until their expected counts reach 5. A p-value/independence claim is not made.
[[nodiscard]] ChiSquare binomial_chi_square(const AvalancheResult& result);

}  // namespace pq::analysis
