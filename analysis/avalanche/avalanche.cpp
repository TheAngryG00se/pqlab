#include "avalanche.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>

#include "pq/error.hpp"

namespace pq::analysis {
namespace {

size_t checked_product(size_t first, size_t second) {
  if (second != 0 && first > std::numeric_limits<size_t>::max() / second) {
    throw Error("Avalanche dimensions overflow");
  }
  return first * second;
}

size_t pair_count(size_t bits) { return checked_product(bits, bits - 1) / 2; }

size_t pair_index(size_t first, size_t second, size_t bits) {
  return first * (2 * bits - first - 1) / 2 + second - first - 1;
}

void reserve_budget(size_t count, size_t width, size_t& remaining) {
  const size_t bytes = checked_product(count, width);
  if (bytes > remaining) {
    throw Error("Avalanche dimensions exceed the memory budget");
  }
  remaining -= bytes;
}

uint8_t output_bit(ByteView bytes, size_t bit) {
  return static_cast<uint8_t>((bytes[bit / 8] >> (bit & 7)) & 1U);
}

}  // namespace

double AvalancheResult::sac(size_t input_bit, size_t output_bit) const {
  if (input_bit >= input_bits || output_bit >= output_bits || samples_per_bit == 0) {
    throw Error("SAC index or sample count is invalid");
  }
  return static_cast<double>(flip_counts.at(input_bit * output_bits + output_bit)) /
         static_cast<double>(samples_per_bit);
}

double AvalancheResult::max_sac_deviation() const {
  if (samples_per_bit == 0 || flip_counts.empty()) {
    throw Error("SAC requires samples");
  }
  double maximum = 0;
  for (const uint64_t count : flip_counts) {
    maximum = std::max(
        maximum, std::abs(static_cast<double>(count) / static_cast<double>(samples_per_bit) - 0.5));
  }
  return maximum;
}

std::optional<double> AvalancheResult::bic(size_t input_bit, size_t first, size_t second) const {
  if (input_bit >= input_bits || first >= output_bits || second >= output_bits || first == second ||
      bic_correlations.empty()) {
    throw Error("BIC was not measured or indices are invalid");
  }
  if (second < first) {
    std::swap(first, second);
  }
  const double correlation = bic_correlations.at(input_bit * pair_count(output_bits) +
                                                 pair_index(first, second, output_bits));
  if (!std::isfinite(correlation)) {
    return std::nullopt;
  }
  return correlation;
}

std::optional<double> AvalancheResult::max_absolute_bic() const {
  std::optional<double> maximum;
  for (const double correlation : bic_correlations) {
    if (std::isfinite(correlation)) {
      maximum = std::max(maximum.value_or(0), std::abs(correlation));
    }
  }
  return maximum;
}

size_t hamming_distance(ByteView first, ByteView second) {
  if (first.size() != second.size()) {
    throw Error("Hamming distance requires equal lengths");
  }
  size_t distance = 0;
  for (size_t i = 0; i < first.size(); ++i) {
    distance += static_cast<size_t>(std::popcount(static_cast<uint32_t>(first[i] ^ second[i])));
  }
  return distance;
}

// Carlet, Sections 3.1.7 and 3.4.2: derivatives in unit-vector directions and SAC.
// BIC uses Pearson correlation of the two binary derivative coordinates, for each
// fixed input bit independently, never mixing different input directions.
AvalancheResult measure_avalanche(const AvalancheFunction& function, size_t input_bytes,
                                  size_t output_bytes, Rng& rng, const AvalancheOptions& options) {
  if (!function || input_bytes == 0 || output_bytes == 0 || options.samples_per_bit == 0) {
    throw Error("Avalanche requires a function, nonzero dimensions and samples");
  }
  const size_t input_bits = checked_product(input_bytes, 8);
  const size_t output_bits = checked_product(output_bytes, 8);
  // Keeps integer-to-double count conversion exact and checks the pair-count product.
  constexpr uint64_t kMaxPairs = uint64_t{1} << 53;
  if (input_bits > kMaxPairs || options.samples_per_bit > kMaxPairs / input_bits) {
    throw Error("Avalanche sample count is too large");
  }
  const size_t sac_cells = checked_product(input_bits, output_bits);
  const size_t output_pairs = options.compute_bic ? pair_count(output_bits) : 0;
  const size_t bic_cells = checked_product(input_bits, output_pairs);
  size_t memory = options.max_memory_bytes;
  reserve_budget(input_bytes, 1, memory);
  reserve_budget(output_bytes, 3, memory);
  reserve_budget(output_bits + 1, sizeof(uint64_t), memory);
  reserve_budget(sac_cells, sizeof(uint64_t), memory);
  reserve_budget(output_pairs, sizeof(uint64_t), memory);
  reserve_budget(bic_cells, sizeof(double), memory);

  AvalancheResult result;
  result.input_bits = input_bits;
  result.output_bits = output_bits;
  result.samples_per_bit = options.samples_per_bit;
  result.pairs = static_cast<uint64_t>(input_bits) * options.samples_per_bit;
  result.hamming_histogram.resize(output_bits + 1);
  result.flip_counts.resize(sac_cells);
  result.bic_correlations.resize(bic_cells);
  std::vector<uint64_t> joint_counts(output_pairs);
  SecureBytes input(input_bytes);
  Bytes difference(output_bytes);
  double m2 = 0;
  uint64_t observed = 0;
  for (size_t i = 0; i < input_bits; ++i) {
    std::fill(joint_counts.begin(), joint_counts.end(), 0);
    const size_t row = i * output_bits;
    for (uint64_t sample = 0; sample < options.samples_per_bit; ++sample) {
      rng.fill(input.span());
      const Bytes before = function(input);
      input[i / 8] ^= static_cast<uint8_t>(1U << (i & 7));
      const Bytes after = function(input);
      if (before.size() != output_bytes || after.size() != output_bytes) {
        throw Error("Avalanche function returned an unexpected output length");
      }
      for (size_t byte = 0; byte < output_bytes; ++byte) {
        difference[byte] = before[byte] ^ after[byte];
      }
      const size_t distance = hamming_distance(before, after);
      ++result.hamming_histogram[distance];
      ++observed;
      const double delta = static_cast<double>(distance) - result.mean;
      result.mean += delta / static_cast<double>(observed);
      m2 += delta * (static_cast<double>(distance) - result.mean);
      for (size_t j = 0; j < output_bits; ++j) {
        result.flip_counts[row + j] += output_bit(difference, j);
      }
      if (options.compute_bic) {
        size_t pair = 0;
        for (size_t j = 0; j < output_bits; ++j) {
          const uint8_t first = output_bit(difference, j);
          for (size_t k = j + 1; k < output_bits; ++k) {
            joint_counts[pair++] += first & output_bit(difference, k);
          }
        }
      }
    }
    if (options.compute_bic) {
      const double count = static_cast<double>(options.samples_per_bit);
      size_t pair = 0;
      for (size_t j = 0; j < output_bits; ++j) {
        const double first = static_cast<double>(result.flip_counts[row + j]) / count;
        for (size_t k = j + 1; k < output_bits; ++k) {
          const double second = static_cast<double>(result.flip_counts[row + k]) / count;
          const double denominator = std::sqrt(first * (1 - first) * second * (1 - second));
          result.bic_correlations[i * output_pairs + pair] =
              denominator == 0
                  ? std::numeric_limits<double>::quiet_NaN()
                  : std::clamp((static_cast<double>(joint_counts[pair]) / count - first * second) /
                                   denominator,
                               -1.0, 1.0);
          ++pair;
        }
      }
    }
  }
  result.variance = m2 / static_cast<double>(observed);
  return result;
}

ChiSquare binomial_chi_square(const AvalancheResult& result) {
  if (result.output_bits == 0 || result.pairs < 10 ||
      result.hamming_histogram.size() != result.output_bits + 1) {
    throw Error("Binomial comparison requires a histogram and at least ten pairs");
  }
  uint64_t total = 0;
  for (const uint64_t count : result.hamming_histogram) {
    if (count > result.pairs - total) {
      throw Error("Hamming histogram does not match the pair count");
    }
    total += count;
  }
  if (total != result.pairs) {
    throw Error("Hamming histogram does not match the pair count");
  }
  const double n = static_cast<double>(result.output_bits);
  double observed = 0;
  double expected = 0;
  double previous_observed = 0;
  double previous_expected = 0;
  ChiSquare score;
  const auto term = [](double obs, double exp) { return (obs - exp) * (obs - exp) / exp; };
  for (size_t k = 0; k <= result.output_bits; ++k) {
    const double kd = static_cast<double>(k);
    expected +=
        static_cast<double>(result.pairs) * std::exp(std::lgamma(n + 1) - std::lgamma(kd + 1) -
                                                     std::lgamma(n - kd + 1) - n * std::log(2.0));
    observed += static_cast<double>(result.hamming_histogram[k]);
    if (expected >= 5) {
      score.statistic += term(observed, expected);
      ++score.bins;
      previous_observed = observed;
      previous_expected = expected;
      observed = 0;
      expected = 0;
    }
  }
  if (score.bins == 0) {
    throw Error("Insufficient expected counts for a binomial comparison");
  }
  // Merge the final sparse tail with the previous complete bin.
  score.statistic -= term(previous_observed, previous_expected);
  score.statistic += term(previous_observed + observed, previous_expected + expected);
  score.degrees_of_freedom = score.bins - 1;
  return score;
}

}  // namespace pq::analysis
