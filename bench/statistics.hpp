#pragma once

#include <cstdint>
#include <limits>
#include <span>

namespace pq::bench {

struct Sample {
  double cycles;
  double ns;
};

struct Statistics {
  uint64_t iterations = 0;
  double median_cycles = std::numeric_limits<double>::quiet_NaN();
  double p5_cycles = std::numeric_limits<double>::quiet_NaN();
  double p95_cycles = std::numeric_limits<double>::quiet_NaN();
  double median_ns = 0;
  double stddev_ns = 0;
};

// Percentiles use linear interpolation at p * (n - 1); stddev is population stddev.
[[nodiscard]] Statistics summarize(std::span<const Sample> samples, uint64_t iterations,
                                   bool has_cycles);

}  // namespace pq::bench
