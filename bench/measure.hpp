#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "bench/statistics.hpp"
#include "bench/timer.hpp"
#include "pq/error.hpp"

namespace pq::bench {

struct MeasureOptions {
  uint64_t min_iterations = 10000;
  std::chrono::nanoseconds min_time{0};
  uint32_t warmup = 100;
  uint32_t batch_size = 1;
  uint32_t min_samples = 30;
  size_t max_samples = 200000;
};

// A sample is the per-operation average of a fixed batch. Allocation/sorting of
// timing data is outside the timed region; allocations in the measured API count.
template <typename Operation>
[[nodiscard]] Statistics measure(Operation&& operation, const MeasureOptions& options) {
  if (options.min_iterations == 0 || options.batch_size == 0 || options.min_samples == 0 ||
      options.max_samples < options.min_samples || options.min_time.count() < 0) {
    throw Error("benchmark: invalid measurement options");
  }
  for (uint32_t i = 0; i < options.warmup; ++i) {
    operation();
  }
  std::vector<Sample> samples;
  samples.reserve(options.max_samples);
  uint64_t iterations = 0;
  std::chrono::nanoseconds measured_time{0};
  while (iterations < options.min_iterations || measured_time < options.min_time ||
         samples.size() < options.min_samples) {
    if (samples.size() == options.max_samples) {
      throw Error("benchmark: sample capacity exceeded; increase batch size");
    }
    const auto start_ns = std::chrono::steady_clock::now();
    const uint64_t start_cycles = read_cycles();
    for (uint32_t i = 0; i < options.batch_size; ++i) {
      operation();
    }
    const uint64_t end_cycles = read_cycles();
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - start_ns);
    measured_time += elapsed;
    const double batch = options.batch_size;
    samples.push_back(
        {static_cast<double>(end_cycles - start_cycles) / batch, elapsed.count() / batch});
    iterations += options.batch_size;
  }
  return summarize(samples, iterations, kHasCycles);
}

}  // namespace pq::bench
