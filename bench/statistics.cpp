#include "bench/statistics.hpp"

#include <algorithm>
#include <cmath>
#include <vector>

#include "pq/error.hpp"

namespace pq::bench {
namespace {

double percentile(const std::vector<double>& sorted, double p) {
  const double pos = p * static_cast<double>(sorted.size() - 1);
  const auto lo = static_cast<size_t>(pos);
  const size_t hi = std::min(lo + 1, sorted.size() - 1);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - static_cast<double>(lo));
}

}  // namespace

Statistics summarize(std::span<const Sample> samples, uint64_t iterations, bool has_cycles) {
  if (samples.empty() || iterations < samples.size()) {
    throw Error("benchmark: empty samples or invalid iteration count");
  }
  std::vector<double> ns;
  std::vector<double> cycles;
  ns.reserve(samples.size());
  cycles.reserve(samples.size());
  double mean = 0;
  double m2 = 0;
  for (const auto& s : samples) {
    if (!std::isfinite(s.ns) || s.ns <= 0 ||
        (has_cycles && (!std::isfinite(s.cycles) || s.cycles <= 0))) {
      throw Error("benchmark: non-positive or non-finite timing sample");
    }
    ns.push_back(s.ns);
    cycles.push_back(s.cycles);
    const double delta = s.ns - mean;
    mean += delta / static_cast<double>(ns.size());
    m2 += delta * (s.ns - mean);
  }
  std::sort(ns.begin(), ns.end());
  Statistics out;
  out.iterations = iterations;
  out.median_ns = percentile(ns, 0.5);
  out.stddev_ns = std::sqrt(std::max(0.0, m2 / static_cast<double>(ns.size())));
  if (has_cycles) {
    std::sort(cycles.begin(), cycles.end());
    out.median_cycles = percentile(cycles, 0.5);
    out.p5_cycles = percentile(cycles, 0.05);
    out.p95_cycles = percentile(cycles, 0.95);
  }
  return out;
}

}  // namespace pq::bench
