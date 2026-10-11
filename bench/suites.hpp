#pragma once

#include <functional>
#include <string>
#include <vector>

#include "bench/csv.hpp"
#include "pq/registry.hpp"

namespace pq::bench {

struct RunOptions {
  std::string suite = "all";
  std::string filter;
  uint64_t kem_iterations = 10000;
  double seconds = 1;
  uint32_t warmup = 100;
  std::vector<size_t> sizes{16, 256, 4096, 65536, 1048576};
};

// Inject a registry in unit tests; the application only uses Registry::global().
// Missing algorithms produce no rows. A registered algorithm's error propagates.
size_t run_benchmarks(const Registry& registry, const RunOptions& options,
                      const std::function<void(const Result&)>& consume);

}  // namespace pq::bench
