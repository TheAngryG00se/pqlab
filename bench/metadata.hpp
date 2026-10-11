#pragma once

#include "bench/csv.hpp"

namespace pq::bench {

[[nodiscard]] Metadata collect_metadata();
[[nodiscard]] bool release_build();

}  // namespace pq::bench
