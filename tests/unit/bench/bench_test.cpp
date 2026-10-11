#include <gtest/gtest.h>

#include <array>
#include <cmath>
#include <sstream>

#include "bench/csv.hpp"
#include "bench/measure.hpp"
#include "pq/error.hpp"

namespace {

TEST(BenchStatistics, InterpolatedPercentilesAndPopulationDeviation) {
  const std::array<pq::bench::Sample, 4> samples{{{40, 4}, {10, 1}, {30, 3}, {20, 2}}};
  const auto stats = pq::bench::summarize(samples, 16, true);
  EXPECT_DOUBLE_EQ(stats.median_cycles, 25);
  EXPECT_DOUBLE_EQ(stats.p5_cycles, 11.5);
  EXPECT_DOUBLE_EQ(stats.p95_cycles, 38.5);
  EXPECT_DOUBLE_EQ(stats.median_ns, 2.5);
  EXPECT_DOUBLE_EQ(stats.stddev_ns, std::sqrt(1.25));
  EXPECT_EQ(stats.iterations, 16U);
}

TEST(BenchStatistics, RejectsInvalidSamplesAndOmitsUnavailableCycles) {
  const std::array<pq::bench::Sample, 1> invalid{{{1, 0}}};
  EXPECT_THROW((void)pq::bench::summarize(invalid, 1, true), pq::Error);
  EXPECT_THROW((void)pq::bench::summarize({}, 0, true), pq::Error);
  const std::array<pq::bench::Sample, 1> valid{{{0, 3}}};
  EXPECT_TRUE(std::isnan(pq::bench::summarize(valid, 1, false).median_cycles));
}

TEST(BenchMeasure, WarmupIsExcludedAndBatchesCountOperations) {
  pq::bench::MeasureOptions options;
  options.warmup = 3;
  options.min_iterations = 5;
  options.batch_size = 2;
  options.min_samples = 2;
  uint64_t calls = 0;
  const auto stats = pq::bench::measure(
      [&] {
        ++calls;
        pq::bench::do_not_optimize(calls);
      },
      options);
  EXPECT_EQ(stats.iterations, 6U);
  EXPECT_EQ(calls, 9U);
}

TEST(BenchCsv, EscapesMetadataAndUsesTheProjectSchema) {
  std::ostringstream out;
  pq::bench::write_csv_header(out);
  const pq::bench::Metadata meta{"time", "hash", "CPU, \"model\"", "compiler", "flags"};
  pq::bench::Statistics stats;
  stats.iterations = 10000;
  stats.median_ns = 2.5;
  pq::bench::write_csv_row(out, meta, {"KEM", "ML-KEM-512", "encaps", 0, stats});
  EXPECT_NE(out.str().find("\"CPU, \"\"model\"\"\""), std::string::npos);
  EXPECT_NE(out.str().find(",0,10000,,,,2.5,0\n"), std::string::npos);
  EXPECT_EQ(out.str().substr(0, 9), "timestamp");
}

}  // namespace
