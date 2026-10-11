#include "bench/suites.hpp"

#include <gtest/gtest.h>

#include <vector>

#include "support/test_registry.hpp"

namespace {

TEST(BenchSuites, MeasuresAllKemOperationsAndHonoursFilter) {
  const auto registry = pq::test::make_test_registry();
  pq::bench::RunOptions options;
  options.suite = "kem";
  options.filter = pq::test::DummyKem::kName;
  options.kem_iterations = 3;
  options.warmup = 1;
  std::vector<pq::bench::Result> results;
  const size_t count =
      pq::bench::run_benchmarks(registry, options, [&](const auto& r) { results.push_back(r); });
  ASSERT_EQ(count, 3U);
  EXPECT_EQ(results[0].op, "keygen");
  EXPECT_EQ(results[1].op, "encaps");
  EXPECT_EQ(results[2].op, "decaps");
  for (const auto& r : results) {
    EXPECT_EQ(r.param, pq::test::DummyKem::kName);
    EXPECT_GT(r.stats.median_ns, 0);
  }
}

TEST(BenchSuites, MeasuresCipherAndAeadThroughPublicContracts) {
  const auto registry = pq::test::make_test_registry();
  pq::bench::RunOptions options;
  options.filter = "AES-256";
  options.suite = "cipher";
  options.seconds = 0;
  options.warmup = 1;
  options.sizes.assign(1, 16);
  std::vector<pq::bench::Result> results;
  const auto consume = [&](const auto& r) { results.push_back(r); };
  EXPECT_EQ(pq::bench::run_benchmarks(registry, options, consume), 3U);
  EXPECT_EQ(results[0].op, "set_key");
  EXPECT_EQ(results[1].op, "encrypt");
  EXPECT_EQ(results[2].op, "decrypt");
  results.clear();
  options.suite = "aead";
  EXPECT_EQ(pq::bench::run_benchmarks(registry, options, consume), 2U);
  EXPECT_EQ(results[0].param, "AES-256-GCM");
  EXPECT_EQ(results[0].op, "seal");
  EXPECT_EQ(results[1].op, "open");
}

TEST(BenchSuites, MissingAlgorithmsProduceNoFakeMeasurements) {
  const pq::Registry empty;
  const pq::bench::RunOptions options;
  EXPECT_EQ(pq::bench::run_benchmarks(empty, options,
                                      [](const auto&) { ADD_FAILURE() << "unexpected row"; }),
            0U);
}

}  // namespace
