#include <algorithm>
#include <charconv>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>

#include "bench/metadata.hpp"
#include "bench/suites.hpp"
#include "pq/error.hpp"

namespace {

uint64_t integer(std::string_view value) {
  uint64_t out = 0;
  const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), out);
  if (error != std::errc{} || end != value.data() + value.size()) {
    throw pq::Error("expected an unsigned integer");
  }
  return out;
}

void help() {
  std::cout << "pqbench --suite all|kem|cipher|aead|hybrid [--filter NAME]\n"
               "        [--iterations N>=10000] [--seconds N>=1] [--warmup N]\n"
               "        [--sizes 16,256,4096,65536,1048576] [--output FILE.csv]\n"
               "pqbench --list\n\n"
               "Measurements require a Release build. Missing algorithms are skipped.\n"
               "KEM randomness is prepared outside timing. Hybrid includes SystemRng.\n";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    pq::bench::RunOptions options;
    std::filesystem::path output;
    bool list = false;
    for (int i = 1; i < argc; ++i) {
      const std::string_view arg(argv[i]);
      if (arg == "--help" || arg == "-h") {
        help();
        return 0;
      }
      if (arg == "--list") {
        list = true;
        continue;
      }
      if (i + 1 == argc) {
        throw pq::Error("missing option value");
      }
      const std::string value(argv[++i]);
      if (arg == "--suite") {
        options.suite = value;
      } else if (arg == "--filter") {
        options.filter = value;
      } else if (arg == "--output") {
        output = value;
      } else if (arg == "--iterations") {
        options.kem_iterations = integer(value);
      } else if (arg == "--seconds") {
        size_t parsed = 0;
        options.seconds = std::stod(value, &parsed);
        if (parsed != value.size()) {
          throw pq::Error("invalid duration");
        }
      } else if (arg == "--warmup") {
        const auto warmup = integer(value);
        if (warmup > std::numeric_limits<uint32_t>::max()) {
          throw pq::Error("warmup is too large");
        }
        options.warmup = static_cast<uint32_t>(warmup);
      } else if (arg == "--sizes") {
        options.sizes.clear();
        size_t start = 0;
        do {
          const auto end = value.find(',', start);
          const auto size = integer(std::string_view(value).substr(start, end - start));
          if (size == 0 || size > 64 * 1024 * 1024) {
            throw pq::Error("message sizes must be between 1 byte and 64 MiB");
          }
          options.sizes.push_back(static_cast<size_t>(size));
          if (end == std::string::npos) {
            break;
          }
          start = end + 1;
        } while (true);
      } else {
        throw pq::Error("unknown option: " + std::string(arg));
      }
    }
    if (options.suite != "all" && options.suite != "kem" && options.suite != "cipher" &&
        options.suite != "aead" && options.suite != "hybrid") {
      throw pq::Error("unknown benchmark suite");
    }
    if (options.kem_iterations < 10000 || !std::isfinite(options.seconds) || options.seconds < 1 ||
        options.seconds > 3600) {
      throw pq::Error("require iterations >= 10000 and seconds between 1 and 3600");
    }
    std::sort(options.sizes.begin(), options.sizes.end());
    if (std::adjacent_find(options.sizes.begin(), options.sizes.end()) != options.sizes.end()) {
      throw pq::Error("message sizes must not contain duplicates");
    }
    const auto& registry = pq::Registry::global();
    if (list) {
      for (const auto& name : registry.list_kems()) {
        std::cout << "KEM    " << name << '\n';
      }
      for (const auto& name : registry.list_ciphers()) {
        std::cout << "cipher " << name << '\n';
        for (const auto& mode : registry.list_modes()) {
          std::cout << "AEAD   " << name << '-' << mode << '\n';
        }
      }
      return 0;
    }
    if (!pq::bench::release_build()) {
      throw pq::Error("measurements require cmake --preset release and its Release build");
    }
    if (registry.list_ciphers().empty()) {
      std::cerr << "No block ciphers registered; cipher, AEAD and hybrid suites unavailable.\n";
    }
    const auto metadata = pq::bench::collect_metadata();
    if (output.empty()) {
      std::string stamp = metadata.timestamp;
      for (auto& c : stamp) {
        if (c == ':') {
          c = '-';
        }
      }
      output = std::filesystem::path("results") / stamp.substr(0, 10) / ("bench-" + stamp + ".csv");
      if (std::filesystem::exists(output)) {
        throw pq::Error("default output already exists; choose --output");
      }
    }
    std::ofstream csv;
    const auto rows = pq::bench::run_benchmarks(registry, options, [&](const auto& result) {
      if (!csv.is_open()) {
        if (output.has_parent_path()) {
          std::filesystem::create_directories(output.parent_path());
        }
        csv.open(output);
        if (!csv) {
          throw pq::Error("cannot open benchmark output");
        }
        pq::bench::write_csv_header(csv);
      }
      pq::bench::write_csv_row(csv, metadata, result);
      std::cerr << result.param << ' ' << result.op << " [" << result.msg_bytes
                << " B]: " << result.stats.median_ns / 1000 << " us, " << result.stats.iterations
                << " operations\n";
    });
    if (rows == 0) {
      throw pq::Error("no registered algorithms match the selected suite/filter");
    }
    std::cout << "Saved " << rows << " measurements to " << output.string() << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "pqbench: " << error.what() << '\n';
    return 1;
  }
}
