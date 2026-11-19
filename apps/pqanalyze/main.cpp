#include <charconv>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string_view>

#include "analysis/avalanche/mlkem_keygen.hpp"
#include "pq/error.hpp"
#include "pq/registry.hpp"

namespace {

uint32_t parse_samples(std::string_view value) {
  uint32_t samples = 0;
  const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), samples);
  if (error != std::errc{} || end != value.data() + value.size() || samples == 0) {
    throw pq::Error("--samples expects a positive 32-bit integer");
  }
  return samples;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    uint32_t samples = 256;
    std::filesystem::path output;
    for (int i = 1; i < argc; ++i) {
      const std::string_view option(argv[i]);
      if (option == "--help" || option == "-h") {
        std::cout << "pqanalyze [--samples N] [--output FILE.csv]\n"
                     "ML-KEM keygen avalanche: paired one-bit changes in d and z.\n"
                     "Default: 256 pairs per component, one per input bit; CSV to stdout.\n";
        return 0;
      }
      if (i + 1 == argc) {
        throw pq::Error("missing option value");
      }
      if (option == "--samples") {
        samples = parse_samples(argv[++i]);
      } else if (option == "--output") {
        output = argv[++i];
      } else {
        throw pq::Error("unknown option: " + std::string(option));
      }
    }
    std::ostringstream csv;
    csv << std::setprecision(12)
        << "kem,component,output,samples,input_bits,output_bits,mean_changed_bits\n";
    const auto& registry = pq::Registry::global();
    for (const auto name : {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
      const auto kem = registry.kem(name);
      const auto result = pq::analysis::mlkem_keygen_avalanche(*kem, samples);
      for (size_t half = 0; half < result.size(); ++half) {
        const auto emit = [&](std::string_view output_name, size_t bytes, uint64_t distance) {
          csv << name << ',' << (half == 0 ? 'd' : 'z') << ',' << output_name << ',' << samples
              << ",256," << bytes * 8 << ',' << static_cast<double>(distance) / samples << '\n';
        };
        emit("pk", kem->sizes().pk, result[half].pk_bits);
        emit("dk", kem->sizes().sk, result[half].dk_bits);
      }
    }
    if (output.empty()) {
      std::cout << csv.str();
    } else {
      if (output.has_parent_path()) {
        std::filesystem::create_directories(output.parent_path());
      }
      std::ofstream file;
      file.exceptions(std::ios::failbit | std::ios::badbit);
      file.open(output);
      file << csv.str();
      file.close();
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "pqanalyze: " << error.what() << '\n';
    return 1;
  }
}
