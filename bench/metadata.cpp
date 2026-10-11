#include "bench/metadata.hpp"

#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "bench_build_info.hpp"

namespace pq::bench {

Metadata collect_metadata() {
  std::string cpu = "unknown";
  std::ifstream cpuinfo("/proc/cpuinfo");
  for (std::string line; std::getline(cpuinfo, line);) {
    if (line.starts_with("model name")) {
      const auto pos = line.find(':');
      if (pos != std::string::npos) {
        cpu = line.substr(pos + 2);
        break;
      }
    }
  }
  const auto now = std::time(nullptr);
  std::tm utc{};
  gmtime_r(&now, &utc);
  std::ostringstream timestamp;
  timestamp << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
  return {timestamp.str(), kBuildCommit, cpu, kBuildCompiler, kBuildFlags};
}

bool release_build() { return kBuildType == "Release"; }

}  // namespace pq::bench
