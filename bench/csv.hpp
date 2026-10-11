#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>

#include "bench/statistics.hpp"

namespace pq::bench {

struct Metadata {
  std::string timestamp;
  std::string commit;
  std::string cpu;
  std::string compiler;
  std::string flags;
};

struct Result {
  std::string primitive;
  std::string param;
  std::string op;
  size_t msg_bytes;
  Statistics stats;
};

void write_csv_header(std::ostream& out);
void write_csv_row(std::ostream& out, const Metadata& metadata, const Result& result);

}  // namespace pq::bench
