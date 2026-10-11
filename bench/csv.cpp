#include "bench/csv.hpp"

#include <cmath>
#include <iomanip>
#include <locale>
#include <ostream>

#include "pq/error.hpp"

namespace pq::bench {
namespace {

void text_field(std::ostream& out, const std::string& value) {
  out << '"';
  for (const char c : value) {
    if (c == '"') {
      out << '"';
    }
    out << c;
  }
  out << '"';
}

void number_field(std::ostream& out, double value) {
  if (std::isfinite(value)) {
    out << value;
  }
}

}  // namespace

void write_csv_header(std::ostream& out) {
  out << "timestamp,commit,cpu,compiler,flags,primitive,param,op,msg_bytes,iterations,"
         "median_cycles,p5_cycles,p95_cycles,median_ns,stddev_ns\n";
  if (!out) {
    throw Error("benchmark: failed to write CSV header");
  }
}

void write_csv_row(std::ostream& out, const Metadata& m, const Result& r) {
  out.imbue(std::locale::classic());
  out << std::setprecision(12);
  for (const auto* field :
       {&m.timestamp, &m.commit, &m.cpu, &m.compiler, &m.flags, &r.primitive, &r.param, &r.op}) {
    text_field(out, *field);
    out << ',';
  }
  out << r.msg_bytes << ',' << r.stats.iterations << ',';
  number_field(out, r.stats.median_cycles);
  out << ',';
  number_field(out, r.stats.p5_cycles);
  out << ',';
  number_field(out, r.stats.p95_cycles);
  out << ',' << r.stats.median_ns << ',' << r.stats.stddev_ns << '\n';
  out.flush();
  if (!out) {
    throw Error("benchmark: failed to write CSV row");
  }
}

}  // namespace pq::bench
