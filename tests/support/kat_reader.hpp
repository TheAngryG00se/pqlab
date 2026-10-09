#pragma once

// Reader for NIST CAVP .rsp files: "[key = value]" section headers and
// blank-line separated "key = value" records.

#include <cstdint>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace pq::test {

struct KatRecord {
  std::map<std::string, std::string> section;  // [key = value] headers in effect
  std::map<std::string, std::string> fields;
};

inline std::string kat_path(const std::string& relative) {
  return std::string(PQ_KAT_DIR) + "/" + relative;
}

inline std::string trim(const std::string& s) {
  const auto b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) {
    return {};
  }
  const auto e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

inline std::vector<KatRecord> read_rsp(const std::string& relative) {
  std::ifstream in(kat_path(relative));
  if (!in) {
    throw std::runtime_error("cannot open KAT file " + relative);
  }
  std::vector<KatRecord> out;
  std::map<std::string, std::string> section;
  KatRecord cur;
  auto flush = [&] {
    if (!cur.fields.empty()) {
      cur.section = section;
      out.push_back(std::move(cur));
      cur = {};
    }
  };
  std::string line;
  while (std::getline(in, line)) {
    line = trim(line);
    if (line.empty()) {
      flush();
      continue;
    }
    if (line[0] == '#') {
      continue;
    }
    const bool is_section = line.front() == '[' && line.back() == ']';
    if (is_section) {
      flush();
      line = line.substr(1, line.size() - 2);
    }
    const auto eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    const std::string key = trim(line.substr(0, eq));
    const std::string value = trim(line.substr(eq + 1));
    if (is_section) {
      section[key] = value;
    } else {
      cur.fields[key] = value;
    }
  }
  flush();
  return out;
}

inline std::vector<uint8_t> from_hex(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw std::runtime_error("odd hex length");
  }
  auto nibble = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    throw std::runtime_error("bad hex digit");
  };
  std::vector<uint8_t> out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
  }
  return out;
}

template <typename Container>
std::string to_hex(const Container& bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 0xF]);
  }
  return out;
}

}  // namespace pq::test
