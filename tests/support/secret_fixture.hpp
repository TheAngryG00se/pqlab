#pragma once

#include <string_view>

#include "pq/error.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::test {

// Only for published fixtures, never for parsing/logging live secret material.
inline SecureBytes secret_fixture(std::string_view hex) {
  if (hex.size() % 2 != 0) throw Error("fixture: odd hex length");
  const auto nibble = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    throw Error("fixture: invalid hexadecimal digit");
  };
  SecureBytes out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
  }
  return out;
}

}  // namespace pq::test
