#pragma once

#include <string>
#include <string_view>

#include "pq/error.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::keystore {

// Lowercase hex. Only for public data (key ids, public keys, ciphertexts).
[[nodiscard]] inline std::string to_hex(ByteView in) {
  constexpr std::string_view kDigits = "0123456789abcdef";
  std::string out;
  out.reserve(in.size() * 2);
  for (const uint8_t b : in) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 0x0F]);
  }
  return out;
}

namespace detail {
[[nodiscard]] inline uint8_t hex_digit(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<uint8_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<uint8_t>(c - 'a' + 10);
  }
  throw Error("invalid hex digit");
}
}  // namespace detail

// Throws pq::Error on odd length or any character outside [0-9a-f].
[[nodiscard]] inline Bytes from_hex(std::string_view in) {
  if (in.size() % 2 != 0) {
    throw Error("hex string has odd length");
  }
  Bytes out(in.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>((detail::hex_digit(in[2 * i]) << 4) |
                                  detail::hex_digit(in[2 * i + 1]));
  }
  return out;
}

}  // namespace pq::keystore
