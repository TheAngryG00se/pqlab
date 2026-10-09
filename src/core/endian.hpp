#pragma once

// Zone: participant 4. Minimal version added by participant 1 for src/hash.
// Explicit byte order helpers; never reinterpret_cast a byte buffer.

#include <cstdint>

namespace pq {

[[nodiscard]] constexpr uint16_t load16_le(const uint8_t* p) noexcept {
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

[[nodiscard]] constexpr uint32_t load32_le(const uint8_t* p) noexcept {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

[[nodiscard]] constexpr uint64_t load64_le(const uint8_t* p) noexcept {
  return static_cast<uint64_t>(load32_le(p)) | (static_cast<uint64_t>(load32_le(p + 4)) << 32);
}

[[nodiscard]] constexpr uint32_t load32_be(const uint8_t* p) noexcept {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

[[nodiscard]] constexpr uint64_t load64_be(const uint8_t* p) noexcept {
  return (static_cast<uint64_t>(load32_be(p)) << 32) | static_cast<uint64_t>(load32_be(p + 4));
}

constexpr void store16_le(uint8_t* p, uint16_t v) noexcept {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}

constexpr void store32_le(uint8_t* p, uint32_t v) noexcept {
  for (int i = 0; i < 4; ++i) {
    p[i] = static_cast<uint8_t>(v >> (8 * i));
  }
}

constexpr void store64_le(uint8_t* p, uint64_t v) noexcept {
  for (int i = 0; i < 8; ++i) {
    p[i] = static_cast<uint8_t>(v >> (8 * i));
  }
}

constexpr void store32_be(uint8_t* p, uint32_t v) noexcept {
  for (int i = 0; i < 4; ++i) {
    p[i] = static_cast<uint8_t>(v >> (24 - 8 * i));
  }
}

constexpr void store64_be(uint8_t* p, uint64_t v) noexcept {
  for (int i = 0; i < 8; ++i) {
    p[i] = static_cast<uint8_t>(v >> (56 - 8 * i));
  }
}

}  // namespace pq
