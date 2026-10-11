#pragma once

// Numeric identifiers stored in the PQL1 envelope header. Assigned once and
// never reused or renumbered (AGENTS.md, section 5). Names are the canonical
// registry names.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "pq/error.hpp"

namespace pq::hybrid {

struct IdEntry {
  uint8_t id;
  std::string_view name;
};

inline constexpr std::array kKemIds = {
    IdEntry{1, "ML-KEM-512"}, IdEntry{2, "ML-KEM-768"}, IdEntry{3, "ML-KEM-1024"},
    IdEntry{16, "HQC-1"},     IdEntry{17, "HQC-3"},     IdEntry{18, "HQC-5"},
};

inline constexpr std::array kAeadIds = {
    IdEntry{1, "AES-128-GCM"},
    IdEntry{2, "AES-192-GCM"},
    IdEntry{3, "AES-256-GCM"},
    IdEntry{4, "Kuznyechik-GCM"},
};

namespace detail {

template <size_t N>
[[nodiscard]] constexpr uint8_t id_of(const std::array<IdEntry, N>& table, std::string_view name,
                                      const char* what) {
  for (const IdEntry& e : table) {
    if (e.name == name) {
      return e.id;
    }
  }
  throw Error(std::string("unknown ") + what + " name '" + std::string(name) + "'");
}

template <size_t N>
[[nodiscard]] constexpr std::string_view name_of(const std::array<IdEntry, N>& table, uint8_t id,
                                                 const char* what) {
  for (const IdEntry& e : table) {
    if (e.id == id) {
      return e.name;
    }
  }
  throw Error(std::string("unknown ") + what + " id " + std::to_string(id));
}

}  // namespace detail

// All four throw pq::Error for an unknown name or id.
[[nodiscard]] constexpr uint8_t kem_id(std::string_view name) {
  return detail::id_of(kKemIds, name, "KEM");
}
[[nodiscard]] constexpr std::string_view kem_name(uint8_t id) {
  return detail::name_of(kKemIds, id, "KEM");
}
[[nodiscard]] constexpr uint8_t aead_id(std::string_view name) {
  return detail::id_of(kAeadIds, name, "AEAD");
}
[[nodiscard]] constexpr std::string_view aead_name(uint8_t id) {
  return detail::name_of(kAeadIds, id, "AEAD");
}

}  // namespace pq::hybrid
