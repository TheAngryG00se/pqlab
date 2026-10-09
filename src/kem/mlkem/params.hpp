#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace pq::mlkem {

// FIPS 203, Section 8, Table 2.
inline constexpr size_t kN = 256;
inline constexpr uint32_t kQ = 3329;

struct MlKem512Params {
  static constexpr std::string_view kName = "ML-KEM-512";
  static constexpr int kSecurityLevel = 1;
  static constexpr size_t kK = 2;
  static constexpr unsigned kEta1 = 3;
  static constexpr unsigned kEta2 = 2;
  static constexpr unsigned kDu = 10;
  static constexpr unsigned kDv = 4;
};

struct MlKem768Params {
  static constexpr std::string_view kName = "ML-KEM-768";
  static constexpr int kSecurityLevel = 3;
  static constexpr size_t kK = 3;
  static constexpr unsigned kEta1 = 2;
  static constexpr unsigned kEta2 = 2;
  static constexpr unsigned kDu = 10;
  static constexpr unsigned kDv = 4;
};

struct MlKem1024Params {
  static constexpr std::string_view kName = "ML-KEM-1024";
  static constexpr int kSecurityLevel = 5;
  static constexpr size_t kK = 4;
  static constexpr unsigned kEta1 = 2;
  static constexpr unsigned kEta2 = 2;
  static constexpr unsigned kDu = 11;
  static constexpr unsigned kDv = 5;
};

// Byte sizes derived from the parameters (FIPS 203, Algorithms 13-18; Table 3).
template <typename P>
struct Sizes {
  static constexpr size_t kPolyBytes = 384;  // ByteEncode_12 of one polynomial
  static constexpr size_t kEk = 384 * P::kK + 32;
  static constexpr size_t kDkPke = 384 * P::kK;
  static constexpr size_t kDk = 768 * P::kK + 96;
  static constexpr size_t kCt1 = 32 * P::kDu * P::kK;
  static constexpr size_t kCt2 = 32 * P::kDv;
  static constexpr size_t kCt = kCt1 + kCt2;
  static constexpr size_t kSs = 32;
  static constexpr size_t kSeed = 64;  // d || z
  static constexpr size_t kMsg = 32;
};

static_assert(Sizes<MlKem512Params>::kEk == 800 && Sizes<MlKem512Params>::kDk == 1632 &&
              Sizes<MlKem512Params>::kCt == 768);
static_assert(Sizes<MlKem768Params>::kEk == 1184 && Sizes<MlKem768Params>::kDk == 2400 &&
              Sizes<MlKem768Params>::kCt == 1088);
static_assert(Sizes<MlKem1024Params>::kEk == 1568 && Sizes<MlKem1024Params>::kDk == 3168 &&
              Sizes<MlKem1024Params>::kCt == 1568);

}  // namespace pq::mlkem
