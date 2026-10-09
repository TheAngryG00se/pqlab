#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "pq/secure_bytes.hpp"

namespace pq::hash {

inline constexpr size_t kKeccakLanes = 25;
inline constexpr size_t kKeccakStateBytes = 200;
inline constexpr int kKeccakRounds = 24;

// Lane (x, y) is state[x + 5 * y]; bytes are mapped to lanes little-endian
// (FIPS 202, Sections 3.1.2 and B.1).
using KeccakState = std::array<uint64_t, kKeccakLanes>;

// FIPS 202, Algorithm 7 with b = 1600, nr = 24 (KECCAK-f[1600]).
void keccak_f1600(KeccakState& state) noexcept;

// Domain separation suffix with the first bit of pad10*1 folded in
// (FIPS 202, Section 6 and Appendix B.2).
inline constexpr uint8_t kSha3Suffix = 0x06;   // M || 01
inline constexpr uint8_t kShakeSuffix = 0x1F;  // M || 1111

// FIPS 202, Algorithm 8 (SPONGE[KECCAK-f[1600], pad10*1, r]) in byte-oriented
// incremental form: absorb any number of times, then squeeze any number of times.
// The state may depend on secrets, so it is wiped on destruction.
class KeccakSponge {
 public:
  // rate_bytes = r / 8, must be in (0, 200) and a multiple of 8.
  KeccakSponge(size_t rate_bytes, uint8_t suffix);
  ~KeccakSponge();
  KeccakSponge(const KeccakSponge&) = default;
  KeccakSponge& operator=(const KeccakSponge&) = default;

  // Throws pq::Error if called after squeezing started.
  void absorb(ByteView in);
  // Pads on the first call; may be called repeatedly to stream output.
  void squeeze(MutByteView out);
  void reset() noexcept;

  [[nodiscard]] size_t rate() const noexcept { return rate_; }

 private:
  void finalize() noexcept;

  KeccakState state_{};
  size_t rate_;
  uint8_t suffix_;
  size_t pos_ = 0;  // byte position inside the current rate block
  bool squeezing_ = false;
};

}  // namespace pq::hash
