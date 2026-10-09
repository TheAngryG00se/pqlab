#include "hash/keccak.hpp"

#include "core/endian.hpp"
#include "pq/error.hpp"

namespace pq::hash {
namespace detail {
namespace {

[[nodiscard]] constexpr uint64_t rotl64(uint64_t x, unsigned n) noexcept {
  return (x << (n & 63U)) | (x >> ((64U - n) & 63U));
}

// FIPS 202, Algorithm 5 (rc). R[0] is bit 0 of the register.
[[nodiscard]] constexpr bool rc(int t) noexcept {
  if (t % 255 == 0) {
    return true;
  }
  uint32_t r = 0x01;  // R = 10000000
  for (int i = 1; i <= t % 255; ++i) {
    r <<= 1;  // R = 0 || R
    if ((r & 0x100U) != 0) {
      r ^= 0x71U;  // R[0], R[4], R[5], R[6] ^= R[8]
    }
    r &= 0xFFU;  // Trunc8
  }
  return (r & 1U) != 0;
}

// FIPS 202, Algorithm 6, steps 2-3: RC for round index ir (l = 6).
[[nodiscard]] constexpr std::array<uint64_t, kKeccakRounds> make_round_constants() noexcept {
  std::array<uint64_t, kKeccakRounds> out{};
  for (int ir = 0; ir < kKeccakRounds; ++ir) {
    uint64_t c = 0;
    for (int j = 0; j <= 6; ++j) {
      if (rc(j + 7 * ir)) {
        c |= uint64_t{1} << ((1U << j) - 1U);
      }
    }
    out[static_cast<size_t>(ir)] = c;
  }
  return out;
}

// FIPS 202, Algorithm 2 (rho), step 3: offset of lane (x, y) is (t + 1)(t + 2) / 2.
[[nodiscard]] constexpr std::array<unsigned, kKeccakLanes> make_rho_offsets() noexcept {
  std::array<unsigned, kKeccakLanes> out{};
  unsigned x = 1;
  unsigned y = 0;
  for (unsigned t = 0; t < 24; ++t) {
    out[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;
    const unsigned nx = y;
    const unsigned ny = (2 * x + 3 * y) % 5;
    x = nx;
    y = ny;
  }
  return out;
}

constexpr auto kRoundConstants = make_round_constants();
constexpr auto kRhoOffsets = make_rho_offsets();

// Sanity checks against FIPS 202, Table 2 and the first round constant.
static_assert(kRoundConstants[0] == 1);
static_assert(kRhoOffsets[1 + 5 * 0] == 1 && kRhoOffsets[0] == 0);
static_assert(kRhoOffsets[3 + 5 * 2] == 153 % 64);

}  // namespace
}  // namespace detail

void keccak_f1600(KeccakState& a) noexcept {
  using detail::rotl64;
  KeccakState b{};
  std::array<uint64_t, 5> c{};
  std::array<uint64_t, 5> d{};

  for (int ir = 0; ir < kKeccakRounds; ++ir) {
    // theta (Algorithm 1)
    for (size_t x = 0; x < 5; ++x) {
      c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    for (size_t x = 0; x < 5; ++x) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    for (size_t i = 0; i < kKeccakLanes; ++i) {
      a[i] ^= d[i % 5];
    }

    // rho and pi (Algorithms 2, 3): B[x, y] = rot(A[(x + 3y) mod 5, x])
    for (size_t y = 0; y < 5; ++y) {
      for (size_t x = 0; x < 5; ++x) {
        const size_t src = (x + 3 * y) % 5 + 5 * x;
        b[x + 5 * y] = rotl64(a[src], detail::kRhoOffsets[src]);
      }
    }

    // chi (Algorithm 4)
    for (size_t y = 0; y < 25; y += 5) {
      for (size_t x = 0; x < 5; ++x) {
        a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
      }
    }

    // iota (Algorithm 6)
    a[0] ^= detail::kRoundConstants[static_cast<size_t>(ir)];
  }

  secure_zero(b.data(), sizeof(b));
  secure_zero(c.data(), sizeof(c));
  secure_zero(d.data(), sizeof(d));
}

KeccakSponge::KeccakSponge(size_t rate_bytes, uint8_t suffix) : rate_(rate_bytes), suffix_(suffix) {
  if (rate_bytes == 0 || rate_bytes >= kKeccakStateBytes || rate_bytes % 8 != 0) {
    throw Error("KeccakSponge: invalid rate");
  }
}

KeccakSponge::~KeccakSponge() { secure_zero(state_.data(), sizeof(state_)); }

void KeccakSponge::reset() noexcept {
  secure_zero(state_.data(), sizeof(state_));
  pos_ = 0;
  squeezing_ = false;
}

void KeccakSponge::absorb(ByteView in) {
  if (squeezing_) {
    throw Error("KeccakSponge: absorb after squeeze");
  }
  size_t i = 0;
  while (i < in.size()) {
    if (pos_ == 0 && in.size() - i >= rate_) {
      for (size_t lane = 0; lane < rate_ / 8; ++lane) {
        state_[lane] ^= load64_le(in.data() + i + 8 * lane);
      }
      keccak_f1600(state_);
      i += rate_;
      continue;
    }
    state_[pos_ / 8] ^= static_cast<uint64_t>(in[i]) << (8 * (pos_ % 8));
    ++pos_;
    ++i;
    if (pos_ == rate_) {
      keccak_f1600(state_);
      pos_ = 0;
    }
  }
}

// FIPS 202, Algorithm 9 (pad10*1) with the domain suffix in front.
void KeccakSponge::finalize() noexcept {
  state_[pos_ / 8] ^= static_cast<uint64_t>(suffix_) << (8 * (pos_ % 8));
  state_[(rate_ - 1) / 8] ^= uint64_t{0x80} << (8 * ((rate_ - 1) % 8));
  keccak_f1600(state_);
  pos_ = 0;
  squeezing_ = true;
}

void KeccakSponge::squeeze(MutByteView out) {
  if (!squeezing_) {
    finalize();
  }
  for (uint8_t& byte : out) {
    if (pos_ == rate_) {
      keccak_f1600(state_);
      pos_ = 0;
    }
    byte = static_cast<uint8_t>(state_[pos_ / 8] >> (8 * (pos_ % 8)));
    ++pos_;
  }
}

}  // namespace pq::hash
