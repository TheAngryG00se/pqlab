#include "kem/mlkem/ntt.hpp"

#include "kem/mlkem/reduce.hpp"

namespace pq::mlkem::detail {
namespace {

constexpr uint32_t kZeta = 17;    // primitive 256-th root of unity mod q (FIPS 203, Section 4.3)
constexpr uint16_t kNInv = 3303;  // 128^{-1} mod q (FIPS 203, Algorithm 10, step 14)

consteval uint32_t bit_rev7(uint32_t i) {
  uint32_t r = 0;
  for (int b = 0; b < 7; ++b) {
    r |= ((i >> b) & 1U) << (6 - b);
  }
  return r;
}

consteval std::array<uint16_t, 128> make_zetas() {
  std::array<uint16_t, 128> z{};
  for (uint32_t i = 0; i < 128; ++i) {
    z[i] = pow_mod(kZeta, bit_rev7(i));
  }
  return z;
}

consteval std::array<uint16_t, 128> make_gammas() {
  std::array<uint16_t, 128> g{};
  for (uint32_t i = 0; i < 128; ++i) {
    g[i] = pow_mod(kZeta, 2 * bit_rev7(i) + 1);
  }
  return g;
}

consteval uint16_t to_mont(uint16_t x) {
  return static_cast<uint16_t>((static_cast<uint32_t>(x) * kMontR) % kQ);
}

template <size_t N>
consteval std::array<uint16_t, N> to_mont(const std::array<uint16_t, N>& in) {
  std::array<uint16_t, N> out{};
  for (size_t i = 0; i < N; ++i) {
    out[i] = to_mont(in[i]);
  }
  return out;
}

constexpr std::array<uint16_t, 128> kZetasTable = make_zetas();
constexpr std::array<uint16_t, 128> kGammasTable = make_gammas();
constexpr std::array<uint16_t, 128> kZetasMont = to_mont(kZetasTable);
constexpr std::array<uint16_t, 128> kGammasMont = to_mont(kGammasTable);
constexpr uint16_t kNInvMont = to_mont(kNInv);
constexpr uint16_t kR2 = to_mont(to_mont(1));  // R^2 mod q

// x < 4q -> x mod 2q.
constexpr uint16_t csub2q(uint32_t x) noexcept {
  const uint32_t d = x - 2 * kQ;
  const uint32_t mask = 0U - (d >> 31);
  return static_cast<uint16_t>(d + (mask & (2 * kQ)));
}

static_assert(kZetasTable[0] == 1 && kZetasTable[64] == kZeta);
static_assert(pow_mod(kZeta, 128) == kQ - 1, "zeta^128 == -1");
static_assert((128U * kNInv) % kQ == 1);

}  // namespace

const std::array<uint16_t, 128> kZetas = kZetasTable;
const std::array<uint16_t, 128> kGammas = kGammasTable;

// ---------------------------------------------------------------------------
// Reference versions.

// FIPS 203, Algorithm 9 (NTT).
void ntt_ref(Poly& f) noexcept {
  size_t i = 1;
  for (size_t len = 128; len >= 2; len /= 2) {
    for (size_t start = 0; start < kN; start += 2 * len) {
      const uint16_t zeta = kZetasTable[i++];
      for (size_t j = start; j < start + len; ++j) {
        const uint16_t t = mul_mod(zeta, f[j + len]);
        f[j + len] = sub_mod(f[j], t);
        f[j] = add_mod(f[j], t);
      }
    }
  }
}

// FIPS 203, Algorithm 10 (NTT^-1).
void inv_ntt_ref(Poly& f) noexcept {
  size_t i = 127;
  for (size_t len = 2; len <= 128; len *= 2) {
    for (size_t start = 0; start < kN; start += 2 * len) {
      const uint16_t zeta = kZetasTable[i--];
      for (size_t j = start; j < start + len; ++j) {
        const uint16_t t = f[j];
        f[j] = add_mod(t, f[j + len]);
        f[j + len] = mul_mod(zeta, sub_mod(f[j + len], t));
      }
    }
  }
  for (auto& x : f.c) {
    x = mul_mod(x, kNInv);
  }
}

// FIPS 203, Algorithms 11 (MultiplyNTTs) and 12 (BaseCaseMultiply).
void multiply_ntts_ref(Poly& h, const Poly& f, const Poly& g) noexcept {
  for (size_t i = 0; i < 128; ++i) {
    const uint16_t a0 = f[2 * i];
    const uint16_t a1 = f[2 * i + 1];
    const uint16_t b0 = g[2 * i];
    const uint16_t b1 = g[2 * i + 1];
    h[2 * i] = add_mod(mul_mod(a0, b0), mul_mod(mul_mod(a1, b1), kGammasTable[i]));
    h[2 * i + 1] = add_mod(mul_mod(a0, b1), mul_mod(a1, b0));
  }
}

// ---------------------------------------------------------------------------
// Optimized versions.

// Algorithm 9 with lazy reduction. If all inputs are below B, then t < 2q,
// f[j] + t < B + 2q and f[j] + 2q - t < B + 2q, so after 7 layers every
// coefficient is below q + 14q = 15q < 2^16, and zeta * f < q * 2^16 is a
// valid REDC input throughout. One Barrett reduction at the end.
void ntt(Poly& f) noexcept {
  size_t i = 1;
  for (size_t len = 128; len >= 2; len /= 2) {
    for (size_t start = 0; start < kN; start += 2 * len) {
      const uint32_t zeta = kZetasMont[i++];
      for (size_t j = start; j < start + len; ++j) {
        const uint32_t t = montgomery_reduce_lazy(zeta * f[j + len]);
        f[j + len] = static_cast<uint16_t>(f[j] + 2 * kQ - t);
        f[j] = static_cast<uint16_t>(f[j] + t);
      }
    }
  }
  for (auto& x : f.c) {
    x = barrett_reduce(x);
  }
}

// Algorithm 10 keeping every coefficient in [0, 2q) between layers.
void inv_ntt(Poly& f) noexcept {
  size_t i = 127;
  for (size_t len = 2; len <= 128; len *= 2) {
    for (size_t start = 0; start < kN; start += 2 * len) {
      const uint32_t zeta = kZetasMont[i--];
      for (size_t j = start; j < start + len; ++j) {
        const uint32_t t = f[j];
        const uint32_t u = f[j + len];
        f[j] = csub2q(t + u);
        // (u + 2q - t) < 4q, so zeta * (...) < 4q^2 < q * 2^16
        f[j + len] = static_cast<uint16_t>(montgomery_reduce_lazy(zeta * (u + 2 * kQ - t)));
      }
    }
  }
  for (auto& x : f.c) {
    x = montgomery_reduce(static_cast<uint32_t>(x) * kNInvMont);
  }
}

// Algorithms 11-12 in the Montgomery domain: the sums below are < 3q^2, the
// final multiplication by R^2 removes the R^{-1} factor.
void multiply_ntts(Poly& h, const Poly& f, const Poly& g) noexcept {
  for (size_t i = 0; i < 128; ++i) {
    const uint32_t a0 = f[2 * i];
    const uint32_t a1 = f[2 * i + 1];
    const uint32_t b0 = g[2 * i];
    const uint32_t b1 = g[2 * i + 1];
    const uint32_t a1b1 = montgomery_reduce_lazy(a1 * b1);  // a1 b1 / R
    const uint32_t c0 = montgomery_reduce_lazy(a0 * b0 + a1b1 * kGammasMont[i]);
    const uint32_t c1 = montgomery_reduce_lazy(a0 * b1 + a1 * b0);
    h[2 * i] = montgomery_reduce(c0 * kR2);
    h[2 * i + 1] = montgomery_reduce(c1 * kR2);
  }
}

}  // namespace pq::mlkem::detail
