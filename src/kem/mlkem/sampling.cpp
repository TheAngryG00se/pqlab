#include "kem/mlkem/sampling.hpp"

#include <array>

#include "hash/shake.hpp"
#include "kem/mlkem/reduce.hpp"

namespace pq::mlkem::detail {

void sample_ntt(Poly& a, std::span<const uint8_t, 32> rho, uint8_t j, uint8_t i) {
  hash::Shake128 xof;
  xof.absorb(rho);
  const std::array<uint8_t, 2> idx{j, i};
  xof.absorb(idx);

  // Squeezing whole rate blocks yields the same byte stream as 3-byte
  // squeezes (FIPS 203, Algorithm 2); 168 = 56 * 3.
  std::array<uint8_t, hash::Shake128::kRate> buf{};
  size_t pos = buf.size();
  size_t n = 0;
  while (n < kN) {
    if (pos == buf.size()) {
      xof.squeeze(buf);
      pos = 0;
    }
    const uint32_t c0 = buf[pos];
    const uint32_t c1 = buf[pos + 1];
    const uint32_t c2 = buf[pos + 2];
    pos += 3;
    const uint32_t d1 = c0 + 256 * (c1 & 0x0F);
    const uint32_t d2 = (c1 >> 4) + 16 * c2;
    if (d1 < kQ) {
      a[n++] = static_cast<uint16_t>(d1);
    }
    if (d2 < kQ && n < kN) {
      a[n++] = static_cast<uint16_t>(d2);
    }
  }
}

template <unsigned Eta>
void prf(std::span<uint8_t, 64 * Eta> out, std::span<const uint8_t, 32> s, uint8_t b) {
  hash::Shake256 x;
  x.absorb(s);
  const std::array<uint8_t, 1> bb{b};
  x.absorb(bb);
  x.squeeze(out);
}

template <unsigned Eta>
void sample_poly_cbd(Poly& f, std::span<const uint8_t, 64 * Eta> b) noexcept {
  auto bit = [&b](size_t k) -> uint32_t { return (b[k / 8] >> (k % 8)) & 1U; };
  for (size_t i = 0; i < kN; ++i) {
    uint32_t x = 0;
    uint32_t y = 0;
    for (size_t j = 0; j < Eta; ++j) {
      x += bit(2 * i * Eta + j);
      y += bit(2 * i * Eta + Eta + j);
    }
    f[i] = csubq(x + kQ - y);  // x - y mod q, x + q - y < q + eta < 2q
  }
}

template void prf<2>(std::span<uint8_t, 128>, std::span<const uint8_t, 32>, uint8_t);
template void prf<3>(std::span<uint8_t, 192>, std::span<const uint8_t, 32>, uint8_t);
template void sample_poly_cbd<2>(Poly&, std::span<const uint8_t, 128>) noexcept;
template void sample_poly_cbd<3>(Poly&, std::span<const uint8_t, 192>) noexcept;

}  // namespace pq::mlkem::detail
