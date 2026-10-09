#include "kem/mlkem/kpke.hpp"

#include <algorithm>
#include <array>

#include "hash/sha3.hpp"
#include "kem/mlkem/encode.hpp"
#include "kem/mlkem/polyvec.hpp"
#include "kem/mlkem/sampling.hpp"

namespace pq::mlkem::detail {
namespace {

// FIPS 203, Algorithm 13 steps 3-7 and Algorithm 14 steps 4-8:
// A[i][j] = SampleNTT(rho || j || i).
template <size_t K>
void generate_matrix(PolyMat<K>& a, std::span<const uint8_t, 32> rho) {
  for (size_t i = 0; i < K; ++i) {
    for (size_t j = 0; j < K; ++j) {
      sample_ntt(a[i][j], rho, static_cast<uint8_t>(j), static_cast<uint8_t>(i));
    }
  }
}

// SamplePolyCBD_eta(PRF_eta(seed, nonce)).
template <unsigned Eta>
void sample_noise(Poly& f, std::span<const uint8_t, 32> seed, uint8_t nonce) {
  std::array<uint8_t, 64 * Eta> buf{};
  prf<Eta>(buf, seed, nonce);
  sample_poly_cbd<Eta>(f, buf);
  secure_zero(buf);
}

}  // namespace

template <typename P>
void k_pke_keygen(std::span<uint8_t, Sizes<P>::kEk> ek, std::span<uint8_t, Sizes<P>::kDkPke> dk,
                  std::span<const uint8_t, 32> d) {
  constexpr size_t kK = P::kK;

  // 1: (rho, sigma) <- G(d || k)
  std::array<uint8_t, 64> rho_sigma{};
  {
    hash::Sha3_512 g;
    g.update(d);
    const std::array<uint8_t, 1> k_byte{static_cast<uint8_t>(kK)};
    g.update(k_byte);
    g.finalize(rho_sigma);
  }
  const std::span<const uint8_t, 32> rho(rho_sigma.data(), 32);
  const std::span<const uint8_t, 32> sigma(rho_sigma.data() + 32, 32);

  // 2-7
  PolyMat<kK> a;
  generate_matrix<kK>(a, rho);

  // 8-15
  uint8_t n = 0;
  PolyVec<kK> s;
  PolyVec<kK> e;
  for (size_t i = 0; i < kK; ++i) {
    sample_noise<P::kEta1>(s[i], sigma, n++);
  }
  for (size_t i = 0; i < kK; ++i) {
    sample_noise<P::kEta1>(e[i], sigma, n++);
  }

  // 16-18: t = A o s + e
  polyvec_ntt(s);
  polyvec_ntt(e);
  PolyVec<kK> t;
  matrix_mul(t, a, s, false);
  polyvec_add(t, t, e);

  // 19-20
  polyvec_encode<12, kK>(ek.template first<384 * kK>(), t);
  std::copy(rho.begin(), rho.end(), ek.begin() + 384 * kK);
  polyvec_encode<12, kK>(dk, s);

  secure_zero(rho_sigma);
}

template <typename P>
void k_pke_encrypt(std::span<uint8_t, Sizes<P>::kCt> c, std::span<const uint8_t, Sizes<P>::kEk> ek,
                   std::span<const uint8_t, 32> m, std::span<const uint8_t, 32> r) {
  constexpr size_t kK = P::kK;
  using S = Sizes<P>;

  // 2-3
  PolyVec<kK> t;
  polyvec_decode<12, kK>(t, ek.template first<384 * kK>());
  const std::span<const uint8_t, 32> rho = ek.template subspan<384 * kK, 32>();

  // 4-8
  PolyMat<kK> a;
  generate_matrix<kK>(a, rho);

  // 9-17
  uint8_t n = 0;
  PolyVec<kK> y;
  PolyVec<kK> e1;
  Poly e2;
  for (size_t i = 0; i < kK; ++i) {
    sample_noise<P::kEta1>(y[i], r, n++);
  }
  for (size_t i = 0; i < kK; ++i) {
    sample_noise<P::kEta2>(e1[i], r, n++);
  }
  sample_noise<P::kEta2>(e2, r, n);

  // 18-19: u = NTT^-1(A^T o y) + e1
  polyvec_ntt(y);
  PolyVec<kK> u;
  matrix_mul(u, a, y, true);
  polyvec_inv_ntt(u);
  polyvec_add(u, u, e1);

  // 20: mu = Decompress_1(ByteDecode_1(m))
  Poly mu;
  byte_decode<1>(mu, m);
  decompress_poly<1>(mu);

  // 21: v = NTT^-1(t^T o y) + e2 + mu
  Poly v;
  polyvec_dot(v, t, y);
  inv_ntt(v);
  poly_add(v, v, e2);
  poly_add(v, v, mu);

  // 22-24
  for (auto& p : u) {
    compress_poly<P::kDu>(p);
  }
  compress_poly<P::kDv>(v);
  polyvec_encode<P::kDu, kK>(c.template first<S::kCt1>(), u);
  byte_encode<P::kDv>(c.template subspan<S::kCt1, S::kCt2>(), v);
}

template <typename P>
void k_pke_decrypt(std::span<uint8_t, 32> m, std::span<const uint8_t, Sizes<P>::kDkPke> dk,
                   std::span<const uint8_t, Sizes<P>::kCt> c) {
  constexpr size_t kK = P::kK;
  using S = Sizes<P>;

  // 1-4
  PolyVec<kK> u;
  polyvec_decode<P::kDu, kK>(u, c.template first<S::kCt1>());
  for (auto& p : u) {
    decompress_poly<P::kDu>(p);
  }
  Poly v;
  byte_decode<P::kDv>(v, c.template subspan<S::kCt1, S::kCt2>());
  decompress_poly<P::kDv>(v);

  // 5
  PolyVec<kK> s;
  polyvec_decode<12, kK>(s, dk);

  // 6: w = v - NTT^-1(s^T o NTT(u))
  polyvec_ntt(u);
  Poly w;
  polyvec_dot(w, s, u);
  inv_ntt(w);
  poly_sub(w, v, w);

  // 7
  compress_poly<1>(w);
  byte_encode<1>(m, w);
}

#define PQ_MLKEM_INSTANTIATE_KPKE(P)                                                          \
  template void k_pke_keygen<P>(std::span<uint8_t, Sizes<P>::kEk>,                            \
                                std::span<uint8_t, Sizes<P>::kDkPke>,                         \
                                std::span<const uint8_t, 32>);                                \
  template void k_pke_encrypt<P>(std::span<uint8_t, Sizes<P>::kCt>,                           \
                                 std::span<const uint8_t, Sizes<P>::kEk>,                     \
                                 std::span<const uint8_t, 32>, std::span<const uint8_t, 32>); \
  template void k_pke_decrypt<P>(std::span<uint8_t, 32>,                                      \
                                 std::span<const uint8_t, Sizes<P>::kDkPke>,                  \
                                 std::span<const uint8_t, Sizes<P>::kCt>);

PQ_MLKEM_INSTANTIATE_KPKE(MlKem512Params)
PQ_MLKEM_INSTANTIATE_KPKE(MlKem768Params)
PQ_MLKEM_INSTANTIATE_KPKE(MlKem1024Params)

#undef PQ_MLKEM_INSTANTIATE_KPKE

}  // namespace pq::mlkem::detail
