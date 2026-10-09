#include "kem/mlkem/mlkem.hpp"

#include <algorithm>
#include <array>

#include "hash/sha3.hpp"
#include "hash/shake.hpp"
#include "kem/mlkem/kpke.hpp"
#include "kem/mlkem/poly.hpp"
#include "kem/mlkem/polyvec.hpp"
#include "pq/ct.hpp"
#include "pq/error.hpp"

namespace pq::mlkem {
namespace {

// FIPS 203, Eq. (4.4): H(s) = SHA3-256(s).
void h(std::span<uint8_t, 32> out, ByteView in) { hash::sha3_256(out, in); }

// FIPS 203, Eq. (4.5): G(a || b) = SHA3-512(a || b).
void g(std::span<uint8_t, 64> out, ByteView a, ByteView b) {
  hash::Sha3_512 x;
  x.update(a);
  x.update(b);
  x.finalize(out);
}

// FIPS 203, Eq. (4.4): J(z || c) = SHAKE256(z || c, 8 * 32).
void j(std::span<uint8_t, 32> out, ByteView z, ByteView c) {
  hash::Shake256 x;
  x.absorb(z);
  x.absorb(c);
  x.squeeze(out);
}

}  // namespace

template <typename P>
bool MlKem<P>::check_encaps_key(ByteView ek) {
  if (ek.size() != S::kEk) {
    return false;
  }
  // test <- ByteEncode_12(ByteDecode_12(ek[0 : 384k])); ek is public.
  constexpr size_t kLen = 384 * P::kK;
  detail::PolyVec<P::kK> t;
  detail::polyvec_decode<12, P::kK>(t, ek.template first<kLen>());
  std::array<uint8_t, kLen> test{};
  detail::polyvec_encode<12, P::kK>(test, t);
  return ct_equal(test, ek.first(kLen));
}

template <typename P>
bool MlKem<P>::check_decaps_key(ByteView dk) {
  if (dk.size() != S::kDk) {
    return false;
  }
  // test <- H(dk[384k : 768k + 32]); compare with dk[768k + 32 : 768k + 64].
  std::array<uint8_t, 32> test{};
  h(test, dk.subspan(S::kDkPke, S::kEk));
  return ct_equal(test, dk.subspan(S::kDkPke + S::kEk, 32));
}

template <typename P>
KeyPair MlKem<P>::keygen_derand(ByteView seed) const {
  if (seed.size() != S::kSeed) {
    throw Error(std::string(P::kName) + ": keygen seed must be 64 bytes (d || z)");
  }
  const std::span<const uint8_t, 32> d(seed.data(), 32);
  const ByteView z = seed.subspan(32, 32);

  KeyPair kp;
  kp.pk.resize(S::kEk);
  kp.sk = SecureBytes(S::kDk);
  const std::span<uint8_t, S::kEk> ek(kp.pk.data(), S::kEk);
  uint8_t* dk = kp.sk.data();

  // FIPS 203, Algorithm 16: dk = dk_PKE || ek || H(ek) || z
  detail::k_pke_keygen<P>(ek, std::span<uint8_t, S::kDkPke>(dk, S::kDkPke), d);
  std::copy(kp.pk.begin(), kp.pk.end(), dk + S::kDkPke);
  h(std::span<uint8_t, 32>(dk + S::kDkPke + S::kEk, 32), kp.pk);
  std::copy(z.begin(), z.end(), dk + S::kDkPke + S::kEk + 32);
  return kp;
}

template <typename P>
Encapsulation MlKem<P>::encaps_derand(ByteView pk, ByteView m) const {
  if (!check_encaps_key(pk)) {
    throw Error(std::string(P::kName) + ": encapsulation key check failed");
  }
  if (m.size() != S::kMsg) {
    throw Error(std::string(P::kName) + ": encaps randomness must be 32 bytes");
  }

  // FIPS 203, Algorithm 17.
  // 1: (K, r) <- G(m || H(ek))
  std::array<uint8_t, 32> h_ek{};
  h(h_ek, pk);
  std::array<uint8_t, 64> k_r{};
  g(k_r, m, h_ek);

  // 2: c <- K-PKE.Encrypt(ek, m, r)
  Encapsulation out;
  out.ct.resize(S::kCt);
  detail::k_pke_encrypt<P>(std::span<uint8_t, S::kCt>(out.ct.data(), S::kCt),
                           std::span<const uint8_t, S::kEk>(pk.data(), S::kEk),
                           std::span<const uint8_t, 32>(m.data(), 32),
                           std::span<const uint8_t, 32>(k_r.data() + 32, 32));
  out.ss = SecureBytes(ByteView(k_r.data(), 32));
  secure_zero(k_r);
  return out;
}

template <typename P>
SecureBytes MlKem<P>::decaps(ByteView sk, ByteView ct) const {
  // FIPS 203, Section 7.3, checks 1-3.
  if (ct.size() != S::kCt) {
    throw Error(std::string(P::kName) + ": ciphertext has wrong length");
  }
  if (!check_decaps_key(sk)) {
    throw Error(std::string(P::kName) + ": decapsulation key check failed");
  }

  // FIPS 203, Algorithm 18.
  // 1-4: parse dk
  const std::span<const uint8_t, S::kDkPke> dk_pke(sk.data(), S::kDkPke);
  const std::span<const uint8_t, S::kEk> ek_pke(sk.data() + S::kDkPke, S::kEk);
  const ByteView hash_ek = sk.subspan(S::kDkPke + S::kEk, 32);
  const ByteView z = sk.subspan(S::kDkPke + S::kEk + 32, 32);
  const std::span<const uint8_t, S::kCt> c(ct.data(), S::kCt);

  // 5: m' <- K-PKE.Decrypt(dk_PKE, c)
  std::array<uint8_t, 32> m_prime{};
  detail::k_pke_decrypt<P>(m_prime, dk_pke, c);

  // 6: (K', r') <- G(m' || h)
  std::array<uint8_t, 64> k_r{};
  g(k_r, m_prime, hash_ek);

  // 7: K_bar <- J(z || c)
  std::array<uint8_t, 32> k_bar{};
  j(k_bar, z, ct);

  // 8: c' <- K-PKE.Encrypt(ek_PKE, m', r')
  std::array<uint8_t, S::kCt> c_prime{};
  detail::k_pke_encrypt<P>(c_prime, ek_pke, m_prime,
                           std::span<const uint8_t, 32>(k_r.data() + 32, 32));

  // 9-11: K' <- K_bar if c != c', without branching on the comparison.
  SecureBytes k(S::kSs);
  const uint8_t ok = ct_equal_mask(c, c_prime);
  ct_select(k.span(), ByteView(k_r.data(), 32), k_bar, ok);

  secure_zero(m_prime);
  secure_zero(k_r);
  secure_zero(k_bar);
  secure_zero(c_prime);
  return k;
}

template class MlKem<MlKem512Params>;
template class MlKem<MlKem768Params>;
template class MlKem<MlKem1024Params>;

}  // namespace pq::mlkem
