#include "cipher/kuznyechik.hpp"

#include <cstdint>

#include "cipher/kuznyechik_detail.hpp"
#include "pq/error.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::cipher::detail {
namespace {

// GOST R 34.12-2015, Section 4.1.2, equation (1).
// The second coefficient multiplies a_14 (RFC 7801 Section 4.2 has a typo).
constexpr std::array<uint8_t, 16> kLinearCoefficients = {148, 32,  133, 16, 194, 192, 1,   251,
                                                         1,   192, 194, 16, 133, 32,  148, 1};

}  // namespace

// GOST R 34.12-2015, Section 2.2: GF(2)[x]/(x^8+x^7+x^6+x+1).
uint8_t kuznyechik_multiply(uint8_t a, uint8_t b) noexcept {
  uint8_t product = 0;
  for (uint32_t bit = 0; bit < 8; ++bit) {
    const auto bit_mask = static_cast<uint8_t>(0U - static_cast<uint32_t>(b & 1U));
    product ^= static_cast<uint8_t>(a & bit_mask);
    const auto high_mask = static_cast<uint8_t>(0U - static_cast<uint32_t>(a >> 7U));
    a = static_cast<uint8_t>((static_cast<uint32_t>(a) << 1U) ^ (0xC3U & high_mask));
    b = static_cast<uint8_t>(b >> 1U);
  }
  return product;
}

// GOST R 34.12-2015, Section 4.2, equation (2).
void kuznyechik_x(KuznyechikState state, KuznyechikConstState key) noexcept {
  for (uint32_t i = 0; i < 16; ++i) {
    state[i] ^= key[i];
  }
}

// GOST R 34.12-2015, Section 4.2, equation (3).
void kuznyechik_s(KuznyechikState state) noexcept {
  for (auto& value : state) {
    value = kKuznyechikSbox[value];
  }
}

// GOST R 34.12-2015, Section 4.2, equation (4).
void kuznyechik_inverse_s(KuznyechikState state) noexcept {
  for (auto& value : state) {
    value = kKuznyechikInverseSbox[value];
  }
}

// GOST R 34.12-2015, Section 4.2, equation (5).
void kuznyechik_r(KuznyechikState state) noexcept {
  uint8_t feedback = 0;
  for (uint32_t i = 0; i < 16; ++i) {
    feedback ^= kuznyechik_multiply(state[i], kLinearCoefficients[i]);
  }
  for (uint32_t i = 15; i > 0; --i) {
    state[i] = state[i - 1];
  }
  state[0] = feedback;
}

// GOST R 34.12-2015, Section 4.2, equation (7).
void kuznyechik_inverse_r(KuznyechikState state) noexcept {
  uint8_t feedback = state[0];
  for (uint32_t i = 0; i < 15; ++i) {
    state[i] = state[i + 1];
    feedback ^= kuznyechik_multiply(state[i], kLinearCoefficients[i]);
  }
  state[15] = feedback;
}

// GOST R 34.12-2015, Section 4.2, equation (6).
void kuznyechik_l(KuznyechikState state) noexcept {
  for (uint32_t i = 0; i < 16; ++i) {
    kuznyechik_r(state);
  }
}

// GOST R 34.12-2015, Section 4.2, equation (8).
void kuznyechik_inverse_l(KuznyechikState state) noexcept {
  for (uint32_t i = 0; i < 16; ++i) {
    kuznyechik_inverse_r(state);
  }
}

// GOST R 34.12-2015, Section 4.2, equation (9).
void kuznyechik_f(KuznyechikState left, KuznyechikState right,
                  KuznyechikConstState constant) noexcept {
  KuznyechikBlock next{};
  for (uint32_t i = 0; i < 16; ++i) next[i] = left[i];
  kuznyechik_x(next, constant);
  kuznyechik_s(next);
  kuznyechik_l(next);
  kuznyechik_x(next, right);
  for (uint32_t i = 0; i < 16; ++i) {
    right[i] = left[i];
    left[i] = next[i];
  }
  secure_zero(next);
}

// GOST R 34.12-2015, Section 4.3, equations (10)-(11).
void kuznyechik_expand_key(std::span<const uint8_t, 32> key,
                           std::span<uint8_t, 160> round_keys) noexcept {
  KuznyechikBlock left{};
  KuznyechikBlock right{};
  for (uint32_t i = 0; i < 16; ++i) {
    left[i] = key[i];
    right[i] = key[16 + i];
    round_keys[i] = left[i];
    round_keys[16 + i] = right[i];
  }
  for (uint32_t pair = 0; pair < 4; ++pair) {
    for (uint32_t step = 1; step <= 8; ++step) {
      KuznyechikBlock constant{};
      constant[15] = static_cast<uint8_t>(8 * pair + step);
      kuznyechik_l(constant);
      kuznyechik_f(left, right, constant);
    }
    for (uint32_t i = 0; i < 16; ++i) {
      round_keys[32 * (pair + 1) + i] = left[i];
      round_keys[32 * (pair + 1) + 16 + i] = right[i];
    }
  }
  secure_zero(left);
  secure_zero(right);
}

}  // namespace pq::cipher::detail

namespace pq::cipher {

Kuznyechik::~Kuznyechik() { secure_zero(round_keys_); }

// GOST R 34.12-2015, Section 4.3.
void Kuznyechik::set_key(ByteView key) {
  if (key.size() != key_size()) {
    throw Error("Kuznyechik: key must contain 32 bytes");
  }
  secure_zero(round_keys_);
  detail::kuznyechik_expand_key(std::span<const uint8_t, 32>(key.data(), 32), round_keys_);
  keyed_ = true;
}

// GOST R 34.12-2015, Section 4.4.1, equation (12).
void Kuznyechik::encrypt_block(const uint8_t* in, uint8_t* out) const {
  if (!keyed_) throw Error("Kuznyechik: key has not been set");
  if (in == nullptr || out == nullptr) throw Error("Kuznyechik: null block pointer");
  detail::KuznyechikBlock state{};
  for (uint32_t i = 0; i < 16; ++i) state[i] = in[i];
  for (int32_t round = 0; round < rounds_ - 1; ++round) {
    detail::kuznyechik_x(state, detail::KuznyechikConstState(round_keys_.data() + 16 * round, 16));
    detail::kuznyechik_s(state);
    detail::kuznyechik_l(state);
  }
  detail::kuznyechik_x(state,
                       detail::KuznyechikConstState(round_keys_.data() + 16 * (rounds_ - 1), 16));
  for (uint32_t i = 0; i < 16; ++i) out[i] = state[i];
  secure_zero(state);
}

// GOST R 34.12-2015, Section 4.4.2, equation (13).
// Apply inverse L before inverse S, as in GOST and the RFC 7801 examples.
// The displayed formula in RFC 7801 Section 4.5.2 reverses their order.
void Kuznyechik::decrypt_block(const uint8_t* in, uint8_t* out) const {
  if (!keyed_) throw Error("Kuznyechik: key has not been set");
  if (in == nullptr || out == nullptr) throw Error("Kuznyechik: null block pointer");
  detail::KuznyechikBlock state{};
  for (uint32_t i = 0; i < 16; ++i) state[i] = in[i];
  detail::kuznyechik_x(state,
                       detail::KuznyechikConstState(round_keys_.data() + 16 * (rounds_ - 1), 16));
  for (int32_t round = rounds_ - 2; round >= 0; --round) {
    detail::kuznyechik_inverse_l(state);
    detail::kuznyechik_inverse_s(state);
    detail::kuznyechik_x(state, detail::KuznyechikConstState(round_keys_.data() + 16 * round, 16));
  }
  for (uint32_t i = 0; i < 16; ++i) out[i] = state[i];
  secure_zero(state);
}

void Kuznyechik::set_rounds(int r) {
  if (r < 1 || r > 10) throw Error("Kuznyechik: round count must be between 1 and 10");
  rounds_ = r;
}

}  // namespace pq::cipher
