#include "cipher/aes.hpp"

#include <algorithm>

#include "cipher/aes_detail.hpp"
#include "pq/error.hpp"

namespace pq::cipher::detail {

// FIPS 197-upd1, Section 5.1.1 (SUBBYTES).
void aes_sub_bytes(AesBlock& state) noexcept {
  for (auto& byte : state) {
    byte = kAesSbox[byte];
  }
}

// FIPS 197-upd1, Section 5.3.2 (INVSUBBYTES).
void aes_inv_sub_bytes(AesBlock& state) noexcept {
  for (auto& byte : state) {
    byte = kAesInvSbox[byte];
  }
}

// FIPS 197-upd1, Section 5.1.2 (SHIFTROWS).
void aes_shift_rows(AesBlock& state) noexcept {
  AesBlock source = state;
  for (size_t row = 0; row < 4; ++row) {
    for (size_t column = 0; column < 4; ++column) {
      state[row + 4 * column] = source[row + 4 * ((column + row) & 3U)];
    }
  }
  secure_zero(source);
}

// FIPS 197-upd1, Section 5.3.1 (INVSHIFTROWS).
void aes_inv_shift_rows(AesBlock& state) noexcept {
  AesBlock source = state;
  for (size_t row = 0; row < 4; ++row) {
    for (size_t column = 0; column < 4; ++column) {
      state[row + 4 * column] = source[row + 4 * ((column + 4 - row) & 3U)];
    }
  }
  secure_zero(source);
}

// FIPS 197-upd1, Section 5.1.3, Eq. (5.8) (MIXCOLUMNS).
void aes_mix_columns(AesBlock& state) noexcept {
  AesBlock source = state;
  for (size_t column = 0; column < 4; ++column) {
    for (size_t row = 0; row < 4; ++row) {
      const size_t offset = 4 * column;
      state[offset + row] = static_cast<uint8_t>(
          aes_xtime(source[offset + row]) ^ aes_xtime(source[offset + ((row + 1) & 3U)]) ^
          source[offset + ((row + 1) & 3U)] ^ source[offset + ((row + 2) & 3U)] ^
          source[offset + ((row + 3) & 3U)]);
    }
  }
  secure_zero(source);
}

// FIPS 197-upd1, Section 5.3.3, Eq. (5.15) (INVMIXCOLUMNS).
void aes_inv_mix_columns(AesBlock& state) noexcept {
  AesBlock source = state;
  for (size_t column = 0; column < 4; ++column) {
    for (size_t row = 0; row < 4; ++row) {
      const size_t offset = 4 * column;
      state[offset + row] =
          static_cast<uint8_t>(aes_gf_multiply(source[offset + row], 0x0e) ^
                               aes_gf_multiply(source[offset + ((row + 1) & 3U)], 0x0b) ^
                               aes_gf_multiply(source[offset + ((row + 2) & 3U)], 0x0d) ^
                               aes_gf_multiply(source[offset + ((row + 3) & 3U)], 0x09));
    }
  }
  secure_zero(source);
}

// FIPS 197-upd1, Section 5.1.4 (ADDROUNDKEY).
void aes_add_round_key(AesBlock& state, std::span<const uint8_t, 16> round_key) noexcept {
  for (size_t i = 0; i < state.size(); ++i) {
    state[i] ^= round_key[i];
  }
}

// FIPS 197-upd1, Algorithm 2 (KEYEXPANSION), with words stored as four ordered bytes.
void aes_key_expansion(ByteView key, MutByteView expanded) {
  if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
    throw Error("AES key must contain 16, 24, or 32 bytes");
  }
  const size_t words = key.size() / 4;
  if (expanded.size() != 16 * (words + 7)) {
    throw Error("AES expanded key has an incorrect length");
  }
  std::copy(key.begin(), key.end(), expanded.begin());
  std::array<uint8_t, 4> temp{};
  uint8_t round_constant = 1;
  for (size_t word = words; word < expanded.size() / 4; ++word) {
    for (size_t i = 0; i < 4; ++i) {
      temp[i] = expanded[4 * (word - 1) + i];
    }
    // Both conditions depend only on the public word index and key length.
    if (word % words == 0) {
      std::rotate(temp.begin(), temp.begin() + 1, temp.end());
      for (auto& byte : temp) {
        byte = kAesSbox[byte];
      }
      temp[0] ^= round_constant;
      round_constant = aes_xtime(round_constant);
    } else if (words == 8 && word % words == 4) {
      for (auto& byte : temp) {
        byte = kAesSbox[byte];
      }
    }
    for (size_t i = 0; i < 4; ++i) {
      expanded[4 * word + i] = static_cast<uint8_t>(expanded[4 * (word - words) + i] ^ temp[i]);
    }
  }
  secure_zero(temp);
}

}  // namespace pq::cipher::detail

namespace pq::cipher {

Aes::Aes(uint32_t key_bits)
    : key_bytes_(key_bits / 8),
      full_rounds_(static_cast<int32_t>(key_bits / 32) + 6),
      rounds_(full_rounds_) {
  if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
    throw Error("AES supports only 128-, 192-, and 256-bit keys");
  }
}

Aes::~Aes() { secure_zero(round_keys_); }

std::string_view Aes::name() const {
  switch (key_bytes_) {
    case 16:
      return "AES-128";
    case 24:
      return "AES-192";
    default:
      return "AES-256";
  }
}

void Aes::set_key(ByteView key) {
  if (key.size() != key_bytes_) {
    throw Error("AES key length does not match the selected variant");
  }
  secure_zero(round_keys_);
  detail::aes_key_expansion(
      key, MutByteView(round_keys_).first(16 * (static_cast<size_t>(full_rounds_) + 1)));
  keyed_ = true;
}

void Aes::set_rounds(int r) {
  if (r < 1 || r > full_rounds_) {
    throw Error("AES round count is outside the selected variant's range");
  }
  rounds_ = r;
}

// FIPS 197-upd1, Algorithm 1 (CIPHER).
void Aes::encrypt_block(const uint8_t* in, uint8_t* out) const {
  if (!keyed_) {
    throw Error("AES key has not been set");
  }
  if (in == nullptr || out == nullptr) {
    throw Error("AES block pointer must not be null");
  }
  detail::AesBlock state{};
  std::copy_n(in, state.size(), state.begin());
  detail::aes_add_round_key(state, std::span<const uint8_t, 16>(round_keys_.data(), 16));
  for (int32_t round = 1; round < rounds_; ++round) {
    detail::aes_sub_bytes(state);
    detail::aes_shift_rows(state);
    detail::aes_mix_columns(state);
    detail::aes_add_round_key(state,
                              std::span<const uint8_t, 16>(round_keys_.data() + 16 * round, 16));
  }
  detail::aes_sub_bytes(state);
  detail::aes_shift_rows(state);
  detail::aes_add_round_key(state,
                            std::span<const uint8_t, 16>(round_keys_.data() + 16 * rounds_, 16));
  std::copy(state.begin(), state.end(), out);
  secure_zero(state);
}

// FIPS 197-upd1, Algorithm 3 (INVCIPHER).
void Aes::decrypt_block(const uint8_t* in, uint8_t* out) const {
  if (!keyed_) {
    throw Error("AES key has not been set");
  }
  if (in == nullptr || out == nullptr) {
    throw Error("AES block pointer must not be null");
  }
  detail::AesBlock state{};
  std::copy_n(in, state.size(), state.begin());
  detail::aes_add_round_key(state,
                            std::span<const uint8_t, 16>(round_keys_.data() + 16 * rounds_, 16));
  for (int32_t round = rounds_ - 1; round > 0; --round) {
    detail::aes_inv_shift_rows(state);
    detail::aes_inv_sub_bytes(state);
    detail::aes_add_round_key(state,
                              std::span<const uint8_t, 16>(round_keys_.data() + 16 * round, 16));
    detail::aes_inv_mix_columns(state);
  }
  detail::aes_inv_shift_rows(state);
  detail::aes_inv_sub_bytes(state);
  detail::aes_add_round_key(state, std::span<const uint8_t, 16>(round_keys_.data(), 16));
  std::copy(state.begin(), state.end(), out);
  secure_zero(state);
}

}  // namespace pq::cipher
