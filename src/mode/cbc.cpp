#include "mode/cbc.hpp"

#include "mode/padding.hpp"

namespace pq::mode {

Cbc::Cbc(std::unique_ptr<BlockCipher> cipher) : ModeBase(std::move(cipher), "CBC", true) {
  if (block_size() > 255) {
    throw Error("CBC: PKCS#7 requires a block size below 256 bytes");
  }
}

// NIST SP 800-38A, Section 6.2; RFC 5652, Section 6.3.
Bytes Cbc::encrypt(ByteView key, ByteView iv, ByteView pt) {
  check_inputs(key, iv);
  cipher_->set_key(key);
  auto padded = detail::pkcs7_pad(pt, block_size());
  Bytes out(padded.size());
  const uint8_t* previous = iv.data();
  for (size_t offset = 0; offset < padded.size(); offset += block_size()) {
    for (size_t i = 0; i < block_size(); ++i) padded[offset + i] ^= previous[i];
    cipher_->encrypt_block(padded.data() + offset, out.data() + offset);
    previous = out.data() + offset;
  }
  return out;
}

// NIST SP 800-38A, Section 6.2. No plaintext is returned on invalid padding.
std::optional<SecureBytes> Cbc::decrypt(ByteView key, ByteView iv, ByteView ct) {
  check_inputs(key, iv);
  if (ct.empty() || ct.size() % block_size() != 0) {
    throw Error("CBC: ciphertext length must be a positive multiple of the block size");
  }
  cipher_->set_key(key);
  SecureBytes padded(ct.size());
  const uint8_t* previous = iv.data();
  for (size_t offset = 0; offset < ct.size(); offset += block_size()) {
    cipher_->decrypt_block(ct.data() + offset, padded.data() + offset);
    for (size_t i = 0; i < block_size(); ++i) padded[offset + i] ^= previous[i];
    previous = ct.data() + offset;
  }
  const auto size = detail::pkcs7_unpadded_size(padded, block_size());
  // Padding acceptance is the public result of CipherMode::decrypt.
  if (!size) return std::nullopt;
  return SecureBytes(padded.view().first(*size));
}

}  // namespace pq::mode
