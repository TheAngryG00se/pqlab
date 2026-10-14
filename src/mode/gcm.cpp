#include "mode/gcm.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include "core/endian.hpp"
#include "mode/ghash.hpp"
#include "pq/ct.hpp"
#include "pq/error.hpp"

namespace pq::mode {

// NIST SP 800-38D, Section 5.2.1.1: len(P) <= 2^39-256 bits.
void detail::check_gcm_lengths(uint64_t aad_bytes, uint64_t message_bytes) {
  if (aad_bytes > std::numeric_limits<uint64_t>::max() / 8 ||
      message_bytes > (UINT64_C(1) << 36) - 32) {
    throw Error("GCM: input exceeds the SP 800-38D length limit");
  }
}

Gcm::Gcm(std::unique_ptr<BlockCipher> cipher) : cipher_(std::move(cipher)) {
  if (!cipher_ || cipher_->block_size() != 16) {
    throw Error("GCM: a 128-bit block cipher is required");
  }
  name_ = std::string(cipher_->name()) + "-GCM";
}

void Gcm::check_inputs(ByteView key, ByteView nonce, size_t aad_size, size_t message_size) const {
  if (key.size() != key_size() || nonce.size() != nonce_size()) {
    throw Error("GCM: wrong key or nonce length");
  }
  detail::check_gcm_lengths(aad_size, message_size);
  if (message_size > std::numeric_limits<size_t>::max() - tag_size()) {
    throw Error("GCM: output size overflows");
  }
}

// NIST SP 800-38D, Algorithm 3; Algorithm 4, steps 2-3 for 96-bit IVs.
void Gcm::transform(ByteView nonce, ByteView input, MutByteView output) {
  SecureBytes counter(16);
  SecureBytes stream(16);
  std::copy(nonce.begin(), nonce.end(), counter.begin());
  store32_be(counter.data() + 12, 1);
  size_t offset = 0;
  while (offset < input.size()) {
    store32_be(counter.data() + 12, load32_be(counter.data() + 12) + 1U);
    cipher_->encrypt_block(counter.data(), stream.data());
    const size_t take = std::min(size_t{16}, input.size() - offset);
    for (size_t i = 0; i < take; ++i) output[offset + i] = input[offset + i] ^ stream[i];
    offset += take;
  }
}

// NIST SP 800-38D, Algorithm 4, steps 1, 2 and 4-6.
void Gcm::authenticate(ByteView nonce, ByteView aad, ByteView ciphertext, MutByteView tag) {
  SecureBytes h(16);
  cipher_->encrypt_block(h.data(), h.data());
  SecureBytes mask(16);
  std::copy(nonce.begin(), nonce.end(), mask.begin());
  mask[15] = 1;
  cipher_->encrypt_block(mask.data(), mask.data());
  detail::ghash_auth(h, aad, ciphertext, tag);
  for (size_t i = 0; i < 16; ++i) tag[i] ^= mask[i];
}

// NIST SP 800-38D, Algorithm 4 (GCM-AE).
Bytes Gcm::seal(ByteView key, ByteView nonce, ByteView aad, ByteView pt) {
  check_inputs(key, nonce, aad.size(), pt.size());
  cipher_->set_key(key);
  Bytes output(pt.size() + tag_size());
  transform(nonce, pt, MutByteView(output).first(pt.size()));
  // Keep the unmasked GHASH state in wiping storage, even if authentication throws.
  SecureBytes tag(16);
  authenticate(nonce, aad, ByteView(output).first(pt.size()), tag.span());
  std::copy(tag.begin(), tag.end(), output.begin() + pt.size());
  return output;
}

// NIST SP 800-38D, Algorithm 5: permitted tag-first verification ordering.
std::optional<SecureBytes> Gcm::open(ByteView key, ByteView nonce, ByteView aad, ByteView ct) {
  const size_t message_size = ct.size() < tag_size() ? 0 : ct.size() - tag_size();
  check_inputs(key, nonce, aad.size(), message_size);
  if (ct.size() < tag_size()) return std::nullopt;
  cipher_->set_key(key);
  SecureBytes expected_tag(16);
  authenticate(nonce, aad, ct.first(message_size), expected_tag.span());
  // Authentication success/failure is the public Aead::open decision.
  if (!ct_equal(expected_tag, ct.last(tag_size()))) return std::nullopt;
  SecureBytes plaintext(message_size);
  transform(nonce, ct.first(message_size), plaintext.span());
  return plaintext;
}

}  // namespace pq::mode
