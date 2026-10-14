#include "mode/ctr.hpp"

#include <algorithm>
#include <cstdint>

namespace pq::mode {

// NIST SP 800-38A, Appendix B.1: increment the entire big-endian counter.
// Reject crossing the all-ones boundary before processing any data.
void Ctr::check_counter_range(ByteView counter, size_t input_size) const {
  if (input_size == 0) return;
  size_t carry = (input_size - 1) / block_size();
  for (size_t i = counter.size(); i > 0; --i) {
    const size_t sum = counter[i - 1] + (carry & 255U);
    carry = (carry >> 8) + (sum >> 8);
  }
  if (carry != 0) throw Error("CTR: counter would wrap");
}

// NIST SP 800-38A, Section 6.5. All temporary keystream bytes are wiped.
void Ctr::transform(ByteView iv, ByteView input, MutByteView output) {
  SecureBytes counter(iv);
  SecureBytes stream(block_size());
  size_t offset = 0;
  while (offset < input.size()) {
    cipher_->encrypt_block(counter.data(), stream.data());
    const size_t take = std::min(block_size(), input.size() - offset);
    for (size_t i = 0; i < take; ++i) output[offset + i] = input[offset + i] ^ stream[i];
    offset += take;
    uint32_t carry = 1;
    for (size_t i = counter.size(); i > 0; --i) {
      const uint32_t sum = counter[i - 1] + carry;
      counter[i - 1] = static_cast<uint8_t>(sum);
      carry = sum >> 8;
    }
  }
}

Bytes Ctr::encrypt(ByteView key, ByteView iv, ByteView pt) {
  check_inputs(key, iv);
  check_counter_range(iv, pt.size());
  cipher_->set_key(key);
  Bytes out(pt.size());
  transform(iv, pt, out);
  return out;
}

std::optional<SecureBytes> Ctr::decrypt(ByteView key, ByteView iv, ByteView ct) {
  check_inputs(key, iv);
  check_counter_range(iv, ct.size());
  cipher_->set_key(key);
  SecureBytes out(ct.size());
  transform(iv, ct, out.span());
  return out;
}

}  // namespace pq::mode
