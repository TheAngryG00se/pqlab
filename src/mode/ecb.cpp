#include "mode/ecb.hpp"

namespace pq::mode {

// NIST SP 800-38A, Section 6.1. ECB has no padding in the project API.
Bytes Ecb::encrypt(ByteView key, ByteView iv, ByteView pt) {
  check_inputs(key, iv);
  if (pt.size() % block_size() != 0) {
    throw Error("ECB: length must be a multiple of the block size");
  }
  cipher_->set_key(key);
  Bytes out(pt.size());
  for (size_t offset = 0; offset < pt.size(); offset += block_size()) {
    cipher_->encrypt_block(pt.data() + offset, out.data() + offset);
  }
  return out;
}

// NIST SP 800-38A, Section 6.1.
std::optional<SecureBytes> Ecb::decrypt(ByteView key, ByteView iv, ByteView ct) {
  check_inputs(key, iv);
  if (ct.size() % block_size() != 0) {
    throw Error("ECB: length must be a multiple of the block size");
  }
  cipher_->set_key(key);
  SecureBytes out(ct.size());
  for (size_t offset = 0; offset < ct.size(); offset += block_size()) {
    cipher_->decrypt_block(ct.data() + offset, out.data() + offset);
  }
  return out;
}

}  // namespace pq::mode
