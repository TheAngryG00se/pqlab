#pragma once

#include "mode/mode_common.hpp"

namespace pq::mode {

class Ctr final : public detail::ModeBase {
 public:
  explicit Ctr(std::unique_ptr<BlockCipher> cipher) : ModeBase(std::move(cipher), "CTR", true) {}
  [[nodiscard]] Bytes encrypt(ByteView key, ByteView iv, ByteView pt) override;
  [[nodiscard]] std::optional<SecureBytes> decrypt(ByteView key, ByteView iv, ByteView ct) override;

 private:
  void check_counter_range(ByteView counter, size_t input_size) const;
  void transform(ByteView iv, ByteView input, MutByteView output);
};

}  // namespace pq::mode
