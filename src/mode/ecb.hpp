#pragma once

#include "mode/mode_common.hpp"

namespace pq::mode {

class Ecb final : public detail::ModeBase {
 public:
  explicit Ecb(std::unique_ptr<BlockCipher> cipher) : ModeBase(std::move(cipher), "ECB", false) {}
  [[nodiscard]] Bytes encrypt(ByteView key, ByteView iv, ByteView pt) override;
  [[nodiscard]] std::optional<SecureBytes> decrypt(ByteView key, ByteView iv, ByteView ct) override;
};

}  // namespace pq::mode
