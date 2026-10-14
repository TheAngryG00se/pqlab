#pragma once

#include "mode/mode_common.hpp"

namespace pq::mode {

class Cbc final : public detail::ModeBase {
 public:
  explicit Cbc(std::unique_ptr<BlockCipher> cipher);
  [[nodiscard]] Bytes encrypt(ByteView key, ByteView iv, ByteView pt) override;
  [[nodiscard]] std::optional<SecureBytes> decrypt(ByteView key, ByteView iv, ByteView ct) override;
};

}  // namespace pq::mode
