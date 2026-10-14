#pragma once

#include <memory>
#include <utility>

#include "mode/cbc.hpp"
#include "mode/ctr.hpp"
#include "mode/ecb.hpp"
#include "pq/registry.hpp"

namespace pq::mode {

inline void register_algorithms(Registry& registry) {
  registry.add_cipher_mode("ECB", [](std::unique_ptr<BlockCipher> cipher) {
    return std::make_unique<Ecb>(std::move(cipher));
  });
  registry.add_cipher_mode("CBC", [](std::unique_ptr<BlockCipher> cipher) {
    return std::make_unique<Cbc>(std::move(cipher));
  });
  registry.add_cipher_mode("CTR", [](std::unique_ptr<BlockCipher> cipher) {
    return std::make_unique<Ctr>(std::move(cipher));
  });
}

}  // namespace pq::mode
