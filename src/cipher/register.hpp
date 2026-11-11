#pragma once

#include <memory>

#include "cipher/aes.hpp"
#include "cipher/kuznyechik.hpp"
#include "pq/registry.hpp"

namespace pq::cipher {

inline void register_algorithms(Registry& registry) {
  registry.add_cipher("AES-128", [] { return std::make_unique<Aes>(128); });
  registry.add_cipher("AES-192", [] { return std::make_unique<Aes>(192); });
  registry.add_cipher("AES-256", [] { return std::make_unique<Aes>(256); });
  registry.add_cipher("Kuznyechik", [] { return std::make_unique<Kuznyechik>(); });
}

}  // namespace pq::cipher
