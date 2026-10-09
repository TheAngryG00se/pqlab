#pragma once

// Registers ML-KEM-512/768/1024 under their canonical names. Header-only so
// that only the Registry implementation (src/core) depends on it.

#include <memory>
#include <string>

#include "kem/mlkem/mlkem.hpp"
#include "pq/registry.hpp"

namespace pq::mlkem {

inline void register_algorithms(Registry& registry) {
  registry.add_kem(std::string(MlKem512Params::kName), [] { return std::make_unique<MlKem512>(); });
  registry.add_kem(std::string(MlKem768Params::kName), [] { return std::make_unique<MlKem768>(); });
  registry.add_kem(std::string(MlKem1024Params::kName),
                   [] { return std::make_unique<MlKem1024>(); });
}

}  // namespace pq::mlkem
