#pragma once

#include "cipher/register.hpp"
#include "mode/register.hpp"
#include "pq/registry.hpp"

namespace pq::test {

// Local integration of real participant 3 modules. Never installs test doubles
// or reduced-round variants in the production Registry::global().
inline Registry participant3_registry() {
  Registry registry;
  cipher::register_algorithms(registry);
  mode::register_algorithms(registry);
  return registry;
}

}  // namespace pq::test
