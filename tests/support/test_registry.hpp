#pragma once

// A local Registry for tests: real ML-KEM plus the stubs, under the canonical
// names the services look up ("AES-256" + "GCM"). Once the real AES-GCM is in
// Registry::global(), tests that want it simply use the global one.

#include <memory>
#include <string>

#include "kem/mlkem/register.hpp"
#include "pq/registry.hpp"
#include "support/dummy_kem.hpp"
#include "support/stub_aead.hpp"

namespace pq::test {

inline Registry make_test_registry() {
  Registry r;
  mlkem::register_algorithms(r);
  r.add_kem(std::string(DummyKem::kName), [] { return std::make_unique<DummyKem>(); });
  r.add_cipher("AES-256", [] { return std::make_unique<XorCipher>("AES-256", 32); });
  r.add_cipher("Kuznyechik", [] { return std::make_unique<XorCipher>("Kuznyechik", 32); });
  r.add_aead_mode("GCM", [](std::unique_ptr<BlockCipher> c) {
    return std::make_unique<StubGcm>(std::move(c));
  });
  return r;
}

}  // namespace pq::test
