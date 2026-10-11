#pragma once

// INSECURE test double for pq::Kem. Fast and deterministic, used where a unit
// test needs "some KEM" and does not care about ML-KEM/HQC cost. Never register
// it in Registry::global().
//
//   sk = pk = SHA3-256(seed),  ct = m,  K = SHA3-256(pk || ct)
//
// Decaps with a wrong sk returns a different K, like a real KEM does.

#include <array>
#include <string_view>

#include "hash/sha3.hpp"
#include "pq/error.hpp"
#include "pq/kem.hpp"

namespace pq::test {

class DummyKem final : public Kem {
 public:
  static constexpr std::string_view kName = "Dummy-KEM";

  [[nodiscard]] std::string_view name() const override { return kName; }
  [[nodiscard]] int security_level() const override { return 1; }
  [[nodiscard]] KemSizes sizes() const override { return {32, 32, 32, 32, 32, 32}; }

  [[nodiscard]] KeyPair keygen_derand(ByteView seed) const override {
    if (seed.size() != 32) {
      throw Error("DummyKem: seed must be 32 bytes");
    }
    const auto h = hash::sha3_256(seed);
    return {Bytes(h.begin(), h.end()), SecureBytes(ByteView(h))};
  }

  [[nodiscard]] Encapsulation encaps_derand(ByteView pk, ByteView m) const override {
    if (pk.size() != 32 || m.size() != 32) {
      throw Error("DummyKem: bad length");
    }
    return {Bytes(m.begin(), m.end()), derive(pk, m)};
  }

  [[nodiscard]] SecureBytes decaps(ByteView sk, ByteView ct) const override {
    if (sk.size() != 32 || ct.size() != 32) {
      throw Error("DummyKem: bad length");
    }
    return derive(sk, ct);
  }

 private:
  static SecureBytes derive(ByteView pk, ByteView ct) {
    hash::Sha3_256 h;
    h.update(pk);
    h.update(ct);
    std::array<uint8_t, 32> out{};
    h.finalize(out);
    SecureBytes ss{ByteView(out)};
    secure_zero(out.data(), out.size());
    return ss;
  }
};

}  // namespace pq::test
