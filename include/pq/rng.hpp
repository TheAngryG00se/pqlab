#pragma once

#include <cstdint>
#include <memory>
#include <span>

#include "pq/secure_bytes.hpp"

namespace pq {

class Rng {
 public:
  virtual ~Rng() = default;
  virtual void fill(std::span<uint8_t> out) = 0;
};

// getrandom(2). The only Rng allowed in pqtool and KEM-DEM.
// Implemented in src/core (participant 4).
class SystemRng final : public Rng {
 public:
  void fill(std::span<uint8_t> out) override;
};

// SHAKE256(seed) output stream. Tests and pqanalyze only.
// Implemented in src/core (participant 4) on top of pq::hash::Shake256.
class DeterministicRng final : public Rng {
 public:
  explicit DeterministicRng(ByteView seed);
  ~DeterministicRng() override;
  DeterministicRng(const DeterministicRng&) = delete;
  DeterministicRng& operator=(const DeterministicRng&) = delete;

  void fill(std::span<uint8_t> out) override;

 private:
  struct State;
  std::unique_ptr<State> state_;
};

}  // namespace pq
