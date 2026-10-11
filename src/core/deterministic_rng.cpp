#include "hash/shake.hpp"
#include "pq/rng.hpp"

namespace pq {

struct DeterministicRng::State {
  hash::Shake256 xof;
};

DeterministicRng::DeterministicRng(ByteView seed) : state_(std::make_unique<State>()) {
  state_->xof.absorb(seed);
}

DeterministicRng::~DeterministicRng() = default;

void DeterministicRng::fill(std::span<uint8_t> out) { state_->xof.squeeze(out); }

}  // namespace pq
