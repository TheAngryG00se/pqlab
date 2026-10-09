#include "hash/sha3.hpp"

namespace pq::hash {

void sha3_256(std::span<uint8_t, 32> out, ByteView in) {
  Sha3_256 h;
  h.update(in);
  h.finalize(out);
}

void sha3_512(std::span<uint8_t, 64> out, ByteView in) {
  Sha3_512 h;
  h.update(in);
  h.finalize(out);
}

std::array<uint8_t, 32> sha3_256(ByteView in) {
  std::array<uint8_t, 32> out{};
  sha3_256(out, in);
  return out;
}

std::array<uint8_t, 64> sha3_512(ByteView in) {
  std::array<uint8_t, 64> out{};
  sha3_512(out, in);
  return out;
}

}  // namespace pq::hash
