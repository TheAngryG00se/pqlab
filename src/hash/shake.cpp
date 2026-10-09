#include "hash/shake.hpp"

namespace pq::hash {

void shake128(MutByteView out, ByteView in) {
  Shake128 x;
  x.absorb(in);
  x.squeeze(out);
}

void shake256(MutByteView out, ByteView in) {
  Shake256 x;
  x.absorb(in);
  x.squeeze(out);
}

}  // namespace pq::hash
