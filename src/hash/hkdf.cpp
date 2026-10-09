#include "hash/hkdf.hpp"

#include <algorithm>
#include <array>

#include "hash/hmac.hpp"
#include "pq/error.hpp"

namespace pq::hash {

void hkdf_sha3_256_extract(std::span<uint8_t, 32> prk, ByteView salt, ByteView ikm) {
  // HMAC pads the key with zeros anyway, so an empty salt and HashLen zero bytes
  // give the same result.
  hmac_sha3_256(prk, salt, ikm);
}

void hkdf_sha3_256_expand(MutByteView okm, ByteView prk, ByteView info) {
  if (okm.size() > kHkdfSha3_256MaxOutput) {
    throw Error("HKDF: output too long");
  }
  const HmacSha3_256 keyed(prk);
  std::array<uint8_t, HmacSha3_256::kMacSize> t{};
  size_t done = 0;
  for (uint32_t i = 1; done < okm.size(); ++i) {
    // T(i) = HMAC(PRK, T(i - 1) || info || i), T(0) = empty
    HmacSha3_256 mac = keyed;
    if (i > 1) {
      mac.update(t);
    }
    mac.update(info);
    const std::array<uint8_t, 1> counter{static_cast<uint8_t>(i)};
    mac.update(counter);
    mac.finalize(t);
    const size_t n = std::min(t.size(), okm.size() - done);
    std::copy_n(t.begin(), n, okm.begin() + static_cast<std::ptrdiff_t>(done));
    done += n;
  }
  secure_zero(t);
}

void hkdf_sha3_256(MutByteView okm, ByteView ikm, ByteView salt, ByteView info) {
  std::array<uint8_t, 32> prk{};
  hkdf_sha3_256_extract(prk, salt, ikm);
  hkdf_sha3_256_expand(okm, prk, info);
  secure_zero(prk);
}

}  // namespace pq::hash
