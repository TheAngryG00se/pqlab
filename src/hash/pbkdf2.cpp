#include "hash/pbkdf2.hpp"

#include <algorithm>
#include <array>

#include "core/endian.hpp"
#include "hash/hmac.hpp"
#include "pq/error.hpp"

namespace pq::hash {

void pbkdf2_hmac_sha3_256(MutByteView out, ByteView password, ByteView salt, uint32_t iterations) {
  if (iterations == 0 || out.empty()) {
    throw Error("PBKDF2: iterations and output length must be positive");
  }
  // RFC 8018, Section 5.2, step 1: dkLen <= (2^32 - 1) * hLen.
  constexpr size_t kH = HmacSha3_256::kMacSize;
  const uint64_t blocks = (out.size() + kH - 1) / kH;
  if (blocks > 0xFFFFFFFFULL) {
    throw Error("PBKDF2: derived key too long");
  }

  const HmacSha3_256 keyed(password);
  std::array<uint8_t, kH> u{};
  std::array<uint8_t, kH> t{};
  for (uint32_t i = 1; i <= blocks; ++i) {
    // U_1 = PRF(P, S || INT(i))
    HmacSha3_256 mac = keyed;
    mac.update(salt);
    std::array<uint8_t, 4> be_i{};
    store32_be(be_i.data(), i);
    mac.update(be_i);
    mac.finalize(u);
    t = u;
    // U_j = PRF(P, U_{j-1}), T_i = U_1 ^ ... ^ U_c
    for (uint32_t j = 2; j <= iterations; ++j) {
      keyed.compute(u, u);
      for (size_t k = 0; k < kH; ++k) {
        t[k] ^= u[k];
      }
    }
    const size_t done = static_cast<size_t>(i - 1) * kH;
    const size_t n = std::min(kH, out.size() - done);
    std::copy_n(t.begin(), n, out.begin() + static_cast<std::ptrdiff_t>(done));
  }
  secure_zero(u);
  secure_zero(t);
}

}  // namespace pq::hash
