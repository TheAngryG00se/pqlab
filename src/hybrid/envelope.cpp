#include "hybrid/envelope.hpp"

#include <algorithm>

#include "core/endian.hpp"
#include "hash/sha3.hpp"
#include "pq/error.hpp"

namespace pq::hybrid {

namespace {

constexpr std::array<uint8_t, 4> kMagic = {'P', 'Q', 'L', '1'};

// Fixed part of part B in front of ct_kem.
constexpr size_t kPartBPrefix = 1 + kKeyIdSize + 4;
constexpr size_t kPartBSuffix = kNonceSize + kDekSize + kTagSize;

void append(Bytes& out, ByteView v) { out.insert(out.end(), v.begin(), v.end()); }

void append_b_head(Bytes& out, const PartB& b) {
  out.push_back(b.kem_id);
  append(out, b.key_id);
  std::array<uint8_t, 4> len{};
  store32_be(len.data(), static_cast<uint32_t>(b.kem_ct.size()));
  append(out, len);
  append(out, b.kem_ct);
  append(out, b.wrap_nonce);
}

}  // namespace

Bytes serialize_part_a(const PartA& a) {
  Bytes out;
  out.reserve(kPartASize);
  append(out, kMagic);
  out.push_back(a.version);
  out.push_back(a.aead_id);
  append(out, a.nonce_prefix);
  return out;
}

Bytes serialize_part_b(const PartB& b) {
  Bytes out;
  out.reserve(kPartBPrefix + b.kem_ct.size() + kPartBSuffix);
  append_b_head(out, b);
  append(out, b.wrapped_dek);
  append(out, b.wrap_tag);
  return out;
}

Bytes wrap_aad(const PartA& a, const PartB& b) {
  Bytes out = serialize_part_a(a);
  append_b_head(out, b);
  return out;
}

Header parse_header(ByteView env) {
  if (env.size() < kPartASize) {
    throw Error("envelope: truncated header");
  }
  if (!std::equal(kMagic.begin(), kMagic.end(), env.begin())) {
    throw Error("envelope: bad magic");
  }
  Header h;
  h.a.version = env[4];
  if (h.a.version != kEnvelopeVersion) {
    throw Error("envelope: unsupported version");
  }
  h.a.aead_id = env[5];
  std::copy_n(env.begin() + 6, kNoncePrefixSize, h.a.nonce_prefix.begin());

  ByteView rest = env.subspan(kPartASize);
  if (rest.size() < kPartBPrefix) {
    throw Error("envelope: truncated header");
  }
  h.b.kem_id = rest[0];
  std::copy_n(rest.begin() + 1, kKeyIdSize, h.b.key_id.begin());
  const size_t ct_len = load32_be(rest.data() + 1 + kKeyIdSize);
  rest = rest.subspan(kPartBPrefix);
  // Compare against what is left before allocating anything.
  if (rest.size() < kPartBSuffix || rest.size() - kPartBSuffix < ct_len) {
    throw Error("envelope: truncated header");
  }
  h.b.kem_ct.assign(rest.begin(), rest.begin() + static_cast<std::ptrdiff_t>(ct_len));
  rest = rest.subspan(ct_len);
  std::copy_n(rest.begin(), kNonceSize, h.b.wrap_nonce.begin());
  std::copy_n(rest.begin() + kNonceSize, kDekSize, h.b.wrapped_dek.begin());
  std::copy_n(rest.begin() + kNonceSize + kDekSize, kTagSize, h.b.wrap_tag.begin());
  h.size = kPartASize + kPartBPrefix + ct_len + kPartBSuffix;
  return h;
}

std::array<uint8_t, kNonceSize> chunk_nonce(const std::array<uint8_t, kNoncePrefixSize>& prefix,
                                            uint32_t index, bool last) {
  std::array<uint8_t, kNonceSize> n{};
  std::copy(prefix.begin(), prefix.end(), n.begin());
  store32_be(n.data() + kNoncePrefixSize, index);
  n[kNonceSize - 1] = last ? 1 : 0;
  return n;
}

std::array<uint8_t, kKeyIdSize> compute_key_id(ByteView pk) {
  const auto digest = hash::sha3_256(pk);
  std::array<uint8_t, kKeyIdSize> id{};
  std::copy_n(digest.begin(), kKeyIdSize, id.begin());
  return id;
}

}  // namespace pq::hybrid
