#include "hybrid/kem_dem.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <string>

#include "hash/hkdf.hpp"
#include "hybrid/envelope.hpp"
#include "hybrid/ids.hpp"
#include "pq/error.hpp"

namespace pq::hybrid {

namespace {

constexpr std::string_view kAeadMode = "GCM";
constexpr std::string_view kKdfLabel = "pqlab";

std::unique_ptr<Aead> make_aead(const Registry& registry, std::string_view aead_full_name) {
  // "AES-256-GCM" -> mode "GCM", cipher "AES-256".
  if (aead_full_name.size() <= kAeadMode.size() + 1 ||
      aead_full_name.substr(aead_full_name.size() - kAeadMode.size()) != kAeadMode) {
    throw Error("envelope: unsupported AEAD");
  }
  const std::string_view cipher =
      aead_full_name.substr(0, aead_full_name.size() - kAeadMode.size() - 1);
  auto aead = registry.aead(kAeadMode, cipher);
  if (aead->nonce_size() != kNonceSize || aead->tag_size() != kTagSize ||
      aead->key_size() > kDekSize) {
    throw Error("AEAD does not fit the PQL1 format");
  }
  return aead;
}

// KEK = HKDF-SHA3-256(IKM = K, salt = ct_kem, info = "pqlab" || kem_id || aead_id).
SecureBytes derive_kek(ByteView shared_secret, ByteView kem_ct, uint8_t kem_id_byte,
                       uint8_t aead_id_byte, size_t key_size) {
  Bytes info(kKdfLabel.begin(), kKdfLabel.end());
  info.push_back(kem_id_byte);
  info.push_back(aead_id_byte);
  SecureBytes kek(key_size);
  hash::hkdf_sha3_256(kek.span(), shared_secret, kem_ct, info);
  return kek;
}

// The data key is the first key_size() bytes of the 32-byte DEK.
ByteView data_key(const SecureBytes& dek, const Aead& aead) {
  return dek.view().first(aead.key_size());
}

// Fills b.wrapped_dek and b.wrap_tag. b.kem_ct, b.kem_id and b.wrap_nonce must be set.
void wrap_dek(Aead& aead, ByteView shared_secret, const PartA& a, PartB& b,
              const SecureBytes& dek) {
  const SecureBytes kek = derive_kek(shared_secret, b.kem_ct, b.kem_id, a.aead_id, aead.key_size());
  const Bytes sealed = aead.seal(kek, b.wrap_nonce, wrap_aad(a, b), dek);
  std::copy_n(sealed.begin(), kDekSize, b.wrapped_dek.begin());
  std::copy_n(sealed.begin() + kDekSize, kTagSize, b.wrap_tag.begin());
}

std::optional<SecureBytes> unwrap_dek(const Registry& registry, const Header& h, ByteView sk,
                                      Aead& aead) {
  const std::unique_ptr<Kem> kem = registry.kem(kem_name(h.b.kem_id));
  if (h.b.kem_ct.size() != kem->sizes().ct) {
    throw Error("envelope: wrong KEM ciphertext length");
  }
  const SecureBytes shared_secret = kem->decaps(sk, h.b.kem_ct);
  const SecureBytes kek =
      derive_kek(shared_secret, h.b.kem_ct, h.b.kem_id, h.a.aead_id, aead.key_size());
  Bytes sealed(h.b.wrapped_dek.begin(), h.b.wrapped_dek.end());
  sealed.insert(sealed.end(), h.b.wrap_tag.begin(), h.b.wrap_tag.end());
  return aead.open(kek, h.b.wrap_nonce, wrap_aad(h.a, h.b), sealed);
}

}  // namespace

Bytes KemDem::seal(std::string_view kem_name_in, ByteView pk, std::string_view cipher,
                   ByteView plaintext, Rng& rng) const {
  const std::unique_ptr<Kem> kem = registry_.kem(kem_name_in);
  const std::string aead_full_name = std::string(cipher) + "-" + std::string(kAeadMode);
  const std::unique_ptr<Aead> aead = make_aead(registry_, aead_full_name);

  const size_t chunks = std::max<size_t>(1, (plaintext.size() + kChunkSize - 1) / kChunkSize);
  if (chunks - 1 > std::numeric_limits<uint32_t>::max()) {
    throw Error("plaintext too large for one envelope");
  }

  PartA a;
  a.aead_id = aead_id(aead_full_name);
  rng.fill(a.nonce_prefix);

  Encapsulation enc = kem->encaps(pk, rng);
  PartB b;
  b.kem_id = kem_id(kem_name_in);
  b.key_id = compute_key_id(pk);
  b.kem_ct = std::move(enc.ct);
  rng.fill(b.wrap_nonce);

  SecureBytes dek(kDekSize);
  rng.fill(dek.span());
  wrap_dek(*aead, enc.ss, a, b, dek);

  Bytes out = serialize_part_a(a);
  const Bytes part_a = out;
  const Bytes part_b = serialize_part_b(b);
  out.insert(out.end(), part_b.begin(), part_b.end());
  out.reserve(out.size() + plaintext.size() + chunks * kTagSize);

  for (size_t i = 0; i < chunks; ++i) {
    const size_t off = i * kChunkSize;
    const size_t len = std::min(kChunkSize, plaintext.size() - off);
    const bool last = i + 1 == chunks;
    const auto nonce = chunk_nonce(a.nonce_prefix, static_cast<uint32_t>(i), last);
    const Bytes sealed =
        aead->seal(data_key(dek, *aead), nonce, part_a, plaintext.subspan(off, len));
    out.insert(out.end(), sealed.begin(), sealed.end());
  }
  return out;
}

std::optional<SecureBytes> KemDem::open(ByteView sk, ByteView envelope) const {
  const Header h = parse_header(envelope);
  const std::unique_ptr<Aead> aead = make_aead(registry_, aead_name(h.a.aead_id));
  const std::optional<SecureBytes> dek = unwrap_dek(registry_, h, sk, *aead);
  if (!dek) {
    return std::nullopt;
  }

  const ByteView data = envelope.subspan(h.size);
  const ByteView part_a = envelope.first(kPartASize);
  constexpr size_t kFullChunk = kChunkSize + kTagSize;
  const size_t tail = data.size() % kFullChunk;
  if (data.empty() || (tail != 0 && tail < kTagSize)) {
    return std::nullopt;
  }
  const size_t chunks = data.size() / kFullChunk + (tail != 0 ? 1 : 0);
  if (chunks - 1 > std::numeric_limits<uint32_t>::max()) {
    return std::nullopt;
  }

  SecureBytes plaintext(data.size() - chunks * kTagSize);
  size_t written = 0;
  for (size_t i = 0; i < chunks; ++i) {
    const bool last = i + 1 == chunks;
    const ByteView chunk = data.subspan(i * kFullChunk, last && tail != 0 ? tail : kFullChunk);
    const auto nonce = chunk_nonce(h.a.nonce_prefix, static_cast<uint32_t>(i), last);
    const std::optional<SecureBytes> pt = aead->open(data_key(*dek, *aead), nonce, part_a, chunk);
    if (!pt) {
      return std::nullopt;
    }
    std::copy(pt->begin(), pt->end(), plaintext.begin() + static_cast<std::ptrdiff_t>(written));
    written += pt->size();
  }
  return plaintext;
}

std::optional<Bytes> KemDem::rewrap(ByteView old_sk, std::string_view new_kem_name, ByteView new_pk,
                                    ByteView envelope, Rng& rng) const {
  const Header h = parse_header(envelope);
  const std::unique_ptr<Aead> aead = make_aead(registry_, aead_name(h.a.aead_id));
  const std::optional<SecureBytes> dek = unwrap_dek(registry_, h, old_sk, *aead);
  if (!dek) {
    return std::nullopt;
  }

  const std::unique_ptr<Kem> new_kem = registry_.kem(new_kem_name);
  Encapsulation enc = new_kem->encaps(new_pk, rng);
  PartB b;
  b.kem_id = kem_id(new_kem_name);
  b.key_id = compute_key_id(new_pk);
  b.kem_ct = std::move(enc.ct);
  rng.fill(b.wrap_nonce);
  wrap_dek(*aead, enc.ss, h.a, b, *dek);

  // Part A and the data are copied from the input, not re-serialized.
  Bytes out(envelope.begin(), envelope.begin() + kPartASize);
  const Bytes part_b = serialize_part_b(b);
  out.insert(out.end(), part_b.begin(), part_b.end());
  out.insert(out.end(), envelope.begin() + static_cast<std::ptrdiff_t>(h.size), envelope.end());
  return out;
}

}  // namespace pq::hybrid
