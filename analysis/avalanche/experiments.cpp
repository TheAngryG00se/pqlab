#include "experiments.hpp"

#include <algorithm>

#include "pq/error.hpp"

namespace pq::analysis {
namespace {

std::vector<size_t> block_distances(ByteView first, ByteView second, size_t block_size) {
  if (first.size() != second.size() || block_size == 0) {
    throw Error("Mode propagation requires equal lengths and a nonzero block size");
  }
  std::vector<size_t> distances;
  for (size_t offset = 0; offset < first.size(); offset += block_size) {
    const size_t length = std::min(block_size, first.size() - offset);
    distances.push_back(
        hamming_distance(first.subspan(offset, length), second.subspan(offset, length)));
  }
  return distances;
}

void flip_bit(MutByteView bytes, size_t bit) {
  if (bit / 8 >= bytes.size()) {
    throw Error("Flipped bit is outside the message");
  }
  bytes[bit / 8] ^= static_cast<uint8_t>(1U << (bit & 7));
}

}  // namespace

AvalancheResult cipher_avalanche(const Registry& registry, std::string_view name, FlipTarget target,
                                 Rng& rng, const AvalancheOptions& options, int32_t rounds) {
  if (target != FlipTarget::Message && target != FlipTarget::Key) {
    throw Error("Unknown avalanche input target");
  }
  auto cipher = registry.cipher(name);
  if (rounds < 0 || rounds > cipher->rounds()) {
    throw Error("Invalid avalanche round count");
  }
  if (rounds != 0) {
    cipher->set_rounds(rounds);
  }
  const size_t block_size = cipher->block_size();
  SecureBytes fixed(target == FlipTarget::Message ? cipher->key_size() : block_size);
  rng.fill(fixed.span());
  if (target == FlipTarget::Message) {
    cipher->set_key(fixed);
    return measure_avalanche(
        [&](ByteView input) {
          Bytes output(block_size);
          cipher->encrypt_block(input.data(), output.data());
          return output;
        },
        block_size, block_size, rng, options);
  }
  return measure_avalanche(
      [&](ByteView input) {
        cipher->set_key(input);
        Bytes output(block_size);
        cipher->encrypt_block(fixed.data(), output.data());
        return output;
      },
      cipher->key_size(), block_size, rng, options);
}

std::vector<RoundAvalanche> cipher_round_avalanche(const Registry& registry, std::string_view name,
                                                   FlipTarget target, ByteView seed,
                                                   const AvalancheOptions& options) {
  const int32_t full_rounds = registry.cipher(name)->rounds();
  std::vector<RoundAvalanche> results;
  for (int32_t round = 1; round <= full_rounds; ++round) {
    DeterministicRng rng(seed);
    const auto result = cipher_avalanche(registry, name, target, rng, options, round);
    results.push_back({round, result.pairs, result.mean, result.variance,
                       result.max_sac_deviation(), result.max_absolute_bic()});
  }
  return results;
}

AvalancheResult mode_avalanche(const Registry& registry, std::string_view mode,
                               std::string_view cipher, size_t message_bytes, Rng& rng,
                               const AvalancheOptions& options) {
  auto algorithm = registry.cipher_mode(mode, cipher);
  SecureBytes key(algorithm->key_size());
  Bytes iv(algorithm->iv_size());
  rng.fill(key.span());
  rng.fill(iv);
  // Query the output length through the public interface, including CBC padding.
  SecureBytes probe(message_bytes);
  const size_t output_bytes = algorithm->encrypt(key, iv, probe).size();
  return measure_avalanche([&](ByteView input) { return algorithm->encrypt(key, iv, input); },
                           message_bytes, output_bytes, rng, options);
}

ModePropagation mode_propagation(const Registry& registry, std::string_view mode,
                                 std::string_view cipher, size_t message_bytes, size_t flipped_bit,
                                 Rng& rng) {
  if (flipped_bit / 8 >= message_bytes) {
    throw Error("Flipped bit is outside the plaintext");
  }
  auto algorithm = registry.cipher_mode(mode, cipher);
  SecureBytes key(algorithm->key_size());
  SecureBytes message(message_bytes);
  Bytes iv(algorithm->iv_size());
  rng.fill(key.span());
  rng.fill(message.span());
  rng.fill(iv);
  const Bytes original = algorithm->encrypt(key, iv, message);
  flip_bit(message.span(), flipped_bit);
  const Bytes modified = algorithm->encrypt(key, iv, message);
  flip_bit(message.span(), flipped_bit);
  ModePropagation result;
  result.encryption_changed_bits = block_distances(original, modified, algorithm->block_size());
  Bytes tampered = original;
  flip_bit(tampered, flipped_bit);
  auto decrypted = algorithm->decrypt(key, iv, tampered);
  result.modified_ciphertext_accepted = decrypted.has_value();
  if (decrypted) {
    // A modified final CBC block can also produce valid padding of a different
    // length. Acceptance and length changes are distinct from bit propagation.
    if (decrypted->size() == message.size()) {
      result.decryption_changed_bits =
          block_distances(message, *decrypted, algorithm->block_size());
    }
  }
  return result;
}

bool aead_rejects_change(const Registry& registry, std::string_view mode, std::string_view cipher,
                         size_t message_bytes, size_t flipped_bit, Rng& rng) {
  auto algorithm = registry.aead(mode, cipher);
  SecureBytes key(algorithm->key_size());
  SecureBytes message(message_bytes);
  Bytes nonce(algorithm->nonce_size());
  rng.fill(key.span());
  rng.fill(message.span());
  rng.fill(nonce);
  Bytes ciphertext = algorithm->seal(key, nonce, {}, message);
  flip_bit(ciphertext, flipped_bit);
  return !algorithm->open(key, nonce, {}, ciphertext).has_value();
}

}  // namespace pq::analysis
