#pragma once

#include <string_view>
#include <vector>

#include "avalanche.hpp"
#include "pq/registry.hpp"

namespace pq::analysis {

enum class FlipTarget { Message, Key };

// rounds == 0 selects the full cipher. A fresh cipher instance is used.
[[nodiscard]] AvalancheResult cipher_avalanche(const Registry& registry, std::string_view cipher,
                                               FlipTarget target, Rng& rng,
                                               const AvalancheOptions& options = {},
                                               int32_t rounds = 0);

struct RoundAvalanche {
  int32_t rounds = 0;
  uint64_t pairs = 0;
  double mean = 0;
  double variance = 0;
  double max_sac_deviation = 0;
  std::optional<double> max_absolute_bic;
};

// Replays the same deterministic input stream for each round, for a paired comparison.
// Summaries avoid retaining a separate SAC/BIC matrix for every round.
[[nodiscard]] std::vector<RoundAvalanche> cipher_round_avalanche(
    const Registry& registry, std::string_view cipher, FlipTarget target, ByteView seed,
    const AvalancheOptions& options = {});

// Encrypts synthetic messages with one fixed key and IV for the experiment only.
// CBC's output includes padding. These ciphertexts are not exported or reused.
[[nodiscard]] AvalancheResult mode_avalanche(const Registry& registry, std::string_view mode,
                                             std::string_view cipher, size_t message_bytes,
                                             Rng& rng, const AvalancheOptions& options = {});

struct ModePropagation {
  std::vector<size_t> encryption_changed_bits;
  std::vector<size_t> decryption_changed_bits;
  bool modified_ciphertext_accepted = false;
};

// Flips one plaintext bit, and independently the same-index bit of its original
// ciphertext. Only per-block Hamming distances are released, not decrypted bytes.
[[nodiscard]] ModePropagation mode_propagation(const Registry& registry, std::string_view mode,
                                               std::string_view cipher, size_t message_bytes,
                                               size_t flipped_bit, Rng& rng);

// Tests one changed ciphertext/tag bit of an authenticated message.
[[nodiscard]] bool aead_rejects_change(const Registry& registry, std::string_view mode,
                                       std::string_view cipher, size_t message_bytes,
                                       size_t flipped_bit, Rng& rng);

}  // namespace pq::analysis
