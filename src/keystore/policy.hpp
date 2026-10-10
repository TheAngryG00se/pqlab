#pragma once

// Key life cycle (AGENTS.md, section 10):
//   active -> retired -> destroyed,  and revoked from any state.
// Only an active key may encrypt new data.

#include <cstdint>
#include <string_view>

namespace pq::keystore {

enum class Status : uint8_t { kActive, kRetired, kDestroyed, kRevoked };

[[nodiscard]] std::string_view to_string(Status s);
// Throws pq::Error for an unknown name.
[[nodiscard]] Status parse_status(std::string_view name);

struct Policy {
  // An active key older than this is due for rotation. 90 days by default.
  int64_t max_active_age_seconds = 90LL * 24 * 3600;
};

// New data may be encrypted to this key.
[[nodiscard]] bool can_encrypt(Status s);
// The seed may still be unsealed: active, retired and revoked keys. A revoked key is
// kept readable so that data can be moved off it; every use is audited.
[[nodiscard]] bool can_unseal(Status s);
// Allowed edges: active->retired, retired->destroyed, revoked->destroyed, and
// anything->revoked except revoked->revoked.
[[nodiscard]] bool transition_allowed(Status from, Status to);
[[nodiscard]] bool rotation_due(Status s, int64_t created, int64_t now, const Policy& policy);

}  // namespace pq::keystore
