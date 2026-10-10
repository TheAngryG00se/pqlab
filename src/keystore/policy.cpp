#include "keystore/policy.hpp"

#include <string>

#include "pq/error.hpp"

namespace pq::keystore {

std::string_view to_string(Status s) {
  switch (s) {
    case Status::kActive:
      return "active";
    case Status::kRetired:
      return "retired";
    case Status::kDestroyed:
      return "destroyed";
    case Status::kRevoked:
      return "revoked";
  }
  throw Error("invalid key status");
}

Status parse_status(std::string_view name) {
  for (const Status s : {Status::kActive, Status::kRetired, Status::kDestroyed, Status::kRevoked}) {
    if (to_string(s) == name) {
      return s;
    }
  }
  throw Error("unknown key status '" + std::string(name) + "'");
}

bool can_encrypt(Status s) { return s == Status::kActive; }

bool can_unseal(Status s) {
  return s == Status::kActive || s == Status::kRetired || s == Status::kRevoked;
}

bool transition_allowed(Status from, Status to) {
  switch (to) {
    case Status::kRetired:
      return from == Status::kActive;
    case Status::kDestroyed:
      return from == Status::kRetired || from == Status::kRevoked;
    case Status::kRevoked:
      return from != Status::kRevoked;
    case Status::kActive:
      return false;
  }
  return false;
}

bool rotation_due(Status s, int64_t created, int64_t now, const Policy& policy) {
  return s == Status::kActive && now - created >= policy.max_active_age_seconds;
}

}  // namespace pq::keystore
