#pragma once

// Glue between the keystore and KEM-DEM: encrypt to the current key, decrypt by the key
// id in the envelope, and move data to a new key after a rotation (rewrap).

#include <optional>
#include <string_view>

#include "hybrid/kem_dem.hpp"
#include "keystore/keystore.hpp"

namespace pq::keystore {

// Seals plaintext to the newest active key of kem. Needs no password: only the public key
// is read. Throws pq::Error if there is no active key of that KEM.
[[nodiscard]] Bytes encrypt_to_active(const Keystore& ks, const hybrid::KemDem& kd,
                                      std::string_view kem, std::string_view cipher,
                                      ByteView plaintext, Rng& rng);

// Finds the key by the key_id in the envelope header and unlocks it. Throws pq::Error for a
// malformed envelope or an unknown or destroyed key, PasswordError for a wrong password.
// std::nullopt if the envelope fails authentication.
[[nodiscard]] std::optional<SecureBytes> decrypt(Keystore& ks, const hybrid::KemDem& kd,
                                                 ByteView envelope, ByteView password);

// Moves the envelope from the key it names to the newest active key of target_kem (empty:
// the KEM of the current key). Part A and the data are unchanged (KemDem::rewrap). An
// envelope that already uses that key is returned as it is. Throws as decrypt does, and
// pq::Error if there is no active key of the target KEM. Audited as envelope_rewrapped.
[[nodiscard]] Bytes rewrap_to_active(Keystore& ks, const hybrid::KemDem& kd, ByteView envelope,
                                     ByteView password, std::string_view target_kem, Rng& rng);

}  // namespace pq::keystore
