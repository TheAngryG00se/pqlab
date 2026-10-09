#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "pq/aead.hpp"
#include "pq/cipher.hpp"
#include "pq/kem.hpp"

namespace pq {

// Factory by canonical name (AGENTS.md, section 5). Applications and services
// obtain algorithms only through the registry.
// Implemented in src/core (participant 4).
class Registry {
 public:
  using KemFactory = std::function<std::unique_ptr<Kem>()>;
  using CipherFactory = std::function<std::unique_ptr<BlockCipher>()>;
  // Builds an AEAD mode (e.g. "GCM") around a fresh cipher instance.
  using AeadFactory = std::function<std::unique_ptr<Aead>(std::unique_ptr<BlockCipher>)>;

  // Registry with every built-in algorithm. Attack-only variants from
  // analysis/attacks/ are never registered here.
  static Registry& global();

  // Throw pq::Error if the name is already taken.
  void add_kem(std::string name, KemFactory factory);
  void add_cipher(std::string name, CipherFactory factory);
  void add_aead_mode(std::string mode, AeadFactory factory);

  // Throw pq::Error for unknown names.
  [[nodiscard]] std::unique_ptr<Kem> kem(std::string_view name) const;
  [[nodiscard]] std::unique_ptr<BlockCipher> cipher(std::string_view name) const;
  [[nodiscard]] std::unique_ptr<Aead> aead(std::string_view mode, std::string_view cipher) const;

  [[nodiscard]] std::vector<std::string> list_kems() const;
  [[nodiscard]] std::vector<std::string> list_ciphers() const;
  [[nodiscard]] std::vector<std::string> list_modes() const;

 private:
  std::map<std::string, KemFactory, std::less<>> kems_;
  std::map<std::string, CipherFactory, std::less<>> ciphers_;
  std::map<std::string, AeadFactory, std::less<>> aead_modes_;
};

}  // namespace pq
