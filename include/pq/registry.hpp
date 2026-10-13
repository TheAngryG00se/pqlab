#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "pq/aead.hpp"
#include "pq/cipher.hpp"
#include "pq/cipher_mode.hpp"
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
  // Builds an unauthenticated mode (e.g. "CBC") around a fresh cipher instance.
  using CipherModeFactory =
      std::function<std::unique_ptr<CipherMode>(std::unique_ptr<BlockCipher>)>;

  // Registry with every built-in algorithm. Attack-only variants from
  // analysis/attacks/ are never registered here.
  static Registry& global();

  // Throw pq::Error if the name is already taken. AEAD modes and unauthenticated modes
  // share one namespace of mode names.
  void add_kem(std::string name, KemFactory factory);
  void add_cipher(std::string name, CipherFactory factory);
  void add_aead_mode(std::string mode, AeadFactory factory);
  void add_cipher_mode(std::string mode, CipherModeFactory factory);

  // Throw pq::Error for unknown names.
  [[nodiscard]] std::unique_ptr<Kem> kem(std::string_view name) const;
  [[nodiscard]] std::unique_ptr<BlockCipher> cipher(std::string_view name) const;
  [[nodiscard]] std::unique_ptr<Aead> aead(std::string_view mode, std::string_view cipher) const;
  [[nodiscard]] std::unique_ptr<CipherMode> cipher_mode(std::string_view mode,
                                                        std::string_view cipher) const;

  [[nodiscard]] std::vector<std::string> list_kems() const;
  [[nodiscard]] std::vector<std::string> list_ciphers() const;
  // AEAD modes only ("GCM"); every name here works with aead().
  [[nodiscard]] std::vector<std::string> list_modes() const;
  // Unauthenticated modes ("ECB", "CBC", "CTR"); every name here works with cipher_mode().
  [[nodiscard]] std::vector<std::string> list_cipher_modes() const;

 private:
  std::map<std::string, KemFactory, std::less<>> kems_;
  std::map<std::string, CipherFactory, std::less<>> ciphers_;
  std::map<std::string, AeadFactory, std::less<>> aead_modes_;
  std::map<std::string, CipherModeFactory, std::less<>> cipher_modes_;
};

}  // namespace pq
