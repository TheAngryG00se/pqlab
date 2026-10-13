#include "pq/registry.hpp"

#include <string>
#include <utility>

#include "kem/mlkem/register.hpp"
#include "pq/error.hpp"

namespace pq {

namespace {

template <typename Map, typename Factory>
void add_unique(Map& map, std::string name, Factory factory, const char* what) {
  if (!factory) {
    throw Error(std::string("Registry: empty factory for ") + what + " '" + name + "'");
  }
  const auto [it, inserted] = map.emplace(std::move(name), std::move(factory));
  if (!inserted) {
    throw Error(std::string("Registry: duplicate ") + what + " '" + it->first + "'");
  }
}

template <typename Map>
const typename Map::mapped_type& find_or_throw(const Map& map, std::string_view name,
                                               const char* what) {
  const auto it = map.find(name);
  if (it == map.end()) {
    throw Error(std::string("Registry: unknown ") + what + " '" + std::string(name) + "'");
  }
  return it->second;
}

template <typename Map>
std::vector<std::string> keys_of(const Map& map) {
  std::vector<std::string> names;
  names.reserve(map.size());
  for (const auto& entry : map) {
    names.push_back(entry.first);
  }
  return names;
}

}  // namespace

// Every module contributes through its own register_algorithms(). Block
// ciphers and modes are added here when src/cipher and src/mode exist.
Registry& Registry::global() {
  static Registry instance = [] {
    Registry r;
    mlkem::register_algorithms(r);
    return r;
  }();
  return instance;
}

void Registry::add_kem(std::string name, KemFactory factory) {
  add_unique(kems_, std::move(name), std::move(factory), "KEM");
}

void Registry::add_cipher(std::string name, CipherFactory factory) {
  add_unique(ciphers_, std::move(name), std::move(factory), "cipher");
}

void Registry::add_aead_mode(std::string mode, AeadFactory factory) {
  if (cipher_modes_.contains(mode)) {
    throw Error("Registry: duplicate mode '" + mode + "'");
  }
  add_unique(aead_modes_, std::move(mode), std::move(factory), "AEAD mode");
}

void Registry::add_cipher_mode(std::string mode, CipherModeFactory factory) {
  if (aead_modes_.contains(mode)) {
    throw Error("Registry: duplicate mode '" + mode + "'");
  }
  add_unique(cipher_modes_, std::move(mode), std::move(factory), "cipher mode");
}

std::unique_ptr<Kem> Registry::kem(std::string_view name) const {
  return find_or_throw(kems_, name, "KEM")();
}

std::unique_ptr<BlockCipher> Registry::cipher(std::string_view name) const {
  return find_or_throw(ciphers_, name, "cipher")();
}

std::unique_ptr<Aead> Registry::aead(std::string_view mode, std::string_view cipher_name) const {
  const AeadFactory& make_mode = find_or_throw(aead_modes_, mode, "AEAD mode");
  return make_mode(cipher(cipher_name));
}

std::unique_ptr<CipherMode> Registry::cipher_mode(std::string_view mode,
                                                  std::string_view cipher_name) const {
  const CipherModeFactory& make_mode = find_or_throw(cipher_modes_, mode, "cipher mode");
  return make_mode(cipher(cipher_name));
}

std::vector<std::string> Registry::list_kems() const { return keys_of(kems_); }
std::vector<std::string> Registry::list_ciphers() const { return keys_of(ciphers_); }
std::vector<std::string> Registry::list_modes() const { return keys_of(aead_modes_); }
std::vector<std::string> Registry::list_cipher_modes() const { return keys_of(cipher_modes_); }

}  // namespace pq
