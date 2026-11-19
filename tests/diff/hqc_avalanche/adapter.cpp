// An isolated measurement client for the public API of the HQC v5.1.0 reference.
#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "pq/ct.hpp"

extern "C" {
#include "fips202.h"
#include "hqc-kem.h"
#include "parameters.h"
#include "randombytes.h"

void randombytes_init(unsigned char* entropy, unsigned char* personalization, int strength);
int hqc_kat_randombytes(unsigned char* out, size_t size);
}

namespace {
using pq::ByteView;
using pq::SecureBytes;

// Only this standalone test executable provides this RNG to the unmodified reference.
// A request must match the next input's entire length. Decapsulation uses no coins.
std::array<ByteView, 2> pending{};
size_t next_coin = 0;
size_t coin_count = 0;

void require(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}

struct Keypair {
  pq::Bytes pk = pq::Bytes(CRYPTO_PUBLICKEYBYTES);
  SecureBytes sk{CRYPTO_SECRETKEYBYTES};
};

Keypair keygen(ByteView seed) {
  pending = {seed, ByteView{}};
  next_coin = 0;
  coin_count = 1;
  Keypair keys;
  require(hqc_kem_keygen(keys.pk.data(), keys.sk.data()) == 0 && next_coin == coin_count,
          "keygen coin schedule mismatch");
  pending = {};
  return keys;
}

struct Encapsulation {
  pq::Bytes ct = pq::Bytes(CRYPTO_CIPHERTEXTBYTES);
  SecureBytes ss{CRYPTO_BYTES};
};

Encapsulation encaps(ByteView pk, ByteView message, ByteView salt) {
  pending = {message, salt};
  next_coin = 0;
  coin_count = 2;
  Encapsulation result;
  require(
      hqc_kem_encaps(result.ss.data(), result.ct.data(), pk.data()) == 0 && next_coin == coin_count,
      "encapsulation coin schedule mismatch");
  pending = {};
  return result;
}

void verify_decapsulation(const Keypair& keys, const Encapsulation& enc) {
  SecureBytes recovered(CRYPTO_BYTES);
  require(hqc_kem_decaps(recovered.data(), keys.sk.data(), enc.ct.data()) == 0 &&
              pq::ct_equal(recovered, enc.ss),
          "decapsulation disagrees with encapsulation");
}

SecureBytes read_fixture(size_t size) {
  SecureBytes data(size);
  require(static_cast<bool>(std::cin.read(reinterpret_cast<char*>(data.data()), size)),
          "incomplete official KAT record");
  return data;
}

void verify_kats() {
  for (size_t i = 0; i < 100; ++i) {
    auto drbg_seed = read_fixture(48);
    randombytes_init(drbg_seed.data(), nullptr, 256);
    SecureBytes seed(SEED_BYTES), message(PARAM_K), salt(SALT_BYTES);
    for (const auto view : {seed.span(), message.span(), salt.span()}) {
      require(hqc_kat_randombytes(view.data(), view.size()) == 0, "official KAT RNG failed");
    }
    const auto keys = keygen(seed);
    const auto enc = encaps(keys.pk, message, salt);
    require(pq::ct_equal(keys.pk, read_fixture(keys.pk.size())), "KAT public key mismatch");
    require(pq::ct_equal(keys.sk, read_fixture(keys.sk.size())), "KAT private key mismatch");
    require(pq::ct_equal(enc.ct, read_fixture(enc.ct.size())), "KAT ciphertext mismatch");
    require(pq::ct_equal(enc.ss, read_fixture(enc.ss.size())), "KAT shared secret mismatch");
    verify_decapsulation(keys, enc);
  }
  require(std::cin.peek() == std::char_traits<char>::eof(), "unexpected extra KAT data");
}

size_t distance(ByteView a, ByteView b) {
  require(a.size() == b.size(), "inconsistent output sizes");
  size_t total = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    total += std::popcount(static_cast<unsigned>(a[i] ^ b[i]));
  }
  return total;
}

SecureBytes flipped(ByteView input, size_t bit) {
  SecureBytes result(input);
  result[bit / 8] ^= static_cast<uint8_t>(1U << (bit % 8));
  require(distance(input, result) == 1, "input pair must differ by exactly one bit");
  return result;
}

void print_distance(uint32_t trial, std::string_view component, std::string_view output,
                    size_t flipped_bit, ByteView input, ByteView a, ByteView b) {
  std::cout << CRYPTO_ALGNAME << ',' << trial << ',' << component << ',' << output << ','
            << flipped_bit << ',' << input.size() * 8 << ',' << a.size() * 8 << ','
            << distance(a, b) << '\n';
}

void measure(uint32_t samples) {
  for (uint32_t i = 0; i < samples; ++i) {
    const auto label =
        std::string("pqlab/hqc-avalanche/v1/") + CRYPTO_ALGNAME + "/" + std::to_string(i);
    SecureBytes coins(SEED_BYTES + PARAM_K + SALT_BYTES);
    shake256(coins.data(), coins.size(), reinterpret_cast<const uint8_t*>(label.data()),
             label.size());
    const auto seed = coins.view().first(SEED_BYTES);
    const auto message = coins.view().subspan(SEED_BYTES, PARAM_K);
    const auto salt = coins.view().last(SALT_BYTES);
    const size_t seed_bit = i % (8 * seed.size());
    const size_t message_bit = i % (8 * message.size());
    const auto keys = keygen(seed);
    const auto changed_keys = keygen(flipped(seed, seed_bit));
    const auto original = encaps(keys.pk, message, salt);
    const auto changed = encaps(keys.pk, flipped(message, message_bit), salt);
    if (i == 0) {
      const auto replay_keys = keygen(seed);
      const auto replay_enc = encaps(replay_keys.pk, message, salt);
      require(pq::ct_equal(replay_keys.pk, keys.pk) && pq::ct_equal(replay_keys.sk, keys.sk) &&
                  pq::ct_equal(replay_enc.ct, original.ct) &&
                  pq::ct_equal(replay_enc.ss, original.ss),
              "unchanged-input reproducibility check failed");
    }
    require(pq::ct_equal(ByteView(original.ct).last(SALT_BYTES), salt) &&
                pq::ct_equal(ByteView(changed.ct).last(SALT_BYTES), salt),
            "ciphertext does not preserve the fixed salt");
    verify_decapsulation(keys, original);
    verify_decapsulation(keys, changed);
    print_distance(i, "seed_kem", "pk", seed_bit, seed, keys.pk, changed_keys.pk);
    print_distance(i, "m", "ct", message_bit, message, original.ct, changed.ct);
    print_distance(i, "m", "ss", message_bit, message, original.ss, changed.ss);
  }
}
}  // namespace

extern "C" int randombytes(uint8_t* out, size_t size) {
  if (next_coin >= coin_count || pending[next_coin].size() != size) return -1;
  std::copy_n(pending[next_coin++].begin(), size, out);
  return 0;
}

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "kat") {
      verify_kats();
    } else {
      require(argc == 3 && std::string_view(argv[1]) == "measure", "expected kat or measure N");
      const std::string_view arg(argv[2]);
      uint32_t samples = 0;
      const auto result = std::from_chars(arg.begin(), arg.end(), samples);
      require(result.ec == std::errc{} && result.ptr == arg.end() && samples >= 2,
              "sample count must be at least two");
      measure(samples);
    }
  } catch (const std::exception& error) {
    std::cerr << CRYPTO_ALGNAME << ": " << error.what() << '\n';
    return 1;
  }
}
