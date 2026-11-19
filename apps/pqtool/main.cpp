#include <iostream>
#include <span>
#include <string_view>

#include "file_io.hpp"
#include "keystore/fs_util.hpp"
#include "keystore/rotation.hpp"

namespace {

constexpr std::string_view kUsage =
    "pqtool create KEM LABEL --password-file FILE\n"
    "pqtool list\n"
    "pqtool encrypt KEM CIPHER INPUT OUTPUT\n"
    "pqtool decrypt INPUT OUTPUT --password-file FILE\n"
    "pqtool rotate KEY_ID --password-file FILE\n"
    "pqtool rewrap INPUT OUTPUT [TARGET_KEM] --password-file FILE\n"
    "\nPQLAB_HOME selects the keystore. Password files contain exact bytes (including newlines).\n"
    "Input files are buffered in memory. OUTPUT must be a new path. Key IDs may be unique "
    "prefixes.\n";

void run(std::span<char*> args) {
  const std::string_view command = args.front();
  args = args.subspan(1);
  const bool needs_password =
      command == "create" || command == "decrypt" || command == "rotate" || command == "rewrap";
  const char* password_path = nullptr;
  if (needs_password) {
    if (args.size() < 2 || std::string_view(args[args.size() - 2]) != "--password-file") {
      throw pq::Error("provide --password-file FILE as the final arguments");
    }
    password_path = args.back();
    args = args.first(args.size() - 2);
  }
  const bool valid =
      (command == "create" && args.size() == 2) || (command == "list" && args.empty()) ||
      (command == "encrypt" && args.size() == 4) || (command == "decrypt" && args.size() == 2) ||
      (command == "rotate" && args.size() == 1) ||
      (command == "rewrap" && (args.size() == 2 || args.size() == 3));
  if (!valid) throw pq::Error("invalid invocation; use pqtool --help");

  pq::SecureBytes password;
  if (password_path) {
    password = pq::keystore::fs::read_secret_file(password_path);
    if (password.empty()) throw pq::Error("password file must contain at least one byte");
  }
  const auto& registry = pq::Registry::global();
  pq::SystemRng rng;
  pq::keystore::Keystore store(registry, rng);
  const pq::hybrid::KemDem hybrid(registry);
  if (command == "list") {
    for (const auto& record : store.list()) {
      std::cout << pq::keystore::key_id_hex(record.key_id) << '\t' << record.kem << '\t'
                << pq::keystore::to_string(record.status) << '\t' << record.label << '\n';
    }
  } else if (command == "create") {
    std::cout << pq::keystore::key_id_hex(store.create_key(args[0], args[1], password)) << '\n';
  } else if (command == "rotate") {
    std::cout << pq::keystore::key_id_hex(store.rotate(store.resolve(args[0]), password)) << '\n';
  } else if (command == "encrypt") {
    const auto data = pq::tool::read_input(args[2]);
    const auto envelope = encrypt_to_active(store, hybrid, args[0], args[1], data, rng);
    pq::tool::write_new_file(args[3], envelope);
  } else if (command == "decrypt") {
    const auto envelope = pq::tool::read_input(args[0]);
    const auto opened = decrypt(store, hybrid, envelope, password);
    if (!opened) throw pq::Error("envelope authentication failed");
    pq::tool::write_new_file(args[1], *opened);
  } else {
    const auto envelope = pq::tool::read_input(args[0]);
    const auto moved =
        rewrap_to_active(store, hybrid, envelope, password, args.size() == 3 ? args[2] : "", rng);
    pq::tool::write_new_file(args[1], moved);
  }
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 2 ||
      (argc == 2 && (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h"))) {
    std::cout << kUsage;
    return argc < 2 ? 1 : 0;
  }
  try {
    run({argv + 1, static_cast<size_t>(argc - 1)});
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "pqtool: " << error.what() << '\n';
    return 1;
  }
}
