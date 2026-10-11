#pragma once

// Append-only, hash-chained audit log: one JSON object per line.
//
//   mac_i = HMAC-SHA3-256(audit_key, mac_{i-1} || canonical(entry_i)),  mac_{-1} = 32 zero bytes
//
// Editing, deleting, inserting or reordering any line breaks the chain from that line on,
// and verify() finds the first broken line. What it cannot see: removal of the last lines
// (nothing later refers to them) and anything done by someone who can read audit_key.
// Entries never contain secrets: only event names, key ids and short fixed descriptions.

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "pq/secure_bytes.hpp"

namespace pq::keystore {

struct AuditEntry {
  uint64_t seq = 0;
  int64_t time = 0;  // Unix seconds
  std::string event;
  std::string key_id;  // hex, or empty for keystore-wide events
  std::string detail;
};

struct AuditVerdict {
  bool ok = true;
  size_t entries = 0;   // lines that passed
  size_t bad_line = 0;  // 1-based number of the first failing line, 0 if ok
  std::string problem;  // short reason, empty if ok
};

class AuditLog {
 public:
  // The file need not exist yet. key must be 32 bytes.
  AuditLog(std::filesystem::path file, ByteView audit_key);

  // Appends one entry; seq and the chain value continue from the current last line.
  // Throws pq::Error if the last line cannot be parsed.
  void append(int64_t time, std::string_view event, std::string_view key_id,
              std::string_view detail);

  // Entries in file order, without checking the chain. Throws pq::Error on a line that
  // does not parse.
  [[nodiscard]] std::vector<AuditEntry> read() const;

  [[nodiscard]] AuditVerdict verify() const;

 private:
  std::filesystem::path file_;
  SecureBytes key_;
};

}  // namespace pq::keystore
