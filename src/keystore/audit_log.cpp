#include "keystore/audit_log.hpp"

#include <algorithm>
#include <array>
#include <nlohmann/json.hpp>
#include <sstream>
#include <utility>

#include "core/endian.hpp"
#include "hash/hmac.hpp"
#include "keystore/fs_util.hpp"
#include "keystore/hex.hpp"
#include "pq/ct.hpp"
#include "pq/error.hpp"

namespace pq::keystore {

namespace {

using Json = nlohmann::json;
using Mac = std::array<uint8_t, 32>;

void put_field(Bytes& out, std::string_view v) {
  std::array<uint8_t, 4> len{};
  store32_be(len.data(), static_cast<uint32_t>(v.size()));
  out.insert(out.end(), len.begin(), len.end());
  out.insert(out.end(), v.begin(), v.end());
}

Mac chain_mac(ByteView key, const Mac& prev, const AuditEntry& e) {
  Bytes msg(prev.begin(), prev.end());
  std::array<uint8_t, 16> nums{};
  store64_be(nums.data(), e.seq);
  store64_be(nums.data() + 8, static_cast<uint64_t>(e.time));
  msg.insert(msg.end(), nums.begin(), nums.end());
  put_field(msg, e.event);
  put_field(msg, e.key_id);
  put_field(msg, e.detail);
  Mac mac{};
  hash::hmac_sha3_256(mac, key, msg);
  return mac;
}

struct Line {
  AuditEntry entry;
  Mac mac{};
};

// Throws pq::Error if the line is not a well-formed entry.
Line parse_line(std::string_view text) {
  const Json j = Json::parse(text, nullptr, /*allow_exceptions=*/false);
  if (j.is_discarded() || !j.is_object() || j.size() != 6) {
    throw Error("audit log: malformed line");
  }
  Line l;
  try {
    l.entry.seq = j.at("seq").get<uint64_t>();
    l.entry.time = j.at("time").get<int64_t>();
    l.entry.event = j.at("event").get<std::string>();
    l.entry.key_id = j.at("key_id").get<std::string>();
    l.entry.detail = j.at("detail").get<std::string>();
    const Bytes mac = from_hex(j.at("mac").get<std::string>());
    if (mac.size() != l.mac.size()) {
      throw Error("audit log: bad mac length");
    }
    std::copy(mac.begin(), mac.end(), l.mac.begin());
  } catch (const Json::exception&) {
    throw Error("audit log: malformed line");
  }
  return l;
}

void require_valid(const AuditVerdict& verdict) {
  if (!verdict.ok) {
    throw Error("audit log at line " + std::to_string(verdict.bad_line) + ": " + verdict.problem);
  }
}

}  // namespace

AuditLog::AuditLog(std::filesystem::path file, ByteView audit_key)
    : file_(std::move(file)), key_(audit_key) {
  if (audit_key.size() != 32) {
    throw Error("audit key must be 32 bytes");
  }
}

void AuditLog::append(int64_t time, std::string_view event, std::string_view key_id,
                      std::string_view detail) {
  AuditEntry e;
  e.time = time;
  e.event = std::string(event);
  e.key_id = std::string(key_id);
  e.detail = std::string(detail);

  Mac prev{};
  const AuditVerdict verdict = inspect(nullptr, prev);
  require_valid(verdict);
  e.seq = verdict.entries;
  const Mac mac = chain_mac(key_, prev, e);

  Json j;
  j["seq"] = e.seq;
  j["time"] = e.time;
  j["event"] = e.event;
  j["key_id"] = e.key_id;
  j["detail"] = e.detail;
  j["mac"] = to_hex(mac);
  fs::append_file(file_, j.dump() + "\n");
}

std::vector<AuditEntry> AuditLog::read() const {
  std::vector<AuditEntry> out;
  Mac last{};
  require_valid(inspect(&out, last));
  return out;
}

AuditVerdict AuditLog::verify() const {
  Mac last{};
  return inspect(nullptr, last);
}

AuditVerdict AuditLog::inspect(std::vector<AuditEntry>* entries, Mac& last_mac) const {
  AuditVerdict v;
  if (!std::filesystem::exists(file_)) {
    return v;
  }
  std::istringstream input(fs::read_file(file_));
  std::string text;
  size_t n = 0;
  while (std::getline(input, text)) {
    ++n;
    auto reject = [&](const char* why) {
      v.ok = false;
      v.bad_line = n;
      v.problem = why;
      return v;
    };
    if (input.eof()) {
      return reject("incomplete final line");
    }
    Line line;
    try {
      line = parse_line(text);
    } catch (const Error&) {
      return reject("malformed line");
    }
    if (line.entry.seq != n - 1) {
      return reject("sequence number out of order");
    }
    const Mac want = chain_mac(key_, last_mac, line.entry);
    if (!ct_equal(want, line.mac)) {
      return reject("chain mac mismatch");
    }
    last_mac = line.mac;
    if (entries != nullptr) {
      entries->push_back(std::move(line.entry));
    }
    ++v.entries;
  }
  return v;
}

}  // namespace pq::keystore
