# src/keystore: creating, storing and rotating keys

Owner: participant 4. Namespace `pq::keystore`. Record format version 1.

| File | What |
|---|---|
| `policy.{hpp,cpp}` | `Status`, allowed transitions, rotation age |
| `key_record.{hpp,cpp}` | `KeyRecord`, JSON (de)serialization with strict validation, `record_aad` |
| `seed_seal.{hpp,cpp}` | PBKDF2-HMAC-SHA3-256 + AES-256-GCM encryption of the KEM seed |
| `audit_log.{hpp,cpp}` | Append-only HMAC-SHA3-256 hash chain |
| `fs_util.{hpp,cpp}` | Atomic file write, `flock`, directory exchange, private modes |
| `keystore.{hpp,cpp}` | `Keystore`: create, list, unlock, retire, revoke, destroy, rotate, change password |
| `rotation.{hpp,cpp}` | `encrypt_to_active`, `decrypt`, `rewrap_to_active`: keystore + KEM-DEM |

## On disk

```text
$PQLAB_HOME (default ~/.pqlab)         0700
├── keystore.lock                      flock file, every operation takes it
└── keystore/                          0700
    ├── <key_id hex>.json              0600, one record per key
    ├── audit.log                      0600
    └── audit.key                      0600, 32 random bytes
```

A record holds the public metadata (`key_id`, `label`, `kem`, `status`, `created`,
`status_changed`, `pk`) and, for a key that still has one, the sealed seed:

- the seed is what `Kem::keygen_derand` consumes (ML-KEM: `d || z`, 64 bytes); the expanded
  secret key is recomputed on `unlock` and checked against the stored `pk`;
- `key = PBKDF2-HMAC-SHA3-256(password, salt[16], iterations)`, 600000 iterations by default;
- `ciphertext = AES-256-GCM(key, nonce[12], AAD, seed)`, **AAD = every field of the record
  except the ciphertext** (`record_aad`), each length-prefixed.

Because the status is in the AAD, an edited file (a retired key set back to `active`, another
label, another `created`) fails authentication. The price: `retire` and `revoke` re-seal the
seed and need the password. `destroy` only removes the sealed seed and needs none.

`key_id = SHA3-256(pk)[0..16]` is checked on load, and the file name must equal it.

## Life cycle

```text
active ──retire──▶ retired ──destroy──▶ destroyed
   │                  │                     │
   └──────────────────┴─────revoke──────────┘      (revoked → destroyed is allowed too)
```

Only `active` keys encrypt. `active`, `retired` and `revoked` keys can still be unlocked, so
data can be moved off them; `destroyed` keys cannot. `revoked → destroyed` is an addition to the
plan, so that a compromised key's ciphertext does not have to stay on disk forever.

## Atomicity

Every writing operation copies the keystore directory to `<home>/keystore.stage`, applies the
change there (record files and the audit entry), fsyncs, and swaps it in with
`renameat2(RENAME_EXCHANGE)`. A crash or an exception leaves the old state, also for
`rotate` (two records) and `change_password` (all records). A stale `keystore.stage` or
`*.tmp` from a crashed run is cleaned up by the next operation. The lock serialises processes.

## Rotation and rewrap

`Keystore::rotate(id, password)` makes a new key of the same KEM and label, retires the old one,
and writes `key_retired`, `key_created` and `key_rotated` in one swap. Existing data moves with
`rewrap_to_active`: unlock the key named in the envelope, `KemDem::rewrap` to the newest active
key (optionally of another KEM). After that the old key can be destroyed.

## Audit log

One JSON line per event, `mac = HMAC-SHA3-256(audit.key, prev_mac || seq || time || event ||
key_id || detail)`. Events: `key_created`, `key_unlocked`, `unlock_failed`, `password_failed`,
`key_retired`, `key_revoked`, `key_destroyed`, `key_rotated`, `password_changed`,
`envelope_rewrapped`. Entries carry no secrets.

## Known limitations

- `audit.key` sits next to the log. The chain detects edits, deletions, insertions and
  reordering by anyone who cannot read that file. It does not detect removal of the last
  lines, and it does not stop an attacker with the same user id.
- Status changes are authenticated by the seed's AAD only while a seed exists. A destroyed
  record has no seed, so its metadata is not authenticated.
- `destroy` removes the ciphertext from the record, but the old blocks may stay on the device
  (copy-on-write file systems, SSD wear levelling, journals). Do not rely on it as a wipe.
- Passwords are `ByteView`s; the caller is responsible for keeping them in `SecureBytes`.
- The swap needs a Linux kernel and a file system with `RENAME_EXCHANGE` (ext4, btrfs, xfs,
  tmpfs). Elsewhere it throws `pq::Error`.
- The seed is sealed with `<cipher>-GCM` looked up in the registry (`AES-256-GCM` by default).
  Until `src/cipher` and `src/mode` register it in `Registry::global()`, the keystore works only
  with a registry that has it; the tests use `tests/support/stub_aead.hpp`.
- Bulk rewrap of a directory of files (temporary directory, then `rename`) belongs to `pqtool`
  and is not implemented here.
