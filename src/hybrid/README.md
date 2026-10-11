# src/hybrid: KEM-DEM and the PQL1 envelope

Owner: participant 4. Namespace `pq::hybrid`. Format version 1.

| File | What |
|---|---|
| `ids.hpp` | `kem_id` / `aead_id` numbers stored in the envelope. Assigned once, never reused |
| `envelope.{hpp,cpp}` | Wire format: part A, part B, chunk nonce, `key_id`, header parser |
| `kem_dem.{hpp,cpp}` | `KemDem::seal`, `open`, `rewrap` |

Algorithms are looked up through `pq::Registry` by name; nothing here includes a concrete KEM
or cipher header. The AEAD is always `<cipher>-GCM`.

## Format

All integers are big-endian.

```text
part A:  "PQL1" | version[1] = 1 | aead_id[1] | data_nonce_prefix[7]                      13 bytes
part B:  kem_id[1] | key_id[16] | len(ct_kem)[4] | ct_kem | wrap_nonce[12]
         | wrapped_dek[32] | wrap_tag[16]
data:    chunk_0 | tag_0 | chunk_1 | tag_1 | ...        chunks of 64 KiB, the last one 0..64 KiB
```

- **DEK**: 32 random bytes per file. The data key is `DEK[0..key_size)` (the whole DEK for
  256-bit ciphers).
- **KEK** = `HKDF-SHA3-256(IKM = K, salt = ct_kem, info = "pqlab" || kem_id || aead_id)`,
  `key_size` bytes long.
- **Wrapping**: `AEAD(KEK, wrap_nonce, AAD = A || kem_id || key_id || len || ct_kem || wrap_nonce)`
  on the DEK. `wrapped_dek` and `wrap_tag` cannot be in their own AAD, so "A and B in full"
  means everything of B before them.
- **Data nonce** = `data_nonce_prefix || chunk_index[4] || last[1]`; **data AAD** = part A only,
  so a rewrap never invalidates the data tags.
- The last chunk carries `last = 1`; an empty message is one empty last chunk (a bare tag).
  Truncation, extension and reordering of chunks therefore fail the tag check.
- `key_id = SHA3-256(pk)[0..16]`.

## Behaviour

- Malformed structure (magic, version, truncated header, unknown id, wrong `ct_kem` length)
  throws `pq::Error`. Anything that fails authentication returns `std::nullopt`; this includes
  a wrong key, because ML-KEM Decaps rejects implicitly and the KEK simply comes out wrong.
- `rewrap` = Decaps with the old key, unwrap the DEK, Encaps to the new key, new part B. Part A
  and the data are copied byte for byte. It does not read or verify the data chunks, so it
  costs the same for a 1 KB and a 10 GB file.
- Only `SecureBytes` holds secrets (K, KEK, DEK, plaintext); the AEAD key is never copied
  into a plain buffer.

## Known limitations

- Buffer API only: the whole plaintext or envelope sits in memory. The chunked format allows a
  streaming API later. `parse_header` already returns the header size, so a file-based rewrap
  needs to rewrite only the first `Header::size` bytes.
- Only 12-byte nonces, 16-byte tags and keys up to 32 bytes are supported (checked at runtime).
- The `kem_id`s of HQC are reserved but HQC is not in the registry yet; sealing to it throws
  `pq::Error: unknown KEM`.
- Until `src/cipher` and `src/mode` register AES-GCM in `Registry::global()`, `KemDem` works
  only with a registry that has it (the tests use `tests/support/stub_aead.hpp`).
