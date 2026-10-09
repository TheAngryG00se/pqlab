# HMAC / HKDF / PBKDF2 over SHA3-256: OpenSSL reference values

There are no official test vectors for HMAC, HKDF and PBKDF2 instantiated with SHA3-256.
Following AGENTS.md (section 9), the expected values are produced by OpenSSL. The inputs
are deterministic byte patterns defined in `generate.py`; every expected output comes from
the `openssl mac` / `openssl kdf` command line, never from our own code.

Regenerate (overwrites the `.rsp` files next to the script):

```bash
python3 -I tests/kat/kdf/generate.py
```

Commands used per record:

```bash
openssl mac -digest SHA3-256 -macopt hexkey:<Key> HMAC < msg.bin
openssl kdf -keylen <L> -kdfopt digest:SHA3-256 -kdfopt hexkey:<IKM> -kdfopt hexsalt:<Salt> \
            -kdfopt hexinfo:<Info> [-kdfopt mode:EXTRACT_ONLY] HKDF
openssl kdf -keylen <DKLen> -kdfopt digest:SHA3-256 -kdfopt hexpass:<Password> \
            -kdfopt hexsalt:<Salt> -kdfopt iter:<Iterations> PBKDF2
```

Generated 2026-10-09 with OpenSSL 3.0.2 (15 Mar 2022). The KDF implementations used here
do not depend on the ML-KEM additions of OpenSSL 3.5.

SHA-256 of the files:

```text
57fe548c81eda1f3fa9040b279c7a7a7d48049ce0c8c73dad514b499c53bbffe  hkdf_sha3_256.rsp
314f0c17054a392d7380e96f925884e22f9853227631793ccce6e1cd0592bbe3  hmac_sha3_256.rsp
cf9c257a91943ad3a8241712641121b0b52180858217f4ec7e1c154268c9c6c2  pbkdf2_hmac_sha3_256.rsp
```
