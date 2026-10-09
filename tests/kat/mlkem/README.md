# ML-KEM: NIST ACVP vectors (FIPS 203)

Files are copied without modification from the `usnistgov/ACVP-Server` repository at
commit `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0` (tag RELEASE/v1.1.0.42, 2026-04-16). Downloaded 2026-10-09.

| Local file | Source |
|---|---|
| keyGen-internalProjection.json | https://github.com/usnistgov/ACVP-Server/blob/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json |
| encapDecap-internalProjection.json | https://github.com/usnistgov/ACVP-Server/blob/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json |

`internalProjection.json` combines the prompts and the expected results of a vector set.

- keyGen: 25 AFT cases per parameter set, (d, z) -> (ek, dk) via ML-KEM.KeyGen_internal.
- encapDecap: AFT encapsulation (ek, m) -> (c, k); VAL decapsulation (dk, c) -> k, including
  modified ciphertexts (implicit rejection); encapsulationKeyCheck and
  decapsulationKeyCheck (FIPS 203, Sections 7.2 and 7.3) with valid and invalid keys.

SHA-256 of the files:

```text
f1e22b7d399dde7bf61b838770c658a380e4b1cfc4bd395dbed9ec6c1d977d9d  encapDecap-internalProjection.json
d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b  keyGen-internalProjection.json
```
