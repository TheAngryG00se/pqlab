# GCM: официальные NIST CAVP векторы

Источник: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip

Получено 2026-10-14. Все шесть .rsp файлов извлечены целиком без изменений.
SHA-256 архива: `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`.

API проекта поддерживает nonce 96 бит и тег 128 бит. Тесты выполняют все
случаи этого профиля для AES-128/192/256; остальные профили остаются в
исходных файлах и явно отфильтровываются тестом. FAIL — отрицательный
ожидаемый результат, записанный NIST, а не ошибка чтения.

| Файл | SHA-256 |
|---|---|
| `gcmDecrypt128.rsp` | `0d1f98d0c9e176ede1f3e85484dd13de92c3436ca97df378ec3481e04c19a732` |
| `gcmDecrypt192.rsp` | `ca65640844441d58828e29bff87b7ec4571ef6778f4c331fc06697264edb2ffd` |
| `gcmDecrypt256.rsp` | `ed318735a517d5a85c82d2846c23dcf56e57a352fb0f0a163d9e7617a7bd12ad` |
| `gcmEncryptExtIV128.rsp` | `30156236f768b0d81e58a3e5bd3bd79ce294cf9ef0ba0a84cf7b869c89ebd9fd` |
| `gcmEncryptExtIV192.rsp` | `86827942bf67d1c67f34532bd057adf0a41cd911396a36023d9033f89fc6f571` |
| `gcmEncryptExtIV256.rsp` | `4448b4998c3f58cd9f5542ddf7c573189a721ff3d3ac24cd5177bb4910a787f8` |

GHASH промежуточные значения взяты из официальных примеров NIST:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
Получено 2026-10-14; PDF SHA-256: `55e822592257799a4f895d6f3cb4c15515a065c008087105fc2063d2e757b5ef`.
`aes-gcm-examples.txt` — полный вывод `pdftotext -layout`; SHA-256: `59359bf9ef1d81a55e8b70dcb13ed2f8b4c3ebccdbda5673947c63e118deab7b`.
