# Ed25519 verification vectors

Unmodified `testvectors_v1/ed25519_test.json` from
[C2SP Wycheproof, commit 5722833ca004983abd1a91bcb6c24596d50ac0f9](https://github.com/C2SP/wycheproof/blob/5722833ca004983abd1a91bcb6c24596d50ac0f9/testvectors_v1/ed25519_test.json).

SHA-256: `752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536`.
The 151 cases cover valid signatures, malformed encodings, signature malleability,
truncation and appended bytes. Tests run offline against the production verifier.

Copyright the Wycheproof contributors. Distributed under the accompanying
[Apache License 2.0](LICENSE). These resources are test-only and are not packaged
in the plugin.
