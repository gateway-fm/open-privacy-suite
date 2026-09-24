**Implemented decision:** retain Ed25519 and sign immediately available approvals in batches of 1–32, with separate signing, delivery and verification workers. No collection timer. The real HTTP demo and current measurements are in [DEMO.md](DEMO.md). The comparison below records the earlier authentication research.

**We can make permission authentication much cheaper.** The choice is whether the node needs a message authenticated by OPS, or an independently verifiable OPS signature that the node itself cannot produce.

The original implementation used Ed25519 `verify_strict`. Verification decodes an elliptic-curve point, checks encodings and small-order points, hashes the message, and performs elliptic-curve scalar arithmetic. The message is only 120 bytes, but the curve work remains. This follows [Ed25519 verification](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7) and the [pinned Dalek implementation](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict).

I measured alternatives on the same M2 Max, using the same approval fields:

| Authentication operation | Median µs per approval | Consequence |
|---|---:|---|
| Ed25519 strict, predecoded inputs | 32.40 | Only OPS can generate valid signatures |
| Ed25519 plus hex parsing and message allocation | 33.14 | Small wrapper overhead; curve arithmetic dominates |
| HMAC-SHA-256, prepared key context | 0.70 | Node and OPS share a secret; either can generate valid tags |
| HMAC-SHA-256, fresh key context each time | 1.03 | Same trust model, some avoidable key setup |
| One Ed25519 signature over 32 complete approvals | 1.19 | Keeps OPS-only signing; amortized CPU, excludes batch collection delay |

HMAC is about **46× faster** than individual Ed25519 verification in this test. It computes a cryptographic authentication tag using a shared key; it is not a public-key signature. Prepared key state is an optimization described in [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html#section-4), and the benchmark checks the [RFC 4231 HMAC-SHA-256 vector](https://www.rfc-editor.org/rfc/rfc4231.html#section-4.2). Sharing a key is the significant tradeoff: whoever controls the node's MAC key can manufacture an OPS-looking permission. Per-node keys can limit the scope but do not remove that property. A MAC also does not encrypt the permission.

**An alternative for direct-to-RAM delivery is a persistent mutually authenticated TLS connection.** OPS authenticates when connecting to the module's private ingress; the node accepts only authorized OPS client identities. Subsequent permission messages use the connection's symmetric authenticated encryption. An extra Ed25519 signature on every approval is unnecessary if authenticated delivery is the complete requirement. TLS supports this separation between [handshake authentication](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3) and [record protection](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.2).

This keeps the existing asynchronous send, persistent connection, in-memory lookup and execution fingerprint check. It needs no HTTP headers, per-transaction connection establishment or application acknowledgement. The initial handshake/reconnect still has a cost. TLS authenticates traffic on the connection; it does not produce a transferable, independently verifiable OPS signature for each stored permission. A plain hash without a secret or an authenticated channel would provide no sender authentication.

I measured bare AES-256-GCM decryption at 2.23 µs for a 120-byte payload in this crate's default portable configuration. **That is not a TLS benchmark.** Record processing, actual message encoding, buffering and the TLS library's hardware acceleration still need measurement. The crate versions used here do not enable their optional ARM SHA-256/AES backends; Dalek selects its serial curve backend on this ARM target. These results establish substantial room for improvement without claiming the fastest possible implementation.

**If OPS-only signing is required, signed batches preserve it.** OPS can put several complete approvals into one bounded message and sign that message once. Reth verifies that one signature, then makes the individual approvals available in RAM. This experiment uses ordinary `verify_strict` on that message, not the library's `verify_batch` algorithm and not a new cryptographic primitive. Changing any batch member invalidates its signature. It does not approve a transaction whose preflight has not finished.

The 32-approval figure assumes a full batch. At a steady 5,000 approvals/second, filling it would add roughly 6 ms of waiting for the oldest approval. The selected implementation avoids waiting to fill batches altogether: sign the current queue immediately. This reduces available batch size and CPU savings at light traffic. At low traffic, the batch may contain only one approval. The implemented protocol has a 16 KiB frame limit and a maximum of 32 approvals. Framing, queueing and dispatch costs are not included in this primitive microbenchmark.

Tradeoff: persistent mTLS can suffice if permission provenance is only needed by the receiving trusted node. Use HMAC if separately authenticated messages are needed and shared verification/signing authority is acceptable. Keep asymmetric signatures, potentially with bounded batching, if nodes must be unable to forge OPS approvals. These alternatives address permission authenticity; the execution fingerprint comparison remains necessary in every case.

The standalone [benchmark](auth-bench/src/main.rs) was the research step. Subsequent implementation added the signed-batch protocol in OPS and Reth; it preserves OPS-only signing authority. The benchmark uses its own domain separator, distinct from the actual wire protocol.

Method: release build, one thread, 256 varying fixtures, rotated method order, one discarded warmup and nine measured samples. Each sample executes 20,000 signature checks or 500,000 MAC/AEAD checks; batched verification is normalized by 32 approvals. Timed loops use `black_box` and assert verification succeeds. Generation, network transport, JSON parsing, Reth execution and batch collection/dispatch are excluded. Valid fixtures, tampering in every approval field, modified MAC tags/ciphertext, each signed-batch member and the HMAC known-answer vector were checked before timing. Clippy and formatting checks also passed. The continuous microbenchmark's ~33 µs signature cost and the earlier Reth ingress measurement of ~50 µs are different measurement conditions; current pipeline results are reported separately in DEMO.md.

[Raw measurements](evidence/auth-benchmark/primitives.json) and [provenance](evidence/auth-benchmark/manifest.json).

Reproduce from this directory:

```sh
CARGO_TARGET_DIR=../../.tmp/auth-target cargo run --release --locked --manifest-path auth-bench/Cargo.toml
```
