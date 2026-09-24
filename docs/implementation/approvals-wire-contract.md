# Signed approvals: wire contract

One contract between OPS (the sender) and every block producer that enforces approvals (the
receivers: the Besu plugin and the Reth node). Three implementations share it — Go in OPS
(`internal/nodeapproval`), Java in the plugin (`poc/besu-signed-approvals`), Rust in the node
(`poc/reth-signed-approvals`) — and all three test against the same golden vectors. The reasons
behind each choice are in [approvals-production-plan.md](approvals-production-plan.md) §0 and §3.

## 1. Transport

| Aspect | Contract |
|---|---|
| Protocol | gRPC over HTTP/2, service `ops.approvals.v1.ApprovalDelivery` ([`proto/ops/approvals/v1/approvals.proto`](../../proto/ops/approvals/v1/approvals.proto)) |
| Direction | OPS dials each producer (plan §0 1c) |
| Security | Plaintext for now (plan §0.3). A network rule must let only OPS reach the receiver's port; the Ed25519 signature protects integrity either way |
| Calls | One unary `Deliver` per batch. Calls share one connection per producer and do not wait for each other; OPS bounds the calls in flight per producer |
| Message size | A full batch is under 4.1 KiB; receivers cap requests at 64 KiB |
| Deadline | OPS sets one per call |
| Keepalive | OPS pings an idle connection every 20 s; receivers must permit pings at that rate without calls in flight, or they close the connection |

## 2. The signed envelope

`DeliverRequest.batch` carries these bytes verbatim. All integers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 22 | ASCII `OPS_APPROVAL_BATCH_V2` followed by one zero byte |
| 22 | 1 | key id length *k*, 1–64 |
| 23 | *k* | key id, ASCII `[A-Za-z0-9._:-]` — which trusted key signed |
| 23+*k* | 8 | `issued_at`, Unix milliseconds |
| 31+*k* | 8 | `expires_at`, Unix milliseconds, greater than `issued_at` |
| 39+*k* | 4 | approval count *n*, 1–32 |
| 43+*k* | 120·*n* | approvals, below |
| 43+*k*+120·*n* | 64 | Ed25519 signature over every byte before it |

Each approval is 120 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | `OPS_APPROVAL_V1` + zero byte (strict fingerprint) or `OPS_APPROVAL_V3` + zero byte (calls fingerprint) |
| 16 | 8 | chain id |
| 24 | 32 | transaction hash |
| 56 | 32 | fingerprint of the approved execution |
| 88 | 32 | principal: Keccak-256 of the OPS user id |

**Golden vectors:** `internal/nodeapproval/testdata/batch.json` and `call-batch.json`, signed with
the seed `0x07`×32 under key id `default`, `issued_at` 1790000000000, `expires_at` 1790000600000.
Every implementation decodes and verifies them in its own tests; regenerating them is a contract
change (`OPS_UPDATE_BATCH_GOLDEN=1`, `OPS_WRITE_CALL_GOLDEN=1`).

## 3. What the receiver checks, and what the sender does

The receiver checks in this order and answers with the first failing check's status. A batch is
all or nothing: on any error nothing from it is stored.

| # | Check | Status on failure | Sender |
|---|---|---|---|
| 1 | Decodes: known domain, lengths, count 1–32, known approval domains, `expires_at` > `issued_at` | `INVALID_ARGUMENT` | drop the batch, count, alert |
| 2 | The key id is in the trusted set | `PERMISSION_DENIED` | drop, count, alert — usually a rotation gap |
| 3 | The signature verifies under that key | `UNAUTHENTICATED` | drop, count, alert |
| 4 | Every approval's chain id is the receiver's chain | `INVALID_ARGUMENT` | drop, count, alert |
| 5 | `expires_at` is still in the future | `FAILED_PRECONDITION` | drop, count — delivered too late |
| 6 | `expires_at` − now is within the receiver's maximum TTL | `INVALID_ARGUMENT` | drop, count, alert — OPS TTL above the receiver's limit |
| 7 | The store has room for the batch | `RESOURCE_EXHAUSTED` | keep it, retry with backoff |
| — | Stored | `OK`, with `boot_id` and `stored` = *n* | retain until `expires_at` |
| — | Receiver starting or stopping | `UNAVAILABLE` | retry with backoff |
| — | Deadline passed | `DEADLINE_EXCEEDED` | retry; delivery is idempotent |
| — | Anything else | `INTERNAL` / `UNKNOWN` | retry with backoff, count, alert |

Retries use exponential backoff with jitter and stop at `expires_at`. Delivering a batch that is
already stored returns `OK`. Per transaction hash the receiver keeps the approval with the later
`issued_at`; an equal one changes nothing.

## 4. Boot id and redelivery

The receiver's store lives in memory, so a producer restart loses approvals that were already
confirmed. The contract closes that gap:

- The receiver draws a random 128-bit boot id (hex) when its process starts and returns it in every
  `DeliverResponse` and `StatusResponse`.
- OPS remembers the last boot id per producer. It calls `Status` whenever the connection becomes
  ready again. When the boot id differs from the one it remembers — in that response or any other —
  it resends every batch it still retains whose `expires_at` is in the future, oldest first.
- The resend has to be prompt, not wait for the next new batch: after a restart the RPC nodes
  re-announce their pooled transactions, and each one must find its approval within the wait
  window, which counts from pool admission.

`StatusResponse` also carries the receiver's chain id, the key ids it trusts and its maximum TTL,
so OPS can refuse to start a delivery lane whose chain, key id or TTL the receiver would reject.

## 5. Sender behaviour

- Signs with the TTL from `OPS_APPROVAL_TTL` (a duration from 1 s to 1 h, default 10 minutes).
- Retains every signed batch until its `expires_at`, up to a cap; beyond the cap the oldest batches
  are dropped first and counted.
- With several producers configured (a standby sequencer), sends every batch to each of them
  independently: one producer failing does not hold back another.
- Forwards the transaction without waiting for any confirmation (plan §0 1a).

## 6. Receiver behaviour at execution

- An approval is usable while now < `expires_at`. An expired approval counts as absent: the
  transaction waits and is dropped when the wait window ends. The store removes expired approvals.
- Release on finality still applies; expiry bounds it. A reorganisation after expiry needs a fresh
  preflight.
- Clocks on both sides are NTP-synchronised. There is no grace period: a skewed clock fails closed.

## 7. Settings

| Setting | Side | Default | Meaning |
|---|---|---|---|
| `OPS_APPROVAL_TARGETS` | OPS | — | comma-separated `host:port` list of producers (replaces the single `OPS_APPROVAL_TARGET`) |
| `OPS_APPROVAL_TTL` | OPS | `10m` | lifetime of a signed approval |
| `OPS_APPROVAL_DELIVERY_TIMEOUT` | OPS | `2s` | deadline of one `Deliver` call |
| `OPS_APPROVAL_MAX_IN_FLIGHT` | OPS | `8` | calls in flight per producer |
| `OPS_APPROVAL_RETAIN_MAX` | OPS | `100000` | approvals retained for redelivery |
| `--plugin-ops-approval-listen` | Besu plugin | — | gRPC listen address |
| `--plugin-ops-approval-max-ttl-ms` | Besu plugin | `3600000` | longest `expires_at` − now accepted |
| Same two settings | Reth node | as the plugin | named in the node's own configuration |

## 8. Versioning

The envelope's first 22 bytes name its version; receivers refuse versions they do not know. The gRPC
package is `v1`: adding fields stays compatible; a change of meaning is a new package served side
by side.
