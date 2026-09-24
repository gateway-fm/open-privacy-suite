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
| Direction | OPS dials each producer (plan §0 1c). Each target address reaches exactly one producer: no load balancer in between, or the boot id (§4) changes on every reconnect |
| Security | Plaintext for now (plan §0.3). A network rule must let only OPS reach the receiver's port, and receivers refuse to start without an explicit source list (CIDRs, or `any` to rely on the network rule alone). They also cap connections and concurrent calls, and close a connection that has not completed the HTTP/2 preface within 5 s or has carried no call for 30 s — OPS calls `Status` every second, so its own connections never idle. The Ed25519 signature protects integrity either way |
| Calls | One unary `Deliver` per batch. Calls share one connection per producer and do not wait for each other; OPS bounds the calls in flight per producer. No gRPC-level retry policy: retries are OPS's (§5) |
| Reconnect | OPS reconnects with backoff capped at 1 s and resolves the target name on every attempt, so a producer that restarts on a new address is reached within about a second |
| Message size | A full batch is under 4.1 KiB; receivers cap requests at 64 KiB |
| Deadline | OPS sets one per call |
| Keepalive | OPS pings an idle connection every 20 s with a 5 s timeout. Receivers permit pings every 10 s, also with no call in flight (grpc-java's defaults refuse them and close the connection) |

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
| 88 | 32 | reserved: senders write zeros; receivers sign over it and otherwise ignore it |

The reserved field once carried a hash of the submitting user's identifier. That is not a
pseudonym — an identifier derived from an address can be enumerated — and no receiver needs it: OPS's
own audit log records who submitted each transaction.

**Golden vectors:** `internal/nodeapproval/testdata/batch.json` and `call-batch.json`, signed with
the seed `0x07`×32 under key id `default`, `issued_at` 1790000000000, `expires_at` 1790000600000.
Every implementation decodes and verifies them in its own tests (their reserved field is not zero:
decoders must accept any value). Regenerating them is a contract change
(`OPS_UPDATE_BATCH_GOLDEN=1`, `OPS_WRITE_CALL_GOLDEN=1`).

## 3. What the receiver checks, and what the sender does

The receiver checks in this order and answers with the first failing check's status. A batch is
all or nothing: on any error nothing from it is stored.

| # | Check | Status on failure | Sender |
|---|---|---|---|
| 1 | Decodes: known domain, lengths, count 1–32, known approval domains, `expires_at` > `issued_at` | `INVALID_ARGUMENT` | drop the batch, count, alert |
| 2 | The key id is in the trusted set | `PERMISSION_DENIED` | drop, count, alert — usually a rotation gap |
| 3 | The signature verifies under that key | `UNAUTHENTICATED` | drop, count, alert |
| 4 | Every approval's chain id is the receiver's chain | `INVALID_ARGUMENT` | drop, count, alert |
| 5 | `expires_at` − `issued_at` is within the receiver's maximum TTL (no clock involved) | `INVALID_ARGUMENT` | drop, count, alert — OPS TTL above the receiver's limit |
| 6 | `issued_at` ≤ now + 5 s | `FAILED_PRECONDITION` | drop, count, alert — OPS clock ahead |
| 7 | `expires_at` > now | `FAILED_PRECONDITION` | drop, count — delivered too late |
| 8 | The store has room for all *n* approvals, counted before anything is evicted | `UNAVAILABLE` with trailer `ops-approval-reason: store-full` | keep it, retry with the lane's backoff |
| — | Stored | `OK`, with `boot_id` and `stored` = *n* | retain until `expires_at` |
| — | Receiver starting or stopping, connection lost | `UNAVAILABLE` | retry with backoff |
| — | Deadline passed | `DEADLINE_EXCEEDED` | retry; delivery is idempotent |
| — | `RESOURCE_EXHAUSTED`, `OUT_OF_RANGE`, `UNIMPLEMENTED` | generated by the gRPC libraries (message too large, stream limits, wrong service) | permanent: drop, count, alert |
| — | Anything else | `INTERNAL` / `UNKNOWN` | retry with backoff, count, alert |

**Which approval a receiver keeps.** Per transaction hash, the approval with the greatest
(`issued_at`, key id, fingerprint), compared as unsigned integer and then bytewise. The rule is
deterministic, so a primary and a standby keep the same approval whatever order batches arrive in.
Delivering an approval that is already stored changes nothing and returns `OK`.

**Late approvals.** An approval for a transaction the receiver has already dropped or timed out is
stored like any other — the transaction may be re-announced — and never fails its batch.

## 4. Boot id and redelivery

The receiver's store lives in memory, so a producer restart loses approvals that were already
confirmed. The contract closes that gap:

- The receiver draws a random 128-bit boot id (hex) when its process starts and returns it in every
  `DeliverResponse` and `StatusResponse`.
- OPS calls `Status` whenever a lane's connection becomes ready and then every second. It acts on a
  boot id only when it is new for the current connection; responses that belong to an earlier
  connection are ignored. On a new boot id it resends every batch it still retains whose
  `expires_at` is in the future, newest first and behind fresh batches, with at most one redelivery
  running per lane.
- After a restart the RPC nodes re-announce their pooled transactions, possibly before OPS has
  reconnected. So the receiver counts a transaction's wait window from the later of its pool
  admission and the first `Status` call after boot, and extends it that way for at most 60 s
  after boot. With several OPS instances the first `Status` from any of them starts that window;
  an instance that reconnects more than one wait window later is not covered. In practice every
  instance reconnects within about a second (§1).

`StatusResponse` also carries the receiver's chain id, trusted key ids, maximum TTL, capacity and
wait window. OPS signs with a TTL no longer than every ready lane's maximum. A lane whose chain or
trusted key ids do not match, or whose maximum TTL is below 10 s, is not ready and does not shorten
the TTL; OPS forgets a lane's reported values when it stops being ready.

## 5. Sender behaviour

- Signs with the TTL from `OPS_APPROVAL_TTL` (10 s to 1 h, default 10 minutes; the minimum leaves
  room for the wait window plus a block), shortened to the smallest maximum TTL its lanes report.
- Retains every signed batch until its `expires_at`, up to a cap; beyond the cap the oldest batches
  are dropped first and counted. Retention is in memory: a joint restart of OPS and a producer loses
  the approvals of pooled transactions until the durable outbox (plan §5 item 3) lands.
- With several producers configured (a standby sequencer), sends every batch to each of them
  independently: one producer failing does not hold back another.
- Backs off per lane: while a lane refuses (store full, unavailable), only one probe call is in
  flight on it. A retry that is waiting holds no call slot, and fresh batches go before retries and
  redeliveries.
- Forwards the transaction without waiting for any confirmation (plan §0 1a). When no lane is
  ready — none connected with a matching `Status` in the last few seconds — `Enqueue` fails and the
  client gets 503 rather than a forwarded transaction that cannot be approved.

## 6. Receiver behaviour at execution and in the store

- An approval is usable while now < `expires_at`. An expired approval counts as absent: the
  transaction waits and is dropped when the wait window ends.
- The store keeps an approval until its `expires_at` or until the block that included its
  transaction is final, whichever comes first. Expiry replaces the separate orphan lifetime, and the
  number of included blocks tracked is bounded by the TTL.
- Under pressure the store evicts expired approvals first, then those of included transactions,
  then the oldest orphans. An approval younger than the grace period — measured from `issued_at`,
  not from arrival, so a redelivery or a replayed batch cannot make old approvals young again — is
  never evicted for a new one. Pooled transactions still waiting for an approval do not count
  against capacity.
- Clocks on both sides are NTP-synchronised. The only tolerance is check 6's 5 s; otherwise a
  skewed clock fails closed.

## 7. Settings

| Setting | Side | Default | Meaning |
|---|---|---|---|
| `OPS_APPROVAL_TARGETS` | OPS | — | comma-separated `host:port` list of producers (replaces the single `OPS_APPROVAL_TARGET`) |
| `OPS_APPROVAL_TTL` | OPS | `10m` | lifetime of a signed approval, 10 s to 1 h |
| `OPS_APPROVAL_DELIVERY_TIMEOUT` | OPS | `2s` | deadline of one `Deliver` call |
| `OPS_APPROVAL_MAX_IN_FLIGHT` | OPS | `8` | calls in flight per producer |
| `OPS_APPROVAL_RETAIN_MAX` | OPS | `100000` | approvals retained for redelivery |
| `--plugin-ops-approval-listen` | Besu plugin | — | gRPC listen address |
| `--plugin-ops-approval-max-ttl-ms` | Besu plugin | `3600000` | longest `expires_at` − `issued_at` accepted; 10 s to 24 h |
| `--plugin-ops-approval-capacity` | Besu plugin | `100000` | approvals the store holds |
| `--plugin-ops-approval-wait-ms` | Besu plugin | `5000` | how long a pooled transaction waits for its approval |
| `--plugin-ops-approval-allowed-sources` | Besu plugin | — (required) | comma-separated CIDR list of sources allowed to connect, or `any` to rely on the network rule alone |
| `--plugin-ops-approval-max-connections` | Besu plugin | `32` | open delivery connections; one per OPS instance is the norm |
| `--plugin-ops-approval-max-concurrent-calls` | Besu plugin | `32` | delivery calls in flight per connection |
| Same settings | Reth node | as the plugin | environment variables `OPS_APPROVAL_LISTEN`, `OPS_APPROVAL_MAX_TTL_MS`, `OPS_APPROVAL_CAPACITY`, `OPS_APPROVAL_WAIT_MS`, `OPS_APPROVAL_ALLOWED_SOURCES`, `OPS_APPROVAL_MAX_CONNECTIONS`, `OPS_APPROVAL_MAX_CONCURRENT_CALLS` |

Trusted keys are configured as a set of `id=hex` pairs on both receivers
(`--plugin-ops-approval-public-keys`, `OPS_APPROVAL_PUBLIC_KEYS`). The plugin also accepts a single
`--plugin-ops-approval-public-key`, trusted under the id `default`; the Reth node has no such
shorthand.

**Sizing.** Capacity should cover what the OPS instances may redeliver at once plus a grace period
of fresh traffic: capacity ≥ Σ `OPS_APPROVAL_RETAIN_MAX` + rate × grace. Below that, a full
redelivery is absorbed by evicting its old approvals first (§6) rather than refusing fresh ones.

## 8. Versioning

The envelope's first 22 bytes name its version; receivers refuse versions they do not know. The gRPC
package is `v1`: adding fields stays compatible; a change of meaning is a new package served side
by side.
