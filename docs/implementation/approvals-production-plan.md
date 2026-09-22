# Signed approvals: from PoC to production

**Status:** plan, for critic review. **Date:** 22 September 2026. **Owner:** Ivan Beliakov.
**Scope:** the signed-approvals gate (preflight in OPS, fingerprint check in the block producer)
for the current OPS version. The in-node policy runtime is OPS v2 and is not discussed here.

Numbers are measured unless marked *estimate*. File references are to
`poc/ops-besu-signed-approvals` unless another worktree is named.

## 0. Decisions this plan needs

1. **Transport** for approval delivery — §3 recommends gRPC bidirectional streaming with mTLS,
   the node dialling OPS, one acknowledgement per batch. The baseline (§3.5) shows delivery is
   not a latency cost and the race does not occur, so the case rests on reliability, TLS, peer
   authentication, fan-out and operability; §3.4′ is the reduced check before code is written.
2. **Key custody and signature scheme.** AWS KMS does not offer Ed25519: either a software
   Ed25519 key in Secrets Manager (IRSA), or ECDSA P-256 for HSM-backed signing. Changes the
   envelope and both verifiers.
3. **TLS termination**: mesh/sidecar in front of the plugin listener, or in-process.
4. **Where the plugin lives and ships**: inside this repository, or its own repository with
   releases the Lineth operator pulls (Lineth loads plugin JARs from `besu/plugins/`).
5. **Reth**: second shipped target, or reference implementation only. Both PoCs share the OPS
   side (`internal/nodeapproval`), so this decides test scope, not architecture.
6. **Preflight placement** in the target topology (§4c): on the sequencer, or on a dedicated
   Besu replica running only the plugin's RPC.

## 1. What ships

OPS receives `eth_sendRawTransaction`, runs RBAC, simulates the transaction on a Besu node
(`ops_prepareApproval`, the plugin's RPC), validates the observed call tree against policy,
signs an approval `(chain, tx hash, fingerprint, principal)` and delivers it to the block
producer; then forwards the transaction. The producer's plugin refuses to include a
transaction without an approval, and refuses one whose actual execution fingerprint differs
from the approved one — before commit, so a divergent transaction never enters the block.

| Measured (Besu 26.8.1, unmodified; one M2 Max running everything) | |
|---|---|
| Gasstorm Adaptive, 60 s, ETH transfers | **671 tx/s average with the gate, 727 without, 765 straight to Besu** — the gate costs ~7 %, the remaining ceiling is Besu's |
| Per OPS request | 17.5 ms → 21.1 ms with the gate (preflight ~3.5 ms of that) |
| Plugin work inside the producer | 7–22 µs per transaction |
| Scenarios | 20 / 22 checks green, deployments included (strict-V2 encoder ported to Java, verified against the Go golden vector); coexists with Lineth's own sequencer and pool plugins on an Osaka chain |

Not corners: the fingerprint encoders, the selector's veto semantics, the metrics that exist.

## 2. Where the PoC cut corners

| Corner | Where | Consequence | Fix |
|---|---|---|---|
| **Delivery is fire-and-forget.** A batch whose write fails is dropped; a batch the plugin cannot store is logged and dropped. OPS never learns. | `internal/nodeapproval/transport.go` `deliver()`; plugin `ApprovalListener.accept()` | the transaction was already forwarded (`jsonrpc_processor.go:1684` enqueues, then forwards): it waits `waitMs` = 5 s, is evicted `TIMEOUT`, the client holds a hash and never gets a receipt, nothing is told | acknowledgements per batch; redelivery; durable outbox (next row) |
| **Nothing durable.** OPS queue is a channel (4096); plugin store is a `ConcurrentHashMap` | `service.go`; `ApprovalStore` | OPS crash after enqueue, or a Besu restart, loses approvals for forwarded transactions (scenario `restart_drops_approvals…`) | OPS outbox in Postgres; the node asks for redelivery of its pooled hashes on (re)connect |
| **Approvals deleted on inclusion** | `OpsApprovalPlugin.onBlockAdded` on `HEAD_ADVANCED` / `CHAIN_REORG` | a transaction reorged back into the pool has no approval → timeout | delete on finality, or never (orphan TTL already bounds memory) |
| **One key, no `key_id`, no expiry** | `Approval.Message()`; `node_approvals.go:18` (seed file); `ApprovalVerifier` (one key) | rotation = simultaneous restart of every producer and OPS; an approval never expires while pooled, so an RBAC change after approval does not revoke it | envelope v2: `key_id`, `issued_at`, `expires_at`; trusted key *set* on the plugin with validity windows |
| **Plain TCP, no TLS, no peer authentication** | `dialApproval`; `ApprovalListener` | the signature protects content only; anyone reaching the port can flood the store | §3 |
| **Single delivery target**, one connection, one goroutine | `Service.address` | no standby sequencer, no second OPS instance | §4 |
| **`ops_prepareApproval` unauthenticated at the node** | `PrepareApprovalRpc` | simulation only, but compute on the producer; reachable by anyone on the RPC port | network policy or Besu RPC authentication; documented requirement |
| **Diagnostics in the live path** | `OPS_APPROVAL_ENCODING=json`; `hops.go` | dead switches in production code | remove, or keep hops behind a build tag (it is the delivery benchmark, §3.5) |
| **No health signal** | — | OPS disconnected = every transaction times out; nothing pages | connected-producers gauge on OPS, OPS-connected gauge on the plugin; alerts on both; readiness reflects delivery connectivity |
| **Fixed 100 ms reconnect, no jitter; frame limits hard-coded** | `deliver()`; `MaxBatchApprovals` 32, `MaxBatchFrame` 16 KiB | thundering reconnects; limits undocumented | backoff with jitter; limits in the protocol document |
| **Rate limiting deferred to OPS** | README | any authorised client can fill the store (100 k) for the TTL | global (Redis) rate limit on preflight per principal |
| **No CI, `@Unstable` Besu API** | `poc/` trees, Gradle against Cloudsmith | breaks silently on a Besu bump; Lineth pins the commit | per-Besu-version scenario lane (JDK 25 + Besu binary), nightly |
| **Scope limits, documented** | README | producer-only; legacy + EIP-1559 only; strict-V2 state-exact for lifecycle; no revocation | decisions, not bugs; 2930/4844 trivial, 7702 needs the envelope extension |

## 3. Transport

### 3.1 What latency actually depends on

The transaction and its approval travel on two paths. When the producer evaluates a pooled
transaction whose approval has not arrived, the selector answers `PENDING` and re-evaluates it
on the **next candidate build** — on Besu every **~500 ms** (measured: successive `wait`
decisions for one transaction at 07.933, 08.430, 08.937 in `evidence/timeout.log`;
`harness.py:226`); on the Reth PoC, the next payload build, up to one block. After `waitMs`
(5 s) the transaction is dropped.

The transport's own cost is microseconds. The cost that matters is the **race**: if the
transaction reaches the producer before its approval, inclusion slips by up to one candidate
build; if delivery fails, by 5 s to a drop. The PoC instrumented delivery (`hops.go`) but never
recorded it — §3.5 fixes that.

The lever that removes the race is an **acknowledgement**: forward the transaction only after
the producer has acknowledged storing the approval. Cost *estimate* 0.2–1 ms in-cluster on a
~21 ms request. Benefit: `PENDING` becomes exceptional instead of a matter of timing. This is
the strongest single argument for a transport with replies.

### 3.2 Options

| | One-way latency | Ack | TLS / mTLS | Schema, versioning | Fan-out | Go / Java / Rust | Operability |
|---|---|---|---|---|---|---|---|
| Raw TCP, length prefix (current) | ~0.5 RTT + µs | none — must be built | none — must be built | three hand-written encoders, string domain tag | hand-managed mesh | hand-rolled | bespoke protocol, bespoke runbooks |
| Raw TCP + ack frame | same | built by us | must be built | same | same | same | same |
| **gRPC bidi stream, HTTP/2, mTLS** | same ~0.5 RTT; framing + proto ≈ 10 B, µs | native on the stream | native | `.proto`, codegen ×3, field-evolution rules | native: one stream per consumer, name resolution | grpc-go; grpc-java (`grpc-netty-shaded`, Besu bundles its own Netty); tonic | standard: grpcurl, interceptors, tracing, deadlines, health |
| HTTP/1.1 POST per batch, keep-alive | 1 RTT per batch; approval usable at 0.5 RTT | the response | native | JSON or proto | one connection per target | everywhere | standard |
| HTTP/2 POST | as above, multiplexed | the response | native | as above | as above | everywhere | standard |
| WebSocket | ~0.5 RTT | built by us | TLS native, auth ad hoc | none | hand-managed | good | moderate |
| Broker (NATS JetStream / Kafka) | + one hop: ≥ 1 RTT + persistence, *estimate* 1–3 ms | native | native | registry optional | free | good | a new component in the inclusion path |

Raw TCP is what systems use when they *define* a protocol and own every client for decades —
devp2p, Bitcoin P2P, the Postgres and MySQL wire protocols, Redis, Kafka. None of that
describes 120-byte messages between two services we own. What raw TCP costs here is the top of
§2: no acks, no TLS, no peer authentication, no versioning beyond a string, three encoders kept
in parity by hand, and a protocol an on-call engineer has never seen.

### 3.3 Recommendation

**gRPC bidirectional streaming over HTTP/2 with mTLS; the node dials OPS; one acknowledgement
per batch; the Ed25519 payload signature kept.**

- Latency-equivalent to raw TCP: one persistent stream, one write per batch, no batching
  timer (`takeBatch` snapshot semantics unchanged).
- Acknowledgements come with the stream and make forward-after-ack possible (§3.1).
- **Node dials OPS**: the sequencer needs no inbound port (fits the RD-876 zone split); on
  connect it sends its pooled hashes and OPS redelivers, which fixes restart and reorg; a
  standby sequencer or a second OPS instance is one more stream.
- mTLS authenticates both ends and gives encryption in transit (ISO/IEC 27001:2022 Annex A
  8.24, use of cryptography — confirm the mapping with Compliance); the payload signature
  authenticates the *decision* independently of the channel and remains auditable.
- HTTP/1.1 POST is the acceptable fallback: at 700 batches/s it costs a request per batch
  (*estimate* 100–200 µs) and has no server push, so redelivery-on-connect needs a second
  endpoint.
- A broker is not justified: a new component in the inclusion path for an N×M that is small.

### 3.4 Benchmark before committing

Purpose: replace estimates with numbers and test the race claim. Effort *estimate* 1.5–2 days.

1. Transport shim behind `nodeapproval.deliver()` with implementations: raw TCP as-is; raw
   TCP + ack; gRPC bidi (node dials OPS); HTTP/1.1 POST. Matching ingress in the Besu plugin
   for each; the Reth PoC for raw TCP and gRPC if decision 0.5 keeps it.
2. Instrumentation: `OPS_APPROVAL_HOPS_FILE` (exists); add `stored_at` in `ApprovalStore.put`
   and `first_evaluated_at` in the selector. Report enqueue → stored p50/p99 and the fraction of
   transactions whose first evaluation is `PENDING` (the race rate).
3. Load: Gasstorm constant-rate 300 / 500 / 700 tx/s and Adaptive, gate on, per transport;
   with and without forward-after-ack.
4. Network: inject 1 ms and 5 ms one-way delay between OPS and the node (macOS `dnctl` +
   `pfctl`, Linux `tc netem`) to model cross-AZ; repeat 500 tx/s.
5. Output: one table here — transport × delay → enqueue→stored p50/p99, race rate,
   submit→inclusion p50/p95, throughput. Decision 0.1 is taken on that table.

### 3.5 Baseline: the current raw-TCP path (measured 22 September)

`gasstorm.py --only-gate` records OPS-side hop marks (`OPS_APPROVAL_HOPS_FILE`) and, from the
producer's decision log, how many approved transactions were first evaluated *before* their
approval arrived. `analyze_hops.py` reduces the marks. Gate on, ETH transfers, 20 s per rate,
1 s blocks, direct topology (OPS forwards to the producer itself). 8,192 approvals sampled for
hops (the recorder's cap); every transaction counted for the race.

| Rate | Submitted / confirmed | enqueue → written p50 / p90 / p99 / max | of which signing p50 | approval on the wire before forward began | allowed after ≥1 `wait` | dropped |
|---|---|---|---|---|---|---|
| 300 tx/s | 6,003 / 6,003 | **62 µs / 184 µs / 1.17 ms / 34 ms** | 24 µs | 0.01 % (forward starts ~60 µs earlier; the sign loop is asynchronous) | **0 of 6,003** | 0 |
| 500 tx/s | 10,011 / 10,011 | (same sample) | | | **0 of 10,011** | 0 |

Reading: **the race does not occur.** The approval leaves OPS tens of microseconds after the
forward begins, but the forward is an HTTP round trip to Besu and pool admission is followed by
a candidate build every ~500 ms, so the approval is in the store long before the producer
looks. Delivery is not a latency cost: 62 µs median, 1.2 ms p99, of which the TCP write is 6 µs.
Through an RPC node (§4c) the approval's lead only grows.

Consequences for §3:

- **Wire format is irrelevant to delay.** Comparing raw TCP against gRPC or HTTP on latency
  would produce indistinguishable microsecond figures. §3.4 is reduced accordingly.
- **What can still cost 500 ms or 5 s is delivery *failure*** — a dropped batch, a broken
  connection during a burst, a full store — which is the fire-and-forget row of §2. That is a
  reliability property (acknowledgements, redelivery, durable outbox), not a transport-speed
  one, and it argues for a transport with replies for that reason alone.
- The recommendation in §3.3 stands, on grounds of reliability, TLS, peer authentication,
  fan-out and operability — not speed.

### 3.4′ Benchmark, reduced

Replacing §3.4. Effort *estimate* 0.5–1 day.

1. **Failure injection on the current path** (the test that must go red first): under load,
   sever the OPS → producer connection for 1 s, and separately fill the store to capacity;
   count transactions that reach `TIMEOUT` or lose their approval. Expected today: losses equal
   to the batches in flight; expected after acks + redelivery + outbox: zero.
2. **One gRPC implementation, measured once** at 500 tx/s with the same instrumentation, to
   show no regression against the baseline table above (pass criterion: enqueue → stored
   p99 < 5 ms, race rate 0).
3. **Gossip topology check** on the CTO's layout (forward through a Reth or Erigon RPC node):
   race rate at 500 tx/s. Expected 0; recorded for the operator documentation.
4. Cross-AZ delay injection is dropped: with a ~60 µs lead and a ~500 ms evaluation cadence,
   1–5 ms of network delay cannot create a race; it only matters for failure recovery time,
   which item 1 measures.

## 4. Several nodes

The CTO's PoC topology (18 September) fixes the vocabulary: **one Besu sequencer with the plugin,
Reth and Erigon RPC nodes as the transaction submission channels.**

**a) Several OPS instances.** Not supported today (one `address`, one connection). With
node-dials-OPS every instance is dialled; a shared Postgres outbox lets any instance serve any
stream and survive instance loss; per-instance signing keys (with `key_id` and a key set on the
plugin) give attribution and independent rotation. The same transaction reaching two instances
(client retry across the LB) yields two approvals for one hash; the store keeps the newer —
harmless at execution, only the audit attribution can flip.

**b) The sequencer, optionally a standby.** Approvals must reach every node that may build the
next block. With streams per consumer and redelivery-on-connect, a standby is one more stream;
it must be fed continuously, not on failover. "Multiple producers" means nothing else in this
topology.

**c) RPC nodes (Reth, Erigon).** They submit transactions "as normal" and do not build blocks, so
they need no approvals. Two consequences:
- Forwarding through an RPC node adds gossip latency (*estimate* tens of ms) before the
  transaction reaches the sequencer's pool, while the approval goes to the sequencer directly —
  which helps the approval win the race. §3.5 measures the direct case; the gossip case should be
  measured on the target topology.
- **Preflight must run on a Besu node.** The fingerprint is computed by the same tracer the
  producer uses, so `ops_prepareApproval` cannot run on Reth or Erigon. Today it runs on the
  sequencer, i.e. ~3.5 ms of simulation per transaction on the block producer. Alternative: a
  non-producing Besu replica running only the plugin's RPC (decision 0.6).

**d) Several validators importing blocks** — out of scope: enforcement is producer-only; import
does not consult approvals. Every producer must run the plugin.

## 5. Order of work

Independently shippable; each ends with the 22-scenario suite green.

1. **Baseline** (§3.5) — done: 62 µs median delivery, race rate 0 at 300 and 500 tx/s.
2. **Reduced benchmark** (§3.4′): failure injection red test, one gRPC no-regression run,
   gossip-topology race check → decision 0.1.
3. **Transport + durability**: `.proto`; gRPC bidi with mTLS; node dials OPS; acks; Postgres
   outbox; redelivery on connect; forward-after-ack; strip `OPS_APPROVAL_ENCODING`, gate `hops`
   behind a build tag; backoff with jitter.
4. **Envelope v2 + keys**: `key_id`, `issued_at`, `expires_at`; key set on the plugin;
   Secrets Manager via IRSA; rotation procedure; per-instance keys.
5. **Lifecycle**: release on finality; expiry honoured by the selector; global rate limit on
   preflight; `ops_prepareApproval` behind network policy or Besu RPC auth.
6. **Observability**: connected-producers and OPS-connected gauges; delivery lag; race rate;
   alerts; readiness reflects delivery.
7. **Packaging and CI**: plugin build and release (decision 0.4); per-Besu-version scenario
   lane, nightly; compatibility note per Lineth Besu bump.
8. **Scope extensions**: 2930/4844; 7702 with the envelope extension; preflight replica
   (decision 0.6) if the sequencer load says so.

## 6. Compliance notes

- The seed file on disk deviates from Secrets Manager as canonical store — resolved in phase 4;
  document the interim.
- Phases 3–4 change access control (mTLS identities, key rotation) and 6 adds detective
  signals — change-management documentation for ISO 27001 / Vanta.
- Nothing here disables an existing control.
