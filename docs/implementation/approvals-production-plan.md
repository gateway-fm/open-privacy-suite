# Signed approvals: from PoC to production

**Status:** plan, revised after the critic pass of 22 September (24 findings; blockers 1–2 below are folded in). Items marked *fixed* landed on this branch on 22 September. **Date:** 22 September 2026. **Owner:** Ivan Beliakov.
**Scope:** the signed-approvals gate (preflight in OPS, fingerprint check in the block producer)
for the current OPS version. The in-node policy runtime is OPS v2 and is not discussed here.

Numbers are measured unless marked *estimate*. File references are to
`poc/ops-besu-signed-approvals` unless another worktree is named.

## 0. Decisions this plan needs

1. **Transport** for approval delivery — §3 recommends gRPC bidirectional streaming with mTLS,
   **OPS dialling the sequencer** (one inbound mTLS port on the sequencer, one stream per OPS
   instance), one acknowledgement per batch plus a capacity nack, the Ed25519 payload signature
   kept. The baseline (§3.5) shows delivery is not a latency cost and the race does not occur, so
   the case rests on reliability, TLS, peer authentication and operability; §3.4′ is the reduced
   check before code is written. *(Critic: the earlier "node dials OPS" was inconsistent — the
   sequencer keeps inbound `ops_prepareApproval` and the forward path anyway, and N OPS instances
   behind one address turn a node-initiated stream into a fan-in problem or put Postgres into the
   delivery path. §3.3 weighs both directions.)*
1a. **Forward-after-ack: no, unless a measurement says otherwise.** The race is 0 on both layouts
   (§3.5); making the request path wait for the sequencer's ack would couple request p99 to a
   stalled stream and needs a timeout policy, batch correlation and a head-of-line story (§3.6).
   Acks are for redelivery and nacks, not for ordering.
1b. **Finality on Lineth.** Release-on-finality (`c5b626c`) depends on what Maru sends as
   `finalizedBlockHash` and how far it lags. Nobody has checked. Until it is known, the store must
   be sized for rate × retention and its overflow path must be cheap (§2, blocker row). First item
   of any Lineth work: confirm Maru's finalized/safe semantics and the candidate-build cadence.
2. **Key custody and signature scheme.** AWS KMS does not offer Ed25519: either a software
   Ed25519 key in Secrets Manager (IRSA), or ECDSA P-256 for HSM-backed signing. Changes the
   envelope and both verifiers.
3. **TLS termination**: mesh/sidecar in front of the plugin listener, or in-process.
4. **Where the plugin lives and ships**: inside this repository, or its own repository with
   releases the Lineth operator pulls (Lineth loads plugin JARs from `besu/plugins/`).
5. **Reth**: second shipped target, or reference implementation only. Both PoCs share the OPS
   side (`internal/nodeapproval`), so this decides test scope, not architecture.
6. **Preflight placement** in the target topology (§4c): on the sequencer, or on a dedicated
   Besu replica running the plugin's RPC. A replica needs a **separate preflight URL** in OPS
   (today one `NODE_URL` serves preflight and forward) and lags the head by its import latency,
   which widens strict-V2's mismatch window; calls-V3 is mostly insensitive. The follower run
   (§3.5) already exercised this layout for plain transfers.

## 1. What ships

OPS receives `eth_sendRawTransaction`, runs RBAC, simulates the transaction on a Besu node
(`ops_prepareApproval`, the plugin's RPC), validates the observed call tree against policy,
signs an approval `(chain, tx hash, fingerprint, principal)` and delivers it to the block
producer; then forwards the transaction. The producer's plugin refuses to include a
transaction without an approval, and refuses one whose actual execution fingerprint differs
from the approved one — before commit, so a divergent transaction never enters the block.

| Measured (Besu 26.8.1, unmodified; one M2 Max running everything) | |
|---|---|
| Gasstorm **Adaptive**, 60 s, ETH transfers (README) | **671 tx/s average with the gate, 727 without, 765 straight to Besu** — the gate costs ~7 %, the remaining ceiling is Besu's |
| Per OPS request (`demo.py bench`, **constant-rate**, 16 clients; DEMO.md) | 17.5 ms → 21.1 ms with the gate (preflight ~3.5 ms of that); 775 → 657 submissions/s in that harness |
| Plugin work inside the producer | 7–22 µs per transaction |
| Scenarios | 20 scenarios, 22 checks, all green, deployments included (strict-V2 encoder ported to Java, verified against the Go golden vector); coexists with Lineth's own sequencer and pool plugins on an Osaka chain |

Not corners: the fingerprint encoders, the selector's veto semantics, the metrics that exist.

## 2. Where the PoC cut corners

| Corner | Where | Consequence | Fix |
|---|---|---|---|
| **Delivery is fire-and-forget.** ~~A batch whose write fails is dropped~~ — **fixed in `f98c440`**: the signed frame is resent on the next connection. Still open: a batch the plugin receives but cannot store (capacity) is logged and dropped, and a batch lost in a peer-closed socket buffer is never noticed. OPS learns nothing either way. | `internal/nodeapproval/transport.go` `deliver()`; plugin `ApprovalListener.accept()` | the transaction was already forwarded (`jsonrpc_processor.go:1684` enqueues, then forwards): it waits `waitMs` = 5 s, is evicted `TIMEOUT`, the client holds a hash and never gets a receipt, nothing is told | acknowledgements per batch (and a negative one for capacity); redelivery; durable outbox (next row) |
| **Nothing durable.** OPS queue is a channel (4096); plugin store is a `ConcurrentHashMap` | `service.go`; `ApprovalStore` | OPS crash after enqueue, or a Besu restart, loses approvals for forwarded transactions (scenario `restart_drops_approvals…`) | OPS outbox in Postgres; the node asks for redelivery of its pooled hashes on (re)connect |
| ~~**Approvals deleted on inclusion**~~ — changed in `c5b626c` to **release on finality** (`InclusionTracker`, `BlockchainService.getFinalizedBlock()`). **Open, blocker-grade:** correctness now depends on finality *advancing* on the target network, which is unverified (decision 1b). If finality lags or is absent, every included approval is retained until the 4,096-block cut-off (~68 min at 1 s blocks) or the orphan sweep (5–10 min); at 700 tx/s that is 210k–420k approvals against a 100k capacity | `OpsApprovalPlugin.onBlockAdded`; `ApprovalStore.put` | once full, every `put` iterates the whole pool into a set and sorts all entries under the lock — on the single ingress thread; OPS's 1 s write deadline then fails and transactions go `PENDING`/`TIMEOUT`. The eviction victims are exactly the included-not-final approvals the fix keeps, so reorg protection degrades to zero under load. The suite finalizes every block immediately (`harness.py:230`), so no test exercises a reorg or lagging finality | confirm Maru finality; size capacity/TTL to rate × retention; **cheap overflow path** (insertion-ordered store, pooled set cached, no per-put sort); a reorg scenario with lagging finality in the suite |
| **One key, no `key_id`, no expiry** | `Approval.Message()`; `node_approvals.go:18` (seed file); `ApprovalVerifier` (one key) | rotation = simultaneous restart of every producer and OPS; an approval never expires while pooled, so an RBAC change after approval does not revoke it | envelope v2: `key_id`, `issued_at`, `expires_at`; trusted key *set* on the plugin with validity windows |
| **Plain TCP, no TLS, no peer authentication** | `dialApproval`; `ApprovalListener` | the signature protects content only; anyone reaching the port can flood the store | §3 |
| **Single delivery target**, one connection, one goroutine | `Service.address` | no standby sequencer, no second OPS instance | §4 |
| **`ops_prepareApproval` unauthenticated at the node** | `PrepareApprovalRpc` | simulation only, but compute on the producer; reachable by anyone on the RPC port | network policy or Besu RPC authentication — **documented as a deployment requirement in `16010c9`**; enforcement is the operator's network policy until mTLS |
| **Diagnostics in the live path** | ~~`OPS_APPROVAL_ENCODING=json`~~ removed in `9abebc2`; `hops.go` remains, opt-in by env (nil when unset; `mark` returns at its first check) | — | keep `hops` as is; its 8,192-row cap made the 500 tx/s delivery sample meaningless (§3.5) — make the cap configurable |
| **No health signal** | — | while OPS is disconnected the first ~8k transactions (128 batches + 4,096 queued approvals) are forwarded and time out; after that `Enqueue` fails and requests get 503 without forwarding (`jsonrpc_processor.go:1684`) — fail-closed, but late and unannounced | connected-producers gauge on OPS, OPS-connected gauge on the plugin; the 503 rate as a signal; alerts; readiness reflects delivery connectivity |
| **Reconnect backs off only on dial failure** — a peer that accepts and then resets (the plugin at `maxConnections` closes right after `accept`, a proxy, a half-started plugin) gives a tight dial/write/close loop, one Java reader thread per iteration; and a write that lands in the kernel buffer before the RST is marked written and lost | `deliver()` after `f98c440` | CPU spin on both sides; silent loss of the first batch after a refused connect | backoff with jitter on write failure too; the kernel-buffer case is only closed by acknowledgements |
| **Graceful shutdown drops in-flight approvals** — on `Close()` (every rolling restart) the retry batch, up to 128 signed batches and up to 4,096 queued approvals are discarded, all for transactions already forwarded | `service.go` `Close()`, `deliver()`, `signLoop()` | a deploy loses the last seconds of approvals; their transactions time out | drain on close with a bounded deadline (cheap; predates the outbox) |
| **Frame limits hard-coded** | `MaxBatchApprovals` 32, `MaxBatchFrame` 16 KiB | undocumented | limits in the protocol document |
| **Rate limiting deferred to OPS** | README | any authorised client can fill the store (100 k) for the TTL — and a full store is a **DoS lever**: every further `put` is a full pool scan plus an O(n log n) sort under the lock (see the finality row) | global (Redis) rate limit on preflight per principal; cheap overflow path |
| **No feedback path for producer decisions** | `ApprovalSelector.reject()` logs `OPS_APPROVAL_DECISION` on the sequencer only | a transaction denied `MISMATCH` or dropped `TIMEOUT` vanishes: the user holds a hash and no receipt, OPS cannot say why, the explorer shows nothing, audit attribution stops at "forwarded" | a decision stream from the plugin back to OPS (the bidi stream carries it); surfaced in transaction status and the explorer; recorded for audit |
| **One `NODE_URL` for preflight and forward** | `server.go` → `node_approvals.go:13`; `besu.go` ignores the plugin's `parentBlockHash` | a preflight replica (decision 0.6) is impossible to configure; strict-V2 on a lagging node widens the mismatch window | separate preflight URL; pin the preflight block in the approval and let the producer check freshness |
| **No CI, `@Unstable` Besu API** | `poc/` trees, Gradle against Cloudsmith | breaks silently on a Besu bump; Lineth pins the commit | per-Besu-version scenario lane (JDK 25 + Besu binary), nightly |
| **Scope limits, documented** | README | producer-only; legacy + EIP-1559 only; strict-V2 state-exact for lifecycle; no revocation | decisions, not bugs; 2930/4844 trivial, 7702 needs the envelope extension |

## 3. Transport

### 3.1 What latency actually depends on

The transaction and its approval travel on two paths. When the producer evaluates a pooled
transaction whose approval has not arrived, the selector answers `PENDING` and re-evaluates it
on the **next candidate build** — on Besu every **~500 ms**: successive `wait` decisions for
one transaction in `evidence/timeout.log` are 504–508 ms apart, and the mechanism is Besu's
`DEFAULT_POS_BLOCK_CREATION_REPETITION_MIN_DURATION` = 500 ms (a configurable minimum; Lineth is
Engine-API-driven by Maru, so it applies); on the Reth PoC, the next payload build, up to one block. After `waitMs`
(5 s) the transaction is dropped.

The transport's own cost is microseconds. The cost that matters is the **race**: if the
transaction reaches the producer before its approval, inclusion slips by up to one candidate
build; if delivery fails, by 5 s to a drop. The PoC instrumented delivery (`hops.go`) but never
recorded it — §3.5 fixes that.

An **acknowledgement** could remove the race entirely — forward only after the producer has
stored the approval — but §3.5 shows the race does not occur, and waiting would couple every
request's p99 to a stalled stream and needs a timeout policy, batch correlation and a
head-of-line story (§3.6). Decision 1a: acknowledgements are for **redelivery and nacks**, not
for ordering. They remain the strongest argument for a transport with replies: without them a
batch lost in a peer-closed socket buffer, or refused by a full store, is invisible to OPS.

### 3.2 Options

| | One-way latency | Ack | TLS / mTLS | Schema, versioning | Fan-out | Go / Java / Rust | Operability |
|---|---|---|---|---|---|---|---|
| Raw TCP, length prefix (current) | ~0.5 RTT + µs | none — must be built | none — must be built | three hand-written encoders, string domain tag | hand-managed mesh | hand-rolled | bespoke protocol, bespoke runbooks |
| Raw TCP + ack frame | same | built by us | must be built | same | same | same | same |
| **gRPC bidi stream, HTTP/2, mTLS** | same ~0.5 RTT; framing + proto ≈ 10 B, µs | native on the stream | native | `.proto`, codegen ×3, field-evolution rules | native: one stream per OPS instance | grpc-go (`go.mod` already has grpc 1.82 + protobuf); grpc-java **at Besu's version** — Besu 26.8.1 ships `grpc-{api,core,netty,util,context}` 1.79.0 and Netty 4.2.17 unshaded, and loads plugins parent-first (`URLClassLoader` in `BesuPluginContextImpl`), so the plugin compiles against those and bundles only `grpc-stub`, `grpc-protobuf`, `protobuf-java`; `grpc-netty-shaded` would *not* help; tonic for Reth | standard: grpcurl, interceptors, tracing, deadlines, health |
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

**gRPC bidirectional streaming over HTTP/2 with mTLS; OPS dials the sequencer; one
acknowledgement per batch and a nack for a refused (full-store) batch; the Ed25519 payload
signature kept; the stream also carries the producer's decisions back (§2, feedback row).**

- Latency-equivalent to raw TCP: one persistent stream, one write per batch, no batching
  timer (`takeBatch` snapshot semantics unchanged).
- Acknowledgements make redelivery exact and nacks possible; they are not used to gate
  forwarding (decision 1a).
- **Who dials whom.** *OPS → sequencer* (recommended): the sequencer exposes one inbound mTLS
  port — it already exposes `ops_prepareApproval` and the forward path inbound, so this adds no
  new direction; N OPS instances are N streams with no fan-in; the sequencer's first message on
  any new stream is its pooled hashes, so redelivery on (re)connect works regardless of who
  dialled. *Sequencer → OPS*: attractive only if the sequencer had no inbound ports at all
  (decision 0.6 taken *and* forwarding moved off it); with N OPS behind one address a single
  stream lands on one instance, so either the plugin discovers instances or a shared Postgres
  outbox sits in every delivery — the component-in-the-inclusion-path this section rejects
  for a broker. Standby sequencer: one more stream from each OPS instance (§4b).
- mTLS authenticates both ends and gives encryption in transit (ISO/IEC 27001:2022 Annex A
  8.24, use of cryptography — confirm the mapping with Compliance); the payload signature
  authenticates the *decision* independently of the channel and remains auditable. Certificate
  lifecycle (CA, issuance, rotation, private keys in Secrets Manager / CSI) is part of the
  transport work, not an afterthought (§6).
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

| Layout · requested (achieved avg) | Submitted / confirmed | enqueue → written p50 / p90 / p99 / max | of which signing p50 | approval on the wire before forward began | allowed after ≥1 `wait` | dropped |
|---|---|---|---|---|---|---|
| direct · 300 (225) | 6,003 / 6,003 | **62 µs / 184 µs / 1.17 ms / 34 ms** ¹ | 24 µs | 0.01 % (forward starts ~60 µs earlier; the sign loop is asynchronous) | **0 of 6,003** | 0 |
| direct · 500 (349) | 10,011 / 10,011 | ¹ | | | **0 of 10,011** | 0 |
| follower · 300 (~225) | 6,011 / 6,002 ² | **64 µs / 164 µs / 0.71 ms / 53 ms** ¹ | | 0 % | **0 of 6,002** | 0 |
| follower · 500 (~350) | 10,011 / 10,011 | ¹ | | | **0 of 10,011** | 0 |

¹ The hop recorder caps at 8,192 rows per OPS process and both rates run in one process, so the
delivery sample is the whole 300 run plus the first ~2,200 approvals of the 500 run: **delivery
latency at 500 tx/s is not yet measured**, only the race count is. Nothing yet shows the race at
the 671 tx/s of §1. Fix: configurable cap, one sample per rate (§3.4′ item 2).
² Nine transactions of the follower 300 run were discarded by the generator (`txDiscarded: 9`),
coinciding with five `signed preflight failed … context canceled` in the OPS log — client-side
cancellations during a brief OPS stall, not a delivery race; unexplained and tracked.

Reading: **the race does not occur, on either layout.** The approval leaves OPS tens of
microseconds after the forward begins, but the forward is an HTTP round trip to Besu and pool
admission is followed by a candidate build every ~500 ms, so the approval is in the store long
before the producer looks. Through a follower RPC node the transaction additionally travels
~80 ms of gossip (`topology_probe.py`), so the approval's lead only grows. Delivery is not a
latency cost at the rates measured: 62–64 µs median, ≤ 1.2 ms p99, of which the TCP write is
6 µs.

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
2. **One gRPC implementation, measured once** at 500 tx/s with the same instrumentation and an
   uncapped hop sample, to show no regression against the baseline (pass criterion: enqueue →
   stored p99 < 5 ms, race rate 0). Also the first honest delivery-latency figure *at* 500 tx/s
   (§3.5 caveat).
3. ~~Gossip topology check~~ — **done** (`4573e40`, `topology.py`, `--topology follower`): race
   0 of 16,013; see §3.5. Repeat once with Reth/Erigon as the follower when that stack exists.
3a. **Capacity red test**: fill the store to capacity under load and count approvals refused and
   transactions lost; then the same after the cheap-overflow fix and the nack.
3b. **Reorg with lagging finality** in the scenario suite: finalized = head − 2, build a rival
   block, FCU to it (`CHAIN_REORG`), and require the returned transactions to be included in the
   next block with their approvals intact.
4. Cross-AZ delay injection is dropped: with a ~60 µs lead and a ~500 ms evaluation cadence,
   1–5 ms of network delay cannot create a race; it only matters for failure recovery time,
   which item 1 measures.

### 3.6 What the acknowledgement protocol must specify

Forwarding does not wait for acks (decision 1a), so these are reliability semantics, not
request-path ones — but they still have to be written down before the `.proto`:

- **Batch identity** — a batch id in the frame, echoed in the ack/nack, so a stream can have
  several batches in flight without head-of-line blocking on one nack.
- **Nack reasons** — at least `capacity` and `unsupported`; on `capacity` OPS keeps the batch and
  retries with backoff rather than dropping.
- **Redelivery** — the sequencer's first message on a new stream lists its pooled hashes; OPS
  redelivers what it still holds (outbox). Also **periodic**: after a sequencer restart, RPC nodes
  re-announce pooled transactions before the plugin's stream is up, and `waitMs` counts from pool
  admission (`getAddedAt`) — so a connect-only redelivery can arrive after the timeout. Either
  redeliver on a timer while unacked approvals exist, or measure `waitMs` from plugin readiness.
- **Ordering** — none required across batches; the store is keyed by transaction hash and a
  newer approval replaces an older one.
- **Decision feedback** — the sequencer streams `allow`/`deny(reason)`/`timeout` per transaction
  hash back to OPS (§2, feedback row).

## 4. Several nodes

The CTO's PoC topology (18 September) fixes the vocabulary: **one Besu sequencer with the plugin,
Reth and Erigon RPC nodes as the transaction submission channels.**

**a) Several OPS instances.** Each instance holds its own mTLS stream to the sequencer (OPS dials,
§3.3), so no fan-in and no shared component in the delivery path; a Postgres outbox is per
instance's durability, not a bus. Per-instance signing keys (with `key_id` and a key set on the
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
  producer uses, and Besu and geth-shaped tracers differ in which frames exist (no frame for a
  CALL with insufficient balance or at depth 1024, nor for a CREATE that fails before its frame),
  so `ops_prepareApproval` cannot run on Reth or Erigon. Today it runs on the sequencer, ~3.5 ms
  of simulation per transaction on the block producer. Alternative: a non-producing Besu replica
  running the plugin's RPC (decision 0.6) — the follower run already did exactly this for plain
  transfers. Caveats: OPS needs a separate preflight URL, and a replica lags the head by its
  import latency, which widens strict-V2's state-exact window from "same block" to "lag + same
  block"; calls-V3 is mostly insensitive.

**d) Several validators importing blocks** — out of scope: enforcement is producer-only; import
does not consult approvals. Every producer must run the plugin.

## 5. Order of work

Independently shippable; each ends with the 22-scenario suite green.

0. **Lineth facts first**: Maru's finalized/safe semantics and lag; candidate-build cadence on
   the target configuration; the operator's change process for adding a plugin to the sequencer.
   §3.5 and `c5b626c` rest on these.
1. **Baseline** (§3.5) — done, both layouts: 62–64 µs median delivery, race rate 0.
2. **Reduced benchmark** (§3.4′): write-failure red test **done** (`f98c440`); gossip layout
   **done** (`4573e40`); still to do: capacity red test, reorg-with-lagging-finality scenario, one
   gRPC no-regression run with an uncapped sample → decision 0.1.
2a. **Cheap, safe fixes that need no transport decision**: backoff with jitter on write failure;
   drain on close; configurable hop cap; cheap overflow path in `ApprovalStore` (insertion order,
   cached pooled set); record `FORK` blocks in the tracker; state the basis for the tracked depth.
3. **Transport + durability**: `.proto` **including envelope v2** (`key_id`, `issued_at`,
   `expires_at` — one wire migration, not two); gRPC bidi with mTLS at Besu's grpc version; OPS
   dials the sequencer; acks, capacity nack, decision feedback; Postgres outbox (expand-only, with
   the `privacy_proxy_app` GRANT block); redelivery on connect and periodic; certificate lifecycle.
4. **Keys**: key set on the plugin; Secrets Manager via IRSA scoped to the one secret ARN;
   rotation procedure; per-instance keys.
5. **Lifecycle**: ~~release on finality~~ (done, `c5b626c`); expiry honoured by the selector;
   global rate limit on preflight; `ops_prepareApproval` behind network policy or Besu RPC auth
   (documented, `16010c9`; enforcement is deployment).
6. **Observability** — a prerequisite for putting 3 on Lineth, not a follow-up: connected
   gauges both sides; delivery lag; race rate; 503 rate; decision counts; alerts; readiness
   reflects delivery. The per-transaction `OPS_APPROVAL_DECISION`/`TIMING` INFO lines are a new
   log source on the sequencer (two lines per allowed transaction) — make them sampled or
   metric-only, and treat retention/shipping as a logging-control change.
7. **Packaging and CI** — also earlier than it looks, since it is what lets 3–6 survive a Besu
   bump: plugin build and release (decision 0.4); per-Besu-version scenario lane, nightly; grpc
   and Netty versions pinned to Besu's; compatibility note per Lineth Besu bump.
8. **Scope extensions**: 2930/4844; 7702 with the envelope extension; preflight replica
   (decision 0.6) if the sequencer load says so.

## 6. Compliance notes

- The seed file on disk deviates from Secrets Manager as canonical store — resolved in phase 4;
  document the interim.
- Phase 3 introduces mTLS: CA, issuance, rotation and where private keys live (Secrets Manager
  via CSI/IRSA) are part of the design, not deployment detail. IRSA roles scoped to the specific
  secret ARNs.
- Phases 3–4 change access control (mTLS identities, key rotation) and 6 adds detective
  signals and a new log source on the sequencer (A.8.15 logging) — change-management
  documentation for ISO 27001 / Vanta.
- The Postgres outbox is a new table: expand-only migration with the `privacy_proxy_app` GRANT
  block, per repository policy.
- Installing the plugin on the sequencer is a change to the Lineth operator's component and goes
  through their change process, not only ours.
- Evidence logs under `poc/…/evidence/` embed local paths; scrub before the repository is public.
- Nothing here disables an existing control.
