# Signed approvals: from PoC to production

**Status:** plan, revised after the critic pass of 22 September (24 findings; blockers 1–2 below are folded in). Items marked *fixed* landed on this branch on 22 September. **Date:** 22 September 2026. **Owner:** Ivan Beliakov.
**Scope:** the signed-approvals gate (preflight in OPS, fingerprint check in the block producer)
for the current OPS version. The in-node policy runtime is OPS v2 and is not discussed here.

Numbers are measured unless marked *estimate*. File references are to
`poc/ops-besu-signed-approvals` unless another worktree is named.

## 0. Decisions this plan needs

1. ~~Transport~~ — **decided (24 September): gRPC over HTTP/2 (TLS postponed, decision 3), one unary call per
   batch; the call's status is the confirmation; no broker.** OPS dials the sequencer (1c; one
   inbound port on the sequencer, one channel per OPS instance); the Ed25519 payload signature
   is kept. OK means the plugin verified and stored the batch; a retryable error means OPS resends
   it with backoff (§3.6). This replaces the earlier bidirectional stream with its own ack/nack
   messages: the confirmation comes with the call, so there is no ack protocol to build. Measured (§3.4′ item 2): gRPC is ~20 µs slower at the median than raw TCP and mTLS adds
   nothing measurable, against a ~500 ms candidate cadence; the baseline (§3.5) shows the race
   does not occur. So the decision is not about speed — it is whether to build acks, TLS and peer
   authentication on raw TCP ourselves or take gRPC's. *(Critic: the earlier "node dials OPS" was inconsistent — the
   sequencer keeps inbound `ops_prepareApproval` and the forward path anyway, and N OPS instances
   behind one address turn a node-initiated stream into a fan-in problem or put Postgres into the
   delivery path. §3.3 weighs both directions.)*
1a. **Forward-after-ack: no, unless a measurement says otherwise.** The race is 0 on both layouts
   (§3.5); making the request path wait for the sequencer's confirmation would couple request
   p99 to a stalled call. Confirmations drive redelivery, not forwarding or ordering: OPS forwards
   the transaction without waiting for them.
1b. **Finality on Lineth.** Release-on-finality (`c5b626c`) depends on what Maru sends as
   `finalizedBlockHash` and how far it lags. Nobody has checked. Until it is known, the store must
   be sized for rate × retention and its overflow path must be cheap (§2, blocker row). First item
   of any Lineth work: confirm Maru's finalized/safe semantics and the candidate-build cadence.
1c. ~~Connection direction~~ — **decided (24 September): OPS connects to the node, on Besu and
   Reth alike.** OPS already opens a connection to the node for preflight on both
   (`ops_prepareApproval` on Besu, `debug_traceCall` on Reth), so reversing only the approval
   stream would buy nothing. It would matter only if preflight moved to a replica (decision 6)
   and transactions went through RPC nodes: the approval stream would then be the only connection
   OPS opens to the sequencer, and reversing it would leave the sequencer with no inbound
   connection from OPS. That is a later hardening option, not part of this plan.
2. ~~Key custody and signature scheme~~ — **decided and implemented (22 September).** Keep Ed25519
   as a **software key delivered like every other OPS secret** — environment or a Secrets
   Manager–mounted file (IRSA/CSI), never a config file, exactly the policy `internal/config/file.go`
   states and the pattern the audit chain already follows (`internal/audit/checkpoint.go`: a
   `Signer` with a key id and an explicit "KMS later" seam). Not ECDSA via KMS: a KMS signature per
   batch would put a network call and ~10 ms into the delivery path for no gain over a rotatable
   software key. What changed: the signed batch names its key (`OPS_APPROVAL_BATCH_V2`,
   `key_id` inside the signed bytes, `OPS_APPROVAL_KEY_ID` on OPS, default `default`); the plugin
   holds a **set** of trusted keys (`--plugin-ops-approval-public-keys id=hex,…`; the old single
   `--public-key` is the `default` id); OPS signs through a `Signer` interface so a KMS/HSM-backed
   ECDSA signer can be added without touching the wire. Rotation is add-then-switch: add the new
   key to the plugin, switch OPS's `OPS_APPROVAL_KEY_ID`/seed, remove the old key — no
   simultaneous restart. Still open: expiry (`issued_at`/`expires_at`), which needs the same
   transport-independent envelope work and is scheduled with the `.proto`.
3. ~~TLS termination~~ — **postponed (24 September): plaintext gRPC on the internal network for
   now**, like the rest of OPS's internal traffic (the OPS → node JSON-RPC path already carries
   the raw transactions). Nothing secret crosses the channel and the Ed25519 signature protects
   integrity without TLS: nobody on the network can forge or alter an approval. What TLS would
   add — confidentiality and peer authentication — is covered meanwhile by (a) a network rule
   letting only OPS reach the plugin's port (otherwise anyone reachable can make the plugin
   verify junk), and (b) a recorded risk acceptance (§6). The one privacy-relevant field is the
   principal, a Keccak hash of the OPS user id: a stable pseudonym that lets an eavesdropper link
   one user's transactions across addresses — dropping it from the wire is an open option.
   When TLS comes, it is in-process at both ends (no service mesh is known to be in place, and
   the sequencer may not run in one).
4. ~~Where the plugin lives and ships~~ — **decided (24 September): in this repository.** One
   PR changes both ends of the wire format and the shared golden vectors, and CI runs OPS, Besu
   and the plugin together. The JAR is released from here under its own tag, built for and named
   after the Besu version it supports; the Lineth operator pulls it into `besu/plugins/`. The code
   leaves `poc/` when packaging starts (§5 item 7).
5. ~~Reth~~ — **decided (24 September): both Besu and Reth ship.** Reth is faster and widely used, and it is
   where the performance story can be told; Besu covers Besu-based stacks such as Lineth. Both targets share the OPS side (`internal/nodeapproval`) and implement the same
   delivery contract (§3.6) — so every transport change lands in Java and in Rust, and CI runs a
   lane per target. Starting point: the Reth PoC is still on envelope v1 (the v2 port is parked
   in `patches/reth-poc-envelope-v2.patch`, four type errors left), and its source has never been
   committed — it exists only as untracked files in its own worktree.
6. ~~Preflight placement~~ — **decided (24 September): on the sequencer for now.** A dedicated
   Besu replica running the plugin's RPC stays possible later (with 1c's hardening option); the
   plugin's preflight is a local simulation on the node's own head state and needs nothing from
   the block producer. A replica needs a **separate preflight URL** in OPS
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
| Scenarios | 21 scenarios, 23 checks, all green, deployments included (strict-V2 encoder ported to Java, verified against the Go golden vector); coexists with Lineth's own sequencer and pool plugins on an Osaka chain |

Not corners: the fingerprint encoders, the selector's veto semantics, the metrics that exist.

## 2. Where the PoC cut corners

| Corner | Where | Consequence | Fix |
|---|---|---|---|
| **Delivery is fire-and-forget.** ~~A batch whose write fails is dropped~~ — **fixed in `f98c440`**: the signed frame is resent on the next connection. Still open: a batch the plugin receives but cannot store (capacity) is logged and dropped, and a batch lost in a peer-closed socket buffer is never noticed. OPS learns nothing either way. | `internal/nodeapproval/transport.go` `deliver()`; plugin `ApprovalListener.accept()` | the transaction was already forwarded (`jsonrpc_processor.go:1684` enqueues, then forwards): it waits `waitMs` = 5 s, is evicted `TIMEOUT`, the client holds a hash and never gets a receipt, nothing is told | acknowledgements per batch (and a negative one for capacity); redelivery; durable outbox (next row) |
| **Nothing durable.** OPS queue is a channel (4096); plugin store is a `ConcurrentHashMap` | `service.go`; `ApprovalStore` | OPS crash after enqueue, or a Besu restart, loses approvals for forwarded transactions (scenario `restart_drops_approvals…`) | OPS outbox in Postgres; the node asks for redelivery of its pooled hashes on (re)connect |
| ~~**Approvals deleted on inclusion**~~ — changed in `c5b626c` to **release on finality** (`InclusionTracker`, `BlockchainService.getFinalizedBlock()`). **Open, blocker-grade:** correctness now depends on finality *advancing* on the target network, which is unverified (decision 1b). If finality lags or is absent, every included approval is retained until the 4,096-block cut-off (~68 min at 1 s blocks) or the orphan sweep (5–10 min); at 700 tx/s that is 210k–420k approvals against a 100k capacity | `OpsApprovalPlugin.onBlockAdded`; `ApprovalStore.put` | once full, every `put` iterates the whole pool into a set and sorts all entries under the lock — on the single ingress thread; OPS's 1 s write deadline then fails and transactions go `PENDING`/`TIMEOUT`. The eviction victims are exactly the included-not-final approvals the fix keeps, so reorg protection degrades to zero under load. ~~The suite finalizes every block immediately, so no test exercises a reorg or lagging finality~~ — `reorg_keeps_approvals` now does (finality lags one block, a rival replaces the head, the returned transactions are included again with **no new approval**) | confirm Maru finality; size capacity/TTL to rate × retention; ~~cheap overflow path~~ (`8186d3d`: event-driven liveness, no scan, no sort); **finding from the scenario:** Besu 26.8.1 re-adds a reorganised block's transactions to its pool unreliably (one run returned nonce 1 and dropped nonce 0, another returned neither) — see the new row below |
| **Nobody resubmits a reorganised transaction.** Besu's pool re-add after a reorg is partial (above); OPS keeps no record of what it forwarded, so it cannot detect that a forwarded transaction vanished from the canonical chain, let alone resubmit it | `jsonrpc_processor.go` forward path; no submission table on this branch | the approval survives (`c5b626c`), the transaction does not: the client sees a receipt disappear and must resubmit the same signed bytes itself — which does work without a new approval | a submissions record with reconciliation (the v2 branch's `node_submissions` + reconciler is the shape); belongs with the decision-feedback row |
| ~~**One key, no `key_id`**~~ — **fixed (envelope v2)**: the batch names its key inside the signed bytes; the plugin (and the Reth PoC) hold a key set; unknown or swapped id fails closed. **Still open: no expiry** — an approval never expires while pooled, so an RBAC change after approval does not revoke it | `batch.go` `Ed25519Signer`; `ApprovalBatch`/`ApprovalVerifier`/`PluginOptions`; `batch.rs` | — | `issued_at`/`expires_at` with the `.proto` (phase 3) |
| **Plain TCP, no TLS, no peer authentication** | `dialApproval`; `ApprovalListener` | the signature protects content only; anyone reaching the port can flood the store | §3 |
| **Single delivery target**, one connection, one goroutine | `Service.address` | no standby sequencer, no second OPS instance | §4 |
| **`ops_prepareApproval` unauthenticated at the node** | `PrepareApprovalRpc` | simulation only, but compute on the producer; reachable by anyone on the RPC port | network policy or Besu RPC authentication — **documented as a deployment requirement in `16010c9`**; enforcement is the operator's network policy until mTLS |
| **Diagnostics in the live path** | ~~`OPS_APPROVAL_ENCODING=json`~~ removed in `9abebc2`; `hops.go` remains, opt-in by env (nil when unset) | — | ~~cap~~ `OPS_APPROVAL_HOPS_LIMIT` (`0ee3167`); the load harness records whole runs now |
| **No health signal** | — | while OPS is disconnected the first ~8k transactions (128 batches + 4,096 queued approvals) are forwarded and time out; after that `Enqueue` fails and requests get 503 without forwarding (`jsonrpc_processor.go:1684`) — fail-closed, but late and unannounced | connected-producers gauge on OPS, OPS-connected gauge on the plugin; the 503 rate as a signal; alerts; readiness reflects delivery connectivity |
| ~~**Reconnect backs off only on dial failure**~~ — **fixed in `0ee3167`**: every connection loss (dial, write, peer close) is followed by one jittered pause; the test saw 11,023 connections in 700 ms before. Still open: a write that lands in the kernel buffer before the RST is marked written and lost | `deliver()` | — | the kernel-buffer case is only closed by acknowledgements |
| ~~**Graceful shutdown drops in-flight approvals**~~ — **fixed in `0ee3167`**: the signer drains the queue on stop, the sender delivers until the batch channel closes or 2 s pass, `Enqueue` refuses once closing; 45 of 200 delivered before, 200 after | `Close()`, `deliver()`, `signLoop()` | — | — |
| **Frame limits hard-coded** | `MaxBatchApprovals` 32, `MaxBatchFrame` 16 KiB | undocumented | limits in the protocol document |
| **Rate limiting deferred to OPS** | README | any authorised client can fill the store (100 k) for the TTL — and a full store is a **DoS lever**: every further `put` is a full pool scan plus an O(n log n) sort under the lock (see the finality row) | global (Redis) rate limit on preflight per principal; cheap overflow path |
| **No feedback path for producer decisions** | `ApprovalSelector.reject()` logs `OPS_APPROVAL_DECISION` on the sequencer only | a transaction denied `MISMATCH` or dropped `TIMEOUT` vanishes: the user holds a hash and no receipt, OPS cannot say why, the explorer shows nothing, audit attribution stops at "forwarded" | decided 24 September (§3.3): decisions stay internal — the sequencer's decision log and metrics, shipped by the logging pipeline and recorded for audit; not sent back over the delivery channel and not surfaced to users |
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
head-of-line story (§3.6). Decision 1a: confirmations drive **redelivery and refusals**, not
forwarding or ordering. They remain the strongest argument for a transport with replies: without them a
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

**Decided (24 September): gRPC over HTTP/2 (mTLS postponed, §0.3); OPS dials the sequencer; one unary call
per batch, whose status is the confirmation; the Ed25519 payload signature kept; no broker.
The producer's decisions stay on the sequencer — decision log and metrics — and do not travel
back over this channel (§2, feedback row: internal, never user-facing).**

- Latency-equivalent to raw TCP: one persistent HTTP/2 connection, one call per batch, calls
  multiplexed so none waits for another, no batching timer (`takeBatch` snapshot semantics
  unchanged). §3.4′ measured the streaming shape; the unary shape is re-measured on the same
  bench before quoting a number for it (§5 item 2).
- Confirmations make redelivery exact and refusals visible to OPS; they are not used to gate
  forwarding (decision 1a).
- **Who dials whom — decided (§0 1c).** *OPS → sequencer*: the sequencer exposes one inbound
  port — it already exposes `ops_prepareApproval` and the forward path inbound, so this adds no
  new direction; N OPS instances are N channels with no fan-in; redelivery after a sequencer
  restart is driven by the plugin's boot id in every response (§3.6). *Sequencer → OPS*: attractive only if the sequencer had no inbound ports at all
  (decision 0.6 taken *and* forwarding moved off it); with N OPS behind one address a single
  stream lands on one instance, so either the plugin discovers instances or a shared Postgres
  outbox sits in every delivery — the component-in-the-inclusion-path this section rejects
  for a broker. Standby sequencer: one more channel from each OPS instance (§4b).
- *Postponed (§0.3); kept for when it lands:* mTLS authenticates both ends and gives encryption in transit (ISO/IEC 27001:2022 Annex A
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
² Nine transactions of the follower 300 run were discarded by the generator (`txDiscarded: 9`).
The OPS log explains it: at 19:59:34.874 `context canceled` hit unrelated operations in the same
millisecond — preflight `POST`s, address linking, a compliance-config read — so the *client*
cancelled its requests during a brief OPS latency spike (~80 ms requests just before, against
~12 ms). OPS answered 403 and forwarded nothing. Fail-closed; not a delivery race. The spike is an
OPS latency item, outside this plan.

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
2. ~~One gRPC implementation, measured once~~ — **done** (`bench/`): the same signed frames, the
   same host, 500 batches/s × 32 approvals for 10,000 batches, sender in Go (grpc-go 1.82),
   receiver in Java at **Besu's grpc 1.79.0 / Netty 4.2.17** — the versions a plugin inside Besu
   is bound to. One-way delivery, sender wall clock to receiver wall clock:

   | Transport | p50 | p90 | p99 | max | ack round trip p50 / p99 |
   |---|---:|---:|---:|---:|---:|
   | raw TCP, length prefix (today) | **102 µs** | 224 µs | 568 µs | 18.7 ms | — |
   | gRPC bidi stream, plaintext | **123 µs** | 262 µs | 615 µs | 29.2 ms | 232 µs / 1.15 ms |
   | gRPC bidi stream, **mTLS** (TLS 1.3, P-256) | **109 µs** | 245 µs | 645 µs | 28.6 ms | 211 µs / 1.18 ms |

   gRPC costs ~20 µs at the median and ~50–80 µs at p99 over raw TCP; mTLS costs nothing
   measurable on 3.9 KB frames; an acknowledgement returns in ~0.2 ms. Against a ~500 ms
   candidate cadence none of this is a factor, which is the measured answer to "is raw TCP
   faster": yes, by an amount that cannot matter. Reproduce with `bench/run.sh`.
3. ~~Gossip topology check~~ — **done** (`4573e40`, `topology.py`, `--topology follower`): race
   0 of 16,013; see §3.5. Repeat once with Reth/Erigon as the follower when that stack exists.
3a. **Capacity red test**: fill the store to capacity under load and count approvals refused and
   transactions lost; then the same after the cheap-overflow fix and the capacity refusal
   (`RESOURCE_EXHAUSTED`, §3.6).
3b. ~~Reorg with lagging finality~~ — **done**: `reorg_keeps_approvals` (harness gained
   `finality_lag`, `parent`, `reorg_to_rival`). Finalized lags one block, a rival replaces the head
   (Besu logs the chain reorg), the orphaned transactions are resubmitted as the same signed bytes
   and included with no new approval; each transaction is allowed twice in the decision log.
4. Cross-AZ delay injection is dropped: with a ~60 µs lead and a ~500 ms evaluation cadence,
   1–5 ms of network delay cannot create a race; it only matters for failure recovery time,
   which item 1 measures.

### 3.6 What the delivery contract must specify

Forwarding does not wait for confirmations (decision 1a), so these are reliability semantics,
not request-path ones — written down before the `.proto`:

- **One call per batch.** The call returns only after the plugin has verified the signature and
  stored the batch, so its status is the confirmation. Calls are independent and multiplexed on
  one connection: no batch id, no head-of-line blocking, no ack messages.
- **Status codes.** `OK` — stored. `RESOURCE_EXHAUSTED` — store full; OPS keeps the batch and
  retries with backoff. `UNAVAILABLE` / `DEADLINE_EXCEEDED` — retry with backoff.
  `UNAUTHENTICATED` / `PERMISSION_DENIED` / `INVALID_ARGUMENT` — bad signature, untrusted key id,
  wrong chain or malformed batch: no retry, counted and alerted on OPS (a configuration fault,
  e.g. a key not yet in the plugin's set).
- **Redelivery after a sequencer restart.** A confirmed approval can still be lost when the
  sequencer restarts (the store is RAM). Every response carries the plugin's boot id; when it
  changes, OPS resends every approval it still retains (not yet final, §2). RPC nodes re-announce
  pooled transactions after a restart and `waitMs` counts from pool admission (`getAddedAt`), so
  the resend must land within `waitMs` of the plugin coming up — OPS probes on channel reconnect
  rather than waiting for the next batch; alternatively `waitMs` counts from plugin readiness.
- **Ordering** — none required across batches; the store is keyed by transaction hash and a
  newer approval replaces an older one.
- **Decisions** — `allow`/`deny(reason)`/`timeout` stay on the sequencer (decision log and
  metrics, shipped by the logging pipeline); they are internal and never reach the user.

## 4. Several nodes

The CTO's PoC topology (18 September) fixes the vocabulary: **one Besu sequencer with the plugin,
Reth and Erigon RPC nodes as the transaction submission channels.**

**a) Several OPS instances.** Each instance holds its own gRPC channel to the sequencer (OPS dials,
§3.3), so no fan-in and no shared component in the delivery path; a Postgres outbox is per
instance's durability, not a bus. Per-instance signing keys (with `key_id` and a key set on the
plugin) give attribution and independent rotation. The same transaction reaching two instances
(client retry across the LB) yields two approvals for one hash; the store keeps the newer —
harmless at execution, only the audit attribution can flip.

**b) The sequencer, optionally a standby.** Approvals must reach every node that may build the
next block. With a channel per consumer and redelivery on a boot-id change, a standby is one more channel;
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
   gRPC no-regression run with an uncapped sample, and the §3.4′ bench re-run in the decided
   unary shape (one call per batch) before its latency is quoted.
2a. **Cheap, safe fixes that need no transport decision**: ~~backoff with jitter; drain on close;
   configurable hop cap~~ (`0ee3167`); **cheap overflow path** in `ApprovalStore` — event-driven
   liveness from the pool's `TransactionAdded`/`Dropped` listeners, insertion order, a grace period
   for approvals whose transaction may still be on its way, no pool scan and no sort on overflow
   (a cached pool *query* was tried first and rejected by its own test: a stale view can evict a
   live approval); `FORK` blocks recorded in the tracker; tracked depth given a basis (`8186d3d`);
   the reorg-with-lagging-finality scenario `reorg_keeps_approvals` (passes; full suite pending).
3. **Transport + durability**: `.proto` **including envelope v2** (`key_id`, `issued_at`,
   `expires_at` — one wire migration, not two); gRPC unary per batch (plaintext; mTLS later, §0.3) at Besu's grpc
   version; OPS dials the sequencer; status-code handling and boot-id redelivery (§3.6); Postgres
   outbox (expand-only, with the `privacy_proxy_app` GRANT block); certificate lifecycle.
4. **Keys**: ~~key set on the plugin~~ (done, envelope v2); Secrets Manager via IRSA scoped to the
   one secret ARN (deployment); rotation procedure documented in the plugin README; per-instance
   keys are now one `OPS_APPROVAL_KEY_ID` per instance plus one entry in the plugin's key set.
5. **Lifecycle**: ~~release on finality~~ (done, `c5b626c`); expiry honoured by the selector;
   global rate limit on preflight; `ops_prepareApproval` behind network policy or Besu RPC auth
   (documented, `16010c9`; enforcement is deployment).
6. **Observability** — a prerequisite for putting 3 on Lineth, not a follow-up: connected
   gauges both sides; delivery lag; race rate; 503 rate; decision counts; alerts; readiness
   reflects delivery. The per-transaction `OPS_APPROVAL_DECISION`/`TIMING` INFO lines are a new
   log source on the sequencer (two lines per allowed transaction) — make them sampled or
   metric-only, and treat retention/shipping as a logging-control change.
7. **Packaging and CI** — also earlier than it looks, since it is what lets 3–6 survive a Besu
   bump: plugin build and release from this repository under its own tag (decision 0.4); per-Besu-version scenario lane, nightly; grpc
   and Netty versions pinned to Besu's; compatibility note per Lineth Besu bump.
7r. **Reth parity** (decision 0.5): commit the Reth PoC into this branch; finish envelope v2 with
   the key set; the gRPC delivery service on the Reth side with the same status codes and boot
   id; the scenario suite on Reth; a CI lane; and a Reth performance run on the production path
   with the same workloads as Besu, so the numbers can be compared and quoted.
8. **Scope extensions**: 2930/4844; 7702 with the envelope extension; preflight replica
   (decision 0.6) if the sequencer load says so.

## 6. Compliance notes

- The seed file on disk deviates from Secrets Manager as canonical store — resolved in phase 4;
  document the interim.
- **TLS on the approval channel is postponed (§0.3): record it as a risk acceptance** (ISO/IEC
  27001:2022 Annex A 8.24, use of cryptography — Compliance to confirm how it is recorded), with
  the network rule restricting the plugin's port to OPS as the compensating control. When mTLS
  lands: CA, issuance, rotation and where private keys live (Secrets Manager via CSI/IRSA) are
  part of the design, not deployment detail; IRSA roles scoped to the specific secret ARNs.
- Phases 3–4 change access control (key rotation; mTLS identities once TLS lands) and 6 adds detective
  signals and a new log source on the sequencer (A.8.15 logging) — change-management
  documentation for ISO 27001 / Vanta.
- The Postgres outbox is a new table: expand-only migration with the `privacy_proxy_app` GRANT
  block, per repository policy.
- Installing the plugin on the sequencer is a change to the Lineth operator's component and goes
  through their change process, not only ours.
- Evidence logs under `poc/…/evidence/` embed local paths; scrub before the repository is public.
- Nothing here disables an existing control.
