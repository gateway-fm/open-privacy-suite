# Operating signed approvals

## Enable and verify

Install only the artifact for the exact upstream version in [compatibility.json](compatibility.json).
For Besu, stop the producer, remove the previous OPS approval JAR from `plugins/`, install the
new one and restart. Keep one OPS approval JAR: two versions can load incompatible classes.
For Reth, replace the executable with the bundled `ops-reth-approvals`; retain the upstream
node's normal arguments and supported datadir upgrade/rollback procedure.

Deliver a randomly generated 32-byte Ed25519 seed as a hex file from the deployment's secret
manager, readable only by the OPS service account. Do not reuse fixture seeds. Keep the public
key and key id in the producers' trusted key sets. Do not put seeds in source, images, logs or
command-line arguments. The seed is read at startup; changing the mounted file requires an OPS
restart. One signing identity should identify one controlled deployment, not an end user.

OPS settings (add to its existing configuration):

```sh
OPS_APPROVAL_NODE=besu                 # or reth
OPS_APPROVAL_TARGETS=producer-a:50051,producer-b:50051
OPS_APPROVAL_SEED_FILE=/run/secrets/ops-approval-seed
OPS_APPROVAL_KEY_ID=ops-2026-09
OPS_APPROVAL_TTL=10m
OPS_APPROVAL_RETAIN_MAX=100000
```

Set each Besu producer's `--plugin-ops-approval-listen=address:port`,
`--plugin-ops-approval-public-keys=id=hex`, `--plugin-ops-approval-chain-id` and
`--plugin-ops-approval-allowed-sources` as described in the [wire settings](../docs/implementation/approvals-wire-contract.md#7-settings).
For Reth set `OPS_APPROVALS=1`, `OPS_APPROVAL_LISTEN=address:port`,
`OPS_APPROVAL_PUBLIC_KEYS=id=hex`, `OPS_APPROVAL_CHAIN_ID` and `OPS_APPROVAL_ALLOWED_SOURCES`.
The chain id must match the node. Reth rejects an invalid enable flag; absent/`0` intentionally
disables its gate for ordinary-node operation, so deployment templates must explicitly require `1`.

Before admitting traffic, verify every producer's activation log, chain/key compatibility and
OPS `privacyproxy_approval_target_connected{target=...}=1`. On a disposable canary, submit an
unapproved transaction directly: it must never enter a block. Then submit through OPS and verify
a successful receipt. A successful delivery acknowledgement alone is not proof of enforcement.

## Network and API boundary

Keep delivery gRPC, node JSON-RPC, metrics and Engine API on private interfaces. Network policy
must admit the delivery port only from OPS and Engine API only from the authorized consensus
client (with Engine JWT authentication). Set an explicit narrow source CIDR list on the receiver;
`any` is only appropriate behind an independently enforced network rule. Restrict Besu's
`ops_prepareApproval` and Reth's `debug_traceCall` to OPS using node RPC authentication and/or
network policy. They expose execution facts and spend node CPU. Never publish the node RPC
directly beside the OPS endpoint. OPS blocks the whole private `ops_` namespace even for wildcard
method grants; its internal preflight uses the private node connection.

Delivery remains plaintext by the agreed design. Signatures prevent forged approvals; they do
not authenticate status responses or prevent observation, replay, suppression or denial of
service by an attacker on that network. The RPC simulation response is also trusted input from
the configured node. Crossing an untrusted network needs an authenticated encrypted tunnel or
transport work before deployment. Source CIDRs are a supplement to that boundary, not peer identity.

OPS preflight is limited per principal (Redis across instances, bounded local fallback during a
Redis outage). Choose budgets for expected identities and keep global HTTP/concurrency limits.
The local fallback budget applies per OPS process, so total allowance can increase during an
outage. Do not copy the load fixture's effectively unlimited principal budget into production.
Delivery has message, connection and stream limits. Besu additionally bounds its verification
queue to 128 batches and answers `UNAVAILABLE` when busy; OPS retries with backoff. Reth uses a
bounded verification queue and deadline-bounded waiting. These are resource controls, not a
substitute for restricting who can reach the listener.

## Capacity, cleanup and performance

OPS and producers keep approvals in bounded RAM. OPS removes expired entries and evicts old
ones at its capacity cap; a producer removes expired/finalized approvals and applies its bounded
overflow policy. No cleanup job or approval database is required. Acknowledged approvals remain
in OPS memory for recovery until expiry or eviction. Acknowledgement counts include duplicates.

At 5,000 approvals/second, 100,000 entries represent approximately 20 seconds of issuance history,
even with a ten-minute TTL. The measured OPS live retention cost at batch size one is about
65 MiB per 100,000 entries; reserve process/GC headroom separately. Size producer capacity for
all OPS instances and fresh traffic during replay. Use observed issuance rates, which include
retries, rather than committed TPS. Full caches can evict old approvals while replay catches up.
See [measured limits of recovery](../poc/approval-performance/README.md).

Signing/delivery does not wait for disk or batch fill. Increasing verification workers competes
with execution for CPU; defaults remain two, with four tested as a Besu tuning option. The local
M2 Max throughput numbers are development comparisons, not solution limits or a production SLA.

## Health, alerts and logs

`/health` is process liveness. Keep it suitable for restarting dead processes; producer loss
must not create an OPS restart loop that also discards recovery copies. Read operations may stay
available while submission is degraded. OPS rejects new raw submissions with 503 before simulation
when no compatible producer is ready. With multiple targets, at least one compatible connected
producer admits submissions; a disconnected standby is still an operational alert.

Scrape OPS `/metrics`, Besu's metrics endpoint with category `ops_approval`, and Reth's private
`--metrics address:port` endpoint. Reth exports approval store/counter metrics once per second,
independent of block activity. [alerts.yml](alerts.yml) supplies starting rules for disconnection,
loss of unconfirmed approvals, retention eviction, retries and receiver overload. Add a normal
Prometheus target-missing alert: a missing series is not a healthy zero. Route alerts to the
existing operations system and set thresholds against measured delivery latency and the wait
window; alerts do not define an automatic retry or failover policy.

Keep deny/drop decision records in the existing access-controlled log pipeline, with rotation,
volume limits and an explicit retention period. They carry transaction hashes/fingerprints;
do not expose them through public APIs. Successful/waiting per-transaction and timing diagnostics
are off by default; `OPS_APPROVAL_DIAGNOSTICS=1` enables them for bounded investigations and
fixtures. Keep hop tracing/profiling off normally. Monitor log shipping and free disk space;
failure counters remain useful without enabling high-volume success logs.

## Restart, retry and shutdown

1. A node restart changes its boot id. A surviving OPS process automatically replays its retained,
   unexpired batches. Monitor redeliveries, connection readiness and actual receipts. OPS does
   not resubmit transaction bytes; pool restoration differs by node and failure mode.
2. An OPS restart loses its queue and recovery copies. A live producer can still use approvals
   already confirmed in its memory. Restart OPS instances individually, keeping producers live.
3. If OPS restarts and the producer later restarts, both copies may be gone. This also applies
   after expiry/eviction. Restarts need not be simultaneous. Recovery then requires the client.
4. The client checks its transaction receipt and canonical inclusion/finality, then its pending
   status and sender nonce. If still absent/unconfirmed, retry the **same signed bytes through
   OPS** with backoff and a bounded retry deadline. This triggers fresh current-policy preflight;
   it can now be denied. Do not automatically create a new nonce/value transfer merely because
   an old receipt is missing. A returned hash is not a commitment to inclusion.
5. For planned OPS shutdown, stop incoming HTTP traffic and let requests finish (up to 10 seconds
   in the server), then drain signing/delivery (bounded, default two seconds). Give the process
   termination grace additional room for audit/service cleanup. A timed-out drain or SIGKILL can
   lose the newest approvals. Never promise that graceful shutdown guarantees delivery to a
   failed producer. Exercise these steps with the actual load balancer and termination settings.

Reorgs can also remove a transaction from canonical history. Retained approvals can remain usable,
but clients still need receipt monitoring and transaction resubmission if the node loses it.
Durable approvals and automatic transaction reconciliation are deliberately deferred.

## Key rotation and upgrades

Add the new public key/id to **all** producers, roll them one at a time, and verify Status reports
both ids. Switch OPS seed/key id and roll OPS instances. Confirm new deliveries, then retain the
old public key through the old approvals' expiry and the operational recovery window before
removing it. This order permits in-memory replay across a producer restart; removing an old key
too early makes that replay fail. Existing stored approvals are not a revocation mechanism.

For a compromised signing key, stop new issuance, isolate affected producers, remove trust and
restart them to clear in-memory approvals. Reassess pending transactions under current policy
before reopening. For rollback, stop submissions, restore the previous **compatible** node/plugin
pair and keys, and verify gate activation. Disabling the plugin/gate is not a safe rollback of an
enforcement deployment. Datadir compatibility follows the upstream client's rules.

Release qualification includes the exact node version/fork, network rules and denied-source
checks, secret distribution/rotation, clock synchronization, target-hardware overload and recovery
tests, receipt retry behavior and alert routing. These deployment facts cannot be certified by a
workstation test. Record them with the deployed artifact checksums and change record.
