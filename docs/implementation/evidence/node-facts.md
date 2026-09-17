# Signed facts and execution identity evidence

Implemented in `internal/nodepolicy`, migration 073 and `internal/db/node_policy_export*`.

TDD red evidence included absent protocol APIs; case-insensitive JSON fields accepted; omitted required zero fields accepted; simulation identity collisions; selected organisation without membership; and exporter target claims incorrectly sourced from the dormant `contract_grants.claims` column. Each has a regression and corrected implementation.

PostgreSQL tests exercise rollback, multiple mutations sharing one version, concurrent commit-order serialization, signer-link dirty markers, coherent repeatable-read export, scoped sanctions, bans, omitted private notes, current group claims and their revocation. Outbox + exporter passed together in 11.591 s. The subsequent claim-source regression failed with upgrade mask 4 instead of deploy mask 2, then both exporter tests passed in 5.326 s.

Signed stream tests cover exact payload signatures/domain separation, duplicate/unknown/case/missing/null fields, network/time limits, shared signers with separate principals, simulation context isolation, revocation, immutable pinning, atomic coalesced deltas, gaps/conflicts, duplicate retry, malformed final graphs, heartbeat lease separation and full resynchronisation. The complete protocol suite passed after the feed addition in 0.434 s.

Go-created identity, snapshot, delta, heartbeat and simulation vectors are frozen in `internal/nodepolicy/testdata/envelopes-v1.json` for Rust conformance. The Go feed is a reference receiver; production execution remains the Reth adapter. These package tests do not claim a complete stack or live transaction enforcement.
