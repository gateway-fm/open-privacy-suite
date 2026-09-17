# Deployment and legacy migration — A5

Final private ABI (undeployed A3/A4 artifacts must be recompiled):

```text
check((address,address[],bytes32[],bytes32,bytes32,bytes32,bytes32,uint8,bool,bool,uint8,bytes32,uint8[],bool,bool),(uint8,address,address,address,bytes,uint256,uint256)) returns(uint256)
selector: 0x9f0a7e8f
```

The final two facts are `storageDeployer` and `storagePending`. Deployer means
the current named principal, not another principal sharing its signer. Pending
means a same-organization preregistered target without completed deployment.
Actual same-organization CREATE overlays override stale deployer/pending
metadata until transaction completion; registered ownership still wins namespace
resolution. Rust owns overlay rollback and live fact derivation. No legacy
read-grant or function-permission verdict is passed as a policy fact.

`targetClass: deployer` with `selector: "*"` covers the principal's current and
future deployed contracts. `targetClass: pending` also requires the matching
binding's current deploy/admin claim. Both require equal code/storage addresses
owned by the policy organization and permit CALL/STATICCALL only. Neither
implicitly grants upgrade or delegate execution. All linked addresses remain
available to argument and record-party rules.

The old resolver suppresses individual-deployer fallback where the principal
belongs to a group with an explicit target grant, including an explicit empty
function list. Import records that exact suppression in a deployer rule's
`except: [{storageAddress, groups}]`. Current membership facts apply the reviewed
exception; ordinary literal rules still union normally. Changing membership
therefore preserves null/empty/restricted precedence without consulting mutable
legacy execution grants. Exception targets and groups are sorted, unique,
same-organization and bounded at 64 each; unsupported input fails the whole
import. Newly deployed targets do not require a per-address compiler update.

Ordinary proxy relations require explicit reviewed `spec.proxyPairs` entries
with `storageAddress` and `codeAddress`. Each implementation literal rule is
expanded to a DELEGATECALL pair retaining its selector, argument predicates and
bounds. Missing implementation rules fail with an actionable typed diagnostic.
Unknown proxy relationships cannot safely be inferred from ABI or ownership;
context reports that review requirement. CALLCODE requires explicit DSL source.

An older POC policy was a restriction over RBAC, not the effective union. Context
provides the imported RBAC baseline plus separate old source/artifact/digest
evidence. Replacement submission and activation require the reviewed exact
`legacyRestrictionDigest`; four-eyes/CI approval still applies. The diff records
the acknowledgement evidence. This permits deliberate migration without claiming
automatic equivalence to an unknown intersection.

## Red and green

The deployer import regression first failed on two unsupported deployment
records (0.609s); conversion then passed (2.733s). The explicit proxy regression
first denied the delegate frame with no matching rule (1.035s); the focused
deployment/import selection then passed (5.308s). Tests compare reference and
real compiled EVM decisions for null/empty/restricted grants, overlapping groups,
membership removal, shared-signer separation, pending claims, new deployments,
foreign owners, upgrade/delegate denial and proxy argument preservation.

```text
go test -race ./internal/policydsl -count=1
ok privacy-proxy/internal/policydsl 25.334s

go test -race ./internal/db -run '^TestConfigurationExecution' -count=1
ok privacy-proxy/internal/db 25.756s
```

The complete lifecycle and record-party cross-language fixtures were regenerated
with the new selector and deterministic solc 0.8.35 artifacts (1.779s). The node
consumes these exact fixtures. A final context regression failed because proxy
review requirements were absent (5.025s), before adding the explicit diagnostic.
The complete database race selection then passed again (34.382s).

This evidence covers the compiler and real database lifecycle. Actual Reth
deployment/factory/preregistration behavior is exercised by the node and OPS
stack integration suites separately.
