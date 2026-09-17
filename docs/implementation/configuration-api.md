# Configuration revision API

Organization stream base URL: `/api/v1/admin/orgs/{org_id}/configuration/{kind}`.
The legacy `/api/admin` mount exposes the same routes. Organization streams are
`groups`, `contract-registry`, `compliance`, `approvers`, `execution-rules`.
Platform has the same lifecycle under `/api/v1/admin/configuration/platform`.

`GET /context` returns editable **object** `source`, `active` revision or null,
the relevant live snapshot (`groups` or `registry`), and `legacyExecution: []`.
Submit the complete source object with `POST /revisions`. The revision response
stores `source` as a **string**, preserving the submitted document for review.
All public field names below are camelCase. Arrays in source must be explicit
`[]`, never missing or null. Source rejects unknown/case-aliased/duplicate keys.

Example initial groups context (UUIDs illustrative):

```json
{
  "active": null,
  "source": {
    "apiVersion": "ops.configuration/v1",
    "kind": "groups",
    "scope": {"kind": "organization", "id": "11111111-1111-1111-1111-111111111111"},
    "baseRevision": 0,
    "dependencies": {},
    "deletions": [],
    "spec": {"groups": [{
      "id": "22222222-2222-2222-2222-222222222222",
      "slug": "operators", "name": "Operators", "description": "",
      "isOrgAdmin": false, "isOrgReadonlyAdmin": false,
      "allowedMethods": ["eth_call"], "claims": [], "verboseErrors": false
    }]}
  },
  "groups": {
    "scope": {"kind": "organization", "id": "11111111-1111-1111-1111-111111111111"},
    "activeRevision": 0,
    "groups": [{
      "group": {
        "id": "22222222-2222-2222-2222-222222222222",
        "slug": "operators", "name": "Operators", "description": "",
        "isOrgAdmin": false, "isOrgReadonlyAdmin": false,
        "allowedMethods": ["eth_call"], "claims": [], "verboseErrors": false
      },
      "managed": false, "protected": false, "liveMemberships": 0, "activeMembers": 0
    }]
  },
  "legacyExecution": []
}
```

Every context also carries `capabilities`, so a headless client can discover
the API before drafting instead of probing endpoints:

```json
{
  "capabilities": {
    "apiVersion": "ops.configuration/v1",
    "kinds": ["groups", "contract-registry", "compliance", "approvers", "execution-rules"],
    "humanOnlyKinds": ["approvers", "platform"],
    "approvalModes": ["human", "trusted-ci"],
    "maxDocumentBytes": 1048576,
    "compiler": {"version": "0.8.35", "available": true}
  }
}
```

`kinds` are the organization streams; `platform` is a separate scope (below).
`humanOnlyKinds` may only be drafted and approved by human principals.
`compiler` names the pinned Solidity version execution-rules artifacts are
built with and whether that exact compiler is usable in this process right now
(one probe is shared by all context reads for 30 seconds; the ARM backend image
ships without the compiler, so expect `false` there until it is installed).
`available: false` means an execution-rules submission will be refused until the
operator installs the pinned compiler; other streams are unaffected. The block
describes the API, not the caller's authority — that is `viewer`.

`GET /revisions` returns `{ "revisions": [...] }`; `GET /revisions/{id}`
returns one revision. Revision fields are `id, scope, kind, revision,
baseRevision, source, digest, dependencies, status, createdBy, createdAt,
activatedBy, activatedAt, createdPrincipalKind`. Nullable activation fields remain null on drafts.
`revision` is a monotonic draft number; `baseRevision` must be the currently
active revision number, not the newest draft number.

`POST /revisions/{id}/simulate` accepts `{ "coactivate": [] }` (or no body).
It returns `{revisions,groups,registry,groupDiff,registryDiff,legacyExecution}`.
`groups`/`registry` are the current snapshots, not the proposed result.
An absent stream diff is null. A group diff has:

```json
{
  "changes": [{
    "action": "adopt",
    "id": "22222222-2222-2222-2222-222222222222",
    "before": {"...": "complete existing group"},
    "after": {"...": "complete proposed group"},
    "liveMemberships": 0,
    "requiresPlatform": false
  }],
  "preservedDrift": [],
  "projection": [{"...": "complete proposed groups, including preserved drift"}]
}
```

The ellipses above explain object content; they are not valid source fields.
Change actions are `adopt`, `create`, `update`, `delete`. A new group's `before`
is null; a deleted group's `after` is null. Registry changes are
`{action,resource,id}` with resource `contract` or `grant`. Registry projection
is complete contracts including their `readGrants`.

Registry source `spec` is `{contracts:[]}`. Contract fields are
`id,address,name,abi,allowVisibleToUnlock,eventsAllowDynamicPayload,readGrants`.
`abi` is a JSON array. A read grant is
`{id,groupId,legacyClaims:[],eventRules:{mode:"none",rules:[]}}`.
Modes are `none`, `all`, `allowlist`; allowlist rules contain
`{topic0,name,paramRules:[{index:0,must_be:"self"}]}`. Legacy claims are retained
metadata and cannot be edited; new grants require an empty list. Effective
claims come from group access. Registry never edits execution functions;
`legacyExecution` preserves null (wildcard) versus [] (deny all) for import.

`POST /revisions/{id}/activate` takes the same sibling-ID body and atomically
returns `{revisions:[...]}`. Sibling dependency digests bind either an active
stream or a sibling candidate in that activation. A named independent human
with current full authority approves; the original author's current authority
is checked again in the same transaction. Readonly humans and service
principals may draft/review. Missing principal kind requires a fresh login for
approval. Changes to full-admin groups additionally require the deployment
platform allowlist; an org administrator cannot promote their own authority.
`POST /revisions/{id}/withdraw` changes a draft to withdrawn.

Managed resource omission is not deletion: include its UUID in `deletions`.
Group deletion with live members requires the exact current count in
`{id,liveMemberships}`. Unmanaged drift is retained until explicitly adopted.
Once activated, legacy desired-state writer routes return 409 — including the
earlier `/execution-policy/revisions` submit/activate/withdraw routes once the
`execution-rules` stream is active; database guards also reject stale or direct
writers. That 409 guard authorizes first: on the
registry and compliance streams the operator token is rejected before the
managed-stream lookup, and on the platform stream anything but the super-admin
token is, exactly as the handlers behind it would reject them, so a forbidden
credential never learns whether a tenant's stream is managed. The groups
stream is the exception: the operator token may manage org-admin and system
groups, which the handler decides per group after loading it, so there the
handler's gate stays the only one. Operational memberships and onboarding
remain available. Deployment reconciliation has an internal scoped INSERT
exception; ordinary callers cannot request this exception.

Additional typed sources:

- `compliance.spec`: `settings:{enabled,thresholdFiat,currency,unknownPricePolicy,enforcementMode}`,
  `addressThresholds:[{id,address,thresholdFiat,note}]`,
  `tokenPrices:[{id,tokenAddress,symbol,decimals,pricesByCurrency,coingeckoId}]`.
  Currency is `usd|eur|chf|gbp|aed`, unknown-price policy `allowed|forbidden`,
  enforcement `enforce|monitor`. `coingeckoId` is an explicit string (empty for
  authored manual prices). Fetched rates, sanctions and travel-rule records
  remain operational. Context has `compliance:{scope,activeRevision,spec,managedIds}`;
  review has `complianceDiff:{changes,preservedDrift,projection}`.
- `approvers.spec`: `groupIds:[]`, `trustedCI:[]`. Eligible groups must already
  be full-admin groups in the scope and retain a live member. Each trusted CI
  entry contains `id,issuer,audience,subject,repository,ref,publicKey`; bindings
  match exactly, and `publicKey` is standard base64 Ed25519 public key bytes.
  Trust removal names the old trust UUID in `deletions`. Eligibility for the
  current approval uses the previously active policy, never its replacement.
  Context/review return `approvers`; proposed review policy is `approversDiff`.
- `platform.spec`: `sharedInfrastructure:[{id,address,name,description,codehash}]`,
  `tenants:[{id,tenantId,label,defaultOrgId,defaultGroupId,autoProvision}]`.
  Shared codehash is a required lowercase 32-byte hex pin. Optional tenant
  placement uses empty strings; a default group must belong to its default
  organization. Scope is `{kind:"platform"}`, dependencies is `{}`.
  Context has `platform:{activeRevision,spec,managedIds}`; review has
  `platformDiff:{changes,preservedDrift,projection}`. Legacy shared addresses
  receive deterministic UUIDs in exports; preserve those IDs when adopting.
- `execution-rules.spec`: `policy` is the existing closed DSL policy object.
  A revision's optional `artifact` is generated by the server. Review has an
  `executionDiff` with before/after policy, binding changes and compiled digests.

Every context also contains `viewer:{principalId,principalKind,canActivate}`.
This is a display hint; the server rechecks current authority at activation.
Compare `viewer.principalId` with revision `createdBy` to disable self-approval.

Platform setup uses deployment environment `PLATFORM_ADMIN_SUBJECTS`, a
comma-separated exact allowlist of authenticated external subject IDs. These
subjects still require normal JWT verification, revocation and ban checks.
Configure at least two human subjects and have them sign in again to obtain
signed `principal_kind=human` tokens. Only configuration routes gain this
platform authority; the deployment allowlist is never source-authorable.
Platform drafts themselves require a human login, and activation requires a
different currently allowlisted human. Full-admin group changes require
platform authority of both the group revision author and activator.

CI activation uses the separate organization endpoint
`POST /revisions/{id}/activate-ci` with strict body
`{coactivate:[],approval:{...}}`. It requires a signed service-principal JWT
whose current organization role is full admin. The independently operated
approval service signs `ops.configuration-approval/v1` evidence containing:

```json
{
  "version": "ops.configuration-approval/v1",
  "trustId": "22222222-2222-2222-2222-222222222222",
  "issuer": "customer-review-service", "audience": "privacy-proxy",
  "subject": "the-exact-service-principal-subject",
  "repository": "customer/ops", "ref": "refs/heads/main",
  "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "scope": {"kind":"organization","id":"11111111-1111-1111-1111-111111111111"},
  "candidateDigests": {"groups":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "reviewerSubjects": ["the-exact-independent-human-subject"],
  "issuedAt": 1700000000, "expiresAt": 1700000300,
  "nonce": "33333333-3333-3333-3333-333333333333",
  "signature": "base64-ed25519-signature"
}
```

The signing message is canonical JSON with `signature` removed: recursively
sorted object keys, integer timestamps, no insignificant whitespace. Use
`configuration.CIApproval.SigningBytes()` to produce its exact bytes. Maximum
validity is 15 minutes. The independent signer must obtain merged-PR approval
and bind the exact candidate digests, reviewed commit and reviewers itself.
The application verifies that trusted assertion; it does not independently
query Git or infer approval from an agent's claim. Keep the private signing key
outside the agent/service principal's credential set. Trust setup and rotation
require a verified human source author plus a different verified human activator;
the author kind is retained immutably. Services can propose these documents
externally for human submission, while ordinary scoped sources remain directly
service-draftable. CI cannot change approver trust or platform state.
Reviewers must remain unbanned current full-admin members of eligible groups
and be distinct from the candidate authors and CI caller. The signed evidence
is retained in the activation's existing RBAC audit chain.

Operational upstream credential rotation remains `PUT /api/v1/admin/orgs/{org_id}/groups/{group_id}/rpc-credential` with only `{"rpc_api_key":"new-secret"}`. Empty string clears it; the response is 204. This operation cannot create access rows or change methods/claims and retains existing group-tier authorization. Secrets are never source fields or audit values.
