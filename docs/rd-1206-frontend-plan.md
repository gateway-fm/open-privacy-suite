# RD-1206 — Frontend (admin dashboard) plan

The admin UI must let an operator **see** a contract's method access policy in
plain language and **build/edit** one with a wizard that compiles to the policy
JSON the backend validates. Lives in the React admin dashboard (`frontend/`),
alongside the existing per-contract controls in `ContractGrantsManager`.

## Pieces

1. **Types** (`frontend/src/types/rbac.ts`): add `method_policies?` to `Contract`;
   add `MethodPolicyDocument` mirroring the Go model (records → capture[] /
   access[], KeySpec, RememberField, AllowRule with `callerIn` = string[] or
   `{source:"return",paths,kind}`).
2. **API client** (`frontend/src/api/rbac.ts`): `getMethodPolicies(org, addr)`
   and `updateMethodPolicies(org, addr, doc|null)` → the `.../method-policies`
   endpoints.
3. **Display** (`MethodPoliciesPanel`): for each record type, render "Reader
   `getPaymentInfo(string)` is readable by: payer, payee, audience (captured
   from …), or an address the call returns (payer, payee)." Empty state makes
   the default explicit: "No method policies — getters are gated by the contract
   grant only (any group member may read any record)."
4. **Wizard** (`MethodPolicyWizard`, a `dialog`): steps —
   (1) record type name + the **reader** method + its key parameter;
   (2) the **writer** method + its key parameter + remember rules (field → source
   `sender`/`param(i)`/`visibleTo`, merge `set_once`/`union`);
   (3) allow rules for the reader (checkbox the captured field names, and/or
   pick address return paths);
   (4) review the compiled JSON + Save.
   Functions/params/outputs come from parsing `contract.abi` with **viem**
   (`parseAbi`/`Abi`), so the pickers only offer real methods and only
   address-typed outputs as return paths.
5. **Super-admin surfacing**: the PUT is super-admin only. The panel shows the
   wizard/save only when the session is super-admin; otherwise it renders
   read-only with a note. (Mirrors how the dashboard gates other super-admin
   controls.) The backend enforces regardless — the UI just avoids a dead 403.
6. **Tests**: RTL/vitest unit tests (wizard compiles the exact JSON for the
   Partior case; key-param/return-path pickers restrict to valid choices;
   empty/clear path) + a Playwright e2e (open a contract, run the wizard, save,
   see the policy rendered).

## Guardrails

- The wizard is a convenience; **the backend is the source of truth** — it
  re-validates against the ABI and rejects bad policies. The UI must surface the
  backend's 400 validation message verbatim on save, never silently assume its
  own client-side check is sufficient.
- No secrets or raw errors in the UI; show the backend's opaque messages.
- Keep the compiled JSON exactly matching the Go schema (record types, sources,
  merges, callerIn shapes) so a UI-built policy validates first try.
