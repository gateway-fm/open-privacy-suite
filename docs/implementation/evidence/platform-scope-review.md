# Platform authority scope regression

Independent review found that `configuration_platform_admin` bypassed tenant
scoping on both organization and platform configuration routes. The viewer also
reported activation authority from the platform allowlist without checking the
requested scope, and the activation callback accepted that shortcut.

`TestConfigurationPlatformAllowlistDoesNotGrantTenantAuthority` first reproduced
an allowlisted administrator reading an unrelated tenant's configuration with
HTTP 200 and `canActivate: true` (expected HTTP 403; red run 3.644s).

The shortcut now requires a verified human principal on the exact platform
configuration routes. Organization routes require their own current tenant
roles; activation additionally checks current approver eligibility. Platform
eligibility remains an additional requirement for protected group changes and
their authors. It never substitutes for tenant authority. A read-only tenant
administrator on the platform allowlist cannot approve that tenant's documents.

```text
go test -race ./internal/server -run '^TestConfiguration(Platform|Context|API|CI)' -count=1
ok privacy-proxy/internal/server 6.118s
```

The regression covers unrelated context/list reads, legitimate platform context,
read-only tenant viewer eligibility and the transaction-level activation
callback. Existing platform, tenant and signed CI workflow tests pass. Parent
independent review confirmed the scope checks and regression coverage with no
new finding.
