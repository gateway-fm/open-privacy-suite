import { test, expect } from '@playwright/test';
import { selectors } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../helpers/rbac-fixtures';

// ---------------------------------------------------------------------------
// RD-1069 — visibleTo unlock caption (v0.12.0 acceptance §3E).
//
// Acceptance "Expect": RBAC → Contracts → Grants → enable the per-contract
// visibleTo unlock → the enabled-state caption must say the unlock reaches
// only listed users with an eligible contract grant or org-admin membership in
// this org (cross-org / anonymous stay denied) — it must NOT claim the sender
// can reveal to "any DID" they list.
//
// The exact copy asserted here mirrors the vitest guard in
// frontend/src/components/rbac/__tests__/ContractGrantsManager.test.tsx
// ("eligible contract grant or org-admin membership in this org" present;
// "with any DID they list" absent), lifted to the full browser stack.
//
// Flow to reach the caption (matches ContractGrantsManager.tsx):
//   contracts tab → shield ("Manage permissions") → "Contract Permissions"
//   dialog → toggle the "Allow visibleTo to unlock event visibility" switch →
//   confirm "Enable visibleTo unlock?" → caption renders.
// ---------------------------------------------------------------------------

test.describe('visibleTo unlock caption (RD-1069)', () => {
  let fixture: RBACTestFixture;

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('enabled caption gates on existing contract group access, not "any DID"', async ({ page, request }) => {
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await mockLoginViaAPI(page, currentDid);

    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrgWithAdmin('vt-cap', currentDid);
    await fixture.createContract(org.id, { name: 'VisibleTo Token' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Scope to our org so the contract table shows exactly our seeded contract.
    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Open the contract permissions dialog via the shield button on the row.
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(1, { timeout: 10000 });
    await rows.first().getByTitle('Manage permissions').click();

    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible({ timeout: 5000 });
    await expect(permDialog.getByText('Contract Permissions')).toBeVisible();

    // Toggle the visibleTo unlock switch — this opens a confirm modal first
    // (the PUT is not sent until "Enable" is clicked).
    const unlockSwitch = permDialog.getByRole('switch', {
      name: /allow visibleto to unlock event visibility/i,
    });
    await expect(unlockSwitch).not.toBeChecked();
    await unlockSwitch.click();

    // Confirm dialog "Enable visibleTo unlock?" → click "Enable".
    await expect(page.getByText(/Enable visibleTo unlock\?/i)).toBeVisible({ timeout: 5000 });
    await page.getByRole('button', { name: /^enable$/i }).click();

    // Enabled-state caption must gate on an eligible grant or org-admin
    // membership in this org and must NOT promise reveal-to-any-DID.
    await expect(
      page.getByText(/eligible contract grant or org-admin membership in this org/i),
    ).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/with any DID they list/i)).toHaveCount(0);
  });
});
