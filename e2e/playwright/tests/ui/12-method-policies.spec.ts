import { test, expect } from '@playwright/test';
import { selectors } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../helpers/rbac-fixtures';

// RD-1206: the Method Access Policies panel lives inside the Contract
// Permissions dialog (rendered by ContractGrantsManager). This spec verifies it
// renders in a real browser and that the C1 gating holds: a tier-2 org-admin
// (JWT) session — which the backend rejects for the super-admin-only PUT — sees
// the panel read-only with the explanatory note, and no wizard affordance. The
// full wizard-compile-and-save path is covered by the RTL component test
// (MethodPolicyManager.test.tsx) and the backend e2e (method_policy_e2e_test.go).

const PAYMENT_ABI = JSON.stringify([
  {
    type: 'function',
    name: 'createPayment',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'paymentIdentifier', type: 'string' },
      { name: 'payee', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'getPaymentInfo',
    stateMutability: 'view',
    inputs: [{ name: 'paymentIdentifier', type: 'string' }],
    outputs: [
      { name: 'amount', type: 'uint256' },
      { name: 'payer', type: 'address' },
      { name: 'payee', type: 'address' },
    ],
  },
]);

test.describe('Method access policies panel', () => {
  let fixture: RBACTestFixture;

  test.afterEach(async () => {
    if (fixture) await fixture.cleanup();
  });

  test('renders the panel with the empty-state default and the getter-only caveat', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const did = `did:privado:test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await mockLoginViaAPI(page, did);
    const org = await fixture.createOrgWithAdmin('mp-ui', did);
    await fixture.createGroup(org.id, 'grp-mp', { name: 'Group MP' });
    await fixture.createContractWithABI(org.id, { name: 'PaymentRegistry', abi: PAYMENT_ABI });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });
    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Open the Contract Permissions dialog (shield on the first contract row).
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(1, { timeout: 10000 });
    await rows.first().getByTitle('Manage permissions').click();

    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible({ timeout: 5000 });

    // The method-policy panel renders with its heading + empty-state default.
    await expect(permDialog.getByText('Method access policies')).toBeVisible();
    await expect(permDialog.getByText(/No method policies configured/i)).toBeVisible();
    // The getter-only surface-asymmetry caveat must be present (false-confidence guard).
    await expect(permDialog.getByText(/gates the/i)).toBeVisible();

    // C1: a JWT (tier-2) session cannot save — no configure affordance, and the
    // read-only note is shown instead. (The backend enforces regardless.)
    await expect(permDialog.getByRole('button', { name: /configure a policy/i })).toHaveCount(0);
    await expect(permDialog.getByText(/requires the super-admin API token/i)).toBeVisible();
  });
});
