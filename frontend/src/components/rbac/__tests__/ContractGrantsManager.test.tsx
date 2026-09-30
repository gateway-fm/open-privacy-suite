import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { toFunctionSelector } from 'viem';
import ContractGrantsManager from '../ContractGrantsManager';
import { TooltipProvider } from '@/components/ui/tooltip';
import { rbacApi } from '@/api/rbac';
import type { Contract, ContractGrant, Group, GroupAccess, GroupWithAccess, Claim } from '@/types/rbac';

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

const mockContract: Contract = {
  id: 'contract-1',
  org_id: 'org-1',
  address: '0x1111111111111111111111111111111111111111',
  name: 'Token Contract',
  deployed_by_user_id: null,
  deployed_at: null,
  metadata: {},
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

const mockGroups: Group[] = [
  {
    id: 'group-1',
    org_id: 'org-1',
    slug: 'auditors',
    name: 'Auditors',
    description: 'Audit group',
    depth: 1,
    path: 'root.auditors',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'group-2',
    org_id: 'org-1',
    slug: 'ops',
    name: 'Ops',
    description: 'Operations group',
    depth: 1,
    path: 'root.ops',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
];

const mockGroupAccess: GroupAccess = {
  id: 'access-1',
  group_id: 'group-1',
  allowed_methods: ['eth_call'],
  claims: [] as Claim[],
  rate_limit_rps: 100,
  rate_limit_daily: 10000,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/** Build an axios-like response wrapper used by vi.spyOn mocks. */
function axiosRes<T>(data: T) {
  return {
    data,
    status: 200,
    statusText: 'OK',
    headers: {},
    config: { headers: {} },
  };
}

function groupsResponse(groups: Group[] = mockGroups): GroupWithAccess[] {
  return groups.map(g => ({
    group: g,
    access: g.id === 'group-1' ? mockGroupAccess : null,
  }));
}

function stubApis(grants: ContractGrant[]) {
  vi.spyOn(rbacApi.contracts, 'listGrants').mockResolvedValue(
    axiosRes(grants) as Awaited<ReturnType<typeof rbacApi.contracts.listGrants>>
  );
  vi.spyOn(rbacApi.groups, 'list').mockResolvedValue(
    axiosRes({ data: groupsResponse(), total: mockGroups.length, limit: 50, offset: 0 }) as Awaited<
      ReturnType<typeof rbacApi.groups.list>
    >
  );
}

function renderManager(contract: Contract = mockContract) {
  return render(
    <TooltipProvider>
      <ContractGrantsManager orgId="org-1" contract={contract} />
    </TooltipProvider>
  );
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

describe('ContractGrantsManager — event rules display', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows "No events visible" when grant has null event_rules', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    expect(screen.getByText('No events visible')).toBeInTheDocument();
    expect(screen.queryByText('All events visible')).not.toBeInTheDocument();
  });

  it('shows "No events visible" when event_rules is an empty array', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    expect(screen.getByText('No events visible')).toBeInTheDocument();
    expect(screen.queryByText('All events visible')).not.toBeInTheDocument();
  });

  it('displays event rule names as violet pills', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [
        {
          topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          name: 'Transfer',
        },
        {
          topic0: '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
          name: 'Approval',
        },
      ],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    // Event names should be rendered
    expect(screen.getByText('Transfer')).toBeInTheDocument();
    expect(screen.getByText('Approval')).toBeInTheDocument();

    // "All events visible" should NOT be shown
    expect(screen.queryByText('All events visible')).not.toBeInTheDocument();

    // The pills should have violet styling (bg-violet-100)
    const transferPill = screen.getByText('Transfer').closest('span');
    expect(transferPill?.className).toContain('bg-violet-100');
    expect(transferPill?.className).toContain('text-violet-800');
  });

  it('displays param constraints on event rule pills', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [
        {
          topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          name: 'Transfer',
          param_rules: [{ index: 0, must_be: 'self' }],
        },
      ],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    // Event name
    expect(screen.getByText('Transfer')).toBeInTheDocument();

    // Param constraint annotation
    expect(screen.getByText('[param[0]=self]')).toBeInTheDocument();
  });

  it('displays multiple param constraints on a single event', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [
        {
          topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          name: 'Transfer',
          param_rules: [
            { index: 0, must_be: 'self' },
            { index: 1, must_be: 'self' },
          ],
        },
      ],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Transfer')).toBeInTheDocument();
    });

    // Should show both param constraints joined with OR
    expect(screen.getByText('[param[0]=self OR param[1]=self]')).toBeInTheDocument();
  });

  it('shows both function rules and event rules on the same grant', async () => {
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: [{ selector: '0x70a08231' }],
      event_rules: [
        {
          topic0: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          name: 'Transfer',
        },
      ],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    // Function rule displayed (the component resolves 0x70a08231 to "balanceOf")
    expect(screen.getByText('balanceOf')).toBeInTheDocument();

    // Event rule displayed
    expect(screen.getByText('Transfer')).toBeInTheDocument();

    // Neither "All functions" nor "All events" should appear
    expect(screen.queryByText('All functions allowed')).not.toBeInTheDocument();
    expect(screen.queryByText('All events visible')).not.toBeInTheDocument();
  });

  it('grant without event_rules field shows "No events visible"', async () => {
    // A grant where event_rules is undefined (field missing from API response)
    const legacyGrant = {
      id: 'grant-legacy',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    } as ContractGrant; // event_rules missing entirely
    stubApis([legacyGrant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });

    expect(screen.getByText('No events visible')).toBeInTheDocument();
    expect(screen.queryByText('All events visible')).not.toBeInTheDocument();
  });

  it('event rule pill has tooltip with topic0 hash', async () => {
    const topic0 = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
    const grant: ContractGrant = {
      id: 'grant-1',
      contract_id: 'contract-1',
      group_id: 'group-1',
      functions: null,
      event_rules: [{ topic0, name: 'Transfer' }],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };
    stubApis([grant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Transfer')).toBeInTheDocument();
    });

    // The pill has a title attribute like "Transfer — 0xddf252ad..."
    const pill = screen.getByTitle(`Transfer — ${topic0}`);
    expect(pill).toBeInTheDocument();
  });

  describe('visibleTo unlock toggle (RD-874)', () => {
    const visibleToUnlockUrl =
      '/api/v1/admin/orgs/:orgId/contracts/:address/visibleto-unlock';

    it('renders the toggle reflecting the current flag', async () => {
      stubApis([]);
      const off = { ...mockContract, allow_visibleto_unlock: false };
      const { unmount } = renderManager(off);

      await waitFor(() => {
        expect(screen.getByText('Groups with Access')).toBeInTheDocument();
      });

      const sw = screen.getByRole('switch', {
        name: /allow visibleto to unlock event visibility/i,
      });
      expect(sw).not.toBeChecked();
      expect(screen.queryByText(/^enabled$/i)).not.toBeInTheDocument();
      unmount();

      const on = { ...mockContract, allow_visibleto_unlock: true };
      renderManager(on);

      await waitFor(() => {
        expect(screen.getByText('Groups with Access')).toBeInTheDocument();
      });

      const swOn = screen.getByRole('switch', {
        name: /allow visibleto to unlock event visibility/i,
      });
      expect(swOn).toBeChecked();
      expect(screen.getByText(/^enabled$/i)).toBeInTheDocument();
    });

    it('enabling the flag opens a confirmation dialog and only calls the API after Enable', async () => {
      // Need user-event for interaction
      const userEvent = (await import('@testing-library/user-event')).default;
      const user = userEvent.setup();
      stubApis([]);
      const contract = { ...mockContract, allow_visibleto_unlock: false };
      renderManager(contract);

      await waitFor(() => {
        expect(screen.getByText('Groups with Access')).toBeInTheDocument();
      });

      let putCalled = false;
      let putBody: { allow_visibleto_unlock?: boolean } | null = null;
      
      const { http, HttpResponse } = await import('msw');
      const { server } = await import('@/test/mocks/server');
      
      server.use(
        http.put(visibleToUnlockUrl, async ({ request }) => {
          putCalled = true;
          putBody = (await request.json()) as { allow_visibleto_unlock: boolean };
          return HttpResponse.json({ ...contract, allow_visibleto_unlock: true });
        }),
      );

      const sw = screen.getByRole('switch', {
        name: /allow visibleto to unlock event visibility/i,
      });
      await user.click(sw);

      // Confirmation modal renders; API not yet called.
      const dialogHeading = await screen.findByText(/Enable visibleTo unlock\?/i);
      expect(dialogHeading).toBeInTheDocument();
      expect(putCalled).toBe(false);

      // Cancel keeps it disabled.
      const dialog = dialogHeading.closest('div.fixed') as HTMLElement;
      // The operator must see that the unlock shares full event payloads,
      // embedded addresses included — not only that it bypasses event rules.
      expect(
        (await import('@testing-library/react')).within(dialog).getByText(/including embedded addresses/i),
      ).toBeInTheDocument();
      const cancelBtn = (await import('@testing-library/react')).within(dialog).getByRole('button', { name: /cancel/i });
      await user.click(cancelBtn);
      
      expect(putCalled).toBe(false);
      await waitFor(() => {
        expect(screen.queryByText(/Enable visibleTo unlock\?/i)).not.toBeInTheDocument();
      });

      // Re-open and confirm.
      await user.click(sw);
      const enable = await screen.findByRole('button', { name: /^enable$/i });
      await user.click(enable);

      await waitFor(() => expect(putCalled).toBe(true));
      expect(putBody).toEqual({ allow_visibleto_unlock: true });
      expect(
        await screen.findByText(/visibleTo unlock enabled for this contract/i),
      ).toBeInTheDocument();

      // RD-1069: the enabled-state caption must match the confirm dialog —
      // it gates on contract group access and denies cross-org/anonymous,
      // and must NOT claim "full event payloads with any DID".
      expect(
        screen.getByText(/already hold contract group access in this org/i),
      ).toBeInTheDocument();
      expect(screen.queryByText(/with any DID they list/i)).not.toBeInTheDocument();
    });

    it('RD-1075: enabling fires onContractUpdated with the saved contract', async () => {
      const userEvent = (await import('@testing-library/user-event')).default;
      const user = userEvent.setup();
      stubApis([]);
      const contract = { ...mockContract, allow_visibleto_unlock: false };
      const onContractUpdated = vi.fn();

      render(
        <TooltipProvider>
          <ContractGrantsManager
            orgId="org-1"
            contract={contract}
            onContractUpdated={onContractUpdated}
          />
        </TooltipProvider>,
      );

      await waitFor(() => {
        expect(screen.getByText('Groups with Access')).toBeInTheDocument();
      });

      const { http, HttpResponse } = await import('msw');
      const { server } = await import('@/test/mocks/server');
      server.use(
        http.put(visibleToUnlockUrl, () =>
          HttpResponse.json({ ...contract, allow_visibleto_unlock: true }),
        ),
      );

      await user.click(
        screen.getByRole('switch', {
          name: /allow visibleto to unlock event visibility/i,
        }),
      );
      await user.click(await screen.findByRole('button', { name: /^enable$/i }));

      await waitFor(() => expect(onContractUpdated).toHaveBeenCalled());
      expect(onContractUpdated).toHaveBeenCalledWith(
        expect.objectContaining({ id: contract.id, allow_visibleto_unlock: true }),
      );
    });

    it('disabling does NOT prompt — applies immediately', async () => {
      const userEvent = (await import('@testing-library/user-event')).default;
      const user = userEvent.setup();
      stubApis([]);
      const contract = { ...mockContract, allow_visibleto_unlock: true };
      renderManager(contract);

      await waitFor(() => {
        expect(screen.getByText('Groups with Access')).toBeInTheDocument();
      });

      let putBody: { allow_visibleto_unlock?: boolean } | null = null;
      
      const { http, HttpResponse } = await import('msw');
      const { server } = await import('@/test/mocks/server');
      
      server.use(
        http.put(visibleToUnlockUrl, async ({ request }) => {
          putBody = (await request.json()) as { allow_visibleto_unlock: boolean };
          return HttpResponse.json({ ...contract, allow_visibleto_unlock: false });
        }),
      );

      const sw = screen.getByRole('switch', {
        name: /allow visibleto to unlock event visibility/i,
      });
      await user.click(sw);

      // No confirmation modal for disabling.
      expect(screen.queryByText(/Enable visibleTo unlock\?/i)).not.toBeInTheDocument();
      await waitFor(() => expect(putBody).toEqual({ allow_visibleto_unlock: false }));
      expect(
        await screen.findByText(/visibleTo unlock disabled/i),
      ).toBeInTheDocument();
    });

    it('surfaces the API error if the toggle fails', async () => {
      const userEvent = (await import('@testing-library/user-event')).default;
      const user = userEvent.setup();
      stubApis([]);
      const contract = { ...mockContract, allow_visibleto_unlock: false };
      renderManager(contract);

      await waitFor(() => {
        expect(screen.getByText('Groups with Access')).toBeInTheDocument();
      });
      
      const { http, HttpResponse } = await import('msw');
      const { server } = await import('@/test/mocks/server');

      server.use(
        http.put(visibleToUnlockUrl, async () =>
          HttpResponse.json({ error: 'permission denied: not an admin' }, { status: 403 }),
        ),
      );

      const sw = screen.getByRole('switch', {
        name: /allow visibleto to unlock event visibility/i,
      });
      await user.click(sw);
      const enable = await screen.findByRole('button', { name: /^enable$/i });
      await user.click(enable);

      expect(
        await screen.findByText(/permission denied: not an admin/i),
      ).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// RD-1201: functions tri-state display — "all" and "none" must never collapse
// into the same rendered state.
// ---------------------------------------------------------------------------

describe('ContractGrantsManager — functions tri-state display (RD-1201)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const baseGrant = {
    id: 'grant-1',
    contract_id: 'contract-1',
    group_id: 'group-1',
    event_rules: null,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  };

  it('renders "All functions allowed" for functions: null', async () => {
    stubApis([{ ...baseGrant, functions: null } as ContractGrant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });
    expect(screen.getByText('All functions allowed')).toBeInTheDocument();
    expect(screen.queryByText('No functions (events only)')).not.toBeInTheDocument();
  });

  it('renders "No functions (events only)" for functions: [] — distinct from all', async () => {
    stubApis([{ ...baseGrant, functions: [] } as ContractGrant]);
    renderManager();

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });
    expect(screen.getByText('No functions (events only)')).toBeInTheDocument();
    expect(screen.queryByText('All functions allowed')).not.toBeInTheDocument();
  });

  // RD-1205: the summary's selector→name map must canonicalize tuple params
  // (a struct input's `type` is the literal "tuple"; hashing that never
  // matches real calldata). With the fixed map, a grant holding the canonical
  // tuple selector renders the function NAME, not the raw selector hex.
  it('maps a tuple-param selector to its ABI name in the grant summary', async () => {
    const tupleAbi = JSON.stringify([
      {
        type: 'function',
        name: 'setWorkflowDetails',
        stateMutability: 'nonpayable',
        inputs: [
          { name: 'id', type: 'uint256' },
          {
            name: 'details',
            type: 'tuple',
            components: [
              { name: 'label', type: 'string' },
              { name: 'uri', type: 'string' },
            ],
          },
        ],
        outputs: [],
      },
    ]);
    // Independent oracle: derive the selector from the canonical STRING
    // signature — the component must arrive at the same selector from the
    // ABI OBJECT.
    const expectedSelector = toFunctionSelector('setWorkflowDetails(uint256,(string,string))');

    stubApis([
      { ...baseGrant, functions: [{ selector: expectedSelector }] } as ContractGrant,
    ]);
    renderManager({ ...mockContract, abi: tupleAbi });

    await waitFor(() => {
      expect(screen.getByText('Auditors')).toBeInTheDocument();
    });
    expect(screen.getByText('setWorkflowDetails')).toBeInTheDocument();
  });
});
