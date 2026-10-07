import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import GroupAccessForm from '../GroupAccessForm';
import { mockGroupAccess } from '@/test/mocks/handlers';
import { mockGroupAccessFull } from '@/test/mocks/rbac-fixtures';
import { METHOD_SECTIONS, getPresetMethods, PERMISSION_PRESETS } from '@/types/rbac';

// Minimal wrapper since GroupAccessForm doesn't need org context directly
function renderGroupAccessForm(props: {
  orgId?: string;
  groupId?: string;
  isOrgAdmin?: boolean;
  onClose?: () => void;
  onSave?: () => void;
}) {
  const defaultProps = {
    orgId: 'org-1',
    groupId: 'group-1',
    onClose: vi.fn(),
    onSave: vi.fn(),
  };

  return render(<GroupAccessForm {...defaultProps} {...props} />);
}

describe('GroupAccessForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Loading', () => {
    it('fetches /groups/:id/access on mount', async () => {
      let fetchCalled = false;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          fetchCalled = true;
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(fetchCalled).toBe(true);
      });
    });

    it('shows loading spinner while fetching', () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async () => {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({});

      expect(document.querySelector('.animate-spin')).toBeInTheDocument();
    });

    it('shows existing allowed_methods as checked checkboxes', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('eth_call')).toBeInTheDocument();
      });

      // Check that selected methods have the checked indicator (bg-primary)
      const ethCallLabel = screen.getByText('eth_call').closest('label');
      expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
    });

    it('does not render rate limit inputs', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccessFull);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('eth_call')).toBeInTheDocument();
      });

      // Rate limit fields should not exist — rate limiting is handled at the RPC proxy API key level
      expect(screen.queryByPlaceholderText('100')).not.toBeInTheDocument();
      expect(screen.queryByPlaceholderText('100000')).not.toBeInTheDocument();
      expect(screen.queryByText('Rate Limit (RPS)')).not.toBeInTheDocument();
      expect(screen.queryByText('Rate Limit (Daily)')).not.toBeInTheDocument();
    });
  });

  describe('Org-admin group (RD-968)', () => {
    it('hides the claims editor and shows a banner for org-admin groups', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json(mockGroupAccess)
        )
      );

      renderGroupAccessForm({ isOrgAdmin: true });

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      expect(
        screen.getByText(/Members automatically receive all claims/)
      ).toBeInTheDocument();
      // The editable claim option labels are gone (claims don't apply here).
      expect(screen.queryByText('Deploy')).not.toBeInTheDocument();
    });

    it('saves empty claims for an org-admin group even if the stored row had claims', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json({ ...mockGroupAccess, allowed_methods: ['eth_call'], claims: ['admin'] })
        ),
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({ isOrgAdmin: true, onSave });

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Save Access Settings'));

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({ claims: [] });
    });
  });

  describe('Preset Cards', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('renders all three preset cards', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Each preset appears as a card (button) with description
      expect(screen.getByText('End users with wallets — send payments, check balances')).toBeInTheDocument();
      expect(screen.getByText('Automated systems — raw transactions, event monitoring')).toBeInTheDocument();
      expect(screen.getByText('Engineers — deploy, debug, inspect contract state')).toBeInTheDocument();
    });

    it('clicking preset fills methods', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Click Wallet User preset card (use the description to find the right button)
      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      // After clicking, all Wallet User methods should be checked
      await waitFor(() => {
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
      });

      // eth_sendTransaction should also be checked (part of Wallet User preset)
      const sendTxLabel = screen.getByText('eth_sendTransaction').closest('label');
      expect(sendTxLabel?.querySelector('.bg-primary')).toBeInTheDocument();

      // eth_sendRawTransaction should NOT be checked (Service/Backend only)
      const rawTxLabel = screen.getByText('eth_sendRawTransaction').closest('label');
      expect(rawTxLabel?.querySelector('.bg-primary')).not.toBeInTheDocument();
    });

    it('clicking Developer preset includes all lower-level methods', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Click Developer preset card
      const devCard = screen.getByText('Engineers — deploy, debug, inspect contract state').closest('button')!;
      await user.click(devCard);

      // Developer includes Wallet User + Service/Backend + Developer methods
      await waitFor(() => {
        // Wallet User method
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
      });

      // Service/Backend method
      const rawTxLabel = screen.getByText('eth_sendRawTransaction').closest('label');
      expect(rawTxLabel?.querySelector('.bg-primary')).toBeInTheDocument();

      // Developer method
      const traceLabel = screen.getByText('debug_traceTransaction').closest('label');
      expect(traceLabel?.querySelector('.bg-primary')).toBeInTheDocument();
    });

    it('modifying methods deselects preset highlight', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Apply Wallet User preset
      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      await waitFor(() => {
        // The Wallet User card should be highlighted (border-primary)
        expect(walletCard.className).toContain('border-primary');
      });

      // Now toggle off a method to diverge from the preset
      const ethCallLabel = screen.getByText('eth_call').closest('label');
      if (ethCallLabel) {
        await user.click(ethCallLabel);
      }

      // The preset card should no longer be highlighted
      await waitFor(() => {
        expect(walletCard.className).not.toContain('border-primary bg-primary-50');
      });
    });

    it('clicking Wallet User preset selects exactly the right number of methods', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
      const expectedCount = getPresetMethods(walletPreset).length;

      // Verify the section counter shows the correct count
      await waitFor(() => {
        // Wallet User section header should show N / N (all selected)
        const sectionMethods = METHOD_SECTIONS['Wallet User'].methods;
        expect(screen.getByText(`${sectionMethods.length} / ${sectionMethods.length}`)).toBeInTheDocument();
      });

      // Service/Backend section should show 0 selected
      const serviceMethods = METHOD_SECTIONS['Service / Backend'].methods;
      expect(screen.getByText(`0 / ${serviceMethods.length}`)).toBeInTheDocument();

      // Developer section should show 0 selected
      const devMethods = METHOD_SECTIONS['Developer'].methods;
      expect(screen.getByText(`0 / ${devMethods.length}`)).toBeInTheDocument();

      // The preset card shows "N methods" label
      expect(screen.getByText(`${expectedCount} methods`)).toBeInTheDocument();
    });

    it('clicking Developer preset selects all 3 sections fully', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      const devCard = screen.getByText('Engineers — deploy, debug, inspect contract state').closest('button')!;
      await user.click(devCard);

      // All three sections should show full counts
      await waitFor(() => {
        const walletMethods = METHOD_SECTIONS['Wallet User'].methods;
        expect(screen.getByText(`${walletMethods.length} / ${walletMethods.length}`)).toBeInTheDocument();
      });

      const serviceMethods = METHOD_SECTIONS['Service / Backend'].methods;
      expect(screen.getByText(`${serviceMethods.length} / ${serviceMethods.length}`)).toBeInTheDocument();

      const devMethods = METHOD_SECTIONS['Developer'].methods;
      expect(screen.getByText(`${devMethods.length} / ${devMethods.length}`)).toBeInTheDocument();
    });

    it('edit mode detects matching preset on load', async () => {
      // Load with exact Wallet User preset methods
      const walletPreset = PERMISSION_PRESETS.find(p => p.id === 'wallet_user')!;
      const walletMethods = getPresetMethods(walletPreset);

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json({
            ...mockGroupAccess,
            allowed_methods: walletMethods,
            claims: [],
          });
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        // The Wallet User preset card should be highlighted
        const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button');
        expect(walletCard?.className).toContain('border-primary');
      });
    });
  });

  describe('Method Sections', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('displays method sections by role', async () => {
      renderGroupAccessForm({});

      await waitFor(() => {
        // Service/Backend section (with + prefix) - unique to section headers
        expect(screen.getByText('+ Service / Backend')).toBeInTheDocument();
      });

      // Developer section (with + prefix)
      expect(screen.getByText('+ Developer')).toBeInTheDocument();

      // Method section descriptions
      expect(screen.getByText('Core methods for end users with wallets')).toBeInTheDocument();
      expect(screen.getByText('Additional methods for automated systems and backend services')).toBeInTheDocument();
      expect(screen.getByText('Deep inspection and debugging tools for engineers')).toBeInTheDocument();
    });

    it('can toggle method by clicking checkbox', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('eth_estimateGas')).toBeInTheDocument();
      });

      // Click on eth_estimateGas to toggle it
      const methodLabel = screen.getByText('eth_estimateGas').closest('label');
      if (methodLabel) {
        await user.click(methodLabel);
      }

      // After clicking, it should be toggled
      await waitFor(() => {
        const updatedLabel = screen.getByText('eth_estimateGas').closest('label');
        expect(updatedLabel).toBeInTheDocument();
      });
    });

    it('can use Select All to check all methods in section', async () => {
      const user = userEvent.setup();

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Core methods for end users with wallets')).toBeInTheDocument();
      });

      // Click Select All for the first section (Wallet User)
      const selectAllButtons = screen.getAllByText('Select All');
      await user.click(selectAllButtons[0]);

      // After clicking, all Wallet User methods should be selected
      await waitFor(() => {
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
      });
    });
  });

  describe('Saving', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('Save button submits PUT to /groups/:id/access', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroupAccess,
            ...capturedBody,
          });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      // Click save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toBeDefined();
      expect(capturedBody).toHaveProperty('allowed_methods');
      expect(capturedBody).toHaveProperty('claims');
    });

    it('success calls onSave callback', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
    });

    it('error shows error message', async () => {
      const user = userEvent.setup();

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(
            { error: 'Invalid rate limit value' },
            { status: 400 }
          );
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(screen.getByText('Invalid rate limit value')).toBeInTheDocument();
      });
    });

    it('shows loading state while saving', async () => {
      const user = userEvent.setup();

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async () => {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return HttpResponse.json(mockGroupAccess);
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(screen.getByText('Saving...')).toBeInTheDocument();
      });
    });

    it('save derives correct claims for Wallet User preset', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroupAccess,
            ...capturedBody,
          });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Apply Wallet User preset
      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      await waitFor(() => {
        expect(walletCard.className).toContain('border-primary');
      });

      // Save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      // Wallet User has no operational claims — read/write are implicit from methods
      expect(capturedBody).toBeDefined();
      const claims = capturedBody!.claims as string[];
      expect(claims).not.toContain('read');
      expect(claims).not.toContain('write');
      expect(claims).not.toContain('admin');
      expect(claims).not.toContain('deploy');
      expect(claims).not.toContain('upgrade');
    });

    it('manual claims selection includes deploy and upgrade when admin is checked', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroupAccess,
            ...capturedBody,
          });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
      });

      // Click Admin claim checkbox using its description to avoid matching the Admin preset
      const adminClaimLabel = screen.getByText('Full control — implies Deploy and Upgrade').closest('label')!;
      await user.click(adminClaimLabel);

      // Save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toBeDefined();
      const claims = capturedBody!.claims as string[];
      expect(claims).toContain('admin');
      expect(claims).toContain('deploy');
      expect(claims).toContain('upgrade');
      expect(claims).not.toContain('read');
      expect(claims).not.toContain('write');
    });
  });

  describe('Cancel Button', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        })
      );
    });

    it('calls onClose when Cancel is clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      renderGroupAccessForm({ onClose });

      await waitFor(() => {
        expect(screen.getByText('Cancel')).toBeInTheDocument();
      });

      const cancelButton = screen.getByText('Cancel');
      await user.click(cancelButton);

      expect(onClose).toHaveBeenCalled();
    });
  });

  describe('Empty Access Settings', () => {
    it('handles group with no existing access settings', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(null, { status: 404 });
        })
      );

      renderGroupAccessForm({});

      // Should not crash and show empty form
      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      // Method sections should be shown (use unique section descriptions)
      expect(screen.getByText('Core methods for end users with wallets')).toBeInTheDocument();
      expect(screen.getByText('+ Service / Backend')).toBeInTheDocument();
      expect(screen.getByText('+ Developer')).toBeInTheDocument();
    });
  });

  describe('Full Integration', () => {
    it('can apply preset, modify methods, and save', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
          return HttpResponse.json(mockGroupAccess);
        }),
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroupAccess,
            ...capturedBody,
          });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });

      // Apply Wallet User preset
      const walletCard = screen.getByText('End users with wallets — send payments, check balances').closest('button')!;
      await user.click(walletCard);

      // Verify methods are checked
      await waitFor(() => {
        const ethCallLabel = screen.getByText('eth_call').closest('label');
        expect(ethCallLabel?.querySelector('.bg-primary')).toBeInTheDocument();
      });

      // Save
      const saveButton = screen.getByText('Save Access Settings');
      await user.click(saveButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        allowed_methods: expect.arrayContaining(['eth_call', 'eth_sendTransaction']),
      });
      // Wallet User has no operational claims — read/write removed
      const integClaims = (capturedBody as Record<string, unknown>).claims as string[];
      expect(integClaims).not.toContain('read');
      expect(integClaims).not.toContain('write');
      // Rate limits should not be in the payload
      expect(capturedBody).not.toHaveProperty('rate_limit_rps');
      expect(capturedBody).not.toHaveProperty('rate_limit_daily');
    });
  });

  // Operator-configured namespaces. The proxy forwards only catalog methods
  // plus methods the operator lists by exact name, so the form must never
  // offer (or re-save) a "<prefix>*" wildcard, and it must flag the methods
  // the operator exposes as unfiltered passthrough.
  describe('Operator namespaces', () => {
    const statusWith = (methods: Record<string, unknown>) =>
      http.get('/api/v1/admin/status', () =>
        HttpResponse.json({
          proxy: { status: 'running', port: '8080' },
          node: { status: 'ok', url: 'http://localhost:8545', latency_ms: 12 },
          security: { travel_rule_enabled: false },
          methods,
        })
      );

    it('does not offer a prefix-wildcard toggle', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json(mockGroupAccess)
        ),
        statusWith({
          extra_namespaces: { Linea: ['linea_estimateGas'] },
          extra_wildcards: { Linea: { prefix: 'linea_', deny: ['linea_sendTransaction'] } },
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('linea_estimateGas')).toBeInTheDocument();
      });
      expect(screen.queryByText('linea_*')).not.toBeInTheDocument();
      expect(screen.queryByText(/Allow any method starting with/)).not.toBeInTheDocument();
    });

    it('does not re-submit stored wildcard entries on save', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json({
            ...mockGroupAccess,
            allowed_methods: ['eth_call', 'linea_*', '*', 'eth_get*'],
          })
        ),
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ ...mockGroupAccess, ...capturedBody });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });
      await user.click(screen.getByText('Save Access Settings'));
      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect((capturedBody as unknown as Record<string, unknown>).allowed_methods).toEqual(['eth_call']);
    });

    it('drops stored methods the proxy does not support, and says so', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json({
            ...mockGroupAccess,
            allowed_methods: ['eth_call', 'eth_getRawTransactionByHash', 'eth_getProof'],
          })
        ),
        statusWith({ supported_methods: ['eth_call', 'eth_getLogs', 'eth_getProof'] }),
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ ...mockGroupAccess, ...capturedBody });
        })
      );

      renderGroupAccessForm({ onSave });

      await waitFor(() => {
        expect(screen.getByText(/Not supported by this proxy/)).toBeInTheDocument();
      });
      expect(screen.getByText(/Not supported by this proxy/).closest('p')).toHaveTextContent('eth_getRawTransactionByHash');
      // A supported method granted outside the picker is shown and kept.
      expect(screen.getByText(/Also granted/).closest('p')).toHaveTextContent('eth_getProof');

      await user.click(screen.getByText('Save Access Settings'));
      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
      expect((capturedBody as unknown as Record<string, unknown>).allowed_methods).toEqual(['eth_call', 'eth_getProof']);
    });

    it('keeps stored methods when the backend does not report supported methods', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json({ ...mockGroupAccess, allowed_methods: ['eth_call', 'eth_getProof'] })
        ),
        statusWith({}),
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ ...mockGroupAccess, ...capturedBody });
        })
      );

      renderGroupAccessForm({ onSave });
      await waitFor(() => {
        expect(screen.getByText('Save Access Settings')).toBeInTheDocument();
      });
      expect(screen.queryByText(/Not supported by this proxy/)).not.toBeInTheDocument();
      await user.click(screen.getByText('Save Access Settings'));
      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
      expect((capturedBody as unknown as Record<string, unknown>).allowed_methods).toEqual(['eth_call', 'eth_getProof']);
    });

    it('says when stored wildcard entries will be replaced on save', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json({ ...mockGroupAccess, allowed_methods: ['*'] })
        )
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText(/This group holds wildcard entries/)).toBeInTheDocument();
      });
      expect(screen.getByText(/This group holds wildcard entries/).closest('p')).toHaveTextContent('*');
    });

    it('keeps methods granted outside the picker when a preset is applied', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json({ ...mockGroupAccess, allowed_methods: ['eth_call', 'eth_getProof'] })
        ),
        statusWith({ supported_methods: ['eth_call', 'eth_getProof', ...getPresetMethods(PERMISSION_PRESETS[0])] }),
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ ...mockGroupAccess, ...capturedBody });
        })
      );

      renderGroupAccessForm({ onSave });
      await waitFor(() => {
        expect(screen.getByText(/Also granted/)).toBeInTheDocument();
      });
      await user.click(screen.getByText(PERMISSION_PRESETS[0].description).closest('button')!);
      await user.click(screen.getByText('Save Access Settings'));
      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
      const saved = (capturedBody as unknown as Record<string, unknown>).allowed_methods as string[];
      expect(saved).toContain('eth_getProof');
      expect(saved).toEqual(expect.arrayContaining(getPresetMethods(PERMISSION_PRESETS[0])));
    });

    it('marks operator passthrough methods as unfiltered', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () =>
          HttpResponse.json(mockGroupAccess)
        ),
        statusWith({
          extra_namespaces: { zkEVM: ['zkevm_batchNumber', 'zkevm_aliased'] },
          extra_passthrough: ['zkevm_batchNumber'],
        })
      );

      renderGroupAccessForm({});

      await waitFor(() => {
        expect(screen.getByText('zkevm_batchNumber')).toBeInTheDocument();
      });
      const passthroughLabel = screen.getByText('zkevm_batchNumber').closest('label');
      expect(passthroughLabel).toHaveTextContent(/unfiltered/i);
      const aliasedLabel = screen.getByText('zkevm_aliased').closest('label');
      expect(aliasedLabel).not.toHaveTextContent(/unfiltered/i);
    });
  });
});
