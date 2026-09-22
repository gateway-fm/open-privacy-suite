import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import { TooltipProvider } from '@/components/ui/tooltip';
import type { AllowedAzureTenant } from '@/types/rbac';

vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

import GroupList from '../GroupList';
import ContractList from '../ContractList';
import AzureTenantList from '../AzureTenantList';

// The exact text the writer guard returns (internal/server/admin_configuration.go).
const REFUSAL = 'use a configuration revision for this managed stream';

function managedStreams(...kinds: string[]) {
  server.use(
    http.get('/api/v1/admin/orgs/:orgId/configuration/:kind/managed', ({ params }) =>
      HttpResponse.json({ kind: params.kind, managed: kinds.includes(String(params.kind)) })
    )
  );
}

/**
 * RD-1295: once a reviewed document owns a stream, the legacy write endpoints
 * answer 409. The screens must not offer controls that can only fail, and when
 * a write is refused anyway the administrator must read the server's reason,
 * not a guess about members or chain state.
 */
describe('Managed configuration streams in the RBAC screens (RD-1295)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('GroupList', () => {
    it('still lists groups, offers no edit controls, and points at the configuration screen', async () => {
      managedStreams('groups');
      renderWithRBACContext(<GroupList />);

      // Reads keep working: activation projects into the tables the screen reads.
      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });
      await waitFor(() => {
        expect(screen.getByTestId('managed-stream-notice')).toBeInTheDocument();
      });
      expect(screen.getByRole('link', { name: 'Configuration' })).toHaveAttribute('href', '/admin/rbac/configuration');

      // No control that the server would refuse.
      expect(screen.queryByRole('button', { name: /add group/i })).not.toBeInTheDocument();
      expect(screen.queryByTitle('Delete group')).not.toBeInTheDocument();
    });

    it('keeps its controls when a different stream is managed', async () => {
      managedStreams('contract-registry');
      renderWithRBACContext(<GroupList />);

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });
      expect(screen.getByRole('button', { name: /add group/i })).toBeInTheDocument();
      expect(screen.queryByTestId('managed-stream-notice')).not.toBeInTheDocument();
    });

    it("shows the server's refusal word for word when a delete is rejected", async () => {
      const user = userEvent.setup();
      server.use(
        http.delete('/api/v1/admin/orgs/:orgId/groups/:groupId', () =>
          HttpResponse.json({ error: REFUSAL, kind: 'groups' }, { status: 409 })
        )
      );
      renderWithRBACContext(<GroupList />);

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });
      await user.click(screen.getByTitle('Delete group'));
      await waitFor(() => {
        expect(screen.getByText('Delete Group')).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /^delete$/i }));

      await waitFor(() => {
        expect(screen.getByText('Delete Failed')).toBeInTheDocument();
      });
      expect(screen.getByText(REFUSAL)).toBeInTheDocument();
      expect(screen.queryByText(/may have members/)).not.toBeInTheDocument();
    });
  });

  describe('ContractList', () => {
    it('still lists contracts and offers no add, sync or delete controls', async () => {
      managedStreams('contract-registry');
      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });
      await waitFor(() => {
        expect(screen.getByTestId('managed-stream-notice')).toBeInTheDocument();
      });
      expect(screen.queryByRole('button', { name: /add contract/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /sync with chain/i })).not.toBeInTheDocument();
      expect(screen.queryByTitle('Delete contract')).not.toBeInTheDocument();
    });

    it("shows the server's refusal word for word when a delete is rejected", async () => {
      const user = userEvent.setup();
      server.use(
        http.delete('/api/v1/admin/orgs/:orgId/contracts/:address', () =>
          HttpResponse.json({ error: REFUSAL, kind: 'contract-registry' }, { status: 409 })
        )
      );
      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });
      await user.click(screen.getByTitle('Delete contract'));
      await waitFor(() => {
        expect(screen.getByText('Delete Contract')).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /^delete$/i }));

      await waitFor(() => {
        expect(screen.getByText('Delete Failed')).toBeInTheDocument();
      });
      expect(screen.getByText(REFUSAL)).toBeInTheDocument();
    });
  });

  describe('ContractGrantsManager', () => {
    it('goes read-only when the execution rules are managed, even though contracts themselves are not', async () => {
      const user = userEvent.setup();
      managedStreams('execution-rules');
      renderWithRBACContext(
        <TooltipProvider>
          <ContractList />
        </TooltipProvider>
      );

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });
      // The contract rows stay editable: only the registry document would close them.
      expect(screen.queryByTestId('managed-stream-notice')).not.toBeInTheDocument();
      await user.click(await screen.findByTitle('Manage permissions'));

      // Inside the manager: grants belong to the rules document now.
      await waitFor(() => {
        expect(screen.getByTestId('managed-stream-notice')).toBeInTheDocument();
      });
      expect(screen.queryByRole('button', { name: /add (a )?group/i })).not.toBeInTheDocument();
    });
  });

  describe('AzureTenantList', () => {
    const tenant: AllowedAzureTenant = {
      id: 'tenant-1',
      tenant_id: 'aaaabbbb-cccc-dddd-eeee-ffffffffffff',
      label: 'Contoso Corp',
      default_org_id: null,
      default_group_id: null,
      auto_provision: true,
      created_at: '2024-06-01T00:00:00Z',
      updated_at: '2024-06-01T00:00:00Z',
    };

    it('goes read-only when the platform document is active, and points at the platform screen', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => HttpResponse.json({ data: [tenant] })),
        http.get('/api/v1/admin/configuration/platform/managed', () =>
          HttpResponse.json({ kind: 'platform', managed: true })
        )
      );
      renderWithRBACContext(<AzureTenantList />);

      await waitFor(() => {
        expect(screen.getByText('Contoso Corp')).toBeInTheDocument();
      });
      await waitFor(() => {
        expect(screen.getByTestId('managed-stream-notice')).toBeInTheDocument();
      });
      expect(screen.getByRole('link', { name: 'Configuration' })).toHaveAttribute(
        'href',
        '/admin/rbac/platform-configuration'
      );
      expect(screen.queryByRole('button', { name: /add tenant/i })).not.toBeInTheDocument();
    });

    it('keeps its controls while the platform stream is unmanaged', async () => {
      server.use(http.get('/api/v1/admin/azure-tenants', () => HttpResponse.json({ data: [tenant] })));
      renderWithRBACContext(<AzureTenantList />);

      await waitFor(() => {
        expect(screen.getByText('Contoso Corp')).toBeInTheDocument();
      });
      expect(screen.getByRole('button', { name: /add tenant/i })).toBeInTheDocument();
      expect(screen.queryByTestId('managed-stream-notice')).not.toBeInTheDocument();
    });
  });
});
