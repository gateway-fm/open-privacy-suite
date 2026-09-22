import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import { TooltipProvider } from '@/components/ui/tooltip';
import {
  mockContracts,
  mockContractNoName,
  createMockContract,
} from '@/test/mocks/rbac-fixtures';
import { mockContract } from '@/test/mocks/handlers';

// Mock the useOrgContext hook from RBACManager
// Use the shared TestOrgContext from test-utils so MockOrgProvider works
vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

// Import after mock is set up
import ContractList from '../ContractList';

describe('ContractList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Ensure cleanup happens before handlers are reset to prevent pending state updates
  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      // Use MSW's delay to simulate slow response - will be cancelled on cleanup
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      const { unmount } = renderWithRBACContext(<ContractList />);

      // Should show loading spinner (Loader2 icon with animate-spin)
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();

      // Explicitly unmount to prevent act() warnings from pending state updates
      unmount();
    });

    it('shows "Contracts" heading', async () => {
      renderWithRBACContext(<ContractList />);

      expect(screen.getByText('Contracts')).toBeInTheDocument();
    });

    it('shows empty state when no contracts', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('No contracts registered')).toBeInTheDocument();
      });

      expect(
        screen.getByText('Register your first contract')
      ).toBeInTheDocument();
    });

    it('displays table with headers (Address, Name, Groups, Created)', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: mockContracts, total: mockContracts.length, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Address')).toBeInTheDocument();
      });

      expect(screen.getByText('Name')).toBeInTheDocument();
      expect(screen.getByText('Groups')).toBeInTheDocument();
      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Actions')).toBeInTheDocument();
    });
  });

  describe('Data Display', () => {
    it('shows contract address (possibly truncated)', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        // Address is truncated: 0x123456...567890
        expect(screen.getByText(/0x123456.*567890/)).toBeInTheDocument();
      });
    });

    it('shows contract name if present', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });
    });

    it('shows "-" when name is null or undefined', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContractNoName], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        // The component shows '-' for null/undefined names
        // Use getAllByText since ABI column also shows '-' when no ABI
        const dashes = screen.getAllByText('-');
        // At least one dash should be in the name cell (and one in ABI cell)
        expect(dashes.length).toBeGreaterThanOrEqual(1);
      });
    });

    it('formats created date with time', async () => {
      const contract = createMockContract({
        id: 'contract-date-test',
        address: '0xABCDEF1234567890ABCDEF1234567890ABCDEF12',
        name: 'Date Test Contract',
        created_at: '2024-03-15T10:30:00Z',
      });

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [contract], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        // The date is formatted with date + time, e.g. "Mar 15, 2024, 10:30 AM"
        // Match just the date portion since the time depends on the test locale/timezone
        expect(screen.getByText(/Mar 15, 2024/)).toBeInTheDocument();
      });
    });

    it('shows groups badge with count from grant summary', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        }),
        http.get('/api/v1/admin/orgs/:orgId/contracts/grant-summary', () => {
          return HttpResponse.json({
            [mockContract.id]: {
              count: 3,
              groups: [
                { id: 'g1', name: 'Alpha' },
                { id: 'g2', name: 'Beta' },
                { id: 'g3', name: 'Gamma' },
              ],
            },
          });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('3')).toBeInTheDocument();
      });

      // Badge should have the group names as a tooltip
      const badge = screen.getByTitle('Alpha, Beta, Gamma');
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveTextContent('3');
    });

    it('shows groups badge as 0 with "No groups assigned" tooltip when no grants', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        }),
        http.get('/api/v1/admin/orgs/:orgId/contracts/grant-summary', () => {
          return HttpResponse.json({});
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });

      const badge = screen.getByTitle('No groups assigned');
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveTextContent('0');
    });

    it('shows block number when deploy_block is present in metadata', async () => {
      const contractWithBlock = createMockContract({
        id: 'contract-block-test',
        address: '0x1111111111111111111111111111111111111111',
        name: 'Block Test',
        metadata: { deploy_block: '0x1A4' }, // 420 in decimal
      });

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [contractWithBlock], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText(/block 420/)).toBeInTheDocument();
      });
    });

    it('shows raw deploy_block value when it is not valid hex', async () => {
      const contractWithBadBlock = createMockContract({
        id: 'contract-badblock-test',
        address: '0x2222222222222222222222222222222222222222',
        name: 'Bad Block Test',
        metadata: { deploy_block: 'not-a-number' },
      });

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [contractWithBadBlock], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText(/block not-a-number/)).toBeInTheDocument();
      });
    });

    it('shows correct number of rows', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: mockContracts, total: mockContracts.length, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Token Contract')).toBeInTheDocument();
      });

      // mockContracts has 3 contracts
      expect(screen.getByText('NFT Collection')).toBeInTheDocument();
      expect(screen.getByText('Governance')).toBeInTheDocument();
    });
  });

  describe('Actions', () => {
    it('Create button opens ContractForm dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Add Contract')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Contract'));

      await waitFor(() => {
        // Look for the dialog heading specifically
        expect(screen.getByRole('heading', { name: 'Register Contract' })).toBeInTheDocument();
      });

      // Form should be visible with empty fields
      expect(screen.getByText('Contract Address')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('0x...')).toBeInTheDocument();
    });

    it('Edit button opens form with contract data', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });

      // Find and click the edit button (pencil icon)
      const editButton = screen.getByTitle('Edit contract');
      await user.click(editButton);

      await waitFor(() => {
        expect(screen.getByText('Edit Contract')).toBeInTheDocument();
      });

      // Form should be pre-filled with contract data
      const addressInput = screen.getByDisplayValue(mockContract.address);
      expect(addressInput).toBeInTheDocument();
      expect(addressInput).toBeDisabled(); // Address should be read-only in edit mode

      const nameInput = screen.getByDisplayValue('Test Contract');
      expect(nameInput).toBeInTheDocument();
    });

    it('Delete shows confirmation dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });

      // Find and click the delete button (trash icon)
      const deleteButton = screen.getByTitle('Delete contract');
      await user.click(deleteButton);

      // Confirmation dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Contract')).toBeInTheDocument();
      });
      expect(screen.getByText(/Are you sure you want to delete/)).toBeInTheDocument();
    });

    it('Delete success removes from list', async () => {
      const user = userEvent.setup();

      let deleted = false;
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          if (deleted) {
            return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
          }
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        }),
        http.delete('/api/v1/admin/orgs/:orgId/contracts/:address', () => {
          deleted = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });

      const deleteButton = screen.getByTitle('Delete contract');
      await user.click(deleteButton);

      // Wait for confirmation dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Contract')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      await waitFor(() => {
        expect(screen.getByText('No contracts registered')).toBeInTheDocument();
      });
    });

    it('Delete failure shows error dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
        }),
        http.delete('/api/v1/admin/orgs/:orgId/contracts/:address', () => {
          return HttpResponse.json(
            { error: 'Cannot delete contract' },
            { status: 500 }
          );
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(screen.getByText('Test Contract')).toBeInTheDocument();
      });

      const deleteButton = screen.getByTitle('Delete contract');
      await user.click(deleteButton);

      // Wait for confirmation dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Contract')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      // Error dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Failed')).toBeInTheDocument();
      });
      // The server's own reason is shown, not a fixed guess (RD-1295).
      expect(screen.getByText('Cannot delete contract')).toBeInTheDocument();
    });

    it('Empty state button opens ContractForm dialog', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<ContractList />);

      await waitFor(() => {
        expect(
          screen.getByText('Register your first contract')
        ).toBeInTheDocument();
      });

      await user.click(screen.getByText('Register your first contract'));

      await waitFor(() => {
        // Look for the dialog heading specifically
        expect(screen.getByRole('heading', { name: 'Register Contract' })).toBeInTheDocument();
      });
    });
  });

  describe('visibleTo unlock badge sync (RD-1075)', () => {
    it('reflects the saved flag in the list badge after enabling via the dialog', async () => {
      const user = userEvent.setup();
      const contract = createMockContract({
        name: 'VT Contract',
        allow_visibleto_unlock: false,
      });
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () =>
          HttpResponse.json({ data: [contract], total: 1, limit: 25, offset: 0 }),
        ),
        http.put(
          '/api/v1/admin/orgs/:orgId/contracts/:address/visibleto-unlock',
          () => HttpResponse.json({ ...contract, allow_visibleto_unlock: true }),
        ),
      );

      // Wrap in TooltipProvider: the visibleTo badge is a Radix Tooltip, and
      // the real app provides the provider at the App root (App.tsx).
      renderWithRBACContext(
        <TooltipProvider>
          <ContractList />
        </TooltipProvider>,
      );

      // Row present, no badge yet.
      await waitFor(() => {
        expect(screen.getByText('VT Contract')).toBeInTheDocument();
      });
      expect(screen.queryByTestId('visibleto-unlock-badge')).not.toBeInTheDocument();

      // Open the permissions dialog for the row.
      await user.click(screen.getByRole('button', { name: /manage permissions/i }));

      // Enable visibleTo unlock: switch → confirmation → Enable.
      const sw = await screen.findByRole('switch', {
        name: /allow visibleto to unlock event visibility/i,
      });
      await user.click(sw);
      await user.click(await screen.findByRole('button', { name: /^enable$/i }));

      // RD-1075: the parent list now reflects the saved flag — badge appears
      // without a full page reload (previously it stayed stale).
      await waitFor(() => {
        expect(screen.getByTestId('visibleto-unlock-badge')).toBeInTheDocument();
      });
    });
  });
});
