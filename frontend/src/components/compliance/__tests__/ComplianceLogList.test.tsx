import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';
import { mockComplianceLogs } from '@/test/mocks/handlers';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import ComplianceLogList from '../ComplianceLogList';

describe('ComplianceLogList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/logs', async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      const { unmount } = renderWithComplianceContext(<ComplianceLogList />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no logs', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/logs', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('No compliance logs')).toBeInTheDocument();
      });
    });

    it('displays logs in a table', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        // Should show user DIDs (short enough to display fully)
        expect(screen.getByText('did:test:alice')).toBeInTheDocument();
        expect(screen.getByText('did:test:bob')).toBeInTheDocument();
      });

      // Check table headers
      expect(screen.getByText('Time')).toBeInTheDocument();
      expect(screen.getByText('User')).toBeInTheDocument();
      expect(screen.getByText('Type')).toBeInTheDocument();
      expect(screen.getByText('Decision')).toBeInTheDocument();
    });

    it('shows decision badges with correct variants', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('allowed')).toBeInTheDocument();
        expect(screen.getByText('denied')).toBeInTheDocument();
      });
    });

    it('shows transfer type badges', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('ETH')).toBeInTheDocument();
        expect(screen.getByText('ERC20')).toBeInTheDocument();
      });
    });

    it('shows denial reason in detail dialog', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('denied')).toBeInTheDocument();
      });

      // Click the denied row to open detail dialog
      const deniedRow = screen.getByText('denied').closest('tr')!;
      await user.click(deniedRow);

      await waitFor(() => {
        expect(screen.getByText('sanctioned_address')).toBeInTheDocument();
      });
    });

    it('shows USD amounts', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('$1,250.00')).toBeInTheDocument();
        expect(screen.getByText('$2,000.00')).toBeInTheDocument();
      });
    });

    it('marks a monitored (would_block) row and surfaces it in the detail dialog (RD-1160)', async () => {
      // A monitor-mode would-have-blocked transfer: decision is `allowed` but
      // would_block=true, with the reason it would have blocked. The list must
      // distinguish it from a plain allow — in the row and in the detail dialog.
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/logs', () =>
          HttpResponse.json({
            data: [{
              id: 99,
              org_id: 'org-1',
              user_id: 'user-9',
              user_external_id: 'did:test:monitored',
              transfer_type: 'eth',
              from_address: '0x1111111111111111111111111111111111111111',
              to_address: '0x2222222222222222222222222222222222222222',
              amount_wei: '5000000000000000000',
              amount_fiat: 5000,
              threshold_fiat: 1000,
              decision: 'allowed',
              would_block: true,
              denial_reason: 'threshold_exceeded',
              created_at: '2024-01-16T09:00:00Z',
            }],
            total: 1, limit: 25, offset: 0,
          })
        )
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('did:test:monitored')).toBeInTheDocument();
      });

      // Row shows BOTH the green `allowed` decision AND a would-block marker,
      // so a monitored allow is not mistaken for a plain allow.
      expect(screen.getByText('allowed')).toBeInTheDocument();
      expect(screen.getByText(/would.?block/i)).toBeInTheDocument();

      // Detail dialog also surfaces the would-have-blocked state.
      await user.click(screen.getByText('did:test:monitored').closest('tr')!);
      await waitFor(() => {
        expect(screen.getByText(/would have blocked/i)).toBeInTheDocument();
      });
    });

    it('does not mark a plain allowed row as would-block (RD-1160)', async () => {
      // Default mock: alice is a plain allow (no would_block) — no marker.
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('did:test:alice')).toBeInTheDocument();
      });

      expect(screen.queryByText(/would.?block/i)).not.toBeInTheDocument();
    });

    it('does not mark a denied row even if would_block is set (RD-1160 gating)', async () => {
      // would_block is only meaningful for decision='allowed' (monitor mode). If
      // it ever appears on a denied row, the marker must NOT show — the "allowed
      // in monitor mode" semantics would otherwise be contradictory.
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/logs', () =>
          HttpResponse.json({
            data: [{
              id: 98, org_id: 'org-1', user_id: 'user-8', user_external_id: 'did:test:denied',
              transfer_type: 'eth',
              from_address: '0x1111111111111111111111111111111111111111',
              to_address: '0x2222222222222222222222222222222222222222',
              amount_wei: '1', amount_fiat: 10, decision: 'denied',
              would_block: true, denial_reason: 'sanctioned_address',
              created_at: '2024-01-16T09:00:00Z',
            }],
            total: 1, limit: 25, offset: 0,
          })
        )
      );
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('did:test:denied')).toBeInTheDocument();
      });

      expect(screen.getByText('denied')).toBeInTheDocument();
      expect(screen.queryByText(/would.?block/i)).not.toBeInTheDocument();
    });
  });

  describe('Filters', () => {
    it('renders filter controls', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('Controls Logs')).toBeInTheDocument();
      });

      expect(screen.getByPlaceholderText('Search by user DID...')).toBeInTheDocument();
    });

    it('filters by decision when selecting Denied', async () => {
      let lastParams: URLSearchParams | null = null;
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/logs', ({ request }) => {
          lastParams = new URL(request.url).searchParams;
          return HttpResponse.json({
            data: mockComplianceLogs.filter(l => {
              const decision = lastParams?.get('decision');
              return !decision || l.decision === decision;
            }),
            total: 1,
            limit: 25,
            offset: 0,
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('did:test:alice')).toBeInTheDocument();
      });

      // Click the decision filter trigger
      const triggers = screen.getAllByRole('combobox');
      const decisionTrigger = triggers[0]; // First select = decisions
      await user.click(decisionTrigger);

      // Select "Denied"
      await waitFor(() => {
        const deniedOption = screen.getByRole('option', { name: 'Denied' });
        return user.click(deniedOption);
      });

      // Verify the API was called with the filter
      await waitFor(() => {
        expect(lastParams?.get('decision')).toBe('denied');
      });
    });

    it('filters by user search with debounce', async () => {
      let lastParams: URLSearchParams | null = null;
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/logs', ({ request }) => {
          lastParams = new URL(request.url).searchParams;
          return HttpResponse.json({
            data: mockComplianceLogs,
            total: mockComplianceLogs.length,
            limit: 25,
            offset: 0,
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('did:test:alice')).toBeInTheDocument();
      });

      const userSearchInput = screen.getByPlaceholderText('Search by user DID...');
      await user.type(userSearchInput, 'did:test');

      // Wait for debounce and API call
      await waitFor(() => {
        expect(lastParams?.get('user_search')).toBe('did:test');
      }, { timeout: 2000 });
    });
  });

  describe('Read-Only', () => {
    it('does not show create or delete buttons', async () => {
      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('did:test:alice')).toBeInTheDocument();
      });

      // Logs are read-only — no Add/Create/Delete buttons
      expect(screen.queryByText('Add')).not.toBeInTheDocument();
      expect(screen.queryByText('Create')).not.toBeInTheDocument();
      // No trash icons
      expect(document.querySelector('.lucide-trash-2')).not.toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('shows error when logs fail to load', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/logs', () => {
          return HttpResponse.json({ error: 'Forbidden' }, { status: 403 });
        })
      );

      renderWithComplianceContext(<ComplianceLogList />);

      await waitFor(() => {
        expect(screen.getByText('Forbidden')).toBeInTheDocument();
      });
    });
  });
});
