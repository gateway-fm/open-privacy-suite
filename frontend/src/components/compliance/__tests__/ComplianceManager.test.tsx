/**
 * Integration tests for ComplianceManager component.
 *
 * Tests navigation between compliance tabs, org selector behavior,
 * and proper routing.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { MemoryRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import ComplianceManager from '../ComplianceManager';
import ComplianceConfig from '../ComplianceConfig';
import TokenPriceList from '../TokenPriceList';
import SanctionsList from '../SanctionsList';
import TravelRuleRecordList from '../TravelRuleRecordList';
import AddressThresholdList from '../AddressThresholdList';
import ComplianceLogList from '../ComplianceLogList';
import {
  mockOrganizations,
} from '@/test/mocks/rbac-fixtures';

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

function renderComplianceManager(initialRoute = '/admin/compliance/config') {
  const queryClient = createTestQueryClient();
  const user = userEvent.setup();

  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }} initialEntries={[initialRoute]}>
          <Routes>
            <Route path="/admin/compliance" element={<ComplianceManager />}>
              <Route index element={<Navigate to="config" replace />} />
              <Route path="config" element={<ComplianceConfig />} />
              <Route path="tokens" element={<TokenPriceList />} />
              <Route path="travel-rules" element={<TravelRuleRecordList />} />
              <Route path="address-thresholds" element={<AddressThresholdList />} />
              <Route path="sanctions" element={<SanctionsList />} />
              <Route path="logs" element={<ComplianceLogList />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );

  return { user, queryClient };
}

describe('ComplianceManager Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    server.use(
      http.get('/api/v1/admin/orgs', () => {
        return HttpResponse.json({
          data: mockOrganizations,
          total: mockOrganizations.length,
          limit: 1000,
          offset: 0,
        });
      }),
      http.get('/api/v1/admin/status', () => {
        return HttpResponse.json({
          proxy: { status: 'ok', port: '8080' },
          node: { status: 'ok', url: 'http://localhost:8545', latency_ms: 1 },
          security: { runtime_tracing_enabled: false },
        });
      })
    );
  });

  afterEach(() => {
    cleanup();
  });

  describe('Tab Navigation', () => {
    it('renders all six compliance tabs', async () => {
      renderComplianceManager();

      await waitFor(() => {
        expect(screen.getByText('Config')).toBeInTheDocument();
        expect(screen.getByText('Token Prices')).toBeInTheDocument();
        expect(screen.getByText('Travel Rules')).toBeInTheDocument();
        expect(screen.getByText('Address Thresholds')).toBeInTheDocument();
        expect(screen.getByText('Sanctions')).toBeInTheDocument();
        expect(screen.getByText('Logs')).toBeInTheDocument();
      });
    });

    it('renders compliance header with icon and description', async () => {
      renderComplianceManager();

      await waitFor(() => {
        expect(screen.getByText('Controls')).toBeInTheDocument();
        expect(screen.getByText('Travel rule enforcement, token prices, and sanctions')).toBeInTheDocument();
      });
    });

    it('shows org selector on Config tab', async () => {
      renderComplianceManager('/admin/compliance/config?org=org-1');

      await waitFor(() => {
        // Should show org selector (not global scope)
        expect(screen.queryByText('Global (all organizations)')).not.toBeInTheDocument();
      });
    });

    it('shows org selector on Address Thresholds tab', async () => {
      renderComplianceManager('/admin/compliance/address-thresholds?org=org-1');

      await waitFor(() => {
        // Should show org selector (not global scope)
        expect(screen.queryByText('Global (all organizations)')).not.toBeInTheDocument();
      });
    });

    it('requires an org on the Sanctions tab and never renders a "Global" scope', async () => {
      // Sanctions used to render as "Global (all organizations)" with no
      // org selector, which made the frontend call /admin/compliance/sanctions
      // without ?org_id= — JWT-admin callers now get 400 from the backend
      // (admin_compliance.go: "org_id query parameter is required"). The tab
      // must behave like the other org-scoped tabs: show the same org
      // selector and the "Select an organization" empty state when none is
      // picked.
      renderComplianceManager('/admin/compliance/sanctions');

      await waitFor(() => {
        expect(screen.queryByText('Global (all organizations)')).not.toBeInTheDocument();
        expect(screen.getByText('No organization selected')).toBeInTheDocument();
      });
    });

    it('navigates between tabs', async () => {
      const { user } = renderComplianceManager('/admin/compliance/config?org=org-1');

      // Wait for initial load
      await waitFor(() => {
        expect(screen.getByText('Controls Configuration')).toBeInTheDocument();
      });

      // Click Token Prices tab
      const tokenPricesTab = screen.getAllByText('Token Prices')[0];
      await user.click(tokenPricesTab);

      // After navigating, the config content should disappear and token content should appear
      await waitFor(() => {
        expect(screen.queryByText('Controls Configuration')).not.toBeInTheDocument();
      });

      // The Token Prices sub-component should render (shows Add Token button)
      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });
    });
  });

  describe('Organization Selector', () => {
    it('selects org from URL param', async () => {
      renderComplianceManager('/admin/compliance/config?org=org-1');

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
    });

    it('does not auto-select org when no org param in URL', async () => {
      renderComplianceManager('/admin/compliance/config');

      await waitFor(() => {
        // Should show the "Select an org" hint and blocked content
        expect(screen.getByText('Select an org')).toBeInTheDocument();
        expect(screen.getByText('No organization selected')).toBeInTheDocument();
      });
    });

    it('shows "No organization selected" when no orgs exist', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 1000, offset: 0 });
        })
      );

      renderComplianceManager('/admin/compliance/config');

      await waitFor(() => {
        expect(screen.getByText('No organization selected')).toBeInTheDocument();
      });
    });
  });
});
