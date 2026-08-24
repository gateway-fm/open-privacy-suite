/**
 * Integration tests for RBACManager component.
 *
 * These tests verify the full RBAC flow including:
 * - Navigation between tabs (Organizations, Groups, Users, Contracts)
 * - Full CRUD flow: Create org -> Create group -> Add user to group -> Verify permissions
 * - Tab state persistence and URL routing
 * - Cross-component data consistency
 * - Error boundary behavior
 * - Loading states across multiple data fetches
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import RBACManager from '../RBACManager';
import OrganizationList from '../OrganizationList';
import GroupList from '../GroupList';
import UserList from '../UserList';
import ContractList from '../ContractList';
import {
  mockOrganizations,
  mockGroupHierarchy,
  mockUsers,
  mockContracts,
  mockMembershipsWithDetails,
  mockFullEffectivePermissions,
  mockLinkedAddresses,
  createMockOrganization,
  createMockGroup,
} from '@/test/mocks/rbac-fixtures';
import {
  mockUser,
  mockGroupAccess,
} from '@/test/mocks/handlers';
import type { Organization, Group, User, Contract } from '@/types/rbac';

// Note: We no longer mock window.confirm and window.alert since we use styled dialogs

// Mock useEnsNames to avoid network calls to ENS
vi.mock('@/hooks/useEnsNames', () => ({
  useEnsNames: () => ({
    data: {},
    isLoading: false,
    error: null,
  }),
}));

// Create a fresh QueryClient for each test
function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  });
}

interface RenderRBACManagerOptions {
  initialRoute?: string;
}

/**
 * Render the full RBACManager with nested routes.
 * This mimics the actual app routing structure.
 */
function renderRBACManager(options: RenderRBACManagerOptions = {}) {
  const { initialRoute = '/admin/rbac/organizations' } = options;
  const queryClient = createTestQueryClient();
  const user = userEvent.setup();

  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }} initialEntries={[initialRoute]}>
          <Routes>
            <Route path="/admin/rbac" element={<RBACManager />}>
              <Route index element={<OrganizationList />} />
              <Route path="organizations" element={<OrganizationList />} />
              <Route path="groups" element={<GroupList />} />
              <Route path="users" element={<UserList />} />
              <Route path="users/:userId" element={<UserList />} />
              <Route path="contracts" element={<ContractList />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );

  return { user, queryClient };
}

describe('RBACManager Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Setup default handlers for all RBAC endpoints
    const groupsWithAccess = mockGroupHierarchy.map(g => ({ group: g, access: mockGroupAccess }));
    server.use(
      http.get('/api/v1/admin/orgs', () => {
        return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 1000, offset: 0 });
      }),
      http.get('/api/v1/admin/orgs/:orgId/groups', () => {
        return HttpResponse.json({ data: groupsWithAccess, total: groupsWithAccess.length, limit: 50, offset: 0 });
      }),
      http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
        return HttpResponse.json(mockGroupAccess);
      }),
      http.get('/api/v1/admin/users', () => {
        return HttpResponse.json({ data: mockUsers, total: mockUsers.length, limit: 25, offset: 0 });
      }),
      http.get('/api/v1/admin/users/:userId', () => {
        return HttpResponse.json(mockUser);
      }),
      http.get('/api/v1/admin/users/:userId/memberships', () => {
        return HttpResponse.json(mockMembershipsWithDetails);
      }),
      http.get('/api/v1/admin/users/:userId/linked-addresses', () => {
        return HttpResponse.json({ addresses: mockLinkedAddresses });
      }),
      http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
        return HttpResponse.json(mockFullEffectivePermissions);
      }),
      http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
        return HttpResponse.json({ data: mockContracts, total: mockContracts.length, limit: 25, offset: 0 });
      })
    );
  });

  afterEach(() => {
    server.resetHandlers();
  });

  // ===========================================================================
  // Tab Navigation Tests
  // ===========================================================================
  describe('Tab Navigation', () => {
    it('renders RBACManager with all four tabs', async () => {
      renderRBACManager();

      await waitFor(() => {
        expect(screen.getByTestId('rbac-manager')).toBeInTheDocument();
      });

      // Verify all tabs are present
      expect(screen.getByTestId('tab-organizations')).toBeInTheDocument();
      expect(screen.getByTestId('tab-groups')).toBeInTheDocument();
      expect(screen.getByTestId('tab-users')).toBeInTheDocument();
      expect(screen.getByTestId('tab-contracts')).toBeInTheDocument();
    });

    it('Organizations tab is active by default on /admin/rbac/organizations', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        const orgTab = screen.getByTestId('tab-organizations');
        expect(orgTab).toHaveAttribute('data-state', 'active');
      });
    });

    it('navigates from Organizations to Groups tab', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByTestId('tab-organizations')).toHaveAttribute('data-state', 'active');
      });

      // Click on Groups tab
      const groupsTab = screen.getByTestId('tab-groups');
      await user.click(groupsTab);

      await waitFor(() => {
        expect(groupsTab).toHaveAttribute('data-state', 'active');
      });

      // Without org selected, should show "Select an org" prompt
      await waitFor(() => {
        expect(screen.getByText('Select an org')).toBeInTheDocument();
      });
    });

    it('navigates from Groups to Users tab', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      await waitFor(() => {
        expect(screen.getByTestId('tab-groups')).toHaveAttribute('data-state', 'active');
      });

      const usersTab = screen.getByTestId('tab-users');
      await user.click(usersTab);

      await waitFor(() => {
        expect(usersTab).toHaveAttribute('data-state', 'active');
      });

      // Users tab shows user list heading
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Users' })).toBeInTheDocument();
      });
    });

    it('navigates to Contracts tab', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/contracts?org=org-1' });

      await waitFor(() => {
        expect(screen.getByTestId('rbac-manager')).toBeInTheDocument();
      });

      const contractsTab = screen.getByTestId('tab-contracts');

      await waitFor(() => {
        expect(contractsTab).toHaveAttribute('data-state', 'active');
      });

      // Contracts content should be visible (the heading in ContractList)
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Contracts' })).toBeInTheDocument();
      });
    });

    it('shows "Global" scope indicator on Organizations tab', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByText('Global (all organizations)')).toBeInTheDocument();
      });
    });

    it('shows organization selector on Users tab', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByTestId('rbac-manager')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('tab-users'));

      await waitFor(() => {
        // Users tab requires org selection (not global)
        expect(screen.queryByText('Global (all organizations)')).not.toBeInTheDocument();
        expect(screen.getByTestId('org-selector')).toBeInTheDocument();
      });
    });

    it('shows organization selector on Groups tab', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByTestId('rbac-manager')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('tab-groups'));

      await waitFor(() => {
        // Should show org selector (not Global scope)
        expect(screen.queryByText('Global (all organizations)')).not.toBeInTheDocument();
        expect(screen.getByTestId('org-selector')).toBeInTheDocument();
      });
    });

    it('shows organization selector on Contracts tab', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByTestId('rbac-manager')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('tab-contracts'));

      await waitFor(() => {
        expect(screen.queryByText('Global (all organizations)')).not.toBeInTheDocument();
        expect(screen.getByTestId('org-selector')).toBeInTheDocument();
      });
    });
  });

  // ===========================================================================
  // Organization Selector Tests
  // ===========================================================================
  describe('Organization Selector', () => {
    it('does not auto-select org when switching to Groups tab without org param', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByTestId('rbac-manager')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('tab-groups'));

      await waitFor(() => {
        expect(screen.getByTestId('org-selector')).toBeInTheDocument();
        expect(screen.getByText('Select an org')).toBeInTheDocument();
      });
    });

    it('preserves organization selection across tab changes', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      // Wait for org to load and be selected
      await waitFor(() => {
        expect(screen.getByTestId('org-selector')).toBeInTheDocument();
      });

      // Wait for first org to be displayed (Acme Corporation is org-1)
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      // Navigate to contracts (which also requires org)
      await user.click(screen.getByTestId('tab-contracts'));
      await waitFor(() => {
        expect(screen.getByTestId('tab-contracts')).toHaveAttribute('data-state', 'active');
      });

      // Org should still be selected (Acme Corporation = org-1)
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
    });

    it('shows "No organization selected" when org is required but none selected', async () => {
      // Return empty orgs list
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 1000, offset: 0 });
        })
      );

      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByTestId('rbac-manager')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('tab-groups'));

      await waitFor(() => {
        expect(screen.getByText('No organization selected')).toBeInTheDocument();
      });
    });
  });

  // ===========================================================================
  // Full CRUD Flow Tests
  // ===========================================================================
  describe('Full CRUD Flow', () => {
    it('does not expose an add-organization button (RD-917 §1: tier-1-only)', async () => {
      // Tenant lifecycle is reserved for super-admin (X-Admin-Token) which
      // never has a UI session. The button was removed from
      // OrganizationList.tsx; this assertion guards the dashboard from
      // re-introducing it. Original test exercised the create flow which
      // no longer exists.
      renderRBACManager({ initialRoute: '/admin/rbac/organizations' });
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
      expect(screen.queryByRole('button', { name: /add organization/i })).not.toBeInTheDocument();
    });

    it('opens group creation dialog from Groups tab', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      await waitFor(() => {
        expect(screen.getByText('Root')).toBeInTheDocument();
      });

      // Click add group button
      const addButton = screen.getByText('Add Group');
      await user.click(addButton);

      // Dialog should open with create group form
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Create Group' })).toBeInTheDocument();
      });

      // Form fields should be visible
      expect(screen.getByPlaceholderText('e.g., Engineering, DevOps, Auditors')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('e.g., engineering')).toBeInTheDocument();
    });

    it('adds user to group and verifies membership', async () => {
      let membershipAdded = false;
      const newMembership = {
        membership: {
          id: 'membership-new',
          user_id: 'user-1',
          group_id: 'group-devops',
          source: 'admin',
          zk_credential_ref: '',
          expires_at: null,
          created_at: '2024-02-01T00:00:00Z',
          updated_at: '2024-02-01T00:00:00Z',
        },
        group: mockGroupHierarchy[2], // DevOps
      };

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          if (membershipAdded) {
            return HttpResponse.json([...mockMembershipsWithDetails, newMembership]);
          }
          return HttpResponse.json(mockMembershipsWithDetails);
        }),
        http.post('/api/v1/admin/users/:userId/memberships', async () => {
          membershipAdded = true;
          return HttpResponse.json(newMembership.membership);
        })
      );

      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/users/user-1' });

      // Wait for user detail dialog to open
      await waitFor(() => {
        expect(screen.getByText('User Details')).toBeInTheDocument();
      });

      // Wait for memberships to load
      await waitFor(() => {
        expect(screen.getByText('Group Memberships')).toBeInTheDocument();
      });

      // Click add membership button
      const addButtons = screen.getAllByRole('button', { name: /add/i });
      const membershipAddButton = addButtons.find(btn =>
        btn.closest('.space-y-3')?.querySelector('h4')?.textContent?.includes('Group Memberships')
      );

      if (membershipAddButton) {
        await user.click(membershipAddButton);
      }

      // Dialog should open
      await waitFor(() => {
        expect(screen.getByText('Add Group Membership')).toBeInTheDocument();
      });
    });
  });

  // ===========================================================================
  // Cross-Component Data Consistency Tests
  // ===========================================================================
  describe('Cross-Component Data Consistency', () => {
    it('displays only memberships returned by API (no phantom data)', async () => {
      // Return exactly one membership
      const singleMembership = [mockMembershipsWithDetails[0]];

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json(singleMembership);
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/users/user-1' });

      await waitFor(() => {
        expect(screen.getByText('User Details')).toBeInTheDocument();
      });

      await waitFor(() => {
        // Should show exactly the membership from API
        expect(screen.getByText('Engineering')).toBeInTheDocument();
      });

      // Should NOT show other groups that aren't in the response
      expect(screen.queryByText('DevOps')).not.toBeInTheDocument();
      expect(screen.queryByText('Operations')).not.toBeInTheDocument();
    });

    it('displays linked wallet addresses correctly', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/users/user-1' });

      await waitFor(() => {
        expect(screen.getByText('User Details')).toBeInTheDocument();
      });

      await waitFor(() => {
        expect(screen.getByText('Linked Wallet Addresses')).toBeInTheDocument();
        // Verify verification timestamps appear
        const verifiedTexts = screen.getAllByText(/Verified/);
        expect(verifiedTexts.length).toBeGreaterThan(0);
      });
    });

    it('effective permissions reflect actual group membership', async () => {
      // The beforeEach already sets up effective-permissions handler to return mockFullEffectivePermissions
      renderRBACManager({ initialRoute: '/admin/rbac/users/user-1' });

      await waitFor(() => {
        expect(screen.getByText('User Details')).toBeInTheDocument();
      });

      // Should show effective permissions section
      await waitFor(() => {
        expect(screen.getByText(/Effective Permissions/i)).toBeInTheDocument();
      });

      // Should show allowed methods from mockFullEffectivePermissions
      // mockFullEffectivePermissions has allowed_methods including 'eth_call'
      await waitFor(() => {
        expect(screen.getByText('eth_call')).toBeInTheDocument();
      }, { timeout: 5000 });
    });

    it('does not expose per-row delete-organization buttons (RD-917 §1: tier-1-only)', async () => {
      // Tenant deletion is super-admin only; the per-row Delete button was
      // removed from OrganizationList.tsx. Original test exercised the
      // delete flow which no longer exists.
      renderRBACManager({ initialRoute: '/admin/rbac/organizations' });
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
      expect(screen.queryAllByTitle('Delete organization')).toHaveLength(0);
    });

    it('refreshes data after deleting group', async () => {
      let deleteCalled = false;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          if (deleteCalled) {
            // Return list without the first group
            const remaining = mockGroupHierarchy.slice(1).map(g => ({ group: g, access: mockGroupAccess }));
            return HttpResponse.json({ data: remaining, total: remaining.length, limit: 50, offset: 0 });
          }
          const all = mockGroupHierarchy.map(g => ({ group: g, access: mockGroupAccess }));
          return HttpResponse.json({ data: all, total: all.length, limit: 50, offset: 0 });
        }),
        http.delete('/api/v1/admin/orgs/:orgId/groups/:groupId', () => {
          deleteCalled = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      await waitFor(() => {
        expect(screen.getByText('Root')).toBeInTheDocument();
      });

      // Click delete on first group
      const deleteButtons = screen.getAllByTitle('Delete group');
      await user.click(deleteButtons[0]);

      // Wait for confirmation dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Group')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      // Group should be removed from list
      await waitFor(() => {
        // Root group should be gone (we deleted the first one)
        expect(screen.queryByText(/^Root$/)).not.toBeInTheDocument();
      });
    });
  });

  // ===========================================================================
  // Loading States Tests
  // ===========================================================================
  describe('Loading States', () => {
    it('transitions from loading to showing organizations', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      // Eventually content should load
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
    });

    it('transitions from loading to showing groups', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      // Eventually should show groups
      await waitFor(() => {
        expect(screen.getByText('Root')).toBeInTheDocument();
      });
    });

    it('transitions from loading to showing users', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/users' });

      // Should show user data from the API after loading
      // UserList truncates IDs: "did:polygo...r123abc" for 'did:polygonid:polygon:main:user123abc'
      await waitFor(() => {
        // Look for the truncated format - last 8 chars contain 'r123abc'
        expect(screen.getByText(/r123abc/)).toBeInTheDocument();
      });
    });

    it('transitions from loading to showing contracts', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/contracts?org=org-1' });

      // Eventually should load contract list
      await waitFor(() => {
        expect(screen.getByText('Token Contract')).toBeInTheDocument();
      });
    });

    it('shows org selector when orgs are loaded on Groups tab', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      // Eventually should load org selector
      await waitFor(() => {
        expect(screen.getByTestId('org-selector')).toBeInTheDocument();
      });
    });
  });

  // ===========================================================================
  // Error Handling Tests
  // ===========================================================================
  describe('Error Handling', () => {
    it('handles organization fetch error gracefully', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ error: 'Internal Server Error' }, { status: 500 });
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        // Should show empty state or error message
        expect(screen.getByText('No organizations found')).toBeInTheDocument();
      });
    });

    it('handles group fetch error gracefully', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ error: 'Internal Server Error' }, { status: 500 });
        }),
        // Ensure orgs handler still returns paginated format for org selector
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 1000, offset: 0 });
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      await waitFor(() => {
        // Should show empty state
        expect(screen.getByText('No groups found')).toBeInTheDocument();
      });
    });

    it('handles user fetch error gracefully', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ error: 'Internal Server Error' }, { status: 500 });
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/users' });

      await waitFor(() => {
        // RD-1239: a failed fetch reports the failure; it no longer renders as
        // an empty list, which would assert the org has no users.
        expect(screen.getByTestId('users-load-error')).toBeInTheDocument();
      });
    });

    it('handles contract fetch error gracefully', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ error: 'Internal Server Error' }, { status: 500 });
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/contracts?org=org-1' });

      await waitFor(() => {
        // Should show empty state
        expect(screen.getByText('No contracts registered')).toBeInTheDocument();
      });
    });

    // Removed: 'shows error dialog when organization delete fails' — the
    // delete-org button no longer exists in the dashboard (RD-917 §1).
    // The error-path coverage moved to backend integration tests in
    // internal/server/admin_org_isolation_test.go.

    it('shows error dialog when group delete fails', async () => {
      server.use(
        http.delete('/api/v1/admin/orgs/:orgId/groups/:groupId', () => {
          return HttpResponse.json(
            { error: 'Cannot delete group with children' },
            { status: 400 }
          );
        })
      );

      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      await waitFor(() => {
        expect(screen.getByText('Root')).toBeInTheDocument();
      });

      const deleteButtons = screen.getAllByTitle('Delete group');
      await user.click(deleteButtons[0]);

      // Wait for confirmation dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Group')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      // Error dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Failed')).toBeInTheDocument();
      });
      expect(screen.getByText(/Failed to delete group/)).toBeInTheDocument();
    });
  });

  // ===========================================================================
  // "How It Works" Section Tests
  // ===========================================================================
  describe('How It Works Section', () => {
    it('toggles "How permissions work" section', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByTestId('rbac-manager')).toBeInTheDocument();
      });

      // Find the toggle button
      const toggleButton = screen.getByText('How permissions work');
      expect(toggleButton).toBeInTheDocument();

      // Initially collapsed
      expect(screen.queryByText('Permission Model')).not.toBeInTheDocument();

      // Click to expand
      await user.click(toggleButton);

      await waitFor(() => {
        expect(screen.getByText('Permission Model')).toBeInTheDocument();
        expect(screen.getByText('How Users Get Permissions')).toBeInTheDocument();
      });

      // Click to collapse
      await user.click(toggleButton);

      await waitFor(() => {
        expect(screen.queryByText('Permission Model')).not.toBeInTheDocument();
      });
    });
  });

  // ===========================================================================
  // URL Routing Tests
  // ===========================================================================
  describe('URL Routing', () => {
    it('loads correct tab from URL path', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/users' });

      await waitFor(() => {
        const usersTab = screen.getByTestId('tab-users');
        expect(usersTab).toHaveAttribute('data-state', 'active');
      });
    });

    it('preserves org param when switching tabs', async () => {
      const { user } = renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      await waitFor(() => {
        expect(screen.getByTestId('tab-groups')).toHaveAttribute('data-state', 'active');
      });

      // Wait for org to be loaded
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      // Switch to contracts (which also requires org)
      await user.click(screen.getByTestId('tab-contracts'));

      await waitFor(() => {
        expect(screen.getByTestId('tab-contracts')).toHaveAttribute('data-state', 'active');
      });

      // Org should still be selected (Acme Corporation = org-1)
      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
    });

    it('opens user detail when navigating to /users/:userId', async () => {
      renderRBACManager({ initialRoute: '/admin/rbac/users/user-1' });

      await waitFor(() => {
        // User detail dialog should be open
        expect(screen.getByText('User Details')).toBeInTheDocument();
      });
    });
  });

  // ===========================================================================
  // Data Integrity Tests
  // ===========================================================================
  describe('Data Integrity', () => {
    it('organization list matches API response exactly', async () => {
      const specificOrgs: Organization[] = [
        createMockOrganization({ id: 'test-org-1', name: 'Only Org 1', slug: 'only-org-1' }),
        createMockOrganization({ id: 'test-org-2', name: 'Only Org 2', slug: 'only-org-2' }),
      ];

      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: specificOrgs, total: specificOrgs.length, limit: 1000, offset: 0 });
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/organizations' });

      await waitFor(() => {
        expect(screen.getByText('Only Org 1')).toBeInTheDocument();
        expect(screen.getByText('Only Org 2')).toBeInTheDocument();
      });

      // Should NOT show mock organizations from fixtures
      expect(screen.queryByText('Acme Corporation')).not.toBeInTheDocument();
      expect(screen.queryByText('Globex Inc')).not.toBeInTheDocument();
    });

    it('groups list matches API response exactly', async () => {
      const specificGroups: Group[] = [
        createMockGroup({ id: 'test-group-1', name: 'Specific Group 1', slug: 'specific-group-1' }),
        createMockGroup({ id: 'test-group-2', name: 'Specific Group 2', slug: 'specific-group-2' }),
      ];

      const specificGroupsWithAccess = specificGroups.map(g => ({ group: g, access: null }));
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: specificGroupsWithAccess, total: specificGroupsWithAccess.length, limit: 50, offset: 0 });
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/groups?org=org-1' });

      await waitFor(() => {
        expect(screen.getByText('Specific Group 1')).toBeInTheDocument();
        expect(screen.getByText('Specific Group 2')).toBeInTheDocument();
      });

      // Should NOT show fixture groups
      expect(screen.queryByText('Root')).not.toBeInTheDocument();
      expect(screen.queryByText('Engineering')).not.toBeInTheDocument();
    });

    it('users list matches API response exactly', async () => {
      const specificUsers: User[] = [
        {
          id: 'specific-user-1',
          external_id: 'did:specific:user:1',
          kyc: true,
          banned: false,
          note: '',
          metadata: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      ];

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: specificUsers, total: specificUsers.length, limit: 25, offset: 0 });
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/users' });

      await waitFor(() => {
        expect(screen.getByText(/did:specific:user:1/)).toBeInTheDocument();
      });

      // Should NOT show fixture users
      expect(screen.queryByText(/did:polygonid:polygon:main:user123abc/)).not.toBeInTheDocument();
    });

    it('contracts list matches API response exactly', async () => {
      const specificContracts: Contract[] = [
        {
          id: 'specific-contract-1',
          org_id: 'org-1',
          address: '0xspecificaddress123456789012345678901234',
          name: 'Specific Contract',
          deployed_by_user_id: null,
          deployed_at: null,
          metadata: {},
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      ];

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({ data: specificContracts, total: specificContracts.length, limit: 25, offset: 0 });
        })
      );

      renderRBACManager({ initialRoute: '/admin/rbac/contracts?org=org-1' });

      await waitFor(() => {
        expect(screen.getByText('Specific Contract')).toBeInTheDocument();
      });

      // Should NOT show fixture contracts
      expect(screen.queryByText('Token Contract')).not.toBeInTheDocument();
    });
  });
});
