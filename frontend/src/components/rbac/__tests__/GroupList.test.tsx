import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import GroupList from '../GroupList';
import {
  mockGroupHierarchy,
  mockGroupAccessFull,
  mockGroupAccessReadOnly,
} from '@/test/mocks/rbac-fixtures';
import { mockGroup, mockGroupAccess } from '@/test/mocks/handlers';

// Mock the useOrgContext hook from RBACManager
// Note: vi.mock is hoisted, so create context inside the factory
vi.mock('../RBACManager', async () => {
  const { createContext } = await import('react');
  const { mockOrganization } = await import('@/test/mocks/handlers');
  const MockOrgContext = createContext(null);
  // Return a static context since GroupList.test.tsx doesn't use renderWithRBACContext
  return {
    OrgContext: MockOrgContext,
    useOrgContext: () => ({
      selectedOrg: mockOrganization,
      setSelectedOrg: vi.fn(),
      organizations: [mockOrganization],
      refreshOrgs: vi.fn(),
    }),
  };
});

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

// Helper to render GroupList with necessary providers
function renderGroupList() {
  const queryClient = createTestQueryClient();

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <GroupList />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

describe('GroupList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', () => {
      // Use a handler that delays response
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', async () => {
          await new Promise((resolve) => setTimeout(resolve, 100));
          return HttpResponse.json({ data: [{ group: mockGroup, access: mockGroupAccess }], total: 1, limit: 50, offset: 0 });
        })
      );

      renderGroupList();

      // The component shows loading state
      expect(document.querySelector('.animate-spin')).toBeInTheDocument();
    });

    it('shows "Groups" heading', async () => {
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Groups')).toBeInTheDocument();
      });
    });

    it('shows empty state when no groups', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 50, offset: 0 });
        })
      );

      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('No groups found')).toBeInTheDocument();
      });

      expect(screen.getByText('Create your first group')).toBeInTheDocument();
    });

    it('displays groups after loading', async () => {
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });
    });
  });

  describe('Flat List Display', () => {
    beforeEach(() => {
      // Setup groups with inline access data
      const groupsWithAccess = mockGroupHierarchy.map(g => {
        let access = mockGroupAccess;
        if (g.id === 'group-engineering') access = mockGroupAccessFull;
        else if (g.id === 'group-operations') access = mockGroupAccessReadOnly;
        return { group: g, access };
      });
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: groupsWithAccess, total: groupsWithAccess.length, limit: 50, offset: 0 });
        })
      );
    });

    it('shows all groups in a flat list', async () => {
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root')).toBeInTheDocument();
      });

      expect(screen.getByText('Engineering')).toBeInTheDocument();
      expect(screen.getByText('DevOps')).toBeInTheDocument();
    });

    it('does not indent child groups', async () => {
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Engineering')).toBeInTheDocument();
      });

      // No group card should have ml-6 (hierarchy indentation)
      const groupCards = screen.getAllByTestId('group-card');
      for (const card of groupCards) {
        const innerDiv = card.querySelector('.ml-6');
        expect(innerDiv).toBeNull();
      }
    });
  });

  describe('Actions', () => {
    it('Create button opens GroupForm dialog', async () => {
      const user = userEvent.setup();
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Add Group')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Group'));

      await waitFor(() => {
        // The dialog title is "Create Group", check for the dialog heading
        expect(screen.getByRole('heading', { name: 'Create Group' })).toBeInTheDocument();
      });
    });

    it('Edit button opens form with group data', async () => {
      const user = userEvent.setup();
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Click the edit button (Pencil icon)
      const editButton = screen.getByTitle('Edit group');
      await user.click(editButton);

      await waitFor(() => {
        expect(screen.getByText('Edit Group')).toBeInTheDocument();
      });

      // The form should be populated with group data
      expect(screen.getByDisplayValue('Root Group')).toBeInTheDocument();
    });

    it('Access button opens GroupAccessForm', async () => {
      const user = userEvent.setup();
      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Click the settings button (Settings icon for access)
      const accessButton = screen.getByTitle('Edit access settings');
      await user.click(accessButton);

      await waitFor(() => {
        expect(screen.getByText(/Edit Access for/)).toBeInTheDocument();
      });
    });

    it('Delete shows confirmation', async () => {
      const user = userEvent.setup();

      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Click the delete button
      const deleteButton = screen.getByTitle('Delete group');
      await user.click(deleteButton);

      // Confirmation dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Group')).toBeInTheDocument();
      });
      expect(screen.getByText(/Are you sure you want to delete/)).toBeInTheDocument();
    });

    it('Delete failure shows error dialog', async () => {
      const user = userEvent.setup();

      // Setup handler that returns error for delete
      server.use(
        http.delete('/api/v1/admin/orgs/:orgId/groups/:groupId', () => {
          return HttpResponse.json(
            { error: 'Cannot delete group with members' },
            { status: 400 }
          );
        })
      );

      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      const deleteButton = screen.getByTitle('Delete group');
      await user.click(deleteButton);

      // Wait for confirmation dialog and click Delete
      await waitFor(() => {
        expect(screen.getByText('Delete Group')).toBeInTheDocument();
      });
      const deleteConfirmButton = screen.getByRole('button', { name: /^delete$/i });
      await user.click(deleteConfirmButton);

      // Error dialog should appear, carrying the server's own reason rather
      // than a guess (RD-1295).
      await waitFor(() => {
        expect(screen.getByText('Delete Failed')).toBeInTheDocument();
      });
      expect(screen.getByText('Cannot delete group with members')).toBeInTheDocument();
    });
  });

  describe('Org Admin Badge', () => {
    it('shows Org Admin badge for admin groups', async () => {
      const groupsWithAccess = mockGroupHierarchy.map(g => ({ group: g, access: mockGroupAccess }));
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: groupsWithAccess, total: groupsWithAccess.length, limit: 50, offset: 0 });
        })
      );

      renderGroupList();

      await waitFor(() => {
        // The Root group in mockGroupHierarchy has is_org_admin: true
        expect(screen.getByText('Org Admin')).toBeInTheDocument();
      });
    });
  });

  describe('Methods Count Display', () => {
    it('shows methods count when group has allowed methods', async () => {
      const accessWith3Methods = {
        ...mockGroupAccess,
        allowed_methods: ['eth_call', 'eth_getBalance', 'eth_sendTransaction'],
      };
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: accessWith3Methods }], total: 1, limit: 50, offset: 0 });
        })
      );

      renderGroupList();

      await waitFor(() => {
        expect(screen.getByText('3 methods')).toBeInTheDocument();
      });
    });
  });
});
