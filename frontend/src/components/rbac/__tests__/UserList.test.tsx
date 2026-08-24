import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import {
  mockUsers,
  mockUserFull,
  mockUserNoKyc,
  mockUserBanned,
  createMockUser,
} from '@/test/mocks/rbac-fixtures';
import { mockUser } from '@/test/mocks/handlers';
import { useAdmin } from '@/components/auth/RequireAdmin';

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
import UserList from '../UserList';

// Mock useNavigate
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({}),
  };
});

describe('UserList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockNavigate.mockClear();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      // Set up a delayed response to see the loading state
      server.use(
        http.get('/api/v1/admin/users', async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      // Should show loading spinner (Loader2 component)
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
    });

    it('shows "Users" heading', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Users')).toBeInTheDocument();
      });
    });

    it('shows empty state when no users', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('No users found')).toBeInTheDocument();
      });

      expect(
        screen.getByText('Users are created automatically when they authenticate')
      ).toBeInTheDocument();
    });

    it('displays table with headers (External ID, Groups, KYC, Status, Created, Note, Actions)', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByRole('columnheader', { name: 'External ID' })).toBeInTheDocument();
      });

      expect(screen.getByRole('columnheader', { name: 'Groups' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'KYC' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Status' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Created' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Note' })).toBeInTheDocument();
      expect(screen.getByRole('columnheader', { name: 'Actions' })).toBeInTheDocument();
    });
  });

  describe('Groups column + filters (RD-868)', () => {
    it('renders group badges from user.groups', async () => {
      const user = createMockUser({
        id: 'user-with-groups',
        external_id: 'did:test:groupy',
        groups: [
          {
            group_id: 'g-1',
            slug: 'admins',
            name: 'Admins',
            org_id: 'org-1',
            is_org_admin: true,
          },
          {
            group_id: 'g-2',
            slug: 'members',
            name: 'Members',
            org_id: 'org-1',
            is_org_admin: false,
          },
        ],
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [user], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Admins')).toBeInTheDocument();
      });
      expect(screen.getByText('Members')).toBeInTheDocument();
    });

    it('shows em dash for users with no groups', async () => {
      const user = createMockUser({
        id: 'user-orphan',
        external_id: 'did:test:orphan',
        groups: [],
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [user], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // The em dash is rendered in the Groups cell as a placeholder.
        expect(screen.getByText('—')).toBeInTheDocument();
      });
    });

    it('forwards role param to the users-list API when filter set', async () => {
      const seenRoles: (string | null)[] = [];
      server.use(
        http.get('/api/v1/admin/users', ({ request }) => {
          const url = new URL(request.url);
          seenRoles.push(url.searchParams.get('role'));
          return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(seenRoles.length).toBeGreaterThan(0);
      });
      // First load: no role filter selected -> param absent.
      expect(seenRoles[0]).toBeNull();

      // Open the role select and choose "Org admin".
      await userEvent.click(screen.getByRole('combobox'));
      await userEvent.click(await screen.findByRole('option', { name: 'Org admin' }));

      await waitFor(() => {
        expect(seenRoles).toContain('org_admin');
      });
    });
  });

  describe('Data Display', () => {
    it('shows user external_id (DID) in row', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // DID should be displayed (possibly truncated) with title attribute
        const didElement = screen.getByTitle(mockUserFull.external_id);
        expect(didElement).toBeInTheDocument();
      });
    });

    it('truncates long DIDs appropriately', async () => {
      const longDid = 'did:polygonid:polygon:main:extremelylongidentifier1234567890abcdef';
      const userWithLongDid = createMockUser({
        id: 'user-long',
        external_id: longDid,
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [userWithLongDid], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // The component truncates DIDs longer than 20 chars to: first 10 + ... + last 8
        // The full DID should be available in the title attribute
        const didElement = screen.getByTitle(longDid);
        expect(didElement).toBeInTheDocument();
        expect(didElement.textContent).toContain('...');
      });
    });

    it('shows correct number of rows', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: mockUsers, total: mockUsers.length, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // mockUsers has 3 users
        const rows = screen.getAllByRole('row');
        // +1 for header row
        expect(rows).toHaveLength(mockUsers.length + 1);
      });
    });
  });

  describe('Status Badges', () => {
    it('KYC true shows "Verified" with checkmark', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });
    });

    it('KYC false shows "No" indicator', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserNoKyc], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('No')).toBeInTheDocument();
      });
    });

    it('Banned user shows red "Banned" badge', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserBanned], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Banned')).toBeInTheDocument();
      });
    });

    it('Non-banned users show "Active" badge', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Active')).toBeInTheDocument();
      });
    });

    it('shows both KYC and ban status correctly for multiple users', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull, mockUserNoKyc, mockUserBanned], total: 3, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // mockUserFull: KYC=true, banned=false
        // mockUserNoKyc: KYC=false, banned=false
        // mockUserBanned: KYC=true, banned=true
        expect(screen.getAllByText('Verified')).toHaveLength(2);
        expect(screen.getByText('No')).toBeInTheDocument();
        expect(screen.getAllByText('Active')).toHaveLength(2);
        expect(screen.getByText('Banned')).toBeInTheDocument();
      });
    });
  });

  describe('Actions', () => {
    it('clicking user row navigates to detail view', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      // Find the row by looking for its content and getting the parent row
      const rows = screen.getAllByRole('row');
      // First row is header, second is data row
      const dataRow = rows[1];
      await user.click(dataRow);

      expect(mockNavigate).toHaveBeenCalledWith(`/admin/rbac/users/${mockUserFull.id}`);
    });

    it('clicking ban button toggles user ban status', async () => {
      const user = userEvent.setup();

      let currentBanned = false;
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [
            { ...mockUserFull, banned: currentBanned },
          ], total: 1, limit: 25, offset: 0 });
        }),
        http.put('/api/v1/admin/users/:userId', async ({ request }) => {
          const body = (await request.json()) as { banned: boolean };
          currentBanned = body.banned;
          return HttpResponse.json({ ...mockUserFull, banned: currentBanned });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Ban')).toBeInTheDocument();
      });

      // Click ban button
      await user.click(screen.getByText('Ban'));

      await waitFor(() => {
        expect(screen.getByText('Unban')).toBeInTheDocument();
      });
    });

    it('clicking view button navigates to user detail', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      // Find and click the eye (view) button
      const viewButton = screen.getByTitle('View user details');
      await user.click(viewButton);

      expect(mockNavigate).toHaveBeenCalledWith(`/admin/rbac/users/${mockUserFull.id}`);
    });

    it('formats created date correctly', async () => {
      const userWithDate = createMockUser({
        id: 'user-date',
        created_at: '2024-03-15T10:30:00Z',
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [userWithDate], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // The component formats dates like "Mar 15, 2024"
        expect(screen.getByText('Mar 15, 2024')).toBeInTheDocument();
      });
    });
  });

  describe('Error Handling', () => {
    it('reports a failed load rather than presenting it as an empty list', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
          );
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByTestId('users-load-error')).toBeInTheDocument();
      });
      // "No users found" would state as fact something the request never
      // established.
      expect(screen.queryByText('No users found')).not.toBeInTheDocument();
      expect(screen.getByTestId('users-retry-button')).toBeInTheDocument();
    });

    it('recovers on retry after a failed load', async () => {
      const user = userEvent.setup();
      let fail = true;
      server.use(
        http.get('/api/v1/admin/users', () => {
          if (fail) {
            return HttpResponse.json({ error: 'boom' }, { status: 500 });
          }
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByTestId('users-load-error')).toBeInTheDocument();
      });

      fail = false;
      await user.click(screen.getByTestId('users-retry-button'));

      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });
      expect(screen.queryByTestId('users-load-error')).not.toBeInTheDocument();
    });
  });

  describe('User Note Display', () => {
    it('shows user note when present', async () => {
      const userWithNote = createMockUser({
        id: 'user-note',
        note: 'VIP customer',
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [userWithNote], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        expect(screen.getByText('VIP customer')).toBeInTheDocument();
      });
    });

    it('shows dash when note is empty', async () => {
      const userWithoutNote = createMockUser({
        id: 'user-no-note',
        note: '',
      });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [userWithoutNote], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        // Component shows '-' when note is empty/null
        expect(screen.getByText('-')).toBeInTheDocument();
      });
    });
  });

  // RD-1239: the users list only ever returns users who already belong to an
  // org the caller administers (backend tenant-confidentiality), so a
  // not-yet-onboarded DID can never appear in search results. Without an
  // explanation an empty result for a pasted DID reads as a broken search
  // rather than "this user doesn't exist yet — onboard them".
  describe('Onboard-by-DID discoverability (RD-1239)', () => {
    const SEARCH_DID =
      'did:iden3:privado:main:2qABCDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHi';

    // Zero results for any search, one user otherwise, so the empty state is
    // reached only via the search path.
    function serveEmptyOnSearch() {
      server.use(
        http.get('/api/v1/admin/users', ({ request }) => {
          const url = new URL(request.url);
          if (url.searchParams.get('search')) {
            return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
          }
          return HttpResponse.json({
            data: [mockUserFull],
            total: 1,
            limit: 25,
            offset: 0,
          });
        })
      );
    }

    async function search(
      user: ReturnType<typeof userEvent.setup>,
      query: string
    ) {
      const input = screen.getByPlaceholderText('Search by DID or wallet address...');
      await user.click(input);
      await user.paste(query);
    }

    afterEach(() => {
      // Restore the default (non-readonly) admin so sibling tests are unaffected.
      vi.mocked(useAdmin).mockReturnValue({
        isAdmin: true,
        isReadonlyAdmin: false,
        adminOrgIds: [],
        readonlyAdminOrgIds: [],
      });
    });

    it('shows the onboard hint when a search returns no users', async () => {
      const user = userEvent.setup();
      serveEmptyOnSearch();

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, SEARCH_DID);

      await waitFor(() => {
        expect(screen.getByTestId('users-empty-search')).toBeInTheDocument();
      });
      expect(screen.getByTestId('onboard-by-did-hint-button')).toBeInTheDocument();
      // The generic "created automatically when they authenticate" copy is
      // wrong here — it implies waiting is the answer.
      expect(
        screen.queryByText('Users are created automatically when they authenticate')
      ).not.toBeInTheDocument();
    });

    it('hint button opens the onboard dialog prefilled with the searched DID', async () => {
      const user = userEvent.setup();
      serveEmptyOnSearch();

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, SEARCH_DID);
      await user.click(await screen.findByTestId('onboard-by-did-hint-button'));

      expect(await screen.findByText('Onboard user by DID')).toBeInTheDocument();
      await waitFor(() => {
        expect(screen.getByLabelText(/User DID/i)).toHaveValue(SEARCH_DID);
      });
    });

    it('does not prefill a wallet-address search into the DID field', async () => {
      const user = userEvent.setup();
      serveEmptyOnSearch();

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      // The search box also accepts wallet addresses, which don't belong in a
      // DID field.
      await search(user, '0x1234567890123456789012345678901234567890');
      await user.click(await screen.findByTestId('onboard-by-did-hint-button'));

      expect(await screen.findByText('Onboard user by DID')).toBeInTheDocument();
      expect(screen.getByLabelText(/User DID/i)).toHaveValue('');
    });

    it('does not carry the searched DID into a later header-opened dialog', async () => {
      const user = userEvent.setup();
      serveEmptyOnSearch();

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, SEARCH_DID);
      await user.click(await screen.findByTestId('onboard-by-did-hint-button'));
      await waitFor(() => {
        expect(screen.getByLabelText(/User DID/i)).toHaveValue(SEARCH_DID);
      });

      await user.click(screen.getByRole('button', { name: /Cancel/i }));
      await waitFor(() => {
        expect(screen.queryByLabelText(/User DID/i)).not.toBeInTheDocument();
      });

      // Onboarding someone else must start from a clean field — a leftover DID
      // here would silently onboard the wrong identity.
      await user.click(screen.getByTestId('onboard-by-did-button'));
      expect(await screen.findByLabelText(/User DID/i)).toHaveValue('');
    });

    it('notes that active filters may also be hiding matches', async () => {
      const user = userEvent.setup();
      serveEmptyOnSearch();

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      // No filter yet — the hint must not claim filters are involved.
      await search(user, SEARCH_DID);
      await waitFor(() => {
        expect(screen.getByTestId('users-empty-search')).toBeInTheDocument();
      });
      expect(screen.queryByText(/filters may also be hiding/i)).not.toBeInTheDocument();

      // Apply a role filter: "never onboarded" is no longer the only explanation.
      await user.click(screen.getByRole('combobox'));
      await user.click(await screen.findByRole('option', { name: 'Org admin' }));

      await waitFor(() => {
        expect(screen.getByText(/filters may also be hiding/i)).toBeInTheDocument();
      });
    });

    it('reports a group-load failure instead of claiming the org has no groups', async () => {
      const user = userEvent.setup();
      serveEmptyOnSearch();
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => HttpResponse.error())
      );

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('onboard-by-did-button'));

      // "Create one in the Groups tab" is the wrong instruction when the list
      // simply failed to load.
      expect(await screen.findByTestId('onboard-groups-error')).toBeInTheDocument();
      expect(screen.queryByTestId('onboard-no-groups')).not.toBeInTheDocument();
    });

    it('does not show the hint when the search returns users', async () => {
      const user = userEvent.setup();
      // Return a distinguishable row for the searched query so the assertion
      // below runs against the post-search render, not the initial one.
      server.use(
        http.get('/api/v1/admin/users', ({ request }) => {
          const searched = new URL(request.url).searchParams.get('search');
          return HttpResponse.json({
            data: [
              searched
                ? { ...mockUserFull, id: 'user-searched', note: 'searched-hit' }
                : mockUserFull,
            ],
            total: 1,
            limit: 25,
            offset: 0,
          });
        })
      );

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, SEARCH_DID);

      // Proves the debounced search request landed and rendered.
      await waitFor(() => {
        expect(screen.getByText('searched-hit')).toBeInTheDocument();
      });
      expect(screen.queryByTestId('users-empty-search')).not.toBeInTheDocument();
      expect(screen.queryByTestId('onboard-by-did-hint-button')).not.toBeInTheDocument();
    });

    it('does not offer onboarding when the search request itself fails', async () => {
      const user = userEvent.setup();
      server.use(
        http.get('/api/v1/admin/users', ({ request }) => {
          if (new URL(request.url).searchParams.get('search')) {
            return HttpResponse.error();
          }
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, SEARCH_DID);

      // A failed search says nothing about whether the DID exists — offering
      // onboarding here would invite a duplicate membership.
      await waitFor(() => {
        expect(screen.getByTestId('users-load-error')).toBeInTheDocument();
      });
      expect(screen.queryByTestId('users-empty-search')).not.toBeInTheDocument();
      expect(screen.queryByTestId('onboard-by-did-hint-button')).not.toBeInTheDocument();
    });

    it('offers no onboard action to a read-only admin, but still explains why search is empty', async () => {
      vi.mocked(useAdmin).mockReturnValue({
        isAdmin: true,
        isReadonlyAdmin: true,
        adminOrgIds: [],
        readonlyAdminOrgIds: ['org-1'],
      });
      const user = userEvent.setup();
      serveEmptyOnSearch();

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, SEARCH_DID);

      await waitFor(() => {
        expect(screen.getByTestId('users-empty-search')).toBeInTheDocument();
      });
      // RD-866: read-only admins get no mutating affordance — not the header
      // button, and not the hint's.
      expect(screen.queryByTestId('onboard-by-did-hint-button')).not.toBeInTheDocument();
      expect(screen.queryByTestId('onboard-by-did-button')).not.toBeInTheDocument();
    });
  });

  // Out-of-order search responses are not a cosmetic glitch here: a stale empty
  // page rendered against the *current* query makes the RD-1239 hint claim the
  // searched DID was never onboarded, and prefills the onboard dialog with it —
  // inviting a duplicate membership for a user who does exist.
  //
  // The 300ms debounce coalesces keystrokes, so simply pasting A then B issues
  // ONE request for B. Every test below therefore waits for A to actually reach
  // the server (proving two requests are genuinely in flight) before
  // superseding it — otherwise the test would pass without reproducing anything.
  describe('Superseded search responses (RD-1239)', () => {
    const DID_A =
      'did:iden3:privado:main:2qAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAA';
    const DID_B =
      'did:iden3:privado:main:2qBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbbBBBB';
    const matched = { ...mockUserFull, external_id: DID_B };
    const B_ROW = new RegExp(DID_B.slice(-8));

    async function search(
      user: ReturnType<typeof userEvent.setup>,
      query: string
    ) {
      const input = screen.getByPlaceholderText('Search by DID or wallet address...');
      await user.click(input);
      await user.clear(input);
      await user.paste(query);
    }

    // Holds A until released and answers B either immediately or on release.
    // `seen` records every search actually issued, so a test can prove A was
    // in flight before B superseded it.
    function serveOutOfOrder(bImmediate: boolean, aResponse: () => Response) {
      const seen: string[] = [];
      let releaseA: () => void = () => {};
      let releaseB: () => void = () => {};
      const aGate = new Promise<void>(r => { releaseA = r; });
      const bGate = new Promise<void>(r => { releaseB = r; });

      server.use(
        http.get('/api/v1/admin/users', async ({ request }) => {
          const q = new URL(request.url).searchParams.get('search') ?? '';
          seen.push(q);
          if (q === DID_A) {
            await aGate;
            return aResponse();
          }
          if (q === DID_B) {
            if (!bImmediate) await bGate;
            return HttpResponse.json({ data: [matched], total: 1, limit: 25, offset: 0 });
          }
          return HttpResponse.json({ data: [mockUserFull], total: 1, limit: 25, offset: 0 });
        })
      );
      return { seen, releaseA: () => releaseA(), releaseB: () => releaseB() };
    }

    it('a slow empty response for a superseded query does not overwrite the current match', async () => {
      const user = userEvent.setup();
      const { seen, releaseA } = serveOutOfOrder(true, () =>
        HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 })
      );

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, DID_A);
      // Precondition: A really is in flight (past the debounce), so B genuinely
      // supersedes an outstanding request rather than replacing a queued one.
      await waitFor(() => {
        expect(seen).toContain(DID_A);
      });

      await search(user, DID_B);
      await waitFor(() => {
        expect(screen.getByText(B_ROW)).toBeInTheDocument();
      });

      // Only now does the superseded request answer, with an empty page.
      releaseA();

      // It must not blank B's result, and must not fire the onboarding hint —
      // which would tell the admin that DID_B has never been onboarded.
      await waitFor(() => {
        expect(screen.getByText(B_ROW)).toBeInTheDocument();
      });
      expect(screen.queryByTestId('users-empty-search')).not.toBeInTheDocument();
      expect(screen.queryByTestId('onboard-by-did-hint-button')).not.toBeInTheDocument();
    });

    it('a stale failure does not replace a current successful result', async () => {
      const user = userEvent.setup();
      const { seen, releaseA } = serveOutOfOrder(true, () => HttpResponse.error());

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, DID_A);
      await waitFor(() => {
        expect(seen).toContain(DID_A);
      });

      await search(user, DID_B);
      await waitFor(() => {
        expect(screen.getByText(B_ROW)).toBeInTheDocument();
      });

      releaseA();

      // The superseded request's catch branch must not raise the error state
      // over the result the admin is currently looking at.
      await waitFor(() => {
        expect(screen.getByText(B_ROW)).toBeInTheDocument();
      });
      expect(screen.queryByTestId('users-load-error')).not.toBeInTheDocument();
    });

    it('a stale response does not clear the spinner while the current request is in flight', async () => {
      const user = userEvent.setup();
      const { seen, releaseA, releaseB } = serveOutOfOrder(false, () =>
        HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 })
      );

      renderWithRBACContext(<UserList />);
      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });

      await search(user, DID_A);
      await waitFor(() => {
        expect(seen).toContain(DID_A);
      });

      await search(user, DID_B);
      await waitFor(() => {
        expect(seen).toContain(DID_B);
      });

      // Land A while B is still outstanding: a stale `finally` must not report
      // the view as settled, which would flash A's empty page (and the hint)
      // for query B.
      releaseA();
      await waitFor(() => {
        expect(document.querySelector('.animate-spin')).toBeInTheDocument();
      });
      expect(screen.queryByTestId('users-empty-search')).not.toBeInTheDocument();
      expect(screen.queryByTestId('onboard-by-did-hint-button')).not.toBeInTheDocument();

      releaseB();
      await waitFor(() => {
        expect(screen.getByText(B_ROW)).toBeInTheDocument();
      });
    });
  });

  describe('Ban/Unban Button States', () => {
    it('shows "Ban" button for active users', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [{ ...mockUserFull, banned: false }], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        const banButton = screen.getByTitle('Ban this user');
        expect(banButton).toBeInTheDocument();
        expect(screen.getByText('Ban')).toBeInTheDocument();
      });
    });

    it('shows "Unban" button for banned users', async () => {
      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [{ ...mockUserBanned, banned: true }], total: 1, limit: 25, offset: 0 });
        })
      );

      renderWithRBACContext(<UserList />);

      await waitFor(() => {
        const unbanButton = screen.getByTitle('Unban this user');
        expect(unbanButton).toBeInTheDocument();
        expect(screen.getByText('Unban')).toBeInTheDocument();
      });
    });
  });
});
