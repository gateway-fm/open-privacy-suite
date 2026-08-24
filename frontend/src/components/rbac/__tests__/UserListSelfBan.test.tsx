import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import { mockUsers } from '@/test/mocks/rbac-fixtures';

// RD-1238: the backend rejects banning your own account with 400. Mirror that
// client-side so the operator never sees a control that cannot do anything —
// same reasoning as ViewAsInExplorerButton's self-impersonation check.

vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

// Control the signed-in identity. useAuthOptional is the cosmetic-affordance
// accessor (never an auth gate), so stubbing it is the intended test seam.
const mockUserDID = vi.fn<() => string | null>(() => null);
vi.mock('@/contexts/AuthContext', async () => {
  const actual = await vi.importActual<typeof import('@/contexts/AuthContext')>(
    '@/contexts/AuthContext'
  );
  return {
    ...actual,
    useAuthOptional: () => ({ userDID: mockUserDID() }),
  };
});

import UserList from '../UserList';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({}),
  };
});

const self = mockUsers[0]; // did:polygonid:polygon:main:user123abc, banned: false
const other = mockUsers[1];

function serveUsers(users: typeof mockUsers) {
  server.use(
    http.get('/api/v1/admin/users', () =>
      HttpResponse.json({ data: users, total: users.length, limit: 25, offset: 0 })
    )
  );
}

describe('UserList self-ban guard (RD-1238)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUserDID.mockReturnValue(null);
  });

  it("marks the Ban button aria-disabled on the signed-in admin's own row", async () => {
    mockUserDID.mockReturnValue(self.external_id);
    serveUsers([self]);

    renderWithRBACContext(<UserList />);

    const banButton = await waitFor(() => screen.getByRole('button', { name: /ban/i }));
    expect(banButton).toHaveAttribute('aria-disabled', 'true');
    // aria-disabled, not `disabled`: the shared Button sets
    // disabled:pointer-events-none and disabled controls aren't focusable, so a
    // real `disabled` would suppress the tooltip explaining why it's inert.
    expect(banButton).not.toBeDisabled();
    expect(banButton).toHaveAttribute('title', expect.stringMatching(/own account/i));
  });

  it('exposes the reason as the button\'s accessible description', async () => {
    // The button stays focusable (aria-disabled, not `disabled`), and `title`
    // counts as its accessible description under accname — so assistive tech
    // gets the reason here without extra markup. UserDetail cannot rely on that
    // (its control is visually hidden), so it carries visible help text wired up
    // with aria-describedby instead. Pinned so removing the title regresses.
    mockUserDID.mockReturnValue(self.external_id);
    serveUsers([self]);

    renderWithRBACContext(<UserList />);

    const banButton = await waitFor(() => screen.getByRole('button', { name: /ban/i }));
    expect(banButton).toHaveAccessibleDescription(/cannot ban your own account/i);
  });

  it('leaves the Ban button actionable for other users', async () => {
    mockUserDID.mockReturnValue(self.external_id);
    serveUsers([other]);

    renderWithRBACContext(<UserList />);

    const banButton = await waitFor(() => screen.getByRole('button', { name: /ban/i }));
    expect(banButton).toBeEnabled();
    expect(banButton).not.toHaveAttribute('aria-disabled');
  });

  it('does not send the request when the own-row button is clicked', async () => {
    mockUserDID.mockReturnValue(self.external_id);
    serveUsers([self]);
    const updateSpy = vi.fn();
    server.use(
      http.put('/api/v1/admin/users/:id', async () => {
        updateSpy();
        return HttpResponse.json({ ...self, banned: true });
      })
    );

    renderWithRBACContext(<UserList />);
    const banButton = await waitFor(() => screen.getByRole('button', { name: /ban/i }));
    await userEvent.click(banButton);

    expect(updateSpy).not.toHaveBeenCalled();
  });

  it('matches the DID case-insensitively (DID casing is not semantic)', async () => {
    mockUserDID.mockReturnValue(self.external_id.toUpperCase());
    serveUsers([self]);

    renderWithRBACContext(<UserList />);

    const banButton = await waitFor(() => screen.getByRole('button', { name: /ban/i }));
    expect(banButton).toHaveAttribute('aria-disabled', 'true');
  });

  it('keeps every Ban button actionable when the identity is unknown', async () => {
    // Fail-open on the affordance only: the server gate still rejects a real
    // self-ban, so an unknown identity must not disable unrelated controls.
    mockUserDID.mockReturnValue(null);
    serveUsers([self, other]);

    renderWithRBACContext(<UserList />);

    await waitFor(() => expect(screen.getAllByRole('button', { name: /ban/i })).toHaveLength(2));
    screen
      .getAllByRole('button', { name: /ban/i })
      .forEach(b => expect(b).not.toHaveAttribute('aria-disabled'));
  });
});
