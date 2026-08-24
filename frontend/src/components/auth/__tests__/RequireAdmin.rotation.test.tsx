import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';

// The token is driven directly so the gate can be observed mid-rotation.
// Separate file from RequireAdmin.test.tsx, which exercises the real
// AuthProvider and must keep doing so.
const mockAuth: { accessToken: string | null; isLoading: boolean } = {
  accessToken: 'token-admin',
  isLoading: false,
};

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => mockAuth,
}));

const { RequireAdmin } = await import('../RequireAdmin');

function renderGate() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <RequireAdmin>
        <div data-testid="admin-child">Admin dashboard</div>
      </RequireAdmin>
    </MemoryRouter>,
  );
}

describe('RequireAdmin token rotation', () => {
  beforeEach(() => {
    mockAuth.accessToken = 'token-admin';
    mockAuth.isLoading = false;
  });

  it('closes the gate while a new token is being checked', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });

    server.use(
      http.get('/api/v1/me/admin-status', async ({ request }) => {
        if (request.headers.get('Authorization') === 'Bearer token-admin') {
          return HttpResponse.json({ is_admin: true, admin_org_ids: ['org-a'] });
        }
        await gate;
        return HttpResponse.json({ is_admin: false });
      }),
    );

    const { rerender } = renderGate();
    await waitFor(() => expect(screen.getByTestId('admin-child')).toBeInTheDocument());

    // A different identity's token arrives. The previous answer must not keep
    // the dashboard on screen while the new one is still unanswered.
    mockAuth.accessToken = 'token-regular';
    rerender(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RequireAdmin>
          <div data-testid="admin-child">Admin dashboard</div>
        </RequireAdmin>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.queryByTestId('admin-child')).not.toBeInTheDocument();
    });
    expect(screen.getByText('Checking admin privileges...')).toBeInTheDocument();

    release();
    await waitFor(() => expect(screen.getByText('Access Denied')).toBeInTheDocument());
    expect(screen.queryByTestId('admin-child')).not.toBeInTheDocument();
  });

  // The gate is a render-time decision, so it has to be asserted at render
  // time. `rerender` runs inside act(), which flushes the passive effect that
  // re-arms the gate before any query can run — so the commit this guards
  // against is already over by the time the assertions in the test above
  // execute. A child that records what it saw *while rendering* is the only
  // way to observe it.
  //
  // The recorded value is the token, not the admin context: src/test/setup.ts
  // mocks useAdmin() globally to a fixed object, so the context cannot show
  // whose org scope was in effect. The token alone is enough — the protected
  // subtree must never render while the current token's verdict is unknown.
  it('never renders children for a token the verdict was not obtained with', async () => {
    const rendersSeenBy: Array<string | null> = [];

    function Probe() {
      // mockAuth is exactly what useAuth() returns, read during render.
      rendersSeenBy.push(mockAuth.accessToken);
      return <div data-testid="admin-child">Admin dashboard</div>;
    }

    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });

    server.use(
      http.get('/api/v1/me/admin-status', async ({ request }) => {
        if (request.headers.get('Authorization') === 'Bearer token-admin') {
          return HttpResponse.json({ is_admin: true, admin_org_ids: ['org-a'] });
        }
        await gate;
        return HttpResponse.json({ is_admin: false });
      }),
    );

    // A fresh element each time: handing rerender() the identical element
    // object lets React bail out of the re-render entirely, so the effect
    // would never re-run and this test would pass without proving anything.
    const tree = () => (
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RequireAdmin>
          <Probe />
        </RequireAdmin>
      </MemoryRouter>
    );

    const { rerender } = render(tree());
    await waitFor(() => expect(screen.getByTestId('admin-child')).toBeInTheDocument());
    expect(rendersSeenBy).toEqual(['token-admin']);

    // A different identity's token arrives. token-regular is not an admin, so
    // the protected subtree must not render for it even once — not even for
    // the single commit before the re-arming effect runs.
    mockAuth.accessToken = 'token-regular';
    rerender(tree());

    expect(rendersSeenBy.filter((t) => t === 'token-regular')).toEqual([]);

    release();
    await waitFor(() => expect(screen.getByText('Access Denied')).toBeInTheDocument());
    expect(rendersSeenBy.filter((t) => t === 'token-regular')).toEqual([]);
  });
});
