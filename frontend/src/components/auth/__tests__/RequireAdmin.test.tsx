import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { AuthProvider } from '@/contexts/AuthContext';

vi.unmock('@/components/auth/RequireAdmin');
import { RequireAdmin } from '../RequireAdmin';

// Helpers -------------------------------------------------------------------

/** Build a fake JWT whose payload is parseable by AuthContext.parseJWT. */
function makeFakeJWT(sub: string, expiresInMs = 3_600_000): string {
  const payload = {
    sub,
    exp: Math.floor((Date.now() + expiresInMs) / 1000),
  };
  const encoded = btoa(JSON.stringify(payload));
  return `header.${encoded}.signature`;
}

/** Seed AuthContext's sessionStorage so the user appears authenticated. */
function seedAuth(token: string) {
  sessionStorage.setItem(
    'privacy_proxy_auth',
    JSON.stringify({
      accessToken: token,
      refreshToken: 'fake-refresh',
      expiresAt: Date.now() + 3_600_000,
    }),
  );
}

function renderWithAuth(children: React.ReactNode) {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AuthProvider>
        <RequireAdmin>{children}</RequireAdmin>
      </AuthProvider>
    </MemoryRouter>,
  );
}

/**
 * Renders RequireAdmin at /admin with a real /success route, so a test can
 * click an escape control and assert where it actually lands. Kept separate
 * from renderWithAuth so the existing gate tests are unaffected.
 */
function renderWithRoutes(children: React.ReactNode) {
  return render(
    <MemoryRouter
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      initialEntries={['/admin']}
    >
      <AuthProvider>
        <Routes>
          <Route path="/admin" element={<RequireAdmin>{children}</RequireAdmin>} />
          <Route path="/success" element={<div data-testid="user-dashboard">User Dashboard</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

// Tests ---------------------------------------------------------------------

describe('RequireAdmin', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it('shows spinner while checking admin status', async () => {
    const token = makeFakeJWT('did:test:admin');
    seedAuth(token);

    // Hold the response so we can observe the loading state.
    let resolveResponse!: () => void;
    const responsePromise = new Promise<void>((r) => {
      resolveResponse = r;
    });

    server.use(
      http.get('/api/v1/me/admin-status', async () => {
        await responsePromise;
        return HttpResponse.json({ is_admin: true });
      }),
    );

    renderWithAuth(<div data-testid="child">Admin Content</div>);

    // AuthProvider loads first, then RequireAdmin kicks off the API call.
    await waitFor(() => {
      expect(screen.getByText('Checking admin privileges...')).toBeInTheDocument();
    });

    // Release the response and verify children render.
    resolveResponse();
    await waitFor(() => {
      expect(screen.getByTestId('child')).toBeInTheDocument();
    });
  });

  it('renders children when user is admin', async () => {
    const token = makeFakeJWT('did:test:admin');
    seedAuth(token);

    server.use(
      http.get('/api/v1/me/admin-status', () =>
        HttpResponse.json({ is_admin: true }),
      ),
    );

    renderWithAuth(<div data-testid="child">Admin Content</div>);

    await waitFor(() => {
      expect(screen.getByTestId('child')).toBeInTheDocument();
    });
  });

  it('shows access denied when user is not admin', async () => {
    const token = makeFakeJWT('did:test:reader');
    seedAuth(token);

    server.use(
      http.get('/api/v1/me/admin-status', () =>
        HttpResponse.json({ is_admin: false }),
      ),
    );

    renderWithAuth(<div data-testid="child">Should not appear</div>);

    await waitFor(() => {
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
      expect(
        screen.getByText(
          "You don't have admin privileges. Contact your organization administrator.",
        ),
      ).toBeInTheDocument();
    });

    expect(screen.queryByTestId('child')).not.toBeInTheDocument();
  });

  it('handles API error gracefully', async () => {
    const token = makeFakeJWT('did:test:user');
    seedAuth(token);

    server.use(
      http.get('/api/v1/me/admin-status', () =>
        HttpResponse.json({ error: 'internal' }, { status: 500 }),
      ),
    );

    renderWithAuth(<div data-testid="child">Should not appear</div>);

    await waitFor(() => {
      expect(
        screen.getByText('Unable to verify admin status'),
      ).toBeInTheDocument();
    });

    expect(screen.queryByTestId('child')).not.toBeInTheDocument();
  });

  it('gives a denied non-admin a way back to the user dashboard', async () => {
    // Signing out of an admin account and back in as a regular user lands on
    // the remembered /admin URL. Without this control the denial screen is a
    // dead end and the only escape is editing the address bar. Click it: the
    // assertion has to prove where it goes, not just that it renders.
    seedAuth(makeFakeJWT('did:test:regular-user'));
    server.use(
      http.get('/api/v1/me/admin-status', () =>
        HttpResponse.json({ is_admin: false }),
      ),
    );

    renderWithRoutes(<div data-testid="child">Should not appear</div>);

    await waitFor(() => {
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('child')).not.toBeInTheDocument();

    await userEvent.click(screen.getByTestId('admin-denied-back-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('user-dashboard')).toBeInTheDocument();
    });
  });

  it('gives the same way out when the admin check errors', async () => {
    seedAuth(makeFakeJWT('did:test:regular-user'));
    server.use(
      http.get('/api/v1/me/admin-status', () =>
        HttpResponse.json({ error: 'internal' }, { status: 500 }),
      ),
    );

    renderWithRoutes(<div data-testid="child">Should not appear</div>);

    await waitFor(() => {
      expect(screen.getByText('Unable to verify admin status')).toBeInTheDocument();
    });

    await userEvent.click(screen.getByTestId('admin-error-back-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('user-dashboard')).toBeInTheDocument();
    });
  });

  it('treats a malformed is_admin value as not an admin', async () => {
    // The endpoint contract is a boolean. A truthiness check would read the
    // string "false" as admin — deny instead.
    seedAuth(makeFakeJWT('did:test:regular-user'));
    server.use(
      http.get('/api/v1/me/admin-status', () =>
        HttpResponse.json({ is_admin: 'false' }),
      ),
    );

    renderWithAuth(<div data-testid="child">Should not appear</div>);

    await waitFor(() => {
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('child')).not.toBeInTheDocument();
  });

  it('shows access denied when no access token', async () => {
    // No seedAuth call — user is not authenticated.
    renderWithAuth(<div data-testid="child">Should not appear</div>);

    await waitFor(() => {
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
    });

    expect(screen.queryByTestId('child')).not.toBeInTheDocument();
  });
});
