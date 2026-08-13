import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
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
    // dead end and the only escape is editing the address bar.
    seedAuth(makeFakeJWT('did:test:regular-user'));
    server.use(
      http.get('/api/v1/me/admin-status', () =>
        HttpResponse.json({ is_admin: false }),
      ),
    );

    renderWithAuth(<div data-testid="child">Should not appear</div>);

    await waitFor(() => {
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
    });
    expect(screen.getByTestId('admin-denied-back-btn')).toBeInTheDocument();
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
