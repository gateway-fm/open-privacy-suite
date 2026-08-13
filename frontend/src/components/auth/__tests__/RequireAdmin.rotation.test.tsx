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
});
