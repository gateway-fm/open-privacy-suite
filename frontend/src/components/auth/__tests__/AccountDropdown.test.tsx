import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from '@/contexts/AuthContext';
import { AccountDropdown } from '../AccountDropdown';

/** Build a fake JWT whose payload is parseable by AuthContext.parseJWT. */
function makeFakeJWT(sub: string, expiresInMs = 3_600_000): string {
  const payload = {
    sub,
    exp: Math.floor((Date.now() + expiresInMs) / 1000),
  };
  return `header.${btoa(JSON.stringify(payload))}.signature`;
}

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

function renderDropdown() {
  return render(
    <MemoryRouter
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      initialEntries={['/admin/rbac']}
    >
      <AuthProvider>
        <Routes>
          <Route path="/admin/rbac" element={<AccountDropdown />} />
          <Route path="/success" element={<div data-testid="user-dashboard">User Dashboard</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('AccountDropdown', () => {
  beforeEach(() => {
    sessionStorage.clear();
    seedAuth(makeFakeJWT('did:test:org-admin'));
  });

  it('returns an admin to the user dashboard', async () => {
    // The counterpart to the "Admin dashboard" button on the user page: an
    // admin who switched into the dashboard must not have to edit the URL to
    // get back out.
    renderDropdown();

    await userEvent.click(screen.getByTestId('account-dropdown-trigger'));
    await userEvent.click(screen.getByTestId('back-to-app-link'));

    await waitFor(() => {
      expect(screen.getByTestId('user-dashboard')).toBeInTheDocument();
    });
  });

  it('closes the menu when the entry is used', async () => {
    renderDropdown();

    await userEvent.click(screen.getByTestId('account-dropdown-trigger'));
    expect(screen.getByTestId('account-dropdown-menu')).toBeInTheDocument();

    await userEvent.click(screen.getByTestId('back-to-app-link'));

    await waitFor(() => {
      expect(screen.queryByTestId('account-dropdown-menu')).not.toBeInTheDocument();
    });
  });
});
