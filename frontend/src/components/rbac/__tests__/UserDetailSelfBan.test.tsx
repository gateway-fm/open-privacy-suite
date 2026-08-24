import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { mockUser, mockOrganization } from '@/test/mocks/handlers';
import type { User } from '@/types/rbac';

// RD-1238: UserDetail carries the second ban control — a "Banned" checkbox that
// saves through the same PUT the backend now rejects with 400 for a self-ban.
// Disable it on your own record so the form cannot be armed into a failing save.

const mockUseOrgContext = vi.fn();
vi.mock('../RBACManager', async () => {
  const { createContext } = await import('react');
  const MockOrgContext = createContext(null);
  return {
    OrgContext: MockOrgContext,
    useOrgContext: () => mockUseOrgContext(),
    useOrgContextOptional: () => mockUseOrgContext(),
  };
});

vi.mock('@/hooks/useEnsNames', () => ({
  useEnsNames: () => ({ data: {}, isLoading: false, error: null }),
}));

// Control the signed-in identity. useAuthOptional is the cosmetic-affordance
// accessor (never an auth gate), so stubbing it is the intended test seam.
const mockUserDID = vi.fn<() => string | null>(() => null);
vi.mock('@/contexts/AuthContext', async () => {
  const actual = await vi.importActual<typeof import('@/contexts/AuthContext')>(
    '@/contexts/AuthContext'
  );
  return { ...actual, useAuthOptional: () => ({ userDID: mockUserDID() }) };
});

import UserDetail from '../UserDetail';

function renderUserDetail(user: User = mockUser) {
  mockUseOrgContext.mockReturnValue({
    selectedOrg: mockOrganization,
    setSelectedOrg: vi.fn(),
    organizations: [mockOrganization],
    refreshOrgs: vi.fn(),
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <UserDetail user={user} onUpdate={vi.fn()} />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

const otherUser: User = { ...mockUser, id: 'other-user', external_id: 'did:test:someone-else' };

async function bannedCheckbox(): Promise<HTMLInputElement> {
  const label = await waitFor(() => screen.getByText('Banned'));
  const box = label.closest('label')?.querySelector('input[type="checkbox"]');
  expect(box).toBeTruthy();
  return box as HTMLInputElement;
}

describe('UserDetail self-ban guard (RD-1238)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUserDID.mockReturnValue(null);
    mockUseOrgContext.mockReturnValue({
      selectedOrg: mockOrganization,
      setSelectedOrg: vi.fn(),
      organizations: [mockOrganization],
      refreshOrgs: vi.fn(),
    });
  });

  it("disables the Banned checkbox on the signed-in admin's own record", async () => {
    mockUserDID.mockReturnValue(mockUser.external_id);
    renderUserDetail();

    expect(await bannedCheckbox()).toBeDisabled();
  });

  it('leaves the Banned checkbox editable for another user', async () => {
    mockUserDID.mockReturnValue(mockUser.external_id);
    renderUserDetail(otherUser);

    expect(await bannedCheckbox()).toBeEnabled();
  });

  it('matches the DID case-insensitively (DID casing is not semantic)', async () => {
    mockUserDID.mockReturnValue(mockUser.external_id.toUpperCase());
    renderUserDetail();

    expect(await bannedCheckbox()).toBeDisabled();
  });

  it('leaves the checkbox editable when the identity is unknown', async () => {
    // Fail-open on the affordance only — the server still rejects a real
    // self-ban, so an unknown identity must not disable an unrelated control.
    mockUserDID.mockReturnValue(null);
    renderUserDetail();

    expect(await bannedCheckbox()).toBeEnabled();
  });
});
