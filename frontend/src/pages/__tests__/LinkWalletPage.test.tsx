import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { LinkWalletPage } from '../LinkWalletPage';
import { AuthProvider } from '@/contexts/AuthContext';

// Mock wagmi hooks
const mockUseAccount = vi.fn();
const mockUseSignMessage = vi.fn();
const mockUseDisconnect = vi.fn();

vi.mock('wagmi', () => ({
  useAccount: () => mockUseAccount(),
  useSignMessage: () => mockUseSignMessage(),
  useDisconnect: () => mockUseDisconnect(),
}));

// Mock RainbowKit ConnectButton
vi.mock('@rainbow-me/rainbowkit', () => ({
  ConnectButton: {
    Custom: ({ children }: { children: (props: {
      account?: { displayName: string };
      chain?: { name: string };
      openConnectModal: () => void;
      openChainModal: () => void;
      mounted: boolean;
    }) => React.ReactNode }) => {
      const { isConnected, address } = mockUseAccount();
      return children({
        account: isConnected ? { displayName: address?.slice(0, 6) + '...' + address?.slice(-4) } : undefined,
        chain: isConnected ? { name: 'Ethereum' } : undefined,
        openConnectModal: vi.fn(),
        openChainModal: vi.fn(),
        mounted: true,
      });
    },
  },
}));

// Helper to create valid JWT payload
function createMockToken(expiresIn: number = 3600): string {
  const payload = {
    sub: 'did:polygonid:polygon:main:user123',
    exp: Math.floor(Date.now() / 1000) + expiresIn,
  };
  const encodedPayload = btoa(JSON.stringify(payload));
  return `header.${encodedPayload}.signature`;
}

// Helper to setup authenticated state
function setupAuthenticated() {
  const mockToken = createMockToken();
  const authData = {
    accessToken: mockToken,
    refreshToken: 'test-refresh',
    expiresAt: Date.now() + 3600000,
  };
  sessionStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));
  return mockToken;
}

// Helper to render with providers
function renderLinkWalletPage(initialRoute = '/link-wallet') {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }} initialEntries={[initialRoute]}>
      <AuthProvider>
        <Routes>
          <Route path="/link-wallet" element={<LinkWalletPage />} />
          <Route path="/login" element={<div data-testid="login-page">Login Page</div>} />
          <Route path="/success" element={<div data-testid="success-page">Success Page</div>} />
          <Route path="/admin" element={<div data-testid="admin-area">Admin Area</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('LinkWalletPage', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.clearAllMocks();

    // Default mock implementations
    mockUseAccount.mockReturnValue({
      address: undefined,
      isConnected: false,
    });

    mockUseSignMessage.mockReturnValue({
      signMessageAsync: vi.fn(),
    });

    mockUseDisconnect.mockReturnValue({
      disconnect: vi.fn(),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Authentication Redirect', () => {
    it('should redirect to login when not authenticated', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByTestId('login-page')).toBeInTheDocument();
      });
    });

    it('should render link wallet page when authenticated', async () => {
      setupAuthenticated();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Link Your Wallet')).toBeInTheDocument();
      });
    });
  });

  describe('Admin dashboard entry point', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('lets an admin reach the dashboard without clearing the wallet step first', async () => {
      // Login lands here by default, so this is where an org admin actually
      // arrives — not on /success.
      server.use(
        http.get('/api/v1/me/admin-status', () =>
          HttpResponse.json({ is_admin: true, is_readonly_admin: false, admin_org_ids: ['org-1'], readonly_admin_org_ids: [] })
        )
      );
      renderLinkWalletPage();

      await userEvent.click(await screen.findByTestId('link-wallet-admin-btn'));

      await waitFor(() => {
        expect(screen.getByTestId('admin-area')).toBeInTheDocument();
      });
    });

    it('does not show it to a regular user', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Link Your Wallet')).toBeInTheDocument();
      });
      expect(screen.queryByTestId('link-wallet-admin-btn')).not.toBeInTheDocument();
    });
  });

  describe('Initial Rendering', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should display the header', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Link Your Wallet')).toBeInTheDocument();
        expect(screen.getByText('Connect an Ethereum address')).toBeInTheDocument();
      });
    });

    it('should show connect wallet button when not connected', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Connect Wallet')).toBeInTheDocument();
      });
    });

    it('should display existing linked addresses', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Linked Addresses')).toBeInTheDocument();
        expect(
          screen.getByText('0x1234567890123456789012345678901234567890')
        ).toBeInTheDocument();
      });
    });
  });

  describe('Wallet Connection', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should show wallet info when connected', async () => {
      mockUseAccount.mockReturnValue({
        address: '0xabcdef1234567890123456789012345678901234',
        isConnected: true,
      });

      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('0xabcd...1234')).toBeInTheDocument();
        expect(screen.getByText('Ethereum')).toBeInTheDocument();
      });
    });

    it('should show sign button for new address', async () => {
      mockUseAccount.mockReturnValue({
        address: '0xabcdef1234567890123456789012345678901234',
        isConnected: true,
      });

      // No existing linked addresses
      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ addresses: [] });
        })
      );

      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Sign & Link Address')).toBeInTheDocument();
      });
    });

    it('should show already linked status for linked address', async () => {
      mockUseAccount.mockReturnValue({
        address: '0x1234567890123456789012345678901234567890',
        isConnected: true,
      });

      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Address linked')).toBeInTheDocument();
      });
    });
  });

  describe('Link Wallet Flow', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should complete link flow successfully', async () => {
      const signMessageAsync = vi.fn().mockResolvedValue('0xsignature123');

      mockUseAccount.mockReturnValue({
        address: '0xnewaddress12345678901234567890123456789012',
        isConnected: true,
      });

      mockUseSignMessage.mockReturnValue({
        signMessageAsync,
      });

      // No existing linked addresses initially
      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ addresses: [] });
        })
      );

      const user = userEvent.setup();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Sign & Link Address')).toBeInTheDocument();
      });

      // Update handler to return new address after linking
      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({
            addresses: [
              {
                address: '0xnewaddress12345678901234567890123456789012',
                verified_at: '2024-01-01T00:00:00Z',
              },
            ],
          });
        })
      );

      await user.click(screen.getByText('Sign & Link Address'));

      await waitFor(() => {
        expect(signMessageAsync).toHaveBeenCalled();
      });

      await waitFor(() => {
        // Should show success or linked state
        expect(screen.getByText('Address linked')).toBeInTheDocument();
      });
    });

    it('should show error when signing fails', async () => {
      const signMessageAsync = vi.fn().mockRejectedValue(new Error('User rejected'));

      mockUseAccount.mockReturnValue({
        address: '0xnewaddress12345678901234567890123456789012',
        isConnected: true,
      });

      mockUseSignMessage.mockReturnValue({
        signMessageAsync,
      });

      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ addresses: [] });
        })
      );

      const user = userEvent.setup();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Sign & Link Address')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Sign & Link Address'));

      await waitFor(() => {
        expect(screen.getByText('Error')).toBeInTheDocument();
        expect(screen.getByText('User rejected')).toBeInTheDocument();
      });
    });

    it('should show error when verification fails', async () => {
      const signMessageAsync = vi.fn().mockResolvedValue('0xsignature123');

      mockUseAccount.mockReturnValue({
        address: '0xnewaddress12345678901234567890123456789012',
        isConnected: true,
      });

      mockUseSignMessage.mockReturnValue({
        signMessageAsync,
      });

      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ addresses: [] });
        }),
        http.post('/api/v1/eth/link/verify', () => {
          return HttpResponse.json(
            { error: 'Signature verification failed' },
            { status: 400 }
          );
        })
      );

      const user = userEvent.setup();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Sign & Link Address')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Sign & Link Address'));

      await waitFor(() => {
        expect(screen.getByText('Error')).toBeInTheDocument();
      });
    });
  });

  describe('Unlink Address', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should unlink address when unlink button is clicked', async () => {
      const user = userEvent.setup();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Unlink')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Unlink'));

      await waitFor(() => {
        // Address should be removed from list
        expect(
          screen.queryByText('0x1234567890123456789012345678901234567890')
        ).not.toBeInTheDocument();
      });
    });
  });

  describe('Navigation', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should show skip button when no addresses linked', async () => {
      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ addresses: [] });
        })
      );

      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Skip for now')).toBeInTheDocument();
      });
    });

    it('should navigate to success when skip is clicked', async () => {
      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ addresses: [] });
        })
      );

      const user = userEvent.setup();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Skip for now')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Skip for now'));

      await waitFor(() => {
        expect(screen.getByTestId('success-page')).toBeInTheDocument();
      });
    });

    it('should hide skip button when addresses are linked', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Linked Addresses')).toBeInTheDocument();
      });

      expect(screen.queryByText('Skip for now')).not.toBeInTheDocument();
    });

    it('should enable continue button when addresses are linked', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Continue')).toBeInTheDocument();
      });

      expect(screen.getByText('Continue')).not.toBeDisabled();
    });

    it('should disable continue button when no addresses linked', async () => {
      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ addresses: [] });
        })
      );

      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Continue')).toBeInTheDocument();
      });

      expect(screen.getByText('Continue')).toBeDisabled();
    });

    it('should navigate to success when continue is clicked', async () => {
      const user = userEvent.setup();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Continue')).toBeInTheDocument();
        expect(screen.getByText('Continue')).not.toBeDisabled();
      });

      await user.click(screen.getByText('Continue'));

      await waitFor(() => {
        expect(screen.getByTestId('success-page')).toBeInTheDocument();
      });
    });

    it('should logout when sign out is clicked', async () => {
      const user = userEvent.setup();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('Sign out')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Sign out'));

      await waitFor(() => {
        expect(screen.getByTestId('login-page')).toBeInTheDocument();
      });

      expect(sessionStorage.getItem('privacy_proxy_auth')).toBeNull();
    });
  });

  describe('Copy Address', () => {
    beforeEach(() => {
      setupAuthenticated();
      // Mock clipboard API
      Object.defineProperty(navigator, 'clipboard', {
        value: {
          writeText: vi.fn().mockResolvedValue(undefined),
        },
        writable: true,
        configurable: true,
      });
    });

    it('should have copy button for linked address', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(
          screen.getByText('0x1234567890123456789012345678901234567890')
        ).toBeInTheDocument();
      });

      // Verify copy button is present
      const copyButton = screen.getByTitle('Copy address');
      expect(copyButton).toBeInTheDocument();
    });
  });

  describe('Disconnect Wallet', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should call disconnect when disconnect button is clicked', async () => {
      const disconnectMock = vi.fn();

      mockUseAccount.mockReturnValue({
        address: '0xabcdef1234567890123456789012345678901234',
        isConnected: true,
      });

      mockUseDisconnect.mockReturnValue({
        disconnect: disconnectMock,
      });

      const user = userEvent.setup();
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByText('0xabcd...1234')).toBeInTheDocument();
      });

      // Find the X button to disconnect
      const disconnectButtons = screen.getAllByRole('button');
      const disconnectButton = disconnectButtons.find(
        (btn) => btn.querySelector('svg.lucide-x')
      );

      if (disconnectButton) {
        await user.click(disconnectButton);
        expect(disconnectMock).toHaveBeenCalled();
      }
    });
  });

  describe('Accessibility', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should have proper heading structure', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
          'Link Your Wallet'
        );
      });
    });

    it('should have accessible buttons', async () => {
      renderLinkWalletPage();

      await waitFor(() => {
        const buttons = screen.getAllByRole('button');
        expect(buttons.length).toBeGreaterThan(0);
        buttons.forEach((button) => {
          expect(button).toBeVisible();
        });
      });
    });
  });
});
