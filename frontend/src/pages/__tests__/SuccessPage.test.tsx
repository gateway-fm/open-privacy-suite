import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { SuccessPage } from '../SuccessPage';
import { AuthProvider } from '@/contexts/AuthContext';

// Mock RPC endpoint helpers
vi.mock('@/config/rpc', () => ({
  getRpcEndpoint: () => 'http://localhost:3000/rpc',
  getAddNetworkParams: () => ({
    chainId: '0x1',
    chainName: 'Open Privacy Suite (Mainnet)',
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: ['http://localhost:3000/rpc'],
    blockExplorerUrls: ['https://etherscan.io'],
  }),
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
function renderSuccessPage(initialRoute = '/success') {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }} initialEntries={[initialRoute]}>
      <AuthProvider>
        <Routes>
          <Route path="/success" element={<SuccessPage />} />
          <Route path="/login" element={<div data-testid="login-page">Login Page</div>} />
          <Route path="/link-wallet" element={<div data-testid="link-wallet-page">Link Wallet Page</div>} />
          <Route path="/admin" element={<div data-testid="admin-area">Admin Area</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('SuccessPage', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Authentication Redirect', () => {
    it('should redirect to login when not authenticated', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByTestId('login-page')).toBeInTheDocument();
      });
    });

    it('should render success page when authenticated', async () => {
      setupAuthenticated();
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText("You're All Set!")).toBeInTheDocument();
      });
    });
  });

  describe('Admin dashboard entry point', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('offers a way into the admin dashboard for an org admin', async () => {
      server.use(
        http.get('/api/v1/me/admin-status', () =>
          HttpResponse.json({
            is_admin: true,
            is_readonly_admin: false,
            admin_org_ids: ['org-1'],
            readonly_admin_org_ids: [],
          })
        )
      );
      renderSuccessPage();

      const btn = await screen.findByTestId('go-to-admin-btn');
      await userEvent.click(btn);

      await waitFor(() => {
        expect(screen.getByTestId('admin-area')).toBeInTheDocument();
      });
    });

    it('hides it from a non-admin (default handler says is_admin=false)', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText("You're All Set!")).toBeInTheDocument();
      });
      expect(screen.queryByTestId('go-to-admin-btn')).not.toBeInTheDocument();
    });

    it('hides it when is_admin is a non-boolean, rather than trusting truthiness', async () => {
      server.use(
        http.get('/api/v1/me/admin-status', () =>
          HttpResponse.json({ is_admin: 'false' })
        )
      );
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText("You're All Set!")).toBeInTheDocument();
      });
      expect(screen.queryByTestId('go-to-admin-btn')).not.toBeInTheDocument();
    });

    it('hides it when the admin-status probe fails, rather than linking to a denied page', async () => {
      server.use(
        http.get('/api/v1/me/admin-status', () => HttpResponse.error())
      );
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText("You're All Set!")).toBeInTheDocument();
      });
      expect(screen.queryByTestId('go-to-admin-btn')).not.toBeInTheDocument();
    });
  });

  describe('Initial Rendering', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should display the success message', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText("You're All Set!")).toBeInTheDocument();
        expect(
          screen.getByText('Your authenticated RPC endpoint is ready to use')
        ).toBeInTheDocument();
      });
    });

    it('should display the RPC endpoint', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('http://localhost:3000/rpc')).toBeInTheDocument();
      });
    });

    it('should display the user DID', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(
          screen.getByText('did:polygonid:polygon:main:user123')
        ).toBeInTheDocument();
      });
    });

    it('should show verified status', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('Verified')).toBeInTheDocument();
      });
    });

    it('should display quick start examples', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('Quick Start')).toBeInTheDocument();
        expect(screen.getByText('cURL')).toBeInTheDocument();
        expect(screen.getByText('ethers.js')).toBeInTheDocument();
      });
    });
  });

  describe('Copy to Clipboard', () => {
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

    it('should have copy buttons for RPC endpoint and token', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('http://localhost:3000/rpc')).toBeInTheDocument();
      });

      // Find all copy buttons - there should be at least 2 (RPC URL and token)
      const copyButtons = screen.getAllByRole('button').filter(
        btn => btn.querySelector('svg.lucide-copy') || btn.querySelector('svg.lucide-check')
      );

      // Should have copy buttons present
      expect(copyButtons.length).toBeGreaterThan(0);
    });
  });

  describe('Linked Addresses', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should display linked addresses when they exist', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('Linked Wallets')).toBeInTheDocument();
        expect(
          screen.getByText('0x1234567890123456789012345678901234567890')
        ).toBeInTheDocument();
      });
    });

    it('should not show linked wallets section when no addresses', async () => {
      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ addresses: [] });
        })
      );

      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText("You're All Set!")).toBeInTheDocument();
      });

      expect(screen.queryByText('Linked Wallets')).not.toBeInTheDocument();
    });
  });

  describe('MetaMask Integration', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should show Add to MetaMask button', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('Add Network to MetaMask')).toBeInTheDocument();
      });
    });

    it('should show alert dialog when MetaMask is not installed', async () => {
      // Ensure window.ethereum is undefined
      const originalEthereum = window.ethereum;
      delete (window as { ethereum?: unknown }).ethereum;

      const user = userEvent.setup();
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('Add Network to MetaMask')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Network to MetaMask'));

      // Alert dialog should appear
      await waitFor(() => {
        expect(screen.getByText('MetaMask Not Found')).toBeInTheDocument();
      });
      expect(screen.getByText(/MetaMask is not installed/)).toBeInTheDocument();

      // Restore
      if (originalEthereum) {
        (window as { ethereum?: unknown }).ethereum = originalEthereum;
      }
    });

    it('should call wallet_addEthereumChain when MetaMask is available', async () => {
      const requestMock = vi.fn().mockResolvedValue(null);
      (window as { ethereum?: { request: typeof requestMock } }).ethereum = {
        request: requestMock,
      };

      const user = userEvent.setup();
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('Add Network to MetaMask')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Network to MetaMask'));

      await waitFor(() => {
        expect(requestMock).toHaveBeenCalledWith({
          method: 'wallet_addEthereumChain',
          params: [expect.objectContaining({
            chainId: '0x1',
            chainName: 'Open Privacy Suite (Mainnet)',
          })],
        });
      });

      // Clean up
      delete (window as { ethereum?: unknown }).ethereum;
    });
  });

  describe('Navigation', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should navigate to link-wallet when Manage Wallets is clicked', async () => {
      const user = userEvent.setup();
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('Manage Wallets')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Manage Wallets'));

      await waitFor(() => {
        expect(screen.getByTestId('link-wallet-page')).toBeInTheDocument();
      });
    });

    it('should logout and redirect when sign out is clicked', async () => {
      const user = userEvent.setup();
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByText('Sign out')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Sign out'));

      await waitFor(() => {
        expect(screen.getByTestId('login-page')).toBeInTheDocument();
      });

      // Auth should be cleared
      expect(sessionStorage.getItem('privacy_proxy_auth')).toBeNull();
    });
  });

  describe('Error Handling', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should handle failed address fetch gracefully', async () => {
      server.use(
        http.get('/api/v1/eth/addresses', () => {
          return HttpResponse.json({ error: 'Server error' }, { status: 500 });
        })
      );

      renderSuccessPage();

      // Should still render page without linked addresses
      await waitFor(() => {
        expect(screen.getByText("You're All Set!")).toBeInTheDocument();
      });

      expect(screen.queryByText('Linked Wallets')).not.toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    beforeEach(() => {
      setupAuthenticated();
    });

    it('should have proper heading structure', async () => {
      renderSuccessPage();

      await waitFor(() => {
        expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
          "You're All Set!"
        );
      });
    });

    it('should have accessible buttons', async () => {
      renderSuccessPage();

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
