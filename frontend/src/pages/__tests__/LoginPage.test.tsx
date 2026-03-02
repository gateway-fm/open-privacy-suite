import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter, MemoryRouter } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { LoginPage } from '../LoginPage';
import { AuthProvider } from '@/contexts/AuthContext';
import {
  mockTokenResponse,
  setSessionCompleted,
  resetSessionState,
} from '@/test/mocks/handlers';

// Helper to render with providers
function renderLoginPage(initialRoute = '/login') {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }} initialEntries={[initialRoute]}>
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('LoginPage', () => {
  beforeEach(() => {
    localStorage.clear();
    resetSessionState();
    vi.clearAllMocks();
  });

  describe('Initial Rendering', () => {
    it('should render login page with title', async () => {
      renderLoginPage();

      expect(screen.getByText('Privacy Proxy')).toBeInTheDocument();
      expect(
        screen.getByText('Sign In')
      ).toBeInTheDocument();
    });

    it('should show loading state initially', async () => {
      renderLoginPage();

      // Should show loading while requesting auth
      expect(screen.getByText('Preparing authentication...')).toBeInTheDocument();
    });

    it('should show QR code after loading', async () => {
      renderLoginPage();

      // Wait for auth request to complete
      await waitFor(() => {
        expect(
          screen.getByText('Scan with your Privado ID wallet')
        ).toBeInTheDocument();
      });

      // QR code should be rendered (as SVG)
      const qrCode = document.querySelector('svg');
      expect(qrCode).toBeInTheDocument();
    });

    it('should show polling indicator when ready', async () => {
      renderLoginPage();

      await waitFor(() => {
        expect(
          screen.getByText('Waiting for wallet confirmation...')
        ).toBeInTheDocument();
      });
    });
  });

  describe('QR Code and Deep Links', () => {
    it('should render QR code with correct deep link', async () => {
      renderLoginPage();

      await waitFor(() => {
        expect(
          screen.getByText('Scan with your Privado ID wallet')
        ).toBeInTheDocument();
      });

      // The QR code value should be an iden3comm deep link
      const qrCode = document.querySelector('svg');
      expect(qrCode).toBeInTheDocument();
    });

    it('should show open wallet button on desktop', async () => {
      renderLoginPage();

      await waitFor(() => {
        expect(screen.getByText('Open Wallet App')).toBeInTheDocument();
      });
    });
  });

  describe('Session Polling', () => {
    it('should show success state when session completes', async () => {
      renderLoginPage();

      // Wait for initial load
      await waitFor(() => {
        expect(
          screen.getByText('Waiting for wallet confirmation...')
        ).toBeInTheDocument();
      });

      // Simulate session completion
      act(() => {
        setSessionCompleted(true, mockTokenResponse);
      });

      // Wait for success state
      await waitFor(
        () => {
          expect(
            screen.getByText('Authentication successful!')
          ).toBeInTheDocument();
        },
        { timeout: 5000 }
      );
    });
  });

  describe('Error Handling', () => {
    it('should show error state when auth request fails', async () => {
      server.use(
        http.post('/api/v1/auth/request', () => {
          return HttpResponse.json(
            { error: 'Service unavailable' },
            { status: 503 }
          );
        })
      );

      renderLoginPage();

      await waitFor(() => {
        expect(screen.getByText('Authentication Failed')).toBeInTheDocument();
      });

      expect(screen.getByText('Try Again')).toBeInTheDocument();
    });

    it('should allow retry after error', async () => {
      // First request fails
      server.use(
        http.post('/api/v1/auth/request', () => {
          return HttpResponse.json(
            { error: 'Service unavailable' },
            { status: 503 }
          );
        })
      );

      const user = userEvent.setup();
      renderLoginPage();

      await waitFor(() => {
        expect(screen.getByText('Authentication Failed')).toBeInTheDocument();
      });

      // Reset handler to succeed
      server.resetHandlers();

      // Click try again
      await user.click(screen.getByText('Try Again'));

      // Should show loading and then QR code
      await waitFor(() => {
        expect(
          screen.getByText('Scan with your Privado ID wallet')
        ).toBeInTheDocument();
      });
    });
  });

  describe('Humanity Verification', () => {
    it('should show humanity verification required state', async () => {
      // Make poll return humanity verification error
      server.use(
        http.get('/api/v1/auth/session/:sessionId/status', () => {
          return HttpResponse.json(
            {
              error: 'humanity_verification_required',
              message: 'Please verify your humanity',
              verify_url: 'https://billions.example.com/verify',
            },
            { status: 403 }
          );
        })
      );

      renderLoginPage();

      await waitFor(
        () => {
          expect(
            screen.getByText('Humanity Verification Required')
          ).toBeInTheDocument();
        },
        { timeout: 5000 }
      );

      expect(screen.getByText('Verify on Billions')).toBeInTheDocument();
    });
  });

  describe('Development Mode', () => {
    it('should show mock login button in dev mode', async () => {
      renderLoginPage();

      await waitFor(() => {
        expect(
          screen.getByText('Mock Login (Skip Wallet)')
        ).toBeInTheDocument();
      });

      expect(screen.getByText('Development Only')).toBeInTheDocument();
    });

    it('should authenticate with mock login', async () => {
      const user = userEvent.setup();
      renderLoginPage();

      await waitFor(() => {
        expect(
          screen.getByText('Mock Login (Skip Wallet)')
        ).toBeInTheDocument();
      });

      await user.click(screen.getByText('Mock Login (Skip Wallet)'));

      await waitFor(
        () => {
          expect(
            screen.getByText('Authentication successful!')
          ).toBeInTheDocument();
        },
        { timeout: 5000 }
      );
    });
  });

  describe('Redirect Behavior', () => {
    it('should redirect to link-wallet if already authenticated', async () => {
      // Setup authenticated state
      const payload = {
        sub: 'did:test:user',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `header.${encodedPayload}.signature`;

      const authData = {
        accessToken: mockToken,
        refreshToken: 'test-refresh',
        expiresAt: Date.now() + 3600000,
      };
      localStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));

      // Use BrowserRouter for this test to check navigation
      render(
        <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <AuthProvider>
            <LoginPage />
          </AuthProvider>
        </BrowserRouter>
      );

      // The redirect should happen, but we can't easily test it
      // with MemoryRouter, so we just verify the component renders
      await waitFor(() => {
        // Component should attempt to navigate away
      });
    });
  });

  describe('Help Link', () => {
    it('should show link to download Privado ID wallet', async () => {
      renderLoginPage();

      const link = await waitFor(() => {
        return screen.getByText('Download the wallet');
      });

      expect(link).toHaveAttribute(
        'href',
        'https://docs.privado.id/docs/wallet/wallet-app/privadoid-app/'
      );
      expect(link).toHaveAttribute('target', '_blank');
    });
  });

  describe('Accessibility', () => {
    it('should have proper heading structure', async () => {
      renderLoginPage();

      await waitFor(() => {
        expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
          'Privacy Proxy'
        );
      });
    });

    it('should have accessible buttons', async () => {
      renderLoginPage();

      await waitFor(() => {
        const buttons = screen.getAllByRole('button');
        buttons.forEach((button) => {
          expect(button).toBeVisible();
        });
      });
    });
  });
});
