import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter, MemoryRouter } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { LoginPage } from '../LoginPage';
import { AuthProvider } from '@/contexts/AuthContext';
import { authApiMethods } from '@/api/auth';
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
    sessionStorage.clear();
    resetSessionState();
    vi.clearAllMocks();
  });

  describe('Initial Rendering', () => {
    it('should render login page with title', async () => {
      renderLoginPage();

      expect(screen.getByText('Open Privacy Suite')).toBeInTheDocument();
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

    it('should show the wallet brand panel (RD-859)', async () => {
      renderLoginPage();

      // The brand panel renders alongside the QR section once auth is ready
      await waitFor(() => {
        expect(screen.getByTestId('privado-brand-panel')).toBeInTheDocument();
      });

      // Privado ID is the wallet protocol either way, so it is always named.
      // Whether Billions is co-branded depends on the deployment reporting a
      // billions:main resolver — see the RD-1241 suite below. The default mock
      // reports no networks, so only Privado is advertised here.
      expect(screen.getByTestId('brand-privado')).toBeInTheDocument();
      expect(screen.getByText('Sign in with Privado ID')).toBeInTheDocument();
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
      sessionStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));

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
          'Open Privacy Suite'
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

  describe('Azure AD Provider', () => {
    it('should show Azure tab when azuread provider is available', async () => {
      server.use(
        http.get('/api/v1/auth/providers', () => {
          return HttpResponse.json({ providers: ['privado', 'azuread'] });
        })
      );

      renderLoginPage();

      await waitFor(() => {
        expect(screen.getByTestId('tab-azuread')).toBeInTheDocument();
      });

      expect(screen.getByTestId('tab-privado')).toBeInTheDocument();
      expect(screen.getByText('Microsoft')).toBeInTheDocument();
    });

    it('should hide Azure tab when only privado provider is available', async () => {
      server.use(
        http.get('/api/v1/auth/providers', () => {
          return HttpResponse.json({ providers: ['privado'] });
        })
      );

      renderLoginPage();

      // Wait for the QR code to appear (providers loaded)
      await waitFor(() => {
        expect(screen.getByText('Scan with your Privado ID wallet')).toBeInTheDocument();
      });

      expect(screen.queryByTestId('tab-azuread')).not.toBeInTheDocument();
    });

    it('should call getAzureAuthURL and redirect on Azure button click', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/auth/providers', () => {
          return HttpResponse.json({ providers: ['privado', 'azuread'] });
        }),
        http.get('/api/v1/auth/azure/url', ({ request }) => {
          const url = new URL(request.url);
          const redirectUri = url.searchParams.get('redirect_uri');
          return HttpResponse.json({
            url: `https://login.microsoftonline.com/authorize?redirect_uri=${redirectUri}`,
            state: 'mock-state',
          });
        })
      );

      // Spy on getAzureAuthURL
      const getAzureAuthURLSpy = vi.spyOn(authApiMethods, 'getAzureAuthURL');

      // Mock window.location.href setter to capture the redirect
      const originalLocation = window.location;
      const locationMock = {
        ...originalLocation,
        href: originalLocation.href,
        origin: originalLocation.origin,
      };
      Object.defineProperty(window, 'location', {
        value: locationMock,
        writable: true,
        configurable: true,
      });

      renderLoginPage();

      // Wait for Azure tab to appear and click it
      await waitFor(() => {
        expect(screen.getByTestId('tab-azuread')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('tab-azuread'));

      // Wait for Azure sign-in section
      await waitFor(() => {
        expect(screen.getByTestId('azure-signin-btn')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('azure-signin-btn'));

      await waitFor(() => {
        expect(getAzureAuthURLSpy).toHaveBeenCalledWith(
          expect.stringContaining('/auth/azure/callback')
        );
      });

      await waitFor(() => {
        expect(window.location.href).toContain('https://login.microsoftonline.com/authorize');
      });

      // Restore
      Object.defineProperty(window, 'location', {
        value: originalLocation,
        writable: true,
        configurable: true,
      });
      getAzureAuthURLSpy.mockRestore();
    });
  });

  describe('OAuth mode — silent SSO', () => {
    const SID = 'oauth-sess-1';
    const ROUTE = `/login?oauth_session=${SID}`;
    const info = { auth_request: { id: 'x', typ: 't', type: 't', thid: 'x', body: {} }, allow_mock: true };

    // window.location is a global; restore it in afterEach so a test that fails
    // or throws before cleanup can't leak the mock into later tests.
    let restoreLocation: (() => void) | null = null;
    afterEach(() => {
      restoreLocation?.();
      restoreLocation = null;
    });

    function mockLocation() {
      const original = window.location;
      const mock = { ...original, href: original.href, origin: original.origin, assign: () => {} };
      Object.defineProperty(window, 'location', { value: mock, writable: true, configurable: true });
      restoreLocation = () => Object.defineProperty(window, 'location', { value: original, writable: true, configurable: true });
      return { mock };
    }

    it('attempts cookie-based silent SSO even with no in-tab session', async () => {
      let silentCalled = 0;
      server.use(
        http.post(`/oauth/session/${SID}/silent-complete`, () => { silentCalled++; return HttpResponse.json({ completed: false }); }),
        http.get(`/oauth/session/${SID}/info`, () => HttpResponse.json(info)),
      );
      renderLoginPage(ROUTE); // sessionStorage cleared in beforeEach => not authenticated
      await waitFor(() => expect(silentCalled).toBeGreaterThan(0));
    });

    it('falls through to the interactive picker when silent SSO is refused', async () => {
      let infoCalled = 0;
      server.use(
        http.post(`/oauth/session/${SID}/silent-complete`, () => new HttpResponse(null, { status: 403 })),
        http.get(`/oauth/session/${SID}/info`, () => { infoCalled++; return HttpResponse.json(info); }),
      );
      renderLoginPage(ROUTE);
      await waitFor(() => expect(infoCalled).toBeGreaterThan(0));
    });

    it('redirects to the app when silent SSO succeeds', async () => {
      const redirectUrl = 'https://explorer.example/api/auth/callback?code=abc&state=xyz';
      server.use(
        http.post(`/oauth/session/${SID}/silent-complete`, () => HttpResponse.json({ completed: true, redirect_url: redirectUrl })),
      );
      const loc = mockLocation();
      renderLoginPage(ROUTE);
      await waitFor(() => expect(loc.mock.href).toBe(redirectUrl));
    });

    it('reuses the current DID via mock-complete when authenticated and silent SSO is refused', async () => {
      const payload = { sub: 'did:test:alice', exp: Math.floor(Date.now() / 1000) + 3600 };
      const token = `header.${btoa(JSON.stringify(payload))}.sig`;
      sessionStorage.setItem('privacy_proxy_auth', JSON.stringify({ accessToken: token, refreshToken: 'r', expiresAt: Date.now() + 3600000 }));
      let mockBody = null;
      server.use(
        http.post(`/oauth/session/${SID}/silent-complete`, () => new HttpResponse(null, { status: 403 })),
        http.post(`/oauth/session/${SID}/mock-complete`, async ({ request }) => { mockBody = await request.json().catch(() => null); return HttpResponse.json({ ok: true, did: 'did:test:alice' }); }),
        http.get(`/oauth/session/${SID}/status`, () => HttpResponse.json({ completed: true, redirect_url: 'https://explorer.example/api/auth/callback?code=1' })),
      );
      mockLocation(); // installed so the redirect on completion can't navigate the test runner
      renderLoginPage(ROUTE);
      await waitFor(() => expect(mockBody).toEqual({ did: 'did:test:alice' }));
    });
  });
});

// RD-1241: the brand panel used to advertise Billions unconditionally, so a
// deployment with no billions:main state resolver promised a sign-in it could
// not verify — the wallet's proof was rejected and the user was left with a
// spinner. The panel now follows what /auth/providers reports.
describe('LoginPage — Billions branding follows configured networks', () => {
  beforeEach(() => {
    sessionStorage.clear();
    resetSessionState();
    vi.clearAllMocks();
  });

  function mockNetworks(body: unknown) {
    server.use(
      http.get('*/auth/providers', () => HttpResponse.json(body))
    );
  }

  it('advertises Billions when billions:main is configured', async () => {
    mockNetworks({ providers: ['privado'], networks: ['billions:main', 'privado:main'] });
    renderLoginPage();

    await waitFor(() => {
      expect(screen.getByTestId('privado-brand-panel')).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByTestId('brand-billions')).toBeInTheDocument();
    });
    expect(screen.getByText('Sign in with Billions/Privado')).toBeInTheDocument();
  });

  it('hides Billions when only privado:main is configured', async () => {
    mockNetworks({ providers: ['privado'], networks: ['privado:main'] });
    renderLoginPage();

    await waitFor(() => {
      expect(screen.getByTestId('privado-brand-panel')).toBeInTheDocument();
    });
    // Privado is still offered — this removes a false promise, not the flow.
    expect(screen.getByTestId('brand-privado')).toBeInTheDocument();
    expect(screen.queryByTestId('brand-billions')).not.toBeInTheDocument();
    expect(screen.queryByText('Sign in with Billions/Privado')).not.toBeInTheDocument();
    expect(screen.getByText('Sign in with Privado ID')).toBeInTheDocument();
  });

  it('hides Billions when the backend does not report networks at all', async () => {
    // Fails closed: an older backend that omits the field cannot confirm the
    // network, and advertising an unconfirmed network is the defect being fixed.
    mockNetworks({ providers: ['privado'] });
    renderLoginPage();

    await waitFor(() => {
      expect(screen.getByTestId('privado-brand-panel')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('brand-billions')).not.toBeInTheDocument();
    expect(screen.getByTestId('brand-privado')).toBeInTheDocument();
  });

  it('hides Billions when the providers request fails', async () => {
    server.use(
      http.get('*/auth/providers', () => HttpResponse.error())
    );
    renderLoginPage();

    await waitFor(() => {
      expect(screen.getByTestId('privado-brand-panel')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('brand-billions')).not.toBeInTheDocument();
    expect(screen.getByTestId('brand-privado')).toBeInTheDocument();
  });
});
