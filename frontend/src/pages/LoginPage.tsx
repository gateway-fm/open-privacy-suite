import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { QRCodeSVG } from 'qrcode.react';
import { Shield, Smartphone, ExternalLink, Loader2, AlertCircle, CheckCircle2, FlaskConical } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { authApiMethods, generatePrivadoLink, isMobileDevice, AuthRequestResponse, HumanityVerificationError } from '@/api/auth';

// Microsoft logo SVG (official brand colours)
function MicrosoftIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 21 21" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect x="1" y="1" width="9" height="9" fill="#F25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
      <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
      <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
    </svg>
  );
}

// Mock login requires explicit opt-in via VITE_ALLOW_MOCK_LOGIN=true
const allowMockLogin = import.meta.env.VITE_ALLOW_MOCK_LOGIN === 'true';
const AUTH_POLL_INTERVAL_MS = 2000;
const AUTH_MAX_POLLS = 150;

type AuthStep = 'init' | 'loading' | 'ready' | 'success' | 'error' | 'humanity_required' | 'timed_out';
type AuthProvider = 'privado' | 'azuread';

interface AuthState {
  step: AuthStep;
  sessionId: string | null;
  authRequest: AuthRequestResponse['auth_request'] | null;
  error: string | null;
  humanityVerifyUrl: string | null;
}

export function LoginPage() {
  const navigate = useNavigate();
  const { login, isAuthenticated, isLoading } = useAuth();
  const [providers, setProviders] = useState<string[]>(['privado']);
  const [activeProvider, setActiveProvider] = useState<AuthProvider>('privado');
  const [azureLoading, setAzureLoading] = useState(false);
  const [state, setState] = useState<AuthState>({
    step: 'init',
    sessionId: null,
    authRequest: null,
    error: null,
    humanityVerifyUrl: null,
  });

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/link-wallet');
    }
  }, [isAuthenticated, navigate, isLoading]);

  // Load available providers (silently ignore errors — default to privado only)
  useEffect(() => {
    authApiMethods.getAuthProviders().then((res) => setProviders(res.providers)).catch(() => {});
  }, []);

  // Handle "Sign in with Microsoft" — fetch auth URL then redirect browser
  const handleAzureLogin = useCallback(async () => {
    setAzureLoading(true);
    try {
      const redirectURI = `${window.location.origin}/auth/azure/callback`;
      const { url } = await authApiMethods.getAzureAuthURL(redirectURI);
      window.location.href = url;
    } catch {
      setAzureLoading(false);
    }
  }, []);

  // Start auth request
  const startAuth = useCallback(async () => {
    setState(prev => ({ ...prev, step: 'loading', error: null }));

    try {
      const response = await authApiMethods.requestAuth();
      setState({
        step: 'ready',
        sessionId: response.session_id,
        authRequest: response.auth_request,
        error: null,
        humanityVerifyUrl: null,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to start authentication';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    }
  }, []);

  // Mock login for development (requires explicit opt-in)
  const handleMockLogin = useCallback(async () => {
    if (!allowMockLogin) return;

    setState(prev => ({ ...prev, step: 'loading', error: null }));

    try {
      // Step 1: Get a session
      const authResponse = await authApiMethods.requestAuth();

      // Step 2: Verify with mock token (only works in dev mode on backend)
      // Reuse the same dev DID across sessions so ETH address links persist
      const MOCK_DID_KEY = 'privacy-proxy-mock-did';
      let mockDID = localStorage.getItem(MOCK_DID_KEY);
      if (!mockDID) {
        mockDID = `did:privado:dev_${Date.now()}`;
        localStorage.setItem(MOCK_DID_KEY, mockDID);
      }
      const tokens = await authApiMethods.verifyAuth(authResponse.session_id, `mock.${mockDID}`);

      // Step 3: Login
      login(tokens.access_token, tokens.refresh_token, tokens.expires_in);
      setState(prev => ({ ...prev, step: 'success' }));
      setTimeout(() => navigate('/link-wallet'), 1000);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Mock login failed';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    }
  }, [login, navigate]);

  // Auto-start on mount
  useEffect(() => {
    if (state.step === 'init') {
      startAuth();
    }
  }, [state.step, startAuth]);

  // Poll for session completion
  useEffect(() => {
    if (state.step !== 'ready' || !state.sessionId) return;

    let mounted = true;
    let pollCount = 0;

    const poll = async () => {
      if (!mounted) return;
      if (pollCount >= AUTH_MAX_POLLS) {
        setState(prev => ({
          ...prev,
          step: 'timed_out',
          error: 'Authentication timed out. Generate a new QR code and try again.',
        }));
        return;
      }

      try {
        const result = await authApiMethods.pollSession(state.sessionId!);
        if (result && mounted) {
          login(result.access_token, result.refresh_token, result.expires_in);
          setState(prev => ({ ...prev, step: 'success' }));
          setTimeout(() => navigate('/link-wallet'), 1000);
          return;
        }
      } catch (err) {
        // Check for humanity verification error
        const errorData = err as { response?: { data?: HumanityVerificationError } };
        if (errorData?.response?.data?.error === 'humanity_verification_required') {
          setState(prev => ({
            ...prev,
            step: 'humanity_required',
            humanityVerifyUrl: errorData.response!.data!.verify_url,
          }));
          return;
        }
        // Otherwise continue polling
      }

      pollCount++;
      if (mounted) {
        setTimeout(poll, AUTH_POLL_INTERVAL_MS);
      }
    };

    // Start polling after a short delay
    const timer = setTimeout(poll, AUTH_POLL_INTERVAL_MS);
    return () => {
      mounted = false;
      clearTimeout(timer);
    };
  }, [state.step, state.sessionId, login, navigate]);

  // Handle mobile deep link
  const handleMobileAuth = () => {
    if (!state.authRequest) return;
    const deepLink = generatePrivadoLink(state.authRequest);
    window.location.href = deepLink;
  };

  // Render QR code section
  const renderQRSection = () => {
    if (!state.authRequest) return null;

    const deepLink = generatePrivadoLink(state.authRequest);
    const isMobile = isMobileDevice();

    return (
      <div className="space-y-6" data-testid="qr-section">
        {/* QR Code for desktop */}
        {!isMobile && (
          <div className="flex flex-col items-center gap-4">
            <div className="p-4 bg-white rounded-2xl shadow-lg" role="img" aria-label="QR code for Privado ID authentication" data-testid="qr-code">
              <QRCodeSVG
                value={deepLink}
                size={200}
                level="M"
                includeMargin={false}
                aria-hidden="true"
              />
            </div>
            <p className="text-center text-sm text-neutral-500">
              Scan with your Privado ID wallet
            </p>
          </div>
        )}

        {/* Mobile button */}
        {isMobile && (
          <Button
            onClick={handleMobileAuth}
            className="w-full"
            variant="default"
            size="lg"
          >
            <Smartphone className="w-5 h-5 mr-2" />
            Open Privado ID Wallet
          </Button>
        )}

        {/* Desktop: also show button as fallback */}
        {!isMobile && (
          <div className="border-t border-neutral-200 pt-4">
            <p className="mb-3 text-center text-xs text-neutral-700">
              Or open the wallet on this device
            </p>
            <Button
              onClick={handleMobileAuth}
              className="w-full"
              variant="outline"
              size="sm"
            >
              <ExternalLink className="w-4 h-4 mr-2" />
              Open Wallet App
            </Button>
          </div>
        )}

        {/* Polling indicator */}
        <div className="flex items-center justify-center gap-2 text-sm text-neutral-700" role="status" aria-live="polite">
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
          <span>Waiting for wallet confirmation...</span>
        </div>
      </div>
    );
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-100 p-4 overflow-x-hidden" data-testid="login-page">
      <div className="w-full max-w-md animate-fade-in-up">
        {/* Logo Header */}
        <div className="text-center mb-8" data-testid="login-header">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-primary to-primary-300 shadow-lg shadow-primary">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-neutral-900">Privacy Proxy</h1>
          <p className="mt-1 text-neutral-500">Authenticated RPC Access</p>
        </div>

        {/* Auth Card */}
        <Card variant="default" data-testid="auth-card">
          <CardHeader className="text-center">
            <CardTitle data-testid="auth-title">Sign In</CardTitle>
            <CardDescription>
              {activeProvider === 'azuread'
                ? 'Use your Microsoft or corporate account'
                : 'Prove your humanity using zero-knowledge proofs'}
            </CardDescription>
          </CardHeader>

          {/* Provider tabs — only shown when more than one provider is available */}
          {providers.includes('azuread') && (
            <div className="flex border-b border-neutral-200 mx-6">
              <button
                onClick={() => setActiveProvider('privado')}
                className={`flex-1 py-2 text-sm font-medium transition-colors ${
                  activeProvider === 'privado'
                    ? 'border-b-2 border-primary text-primary'
                    : 'text-neutral-500 hover:text-neutral-700'
                }`}
                data-testid="tab-privado"
              >
                Privado ID
              </button>
              <button
                onClick={() => setActiveProvider('azuread')}
                className={`flex-1 py-2 text-sm font-medium transition-colors ${
                  activeProvider === 'azuread'
                    ? 'border-b-2 border-primary text-primary'
                    : 'text-neutral-500 hover:text-neutral-700'
                }`}
                data-testid="tab-azuread"
              >
                Microsoft
              </button>
            </div>
          )}

          <CardContent>
            {/* Microsoft / Azure AD sign-in panel */}
            {activeProvider === 'azuread' && (
              <div className="flex flex-col items-center gap-6 py-8" data-testid="azuread-section">
                <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[#0078d4]/10">
                  <MicrosoftIcon className="h-8 w-8" />
                </div>
                <div className="text-center">
                  <p className="font-medium text-neutral-900">Sign in with Microsoft</p>
                  <p className="mt-1 text-sm text-neutral-500">
                    Use your @outlook.com, @hotmail.com, or corporate account
                  </p>
                </div>
                <Button
                  onClick={handleAzureLogin}
                  disabled={azureLoading}
                  className="w-full bg-[#0078d4] hover:bg-[#106ebe] text-white"
                  size="lg"
                  data-testid="azure-signin-btn"
                >
                  {azureLoading ? (
                    <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                  ) : (
                    <MicrosoftIcon className="w-5 h-5 mr-2" />
                  )}
                  {azureLoading ? 'Redirecting...' : 'Continue with Microsoft'}
                </Button>
              </div>
            )}

            {/* Privado ID flow — hidden when Microsoft tab is active */}
            {activeProvider === 'privado' && (
              <>
            {/* Loading state */}
            {state.step === 'loading' && (
              <div className="flex flex-col items-center gap-4 py-8" role="status" aria-live="polite" data-testid="auth-loading">
                <Loader2 className="h-8 w-8 animate-spin text-primary" aria-hidden="true" />
                <p className="text-neutral-500">Preparing authentication...</p>
              </div>
            )}

            {/* Ready state - show QR */}
            {state.step === 'ready' && renderQRSection()}

            {/* Success state */}
            {state.step === 'success' && (
              <div className="flex flex-col items-center gap-4 py-8" data-testid="auth-success">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-success-light">
                  <CheckCircle2 className="h-8 w-8 text-success-dark" />
                </div>
                <p className="font-medium text-neutral-900">Authentication successful!</p>
                <p className="text-sm text-neutral-500">Redirecting to wallet linking...</p>
              </div>
            )}

            {/* Humanity verification required */}
            {state.step === 'humanity_required' && (
              <div className="flex flex-col items-center gap-4 py-6">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-warning-light">
                  <AlertCircle className="h-8 w-8 text-warning-dark" />
                </div>
                <div className="text-center">
                  <p className="mb-2 font-medium text-neutral-900">Humanity Verification Required</p>
                  <p className="mb-4 text-sm text-neutral-500">
                    Please complete your ProofOfHumanity verification with Billions to continue.
                  </p>
                </div>
                <Button
                  onClick={() => window.open(state.humanityVerifyUrl!, '_blank')}
                  variant="default"
                  size="lg"
                  className="w-full"
                >
                  <ExternalLink className="w-5 h-5 mr-2" />
                  Verify on Billions
                </Button>
                <Button
                  onClick={startAuth}
                  variant="outline"
                  size="sm"
                  className="w-full mt-2"
                >
                  Try Again
                </Button>
              </div>
            )}

            {/* Polling timeout state */}
            {state.step === 'timed_out' && (
              <div className="flex flex-col items-center gap-4 py-6" data-testid="auth-timeout">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-warning-light">
                  <AlertCircle className="h-8 w-8 text-warning-dark" />
                </div>
                <div className="text-center">
                  <p className="mb-2 font-medium text-neutral-900">Authentication Timed Out</p>
                  <p className="text-sm text-neutral-500">{state.error}</p>
                </div>
                <Button onClick={startAuth} variant="default" className="w-full">
                  Generate New QR Code
                </Button>
                <Button
                  onClick={handleMobileAuth}
                  variant="outline"
                  className="w-full"
                  disabled={!state.authRequest}
                >
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Open Wallet App
                </Button>
              </div>
            )}

            {/* Error state */}
            {state.step === 'error' && (
              <div className="flex flex-col items-center gap-4 py-6" data-testid="auth-error">
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-error-light">
                  <AlertCircle className="h-8 w-8 text-error-dark" />
                </div>
                <div className="text-center">
                  <p className="mb-2 font-medium text-neutral-900">Authentication Failed</p>
                  <p className="text-sm text-neutral-500">{state.error}</p>
                </div>
                <Button onClick={startAuth} variant="default" className="w-full mt-2" data-testid="try-again-btn">
                  Try Again
                </Button>
              </div>
            )}
              </>
            )}
          </CardContent>
        </Card>

        {/* Help text — Privado only */}
        {activeProvider === 'privado' && (
          <div className="mt-6 text-center">
            <p className="text-sm text-neutral-700">
              Don't have Privado ID?{' '}
              <a
                href="https://docs.privado.id/docs/wallet/wallet-app/privadoid-app/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline underline-offset-2 hover:text-primary-300"
              >
                Download the wallet
              </a>
            </p>
          </div>
        )}

        {/* Mock login - requires explicit opt-in via VITE_ALLOW_MOCK_LOGIN=true */}
        {allowMockLogin && (
          <div className="mt-6 border-t border-neutral-200 pt-6" data-testid="dev-tools">
            <div className="text-center mb-3">
              <span className="inline-flex items-center gap-1.5 rounded-full bg-warning-light px-2 py-1 text-xs font-medium text-warning-dark">
                <FlaskConical className="w-3 h-3" />
                Development Only
              </span>
            </div>
            <Button
              onClick={handleMockLogin}
              variant="outline"
              className="w-full border-warning text-warning-dark hover:bg-warning-light"
              disabled={state.step === 'loading'}
              data-testid="mock-login-btn"
            >
              {state.step === 'loading' ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <FlaskConical className="w-4 h-4 mr-2" />
              )}
              Mock Login (Skip Wallet)
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
