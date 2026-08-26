import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { LoginPage } from '../LoginPage';
import { AuthProvider } from '@/contexts/AuthContext';
import {
  setSessionFailed,
  setSessionCompleted,
  resetSessionState,
  mockTokenResponse,
} from '@/test/mocks/handlers';

// RD-1242: a rejected wallet proof used to leave the session pending, so the
// browser polled for five minutes (150 polls x 2s) and then claimed the wallet
// had timed out — a diagnosis that sent debugging in the wrong direction. The
// session now reports the failure, so the login page must surface it promptly
// and stop polling.

function renderLoginPage() {
  return render(
    <MemoryRouter
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      initialEntries={['/login']}
    >
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('LoginPage — rejected wallet proof (RD-1242)', () => {
  beforeEach(() => {
    sessionStorage.clear();
    resetSessionState();
    vi.clearAllMocks();
  });

  it('surfaces the error step instead of spinning until the poll budget expires', async () => {
    setSessionFailed('verification_failed');
    renderLoginPage();

    // Wait for the QR to appear, i.e. polling has started.
    await waitFor(() => {
      expect(screen.getByTestId('qr-code')).toBeInTheDocument();
    });

    await waitFor(
      () => {
        expect(screen.getByTestId('auth-error')).toBeInTheDocument();
      },
      { timeout: 5000 }
    );

    expect(screen.getByText('Authentication Failed')).toBeInTheDocument();
    // The waiting spinner must be gone — that copy was the reported symptom.
    expect(screen.queryByText(/Waiting for wallet confirmation/i)).not.toBeInTheDocument();
    // And a recovery path is offered rather than a dead end.
    expect(screen.getByTestId('try-again-btn')).toBeInTheDocument();
  });

  // The security property: the session ID is rendered in the QR code, so anyone
  // who photographs it can post one bogus token. That must not be able to cancel
  // a login that still completes, so the page keeps polling while showing the
  // failure (matching the backend's non-terminal semantics).
  it('keeps polling after a rejection, so a later completion still wins', async () => {
    setSessionFailed('verification_failed');
    renderLoginPage();

    await waitFor(
      () => {
        expect(screen.getByTestId('auth-error')).toBeInTheDocument();
      },
      { timeout: 5000 }
    );

    // A retry succeeds on the backend after the rejection was shown.
    setSessionCompleted(true, mockTokenResponse);

    await waitFor(
      () => {
        expect(screen.queryByTestId('auth-error')).not.toBeInTheDocument();
      },
      { timeout: 6000 }
    );
  }, 15000);

  it('routes a missing humanity credential to its own step, not a generic error', async () => {
    setSessionFailed('humanity_required');
    renderLoginPage();

    await waitFor(
      () => {
        expect(screen.getByText('Humanity Verification Required')).toBeInTheDocument();
      },
      { timeout: 5000 }
    );
  });
});
