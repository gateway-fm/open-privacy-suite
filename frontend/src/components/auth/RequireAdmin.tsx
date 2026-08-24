import { createContext, useContext, ReactNode, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2, ShieldAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';

interface RequireAdminProps {
  children: ReactNode;
}

// A verdict is only meaningful for the token it was obtained with, so the two
// are stored together and can never drift apart. Keeping them in separate
// pieces of state is what allowed the protected subtree to render for one
// commit under a new identity's token while the previous identity's verdict
// was still on screen.
type AdminCheck =
  | { status: 'loading' }
  | { status: 'admin'; token: string; data: AdminContextType }
  | { status: 'denied'; token: string | null }
  | { status: 'error'; token: string };

export interface AdminContextType {
  isAdmin: boolean;
  isReadonlyAdmin: boolean;
  adminOrgIds: string[];
  readonlyAdminOrgIds: string[];
}

const AdminContext = createContext<AdminContextType | undefined>(undefined);

// reason: useAdmin is deliberately co-located with its RequireAdmin provider so
// the admin-gate context and its consumer hook live in one file. This is admin
// dashboard UI; the only cost is a full reload (instead of HMR) when editing
// this file, which is acceptable here.
// eslint-disable-next-line react-refresh/only-export-components
export function useAdmin() {
  const context = useContext(AdminContext);
  if (context === undefined) {
    throw new Error('useAdmin must be used within a RequireAdmin component');
  }
  return context;
}

export function RequireAdmin({ children }: RequireAdminProps) {
  const { accessToken, isLoading: authLoading } = useAuth();
  const navigate = useNavigate();
  const [check, setCheck] = useState<AdminCheck>({ status: 'loading' });

  useEffect(() => {
    // Wait for AuthProvider to finish restoring session from localStorage.
    if (authLoading) return;

    if (!accessToken) {
      setCheck({ status: 'denied', token: null });
      return;
    }

    // Re-arm the gate for every authenticated probe. This is belt-and-braces:
    // the render-time token check below already refuses to render children for
    // an unverified token, so a token change cannot leave the gate open even
    // before this effect runs. The server re-authorises each request
    // regardless, but the gate itself must not stay open across identities.
    setCheck({ status: 'loading' });

    // Pin the narrowed token: inside the async closure below TypeScript widens
    // accessToken back to string | null, and this is also the exact token the
    // verdict is being recorded for.
    const probedToken = accessToken;

    let cancelled = false;

    async function checkAdminStatus() {
      try {
        const response = await fetch('/api/v1/me/admin-status', {
          headers: { Authorization: `Bearer ${probedToken}` },
        });

        if (cancelled) return;

        if (!response.ok) {
          setCheck({ status: 'error', token: probedToken });
          return;
        }

        const data = await response.json();
        // Parsing the body is a second await — re-check before committing, so
        // a probe superseded by a token change cannot decide this gate.
        if (cancelled) return;
        // Strict equality so a malformed body cannot read as admin.
        if (data?.is_admin === true) {
          setCheck({
            status: 'admin',
            token: probedToken,
            data: {
              isAdmin: data.is_admin,
              isReadonlyAdmin: data.is_readonly_admin,
              adminOrgIds: data.admin_org_ids || [],
              readonlyAdminOrgIds: data.readonly_admin_org_ids || [],
            },
          });
        } else {
          setCheck({ status: 'denied', token: probedToken });
        }
      } catch {
        if (!cancelled) {
          setCheck({ status: 'error', token: probedToken });
        }
      }
    }

    checkAdminStatus();

    return () => {
      cancelled = true;
    };
  }, [accessToken, authLoading]);

  // Derived during render, not repaired in an effect: a verdict obtained with a
  // different token says nothing about the current one, so the subtree stays
  // closed until this token has its own answer. Fails closed by construction —
  // an unknown pairing renders the checking state, never the children.
  const settled = check.status !== 'loading' && check.token === accessToken;

  const checkingView = (
    <div className="flex min-h-[40vh] items-center justify-center" role="status" aria-live="polite">
      <div className="flex items-center gap-2 text-neutral-500">
        <Loader2 className="h-4 w-4 animate-spin text-primary" aria-hidden="true" />
        <span className="text-sm">Checking admin privileges...</span>
      </div>
    </div>
  );

  if (authLoading || !settled) {
    return checkingView;
  }

  if (check.status === 'denied') {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="mx-auto max-w-md rounded-lg border border-red-200 bg-red-50 p-8 text-center">
          <ShieldAlert className="mx-auto mb-4 h-12 w-12 text-red-500" />
          <h2 className="mb-2 text-xl font-semibold text-red-900">Access Denied</h2>
          <p className="text-sm text-red-700">
            You don't have admin privileges. Contact your organization administrator.
          </p>
          {/* Without a way out this screen is a dead end: signing out of an
              admin account and back in as a regular user lands on the
              remembered /admin URL, and the only escape was editing the
              address bar. Only offered to a signed-in user — this branch also
              covers "no token at all", where /success would bounce straight
              back to the login page and the label would be a lie. */}
          {accessToken && (
            <Button
              onClick={() => navigate('/success', { replace: true })}
              variant="outline"
              className="mt-6"
              data-testid="admin-denied-back-btn"
            >
              Go to your dashboard
            </Button>
          )}
        </div>
      </div>
    );
  }

  if (check.status === 'error') {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="mx-auto max-w-md rounded-lg border border-amber-200 bg-amber-50 p-8 text-center">
          <ShieldAlert className="mx-auto mb-4 h-12 w-12 text-amber-500" />
          <h2 className="mb-2 text-xl font-semibold text-amber-900">Unable to verify admin status</h2>
          <p className="text-sm text-amber-700">
            An error occurred while checking your permissions. Please try again later.
          </p>
          <Button
            onClick={() => navigate('/success', { replace: true })}
            variant="outline"
            className="mt-6"
            data-testid="admin-error-back-btn"
          >
            Go to your dashboard
          </Button>
        </div>
      </div>
    );
  }

  // Exhaustiveness guard. `settled` already excludes 'loading', but narrowing
  // it for the compiler here keeps the non-null assertion off the context value
  // — an unexpected status renders the checking state instead of the children.
  if (check.status !== 'admin') {
    return checkingView;
  }

  return (
    <AdminContext.Provider value={check.data}>
      {children}
    </AdminContext.Provider>
  );
}
