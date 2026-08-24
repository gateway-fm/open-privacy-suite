import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';

/**
 * useAdminStatus reports whether the signed-in user may open the admin
 * dashboard, so user-facing pages can offer a way in instead of leaving
 * `/admin` as an address-bar secret.
 *
 * This is presentation only — it decides whether to render a link. The gate
 * itself stays server-side: `/admin/*` is wrapped in RequireAdmin, which
 * re-checks the same endpoint and renders Access Denied on a negative answer.
 * Any failure here resolves to "not an admin" so a flaky probe hides a link
 * rather than advertising a dashboard the user cannot open.
 */
export function useAdminStatus(): { isAdmin: boolean; loading: boolean } {
  const { accessToken, isLoading: authLoading } = useAuth();
  // The answer is stored with the token it was obtained for. Callers then read
  // "settled" as a comparison against the *current* token, so a rotation can
  // never surface one identity's access as another's — the staleness is derived
  // rather than repaired by a follow-up state update.
  const [result, setResult] = useState<{ token: string | null; isAdmin: boolean } | null>(null);

  useEffect(() => {
    if (authLoading) return;

    if (!accessToken) {
      setResult({ token: null, isAdmin: false });
      return;
    }

    // Pin the narrowed token: TypeScript widens accessToken back to
    // string | null inside the async closure, and this is the token the answer
    // is being recorded for.
    const probedToken = accessToken;

    let cancelled = false;

    async function check() {
      try {
        const response = await fetch('/api/v1/me/admin-status', {
          headers: { Authorization: `Bearer ${probedToken}` },
        });
        if (cancelled) return;
        if (!response.ok) {
          setResult({ token: probedToken, isAdmin: false });
          return;
        }
        const data = await response.json();
        // Re-check: parsing the body is a second await, so a probe superseded
        // by a token change can land here after the newer one started. Without
        // this the old identity's answer overwrites the new one's.
        if (cancelled) return;
        // Strict equality, not truthiness: a body that violates the endpoint
        // schema (`"is_admin": "false"`, a non-empty string, a number) would
        // otherwise read as admin — the opposite of the fail-closed behaviour
        // this hook promises.
        setResult({ token: probedToken, isAdmin: data?.is_admin === true });
      } catch {
        if (!cancelled) setResult({ token: probedToken, isAdmin: false });
      }
    }

    check();

    return () => {
      cancelled = true;
    };
  }, [accessToken, authLoading]);

  // A result for a different token is not an answer for this one: report
  // loading, and isAdmin false, until the current token has its own verdict.
  const settled = result !== null && result.token === accessToken;
  return { isAdmin: settled ? result.isAdmin : false, loading: authLoading || !settled };
}
