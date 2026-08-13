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
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading) return;

    if (!accessToken) {
      setIsAdmin(false);
      setLoading(false);
      return;
    }

    // Re-arm on every probe. The effect re-runs when the token rotates, and
    // without this `loading` stays false while the second request is in
    // flight, so callers would read the previous token's answer as settled.
    setLoading(true);

    let cancelled = false;

    async function check() {
      try {
        const response = await fetch('/api/v1/me/admin-status', {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (cancelled) return;
        if (!response.ok) {
          setIsAdmin(false);
          return;
        }
        const data = await response.json();
        // Strict equality, not truthiness: a body that violates the endpoint
        // schema (`"is_admin": "false"`, a non-empty string, a number) would
        // otherwise read as admin — the opposite of the fail-closed behaviour
        // this hook promises.
        setIsAdmin(data?.is_admin === true);
      } catch {
        if (!cancelled) setIsAdmin(false);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    check();

    return () => {
      cancelled = true;
    };
  }, [accessToken, authLoading]);

  return { isAdmin, loading };
}
