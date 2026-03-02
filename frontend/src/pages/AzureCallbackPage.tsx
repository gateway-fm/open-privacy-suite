import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Loader2, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { authApiMethods } from '@/api/auth';

// Handles the redirect from Microsoft after Azure AD login.
// Reads code+state from URL params, exchanges them for our JWT tokens.
export function AzureCallbackPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const errorParam = searchParams.get('error');

    if (errorParam) {
      const desc = searchParams.get('error_description') ?? errorParam;
      setError(`Microsoft login failed: ${desc}`);
      return;
    }

    if (!code || !state) {
      setError('Missing code or state from Microsoft redirect');
      return;
    }

    const redirectURI = `${window.location.origin}/auth/azure/callback`;

    authApiMethods
      .completeAzureLogin(code, state, redirectURI)
      .then((tokens) => {
        login(tokens.access_token, tokens.refresh_token, tokens.expires_in);
        navigate('/link-wallet');
      })
      .catch((err) => {
        const msg =
          (err as { response?: { data?: { error?: string } } })?.response?.data?.error ??
          (err instanceof Error ? err.message : 'Authentication failed');
        setError(msg);
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-neutral-100 p-4">
        <Card variant="default" className="w-full max-w-md">
          <CardHeader className="text-center">
            <CardTitle>Authentication Failed</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-4 py-6">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-error-light">
              <AlertCircle className="h-8 w-8 text-error-dark" />
            </div>
            <p className="text-sm text-neutral-500 text-center">{error}</p>
            <Button onClick={() => navigate('/login')} variant="default" className="w-full">
              Back to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-100 p-4">
      <div className="flex flex-col items-center gap-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-neutral-500">Completing Microsoft sign-in...</p>
      </div>
    </div>
  );
}
