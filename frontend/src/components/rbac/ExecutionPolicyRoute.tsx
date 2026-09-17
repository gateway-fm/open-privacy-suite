import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { createAdminClient } from '@/api/adminClient';
import Configuration from './Configuration';
import ExecutionPolicy from './ExecutionPolicy';

export default function ExecutionPolicyRoute() {
  const { accessToken } = useAuth();
  const [probe, setProbe] = useState<{ token: string; mode: string } | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!accessToken) return;
    let cancelled = false;
    createAdminClient({ Authorization: `Bearer ${accessToken}` }).get('/status').then(response => {
      const mode = response.data.execution?.mode;
      if (!cancelled) setProbe({ token: accessToken, mode: mode === 'reth' || mode === 'legacy' ? mode : 'unavailable' });
    }).catch(() => { if (!cancelled) setProbe({ token: accessToken, mode: 'unavailable' }); });
    return () => { cancelled = true; };
  }, [accessToken, attempt]);
  if (!accessToken) return <p>Sign in with a named account to manage execution rules.</p>;
  if (probe?.token !== accessToken) return <p role="status">Checking execution mode…</p>;
  if (probe.mode === 'reth') return <Configuration initialKind="execution-rules" />;
  if (probe.mode === 'legacy') return <ExecutionPolicy />;
  return <p role="alert">Execution mode is unavailable. <button onClick={() => { setProbe(null); setAttempt(attempt + 1); }} className="underline">Retry</button></p>;
}
