import { useEffect, useState } from 'react';
import { fetchStreamManaged } from '@/api/configuration';
import type { ConfigurationKind } from '@/types/configuration';

export interface ManagedStreamState {
  /** True while an active reviewed document owns the stream. */
  managed: boolean;
  /** False until the first answer (or failure) has arrived. */
  checked: boolean;
}

/**
 * useManagedStream reports whether a reviewed configuration document currently
 * owns a stream, so a screen can hide the edit controls the server would refuse
 * and say why. The server enforces regardless: if this check itself fails, the
 * screen keeps its controls and relies on the refusal being shown verbatim.
 */
export function useManagedStream(kind: ConfigurationKind, org?: string): ManagedStreamState {
  const [state, setState] = useState<ManagedStreamState>({ managed: false, checked: false });

  useEffect(() => {
    if (kind !== 'platform' && !org) {
      setState({ managed: false, checked: true });
      return;
    }
    let cancelled = false;
    setState({ managed: false, checked: false });
    fetchStreamManaged(kind, org)
      .then((managed) => {
        if (!cancelled) setState({ managed, checked: true });
      })
      .catch((error) => {
        console.error('Failed to read configuration stream state:', error);
        if (!cancelled) setState({ managed: false, checked: true });
      });
    return () => {
      cancelled = true;
    };
  }, [kind, org]);

  return state;
}
