import { createAdminClient } from './adminClient';
import type { ConfigurationContext, ConfigurationKind, ConfigurationReview, ConfigurationRevision, ExecutionReadiness } from '@/types/configuration';

// Revision authors and approvers must have a named login. An operator token
// saved for other dashboard tools must never replace this identity.
export function configurationApi(token: string, org: string, kind: ConfigurationKind) {
  if (!token) throw new Error('Sign in with a named account to manage configuration.');
  const api = createAdminClient({ Authorization: `Bearer ${token}` });
  const base = kind === 'platform' ? '/configuration/platform' : `/orgs/${encodeURIComponent(org)}/configuration/${kind}`;
  const revision = (id: string) => `${base}/revisions/${encodeURIComponent(id)}`;
  return {
    context: () => api.get<ConfigurationContext>(`${base}/context`),
    list: () => api.get<{ revisions: ConfigurationRevision[] }>(`${base}/revisions`),
    // Keep exact text, including duplicate keys, for the server's strict parser.
    submit: (source: string) => api.post<ConfigurationRevision>(`${base}/revisions`, source, { transformRequest: [(body) => body] }),
    review: (id: string, coactivate: string[]) => api.post<ConfigurationReview>(`${revision(id)}/simulate`, { coactivate }),
    activate: (id: string, coactivate: string[]) => api.post<{ revisions: ConfigurationRevision[] }>(`${revision(id)}/activate`, { coactivate }),
    withdraw: (id: string) => api.post<ConfigurationRevision>(`${revision(id)}/withdraw`),
    preview: (id: string, method: string, params: unknown[], dryRun = false) => api.post(`/orgs/${encodeURIComponent(org)}/execution/simulate`, { candidateRevisionId: id, method, params, dryRun }),
    status: () => api.get<{ execution?: ExecutionReadiness }>('/status'),
  };
}
