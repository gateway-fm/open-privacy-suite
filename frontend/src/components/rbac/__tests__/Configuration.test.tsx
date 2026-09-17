import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import Configuration, { PlatformConfiguration } from '../Configuration';

vi.mock('../RBACManager', () => ({ useOrgContext: () => ({ selectedOrg: { id: 'org-a', name: 'A' } }) }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ accessToken: 'named-jwt' }) }));
vi.mock('@/components/auth/RequireAdmin', () => ({ useAdmin: () => ({ isPlatformAdmin: true }) }));

const base = '/api/v1/admin/orgs/org-a/configuration/groups';
const source = { apiVersion: 'ops.configuration/v1', kind: 'groups', scope: { kind: 'organization', id: 'org-a' }, baseRevision: 0, dependencies: {}, deletions: [], spec: { groups: [] } };
const revision = { id: 'revision-a', revision: 1, baseRevision: 0, kind: 'groups', scope: source.scope, source: JSON.stringify(source), digest: 'a'.repeat(64), dependencies: {}, status: 'draft', createdBy: 'author', createdAt: '2026-09-17T00:00:00Z', activatedBy: null, activatedAt: null };
let canActivate: boolean;
let viewerId: string;
let activationCount: number;
let reviewCount: number;
let submitted: string;

beforeEach(() => {
  canActivate = true; viewerId = 'reviewer'; activationCount = 0; reviewCount = 0; submitted = '';
  localStorage.setItem('privacy_proxy_admin_api_token', 'bootstrap-must-not-be-used');
  server.use(
    http.get(`${base}/context`, () => HttpResponse.json({ active: null, source, viewer: { principalId: viewerId, principalKind: canActivate ? 'human' : 'service', canActivate }, legacyExecution: [] })),
    http.get(`${base}/revisions`, () => HttpResponse.json({ revisions: [revision] })),
    http.post(`${base}/revisions`, async ({ request }) => {
      expect(request.headers.get('Authorization')).toBe('Bearer named-jwt');
      expect(request.headers.has('X-Admin-Token')).toBe(false);
      submitted = await request.text();
      return HttpResponse.json(revision, { status: 201 });
    }),
    http.post(`${base}/revisions/revision-a/simulate`, () => { reviewCount++; return HttpResponse.json({ revisions: [revision], groupDiff: { changes: [], preservedDrift: [], projection: [] }, registryDiff: null, legacyExecution: [] }); }),
    http.post(`${base}/revisions/revision-a/activate`, () => { activationCount++; return HttpResponse.json({ revisions: [{ ...revision, status: 'active' }] }); }),
    http.get('/api/v1/admin/status', () => HttpResponse.json({ execution: { mode: 'reth', ready: false, desired_version: 8, applied_version: 7, reason: 'publication_pending' } })),
  );
});
afterEach(() => { cleanup(); localStorage.clear(); });

describe('Configuration review workflow', () => {
  it('previews a stored execution candidate as the signed-in principal without bypassing the active policy', async () => {
    let previewBody: unknown;
    const executionBase = base.replace('/groups', '/execution-rules');
    const executionRevision = { ...revision, kind: 'execution-rules' };
    server.use(
      http.get(`${executionBase}/context`, () => HttpResponse.json({ active: null, source, viewer: { principalId: viewerId, principalKind: 'service', canActivate: false } })),
      http.get(`${executionBase}/revisions`, () => HttpResponse.json({ revisions: [executionRevision] })),
      http.post(`${executionBase}/revisions/revision-a/simulate`, () => HttpResponse.json({ revisions: [executionRevision], legacyExecution: [] })),
      http.post('/api/v1/admin/orgs/org-a/execution/simulate', async ({ request }) => {
        expect(request.headers.get('Authorization')).toBe('Bearer named-jwt');
        previewBody = await request.json();
        return HttpResponse.json({ result: '0x', policy: { would_allow: false, decisions: [] } });
      }),
    );
    const user = userEvent.setup(); render(<Configuration />);
    await user.selectOptions(screen.getByLabelText('Configuration stream'), 'execution-rules');
    await user.click(await screen.findByRole('button', { name: 'Review revision 1' }));
    const input = await screen.findByLabelText('Simulation parameters');
    await user.clear(input);
    await user.paste('[{"from":"0x1111111111111111111111111111111111111111"},"latest"]');
    await user.click(screen.getByRole('button', { name: 'Preview candidate in node' }));
    await waitFor(() => expect(previewBody).toEqual({ candidateRevisionId: 'revision-a', method: 'eth_call', params: [{ from: '0x1111111111111111111111111111111111111111' }, 'latest'], dryRun: false }));
    expect(await screen.findByLabelText('Node preview result')).toHaveTextContent('"would_allow": false');
  });
  it('locks the bundle while its review is pending', async () => {
    let finish!: () => void;
    const pending = new Promise<void>(resolve => { finish = resolve; });
    server.use(http.post(`${base}/revisions/revision-a/simulate`, async () => {
      await pending;
      return HttpResponse.json({ revisions: [revision], legacyExecution: [] });
    }));
    const user = userEvent.setup(); render(<Configuration />);
    await user.click(await screen.findByRole('button', { name: 'Review revision 1' }));
    try {
      expect(screen.getByLabelText('Coactivate revision IDs')).toBeDisabled();
    } finally { finish(); }
    await screen.findByRole('button', { name: 'Activate reviewed revision' });
  });

  it('loads platform revisions without an organization and uses its named identity', async () => {
    const platformSource = { ...source, kind: 'platform', scope: { kind: 'platform', id: '' } };
    server.use(
      http.get('/api/v1/admin/configuration/platform/context', ({ request }) => {
        expect(request.headers.get('Authorization')).toBe('Bearer named-jwt');
        return HttpResponse.json({ source: platformSource, active: null, viewer: { principalId: 'reviewer', principalKind: 'human', canActivate: true } });
      }),
      http.get('/api/v1/admin/configuration/platform/revisions', () => HttpResponse.json({ revisions: [] })),
    );
    render(<PlatformConfiguration />);
    expect(await screen.findByLabelText('Configuration source')).toHaveValue(JSON.stringify(platformSource, null, 2));
    expect(screen.queryByLabelText('Coactivate revision IDs')).not.toBeInTheDocument();
  });
  it('lets a readonly service draft with its named identity and preserves exact source', async () => {
    canActivate = false;
    const user = userEvent.setup(); render(<Configuration />);
    const editor = await screen.findByLabelText('Configuration source');
    await user.clear(editor);
    const exact = JSON.stringify(source, null, 2);
    await user.paste(exact);
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    await waitFor(() => expect(submitted).toBe(exact));
    expect(screen.queryByRole('button', { name: 'Activate reviewed revision' })).not.toBeInTheDocument();
  });

  it('requires review of the exact bundle before independent activation and reports pending publication', async () => {
    const user = userEvent.setup(); render(<Configuration />);
    await user.click(await screen.findByRole('button', { name: 'Review revision 1' }));
    await waitFor(() => expect(reviewCount).toBe(1));
    await user.click(screen.getByRole('button', { name: 'Activate reviewed revision' }));
    await waitFor(() => expect(activationCount).toBe(1));
    expect(await screen.findByText(/Publication pending/)).toBeInTheDocument();
    expect(screen.getByText(/Desired facts 8; node has applied 7/)).toBeInTheDocument();
  });

  it('does not offer self approval even to a full human administrator', async () => {
    viewerId = 'author';
    const user = userEvent.setup(); render(<Configuration />);
    await user.click(await screen.findByRole('button', { name: 'Review revision 1' }));
    await waitFor(() => expect(reviewCount).toBe(1));
    expect(screen.queryByRole('button', { name: 'Activate reviewed revision' })).not.toBeInTheDocument();
    expect(screen.getByText(/A different human administrator/)).toBeInTheDocument();
  });

  it('invalidates review when the coactivation bundle changes', async () => {
    const user = userEvent.setup(); render(<Configuration />);
    await user.click(await screen.findByRole('button', { name: 'Review revision 1' }));
    await screen.findByRole('button', { name: 'Activate reviewed revision' });
    await user.type(screen.getByLabelText('Coactivate revision IDs'), 'sibling-b');
    expect(screen.queryByRole('button', { name: 'Activate reviewed revision' })).not.toBeInTheDocument();
  });

  it('clears approval after a stale activation and shows the server conflict', async () => {
    server.use(http.post(`${base}/revisions/revision-a/activate`, () => HttpResponse.json({ error: 'base revision is stale; reload the context' }, { status: 409 })));
    const user = userEvent.setup(); render(<Configuration />);
    await user.click(await screen.findByRole('button', { name: 'Review revision 1' }));
    await user.click(await screen.findByRole('button', { name: 'Activate reviewed revision' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('base revision is stale');
    expect(screen.queryByRole('button', { name: 'Activate reviewed revision' })).not.toBeInTheDocument();
  });
});
