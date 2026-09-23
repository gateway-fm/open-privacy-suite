import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';

// The route's only input besides the server is the signed-in token.
const auth = vi.hoisted(() => ({ token: 'named-jwt' }));
vi.mock('@/contexts/AuthContext', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/contexts/AuthContext')>();
  return { ...actual, useAuth: () => ({ ...actual.useAuth?.(), accessToken: auth.token, isLoading: false }) };
});

vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

import ExecutionPolicyRoute from '../ExecutionPolicyRoute';

const STATUS = '/api/v1/admin/status';
const EXECUTION_RULES_CONTEXT = '/api/v1/admin/orgs/:orgId/configuration/:kind/context';

function statusWith(execution: unknown) {
  return http.get(STATUS, () => HttpResponse.json({ proxy: { status: 'running' }, execution }));
}

// A minimal execution-rules context and an empty revision list, so the Reth
// screen renders past its own loads.
function executionRulesRevisions() {
  return http.get('/api/v1/admin/orgs/:orgId/configuration/:kind/revisions', () => HttpResponse.json({ revisions: [] }));
}
function executionRulesContext(seen: { count: number }) {
  return http.get(EXECUTION_RULES_CONTEXT, ({ params }) => {
    if (params.kind === 'execution-rules') seen.count += 1;
    return HttpResponse.json({
      active: null,
      source: { apiVersion: 'ops.configuration/v1', kind: 'execution-rules' },
      viewer: { principalId: 'me', principalKind: 'human', canActivate: false },
      capabilities: {
        apiVersion: 'ops.configuration/v1',
        kinds: ['execution-rules'],
        humanOnlyKinds: [],
        approvalModes: ['human'],
        maxDocumentBytes: 1048576,
        compiler: { version: '0.8.35', available: true },
      },
    });
  });
}

/**
 * ExecutionPolicyRoute is the switch between two products: in Reth mode the
 * configuration document screen, in legacy mode the legacy revisions screen.
 * It decides from the server's reported mode, so the default mock must report
 * one, and every outcome of the probe must land on a definite screen.
 */
describe('ExecutionPolicyRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth.token = 'named-jwt';
  });

  afterEach(() => {
    cleanup();
  });

  it('renders the legacy screen under the default mocks, which report legacy mode', async () => {
    renderWithRBACContext(<ExecutionPolicyRoute />);
    expect(await screen.findByRole('heading', { name: 'Execution Policy' })).toBeInTheDocument();
    // The legacy screen may show its own load alert under the default mocks;
    // what must be absent is the route's verdict that the mode is unknown.
    expect(screen.queryByText(/Execution mode is unavailable/)).not.toBeInTheDocument();
  });

  it('renders the configuration document screen for Reth mode, selecting execution rules', async () => {
    const seen = { count: 0 };
    server.use(statusWith({ mode: 'reth', ready: true }), executionRulesContext(seen), executionRulesRevisions());
    renderWithRBACContext(<ExecutionPolicyRoute />);
    await waitFor(() => {
      expect(seen.count).toBeGreaterThan(0);
    });
    expect(await screen.findByText('Configuration source')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Execution Policy' })).not.toBeInTheDocument();
  });

  it('renders the legacy screen for legacy mode', async () => {
    server.use(statusWith({ mode: 'legacy', ready: true }));
    renderWithRBACContext(<ExecutionPolicyRoute />);
    expect(await screen.findByRole('heading', { name: 'Execution Policy' })).toBeInTheDocument();
  });

  it('shows the probe state while the server has not answered', async () => {
    server.use(
      http.get(STATUS, async () => {
        await delay('infinite');
        return HttpResponse.json({});
      })
    );
    const { unmount } = renderWithRBACContext(<ExecutionPolicyRoute />);
    expect(screen.getByRole('status')).toHaveTextContent('Checking execution mode');
    unmount();
  });

  it('reports an unavailable mode and re-probes on Retry', async () => {
    const user = userEvent.setup();
    let calls = 0;
    const seen = { count: 0 };
    server.use(
      http.get(STATUS, () => {
        calls += 1;
        // First answer carries no execution block; the retry lands on Reth.
        return HttpResponse.json(calls === 1 ? { proxy: { status: 'running' } } : { proxy: { status: 'running' }, execution: { mode: 'reth', ready: true } });
      }),
      executionRulesContext(seen),
      executionRulesRevisions()
    );
    renderWithRBACContext(<ExecutionPolicyRoute />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Execution mode is unavailable');
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Configuration source')).toBeInTheDocument();
    // The route probed twice; the configuration screen then polls readiness on
    // the same endpoint, so the count is a floor, not an exact figure.
    expect(calls).toBeGreaterThanOrEqual(2);
  });

  it('reports an unavailable mode when the status call fails', async () => {
    server.use(http.get(STATUS, () => HttpResponse.json({ error: 'down' }, { status: 500 })));
    renderWithRBACContext(<ExecutionPolicyRoute />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Execution mode is unavailable');
  });

  it('asks for a named login without probing when there is no token', async () => {
    auth.token = '';
    let calls = 0;
    server.use(
      http.get(STATUS, () => {
        calls += 1;
        return HttpResponse.json({});
      })
    );
    renderWithRBACContext(<ExecutionPolicyRoute />);
    expect(screen.getByText(/Sign in with a named account/)).toBeInTheDocument();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(calls).toBe(0);
  });
});
