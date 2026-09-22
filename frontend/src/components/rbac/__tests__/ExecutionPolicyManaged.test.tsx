import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import {
  mockDraftRevisionDetail,
  mockPolicyContext,
  mockPolicyRevisions,
} from '@/test/mocks/execution-policy-fixtures';

vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

import ExecutionPolicy from '../ExecutionPolicy';

const CONTEXT_ROUTE = '/api/v1/admin/orgs/:orgId/execution-policy/context';
const REVISIONS_ROUTE = '/api/v1/admin/orgs/:orgId/execution-policy/revisions';
const REVISION_ROUTE = '/api/v1/admin/orgs/:orgId/execution-policy/revisions/:revisionId';
const MANAGED_ROUTE = '/api/v1/admin/orgs/:orgId/configuration/:kind/managed';

/**
 * RD-1295: the legacy execution-policy screen is shown in legacy mode. Once a
 * reviewed execution-rules document owns the organisation, its draft, activate
 * and withdraw calls answer 409, so the screen keeps the revision history and
 * review surface but stops offering those controls.
 */
describe('ExecutionPolicy under a managed execution-rules stream (RD-1295)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    server.use(
      http.get(CONTEXT_ROUTE, () => HttpResponse.json(mockPolicyContext)),
      http.get(REVISIONS_ROUTE, () => HttpResponse.json(mockPolicyRevisions)),
      http.get(REVISION_ROUTE, () => HttpResponse.json(mockDraftRevisionDetail))
    );
  });

  afterEach(() => {
    cleanup();
  });

  it('shows the notice, disables the editor and offers no activate or withdraw', async () => {
    const user = userEvent.setup();
    server.use(
      http.get(MANAGED_ROUTE, ({ params }) =>
        HttpResponse.json({ kind: params.kind, managed: params.kind === 'execution-rules' })
      )
    );
    renderWithRBACContext(<ExecutionPolicy />);

    await waitFor(() => {
      expect(screen.getByTestId('execution-policy-revisions')).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByTestId('managed-stream-notice')).toBeInTheDocument();
    });

    // The candidate editor is present for reading but cannot submit.
    for (const box of screen.getAllByRole('textbox')) {
      expect(box).toBeDisabled();
    }

    // Reviewing the draft still works; approving it from here does not.
    await user.click(screen.getByRole('button', { name: /Review revision 3/i }));
    await waitFor(() => {
      expect(screen.getByTestId('revision-source')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /Activate…/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Withdraw draft/i })).not.toBeInTheDocument();
  });

  it('keeps activate and withdraw while the stream is unmanaged', async () => {
    const user = userEvent.setup();
    renderWithRBACContext(<ExecutionPolicy />);

    await waitFor(() => {
      expect(screen.getByTestId('execution-policy-revisions')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('managed-stream-notice')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Review revision 3/i }));
    expect(await screen.findByRole('button', { name: /Activate…/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Withdraw draft/i })).toBeInTheDocument();
  });
});
