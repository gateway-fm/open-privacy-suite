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

// Mock the useOrgContext hook from RBACManager, mirroring the other RBAC
// sub-tab tests: the shared TestOrgContext is what MockOrgProvider fills.
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

function useDefaultHandlers() {
  server.use(
    http.get(CONTEXT_ROUTE, () => HttpResponse.json(mockPolicyContext)),
    http.get(REVISIONS_ROUTE, () => HttpResponse.json(mockPolicyRevisions)),
    http.get(REVISION_ROUTE, () => HttpResponse.json(mockDraftRevisionDetail))
  );
}

describe('ExecutionPolicy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useDefaultHandlers();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Revision list', () => {
    it('lists every revision with its status, number and short runtime digest', async () => {
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('execution-policy-revisions')).toBeInTheDocument();
      });

      const draftRow = screen.getByTestId('revision-row-3');
      expect(draftRow).toHaveTextContent('draft');
      expect(draftRow).toHaveTextContent('333333333333');

      const activeRow = screen.getByTestId('revision-row-2');
      expect(activeRow).toHaveTextContent('active');
      expect(activeRow).toHaveTextContent('232323232323');

      expect(screen.getByTestId('revision-row-1')).toHaveTextContent('superseded');
    });

    it('says which revision is in force and that only one can be', async () => {
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('active-policy-banner')).toHaveTextContent(
          'Revision 2 is in force'
        );
      });

      expect(screen.getByTestId('active-policy-banner')).toHaveTextContent(
        'No other revision decides anything'
      );
      expect(
        screen.getByText(/Exactly one revision is active/i)
      ).toBeInTheDocument();
      expect(
        screen.getByText(/A draft — like a superseded or withdrawn revision — enforces nothing/i)
      ).toBeInTheDocument();
    });

    it('states that nothing is enforced when no revision is active', async () => {
      server.use(
        http.get(CONTEXT_ROUTE, () =>
          HttpResponse.json({ ...mockPolicyContext, active: undefined })
        ),
        http.get(REVISIONS_ROUTE, () => HttpResponse.json([]))
      );

      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('active-policy-banner')).toHaveTextContent(
          'No execution policy is in force'
        );
      });

      expect(
        screen.getByText(/No policy revision has been submitted for this organization yet/i)
      ).toBeInTheDocument();
    });

    it('surfaces a load failure instead of rendering an empty policy', async () => {
      server.use(
        http.get(CONTEXT_ROUTE, () =>
          HttpResponse.json({ error: 'failed to read organization' }, { status: 500 })
        )
      );

      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('execution-policy-load-error')).toHaveTextContent(
          'failed to read organization'
        );
      });
    });
  });

  describe('Revision review', () => {
    it('shows the document, the generated Solidity and all three digests', async () => {
      const user = userEvent.setup();
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('revision-row-3')).toBeInTheDocument();
      });

      await user.click(screen.getByRole('button', { name: /Review revision 3/i }));

      const detail = await screen.findByTestId('revision-detail');
      expect(screen.getByTestId('revision-source')).toHaveTextContent('ContractExecutionPolicy');
      expect(screen.getByTestId('revision-solidity')).toHaveTextContent(
        'contract GeneratedExecutionPolicy'
      );
      expect(detail).toHaveTextContent(mockDraftRevisionDetail.policy_digest);
      expect(detail).toHaveTextContent(mockDraftRevisionDetail.solidity_digest);
      expect(detail).toHaveTextContent(mockDraftRevisionDetail.runtime_digest);
    });

    it('warns what activation means before it is confirmed', async () => {
      const user = userEvent.setup();
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('revision-row-3')).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /Review revision 3/i }));
      await screen.findByTestId('revision-detail');

      await user.click(screen.getByRole('button', { name: /Activate…/i }));

      expect(await screen.findByText('Activate revision 3?')).toBeInTheDocument();
      expect(
        screen.getByText(/puts this revision in force immediately/i)
      ).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Activate and enforce' })).toBeInTheDocument();
    });

    it('shows the server refusal verbatim when a revision is no longer a draft', async () => {
      server.use(
        http.post(`${REVISION_ROUTE}/activate`, () =>
          HttpResponse.json(
            { error: 'policy revision is not a draft' },
            { status: 409 }
          )
        )
      );

      const user = userEvent.setup();
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('revision-row-3')).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /Review revision 3/i }));
      await screen.findByTestId('revision-detail');
      await user.click(screen.getByRole('button', { name: /Activate…/i }));
      await user.click(await screen.findByRole('button', { name: 'Activate and enforce' }));

      await waitFor(() => {
        expect(screen.getByTestId('execution-policy-action-error')).toHaveTextContent(
          'policy revision is not a draft'
        );
      });
    });
  });
});
