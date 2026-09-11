import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import {
  mockDraftRevisionDetail,
  mockPolicyContext,
} from '@/test/mocks/execution-policy-fixtures';
import ExecutionPolicyEditor from '../ExecutionPolicyEditor';

const SUBMIT_ROUTE = '/api/v1/admin/orgs/:orgId/execution-policy/revisions';

function renderEditor(overrides: Partial<Parameters<typeof ExecutionPolicyEditor>[0]> = {}) {
  const props = {
    orgId: 'org-1',
    context: mockPolicyContext,
    onSubmitted: vi.fn(),
    onReloadContext: vi.fn(),
    ...overrides,
  };
  renderWithRBACContext(<ExecutionPolicyEditor {...props} />);
  return props;
}

function documentTextarea(): HTMLTextAreaElement {
  return screen.getByLabelText('Policy document (JSON)') as HTMLTextAreaElement;
}

describe('ExecutionPolicyEditor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Skeleton', () => {
    it('prefills a valid skeleton built from the editing context', () => {
      renderEditor();

      const parsed = JSON.parse(documentTextarea().value);
      expect(parsed).toEqual({
        apiVersion: mockPolicyContext.api_version,
        kind: mockPolicyContext.kind,
        org: mockPolicyContext.org_id,
        nestedCalls: mockPolicyContext.nested_calls,
        bindings: [],
      });
    });

    it('shows the bindable groups and the ABI digest a rule must pin', () => {
      renderEditor();

      expect(screen.getByTestId('editor-groups')).toHaveTextContent('group-traders');
      expect(screen.getByTestId('editor-groups')).toHaveTextContent('group-ops');

      const contracts = screen.getByTestId('editor-contracts');
      expect(contracts).toHaveTextContent('Settlement');
      expect(contracts).toHaveTextContent(mockPolicyContext.contracts[0].address);
      expect(contracts).toHaveTextContent(mockPolicyContext.contracts[0].abi_digest as string);
      // A contract without a registered ABI cannot carry a rule, so it is not
      // offered as one that can.
      expect(contracts).not.toHaveTextContent('Unregistered');
      expect(
        screen.getByText(/1 contract without a registered ABI cannot carry a rule/i)
      ).toBeInTheDocument();
    });

    it('submits the parsed document against the context base revision', async () => {
      let body: unknown;
      server.use(
        http.post(SUBMIT_ROUTE, async ({ request }) => {
          body = await request.json();
          return HttpResponse.json(mockDraftRevisionDetail, { status: 201 });
        })
      );

      const user = userEvent.setup();
      const props = renderEditor();

      await user.click(screen.getByRole('button', { name: /Submit candidate/i }));

      await waitFor(() => {
        expect(props.onSubmitted).toHaveBeenCalledWith(mockDraftRevisionDetail);
      });
      expect(body).toEqual({
        policy: {
          apiVersion: mockPolicyContext.api_version,
          kind: mockPolicyContext.kind,
          org: mockPolicyContext.org_id,
          nestedCalls: mockPolicyContext.nested_calls,
          bindings: [],
        },
        base_revision: mockPolicyContext.base_revision,
      });
      expect(screen.getByText(/Draft revision 3 stored/i)).toBeInTheDocument();
    });
  });

  describe('Rejected submissions', () => {
    it('shows the validation message verbatim, naming the field at fault', async () => {
      const validationMessage =
        'bindings[0].allow[0].abiDigest: does not match the ABI registered for 0x1111111111111111111111111111111111111111';
      server.use(
        http.post(SUBMIT_ROUTE, () =>
          HttpResponse.json({ error: validationMessage }, { status: 400 })
        )
      );

      const user = userEvent.setup();
      const props = renderEditor();

      await user.click(screen.getByRole('button', { name: /Submit candidate/i }));

      const alert = await screen.findByTestId('policy-submit-error');
      expect(alert).toHaveTextContent('The policy was rejected');
      expect(alert).toHaveTextContent(validationMessage);
      expect(props.onSubmitted).not.toHaveBeenCalled();
    });

    it('tells the author to reload and rebase when the base revision is stale', async () => {
      server.use(
        http.post(SUBMIT_ROUTE, () =>
          HttpResponse.json(
            { error: 'policy base revision 3 is stale; latest is 4' },
            { status: 409 }
          )
        )
      );

      const user = userEvent.setup();
      const props = renderEditor();

      await user.click(screen.getByRole('button', { name: /Submit candidate/i }));

      const alert = await screen.findByTestId('policy-submit-error');
      expect(alert).toHaveTextContent("This organization's policy changed while you were editing");
      expect(alert).toHaveTextContent('Nothing was saved');
      expect(alert).toHaveTextContent('re-apply your changes on top of the new base');
      expect(alert).toHaveTextContent('policy base revision 3 is stale; latest is 4');

      await user.click(screen.getByRole('button', { name: /Reload context/i }));
      expect(props.onReloadContext).toHaveBeenCalled();
    });

    it('rejects a document that is not JSON before sending it', async () => {
      const user = userEvent.setup();
      renderEditor();

      const textarea = documentTextarea();
      await user.clear(textarea);
      await user.type(textarea, 'not json at all');

      await user.click(screen.getByRole('button', { name: /Submit candidate/i }));

      expect(await screen.findByTestId('policy-submit-error')).toHaveTextContent(
        'The document is not valid JSON'
      );
    });
  });
});
