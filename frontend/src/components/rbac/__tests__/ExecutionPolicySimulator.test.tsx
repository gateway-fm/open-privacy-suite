import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import {
  mockDeniedSimulation,
  mockDraftRevision,
  mockPolicyContext,
} from '@/test/mocks/execution-policy-fixtures';
import ExecutionPolicySimulator from '../ExecutionPolicySimulator';

const SIMULATE_ROUTE =
  '/api/v1/admin/orgs/:orgId/execution-policy/revisions/:revisionId/simulate';

const STORAGE_ADDRESS = '0x1111111111111111111111111111111111111111';
const CALLDATA = '0xa9059cbb';

function renderSimulator() {
  renderWithRBACContext(
    <ExecutionPolicySimulator
      orgId="org-1"
      revision={mockDraftRevision}
      groups={mockPolicyContext.groups}
    />
  );
}

async function fillAndRun(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Storage address'), STORAGE_ADDRESS);
  await user.type(
    screen.getByLabelText('Calldata (0x-prefixed hex, selector included)'),
    CALLDATA
  );
  await user.click(screen.getByRole('button', { name: /Run simulation/i }));
}

describe('ExecutionPolicySimulator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('shows the denial with its code and the reason verbatim', async () => {
    server.use(http.post(SIMULATE_ROUTE, () => HttpResponse.json(mockDeniedSimulation)));

    const user = userEvent.setup();
    renderSimulator();
    await fillAndRun(user);

    const result = await screen.findByTestId('simulate-result');
    expect(result).toHaveTextContent('Denied');
    expect(screen.getByTestId('simulate-code')).toHaveTextContent('argument_constraint');
    expect(screen.getByTestId('simulate-reason')).toHaveTextContent(
      mockDeniedSimulation.reason as string
    );
    expect(screen.getByTestId('simulate-compiled')).toHaveTextContent(
      'denied (argument_constraint)'
    );
    // Both evaluators agreed, so there is no disagreement alarm.
    expect(screen.queryByTestId('simulate-disagreement')).not.toBeInTheDocument();
  });

  it('sends the described execution using the wire field names', async () => {
    let body: unknown;
    server.use(
      http.post(SIMULATE_ROUTE, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(mockDeniedSimulation);
      })
    );

    const user = userEvent.setup();
    renderSimulator();

    await user.click(screen.getByRole('checkbox', { name: 'Group group-traders' }));
    await user.type(screen.getByLabelText('Signer (optional)'), '0xabc');
    await user.type(screen.getByLabelText('Linked addresses (optional)'), '0xdef, 0x123');
    await fillAndRun(user);

    await screen.findByTestId('simulate-result');
    expect(body).toEqual({
      groups: ['group-traders'],
      signer: '0xabc',
      linked_addresses: ['0xdef', '0x123'],
      frames: [
        {
          call_type: 'call',
          storage_address: STORAGE_ADDRESS,
          calldata: CALLDATA,
        },
      ],
    });
  });

  it('raises a loud alarm when the two evaluators disagree', async () => {
    server.use(
      http.post(SIMULATE_ROUTE, () =>
        HttpResponse.json({
          ...mockDeniedSimulation,
          allowed: false,
          compiled_allowed: true,
          compiled_code: '',
          agreed: false,
        })
      )
    );

    const user = userEvent.setup();
    renderSimulator();
    await fillAndRun(user);

    const alarm = await screen.findByTestId('simulate-disagreement');
    expect(alarm).toHaveTextContent('The reviewed policy and the enforced policy disagree');
    expect(alarm).toHaveTextContent('Do not activate this revision');
    expect(alarm).toHaveAttribute('role', 'alert');
  });

  it('shows the server refusal when the described execution is malformed', async () => {
    server.use(
      http.post(SIMULATE_ROUTE, () =>
        HttpResponse.json({ error: 'frames[0].calldata: not 0x-prefixed hex' }, { status: 400 })
      )
    );

    const user = userEvent.setup();
    renderSimulator();
    await fillAndRun(user);

    await waitFor(() => {
      expect(screen.getByTestId('simulate-error')).toHaveTextContent(
        'frames[0].calldata: not 0x-prefixed hex'
      );
    });
  });
});
