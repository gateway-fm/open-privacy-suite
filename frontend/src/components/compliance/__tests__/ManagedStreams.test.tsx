import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import ComplianceConfig from '../ComplianceConfig';
import TokenPriceList from '../TokenPriceList';
import AddressThresholdList from '../AddressThresholdList';

function complianceManaged(managed: boolean) {
  server.use(
    http.get('/api/v1/admin/orgs/:orgId/configuration/:kind/managed', ({ params }) =>
      HttpResponse.json({ kind: params.kind, managed: managed && params.kind === 'compliance' })
    )
  );
}

/**
 * RD-1295: the compliance document owns settings, token entries and address
 * thresholds once it is active. The three screens keep showing the values and
 * stop offering edits the server would refuse.
 */
describe('Managed compliance stream in the compliance screens (RD-1295)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('ComplianceConfig shows the settings read-only with the notice', async () => {
    complianceManaged(true);
    renderWithComplianceContext(<ComplianceConfig />);

    await waitFor(() => {
      expect(screen.getByText('Compliance Configuration')).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByTestId('managed-stream-notice')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /save configuration/i })).not.toBeInTheDocument();
    const toggle = screen.getAllByRole('button').find((b) => /^(Enabled|Disabled)/.test(b.textContent ?? ''));
    expect(toggle).toBeDefined();
    expect(toggle).toBeDisabled();
  });

  it('ComplianceConfig keeps its controls while the stream is unmanaged', async () => {
    complianceManaged(false);
    renderWithComplianceContext(<ComplianceConfig />);

    await waitFor(() => {
      expect(screen.getByText('Save Configuration')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('managed-stream-notice')).not.toBeInTheDocument();
  });

  it('TokenPriceList offers no Add Token control', async () => {
    complianceManaged(true);
    renderWithComplianceContext(<TokenPriceList />);

    await waitFor(() => {
      expect(screen.getByText('Per-Organization Token Prices')).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByTestId('managed-stream-notice')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /add token/i })).not.toBeInTheDocument();
  });

  it('AddressThresholdList offers no Add Override control', async () => {
    complianceManaged(true);
    renderWithComplianceContext(<AddressThresholdList />);

    await waitFor(() => {
      expect(screen.getByTestId('managed-stream-notice')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /add override/i })).not.toBeInTheDocument();
  });
});
