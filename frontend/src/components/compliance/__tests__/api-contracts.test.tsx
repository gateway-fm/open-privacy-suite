/**
 * Backend Response Contract Tests
 *
 * These tests verify that the frontend compliance components correctly handle
 * the EXACT response shapes returned by the real backend (admin_compliance.go).
 *
 * Purpose: Catch frontend/backend contract mismatches that regular MSW-mocked
 * tests miss because the mocks might not match the real backend shapes.
 *
 * Real backend response shapes:
 *   GET  /config              -> ComplianceConfig directly (no wrapper)
 *   PUT  /config              -> ComplianceConfig directly (no wrapper)
 *   GET  /tokens              -> {data: TokenPrice[]} (wrapped, NOT paginated)
 *   PUT  /tokens/:addr        -> TokenPrice directly (no wrapper)
 *   DELETE /tokens/:addr      -> {message: "token price deleted"}
 *   GET  /travel-rule-records -> {data: TravelRuleRecord[], total, limit, offset} (paginated)
 *   POST /travel-rule-records -> TravelRuleRecord directly with 201
 *   GET  /sanctions           -> {data: SanctionedAddress[], total, limit, offset} (paginated)
 *   POST /sanctions           -> SanctionedAddress directly with 201
 *   DELETE /sanctions/:id     -> {message: "sanctioned address removed"}
 *   GET  /logs                -> {data: ComplianceLog[], total, limit, offset} (paginated)
 *   GET  /address-thresholds    -> {data: AddressThresholdOverride[], total, limit, offset} (paginated)
 *   PUT  /address-thresholds/:addr -> AddressThresholdOverride directly (no wrapper)
 *   DELETE /address-thresholds/:addr -> {message: "address threshold override deleted"}
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';

// vi.mock is hoisted, so this single mock covers all 5 component imports below
vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

// Import all components AFTER the vi.mock
import TokenPriceList from '../TokenPriceList';
import ComplianceConfig from '../ComplianceConfig';
import TravelRuleRecordList from '../TravelRuleRecordList';
import SanctionsList from '../SanctionsList';
import ComplianceLogList from '../ComplianceLogList';
import AddressThresholdList from '../AddressThresholdList';

// ---------------------------------------------------------------------------
// Realistic mock data matching the exact shapes the Go backend returns
// ---------------------------------------------------------------------------

const realisticTokenPrices = [
  {
    id: 'tp-1', org_id: 'org-1', token_address: 'native',
    symbol: 'ETH', decimals: 18, price_fiat: 2500,
    created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-15T00:00:00Z',
  },
];

const realisticConfig = {
  id: 'cfg-1', org_id: 'org-1', enabled: true, threshold_fiat: 3000,
  created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-15T00:00:00Z',
};

const realisticTravelRuleRecords = [
  {
    id: 'tr-1', org_id: 'org-1', originator_user_id: 'user-abc-123',
    originator_external_id: 'did:polygonid:polygon:main:user123',
    originator_data: { name: 'Alice' }, beneficiary_data: { name: 'Bob' },
    transfer_type: 'eth', beneficiary_address: '0xabcdef1234567890abcdef1234567890abcdef12',
    amount_wei: '1000000000000000000', amount_fiat: 2500,
    expires_at: new Date(Date.now() + 86400000).toISOString(),
    created_at: '2024-01-15T00:00:00Z',
  },
];

const realisticSanctions = [
  {
    id: 'sanc-1', address: '0x1234567890abcdef1234567890abcdef12345678',
    reason: 'OFAC SDN list', source: 'OFAC', org_id: null,
    created_at: '2024-01-10T00:00:00Z', updated_at: '2024-01-10T00:00:00Z',
  },
];

const realisticAddressThresholds = [
  {
    id: 'ato-1', org_id: 'org-1', address: '0xabcdef1234567890abcdef1234567890abcdef12',
    threshold_fiat: 100, note: 'High-risk counterparty',
    created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-15T00:00:00Z',
  },
];

const realisticLogs = [
  {
    id: 1, org_id: 'org-1', user_id: 'user-abc-12345678',
    user_external_id: 'did:polygonid:polygon:main:user123',
    transfer_type: 'eth', from_address: '0xaaaa00000000000000000000000000000000aaaa',
    to_address: '0xbbbb00000000000000000000000000000000bbbb',
    amount_wei: '5000000000000000000', amount_fiat: 12500,
    threshold_fiat: 3000, decision: 'allowed', created_at: '2024-01-15T10:00:00Z',
  },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('API Route Path Contract Tests', () => {
  // These tests verify the frontend API client uses the correct URL paths
  // matching the backend route registration (no /admin/ prefix).
  // Backend registers: apiV1.Group("/orgs/:org_id/compliance") and apiV1.Group("/compliance")
  it('compliance API paths match backend routes (no /admin/ prefix)', async () => {
    const { complianceApi } = await import('@/api/compliance');

    // Spy on the underlying axios instance to capture request URLs
    const api = (await import('@/api/client')).default;
    const getSpy = vi.spyOn(api, 'get').mockResolvedValue({ data: {} });
    const putSpy = vi.spyOn(api, 'put').mockResolvedValue({ data: {} });
    const postSpy = vi.spyOn(api, 'post').mockResolvedValue({ data: {} });
    const deleteSpy = vi.spyOn(api, 'delete').mockResolvedValue({ data: {} });

    // Call each API method and verify the URL path
    await complianceApi.config.get('org-1');
    expect(getSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/config');

    await complianceApi.config.update('org-1', { enabled: true });
    expect(putSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/config', { enabled: true });

    await complianceApi.tokens.list('org-1');
    expect(getSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/tokens');

    await complianceApi.tokens.upsert('org-1', 'native', { symbol: 'ETH', decimals: 18, prices: { usd: 2500 } });
    expect(putSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/tokens/native', { symbol: 'ETH', decimals: 18, prices: { usd: 2500 } });

    await complianceApi.tokens.delete('org-1', 'native');
    expect(deleteSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/tokens/native');

    await complianceApi.travelRules.list('org-1', { limit: 25, offset: 0 });
    expect(getSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/travel-rule-records', { params: { limit: 25, offset: 0 } });

    // C3: amount_fiat is no longer sent by the client; server computes it
    await complianceApi.travelRules.create('org-1', {
      originator_user_id: 'u1', originator_data: {}, beneficiary_data: {},
      transfer_type: 'eth', beneficiary_address: '0x1234567890123456789012345678901234567890',
      amount_wei: '1000',
    });
    expect(postSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/travel-rule-records', expect.any(Object));

    await complianceApi.travelRules.delete('org-1', 'tr-1');
    expect(deleteSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/travel-rule-records/tr-1');

    await complianceApi.sanctions.list({ limit: 25 });
    expect(getSpy).toHaveBeenCalledWith('/compliance/sanctions', { params: { limit: 25 } });

    await complianceApi.sanctions.add({ address: '0x1234567890123456789012345678901234567890', reason: 'test' });
    expect(postSpy).toHaveBeenCalledWith('/compliance/sanctions', expect.any(Object));

    await complianceApi.sanctions.remove('sanc-1');
    expect(deleteSpy).toHaveBeenCalledWith('/compliance/sanctions/sanc-1');

    await complianceApi.addressThresholds.list('org-1', { limit: 25, offset: 0 });
    expect(getSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/address-thresholds', { params: { limit: 25, offset: 0 } });

    await complianceApi.addressThresholds.upsert('org-1', '0x1234567890123456789012345678901234567890', { threshold_fiat: 100 });
    expect(putSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/address-thresholds/0x1234567890123456789012345678901234567890', { threshold_fiat: 100 });

    await complianceApi.addressThresholds.delete('org-1', '0x1234567890123456789012345678901234567890');
    expect(deleteSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/address-thresholds/0x1234567890123456789012345678901234567890');

    await complianceApi.logs.list('org-1', { limit: 25 });
    expect(getSpy).toHaveBeenCalledWith('/orgs/org-1/compliance/logs', { params: { limit: 25 } });

    // Verify NO call used /admin/ prefix
    for (const spy of [getSpy, putSpy, postSpy, deleteSpy]) {
      for (const call of spy.mock.calls) {
        expect(call[0]).not.toContain('/admin/');
      }
    }

    getSpy.mockRestore();
    putSpy.mockRestore();
    postSpy.mockRestore();
    deleteSpy.mockRestore();
  });
});

describe('Backend Response Contract Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('token prices list parses wrapped {data: [...]} response', async () => {
    // Backend returns {data: TokenPrice[]} — NOT a raw array, NOT paginated
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
        return HttpResponse.json({ data: realisticTokenPrices });
      }),
    );

    renderWithComplianceContext(<TokenPriceList />);

    await waitFor(() => {
      // ETH appears in both system prices section and per-org table
      expect(screen.getAllByText('ETH').length).toBeGreaterThanOrEqual(1);
    });

    // Verify the token address is displayed (rendered as "native (ETH)")
    expect(screen.getByText('native (ETH)')).toBeInTheDocument();
  });

  it('compliance config parses unwrapped response', async () => {
    // Backend returns ComplianceConfig directly — no wrapper object
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/config', () => {
        return HttpResponse.json(realisticConfig);
      }),
    );

    renderWithComplianceContext(<ComplianceConfig />);

    await waitFor(() => {
      expect(screen.getByText('Controls Configuration')).toBeInTheDocument();
    });

    // Verify the enabled badge renders
    expect(screen.getByText('Enabled')).toBeInTheDocument();

    // Verify the threshold value is populated in the input
    expect(screen.getByDisplayValue('3000')).toBeInTheDocument();

    // Verify the last updated timestamp is shown
    expect(screen.getByText(/Last updated:/)).toBeInTheDocument();
  });

  it('travel rule records list parses paginated response', async () => {
    // Backend returns {data: TravelRuleRecord[], total, limit, offset}
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', () => {
        return HttpResponse.json({
          data: realisticTravelRuleRecords,
          total: 1,
          limit: 25,
          offset: 0,
        });
      }),
    );

    renderWithComplianceContext(<TravelRuleRecordList />);

    await waitFor(() => {
      expect(screen.getByText('Travel Rule Records')).toBeInTheDocument();
    });

    // Verify record data renders: originator DID (truncated since > 20 chars)
    expect(screen.getByText('did:polygonid:p...')).toBeInTheDocument();

    // Verify the amount USD is displayed
    expect(screen.getByText('$2,500.00')).toBeInTheDocument();

    // Verify the transfer type badge
    expect(screen.getByText('ETH')).toBeInTheDocument();

    // Verify status badge (expires_at is in the future, not used -> "unused")
    expect(screen.getByText('unused')).toBeInTheDocument();
  });

  it('sanctions list parses paginated response', async () => {
    // Backend returns {data: SanctionedAddress[], total, limit, offset}
    server.use(
      http.get('/api/v1/admin/compliance/sanctions', () => {
        return HttpResponse.json({
          data: realisticSanctions,
          total: 1,
          limit: 25,
          offset: 0,
        });
      }),
    );

    renderWithComplianceContext(<SanctionsList />);

    await waitFor(() => {
      expect(screen.getByText('Sanctioned Addresses')).toBeInTheDocument();
    });

    // Verify the reason column displays the sanction reason
    expect(screen.getByText('OFAC SDN list')).toBeInTheDocument();

    // Verify the source column
    expect(screen.getByText('OFAC')).toBeInTheDocument();

    // Verify the scope badge (org_id is null -> Global)
    expect(screen.getByText('Global')).toBeInTheDocument();
  });

  it('address thresholds list parses paginated response', async () => {
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/address-thresholds', () => {
        return HttpResponse.json({
          data: realisticAddressThresholds,
          total: 1,
          limit: 25,
          offset: 0,
        });
      }),
    );

    renderWithComplianceContext(<AddressThresholdList />);

    await waitFor(() => {
      expect(screen.getByText('0xabcdef1234567890abcdef1234567890abcdef12')).toBeInTheDocument();
    });

    expect(screen.getByText('High-risk counterparty')).toBeInTheDocument();
  });

  it('compliance logs list parses paginated response', async () => {
    // Backend returns {data: ComplianceLog[], total, limit, offset}
    server.use(
      http.get('/api/v1/admin/orgs/:orgId/compliance/logs', () => {
        return HttpResponse.json({
          data: realisticLogs,
          total: 1,
          limit: 25,
          offset: 0,
        });
      }),
    );

    renderWithComplianceContext(<ComplianceLogList />);

    await waitFor(() => {
      expect(screen.getByText('Controls Logs')).toBeInTheDocument();
    });

    // Verify the user DID is displayed (truncated since > 20 chars)
    expect(screen.getByText('did:polygonid:p...')).toBeInTheDocument();

    // Verify transfer type badge
    expect(screen.getByText('ETH')).toBeInTheDocument();

    // Verify amount USD
    expect(screen.getByText('$12,500.00')).toBeInTheDocument();

    // Verify decision badge
    expect(screen.getByText('allowed')).toBeInTheDocument();
  });
});
