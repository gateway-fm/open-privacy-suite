import { http, HttpResponse } from 'msw';
import type {
  AuthRequestResponse,
  AuthTokenResponse,
} from '@/api/auth';
import type {
  Organization,
  Group,
  User,
  Contract,
  ContractGrant,
  GroupAccess,
  EffectivePermissions,
  UserMembership,
  MembershipWithDetails,
  Claim,
} from '@/types/rbac';

// Mock data fixtures
export const mockAuthRequest: AuthRequestResponse = {
  session_id: 'test-session-123',
  auth_request: {
    id: 'auth-req-456',
    typ: 'application/iden3comm-plain-json',
    type: 'https://iden3-communication.io/authorization/1.0/request',
    body: {
      callbackUrl: 'http://localhost:8080/api/auth/callback',
      reason: 'Open Privacy Suite Authentication',
      scope: [],
    },
    from: 'did:polygonid:polygon:main:verifier123',
  },
};

export const mockTokenResponse: AuthTokenResponse = {
  access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bWFpbjp1c2VyMTIzIiwiZXhwIjoxNzA0MDY3MjAwfQ.test',
  refresh_token: 'refresh-token-abc123',
  token_type: 'Bearer',
  expires_in: 3600,
};

export const mockOrganization: Organization = {
  id: 'org-1',
  slug: 'test-org',
  name: 'Test Organization',
  settings: {},
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockGroup: Group = {
  id: 'group-1',
  org_id: 'org-1',
  parent_id: null,
  slug: 'root',
  name: 'Root Group',
  description: 'The root group',
  depth: 0,
  path: 'root',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockUser: User = {
  id: 'user-1',
  external_id: 'did:polygonid:polygon:main:user123',
  kyc: true,
  banned: false,
  note: '',
  metadata: {},
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockContract: Contract = {
  id: 'contract-1',
  address: '0x1234567890123456789012345678901234567890',
  org_id: 'org-1',
  name: 'Test Contract',
  deployed_by_user_id: null,
  deployed_at: null,
  metadata: {},
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockGroupAccess: GroupAccess = {
  id: 'access-1',
  group_id: 'group-1',
  allowed_methods: ['eth_call', 'eth_getBalance'],
  claims: [],
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockMembership: UserMembership = {
  id: 'membership-1',
  user_id: 'user-1',
  group_id: 'group-1',
  source: 'admin',
  zk_credential_ref: '',
  expires_at: null,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockMembershipWithDetails: MembershipWithDetails = {
  membership: mockMembership,
  group: mockGroup,
};

export const mockEffectivePermissions: EffectivePermissions = {
  id: 'eff-perms-1',
  user_id: 'user-1',
  org_id: 'org-1',
  allowed_methods: ['eth_call', 'eth_getBalance', 'eth_sendTransaction'],
  contract_access: {
    '0x1234567890123456789012345678901234567890': {
      claims: [] as Claim[],
      functions: null,
    },
  },
  claims: [] as Claim[],
  rate_limit_rps: 100,
  rate_limit_daily: 10000,
  computed_at: '2024-01-01T00:00:00Z',
  expires_at: '2024-01-02T00:00:00Z',
};

// Linked ETH addresses for user
export const mockLinkedAddresses = [
  { address: '0x1234567890123456789012345678901234567890', verified_at: '2024-01-01T00:00:00Z' },
  { address: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd', verified_at: '2024-01-15T00:00:00Z' },
];

// Contract grants linking groups to contracts
// Claims are inherited from the group's GroupAccess.claims
export const mockContractGrant: ContractGrant = {
  id: 'grant-1',
  contract_id: 'contract-1',
  group_id: 'group-1',
  functions: null,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

// Additional user for multi-user testing
export const mockUser2: User = {
  id: 'user-2',
  external_id: 'did:polygonid:polygon:main:user456',
  kyc: false,
  banned: false,
  note: 'Secondary test user',
  metadata: {},
  created_at: '2024-01-10T00:00:00Z',
  updated_at: '2024-01-10T00:00:00Z',
};

// Additional organization for multi-org testing
export const mockOrganization2: Organization = {
  id: 'org-2',
  slug: 'other-org',
  name: 'Other Organization',
  settings: {},
  created_at: '2024-01-15T00:00:00Z',
  updated_at: '2024-01-15T00:00:00Z',
};

// Additional group for nested hierarchy testing
export const mockChildGroup: Group = {
  id: 'group-2',
  org_id: 'org-1',
  parent_id: 'group-1',
  slug: 'engineering',
  name: 'Engineering',
  description: 'Engineering team',
  depth: 1,
  path: 'root.engineering',
  created_at: '2024-01-02T00:00:00Z',
  updated_at: '2024-01-02T00:00:00Z',
};

// Second membership for multi-membership testing
export const mockMembership2: UserMembership = {
  id: 'membership-2',
  user_id: 'user-1',
  group_id: 'group-2',
  source: 'zk_attested',
  zk_credential_ref: 'cred:polygonid:credential:12345',
  expires_at: '2025-01-01T00:00:00Z',
  created_at: '2024-01-10T00:00:00Z',
  updated_at: '2024-01-10T00:00:00Z',
};

export const mockMembershipWithDetails2: MembershipWithDetails = {
  membership: mockMembership2,
  group: mockChildGroup,
};

// =========================================================================
// Compliance mock data
// =========================================================================
import type {
  ComplianceConfig as ComplianceConfigType,
  TokenPrice,
  TravelRuleRecord,
  SanctionedAddress,
  ComplianceLog,
  AddressThresholdOverride,
} from '@/types/compliance';

export const mockComplianceConfig: ComplianceConfigType = {
  id: 'config-1',
  org_id: 'org-1',
  enabled: true,
  threshold_fiat: 1000,
  currency: 'usd',
  enforcement_mode: 'enforce',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

export const mockTokenPrices: TokenPrice[] = [
  {
    id: 'token-1',
    org_id: 'org-1',
    token_address: 'native',
    symbol: 'ETH',
    decimals: 18,
    price_fiat: 2500,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'token-2',
    org_id: 'org-1',
    token_address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
    symbol: 'USDT',
    decimals: 6,
    price_fiat: 1,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
];

export const mockTravelRuleRecords: TravelRuleRecord[] = [
  {
    id: 'tr-1',
    org_id: 'org-1',
    originator_user_id: 'user-1',
    originator_external_id: 'did:test:alice',
    originator_data: { name: 'Alice' },
    beneficiary_data: { name: 'Bob' },
    transfer_type: 'eth',
    beneficiary_address: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
    amount_wei: '1000000000000000000',
    amount_fiat: 2500,
    expires_at: new Date(Date.now() + 86400000).toISOString(),
    created_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'tr-2',
    org_id: 'org-1',
    originator_user_id: 'user-2',
    originator_external_id: 'did:test:charlie',
    originator_data: { name: 'Charlie' },
    beneficiary_data: { name: 'Dave' },
    transfer_type: 'erc20',
    token_address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
    beneficiary_address: '0x1234567890123456789012345678901234567890',
    amount_wei: '5000000000',
    amount_fiat: 5000,
    expires_at: '2024-01-01T00:00:00Z',
    used_at: '2024-01-02T00:00:00Z',
    used_tx_hash: '0xdeadbeef',
    created_at: '2024-01-01T00:00:00Z',
  },
];

export const mockSanctionedAddresses: SanctionedAddress[] = [
  {
    id: 'sanction-1',
    address: '0xbadaddress000000000000000000000000000dead',
    reason: 'OFAC SDN list',
    source: 'OFAC',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'sanction-2',
    org_id: 'org-1',
    address: '0xsuspicious0000000000000000000000000000bad',
    reason: 'Internal investigation',
    source: 'manual',
    created_at: '2024-01-15T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
];

export const mockComplianceLogs: ComplianceLog[] = [
  {
    id: 1,
    org_id: 'org-1',
    user_id: 'user-1',
    user_external_id: 'did:test:alice',
    transfer_type: 'eth',
    from_address: '0x1111111111111111111111111111111111111111',
    to_address: '0x2222222222222222222222222222222222222222',
    amount_wei: '500000000000000000',
    amount_fiat: 1250,
    threshold_fiat: 1000,
    decision: 'allowed',
    travel_rule_record_id: 'tr-1',
    created_at: '2024-01-15T10:30:00Z',
  },
  {
    id: 2,
    org_id: 'org-1',
    user_id: 'user-2',
    user_external_id: 'did:test:bob',
    transfer_type: 'erc20',
    token_address: '0xdac17f958d2ee523a2206206994597c13d831ec7',
    from_address: '0x3333333333333333333333333333333333333333',
    to_address: '0xbadaddress000000000000000000000000000dead',
    amount_wei: '2000000000',
    amount_fiat: 2000,
    threshold_fiat: 1000,
    decision: 'denied',
    denial_reason: 'sanctioned_address',
    created_at: '2024-01-15T11:00:00Z',
  },
];

export const mockAddressThresholdOverrides: AddressThresholdOverride[] = [
  {
    id: 'ato-1',
    org_id: 'org-1',
    address: '0xabcdef1234567890abcdef1234567890abcdef12',
    threshold_fiat: 100,
    note: 'High-risk counterparty',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
  {
    id: 'ato-2',
    org_id: 'org-1',
    address: '0x1111111111111111111111111111111111111111',
    threshold_fiat: 0,
    created_at: '2024-01-10T00:00:00Z',
    updated_at: '2024-01-10T00:00:00Z',
  },
];

// Session state for polling simulation
let sessionCompleted = false;
let sessionTokens: AuthTokenResponse | null = null;
// RD-1242: a rejected wallet proof is reported on the session so the browser can
// stop polling instead of waiting out its poll budget.
let sessionFailed = false;
let sessionFailureReason = '';

export function setSessionCompleted(completed: boolean, tokens?: AuthTokenResponse) {
  sessionCompleted = completed;
  sessionTokens = tokens || null;
}

export function setSessionFailed(reason: string) {
  sessionFailed = true;
  sessionFailureReason = reason;
}

export function resetSessionState() {
  sessionCompleted = false;
  sessionTokens = null;
  sessionFailed = false;
  sessionFailureReason = '';
}

// MSW handlers
export const handlers = [
  // Auth endpoints
  http.post('/api/v1/auth/request', () => {
    return HttpResponse.json(mockAuthRequest);
  }),

  http.post('/api/v1/auth/verify', async ({ request }) => {
    const body = await request.json() as { session_id: string; jwz_token: string };
    if (body.jwz_token.startsWith('mock.')) {
      return HttpResponse.json(mockTokenResponse);
    }
    return HttpResponse.json({ error: 'Invalid token' }, { status: 401 });
  }),

  http.get('/api/v1/auth/session/:sessionId/status', () => {
    if (sessionCompleted && sessionTokens) {
      return HttpResponse.json({ completed: true, tokens: sessionTokens });
    }
    if (sessionFailed) {
      return HttpResponse.json({ completed: false, failed: true, reason: sessionFailureReason });
    }
    return HttpResponse.json({ completed: false });
  }),

  http.post('/api/v1/refresh', async ({ request }) => {
    const body = await request.json() as { refresh_token: string };
    if (body.refresh_token) {
      return HttpResponse.json({
        ...mockTokenResponse,
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
      });
    }
    return HttpResponse.json({ error: 'Invalid refresh token' }, { status: 401 });
  }),

  http.post('/api/v1/revoke', () => {
    return HttpResponse.json({ message: 'Token revoked' });
  }),

  // ETH Link endpoints
  http.post('/api/v1/eth/link/challenge', () => {
    return HttpResponse.json({
      nonce: 'test-nonce-123',
      message: 'Link Ethereum address to DID\n\nDID: did:test\nNonce: test-nonce-123',
    });
  }),

  http.post('/api/v1/eth/link/verify', async ({ request }) => {
    const body = await request.json() as { nonce: string; address: string; signature: string };
    return HttpResponse.json({
      message: 'Address linked successfully',
      address: body.address,
    });
  }),

  http.get('/api/v1/eth/addresses', () => {
    return HttpResponse.json({
      addresses: [
        { address: '0x1234567890123456789012345678901234567890', verified_at: '2024-01-01T00:00:00Z' },
      ],
    });
  }),

  http.delete('/api/v1/eth/addresses/:address', () => {
    return HttpResponse.json({ message: 'Address unlinked' });
  }),

  // User organization endpoints
  http.get('/api/v1/me/orgs', () => {
    return HttpResponse.json({
      organizations: [
        {
          id: mockOrganization.id,
          slug: mockOrganization.slug,
          name: mockOrganization.name,
        },
      ],
    });
  }),

  // Admin status endpoint
  http.get('/api/v1/admin/status', () => {
    return HttpResponse.json({
      proxy: { status: 'running', port: '8080' },
      node: { status: 'ok', url: 'http://localhost:8545', latency_ms: 12 },
      security: {
        runtime_tracing_enabled: false,
        travel_rule_enabled: true,
      },
    });
  }),

  // Organization endpoints
  http.get('/api/v1/admin/orgs', () => {
    return HttpResponse.json({ data: [mockOrganization], total: 1, limit: 25, offset: 0 });
  }),

  http.get('/api/v1/admin/orgs/:orgId', ({ params }) => {
    if (params.orgId === 'org-1') {
      return HttpResponse.json(mockOrganization);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.post('/api/v1/admin/orgs', async ({ request }) => {
    const body = await request.json() as { slug: string; name: string };
    return HttpResponse.json({
      ...mockOrganization,
      id: 'org-new',
      slug: body.slug,
      name: body.name,
    });
  }),

  http.put('/api/v1/admin/orgs/:orgId', async ({ request, params }) => {
    const body = await request.json() as { slug?: string; name?: string };
    return HttpResponse.json({
      ...mockOrganization,
      id: params.orgId as string,
      ...(body.slug && { slug: body.slug }),
      ...(body.name && { name: body.name }),
    });
  }),

  http.delete('/api/v1/admin/orgs/:orgId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Group endpoints
  http.get('/api/v1/admin/orgs/:orgId/groups', () => {
    return HttpResponse.json({ data: [{ group: mockGroup, access: mockGroupAccess }], total: 1, limit: 50, offset: 0 });
  }),

  http.get('/api/v1/admin/orgs/:orgId/groups/:groupId', ({ params }) => {
    if (params.groupId === 'group-1') {
      return HttpResponse.json(mockGroup);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.post('/api/v1/admin/orgs/:orgId/groups', async ({ request, params }) => {
    const body = await request.json() as { slug: string; name: string; description?: string };
    return HttpResponse.json({
      ...mockGroup,
      id: 'group-new',
      org_id: params.orgId as string,
      slug: body.slug,
      name: body.name,
      description: body.description || '',
    });
  }),

  http.put('/api/v1/admin/orgs/:orgId/groups/:groupId', async ({ request, params }) => {
    const body = await request.json() as { name?: string; description?: string };
    return HttpResponse.json({
      ...mockGroup,
      id: params.groupId as string,
      ...(body.name && { name: body.name }),
      ...(body.description !== undefined && { description: body.description }),
    });
  }),

  http.delete('/api/v1/admin/orgs/:orgId/groups/:groupId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  http.get('/api/v1/admin/orgs/:orgId/groups/:groupId/access', () => {
    return HttpResponse.json(mockGroupAccess);
  }),

  http.put('/api/v1/admin/orgs/:orgId/groups/:groupId/access', async ({ request }) => {
    const body = await request.json() as {
      allowed_methods?: string[];
      claims?: string[];
    };
    return HttpResponse.json({
      ...mockGroupAccess,
      ...(body.allowed_methods && { allowed_methods: body.allowed_methods }),
      ...(body.claims && { claims: body.claims }),
    });
  }),

  // User endpoints
  http.get('/api/v1/admin/users', () => {
    return HttpResponse.json({ data: [mockUser], total: 1, limit: 25, offset: 0 });
  }),

  http.get('/api/v1/admin/users/:userId', ({ params }) => {
    if (params.userId === 'user-1') {
      return HttpResponse.json(mockUser);
    }
    return HttpResponse.json({ error: 'Not found' }, { status: 404 });
  }),

  http.put('/api/v1/admin/users/:userId', async ({ request, params }) => {
    const body = await request.json() as { kyc?: boolean; banned?: boolean; note?: string };
    return HttpResponse.json({
      ...mockUser,
      id: params.userId as string,
      ...(body.kyc !== undefined && { kyc: body.kyc }),
      ...(body.banned !== undefined && { banned: body.banned }),
      ...(body.note !== undefined && { note: body.note }),
    });
  }),

  http.get('/api/v1/admin/users/:userId/memberships', () => {
    return HttpResponse.json([mockMembershipWithDetails]);
  }),

  http.post('/api/v1/admin/users/:userId/memberships', async ({ request, params }) => {
    const body = await request.json() as { group_id: string };
    return HttpResponse.json({
      ...mockMembership,
      id: 'membership-new',
      user_id: params.userId as string,
      group_id: body.group_id,
    });
  }),

  http.delete('/api/v1/admin/users/:userId/memberships/:membershipId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
    return HttpResponse.json(mockEffectivePermissions);
  }),

  // Linked addresses endpoint
  http.get('/api/v1/admin/users/:userId/linked-addresses', () => {
    return HttpResponse.json({ addresses: mockLinkedAddresses });
  }),

  // Contract grant summary
  http.get('/api/v1/admin/orgs/:orgId/contracts/grant-summary', () => {
    return HttpResponse.json({});
  }),

  // Contract endpoints
  http.get('/api/v1/admin/orgs/:orgId/contracts', () => {
    return HttpResponse.json({ data: [mockContract], total: 1, limit: 25, offset: 0 });
  }),

  http.post('/api/v1/admin/orgs/:orgId/contracts', async ({ request, params }) => {
    const body = await request.json() as {
      address: string;
      name?: string;
      metadata?: Record<string, unknown>;
    };
    return HttpResponse.json({
      ...mockContract,
      id: 'contract-new',
      org_id: params.orgId as string,
      address: body.address,
      name: body.name || null,
      metadata: body.metadata || {},
    });
  }),

  http.put('/api/v1/admin/orgs/:orgId/contracts/:address', async ({ request, params }) => {
    const body = await request.json() as {
      name?: string;
      metadata?: Record<string, unknown>;
    };
    return HttpResponse.json({
      ...mockContract,
      address: params.address as string,
      ...(body.name && { name: body.name }),
      ...(body.metadata && { metadata: body.metadata }),
    });
  }),

  http.delete('/api/v1/admin/orgs/:orgId/contracts/:address', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Contract grant endpoints
  http.get('/api/v1/admin/orgs/:orgId/contracts/:address/grants', () => {
    return HttpResponse.json([mockContractGrant]);
  }),

  http.post('/api/v1/admin/orgs/:orgId/contracts/:address/grants', async ({ request, params }) => {
    const body = await request.json() as {
      group_id: string;
      functions?: string[] | null;
    };
    return HttpResponse.json({
      ...mockContractGrant,
      id: 'grant-new',
      contract_id: params.address as string,
      group_id: body.group_id,
      functions: body.functions ?? null,
    });
  }),

  http.put('/api/v1/admin/orgs/:orgId/contracts/:address/grants/:groupId', async ({ request, params }) => {
    const body = await request.json() as {
      functions?: string[] | null;
    };
    return HttpResponse.json({
      ...mockContractGrant,
      group_id: params.groupId as string,
      ...(body.functions !== undefined && { functions: body.functions }),
    });
  }),

  http.delete('/api/v1/admin/orgs/:orgId/contracts/:address/grants/:groupId', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Contract lookup by address (cross-org)
  http.get('/api/v1/admin/contracts/by-address/:address', ({ params }) => {
    if (params.address === mockContract.address) {
      return HttpResponse.json({
        contract: mockContract,
        organization: mockOrganization,
        grants: [{
          grant: mockContractGrant,
          group: mockGroup,
          access: mockGroupAccess,
        }],
      });
    }
    return HttpResponse.json({ error: 'contract not found' }, { status: 404 });
  }),

  // Utility endpoints
  http.post('/api/v1/admin/access/check', async () => {
    return HttpResponse.json({
      allowed: true,
      reason: 'Access granted',
      rate_limit_rps: 100,
      claims: [],
    });
  }),

  http.get('/api/v1/admin/cache/stats', () => {
    return HttpResponse.json({
      hits: 100,
      misses: 10,
      size: 50,
    });
  }),

  // =========================================================================
  // Compliance endpoints
  // =========================================================================

  // Compliance config
  http.get('/api/v1/admin/orgs/:orgId/compliance/config', () => {
    return HttpResponse.json(mockComplianceConfig);
  }),

  http.put('/api/v1/admin/orgs/:orgId/compliance/config', async ({ request }) => {
    const body = await request.json() as { enabled?: boolean; threshold_fiat?: number; currency?: string };
    return HttpResponse.json({
      ...mockComplianceConfig,
      ...(body.enabled !== undefined && { enabled: body.enabled }),
      ...(body.threshold_fiat !== undefined && { threshold_fiat: body.threshold_fiat }),
      ...(body.currency !== undefined && { currency: body.currency }),
      updated_at: new Date().toISOString(),
    });
  }),

  // System token prices (CoinGecko cache)
  http.get('/api/v1/admin/compliance/system-token-prices', () => {
    return HttpResponse.json({ data: [
      { id: 1, coingecko_id: 'ethereum', source: 'coingecko', token_address: 'native', symbol: 'ETH', decimals: 18, price_fiat: 2500, updated_at: new Date().toISOString(), is_stale: false },
      { id: 2, coingecko_id: 'tether', source: 'coingecko', token_address: '0xdac17f958d2ee523a2206206994597c13d831ec7', symbol: 'USDT', decimals: 6, price_fiat: 1.0, updated_at: new Date().toISOString(), is_stale: false },
      { id: 3, coingecko_id: 'usd-coin', source: 'coingecko', token_address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', symbol: 'USDC', decimals: 6, price_fiat: 1.0, updated_at: new Date().toISOString(), is_stale: false },
    ] });
  }),

  // Token prices — backend wraps in {data: [...]}
  http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
    return HttpResponse.json({ data: mockTokenPrices });
  }),

  http.put('/api/v1/admin/orgs/:orgId/compliance/tokens/:tokenAddress', async ({ request, params }) => {
    const body = await request.json() as { symbol: string; decimals: number; prices?: Record<string, number> };
    const priceFiat = body.prices ? (body.prices['usd'] ?? Object.values(body.prices)[0] ?? 0) : 0;
    return HttpResponse.json({
      id: 'token-new',
      org_id: params.orgId as string,
      token_address: params.tokenAddress as string,
      symbol: body.symbol,
      decimals: body.decimals,
      price_fiat: priceFiat,
      prices_by_currency: body.prices ?? {},
      created_at: '2024-01-01T00:00:00Z',
      updated_at: new Date().toISOString(),
    });
  }),

  http.delete('/api/v1/admin/orgs/:orgId/compliance/tokens/:tokenAddress', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Travel rule records
  http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', () => {
    return HttpResponse.json({
      data: mockTravelRuleRecords,
      total: mockTravelRuleRecords.length,
      limit: 25,
      offset: 0,
    });
  }),

  http.delete('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records/:id', () => {
    return new HttpResponse(null, { status: 204 });
  }),

  http.post('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', async ({ request, params }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      id: 'travel-rule-new',
      org_id: params.orgId as string,
      ...body,
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      created_at: new Date().toISOString(),
    });
  }),

  // Sanctions (global routes)
  http.get('/api/v1/admin/compliance/sanctions', () => {
    return HttpResponse.json({
      data: mockSanctionedAddresses,
      total: mockSanctionedAddresses.length,
      limit: 25,
      offset: 0,
    });
  }),

  http.post('/api/v1/admin/compliance/sanctions', async ({ request }) => {
    const body = await request.json() as { address: string; reason: string; source?: string; org_id?: string };
    return HttpResponse.json({
      id: 'sanction-new',
      address: body.address,
      reason: body.reason,
      source: body.source || '',
      org_id: body.org_id || null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
  }),

  http.delete('/api/v1/admin/compliance/sanctions/:id', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Compliance logs
  http.get('/api/v1/admin/orgs/:orgId/compliance/logs', () => {
    return HttpResponse.json({
      data: mockComplianceLogs,
      total: mockComplianceLogs.length,
      limit: 25,
      offset: 0,
    });
  }),

  // Address threshold overrides
  http.get('/api/v1/admin/orgs/:orgId/compliance/address-thresholds', () => {
    return HttpResponse.json({
      data: mockAddressThresholdOverrides,
      total: mockAddressThresholdOverrides.length,
      limit: 25,
      offset: 0,
    });
  }),

  http.put('/api/v1/admin/orgs/:orgId/compliance/address-thresholds/:address', async ({ request, params }) => {
    const body = await request.json() as { threshold_fiat: number; note?: string };
    return HttpResponse.json({
      id: 'ato-new',
      org_id: params.orgId as string,
      address: params.address as string,
      threshold_fiat: body.threshold_fiat,
      note: body.note || null,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: new Date().toISOString(),
    });
  }),

  http.delete('/api/v1/admin/orgs/:orgId/compliance/address-thresholds/:address', () => {
    return HttpResponse.json({ message: 'Deleted' });
  }),

  // Currency settings
  http.get('/api/v1/admin/compliance/currency', () => {
    return HttpResponse.json({
      currency: 'usd',
      all_currencies: [
        { code: 'usd', name: 'US Dollar', symbol: '$' },
        { code: 'eur', name: 'Euro', symbol: '€' },
        { code: 'chf', name: 'Swiss Franc', symbol: 'CHF' },
        { code: 'gbp', name: 'British Pound', symbol: '£' },
        { code: 'aed', name: 'UAE Dirham', symbol: 'AED' },
      ],
      coingecko_enabled: true,
    });
  }),

  http.put('/api/v1/admin/compliance/currency', async ({ request }) => {
    const body = await request.json() as { currency: string };
    return HttpResponse.json({
      currency: body.currency,
      message: `Base currency updated to ${body.currency.toUpperCase()}`,
    });
  }),

  // Default: the signed-in user is NOT an admin, so user-facing pages render
  // without the admin entry point. Tests covering the admin case override this.
  http.get('/api/v1/me/admin-status', () => {
    return HttpResponse.json({
      is_admin: false,
      is_readonly_admin: false,
      admin_org_ids: [],
      readonly_admin_org_ids: [],
    });
  }),
];
