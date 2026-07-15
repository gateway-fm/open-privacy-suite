import { adminApi } from './adminClient';
import type {
  Organization,
  Group,
  User,
  UserMembership,
  GroupAccess,
  Contract,
  ContractGrant,
  MethodPolicyDocument,
  EffectivePermissions,
  AccessCheckRequest,
  AccessCheckResult,
  CacheStats,
  CreateOrganizationInput,
  UpdateOrganizationInput,
  CreateGroupInput,
  UpdateGroupInput,
  UpdateUserInput,
  CreateMembershipInput,
  SetGroupAccessInput,
  CreateContractInput,
  UpdateContractInput,
  CreateContractGrantInput,
  UpdateContractGrantInput,
  MembershipWithDetails,
  ContractSyncCheckResponse,
  ContractSyncDeleteResponse,
  PaginatedResponse,
  GroupWithAccess,
  BatchMoveRequest,
  BatchMoveResponse,
  BatchDeleteRequest,
  BatchDeleteResponse,
  BatchDeletePreviewRequest,
  BatchDeletePreviewResponse,
  EventSignature,
  UserRoleFilter,
} from '../types/rbac';

const api = adminApi;

export const rbacApi = {
  // Organizations
  orgs: {
    list: (params?: { limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<Organization>>('/orgs', { params }),
    get: (orgId: string) => api.get<Organization>(`/orgs/${orgId}`),
    create: (input: CreateOrganizationInput) => api.post<Organization>('/orgs', input),
    update: (orgId: string, input: UpdateOrganizationInput) =>
      api.put<Organization>(`/orgs/${orgId}`, input),
    delete: (orgId: string) => api.delete(`/orgs/${orgId}`),
    // Onboard a user by DID into a group within this org (tier-2 admin
    // surface). Backend creates the user row on first sight, then adds
    // the membership. Backend gate: caller must be full-admin of orgId
    // (super-admin / dev callers bypass) and the group must live in orgId.
    createMembershipByDid: (
      orgId: string,
      input: { did: string; group_id: string; expires_at?: string }
    ) =>
      api.post<{ membership: UserMembership; user_id: string }>(
        `/orgs/${orgId}/memberships/by-did`,
        input
      ),
  },

  // Groups
  groups: {
    list: (orgId: string, params?: { limit?: number; offset?: number; search?: string }) =>
      api.get<PaginatedResponse<GroupWithAccess>>(`/orgs/${orgId}/groups`, { params }),
    get: (orgId: string, groupId: string) =>
      api.get<Group>(`/orgs/${orgId}/groups/${groupId}`),
    create: (orgId: string, input: CreateGroupInput) =>
      api.post<Group>(`/orgs/${orgId}/groups`, input),
    update: (orgId: string, groupId: string, input: UpdateGroupInput) =>
      api.put<Group>(`/orgs/${orgId}/groups/${groupId}`, input),
    delete: (orgId: string, groupId: string) =>
      api.delete(`/orgs/${orgId}/groups/${groupId}`),
    // Group access (replaces old permissions and roles)
    getAccess: (orgId: string, groupId: string) =>
      api.get<GroupAccess>(`/orgs/${orgId}/groups/${groupId}/access`),
    setAccess: (orgId: string, groupId: string, input: SetGroupAccessInput) =>
      api.put<GroupAccess>(`/orgs/${orgId}/groups/${groupId}/access`, input),
    batchDelete: (orgId: string, input: BatchDeleteRequest) =>
      api.post<BatchDeleteResponse>(`/orgs/${orgId}/groups/batch-delete`, input),
    batchDeletePreview: (orgId: string, input: BatchDeletePreviewRequest) =>
      api.post<BatchDeletePreviewResponse>(`/orgs/${orgId}/groups/batch-delete-preview`, input),
  },

  // Users
  users: {
    list: (params?: {
      limit?: number;
      offset?: number;
      org_id?: string;
      search?: string;
      // Repeatable group_id; axios serialises arrays as group_id=a&group_id=b
      // which matches gin's c.QueryArray("group_id").
      group_id?: string[];
      role?: UserRoleFilter;
    }) =>
      api.get<PaginatedResponse<User>>('/users', {
        params,
        // arrayFormat repeat -> ?group_id=a&group_id=b (gin QueryArray)
        paramsSerializer: { indexes: null },
      }),
    get: (userId: string) => api.get<User>(`/users/${userId}`),
    update: (userId: string, input: UpdateUserInput) =>
      api.put<User>(`/users/${userId}`, input),
    getMemberships: (userId: string) =>
      api.get<MembershipWithDetails[]>(`/users/${userId}/memberships`),
    createMembership: (userId: string, input: CreateMembershipInput) =>
      api.post<UserMembership>(`/users/${userId}/memberships`, input),
    deleteMembership: (userId: string, membershipId: string) =>
      api.delete(`/users/${userId}/memberships/${membershipId}`),
    getEffectivePermissions: (userId: string, orgSlug?: string) =>
      api.get<EffectivePermissions>(`/users/${userId}/effective-permissions`, {
        params: { org: orgSlug },
      }),
    getLinkedAddresses: (userId: string) =>
      api.get<{ addresses: Array<{ address: string; verified_at: string }> }>(
        `/users/${userId}/linked-addresses`
      ),
  },

  // Contracts (first-class resources)
  contracts: {
    list: (orgId: string, params?: { limit?: number; offset?: number; search?: string; created_after?: string; created_before?: string }) =>
      api.get<PaginatedResponse<Contract>>(`/orgs/${orgId}/contracts`, { params }),
    get: (orgId: string, address: string) =>
      api.get<Contract>(`/orgs/${orgId}/contracts/${address}`),
    create: (orgId: string, input: CreateContractInput) =>
      api.post<Contract>(`/orgs/${orgId}/contracts`, input),
    update: (orgId: string, address: string, input: UpdateContractInput) =>
      api.put<Contract>(`/orgs/${orgId}/contracts/${address}`, input),
    delete: (orgId: string, address: string) =>
      api.delete(`/orgs/${orgId}/contracts/${address}`),
    // Contract grants
    listGrants: (orgId: string, address: string) =>
      api.get<ContractGrant[]>(`/orgs/${orgId}/contracts/${address}/grants`),
    createGrant: (orgId: string, address: string, input: CreateContractGrantInput) =>
      api.post<ContractGrant>(`/orgs/${orgId}/contracts/${address}/grants`, input),
    updateGrant: (orgId: string, address: string, groupId: string, input: UpdateContractGrantInput) =>
      api.put<ContractGrant>(`/orgs/${orgId}/contracts/${address}/grants/${groupId}`, input),
    deleteGrant: (orgId: string, address: string, groupId: string) =>
      api.delete(`/orgs/${orgId}/contracts/${address}/grants/${groupId}`),
    // ABI management
    updateABI: (orgId: string, address: string, abi: string) =>
      api.put<Contract>(`/orgs/${orgId}/contracts/${address}/abi`, { abi }),
    // RD-874: per-contract visibleTo unlock toggle. Setting true
    // authorises tx senders on this contract to grant per-event
    // visibility to DIDs they list in `visibleTo`. Default false.
    updateAllowVisibleToUnlock: (orgId: string, address: string, allow: boolean) =>
      api.put<Contract>(`/orgs/${orgId}/contracts/${address}/visibleto-unlock`, {
        allow_visibleto_unlock: allow,
      }),
    // RD-1206: per-record method access policies. getMethodPolicies returns
    // the current document (or null); updateMethodPolicies sets it (or clears
    // with null). PUT is super-admin only and validated against the ABI
    // server-side — surface the 400 message verbatim on failure.
    getMethodPolicies: (orgId: string, address: string) =>
      api.get<{ method_policies: MethodPolicyDocument | null }>(
        `/orgs/${orgId}/contracts/${address}/method-policies`
      ),
    updateMethodPolicies: (orgId: string, address: string, doc: MethodPolicyDocument | null) =>
      api.put<Contract>(`/orgs/${orgId}/contracts/${address}/method-policies`, {
        method_policies: doc,
      }),
    // RD-1206 simulator: "would this caller read this record?" — capture-side,
    // no node call. Super-admin only; returns allow/deny/indeterminate + admit-set.
    simulateMethodPolicy: (
      orgId: string,
      address: string,
      body: { method: string; record_key: string; caller_did: string; caller_eth_addresses?: string[] }
    ) =>
      api.post<{
        result: string;
        record_type: string;
        matched_rule?: string;
        has_return_source: boolean;
        poisoned: boolean;
        captured: Record<string, string[]>;
        note?: string;
      }>(`/orgs/${orgId}/contracts/${address}/method-policies/simulate`, body),
    // Event signatures from ABI (for event rules UI)
    listEvents: (orgId: string, address: string) =>
      api.get<{ events: EventSignature[]; message?: string }>(`/orgs/${orgId}/contracts/${address}/events`),
    // Sync with chain
    syncCheck: (orgId: string) =>
      api.post<ContractSyncCheckResponse>(`/orgs/${orgId}/contracts/sync-check`),
    syncDelete: (orgId: string, contractIds: string[]) =>
      api.post<ContractSyncDeleteResponse>(`/orgs/${orgId}/contracts/sync-delete`, { contract_ids: contractIds }),
    // Batch move contracts between groups
    batchMove: (orgId: string, input: BatchMoveRequest) =>
      api.post<BatchMoveResponse>(`/orgs/${orgId}/contracts/batch-move`, input),
    // Grant summary (counts + group names per contract)
    grantSummary: (orgId: string) =>
      api.get<Record<string, { count: number; groups: Array<{id: string; name: string}> }>>(
        `/orgs/${orgId}/contracts/grant-summary`
      ),
    // Lookup by address (cross-org, for test request panel)
    lookupByAddress: (address: string) =>
      api.get<{
        contract: Contract;
        organization: Organization;
        grants: Array<{
          grant: ContractGrant;
          group: Group;
          access: GroupAccess | null;
        }>;
      }>(`/contracts/by-address/${address}`),
  },

  // Utilities
  utils: {
    checkAccess: (request: AccessCheckRequest) =>
      api.post<AccessCheckResult>('/access/check', request),
    getCacheStats: () => api.get<CacheStats>('/cache/stats'),
  },

  // System status
  status: {
    get: () =>
      api.get<{
        proxy: { status: string; port: string };
        node: { status: string; url: string; latency_ms: number; error?: string };
        security: { travel_rule_enabled: boolean };
        methods: {
          extra_namespaces?: Record<string, string[]>;
          // Namespaces opted into prefix-wildcard mode. The frontend renders a
          // single "Allow all <prefix>* methods" toggle per entry; the deny list
          // is shown read-only.
          extra_wildcards?: Record<string, { prefix: string; deny?: string[] }>;
        };
      }>('/status'),
  },

  // Azure AD Tenant Allowlist
  azureTenants: {
    list: () =>
      api.get<{ data: import('../types/rbac').AllowedAzureTenant[] }>('/azure-tenants'),
    get: (id: string) =>
      api.get<import('../types/rbac').AllowedAzureTenant>(`/azure-tenants/${id}`),
    create: (input: import('../types/rbac').CreateAzureTenantInput) =>
      api.post<import('../types/rbac').AllowedAzureTenant>('/azure-tenants', input),
    update: (id: string, input: import('../types/rbac').UpdateAzureTenantInput) =>
      api.put<import('../types/rbac').AllowedAzureTenant>(`/azure-tenants/${id}`, input),
    delete: (id: string) =>
      api.delete(`/azure-tenants/${id}`),
  },
};

export default rbacApi;
