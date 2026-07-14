// RBAC TypeScript types mirroring backend models

// Claims: deploy, upgrade, admin (operational gates only).
// Read/write access is controlled by the method allowlist, not claims.
export type Claim = 'admin' | 'upgrade' | 'deploy';

export type MembershipSource = 'admin' | 'zk_attested';

export interface Organization {
  id: string;
  slug: string;
  name: string;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

// Group - no more role_id (permissions come from GroupAccess and ContractGrants)
export interface Group {
  id: string;
  org_id: string;
  parent_id?: string | null;
  slug: string;
  name: string;
  description?: string;
  depth: number;
  path: string; // Materialized path (e.g., "root.engineering.devops")
  is_org_admin?: boolean; // If true, members get all claims on all contracts in the org
  is_org_readonly_admin?: boolean; // If true, members get read-only access to admin endpoints in the org (RD-866)
  created_at: string;
  updated_at: string;
}

// Batch operation types

export interface BatchMoveRequest {
  contract_ids: string[];
  target_group_id: string;
}

export interface BatchMoveResponse {
  target_group_id: string;
  moved_count: number;
  deleted_group_ids?: string[];
}

export interface BatchDeleteRequest {
  group_ids: string[];
}

export interface BatchDeleteResponse {
  deleted_count: number;
}

export interface BatchDeletePreviewRequest {
  group_ids: string[];
}

export interface BatchDeletePreviewGroup {
  id: string;
  name: string;
  slug: string;
  contract_count: number;
  member_count: number;
  contracts: string[];
}

export interface BatchDeletePreviewResponse {
  groups: BatchDeletePreviewGroup[];
}

// Contract - first-class resource
export interface Contract {
  id: string;
  org_id: string;
  address?: string; // lowercase 0x-prefixed (new format)
  contract_address?: string; // legacy format - deprecated
  name?: string;
  abi?: string; // Contract ABI JSON for function-level access control
  deployed_by_user_id?: string | null;
  deployed_at?: string | null;
  owner_group_id?: string; // legacy format - deprecated
  metadata: Record<string, unknown>;
  // RD-874: when true, per-tx `visibleTo` lists act as an opt-in
  // unlock for event visibility — a tx sender on this contract can
  // grant per-event access to anyone they list in `visibleTo`,
  // bypassing event_rules and param_rules for that one tx. Default
  // false. Admin-only flag; flip via the dedicated endpoint.
  allow_visibleto_unlock: boolean;
  // RD-1206: per-record method access policy document, or null/absent when
  // unset (getters gated by the contract grant only). Configured via the
  // super-admin method-policies endpoint.
  method_policies?: MethodPolicyDocument | null;
  created_at: string;
  updated_at: string;
}

// Method access policies (RD-1206). Mirrors the Go schema exactly so a
// UI-built document validates on the first save.
export interface MethodPolicyKeySpec {
  source: "param";
  index: number;
}

export interface MethodPolicyRememberField {
  source: "sender" | "param" | "visibleTo";
  index?: number; // required when source === "param"
  merge: "set_once" | "union";
}

export interface MethodPolicyCaptureSpec {
  method: string; // canonical ABI signature, e.g. "createPayment(string,address,uint256)"
  key: MethodPolicyKeySpec;
  remember: Record<string, MethodPolicyRememberField>;
}

export interface MethodPolicyReturnSource {
  source: "return";
  paths: string[];
  kind: "address";
}

// callerIn is EITHER a list of captured field names OR a return source.
export type MethodPolicyCallerIn = string[] | MethodPolicyReturnSource;

export interface MethodPolicyAllowRule {
  callerIn: MethodPolicyCallerIn;
}

export interface MethodPolicyAccessSpec {
  method: string;
  key: MethodPolicyKeySpec;
  allow: MethodPolicyAllowRule[];
  onNoRecord?: "deny";
  else?: "deny";
}

export interface MethodPolicyRecord {
  capture: MethodPolicyCaptureSpec[];
  access: MethodPolicyAccessSpec[];
}

export interface MethodPolicyDocument {
  records: Record<string, MethodPolicyRecord>;
}


// FunctionRule describes access to a single contract function with optional parameter constraints
export interface FunctionRule {
  selector: string;
  param_rules?: ParamRule[] | null;
}

// ParamRule constrains a single ABI parameter of a function call
export interface ParamRule {
  index: number;     // ABI parameter position (0-based)
  must_be: string;   // constraint type: "self" for now
}

// EventRule describes visibility of a single contract event with optional parameter constraints
export interface EventRule {
  topic0: string;    // keccak256(EventName(paramTypes)) — 32-byte hex with 0x prefix
  name: string;      // human-readable event name, from ABI
  param_rules?: ParamRule[] | null;
}

// EventSignature returned by GET /orgs/:org_id/contracts/:address/events
export interface EventSignature {
  name: string;        // e.g. "Transfer"
  signature: string;   // e.g. "Transfer(address,address,uint256)"
  topic0: string;      // keccak256 of signature, hex-encoded with 0x prefix
  inputs: EventInput[];
  default_param_rules?: ParamRule[]; // self constraints for address params (from backend)
}

// EventInput describes one parameter of an event
export interface EventInput {
  name: string;
  type: string;    // ABI type string (e.g. "address", "uint256")
  indexed: boolean;
}

// ContractGrant - links groups to contracts, enabling access
// Group's claims (from GroupAccess) apply to this contract.
// Functions can optionally restrict which contract functions are accessible.
export interface ContractGrant {
  id: string;
  contract_id: string;
  group_id: string;
  functions?: FunctionRule[] | null; // null = all functions, or structured rules with optional param constraints
  event_rules?: EventRule[] | '*' | null;  // "*" = all events, null/[] = no events, [...] = allowlist
  created_at: string;
  updated_at: string;
}

// GroupAccess - RPC method permissions and rate limits for a group
// Claims define operational gates (deploy, upgrade, admin). Read/write is method-gated.
export interface GroupAccess {
  id: string;
  group_id: string;
  allowed_methods: string[];
  claims: Claim[]; // Operational claims: deploy, upgrade, admin
  rpc_api_key?: string | null;
  verbose_errors?: boolean; // RD-1137 Part A
  created_at: string;
  updated_at: string;
  // Computed fields (populated by backend for child groups)
  effective_claims?: Claim[];
  narrowed_by_parent?: boolean;
}

export interface User {
  id: string;
  external_id: string; // User's DID
  kyc: boolean;
  banned: boolean;
  note?: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  // Group memberships scoped to the caller's accessible orgs. Returned by
  // the users-list endpoint; older detail endpoints may omit this.
  groups?: UserGroupMembership[];
}

export interface UserGroupMembership {
  group_id: string;
  slug: string;
  name: string;
  org_id: string;
  is_org_admin: boolean;
}

export type UserRoleFilter = 'org_admin' | 'admin' | 'member';

// UserMembership - no more role_id (permissions come from group)
export interface UserMembership {
  id: string;
  user_id: string;
  group_id: string;
  source: MembershipSource;
  zk_credential_ref?: string;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ContractAccess - access permissions for a specific contract
export interface ContractAccess {
  claims: Claim[];
  functions?: FunctionRule[] | null;    // null = all functions allowed
  event_rules?: EventRule[] | null;     // null/[] = no events visible, [...] = allowlist
}

// EffectivePermissions - computed permissions for a user
export interface EffectivePermissions {
  id: string;
  user_id: string;
  org_id: string;
  allowed_methods: string[];
  contract_access: Record<string, ContractAccess>; // address -> access
  claims: Claim[]; // User's capabilities from their groups
  rate_limit_rps?: number | null;
  rate_limit_daily?: number | null;
  computed_at: string;
  expires_at: string;
}

// MembershipWithDetails - no more role field
export interface MembershipWithDetails {
  membership: UserMembership;
  group: Group;
  expired?: boolean; // server-computed: true when expires_at <= now, matching the resolver's expires_at > NOW() filter (RD-1157)
}

export interface AccessCheckRequest {
  user_external_id: string;
  org_slug?: string;
  method: string;
  target_address?: string;
  function_selector?: string;
  required_claims?: Claim[];
}

export interface AccessCheckResult {
  allowed: boolean;
  reason?: string;
  rate_limit_rps?: number | null;
  rate_limit_daily?: number | null;
  claims?: Claim[];
}

export interface CacheStats {
  hits: number;
  misses: number;
  size: number;
}

// Input types for creating/updating entities

export interface CreateOrganizationInput {
  slug: string;
  name: string;
  settings?: Record<string, unknown>;
}

export interface UpdateOrganizationInput {
  slug?: string;
  name?: string;
  settings?: Record<string, unknown>;
}

// No more role_id in group creation
export interface CreateGroupInput {
  slug: string;
  name: string;
  description?: string;
  parent_id?: string | null;
  is_org_admin?: boolean;
  is_org_readonly_admin?: boolean;
}

export interface UpdateGroupInput {
  name?: string;
  description?: string;
  is_org_admin?: boolean;
  is_org_readonly_admin?: boolean;
}

// Input for setting group access
export interface SetGroupAccessInput {
  allowed_methods?: string[];
  claims?: Claim[];
  rpc_api_key?: string | null;
  verbose_errors?: boolean; // RD-1137 Part A: opt-in machine-readable denial reasons on the wire
}

export interface UpdateUserInput {
  kyc?: boolean;
  banned?: boolean;
  note?: string;
  metadata?: Record<string, unknown>;
}

// No more role_id in membership creation
export interface CreateMembershipInput {
  group_id: string;
  // Optional RFC3339 timestamp — end of a time-boxed access window (e.g. a
  // regulator profile granted for 24h / 7 days, RD-1145). Omit for a
  // permanent membership. Access is denied automatically once it passes.
  expires_at?: string;
}

// Input for creating a contract
export interface CreateContractInput {
  address: string;
  name?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateContractInput {
  name?: string;
  metadata?: Record<string, unknown>;
}

// Input for creating a contract grant
// Claims are inherited from the group's GroupAccess.claims
export interface CreateContractGrantInput {
  group_id: string;
  functions?: FunctionRule[] | null;
  event_rules?: EventRule[] | '*' | null;
}

export interface UpdateContractGrantInput {
  functions?: FunctionRule[] | null;
  event_rules?: EventRule[] | '*' | null;
}

// Paginated response envelope from backend list endpoints
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

// Group with inline access settings (returned by paginated groups list)
export interface GroupWithAccess {
  group: Group;
  access: GroupAccess | null;
}

// Operational claims (the only claims that serve as gates)
export const ALL_CLAIMS: Claim[] = ['admin', 'upgrade', 'deploy'];

// Claim labels for display
export const CLAIM_LABELS: Record<Claim, string> = {
  admin: 'Admin',
  upgrade: 'Upgrade',
  deploy: 'Deploy',
};

// Claim descriptions for tooltips
export const CLAIM_DESCRIPTIONS: Record<Claim, string> = {
  admin: 'Full control — implies Deploy and Upgrade',
  upgrade: 'Can upgrade proxy contract implementations',
  deploy: 'Can deploy new contracts to new addresses',
};

// Claims hierarchy: which claims each claim implies.
// Read/write are no longer implied — the method allowlist is the source of truth.
export const CLAIM_HIERARCHY: Partial<Record<Claim, Claim[]>> = {
  admin: ['deploy', 'upgrade'],
  deploy: [],
  upgrade: [],
};

// Get all claims implied by a given claim
export function getImpliedClaims(claim: Claim): Claim[] {
  return CLAIM_HIERARCHY[claim] || [];
}

// Returns which selected claim implies the given claim, or null if none
export function getImplyingClaim(claim: Claim, selectedClaims: Claim[]): Claim | null {
  for (const selected of selectedClaims) {
    const implied = CLAIM_HIERARCHY[selected];
    if (implied && implied.includes(claim)) {
      return selected;
    }
  }
  return null;
}

export const METHOD_CATEGORIES = {
  read: {
    'Chain & Network Info': [
      'eth_chainId',
      'eth_blockNumber',
      'net_version',
      'net_listening',
      'web3_clientVersion',
      'eth_syncing',
      'eth_accounts',
    ],
    'Accounts & Blocks': [
      'eth_getBalance',
      'eth_getTransactionCount',
      'eth_getBlockByHash',
      'eth_getBlockByNumber',
      'eth_getBlockTransactionCountByHash',
      'eth_getBlockTransactionCountByNumber',
    ],
    'Past Activity (Explorer & Logs)': [
      'eth_getTransactionByHash',
      'eth_getTransactionReceipt',
      'eth_getTransactionByBlockHashAndIndex',
      'eth_getTransactionByBlockNumberAndIndex',
      'eth_getLogs',
    ],
    'Contract Execution': [
      'eth_call',
      'eth_estimateGas',
    ],
    'Deep State Inspection': [
      'eth_getCode',
      'eth_getStorageAt',
    ],
    'Gas & Fee Data': [
      'eth_gasPrice',
      'eth_maxPriorityFeePerGas',
    ],
  },
  write: {
    'State Modifying': [
      'eth_sendTransaction',
      'eth_sendRawTransaction',
    ],
  },
  deploy: {
    'Advanced Tracing': [
      'debug_traceTransaction',
      'debug_traceCall',
    ],
  },
} as const;

// RPC methods classified by required claim
// This must match the backend classification in internal/rbac/method_claim.go
export const RPC_METHODS_BY_CLAIM: Record<'read' | 'write' | 'deploy', readonly string[]> = {
  read: Object.values(METHOD_CATEGORIES.read).flat() as unknown as readonly string[],
  write: Object.values(METHOD_CATEGORIES.write).flat() as unknown as readonly string[],
  deploy: Object.values(METHOD_CATEGORIES.deploy).flat() as unknown as readonly string[],
};

// All RPC methods (flattened list)
export const ALL_RPC_METHODS = [
  ...RPC_METHODS_BY_CLAIM.read,
  ...RPC_METHODS_BY_CLAIM.write,
] as const;

// Helper to get required claim for a method.
// Only deploy-tier methods return a non-null claim; read/write are method-gated.
export function getClaimForMethod(method: string): 'deploy' | null {
  if ((RPC_METHODS_BY_CLAIM.deploy as readonly string[]).includes(method)) {
    return 'deploy';
  }
  return null;
}

// Azure AD Tenant Allowlist
export interface AllowedAzureTenant {
  id: string;
  tenant_id: string;
  label: string;
  default_org_id?: string | null;
  default_group_id?: string | null;
  auto_provision: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateAzureTenantInput {
  tenant_id: string;
  label?: string;
  default_org_id?: string | null;
  default_group_id?: string | null;
  auto_provision?: boolean;
}

export interface UpdateAzureTenantInput {
  tenant_id?: string;
  label?: string;
  default_org_id?: string | null;
  default_group_id?: string | null;
  auto_provision?: boolean;
}

// Contract sync status - for checking contracts against chain
export interface ContractSyncStatus {
  id: string;
  address: string;
  name: string;
  status: 'exists' | 'missing' | 'error';
  error?: string;
}

// Response from sync-check endpoint
export interface ContractSyncCheckResponse {
  total: number;
  existing: ContractSyncStatus[];
  missing: ContractSyncStatus[];
  errors: ContractSyncStatus[];
}

// Response from sync-delete endpoint
export interface ContractSyncDeleteResponse {
  deleted_count: number;
  deleted_addresses: string[];
  skipped: Array<{
    id: string;
    reason: string;
  }>;
}

// ============================================================================
// PERMISSION PRESETS & ROLE-BASED METHOD SECTIONS
// ============================================================================

// Expand claims using the hierarchy (frontend equivalent of backend ExpandClaims)
export function ExpandClaims(claims: Claim[]): Claim[] {
  const expanded = new Set<Claim>(claims);
  for (const claim of claims) {
    const implied = CLAIM_HIERARCHY[claim];
    if (implied) {
      for (const c of implied) expanded.add(c);
    }
  }
  return Array.from(expanded);
}

// Role-based method sections — incremental layers
export const METHOD_SECTIONS = {
  'Wallet User': {
    description: 'Core methods for end users with wallets',
    methods: [
      'eth_chainId', 'eth_blockNumber', 'net_version', 'net_listening',
      'web3_clientVersion', 'eth_syncing', 'eth_accounts',
      'eth_getBalance', 'eth_getTransactionCount',
      'eth_getBlockByHash', 'eth_getBlockByNumber',
      'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getLogs',
      'eth_call', 'eth_estimateGas',
      'eth_gasPrice', 'eth_maxPriorityFeePerGas',
      'eth_sendTransaction',
    ],
  },
  'Service / Backend': {
    description: 'Additional methods for automated systems and backend services',
    methods: [
      'eth_sendRawTransaction',
      'eth_getBlockTransactionCountByHash', 'eth_getBlockTransactionCountByNumber',
      'eth_getTransactionByBlockHashAndIndex', 'eth_getTransactionByBlockNumberAndIndex',
    ],
  },
  'Developer': {
    description: 'Deep inspection and debugging tools for engineers',
    methods: [
      'eth_getCode', 'eth_getStorageAt',
      'debug_traceTransaction', 'debug_traceCall',
    ],
  },
} as const;

export interface PermissionPreset {
  id: string;
  name: string;
  description: string;
  icon: string; // lucide-react icon name
  sections: (keyof typeof METHOD_SECTIONS)[]; // which sections to check
}

export const PERMISSION_PRESETS: PermissionPreset[] = [
  {
    id: 'wallet_user',
    name: 'Wallet User',
    description: 'End users with wallets — send payments, check balances',
    icon: 'Wallet',
    sections: ['Wallet User'],
  },
  {
    id: 'service_backend',
    name: 'Service / Backend',
    description: 'Automated systems — raw transactions, event monitoring',
    icon: 'Server',
    sections: ['Wallet User', 'Service / Backend'],
  },
  {
    id: 'developer',
    name: 'Developer',
    description: 'Engineers — deploy, debug, inspect contract state',
    icon: 'Code',
    sections: ['Wallet User', 'Service / Backend', 'Developer'],
  },
];

// Get all methods for a preset
export function getPresetMethods(preset: PermissionPreset): string[] {
  return preset.sections.flatMap(s => [...METHOD_SECTIONS[s].methods]);
}

// Find closest matching preset for a method set. Returns badge text.
export function getClosestPresetLabel(methods: string[]): string {
  const methodSet = new Set(methods);
  let bestPreset: PermissionPreset | null = null;
  let bestDelta = Infinity;

  for (const preset of PERMISSION_PRESETS) {
    const presetMethods = new Set(getPresetMethods(preset));
    let added = 0, removed = 0;
    for (const m of methodSet) { if (!presetMethods.has(m)) added++; }
    for (const m of presetMethods) { if (!methodSet.has(m)) removed++; }
    const delta = added + removed;
    if (delta < bestDelta) {
      bestDelta = delta;
      bestPreset = preset;
    }
  }

  if (!bestPreset || bestDelta > 6) return `Custom \u00b7 ${methods.length}`;
  if (bestDelta === 0) return bestPreset.name;

  const presetMethods = new Set(getPresetMethods(bestPreset));
  let added = 0, removed = 0;
  for (const m of methodSet) { if (!presetMethods.has(m)) added++; }
  for (const m of presetMethods) { if (!methodSet.has(m)) removed++; }

  const parts = [bestPreset.name];
  if (added > 0) parts.push(`+${added}`);
  if (removed > 0) parts.push(`-${removed}`);
  return parts.join(' ');
}

// Detect which preset exactly matches current config
export function detectMatchingPreset(methods: string[]): string | null {
  const methodSet = new Set(methods);
  for (const preset of PERMISSION_PRESETS) {
    const presetMethods = getPresetMethods(preset);
    if (presetMethods.length !== methodSet.size) continue;
    if (presetMethods.every(m => methodSet.has(m))) return preset.id;
  }
  return null;
}
