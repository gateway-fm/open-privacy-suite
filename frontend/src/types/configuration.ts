export type ConfigurationKind = 'groups' | 'contract-registry' | 'execution-rules' | 'compliance' | 'approvers' | 'platform';
export interface ConfigurationRevision {
  id: string;
  scope: { kind: string; id: string };
  kind: ConfigurationKind;
  revision: number;
  baseRevision: number;
  source: string;
  digest: string;
  dependencies: Record<string, string>;
  status: 'draft' | 'active' | 'superseded' | 'withdrawn';
  createdBy: string;
  createdAt: string;
  activatedBy: string | null;
  activatedAt: string | null;
  artifact?: unknown;
}
export interface ConfigurationCapabilities {
  apiVersion: string;
  kinds: ConfigurationKind[];
  humanOnlyKinds: ConfigurationKind[];
  approvalModes: string[];
  maxDocumentBytes: number;
  compiler: { version: string; available: boolean };
  /** Whether a price feed declared in the platform document is polled here. */
  priceFeed?: { available: boolean; reason?: string };
}
export interface ConfigurationContext {
  /** Optional in fixtures; the server always sends it. */
  capabilities?: ConfigurationCapabilities;
  active: ConfigurationRevision | null;
  source: Record<string, unknown>;
  viewer: { principalId: string; principalKind: string; canActivate: boolean };
  groups?: unknown;
  registry?: unknown;
  compliance?: unknown;
  approvers?: unknown;
  platform?: unknown;
  execution?: unknown;
  legacyExecution: unknown[];
}
export interface ConfigurationReview {
  revisions: ConfigurationRevision[];
  groupDiff: unknown;
  registryDiff: unknown;
  complianceDiff?: unknown;
  approversDiff?: unknown;
  platformDiff?: unknown;
  executionDiff?: unknown;
  groups?: unknown;
  registry?: unknown;
  legacyExecution: unknown[];
}
export interface ExecutionReadiness {
  mode: string;
  ready: boolean;
  reason?: string;
  desired_version?: number;
  applied_version?: number;
  expires_at?: number;
}
