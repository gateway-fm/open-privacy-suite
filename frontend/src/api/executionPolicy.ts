import { adminApi } from './adminClient';
import type {
  ExecutionPolicyContext,
  ExecutionPolicyRevision,
  ExecutionPolicyRevisionDetail,
  ExecutionPolicySimulateInput,
  ExecutionPolicySimulateResult,
  ExecutionPolicySubmitInput,
} from '../types/executionPolicy';

const api = adminApi;

// All routes are org-scoped and admin-authenticated; the restricted operator
// token is rejected by the backend for every one of them.
const base = (orgId: string) => `/orgs/${orgId}/execution-policy`;

export const executionPolicyApi = {
  /** Groups, ABI-bearing contracts and the revision a candidate must declare. */
  getContext: (orgId: string) =>
    api.get<ExecutionPolicyContext>(`${base(orgId)}/context`),

  /** Revision history, newest first. */
  listRevisions: (orgId: string) =>
    api.get<ExecutionPolicyRevision[]>(`${base(orgId)}/revisions`),

  /**
   * Submits a candidate. 400 carries the validation message naming the field
   * at fault; 409 means the declared base revision is stale.
   */
  submit: (orgId: string, input: ExecutionPolicySubmitInput) =>
    api.post<ExecutionPolicyRevisionDetail>(`${base(orgId)}/revisions`, input),

  /** One revision with its document, generated Solidity and bytecode. */
  getRevision: (orgId: string, revisionId: string) =>
    api.get<ExecutionPolicyRevisionDetail>(`${base(orgId)}/revisions/${revisionId}`),

  /** Puts a draft in force and retires whatever was active before it. */
  activate: (orgId: string, revisionId: string) =>
    api.post<ExecutionPolicyRevision>(`${base(orgId)}/revisions/${revisionId}/activate`),

  /** Abandons a draft that was never activated. */
  withdraw: (orgId: string, revisionId: string) =>
    api.post<ExecutionPolicyRevision>(`${base(orgId)}/revisions/${revisionId}/withdraw`),

  /** Evaluates a hypothetical execution against a revision. Mutates nothing. */
  simulate: (orgId: string, revisionId: string, input: ExecutionPolicySimulateInput) =>
    api.post<ExecutionPolicySimulateResult>(
      `${base(orgId)}/revisions/${revisionId}/simulate`,
      input
    ),
};

export default executionPolicyApi;
