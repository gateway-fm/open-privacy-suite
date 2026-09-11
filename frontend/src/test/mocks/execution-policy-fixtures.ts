/**
 * Mock data fixtures for the execution-policy admin screen.
 *
 * Field names mirror internal/apimodels/executionpolicy.go exactly — they are
 * the wire contract, so a rename there must fail these tests.
 */

import type {
  ExecutionPolicyContext,
  ExecutionPolicyRevision,
  ExecutionPolicyRevisionDetail,
  ExecutionPolicySimulateResult,
} from '@/types/executionPolicy';

export const mockPolicyCompiler = {
  version: '0.8.35+commit.47b9dedd',
  optimizer_runs: 200,
  evm_version: 'shanghai',
};

/** Superseded — was in force until revision 2 replaced it. */
export const mockSupersededRevision: ExecutionPolicyRevision = {
  id: 'rev-1',
  revision: 1,
  status: 'superseded',
  policy_digest: '1111111111111111111111111111111111111111111111111111111111111111',
  solidity_digest: '1212121212121212121212121212121212121212121212121212121212121212',
  runtime_digest: '1313131313131313131313131313131313131313131313131313131313131313',
  compiler: mockPolicyCompiler,
  created_at: '2024-02-01T10:00:00Z',
  activated_at: '2024-02-01T11:00:00Z',
};

/** The revision currently in force. */
export const mockActiveRevision: ExecutionPolicyRevision = {
  id: 'rev-2',
  revision: 2,
  status: 'active',
  policy_digest: '2121212121212121212121212121212121212121212121212121212121212121',
  solidity_digest: '2222222222222222222222222222222222222222222222222222222222222222',
  runtime_digest: '2323232323232323232323232323232323232323232323232323232323232323',
  compiler: mockPolicyCompiler,
  created_at: '2024-03-01T10:00:00Z',
  activated_at: '2024-03-01T12:00:00Z',
};

/** A draft awaiting review — it enforces nothing. */
export const mockDraftRevision: ExecutionPolicyRevision = {
  id: 'rev-3',
  revision: 3,
  status: 'draft',
  policy_digest: '3131313131313131313131313131313131313131313131313131313131313131',
  solidity_digest: '3232323232323232323232323232323232323232323232323232323232323232',
  runtime_digest: '3333333333333333333333333333333333333333333333333333333333333333',
  compiler: mockPolicyCompiler,
  created_at: '2024-04-01T09:00:00Z',
};

/** Newest first, as the list route returns them. */
export const mockPolicyRevisions: ExecutionPolicyRevision[] = [
  mockDraftRevision,
  mockActiveRevision,
  mockSupersededRevision,
];

export const mockDraftRevisionDetail: ExecutionPolicyRevisionDetail = {
  ...mockDraftRevision,
  source: JSON.stringify(
    {
      apiVersion: 'privacy.gateway.fm/v1alpha1',
      kind: 'ContractExecutionPolicy',
      org: 'org-1',
      nestedCalls: 'requireOwnRule',
      bindings: [
        {
          group: 'group-traders',
          allow: [
            {
              storageAddress: '0x1111111111111111111111111111111111111111',
              selector: '0xa9059cbb',
              abiDigest: 'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888',
            },
          ],
        },
      ],
    },
    null,
    2
  ),
  solidity_source:
    '// SPDX-License-Identifier: Apache-2.0\npragma solidity 0.8.35;\n\ncontract GeneratedExecutionPolicy {\n    function decide(bytes calldata) external pure returns (bool) {\n        return false;\n    }\n}\n',
  runtime_bytecode: '0x6080604052348015600f57600080fd5b50',
};

export const mockPolicyContext: ExecutionPolicyContext = {
  org_id: 'org-1',
  base_revision: 3,
  api_version: 'privacy.gateway.fm/v1alpha1',
  kind: 'ContractExecutionPolicy',
  nested_calls: 'requireOwnRule',
  groups: ['group-traders', 'group-ops'],
  contracts: [
    {
      address: '0x1111111111111111111111111111111111111111',
      name: 'Settlement',
      has_abi: true,
      abi_digest: 'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888',
    },
    {
      address: '0x2222222222222222222222222222222222222222',
      name: 'Unregistered',
      has_abi: false,
    },
  ],
  active: mockActiveRevision,
};

/** A denial both evaluators agreed on. */
export const mockDeniedSimulation: ExecutionPolicySimulateResult = {
  allowed: false,
  code: 'argument_constraint',
  reason:
    'frame 0: transfer(address,uint256) argument 1 is 5000000000000000000, above the bound 1000000000000000000',
  compiled_allowed: false,
  compiled_code: 'argument_constraint',
  agreed: true,
  runtime_digest: mockDraftRevision.runtime_digest,
};
