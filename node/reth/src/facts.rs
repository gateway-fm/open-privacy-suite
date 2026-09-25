//! A5 facts ABI adapter. This resolves facts from the pinned directory;
//! generated private bytecode remains responsible for each frame's rules.

use crate::{
    context::{
        CodeKind, CreatedContract, ExecutionIdentity, FrameKind, FramePolicy, ObservedCall,
        PolicyInvocation, PolicyPlan,
    },
    stream::AppliedFacts,
    wire::{Contract, PolicyArtifact, validate_artifact},
};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, sol};
use std::{collections::HashMap, sync::Arc};

sol! {
    struct Facts { address signer; address[] linkedAddresses; bytes32[] groups; bytes32 policyOrg; bytes32 callerOrg; bytes32 codeOrg; bytes32 storageOrg; uint8 claims; bool codeShared; bool storageShared; uint8 codeKind; bytes32 upgradeTargetOrg; uint8[] groupClaims; bool storageDeployer; bool storagePending; }
    struct Call { uint8 kind; address caller; address codeAddress; address storageAddress; bytes data; uint256 value; uint256 depth; }
    function check(Facts facts, Call frame) external returns (uint256);
}

#[derive(Debug)]
pub struct FactsPolicy {
    facts: Arc<AppliedFacts>,
    at: i64,
    principals: HashMap<String, usize>,
    groups: HashMap<String, usize>,
    contracts: HashMap<Address, usize>,
    policies: HashMap<(String, String), (B256, Bytes)>,
}

impl FactsPolicy {
    pub fn new(facts: Arc<AppliedFacts>, at: i64) -> Result<Self, String> {
        if at < 0 || at >= facts.expires_at() {
            return Err("stale execution facts".into());
        }
        let snapshot = facts.snapshot();
        let principals = snapshot
            .principals
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.clone(), i))
            .collect();
        let groups = snapshot
            .groups
            .iter()
            .enumerate()
            .map(|(i, g)| (g.id.clone(), i))
            .collect();
        let contracts = snapshot
            .contracts
            .iter()
            .enumerate()
            .map(|(i, c)| Ok((parse_address(&c.address)?, i)))
            .collect::<Result<_, String>>()?;
        let policies = snapshot
            .policies
            .iter()
            .map(|p| {
                Ok((
                    (p.org_id.clone(), p.group_id.clone()),
                    (
                        format!("0x{}", p.policy_digest)
                            .parse()
                            .map_err(|_| "invalid policy digest")?,
                        Bytes::copy_from_slice(&p.bytecode),
                    ),
                ))
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            facts,
            at,
            principals,
            groups,
            contracts,
            policies,
        })
    }

    fn contract(&self, address: Address) -> Option<&Contract> {
        self.contracts
            .get(&address)
            .map(|index| &self.facts.snapshot().contracts[*index])
    }
    /// Ephemeral simulation override. The signed stream and its immutable facts
    /// remain untouched; only the selected organization's program is replaced.
    pub fn with_candidate(mut self, candidate: &PolicyArtifact, org: &str) -> Result<Self, String> {
        self.replace_candidates(std::slice::from_ref(candidate), org)?;
        Ok(self)
    }
    pub fn with_candidates(
        mut self,
        candidates: &[PolicyArtifact],
        org: &str,
    ) -> Result<Self, String> {
        self.replace_candidates(candidates, org)?;
        Ok(self)
    }
    fn known_org(&self, org: &str) -> bool {
        // A reviewed deny-all document has an empty artifact set. Diagnostic
        // scope comes from the directory, independently of whether any active
        // group grants execution; ordinary execution still needs an artifact.
        self.facts
            .snapshot()
            .groups
            .iter()
            .any(|group| group.org_id == org)
    }
    fn replace_candidates(
        &mut self,
        candidates: &[PolicyArtifact],
        org: &str,
    ) -> Result<(), String> {
        if !self.known_org(org) {
            return Err("candidate policy organization mismatch".into());
        }
        let mut next = HashMap::new();
        for candidate in candidates {
            validate_artifact(candidate)?;
            if candidate.org_id != org
                || next.contains_key(&(org.to_owned(), candidate.group_id.clone()))
            {
                return Err("candidate policy organization or group mismatch".into());
            }
            if let Some(first) = candidates.first()
                && (candidate.policy_digest != first.policy_digest
                    || candidate.revision != first.revision
                    || (candidates.len() > 1 && candidate.group_id.is_empty()))
            {
                return Err("inconsistent candidate artifact set".into());
            }
            next.insert(
                (org.to_owned(), candidate.group_id.clone()),
                (
                    format!("0x{}", candidate.policy_digest)
                        .parse()
                        .map_err(|_| "invalid candidate digest")?,
                    Bytes::copy_from_slice(&candidate.bytecode),
                ),
            );
        }
        self.policies.retain(|(owner, _), _| owner != org);
        self.policies.extend(next);
        Ok(())
    }
    fn owner<'a>(&'a self, address: Address, created: &'a [CreatedContract]) -> &'a str {
        self.contract(address)
            .filter(|c| !c.org_id.is_empty())
            .map(|c| c.org_id.as_str())
            .or_else(|| {
                created
                    .iter()
                    .rev()
                    .find(|c| c.address == address)
                    .map(|c| c.org_id.as_str())
            })
            .unwrap_or("")
    }
    fn sanctioned(&self, address: Address, org: &str) -> bool {
        let address = format!("{address:#x}");
        self.facts
            .snapshot()
            .sanctions
            .iter()
            .any(|s| s.address == address && (s.org_id.is_empty() || s.org_id == org))
    }
}

impl FramePolicy for FactsPolicy {
    fn authorize_diagnostic(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
        created: &[CreatedContract],
    ) -> Result<(), String> {
        let principal = self
            .principals
            .get(&identity.principal_id)
            .map(|i| &self.facts.snapshot().principals[*i])
            .ok_or("missing diagnostic principal")?;
        if !principal
            .linked_addresses
            .contains(&format!("{:#x}", identity.signer))
            || !self.known_org(&identity.org_id)
        {
            return Err("invalid diagnostic principal scope".into());
        }
        self.authorize_diagnostic_account(
            identity,
            call.code_address,
            call.code_hash,
            call.code_kind,
            created,
        )?;
        self.authorize_diagnostic_account(
            identity,
            call.storage_address,
            call.storage_code_hash,
            if call.storage_address == call.code_address {
                call.code_kind
            } else {
                CodeKind::Contract
            },
            created,
        )?;
        Ok(())
    }

    fn authorize_diagnostic_account(
        &self,
        identity: &ExecutionIdentity,
        account: Address,
        code_hash: B256,
        kind: CodeKind,
        created: &[CreatedContract],
    ) -> Result<(), String> {
        let owner = self.owner(account, created);
        let is_shared = shared(self.contract(account), code_hash)?;
        if !owner.is_empty() {
            return if owner == identity.org_id {
                Ok(())
            } else {
                Err("diagnostic account escaped organization scope".into())
            };
        }
        if matches!(kind, CodeKind::NoCode | CodeKind::Precompile) {
            return Ok(());
        }
        if kind == CodeKind::Contract && is_shared {
            return Ok(());
        }
        Err("diagnostic account is outside known organization scope".into())
    }

    fn authorize_policy_read(
        &self,
        identity: &ExecutionIdentity,
        guarded: &ObservedCall,
        account: Address,
        code_hash: B256,
        active_precompile: bool,
        created: &[CreatedContract],
    ) -> Result<(), String> {
        let storage_org = self.owner(guarded.storage_address, created);
        let policy_org = if matches!(guarded.kind, FrameKind::Create | FrameKind::Create2)
            || storage_org.is_empty()
        {
            identity.org_id.as_str()
        } else {
            storage_org
        };
        if (!active_precompile && self.owner(account, created) != policy_org)
            || self.sanctioned(account, policy_org)
        {
            return Err("policy read escaped organization scope".into());
        }
        shared(self.contract(account), code_hash)?;
        Ok(())
    }
    fn prepare(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
    ) -> Result<PolicyInvocation, String> {
        self.prepare_with_creations(identity, call, &[])
    }

    fn prepare_with_creations(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
        created: &[CreatedContract],
    ) -> Result<PolicyInvocation, String> {
        let mut plan = self.prepare_all(identity, call, created)?;
        if plan.invocations.len() != 1 {
            return Err("execution requires the full group artifact set".into());
        }
        Ok(plan.invocations.remove(0))
    }

    fn prepare_all(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
        created: &[CreatedContract],
    ) -> Result<PolicyPlan, String> {
        if identity.min_snapshot_version == 0
            || identity.min_snapshot_version > self.facts.version()
        {
            return Err("execution snapshot is behind identity context".into());
        }
        let snapshot = self.facts.snapshot();
        let principal = self
            .principals
            .get(&identity.principal_id)
            .map(|i| &snapshot.principals[*i])
            .ok_or("missing execution principal")?;
        if principal.banned
            || !principal
                .linked_addresses
                .contains(&format!("{:#x}", identity.signer))
            || self.sanctioned(identity.signer, &identity.org_id)
        {
            return Err("execution principal is not active".into());
        }
        let mut groups = principal
            .memberships
            .iter()
            .filter(|m| m.expires_at == 0 || m.expires_at > self.at)
            .filter_map(|m| self.groups.get(&m.group_id).map(|i| &snapshot.groups[*i]))
            .collect::<Vec<_>>();
        if !groups.iter().any(|g| g.org_id == identity.org_id) {
            return Err(
                "execution principal has no active selected organization membership".into(),
            );
        }
        let creation = matches!(call.kind, FrameKind::Create | FrameKind::Create2);
        let storage = self.contract(call.storage_address);
        let actual_creation = created.iter().rev().find(|contract| {
            contract.address == call.storage_address
                && contract.org_id == self.owner(call.storage_address, created)
        });
        let storage_pending =
            actual_creation.is_none() && storage.is_some_and(|contract| contract.pending);
        let storage_deployer = actual_creation.map_or_else(
            || {
                storage
                    .is_some_and(|contract| contract.deployer_principal_id == identity.principal_id)
            },
            |contract| contract.principal_id == identity.principal_id,
        );
        let code = self.contract(call.code_address);
        let observed_storage_org = self.owner(call.storage_address, created);
        let observed_code_org = self.owner(call.code_address, created);
        let policy_org = if creation {
            identity.org_id.as_str()
        } else if !observed_storage_org.is_empty() {
            observed_storage_org
        } else {
            identity.org_id.as_str()
        };
        if [
            identity.signer,
            call.caller,
            call.code_address,
            call.storage_address,
        ]
        .iter()
        .any(|address| self.sanctioned(*address, policy_org))
        {
            return Err("execution frame is sanctioned".into());
        }
        groups.retain(|g| g.org_id == policy_org);
        groups.sort_by(|a, b| a.id.cmp(&b.id));
        let group_claims = groups
            .iter()
            .map(|group| {
                if group.org_admin {
                    7
                } else if creation || storage_pending {
                    group.claims
                } else {
                    group
                        .contract_claims
                        .iter()
                        .find(|grant| grant.address == format!("{:#x}", call.storage_address))
                        .map_or(0, |grant| grant.claims)
                }
            })
            .collect::<Vec<_>>();
        let code_org = if creation && observed_code_org.is_empty() {
            policy_org
        } else {
            observed_code_org
        };
        let storage_org = if creation && observed_storage_org.is_empty() {
            policy_org
        } else {
            observed_storage_org
        };
        let (code_shared, storage_shared) = if creation {
            (false, false)
        } else {
            (
                shared(code, call.code_hash)?,
                shared(storage, call.storage_code_hash)?,
            )
        };
        let upgrade_target = upgrade_target(&call.calldata)
            .map(|address| org_word(self.owner(address, created)))
            .unwrap_or(B256::ZERO);
        let input = checkCall {
            facts: Facts {
                signer: identity.signer,
                linkedAddresses: principal
                    .linked_addresses
                    .iter()
                    .map(|s| parse_address(s))
                    .collect::<Result<_, _>>()?,
                groups: groups
                    .iter()
                    .map(|group| keccak256(group.id.as_bytes()))
                    .collect(),
                policyOrg: org_word(policy_org),
                callerOrg: org_word(self.owner(call.caller, created)),
                codeOrg: org_word(code_org),
                storageOrg: org_word(storage_org),
                claims: group_claims.iter().fold(0, |mask, claim| mask | claim),
                codeShared: code_shared,
                storageShared: storage_shared,
                codeKind: call.code_kind as u8,
                upgradeTargetOrg: upgrade_target,
                groupClaims: group_claims,
                storageDeployer: storage_deployer,
                storagePending: storage_pending,
            },
            frame: Call {
                kind: match call.kind {
                    FrameKind::Call => 0,
                    FrameKind::StaticCall => 1,
                    FrameKind::DelegateCall => 2,
                    FrameKind::CallCode => 3,
                    FrameKind::Create => 4,
                    FrameKind::Create2 => 5,
                },
                caller: call.caller,
                codeAddress: call.code_address,
                storageAddress: call.storage_address,
                data: call.calldata.clone(),
                value: call.value,
                depth: U256::from(call.depth),
            },
        };
        let calldata: Bytes = input.abi_encode().into();
        let legacy = self.policies.get(&(policy_org.to_owned(), String::new()));
        let selected = if let Some(artifact) = legacy {
            vec![artifact]
        } else {
            groups
                .iter()
                .filter_map(|group| {
                    self.policies
                        .get(&(policy_org.to_owned(), group.id.clone()))
                })
                .collect()
        };
        if selected.is_empty() {
            return Err("missing applicable execution policy".into());
        }
        Ok(PolicyPlan {
            per_group: legacy.is_none(),
            invocations: selected
                .into_iter()
                .map(|(revision, bytecode)| PolicyInvocation {
                    revision: *revision,
                    bytecode: bytecode.clone(),
                    calldata: calldata.clone(),
                })
                .collect(),
        })
    }
}

fn parse_address(address: &str) -> Result<Address, String> {
    address.parse().map_err(|_| "invalid fact address".into())
}
fn org_word(org: &str) -> B256 {
    if org.is_empty() {
        B256::ZERO
    } else {
        keccak256(org.as_bytes())
    }
}
fn shared(contract: Option<&Contract>, live_hash: B256) -> Result<bool, String> {
    let Some(contract) = contract else {
        return Ok(false);
    };
    if !contract.code_hash.is_empty() && contract.code_hash != format!("{live_hash:#x}") {
        return Err("execution contract code hash mismatch".into());
    }
    Ok(contract.shared_infrastructure)
}
fn upgrade_target(data: &[u8]) -> Option<Address> {
    let selector = data.get(..4)?;
    let index = match selector {
        [0x36, 0x59, 0xcf, 0xe6] | [0x4f, 0x1e, 0xf2, 0x86] | [0xd7, 0x84, 0xd4, 0x26] => 0,
        [0x99, 0xa8, 0x8e, 0xc4] | [0x96, 0x23, 0x60, 0x9d] => 1,
        _ => return None,
    };
    let word = data.get(4 + index * 32..4 + (index + 1) * 32)?;
    if word[..12].iter().any(|b| *b != 0) {
        return None;
    }
    Some(Address::from_slice(&word[12..]))
}
