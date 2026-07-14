import { useState, useEffect, useMemo } from 'react';
import { toFunctionSelector } from 'viem';
import { rbacApi } from '@/api/rbac';
import type { Contract, ContractGrant, FunctionRule, EventRule, Group, GroupAccess, GroupWithAccess } from '@/types/rbac';
import { getClosestPresetLabel } from '@/types/rbac';
import ContractGrantForm from './ContractGrantForm';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import {
  Loader2,
  Plus,
  Trash2,
  Shield,
  Users,
  FileCode2,
  Copy,
  Check,
  Info,
  Pencil,
  Code2,
  Radio,
  Eye,
  ShieldAlert,
} from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { MethodPolicyManager } from '@/components/rbac/MethodPolicyManager';

// Helper to get contract address from either new or legacy format
const getContractAddress = (contract: Contract): string => {
  return contract.address || contract.contract_address || '';
};

// Common function selectors with human-readable names (same as in form)
const COMMON_SELECTORS: Record<string, string> = {
  '0x70a08231': 'balanceOf',
  '0x18160ddd': 'totalSupply',
  '0xa9059cbb': 'transfer',
  '0x23b872dd': 'transferFrom',
  '0x095ea7b3': 'approve',
  '0xdd62ed3e': 'allowance',
  '0x06fdde03': 'name',
  '0x95d89b41': 'symbol',
  '0x313ce567': 'decimals',
};

interface ContractGrantsManagerProps {
  orgId: string;
  contract: Contract;
  // RD-1075: fired after a successful contract-level mutation here (currently
  // the visibleTo-unlock toggle) so the parent can refresh its cached contract.
  // Without it the list badge and a reopened dialog show stale state because
  // this component only updates its own local state.
  onContractUpdated?: (contract: Contract) => void;
}

// Extended grant type that includes the group info and group access
interface GrantWithGroup extends ContractGrant {
  group?: Group;
  groupAccess?: GroupAccess;
}

export default function ContractGrantsManager({
  orgId,
  contract,
  onContractUpdated,
}: ContractGrantsManagerProps) {
  const { isReadonlyAdmin } = useAdmin();
  const [grants, setGrants] = useState<GrantWithGroup[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingGrant, setEditingGrant] = useState<{ grant: GrantWithGroup, mode: 'functions' | 'events' } | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<GrantWithGroup | null>(null);
  const [copiedAddress, setCopiedAddress] = useState(false);

  // RD-874: visibleTo unlock toggle
  const [allowVisibleToUnlock, setAllowVisibleToUnlock] = useState(
    !!contract?.allow_visibleto_unlock,
  );
  const [savingUnlock, setSavingUnlock] = useState(false);
  const [unlockSuccess, setUnlockSuccess] = useState<string | null>(null);
  const [pendingUnlockEnable, setPendingUnlockEnable] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);

  const contractAddress = getContractAddress(contract);

  // reason: intentional reload when orgId/contractAddress change. loadData is a
  // non-memoised helper that reads current state via closure; adding it to deps
  // would require useCallback and risk a refetch loop.
  useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, contractAddress]);

  const loadData = async () => {
    try {
      setLoading(true);
      // Load grants and groups in parallel
      const [grantsRes, groupsRes] = await Promise.all([
        rbacApi.contracts.listGrants(orgId, contractAddress),
        rbacApi.groups.list(orgId),
      ]);

      const grantsData = grantsRes.data || [];
      const groupsWithAccess = groupsRes.data?.data || [];
      const groupsData = groupsWithAccess.map((gwa: GroupWithAccess) => gwa.group);
      setGroups(groupsData);

      // Build access map from inline data
      const accessMap = new Map<string, GroupAccess>();
      for (const gwa of groupsWithAccess) {
        if (gwa.access) {
          accessMap.set(gwa.group.id, gwa.access);
        }
      }

      // Map grants to include group and access info
      const grantsWithGroups: GrantWithGroup[] = grantsData.map(grant => {
          const group = groupsData.find((g: Group) => g.id === grant.group_id);
          const groupAccess = group ? accessMap.get(group.id) : undefined;
          return {
            ...grant,
            group,
            groupAccess,
          };
        });

      setGrants(grantsWithGroups);
    } catch (error) {
      console.error('Failed to load grants:', error);
      setGrants([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditingGrant(null);
    await loadData();
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;

    try {
      await rbacApi.contracts.deleteGrant(orgId, contractAddress, deleteTarget.group_id);
      setDeleteTarget(null);
      await loadData();
    } catch (error) {
      console.error('Failed to delete grant:', error);
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(contractAddress);
      setCopiedAddress(true);
      setTimeout(() => setCopiedAddress(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const applyUnlockToggle = async (allow: boolean) => {
    setSavingUnlock(true);
    setUnlockError(null);
    setUnlockSuccess(null);
    try {
      const res = await rbacApi.contracts.updateAllowVisibleToUnlock(orgId, contractAddress, allow);
      setAllowVisibleToUnlock(allow);
      // RD-1075: propagate the saved value to the parent so the contract-list
      // badge and a reopened dialog reflect the new state. The PUT returns the
      // updated contract; the parent merges the flag into its cached copy.
      onContractUpdated?.(res.data);
      setUnlockSuccess(allow ? 'visibleTo unlock enabled for this contract' : 'visibleTo unlock disabled');
    } catch (err: unknown) {
      console.error('Failed to update visibleTo unlock flag:', err);
      const axiosError = err as { response?: { data?: { error?: string } } };
      setUnlockError(axiosError.response?.data?.error || 'Failed to update visibleTo unlock setting.');
    } finally {
      setSavingUnlock(false);
    }
  };

  const truncateAddress = (address: string | undefined) => {
    if (!address) return '-';
    if (address.length <= 16) return address;
    return `${address.slice(0, 8)}...${address.slice(-6)}`;
  };

  const existingGrantGroupIds = grants.map(g => g.group_id);

  // Parse ABI to extract function selectors and per-selector input param names.
  const { abiFunctions, abiFunctionParams } = useMemo(() => {
    const names: Record<string, string> = {};
    const params: Record<string, Record<number, string>> = {};
    if (!contract.abi) return { abiFunctions: names, abiFunctionParams: params };
    try {
      const parsed = JSON.parse(contract.abi);
      if (!Array.isArray(parsed)) return { abiFunctions: names, abiFunctionParams: params };

      for (const item of parsed) {
        if (item.type !== 'function') continue;
        const inputs: { name: string; type: string }[] = item.inputs || [];
        const inputTypes = inputs.map(input => input.type).join(',');
        const signature = `${item.name}(${inputTypes})`;
        try {
          const selector = toFunctionSelector(signature).toLowerCase();
          names[selector] = item.name;
          const paramMap: Record<number, string> = {};
          inputs.forEach((input, idx) => {
            paramMap[idx] = input.name;
          });
          params[selector] = paramMap;
        } catch {
          // Skip invalid signatures
        }
      }
      return { abiFunctions: names, abiFunctionParams: params };
    } catch {
      return { abiFunctions: names, abiFunctionParams: params };
    }
  }, [contract.abi]);

  // Get selector display name (from ABI first, then common selectors)
  const getSelectorName = (selector: string) => {
    const normalized = selector.toLowerCase();
    return abiFunctions[normalized] || COMMON_SELECTORS[normalized] || null;
  };

  // Parse ABI to map event name -> { paramIndex -> paramName }
  const abiEventParams = useMemo(() => {
    if (!contract.abi) return {};
    try {
      const parsed = JSON.parse(contract.abi);
      if (!Array.isArray(parsed)) return {};
      const map: Record<string, Record<number, string>> = {};
      for (const item of parsed) {
        if (item.type !== 'event') continue;
        const paramMap: Record<number, string> = {};
        (item.inputs || []).forEach((input: { name: string }, idx: number) => {
          paramMap[idx] = input.name;
        });
        map[item.name] = paramMap;
      }
      return map;
    } catch {
      return {};
    }
  }, [contract.abi]);

  // Get event param name: "from", "to", "value" instead of "param[0]", "param[1]", "param[2]"
  const getEventParamLabel = (eventName: string, paramIndex: number, mustBe: string) => {
    const paramName = abiEventParams[eventName]?.[paramIndex];
    const label = paramName || `param[${paramIndex}]`;
    return `${label}=${mustBe}`;
  };

  // Get function param name (e.g. "to", "amount") from the ABI by selector, falling back to param[N].
  const getFunctionParamLabel = (selector: string, paramIndex: number, mustBe: string) => {
    const paramName = abiFunctionParams[selector.toLowerCase()]?.[paramIndex];
    const label = paramName || `param[${paramIndex}]`;
    return `${label}=${mustBe}`;
  };

  return (
    <div className="space-y-4">
      {/* Contract header */}
      <div className="flex items-start gap-3 pb-4 border-b border-neutral-200">
        <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center">
          <FileCode2 className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h3 className="text-lg font-semibold text-neutral-900">
            {contract.name || 'Unnamed Contract'}
          </h3>
          <div className="flex items-center gap-2 mt-1">
            <span className="font-mono text-sm text-neutral-500" title={contractAddress}>
              {truncateAddress(contractAddress)}
            </span>
            <button
              onClick={copyToClipboard}
              className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors"
              title="Copy address"
            >
              {copiedAddress ? (
                <Check className="w-3.5 h-3.5 text-success" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Info banner */}
      <div className="p-3 rounded-lg bg-sky-50 border border-sky-200 flex items-start gap-2">
        <Info className="w-4 h-4 text-sky-600 mt-0.5 flex-shrink-0" />
        <p className="text-xs text-sky-700">
          Groups define claims (admin, deploy, upgrade) in the Groups tab. Adding a group here grants its members access to this contract with their group's claims. You can also restrict access to specific functions.
        </p>
      </div>

      {/* RD-874: per-contract visibleTo unlock toggle */}
      {!isReadonlyAdmin && (
        <div className="space-y-2">
          {unlockError && (
            <div className="p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-error-dark flex-shrink-0 mt-0.5" />
              <span className="text-error-dark text-sm">{unlockError}</span>
            </div>
          )}
          <div className="flex items-start justify-between gap-3 p-3 rounded-lg border border-neutral-200">
            <div className="flex items-start gap-3 min-w-0">
              <Eye className="w-5 h-5 mt-0.5 text-neutral-500 flex-shrink-0" />
              <div className="min-w-0 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-neutral-700">
                    visibleTo unlock
                  </span>
                  {allowVisibleToUnlock && (
                    <span className="text-xs px-2 py-0.5 rounded bg-amber-100 text-amber-800">
                      enabled
                    </span>
                  )}
                </div>
                <p className="text-xs text-neutral-500">
                  When enabled, a transaction sender on this contract can grant
                  per-event visibility to anyone they list in the tx's <code>visibleTo</code>{' '}
                  array — bypassing the contract grant's event rules and parameter
                  rules for that one transaction. Default off; existing additive
                  behaviour stays.
                </p>
                {allowVisibleToUnlock && (
                  <p className="text-xs text-amber-700 flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" />
                    Tx senders can unlock a transaction's event payloads only to
                    listed DIDs that already hold contract group access in this
                    org; cross-org and anonymous viewers remain denied.
                  </p>
                )}
                {unlockSuccess && (
                  <p className="text-xs text-success-dark flex items-center gap-1">
                    <Check className="w-3 h-3" />
                    {unlockSuccess}
                  </p>
                )}
              </div>
            </div>
            <div className="flex items-center">
              {savingUnlock ? (
                <Loader2 className="w-4 h-4 animate-spin text-neutral-500" />
              ) : (
                <input
                  type="checkbox"
                  role="switch"
                  aria-label="Allow visibleTo to unlock event visibility"
                  checked={allowVisibleToUnlock}
                  disabled={savingUnlock}
                  onChange={e => {
                    if (e.target.checked) {
                      setPendingUnlockEnable(true);
                    } else {
                      void applyUnlockToggle(false);
                    }
                  }}
                  className="w-4 h-4 cursor-pointer"
                />
              )}
            </div>
          </div>
        </div>
      )}

      {/* RD-1206: per-record method access policies */}
      <MethodPolicyManager
        orgId={orgId}
        contractAddress={getContractAddress(contract)}
        contractAbi={contract.abi}
        initialPolicy={contract.method_policies}
        isReadonlyAdmin={isReadonlyAdmin}
      />

      {pendingUnlockEnable && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-5 space-y-3">
            <div className="flex items-start gap-3">
              <ShieldAlert className="w-6 h-6 text-amber-600 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-base font-semibold text-neutral-900">
                  Enable visibleTo unlock?
                </h3>
                <p className="text-sm text-neutral-600 mt-1">
                  Once enabled, any transaction sender on this contract can grant
                  per-event visibility (bypassing event rules and parameter rules)
                  to anyone they list in <code>visibleTo</code> on a transaction.
                  Listed users still need contract-level group access in this org —
                  cross-org and anonymous viewers remain denied.
                </p>
                <p className="text-sm text-neutral-600 mt-2">
                  Set this only on contracts where shared per-tx visibility is the
                  intended workflow.
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <Button
                type="button"
                variant="ghost"
                onClick={() => setPendingUnlockEnable(false)}
                disabled={savingUnlock}
              >
                Cancel
              </Button>
              <Button
                type="button"
                onClick={async () => {
                  setPendingUnlockEnable(false);
                  await applyUnlockToggle(true);
                }}
                disabled={savingUnlock}
                className="gap-2"
              >
                {savingUnlock ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                Enable
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Grants section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-neutral-700">Groups with Access</span>
          </div>
          {!isReadonlyAdmin && (
            <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
              <Plus className="w-4 h-4" />
              Add Group
            </Button>
          )}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
          </div>
        ) : grants.length === 0 ? (
          <div className="text-center py-8 border border-dashed border-neutral-200 rounded-lg">
            <Users className="w-8 h-8 text-neutral-400 mx-auto mb-2" />
            <p className="text-sm text-neutral-500 mb-3">
              No groups have access to this contract yet
            </p>
            {!isReadonlyAdmin && (
              <Button variant="outline" size="sm" onClick={() => setShowForm(true)} className="gap-2">
                <Plus className="w-4 h-4" />
                Add a group
              </Button>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {grants.map(grant => (
              <div
                key={grant.id}
                className="p-4 border border-neutral-200 rounded-lg hover:border-primary-100 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-lg bg-neutral-100 flex items-center justify-center">
                      <Users className="w-4 h-4 text-neutral-500" />
                    </div>
                    <div>
                      <h4 className="font-medium text-neutral-900">
                        {grant.group?.name || 'Unknown Group'}
                      </h4>
                      {grant.group && (
                        <p className="text-xs text-neutral-400 mt-0.5">
                          {grant.group.path}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    {!isReadonlyAdmin && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(grant)}
                          className="text-error-dark hover:text-error-dark hover:bg-error-light"
                          title="Remove group access"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </>
                    )}
                  </div>
                </div>

                {/* Group role badge */}
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <span className="text-xs text-neutral-500">Role:</span>
                  {grant.groupAccess?.allowed_methods && grant.groupAccess.allowed_methods.length > 0 ? (
                    <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-primary-50 text-primary">
                      {getClosestPresetLabel(grant.groupAccess.allowed_methods.filter(m => m !== '*'))}
                    </span>
                  ) : (
                    <span className="text-xs text-neutral-400 italic">
                      No permissions configured - set up in Groups tab
                    </span>
                  )}
                </div>

                {/* Function access */}
                <div className="mt-2 flex items-start justify-between gap-4 group">
                  <div className="flex flex-wrap items-center gap-2 pt-0.5">
                    <span className="text-xs text-neutral-500">Functions:</span>
                    {!grant.functions || grant.functions.length === 0 ? (
                    <span className="text-xs text-success font-medium">All functions allowed</span>
                  ) : (
                    <div className="flex flex-wrap items-center gap-1.5">
                      {grant.functions.map((rule: FunctionRule) => {
                        const name = getSelectorName(rule.selector);
                        const paramLabels = (rule.param_rules || []).map(
                          pr => getFunctionParamLabel(rule.selector, pr.index, pr.must_be)
                        );
                        return (
                          <span
                            key={rule.selector}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-amber-100 text-amber-800 border border-amber-200"
                            title={name ? `${name}()` : rule.selector}
                          >
                            <Code2 className="w-3 h-3" />
                            {name || rule.selector}
                            {paramLabels.length > 0 && (
                              <span className="ml-1 text-[10px] text-amber-700">
                                [{paramLabels.join(' AND ')}]
                              </span>
                            )}
                          </span>
                        );
                      })}
                    </div>
                  )}
                  </div>
                  {!isReadonlyAdmin && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="w-6 h-6 shrink-0 text-neutral-400 hover:text-primary opacity-50 group-hover:opacity-100 transition-opacity"
                          onClick={() => setEditingGrant({ grant, mode: 'functions' })}
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>Edit function access</p>
                      </TooltipContent>
                    </Tooltip>
                  )}
                </div>

                {/* Event visibility */}
                <div className="mt-2 flex items-start justify-between gap-4 group">
                  <div className="flex flex-wrap items-center gap-2 pt-0.5">
                    <span className="text-xs text-neutral-500">Events:</span>
                    {grant.event_rules === '*' ? (
                    <span className="text-xs text-success font-medium">All events visible</span>
                  ) : grant.event_rules === null || grant.event_rules === undefined || grant.event_rules.length === 0 ? (
                    grant.group?.is_org_admin || grant.groupAccess?.claims?.includes('admin') ? (
                      <span className="text-xs text-success font-medium">All events (admin bypass)</span>
                    ) : (
                      <span className="text-xs text-error-dark font-medium">No events visible</span>
                    )
                  ) : (
                    <div className="flex flex-wrap items-center gap-1.5">
                      {grant.event_rules.map((rule: EventRule) => {
                        const paramLabels = (rule.param_rules || []).map(
                          pr => getEventParamLabel(rule.name, pr.index, pr.must_be)
                        );
                        return (
                          <span
                            key={rule.topic0}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-violet-100 text-violet-800 border border-violet-200"
                            title={`${rule.name} — ${rule.topic0}`}
                          >
                            <Radio className="w-3 h-3" />
                            {rule.name}
                            {paramLabels.length > 0 && (
                              <span className="ml-1 text-[10px] text-violet-700">
                                [{paramLabels.join(' OR ')}]
                              </span>
                            )}
                          </span>
                        );
                      })}
                    </div>
                  )}
                  </div>
                  {!isReadonlyAdmin && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="w-6 h-6 shrink-0 text-neutral-400 hover:text-primary opacity-50 group-hover:opacity-100 transition-opacity"
                          onClick={() => setEditingGrant({ grant, mode: 'events' })}
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>Edit event visibility</p>
                      </TooltipContent>
                    </Tooltip>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add Group Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent className="max-w-5xl max-h-[90vh] overflow-y-auto overflow-x-hidden">
          <DialogHeader>
            <DialogTitle>Add Group Access</DialogTitle>
          </DialogHeader>
          <ContractGrantForm
            orgId={orgId}
            contractAddress={contractAddress}
            contractAbi={contract.abi}
            groups={groups}
            existingGrantGroupIds={existingGrantGroupIds}
            onClose={() => setShowForm(false)}
            onSave={handleSave}
            editMode="add"
          />
        </DialogContent>
      </Dialog>

      <Dialog open={!!editingGrant} onOpenChange={open => !open && setEditingGrant(null)}>
        <DialogContent className="max-w-5xl max-h-[90vh] overflow-y-auto overflow-x-hidden">
          <DialogHeader>
            <DialogTitle>
              {editingGrant?.mode === 'functions' ? 'Edit Function Rules' : 'Edit Event Rules'}
            </DialogTitle>
          </DialogHeader>
          {editingGrant && (
            <ContractGrantForm
              key={editingGrant.grant.id}
              orgId={orgId}
              contractAddress={contractAddress}
              contractAbi={contract.abi}
              grant={editingGrant.grant}
              groups={groups}
              existingGrantGroupIds={existingGrantGroupIds}
              onClose={() => setEditingGrant(null)}
              onSave={handleSave}
              editMode={editingGrant.mode}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => !open && setDeleteTarget(null)}
        title="Remove Group Access"
        description={`Are you sure you want to remove "${deleteTarget?.group?.name || 'this group'}" access to this contract?`}
        confirmLabel="Remove"
        cancelLabel="Cancel"
        onConfirm={handleDeleteConfirm}
        variant="destructive"
      />
    </div>
  );
}
