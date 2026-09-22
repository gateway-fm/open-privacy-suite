import { useEffect, useState, useMemo } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Contract, ContractSyncCheckResponse, ContractSyncStatus } from '@/types/rbac';

// Helper to get contract address from either new or legacy format
const getContractAddress = (contract: Contract): string => {
  return contract.address || contract.contract_address || '';
};
import ContractForm from './ContractForm';
import ContractGrantsManager from './ContractGrantsManager';
import MoveToGroupDialog from './MoveToGroupDialog';
import { useOrgContext } from './RBACManager';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog, AlertDialog } from '@/components/ui/ConfirmDialog';
import Pagination from '@/components/ui/Pagination';
import { Input } from '@/components/ui/input';
import { FileCode2, Plus, Pencil, Trash2, Loader2, Copy, Check, RefreshCw, AlertTriangle, Shield, ArrowRight, X, Search, Eye } from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { useManagedStream } from '@/hooks/useManagedStream';
import ManagedStreamNotice from './ManagedStreamNotice';
import { extractApiError } from '@/lib/executionPolicy';

const PAGE_SIZE = 25;

export default function ContractList() {
  const { selectedOrg } = useOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const orgId = selectedOrg?.id || '';
  // A reviewed contract-registry document, once active, owns this stream.
  const { managed, checked } = useManagedStream('contract-registry', orgId);
  const canEdit = !isReadonlyAdmin && checked && !managed;
  // Grants close under either document: the registry owns read grants and
  // event rules, the execution rules own the function half.
  const { managed: executionManaged, checked: executionChecked } = useManagedStream('execution-rules', orgId);
  const [contracts, setContracts] = useState<Contract[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Contract | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Contract | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [managingGrants, setManagingGrants] = useState<Contract | null>(null);
  const [grantSummary, setGrantSummary] = useState<Record<string, { count: number; groups: Array<{id: string; name: string}> }>>({});

  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Date filter state
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  // Multi-select state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showMoveDialog, setShowMoveDialog] = useState(false);

  const allSelected = useMemo(
    () => contracts.length > 0 && contracts.every(c => selectedIds.has(c.id)),
    [contracts, selectedIds]
  );
  const someSelected = useMemo(
    () => contracts.some(c => selectedIds.has(c.id)) && !allSelected,
    [contracts, selectedIds, allSelected]
  );

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (allSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(contracts.map(c => c.id)));
    }
  };

  // Sync with chain state
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<ContractSyncCheckResponse | null>(null);
  const [showSyncDialog, setShowSyncDialog] = useState(false);
  const [deletingStale, setDeletingStale] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);

  // Clear selection when org changes
  useEffect(() => {
    setSelectedIds(new Set());
  }, [orgId]);

  // reason: intentional reload when the listed filter keys change.
  // loadContracts is a non-memoised helper that reads current state via closure;
  // adding it to deps would require useCallback and risk a refetch loop.
  useEffect(() => {
    if (orgId) {
      loadContracts(0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, debouncedSearch, dateFrom, dateTo]);

  const loadContracts = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      const params: { limit: number; offset: number; search?: string; created_after?: string; created_before?: string } = { limit: PAGE_SIZE, offset: newOffset };
      if (debouncedSearch) params.search = debouncedSearch;
      if (dateFrom) params.created_after = dateFrom + 'T00:00:00Z';
      if (dateTo) params.created_before = dateTo + 'T23:59:59Z';
      const response = await rbacApi.contracts.list(orgId, params);
      const page = response.data;
      setContracts(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
      try {
        const summaryRes = await rbacApi.contracts.grantSummary(orgId);
        setGrantSummary(summaryRes.data || {});
      } catch {
        setGrantSummary({});
      }
    } catch (error) {
      console.error('Failed to load contracts:', error);
      setContracts([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    const addr = getContractAddress(deleteTarget);

    try {
      await rbacApi.contracts.delete(orgId, addr);
      setDeleteTarget(null);
      await loadContracts();
    } catch (error) {
      console.error('Failed to delete contract:', error);
      setDeleteTarget(null);
      setDeleteError(extractApiError(error, 'Failed to delete contract.').message);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadContracts();
  };

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  // Sync with chain - check contracts exist on-chain
  const handleSyncCheck = async () => {
    if (!orgId) return;
    try {
      setSyncing(true);
      setSyncError(null);
      const response = await rbacApi.contracts.syncCheck(orgId);
      setSyncResult(response.data);

      // Always show the dialog with results
      setShowSyncDialog(true);
    } catch (error) {
      console.error('Failed to sync contracts:', error);
      setSyncError('Failed to check contracts against chain');
    } finally {
      setSyncing(false);
    }
  };

  // Delete stale (missing) contracts
  const handleDeleteStale = async () => {
    if (!orgId || !syncResult || !syncResult.missing?.length) return;

    try {
      setDeletingStale(true);
      const contractIds = syncResult.missing.map(c => c.id);
      await rbacApi.contracts.syncDelete(orgId, contractIds);
      setShowSyncDialog(false);
      setSyncResult(null);
      await loadContracts();
    } catch (error) {
      console.error('Failed to delete stale contracts:', error);
      setSyncError('Failed to delete stale contracts');
    } finally {
      setDeletingStale(false);
    }
  };

  const truncateAddress = (address: string | undefined) => {
    if (!address) return '-';
    if (address.length <= 16) return address;
    return `${address.slice(0, 8)}...${address.slice(-6)}`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-neutral-700">Contracts</h3>
          <p className="text-xs text-neutral-500 mt-0.5">
            Registered contracts with access grants for groups
          </p>
        </div>
        <div className="flex gap-2">
          {canEdit && (
            <>
              <Button
                onClick={handleSyncCheck}
                size="sm"
                variant="outline"
                className="gap-2"
                disabled={syncing || contracts.length === 0}
              >
                <RefreshCw className={`w-4 h-4 ${syncing ? 'animate-spin' : ''}`} />
                {syncing ? 'Checking...' : 'Sync with Chain'}
              </Button>
              <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
                <Plus className="w-4 h-4" />
                Add Contract
              </Button>
            </>
          )}
        </div>
      </div>

      {managed && <ManagedStreamNotice subject="Contracts" />}

      {/* Search + Date Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 max-w-sm min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" />
          <Input
            type="text"
            placeholder="Search by name or address..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-neutral-500">From</span>
          <Input
            type="date"
            value={dateFrom}
            onChange={e => setDateFrom(e.target.value)}
            className="w-[140px] text-xs"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-neutral-500">To</span>
          <Input
            type="date"
            value={dateTo}
            onChange={e => setDateTo(e.target.value)}
            className="w-[140px] text-xs"
          />
        </div>
        {(searchQuery || dateFrom || dateTo) && (
          <Button variant="ghost" size="sm" onClick={() => { setSearchQuery(''); setDateFrom(''); setDateTo(''); }} className="text-neutral-500">
            Clear
          </Button>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
        </div>
      ) : selectedIds.size > 0 ? (
        <div data-testid="selection-toolbar" className="flex items-center gap-3 px-4 py-2 bg-primary-50 rounded-lg border border-primary/20">
          <span className="text-sm font-medium text-primary">
            {selectedIds.size} selected
          </span>
          {canEdit && (
            <Button
              data-testid="move-to-group-btn"
              size="sm"
              variant="outline"
              className="gap-1.5 border-primary/30 text-primary hover:bg-primary/10"
              onClick={() => setShowMoveDialog(true)}
            >
              <ArrowRight className="w-3.5 h-3.5" />
              Move to Group
            </Button>
          )}
          <Button
            data-testid="clear-selection-btn"
            size="sm"
            variant="ghost"
            className="text-neutral-500"
            onClick={() => setSelectedIds(new Set())}
          >
            <X className="w-3.5 h-3.5" />
            Clear
          </Button>
        </div>
      ) : null}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
        </div>
      ) : contracts.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <FileCode2 className="w-8 h-8 text-neutral-400" />
          </div>
          <p className="text-neutral-500 mb-4">No contracts registered</p>
          {canEdit && (
            <Button
              variant="outline"
              onClick={() => setShowForm(true)}
              className="gap-2"
            >
              <Plus className="w-4 h-4" />
              Register your first contract
            </Button>
          )}
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">
                <Checkbox
                  data-testid="contract-select-all"
                  checked={allSelected ? true : someSelected ? "indeterminate" : false}
                  onCheckedChange={toggleSelectAll}
                />
              </TableHead>
              <TableHead>Address</TableHead>
              <TableHead>Name</TableHead>
              <TableHead className="text-center w-16">ABI</TableHead>
              <TableHead className="text-center w-20">Groups</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {contracts.map((contract, index) => (
              <TableRow
                key={contract.id}
                className="animate-fade-in"
                style={{ animationDelay: `${index * 30}ms` }}
              >
                <TableCell>
                  <Checkbox
                    checked={selectedIds.has(contract.id)}
                    onCheckedChange={() => toggleSelect(contract.id)}
                  />
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <FileCode2 className="w-4 h-4 text-primary" />
                    <span
                      className="font-mono text-sm"
                      title={getContractAddress(contract)}
                    >
                      {truncateAddress(getContractAddress(contract))}
                    </span>
                    <button
                      onClick={() => copyToClipboard(getContractAddress(contract), contract.id)}
                      className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors"
                      title="Copy address"
                    >
                      {copiedId === contract.id ? (
                        <Check className="w-3.5 h-3.5 text-success" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className="text-sm">{contract.name || '-'}</span>
                    {contract.allow_visibleto_unlock && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Eye className="w-4 h-4 text-amber-500 cursor-help" data-testid="visibleto-unlock-badge" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>visibleTo bypass enabled</p>
                        </TooltipContent>
                      </Tooltip>
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-center">
                  {contract.abi ? (
                    <span title="ABI loaded">
                      <Check className="w-4 h-4 text-success mx-auto" />
                    </span>
                  ) : (
                    <span className="text-neutral-400" title="No ABI">-</span>
                  )}
                </TableCell>
                <TableCell className="text-center">
                  {(() => {
                    const summary = grantSummary[contract.id];
                    const groupCount = summary?.count ?? 0;
                    const groupNames = summary?.groups?.map(g => g.name).join(', ') ?? '';
                    return (
                      <span
                        className={`inline-flex items-center justify-center rounded-full px-2 py-0.5 text-xs font-medium cursor-default ${
                          groupCount > 0
                            ? 'bg-primary-50 text-primary-700'
                            : 'bg-neutral-100 text-neutral-400'
                        }`}
                        title={groupCount > 0 ? groupNames : 'No groups assigned'}
                      >
                        {groupCount}
                      </span>
                    );
                  })()}
                </TableCell>
                <TableCell>
                  <div className="flex flex-col gap-0.5">
                    <span className="text-sm text-neutral-500">
                      {formatDate(contract.created_at)}
                    </span>
                    {(() => {
                      const raw = contract.metadata?.deploy_block;
                      if (typeof raw !== 'string' || !raw) return null;
                      const blockNum = raw.startsWith('0x') ? parseInt(raw, 16) : Number(raw);
                      return (
                        <span className="text-xs text-neutral-400 font-mono">
                          block {isNaN(blockNum) ? raw : blockNum.toLocaleString()}
                        </span>
                      );
                    })()}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setManagingGrants(contract)}
                      title={canEdit ? "Manage permissions" : "View permissions"}
                      className="text-primary hover:text-primary-600 hover:bg-primary-50"
                    >
                      <Shield className="w-4 h-4" />
                    </Button>
                    {canEdit && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setEditing(contract)}
                          title="Edit contract"
                        >
                          <Pencil className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(contract)}
                          className="text-error-dark hover:text-error-dark hover:bg-error-light"
                          title="Delete contract"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onPageChange={(newOffset) => loadContracts(newOffset)} />

      {/* Create Contract Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Register Contract</DialogTitle>
          </DialogHeader>
          <ContractForm
            orgId={orgId}
            onClose={() => setShowForm(false)}
            onSave={handleSave}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Contract Dialog */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Contract</DialogTitle>
          </DialogHeader>
          {editing && (
            <ContractForm
              key={editing.id}
              orgId={orgId}
              contract={editing}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => !open && setDeleteTarget(null)}
        title="Delete Contract"
        description={`Are you sure you want to delete "${deleteTarget ? (deleteTarget.name || getContractAddress(deleteTarget)) : ''}"? This cannot be undone.`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        onConfirm={handleDeleteConfirm}
        variant="destructive"
      />

      {/* Delete Error Alert */}
      <AlertDialog
        open={deleteError !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteError(null);
        }}
        title="Delete Failed"
        description={deleteError ?? ''}
        buttonLabel="OK"
        variant="error"
      />

      {/* Sync Error Alert */}
      <AlertDialog
        open={!!syncError}
        onOpenChange={() => setSyncError(null)}
        title="Sync Error"
        description={syncError || ''}
        buttonLabel="OK"
        variant="error"
      />

      {/* Grants Manager Dialog */}
      <Dialog open={!!managingGrants} onOpenChange={open => !open && setManagingGrants(null)}>
        <DialogContent className="max-w-5xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Contract Permissions</DialogTitle>
          </DialogHeader>
          {managingGrants && (
            <ContractGrantsManager
              key={managingGrants.id}
              orgId={orgId}
              managed={managed || executionManaged}
              readOnly={!canEdit || !executionChecked}
              contract={managingGrants}
              onContractUpdated={updated => {
                // RD-1075: reflect the saved visibleTo-unlock flag without a full
                // refetch — merge it into the cached list entry (drives the badge)
                // and the open dialog's source contract.
                setContracts(prev =>
                  prev.map(c =>
                    c.id === updated.id
                      ? { ...c, allow_visibleto_unlock: updated.allow_visibleto_unlock }
                      : c,
                  ),
                );
                setManagingGrants(prev =>
                  prev && prev.id === updated.id
                    ? { ...prev, allow_visibleto_unlock: updated.allow_visibleto_unlock }
                    : prev,
                );
              }}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Move to Group Dialog */}
      <MoveToGroupDialog
        open={showMoveDialog}
        onOpenChange={setShowMoveDialog}
        orgId={orgId}
        selectedContractIds={Array.from(selectedIds)}
        onSuccess={() => {
          setSelectedIds(new Set());
          loadContracts();
        }}
      />

      {/* Sync Results Dialog */}
      <Dialog open={showSyncDialog} onOpenChange={setShowSyncDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Sync with Chain Results</DialogTitle>
          </DialogHeader>
          {syncResult && (
            <div className="space-y-4">
              {/* Summary */}
              <div className="grid grid-cols-3 gap-4 text-center">
                <div className="p-3 rounded-lg bg-success-light">
                  <div className="text-2xl font-semibold text-success-dark">
                    {syncResult.existing?.length ?? 0}
                  </div>
                  <div className="text-xs text-success-dark">On Chain</div>
                </div>
                <div className="p-3 rounded-lg bg-amber-100">
                  <div className="text-2xl font-semibold text-amber-800">
                    {syncResult.missing?.length ?? 0}
                  </div>
                  <div className="text-xs text-amber-800">Missing</div>
                </div>
                <div className="p-3 rounded-lg bg-error-light">
                  <div className="text-2xl font-semibold text-error-dark">
                    {syncResult.errors?.length ?? 0}
                  </div>
                  <div className="text-xs text-error-dark">Errors</div>
                </div>
              </div>

              {/* All synced message */}
              {!syncResult.missing?.length && !syncResult.errors?.length && (
                <div className="p-4 rounded-lg bg-success-light text-success-dark text-center">
                  <Check className="w-6 h-6 mx-auto mb-2" />
                  <p className="font-medium">All contracts exist on chain!</p>
                </div>
              )}

              {/* Missing contracts list */}
              {(syncResult.missing?.length ?? 0) > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-amber-800">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="font-medium text-sm">
                      Contracts not found on chain:
                    </span>
                  </div>
                  <div className="max-h-40 overflow-y-auto border rounded-lg divide-y">
                    {(syncResult.missing ?? []).map((contract: ContractSyncStatus) => (
                      <div
                        key={contract.id}
                        className="px-3 py-2 flex items-center justify-between text-sm"
                      >
                        <span className="font-mono text-xs">
                          {truncateAddress(contract.address)}
                        </span>
                        <span className="text-neutral-500">
                          {contract.name || 'Unnamed'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Errors list */}
              {(syncResult.errors?.length ?? 0) > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-error-dark">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="font-medium text-sm">
                      Chain unavailable for these contracts (not deleted):
                    </span>
                  </div>
                  <div className="max-h-40 overflow-y-auto border rounded-lg divide-y">
                    {(syncResult.errors ?? []).map((contract: ContractSyncStatus) => (
                      <div
                        key={contract.id}
                        className="px-3 py-2 text-sm"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs">
                            {truncateAddress(contract.address)}
                          </span>
                          <span className="text-neutral-500">
                            {contract.name || 'Unnamed'}
                          </span>
                        </div>
                        {contract.error && (
                          <div className="text-xs text-error-dark mt-1">
                            {contract.error}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Action buttons */}
              <div className="flex justify-end gap-2 pt-2">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowSyncDialog(false);
                    setSyncResult(null);
                  }}
                >
                  Close
                </Button>
                {(syncResult.missing?.length ?? 0) > 0 && (
                  <Button
                    variant="destructive"
                    onClick={handleDeleteStale}
                    disabled={deletingStale}
                    className="gap-2"
                  >
                    {deletingStale ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Deleting...
                      </>
                    ) : (
                      <>
                        <Trash2 className="w-4 h-4" />
                        Delete {syncResult.missing?.length ?? 0} Missing Contract
                        {(syncResult.missing?.length ?? 0) > 1 ? 's' : ''}
                      </>
                    )}
                  </Button>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
