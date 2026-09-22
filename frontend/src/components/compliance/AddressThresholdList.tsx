import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import Pagination from '@/components/ui/Pagination';
import { Loader2, Plus, AlertCircle, MapPin, Trash2, Pencil, Copy, Check } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import { useCurrency } from './CurrencyContext';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { useManagedStream } from '@/hooks/useManagedStream';
import ManagedStreamNotice from '@/components/rbac/ManagedStreamNotice';
import type { AddressThresholdOverride } from '@/types/compliance';

const PAGE_SIZE = 25;

export default function AddressThresholdList() {
  const { selectedOrg } = useComplianceOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const { formatAmount, currencyLabel } = useCurrency();
  const orgId = selectedOrg?.id;
  // Address thresholds belong to the compliance document once one is active.
  const { managed, checked } = useManagedStream('compliance', orgId);
  const canEdit = !isReadonlyAdmin && checked && !managed;

  const [overrides, setOverrides] = useState<AddressThresholdOverride[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<AddressThresholdOverride | null>(null);

  // Form state
  const [formAddress, setFormAddress] = useState('');
  const [formThreshold, setFormThreshold] = useState('');
  const [formNote, setFormNote] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const loadOverrides = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.addressThresholds.list(orgId, {
        limit: PAGE_SIZE,
        offset: newOffset,
      });
      const page = response.data;
      setOverrides(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setOverrides([]);
        setTotal(0);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load address thresholds');
      }
    } finally {
      setLoading(false);
    }
  };

  // reason: intentional reload-on-orgId. loadOverrides is a non-memoised helper
  // that reads current state via closure; re-running only when orgId changes is
  // the desired behaviour. Adding it to deps would require useCallback and risk
  // a refetch loop.
  useEffect(() => {
    if (orgId) loadOverrides(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  const openCreateForm = () => {
    setFormAddress('');
    setFormThreshold('0');
    setFormNote('');
    setFormError(null);
    setEditMode(false);
    setShowForm(true);
  };

  const openEditForm = (override: AddressThresholdOverride) => {
    setFormAddress(override.address);
    setFormThreshold(String(override.threshold_fiat));
    setFormNote(override.note || '');
    setFormError(null);
    setEditMode(true);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;

    const address = formAddress.trim().toLowerCase();
    if (!/^0x[0-9a-f]{40}$/i.test(address)) {
      setFormError('Invalid address format (must be 0x + 40 hex chars)');
      return;
    }

    const threshold = parseFloat(formThreshold);
    if (isNaN(threshold) || threshold < 0) {
      setFormError('Threshold must be >= 0');
      return;
    }

    try {
      setFormSaving(true);
      setFormError(null);
      await complianceApi.addressThresholds.upsert(orgId, address, {
        threshold_fiat: threshold,
        note: formNote.trim() || undefined,
      });
      setShowForm(false);
      loadOverrides(editMode ? offset : 0);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to save threshold override');
    } finally {
      setFormSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!orgId || !deleteTarget) return;
    try {
      await complianceApi.addressThresholds.delete(orgId, deleteTarget.address);
      setDeleteTarget(null);
      loadOverrides();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to delete threshold override');
      setDeleteTarget(null);
    }
  };

  if (!orgId) return null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-neutral-500">
            Per-address threshold overrides. When set, the address-specific threshold takes precedence
            over the org-level threshold. Use {formatAmount(0)} to require travel rule data for every transfer involving this address.
          </p>
        </div>
        {canEdit && (
          <Button onClick={openCreateForm} size="sm" className="gap-2 shrink-0">
            <Plus className="w-4 h-4" />
            Add Override
          </Button>
        )}
      </div>

      {managed && <ManagedStreamNotice subject="Address thresholds" />}

      {error && (
        <div className="p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-8">
          <Loader2 className="w-6 h-6 animate-spin text-neutral-500" />
        </div>
      ) : overrides.length === 0 ? (
        <div className="text-center py-8">
          <MapPin className="w-8 h-8 mx-auto mb-2 text-neutral-400" />
          <p className="text-neutral-500">No address threshold overrides</p>
          <p className="text-neutral-400 text-sm mt-1">
            All addresses use the org-level threshold
          </p>
        </div>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Threshold ({currencyLabel})</TableHead>
                <TableHead>Note</TableHead>
                <TableHead>Updated</TableHead>
                {canEdit && <TableHead className="w-[80px]"></TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {overrides.map((o) => (
                <TableRow key={o.id}>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <span className="font-mono text-xs">{o.address}</span>
                      <button
                        onClick={() => copyToClipboard(o.address, o.id)}
                        className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors"
                        title="Copy address"
                      >
                        {copiedId === o.id ? (
                          <Check className="w-3.5 h-3.5 text-success" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </TableCell>
                  <TableCell>
                    {o.threshold_fiat === 0 ? (
                      <span className="text-red-600 font-medium">{formatAmount(0)} (all transfers)</span>
                    ) : (
                      <span>{formatAmount(o.threshold_fiat)}</span>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-neutral-500 max-w-[200px] truncate">
                    {o.note || '-'}
                  </TableCell>
                  <TableCell className="text-xs text-neutral-500">
                    {new Date(o.updated_at).toLocaleDateString()}
                  </TableCell>
                  {canEdit && (
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEditForm(o)}
                          className="h-7 w-7 p-0"
                        >
                          <Pencil className="w-3.5 h-3.5 text-neutral-500" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(o)}
                          className="h-7 w-7 p-0 text-red-600 hover:text-error-dark"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {total > PAGE_SIZE && (
            <Pagination
              total={total}
              limit={PAGE_SIZE}
              offset={offset}
              onPageChange={loadOverrides}
            />
          )}
        </>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{editMode ? 'Edit' : 'Add'} Address Threshold Override</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1">
                Address
              </label>
              <Input
                value={formAddress}
                onChange={(e) => setFormAddress(e.target.value)}
                placeholder="0x..."
                disabled={editMode}
                className="font-mono text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1">
                Threshold ({currencyLabel})
              </label>
              <Input
                type="number"
                value={formThreshold}
                onChange={(e) => setFormThreshold(e.target.value)}
                placeholder="0"
                min="0"
                step="0.01"
              />
              <p className="text-xs text-neutral-500 mt-1">
                Set to {formatAmount(0)} to require travel rule data for every transfer involving this address.
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1">
                Note (optional)
              </label>
              <Input
                value={formNote}
                onChange={(e) => setFormNote(e.target.value)}
                placeholder="e.g., High-risk counterparty"
              />
            </div>
            {formError && (
              <p className="text-sm text-red-600">{formError}</p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                {editMode ? 'Save' : 'Add Override'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="Delete Threshold Override"
        description={`Remove the threshold override for ${deleteTarget?.address}? This address will revert to the org-level threshold.`}
        onConfirm={handleDelete}
        confirmLabel="Delete"
        variant="destructive"
      />
    </div>
  );
}
