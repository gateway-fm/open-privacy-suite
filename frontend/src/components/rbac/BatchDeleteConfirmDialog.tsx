import { useState, useEffect } from 'react';
import { rbacApi } from '@/api/rbac';
import { extractApiError } from '@/lib/executionPolicy';
import type { BatchDeletePreviewGroup } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Loader2, AlertTriangle, Trash2 } from 'lucide-react';

interface BatchDeleteConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  orgId: string;
  groupIds: string[];
  onSuccess: () => void;
}

export function BatchDeleteConfirmDialog({
  open,
  onOpenChange,
  orgId,
  groupIds,
  onSuccess,
}: BatchDeleteConfirmDialogProps) {
  const [preview, setPreview] = useState<BatchDeletePreviewGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    if (!open || groupIds.length === 0) {
      setPreview([]);
      setError(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    rbacApi.groups
      .batchDeletePreview(orgId, { group_ids: groupIds })
      .then((res) => {
        if (!cancelled) {
          setPreview(res.data.groups);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err?.message ?? 'Failed to load preview');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, orgId, groupIds]);

  const totalContracts = preview.reduce((sum, g) => sum + g.contract_count, 0);
  const totalMembers = preview.reduce((sum, g) => sum + g.member_count, 0);

  const handleConfirm = async () => {
    setDeleting(true);
    try {
      await rbacApi.groups.batchDelete(orgId, { group_ids: groupIds });
      onSuccess();
      onOpenChange(false);
    } catch (err: unknown) {
      setError(extractApiError(err, 'Failed to delete groups').message);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="batch-delete-dialog" aria-describedby="batch-delete-description">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Trash2 className="w-5 h-5 text-error-dark" />
            Delete {groupIds.length} {groupIds.length === 1 ? 'group' : 'groups'}
          </DialogTitle>
        </DialogHeader>

        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-error-dark/20 bg-error-light px-3 py-2 text-sm text-error-dark">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-neutral-400" />
          </div>
        ) : (
          !error && (
            <div className="space-y-4">
              <ul className="space-y-2 max-h-60 overflow-y-auto">
                {preview.map((group) => (
                  <li
                    key={group.id}
                    className="flex items-center justify-between rounded-lg border border-neutral-200 px-3 py-2"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-sm font-medium text-neutral-900 truncate">
                        {group.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-neutral-500 shrink-0">
                      <span>{group.contract_count} {group.contract_count === 1 ? 'contract' : 'contracts'}</span>
                      <span>{group.member_count} {group.member_count === 1 ? 'member' : 'members'}</span>
                    </div>
                  </li>
                ))}
              </ul>

              {totalContracts > 0 && (
                <p id="batch-delete-description" className="text-sm text-neutral-600">
                  This will remove access for {totalContracts}{' '}
                  {totalContracts === 1 ? 'contract' : 'contracts'}.
                  Contracts will remain registered but will need new group
                  assignments.
                </p>
              )}

              {totalMembers > 0 && (
                <p className="text-sm text-neutral-500">
                  {totalMembers} {totalMembers === 1 ? 'member' : 'members'} will
                  lose their group assignments.
                </p>
              )}
            </div>
          )
        )}

        <DialogFooter>
          <Button
            data-testid="batch-delete-cancel-btn"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={deleting}
          >
            Cancel
          </Button>
          <Button
            data-testid="batch-delete-confirm-btn"
            variant="destructive"
            onClick={handleConfirm}
            disabled={loading || deleting || !!error}
          >
            {deleting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Deleting...
              </>
            ) : (
              <>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete {groupIds.length} {groupIds.length === 1 ? 'group' : 'groups'}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default BatchDeleteConfirmDialog;
