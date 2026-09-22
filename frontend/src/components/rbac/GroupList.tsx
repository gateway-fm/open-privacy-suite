import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group, GroupWithAccess } from '@/types/rbac';
import GroupForm from './GroupForm';
import GroupAccessForm from './GroupAccessForm';
import BatchDeleteConfirmDialog from './BatchDeleteConfirmDialog';
import { useOrgContext } from './RBACManager';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog, AlertDialog } from '@/components/ui/ConfirmDialog';
import Pagination from '@/components/ui/Pagination';
import { Input } from '@/components/ui/input';
import {
  Users,
  Plus,
  Pencil,
  Trash2,
  Settings,
  Loader2,
  ChevronRight,
  Shield,
  Eye,
  X,
  Search,
} from 'lucide-react';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { useManagedStream } from '@/hooks/useManagedStream';
import ManagedStreamNotice from './ManagedStreamNotice';
import { extractApiError } from '@/lib/executionPolicy';

const PAGE_SIZE = 50;

export default function GroupList() {
  const { selectedOrg } = useOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const orgId = selectedOrg?.id || '';
  // A reviewed groups document, once active, owns this stream: the server
  // refuses direct edits, so the screen does not offer them.
  const { managed, checked } = useManagedStream('groups', orgId);
  const canEdit = !isReadonlyAdmin && checked && !managed;
  const [groups, setGroups] = useState<GroupWithAccess[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Group | null>(null);
  const [editingAccess, setEditingAccess] = useState<Group | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Group | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Multi-select for batch delete
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showBatchDelete, setShowBatchDelete] = useState(false);

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === groups.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(groups.map(g => g.group.id)));
    }
  };

  // reason: intentional reload when orgId/search change. loadGroups is a
  // non-memoised helper that reads current state via closure; adding it to deps
  // would require useCallback and risk a refetch loop.
  useEffect(() => {
    if (orgId) {
      loadGroups(0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, debouncedSearch]);

  const loadGroups = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      const params: { limit: number; offset: number; search?: string } = {
        limit: PAGE_SIZE,
        offset: newOffset,
      };
      if (debouncedSearch) params.search = debouncedSearch;
      const response = await rbacApi.groups.list(orgId, params);
      const page = response.data;
      const groupsList = page.data || [];
      // Sort alphabetically by name
      groupsList.sort((a: GroupWithAccess, b: GroupWithAccess) => a.group.name.localeCompare(b.group.name));
      setGroups(groupsList);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (error) {
      console.error('Failed to load groups:', error);
      setGroups([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;

    try {
      await rbacApi.groups.delete(orgId, deleteTarget.id);
      setDeleteTarget(null);
      await loadGroups();
    } catch (error) {
      console.error('Failed to delete group:', error);
      setDeleteTarget(null);
      // Show the server's own reason. A managed stream says so; the old fixed
      // text sent administrators looking for members that did not exist.
      setDeleteError(extractApiError(error, 'Failed to delete group. It may have members that need to be removed first.').message);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadGroups();
  };

  const handleAccessSave = async () => {
    setEditingAccess(null);
    await loadGroups();
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-neutral-700">Groups</h3>
          <p className="text-xs text-neutral-500 mt-0.5">
            Groups define what methods and addresses users can access
          </p>
        </div>
        {canEdit && (
          <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
            <Plus className="w-4 h-4" />
            Add Group
          </Button>
        )}
      </div>

      {managed && <ManagedStreamNotice subject="Groups" />}

      {/* Search + Filter bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" />
          <Input
            type="text"
            placeholder="Search by name or slug..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
        {searchQuery && (
          <Button variant="ghost" size="sm" onClick={() => setSearchQuery('')} className="text-neutral-500">
            Clear
          </Button>
        )}
      </div>

      {/* Selection toolbar */}
      {selectedIds.size > 0 && (
        <div data-testid="selection-toolbar" className="flex items-center gap-3 px-4 py-2 bg-error-light rounded-lg border border-error/20">
          <span className="text-sm font-medium text-error-dark">
            {selectedIds.size} selected
          </span>
          {canEdit && (
            <Button
              data-testid="batch-delete-btn"
              size="sm"
              variant="destructive"
              className="gap-1.5"
              onClick={() => setShowBatchDelete(true)}
            >
              <Trash2 className="w-3.5 h-3.5" />
              Delete Selected
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
      )}

      {/* Select all header */}
      {!loading && groups.length > 0 && (
        <div className="flex items-center gap-3 px-3 py-2 border-b border-neutral-200">
          <Checkbox
            data-testid="group-select-all"
            checked={selectedIds.size > 0 && selectedIds.size < groups.length ? "indeterminate" : selectedIds.size === groups.length}
            onCheckedChange={toggleSelectAll}
          />
          <span className="text-xs text-neutral-500">
            {selectedIds.size === 0 ? 'Select all' : `${selectedIds.size} of ${groups.length} selected`}
          </span>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
        </div>
      ) : groups.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <Users className="w-8 h-8 text-neutral-400" />
          </div>
          <>
            <p className="text-neutral-500 mb-4">No groups found</p>
            {canEdit && (
              <Button
                variant="outline"
                onClick={() => setShowForm(true)}
                className="gap-2"
              >
                <Plus className="w-4 h-4" />
                Create your first group
              </Button>
            )}
          </>
        </div>
      ) : (
        <div className="space-y-2">
          {groups.map(gwa => {
            const hasMethods =
              gwa.access &&
              (gwa.access.allowed_methods?.length || 0) > 0;

            return (
              <div key={gwa.group.id} data-testid="group-card" className="animate-fade-in">
                <div
                  className={`flex items-center gap-3 p-3 rounded-lg bg-neutral-100 hover:bg-primary-50 transition-colors ${
                    selectedIds.has(gwa.group.id) ? 'ring-2 ring-primary/30' : ''
                  }`}
                >
                  <Checkbox
                    checked={selectedIds.has(gwa.group.id)}
                    onCheckedChange={() => toggleSelect(gwa.group.id)}
                    className="flex-shrink-0"
                  />
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    <Users className="w-5 h-5 text-primary flex-shrink-0" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium truncate text-neutral-900">{gwa.group.name}</span>
                        <Badge variant="outline" className="font-mono text-xs flex-shrink-0">
                          {gwa.group.slug}
                        </Badge>
                        {gwa.group.is_org_admin && (
                          <Badge className="bg-warning-light text-warning-dark border-warning/40 gap-1 flex-shrink-0">
                            <Shield className="w-3 h-3" />
                            Org Admin
                          </Badge>
                        )}
                        {gwa.group.is_org_readonly_admin && (
                          <Badge
                            variant="outline"
                            className="bg-neutral-50 text-neutral-700 border-neutral-300 gap-1 flex-shrink-0"
                          >
                            <Eye className="w-3 h-3" />
                            Read-only Admin
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-1 text-xs text-neutral-400 mt-0.5">
                        {hasMethods && (
                          <>
                            <ChevronRight className="w-3 h-3" />
                            <span>
                              {gwa.access?.allowed_methods?.length || 0} methods
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-1 flex-shrink-0">
                    {canEdit && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setEditingAccess(gwa.group)}
                          title="Edit access settings"
                        >
                          <Settings className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setEditing(gwa.group)}
                          title="Edit group"
                        >
                          <Pencil className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(gwa.group)}
                          className="text-error-dark hover:text-error-dark hover:bg-error-light"
                          title="Delete group"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onPageChange={(newOffset) => loadGroups(newOffset)} />

      {/* Create Group Dialog */}
      <Dialog
        open={showForm}
        onOpenChange={open => {
          setShowForm(open);
        }}
      >
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create Group</DialogTitle>
          </DialogHeader>
          <GroupForm
            orgId={orgId}
            groups={groups.map(g => g.group)}
            onClose={() => {
              setShowForm(false);
            }}
            onSave={handleSave}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Group Dialog */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Group</DialogTitle>
          </DialogHeader>
          {editing && (
            <GroupForm
              key={editing.id}
              orgId={orgId}
              groups={groups.map(g => g.group)}
              group={editing}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Edit Access Dialog */}
      <Dialog
        open={!!editingAccess}
        onOpenChange={open => !open && setEditingAccess(null)}
      >
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              Edit Access for "{editingAccess?.name}"
            </DialogTitle>
          </DialogHeader>
          {editingAccess && (
            <GroupAccessForm
              orgId={orgId}
              groupId={editingAccess.id}
              isOrgAdmin={editingAccess.is_org_admin}
              onClose={() => setEditingAccess(null)}
              onSave={handleAccessSave}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => !open && setDeleteTarget(null)}
        title="Delete Group"
        description={`Are you sure you want to delete "${deleteTarget?.name}"?`}
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

      {/* Batch Delete Confirmation Dialog */}
      <BatchDeleteConfirmDialog
        open={showBatchDelete}
        onOpenChange={setShowBatchDelete}
        orgId={orgId}
        groupIds={Array.from(selectedIds)}
        onSuccess={() => {
          setSelectedIds(new Set());
          loadGroups();
        }}
      />
    </div>
  );
}
