import { useEffect, useState } from 'react';
import type { AllowedAzureTenant, Organization, Group } from '@/types/rbac';
import { rbacApi } from '@/api/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ConfirmDialog, AlertDialog } from '@/components/ui/ConfirmDialog';
import {
  Shield,
  Plus,
  Pencil,
  Trash2,
  Loader2,
  AlertCircle,
  Save,
  X,
} from 'lucide-react';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { useManagedStream } from '@/hooks/useManagedStream';
import ManagedStreamNotice from './ManagedStreamNotice';
import { extractApiError } from '@/lib/executionPolicy';

export default function AzureTenantList() {
  const { isReadonlyAdmin } = useAdmin();
  // Tenants belong to the platform document once one is active.
  const { managed, checked } = useManagedStream('platform');
  const canEdit = !isReadonlyAdmin && checked && !managed;
  const [tenants, setTenants] = useState<AllowedAzureTenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<AllowedAzureTenant | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AllowedAzureTenant | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  useEffect(() => {
    loadTenants();
  }, []);

  const loadTenants = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.azureTenants.list();
      setTenants(response.data?.data || []);
    } catch (error) {
      console.error('Failed to load Azure tenants:', error);
      setTenants([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setShowForm(false);
    setEditing(null);
    await loadTenants();
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    try {
      await rbacApi.azureTenants.delete(deleteTarget.id);
      setDeleteTarget(null);
      await loadTenants();
    } catch (error) {
      console.error('Failed to delete Azure tenant:', error);
      setDeleteTarget(null);
      setDeleteError(extractApiError(error, 'Failed to remove Azure AD tenant. Please try again.').message);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-neutral-700">Azure AD Tenants</h3>
          <p className="text-xs text-neutral-500 mt-0.5">
            Control which Azure AD tenants can authenticate
          </p>
        </div>
        {canEdit && (
          <Button onClick={() => setShowForm(true)} size="sm" className="gap-2">
            <Plus className="w-4 h-4" />
            Add Tenant
          </Button>
        )}
      </div>

      {managed && <ManagedStreamNotice subject="Azure AD tenants" to="/admin/rbac/platform-configuration" />}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
        </div>
      ) : tenants.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <Shield className="w-8 h-8 text-neutral-400" />
          </div>
          <p className="text-neutral-500 mb-2">No Azure AD tenants allowed</p>
          <p className="text-neutral-400 text-xs mb-4">
            Azure AD authentication will be blocked until you add at least one tenant.
          </p>
          {canEdit && (
            <Button
              variant="outline"
              onClick={() => setShowForm(true)}
              className="gap-2"
            >
              <Plus className="w-4 h-4" />
              Allow your first tenant
            </Button>
          )}
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Label</TableHead>
              <TableHead>Tenant ID</TableHead>
              <TableHead>Auto-provision</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tenants.map((tenant, index) => (
              <TableRow
                key={tenant.id}
                className="animate-fade-in"
                style={{ animationDelay: `${index * 30}ms` }}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-primary" />
                    <span className="font-medium">{tenant.label || '(no label)'}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="font-mono text-xs">
                    {tenant.tenant_id}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={tenant.auto_provision ? 'default' : 'outline'}>
                    {tenant.auto_provision ? 'Yes' : 'No'}
                  </Badge>
                </TableCell>
                <TableCell className="text-neutral-500 text-sm">
                  {formatDate(tenant.created_at)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    {canEdit && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setEditing(tenant)}
                          title="Edit tenant"
                        >
                          <Pencil className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(tenant)}
                          className="text-error-dark hover:text-error-dark hover:bg-error-light"
                          title="Delete tenant"
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

      {/* Create Tenant Dialog */}
      <Dialog open={showForm} onOpenChange={setShowForm}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Add Azure AD Tenant</DialogTitle>
          </DialogHeader>
          <AzureTenantForm
            onClose={() => setShowForm(false)}
            onSave={handleSave}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Tenant Dialog */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Azure AD Tenant</DialogTitle>
          </DialogHeader>
          {editing && (
            <AzureTenantForm
              key={editing.id}
              tenant={editing}
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
        title="Remove Azure AD Tenant"
        description={`Are you sure you want to remove "${deleteTarget?.label || deleteTarget?.tenant_id}"? Users from this tenant will no longer be able to authenticate.`}
        confirmLabel="Remove"
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
        title="Remove Failed"
        description={deleteError ?? ''}
        buttonLabel="OK"
        variant="error"
      />
    </div>
  );
}

// --- Inline Form Component ---

interface AzureTenantFormProps {
  tenant?: AllowedAzureTenant;
  onClose: () => void;
  onSave: () => void;
}

const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';
const DEFAULT_GROUP_ID = '00000000-0000-0000-0000-000000000001';

function AzureTenantForm({ tenant, onClose, onSave }: AzureTenantFormProps) {
  const [tenantId, setTenantId] = useState(tenant?.tenant_id || '');
  const [label, setLabel] = useState(tenant?.label || '');
  const [defaultOrgId, setDefaultOrgId] = useState(tenant?.default_org_id || DEFAULT_ORG_ID);
  const [defaultGroupId, setDefaultGroupId] = useState(tenant?.default_group_id || DEFAULT_GROUP_ID);
  const [autoProvision, setAutoProvision] = useState(tenant?.auto_provision ?? true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load orgs and groups for dropdowns
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);

  useEffect(() => {
    const loadOrgs = async () => {
      try {
        const response = await rbacApi.orgs.list({ limit: 1000 });
        setOrganizations(response.data?.data || []);
      } catch {
        // Ignore - dropdowns will be empty
      }
    };
    loadOrgs();
  }, []);

  // Load groups when org changes
  useEffect(() => {
    if (!defaultOrgId) {
      setGroups([]);
      return;
    }
    const loadGroups = async () => {
      try {
        const response = await rbacApi.groups.list(defaultOrgId, { limit: 1000 });
        const groupData = (response.data?.data || []).map((gwa: { group: Group }) => gwa.group);
        setGroups(groupData);
      } catch {
        setGroups([]);
      }
    };
    loadGroups();
  }, [defaultOrgId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      const payload = {
        tenant_id: tenantId,
        label,
        default_org_id: defaultOrgId || null,
        default_group_id: defaultGroupId || null,
        auto_provision: autoProvision,
      };

      if (tenant) {
        await rbacApi.azureTenants.update(tenant.id, payload);
      } else {
        await rbacApi.azureTenants.create(payload);
      }
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save Azure tenant:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save tenant. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label htmlFor="tenant-id" className="block text-sm font-medium text-neutral-700">
          Tenant ID
        </label>
        <Input
          id="tenant-id"
          type="text"
          value={tenantId}
          onChange={e => setTenantId(e.target.value)}
          placeholder="e.g., aaaabbbb-cccc-dddd-eeee-ffffffffffff"
          required
        />
        <p className="text-xs text-neutral-400">
          The Azure AD / Microsoft Entra ID tenant identifier (UUID)
        </p>
      </div>

      <div className="space-y-2">
        <label htmlFor="tenant-label" className="block text-sm font-medium text-neutral-700">
          Label
        </label>
        <Input
          id="tenant-label"
          type="text"
          value={label}
          onChange={e => setLabel(e.target.value)}
          placeholder="e.g., Contoso Corp"
        />
        <p className="text-xs text-neutral-400">Human-friendly name for this tenant</p>
      </div>

      <div className="space-y-2">
        <label htmlFor="default-org" className="block text-sm font-medium text-neutral-700">
          Default Organization
        </label>
        <Select value={defaultOrgId} onValueChange={v => {
          setDefaultOrgId(v);
          setDefaultGroupId(v === DEFAULT_ORG_ID ? DEFAULT_GROUP_ID : '');
        }}>
          <SelectTrigger id="default-org">
            <SelectValue placeholder="Select organization" />
          </SelectTrigger>
          <SelectContent>
            {organizations.map(org => (
              <SelectItem key={org.id} value={org.id}>{org.name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-neutral-400">
          New users from this tenant will be placed in this organization
        </p>
      </div>

      {defaultOrgId && (
        <div className="space-y-2">
          <label htmlFor="default-group" className="block text-sm font-medium text-neutral-700">
            Default Group
          </label>
          <Select value={defaultGroupId} onValueChange={v => setDefaultGroupId(v)}>
            <SelectTrigger id="default-group">
              <SelectValue placeholder="Select group" />
            </SelectTrigger>
            <SelectContent>
              {groups.map(g => (
                <SelectItem key={g.id} value={g.id}>{g.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-xs text-neutral-400">
            New users from this tenant will be added to this group
          </p>
        </div>
      )}

      <div className="space-y-2">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={autoProvision}
            onChange={e => setAutoProvision(e.target.checked)}
            className="rounded border-neutral-300 text-primary focus:ring-primary"
          />
          <span className="text-sm font-medium text-neutral-700">Auto-provision users</span>
        </label>
        <p className="text-xs text-neutral-400 ml-6">
          When enabled, new users from this tenant are automatically created on first login.
          When disabled, only pre-existing users can log in.
        </p>
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <Button
          type="button"
          variant="ghost"
          onClick={onClose}
          disabled={saving}
          className="gap-2"
        >
          <X className="w-4 h-4" />
          Cancel
        </Button>
        <Button type="submit" disabled={saving} className="gap-2">
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              {tenant ? 'Update' : 'Add'} Tenant
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
