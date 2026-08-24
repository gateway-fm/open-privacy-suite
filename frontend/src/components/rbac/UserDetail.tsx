import { useEffect, useMemo, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { User, MembershipWithDetails, EffectivePermissions } from '@/types/rbac';
import { useOrgContext } from './RBACManager';
import { getClosestPresetLabel } from '@/types/rbac';
import MembershipForm from './MembershipForm';
import { ViewAsInExplorerButton } from './ViewAsInExplorerButton';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { AddressDisplay } from '@/components/ui/AddressDisplay';
import { useEnsNames } from '@/hooks/useEnsNames';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ConfirmDialog, AlertDialog } from '@/components/ui/ConfirmDialog';
import {
  Check,
  X,
  Loader2,
  Plus,
  Trash2,
  FolderTree,
  Save,
  AlertCircle,
  Wallet,
  Clock,
} from 'lucide-react';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { useAuthOptional } from '@/contexts/AuthContext';

// Ties the self-ban explanation to the Banned checkbox via aria-describedby
// (RD-1238). Only one UserDetail renders at a time, so a constant id is safe.
const SELF_BAN_HELP_ID = 'user-detail-self-ban-help';

interface UserDetailProps {
  user: User;
  onUpdate: () => void;
}

interface LinkedAddress {
  address: string;
  verified_at: string;
  ens_name?: string;
  ens_resolved_at?: string;
}

export default function UserDetail({ user, onUpdate }: UserDetailProps) {
  const { organizations } = useOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  // RD-1238: banning yourself is rejected by the backend (400) — it would end
  // your own session on the spot. Disable the Banned toggle on your own record
  // so the form can't be armed into a save that must fail. Compares lowercase
  // (DID casing isn't semantic) and stays false when the identity is unknown,
  // so an absent AuthProvider disables nothing. Presentation only.
  const signedInDID = useAuthOptional()?.userDID ?? null;
  const isOwnRecord =
    signedInDID !== null && signedInDID.toLowerCase() === user.external_id.toLowerCase();
  const [memberships, setMemberships] = useState<MembershipWithDetails[]>([]);
  const [effectivePermsByOrg, setEffectivePermsByOrg] = useState<Record<string, EffectivePermissions>>({});
  const [loadingPerms, setLoadingPerms] = useState(false);
  const [linkedAddresses, setLinkedAddresses] = useState<LinkedAddress[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingAddresses, setLoadingAddresses] = useState(true);
  const [showMembershipForm, setShowMembershipForm] = useState(false);
  const [deleteMembershipTarget, setDeleteMembershipTarget] = useState<string | null>(null);
  const [showMembershipDeleteError, setShowMembershipDeleteError] = useState(false);

  // Group memberships by organization
  const membershipsByOrg = useMemo(() => {
    const grouped: Record<string, MembershipWithDetails[]> = {};
    for (const m of memberships) {
      const orgId = m.group?.org_id || 'unknown';
      if (!grouped[orgId]) {
        grouped[orgId] = [];
      }
      grouped[orgId].push(m);
    }
    return grouped;
  }, [memberships]);

  // Get unique org IDs from memberships
  const userOrgIds = useMemo(() => {
    return Object.keys(membershipsByOrg).filter(id => id !== 'unknown');
  }, [membershipsByOrg]);

  // Map org ID to org object for display
  const orgById = useMemo(() => {
    const map: Record<string, { name: string; slug: string }> = {};
    for (const org of organizations) {
      map[org.id] = { name: org.name, slug: org.slug };
    }
    return map;
  }, [organizations]);

  // Build cache of ENS names from API response
  const cachedEnsNames = useMemo(() => {
    const cache: Record<string, string | null> = {};
    for (const addr of linkedAddresses) {
      if (addr.ens_name !== undefined) {
        cache[addr.address.toLowerCase()] = addr.ens_name || null;
      }
    }
    return cache;
  }, [linkedAddresses]);

  // ENS name resolution for linked addresses (uses cache from API)
  const { data: ensNames, isLoading: loadingEns } = useEnsNames(
    linkedAddresses.map(a => a.address),
    { cachedNames: cachedEnsNames }
  );

  // Edit form state
  const [kyc, setKyc] = useState(user.kyc);
  const [banned, setBanned] = useState(user.banned);
  // Arming a ban on yourself is the blocked direction; an unban must stay
  // possible so a mistake is recoverable from this same screen.
  const selfBanBlocked = isOwnRecord && !banned;
  const [note, setNote] = useState(user.note || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasChanges, setHasChanges] = useState(false);

  // reason: intentional reload when the viewed user changes. loadMemberships /
  // loadLinkedAddresses are non-memoised helpers that read current state via
  // closure; adding them to deps would require useCallback and risk a refetch
  // loop.
  useEffect(() => {
    loadMemberships();
    loadLinkedAddresses();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user.id]);

  // Stable string key for the org-id set so the effect below re-runs only when
  // the actual membership set changes (extracted out of the dep array so eslint
  // can statically check it).
  const userOrgIdsKey = userOrgIds.join(',');

  // Load effective permissions for all orgs user is a member of
  // reason: intentional reload keyed on the membership set (userOrgIdsKey).
  // loadAllEffectivePermissions is a non-memoised helper that reads current
  // state via closure; adding it (or userOrgIds.length) to deps would require
  // useCallback and risk a refetch loop.
  useEffect(() => {
    if (userOrgIds.length > 0) {
      loadAllEffectivePermissions();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userOrgIdsKey]);

  useEffect(() => {
    setHasChanges(kyc !== user.kyc || banned !== user.banned || note !== (user.note || ''));
  }, [kyc, banned, note, user]);

  const loadMemberships = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.users.getMemberships(user.id);
      setMemberships(response.data || []);
    } catch (error) {
      console.error('Failed to load memberships:', error);
      setMemberships([]);
    } finally {
      setLoading(false);
    }
  };

  const loadLinkedAddresses = async () => {
    try {
      setLoadingAddresses(true);
      const response = await rbacApi.users.getLinkedAddresses(user.id);
      setLinkedAddresses(response.data.addresses || []);
    } catch (error) {
      console.error('Failed to load linked addresses:', error);
      setLinkedAddresses([]);
    } finally {
      setLoadingAddresses(false);
    }
  };

  const loadAllEffectivePermissions = async () => {
    if (userOrgIds.length === 0) return;

    setLoadingPerms(true);
    const permsMap: Record<string, EffectivePermissions> = {};

    try {
      // Load permissions for each org in parallel
      const results = await Promise.allSettled(
        userOrgIds.map(async (orgId) => {
          const org = orgById[orgId];
          if (!org) return null;
          const response = await rbacApi.users.getEffectivePermissions(user.id, org.slug);
          return { orgId, perms: response.data };
        })
      );

      for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
          permsMap[result.value.orgId] = result.value.perms;
        }
      }

      setEffectivePermsByOrg(permsMap);
    } catch (err) {
      console.error('Failed to load effective permissions:', err);
    } finally {
      setLoadingPerms(false);
    }
  };

  const handleDeleteMembershipConfirm = async () => {
    if (!deleteMembershipTarget) return;
    try {
      await rbacApi.users.deleteMembership(user.id, deleteMembershipTarget);
      setDeleteMembershipTarget(null);
      await loadMemberships();
      // Permissions will reload via useEffect when userOrgIds changes
      onUpdate();
    } catch (error) {
      console.error('Failed to delete membership:', error);
      setDeleteMembershipTarget(null);
      setShowMembershipDeleteError(true);
    }
  };

  const handleSaveUser = async () => {
    setSaving(true);
    setError(null);
    try {
      await rbacApi.users.update(user.id, { kyc, banned, note });
      onUpdate();
      setHasChanges(false);
    } catch (err: unknown) {
      console.error('Failed to update user:', err);
      const axiosError = err as {
        response?: { data?: { error?: string } };
      };
      setError(axiosError.response?.data?.error || 'Failed to update user.');
    } finally {
      setSaving(false);
    }
  };

  const handleMembershipSave = async () => {
    setShowMembershipForm(false);
    await loadMemberships();
    // Permissions will reload via useEffect when userOrgIds changes
    onUpdate();
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      {/* User Info */}
      <div className="p-4 rounded-lg bg-neutral-100 space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-medium text-neutral-700">User Information</h4>
          {/* RD-928: primary "View as" affordance. Tier-2 admins only —
              read-only admins (RD-866) don't see this. */}
          {!isReadonlyAdmin && (
            <ViewAsInExplorerButton
              targetDID={user.external_id}
              variant="inline"
            />
          )}
        </div>

        <div className="space-y-2">
          <label className="block text-xs text-neutral-500">External ID (DID)</label>
          <Input
            value={user.external_id}
            disabled
            className="font-mono text-sm bg-neutral-100"
          />
        </div>

        <div className="flex gap-6">
          <label className="flex items-center gap-3 cursor-pointer group">
            <div className="relative">
              <input
                type="checkbox"
                checked={kyc}
                onChange={e => setKyc(e.target.checked)}
                disabled={isReadonlyAdmin}
                className="peer sr-only"
              />
              <div className="w-5 h-5 rounded border border-neutral-300 bg-neutral-100 peer-checked:bg-green-500 peer-checked:border-green-500 transition-all flex items-center justify-center">
                {kyc && (
                  <Check className="w-3 h-3 text-white" />
                )}
              </div>
            </div>
            <span className="text-sm text-neutral-700 group-hover:text-neutral-900 transition-colors">
              KYC Verified
            </span>
          </label>

          <div className="space-y-1">
            <label
              className={
                selfBanBlocked
                  ? 'flex items-center gap-3 cursor-not-allowed group opacity-50'
                  : 'flex items-center gap-3 cursor-pointer group'
              }
            >
              <div className="relative">
                <input
                  type="checkbox"
                  checked={banned}
                  // RD-1238: never let an admin arm a ban on their own record.
                  // aria-disabled rather than `disabled` (mirroring the Ban
                  // button in UserList): a natively disabled control leaves the
                  // tab order, which would put the explanation out of reach of
                  // keyboard and screen-reader users. The handler below is the
                  // thing that makes it inert; the server gate is the real
                  // boundary either way.
                  onChange={e => {
                    if (selfBanBlocked) return;
                    setBanned(e.target.checked);
                  }}
                  disabled={isReadonlyAdmin}
                  aria-disabled={selfBanBlocked || undefined}
                  aria-describedby={selfBanBlocked ? SELF_BAN_HELP_ID : undefined}
                  className="peer sr-only"
                />
                <div className="w-5 h-5 rounded border border-neutral-300 bg-neutral-100 peer-checked:bg-red-500 peer-checked:border-red-500 transition-all flex items-center justify-center">
                  {banned && (
                    <X className="w-3 h-3 text-white" />
                  )}
                </div>
              </div>
              <span className="text-sm text-neutral-700 group-hover:text-neutral-900 transition-colors">
                Banned
              </span>
            </label>
            {selfBanBlocked && (
              // Visible, not a title tooltip: everyone gets the reason, and it
              // doubles as the checkbox's accessible description.
              <p id={SELF_BAN_HELP_ID} className="text-xs text-neutral-500">
                You cannot ban your own account — ask another admin
              </p>
            )}
          </div>
        </div>

        <div className="space-y-2">
          <label className="block text-xs text-neutral-500">Note</label>
          <Textarea
            value={note}
            onChange={e => setNote(e.target.value)}
            disabled={isReadonlyAdmin}
            placeholder="Add a note about this user..."
            className="h-20"
          />
        </div>

        {hasChanges && !isReadonlyAdmin && (
          <div className="flex justify-end">
            <Button onClick={handleSaveUser} disabled={saving} size="sm" className="gap-2">
              {saving ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  Save Changes
                </>
              )}
            </Button>
          </div>
        )}
      </div>

      {/* Linked Addresses */}
      <div className="space-y-3">
        <h4 className="text-sm font-medium text-neutral-700 flex items-center gap-2">
          <Wallet className="w-4 h-4" />
          Linked Wallet Addresses
        </h4>

        {loadingAddresses ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 className="w-5 h-5 text-neutral-400 animate-spin" />
          </div>
        ) : linkedAddresses.length === 0 ? (
          <div className="text-center py-6 text-neutral-400 text-sm">
            No linked wallet addresses
          </div>
        ) : (
          <div className="space-y-2">
            {linkedAddresses.map((addr) => (
              <div
                key={addr.address}
                className="flex items-center justify-between p-3 rounded-lg bg-neutral-100"
              >
                <AddressDisplay
                  address={addr.address}
                  ensName={ensNames?.[addr.address.toLowerCase()]}
                />
                <div className="flex items-center gap-2">
                  {loadingEns && !ensNames?.[addr.address.toLowerCase()] && (
                    <Loader2 className="w-3 h-3 text-neutral-400 animate-spin" />
                  )}
                  <span className="text-xs text-neutral-400">
                    Verified {new Date(addr.verified_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Memberships */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-medium text-neutral-700">Group Memberships</h4>
          {!isReadonlyAdmin && (
            <Button
              onClick={() => setShowMembershipForm(true)}
              size="sm"
              variant="outline"
              className="gap-1"
            >
              <Plus className="w-4 h-4" />
              Add
            </Button>
          )}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-6">
            <Loader2 className="w-5 h-5 text-neutral-400 animate-spin" />
          </div>
        ) : memberships.length === 0 ? (
          <div className="text-center py-6 text-neutral-400 text-sm">
            No group memberships
          </div>
        ) : (
          <div className="space-y-4">
            {Object.entries(membershipsByOrg).map(([orgId, orgMemberships]) => (
              <div key={orgId} className="space-y-2">
                {/* Organization header */}
                <div className="text-xs font-medium text-neutral-500 uppercase tracking-wide px-1">
                  {orgById[orgId]?.name || 'Unknown Organization'}
                </div>
                {/* Memberships in this org */}
                {orgMemberships.map((m, idx) => (
                  <div
                    key={m.membership?.id || idx}
                    className={`flex items-center justify-between p-3 rounded-lg bg-neutral-100 ${m.expired ? 'opacity-60' : ''}`}
                  >
                    <div className="flex items-center gap-3">
                      <FolderTree className="w-4 h-4 text-primary" />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm">{m.group?.name || 'Unknown Group'}</span>
                          {/* Only show path if it differs from name (indicates hierarchy) */}
                          {m.group?.path && m.group.path !== m.group.name && m.group.path !== m.group.slug && (
                            <Badge variant="outline" className="text-xs font-mono">
                              {m.group.path}
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          {m.membership?.source && (
                            <Badge
                              variant="outline"
                              className={`text-xs ${
                                m.membership.source === 'zk_attested'
                                  ? 'text-purple-700 border-purple-300 bg-purple-50'
                                  : 'text-neutral-500'
                              }`}
                            >
                              {m.membership.source === 'admin'
                                ? 'Added by admin'
                                : m.membership.source === 'zk_attested'
                                ? 'ZK Attested'
                                : m.membership.source}
                            </Badge>
                          )}
                          {m.membership?.expires_at && (
                            <Badge
                              variant="outline"
                              className={`text-xs inline-flex items-center gap-1 ${
                                m.expired
                                  ? 'text-error-dark border-red-300 bg-red-50'
                                  : 'text-amber-700 border-amber-300 bg-amber-50'
                              }`}
                            >
                              <Clock className="w-3 h-3" />
                              {m.expired ? 'Expired' : 'Expires'} {new Date(m.membership.expires_at).toLocaleString()}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                    {m.membership?.id && !isReadonlyAdmin && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setDeleteMembershipTarget(m.membership.id)}
                        className="text-error-dark hover:text-red-300 hover:bg-red-500/10"
                        aria-label="Remove membership"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Effective Permissions */}
      {userOrgIds.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-neutral-700">Effective Permissions</h4>

          {loadingPerms ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="w-5 h-5 text-neutral-400 animate-spin" />
            </div>
          ) : (
            <div className="space-y-4">
              {userOrgIds.map((orgId) => {
                const effectivePerms = effectivePermsByOrg[orgId];
                const org = orgById[orgId];

                return (
                  <div key={orgId} className="space-y-2">
                    {/* Organization header */}
                    <div className="text-xs font-medium text-neutral-500 uppercase tracking-wide px-1">
                      {org?.name || 'Unknown Organization'}
                    </div>

                    {effectivePerms ? (
                      <div className="p-4 rounded-lg bg-neutral-100 space-y-4">
                        <div>
                          <label className="text-xs text-neutral-500 mb-1 block">
                            Access Level
                            <span className="ml-1 text-neutral-400" title="Permissions for contracts not explicitly configured">
                              (for unregistered contracts)
                            </span>
                          </label>
                          {effectivePerms.allowed_methods && effectivePerms.allowed_methods.length > 0 ? (
                            <Badge
                              variant="outline"
                              className="text-xs bg-primary-50 text-primary border-primary-200"
                            >
                              {getClosestPresetLabel(effectivePerms.allowed_methods)}
                            </Badge>
                          ) : effectivePerms.claims && effectivePerms.claims.length > 0 ? (
                            <Badge
                              variant="outline"
                              className="text-xs bg-primary-50 text-primary border-primary-200"
                            >
                              Admin
                            </Badge>
                          ) : (
                            <span className="text-neutral-400 text-sm">None</span>
                          )}
                        </div>

                        <div>
                          <label className="text-xs text-neutral-500 mb-1 block">
                            Allowed Methods {effectivePerms.allowed_methods && effectivePerms.allowed_methods.length > 0
                              ? `(${effectivePerms.allowed_methods.length})`
                              : ''}
                          </label>
                          {effectivePerms.allowed_methods && effectivePerms.allowed_methods.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {effectivePerms.allowed_methods.slice(0, 10).map((method: string) => (
                                <Badge key={method} variant="outline" className="text-xs font-mono">
                                  {method}
                                </Badge>
                              ))}
                              {effectivePerms.allowed_methods.length > 10 && (
                                <Badge variant="secondary" className="text-xs">
                                  +{effectivePerms.allowed_methods.length - 10} more
                                </Badge>
                              )}
                            </div>
                          ) : (
                            <span className="text-green-600 text-sm">All methods (unrestricted)</span>
                          )}
                        </div>

                        <div className="flex gap-4">
                          <div>
                            <label className="text-xs text-neutral-500 mb-1 block">Rate Limit (RPS)</label>
                            <span className="text-sm">
                              {effectivePerms.rate_limit_rps ?? 'Unlimited'}
                            </span>
                          </div>
                          <div>
                            <label className="text-xs text-neutral-500 mb-1 block">Rate Limit (Daily)</label>
                            <span className="text-sm">
                              {effectivePerms.rate_limit_daily ?? 'Unlimited'}
                            </span>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="p-4 rounded-lg bg-neutral-100 text-neutral-400 text-sm">
                        No permissions configured
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Add Membership Dialog */}
      <Dialog open={showMembershipForm} onOpenChange={setShowMembershipForm}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Add Group Membership</DialogTitle>
          </DialogHeader>
          <MembershipForm
            userId={user.id}
            organizations={organizations}
            existingMemberships={memberships}
            onClose={() => setShowMembershipForm(false)}
            onSave={handleMembershipSave}
          />
        </DialogContent>
      </Dialog>

      {/* Delete Membership Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteMembershipTarget}
        onOpenChange={open => !open && setDeleteMembershipTarget(null)}
        title="Remove Membership"
        description="Are you sure you want to remove this group membership?"
        confirmLabel="Remove"
        cancelLabel="Cancel"
        onConfirm={handleDeleteMembershipConfirm}
        variant="destructive"
      />

      {/* Delete Membership Error Alert */}
      <AlertDialog
        open={showMembershipDeleteError}
        onOpenChange={setShowMembershipDeleteError}
        title="Remove Failed"
        description="Failed to remove membership."
        buttonLabel="OK"
        variant="error"
      />
    </div>
  );
}
