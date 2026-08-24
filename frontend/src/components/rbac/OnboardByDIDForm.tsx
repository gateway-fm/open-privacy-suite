import { useEffect, useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group, UserMembership } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { AlertCircle, FolderTree, Loader2, UserPlus, X } from 'lucide-react';
import AccessWindowField from './AccessWindowField';
import { resolveExpiry } from './accessWindow';

// Minimum length for any plausible DID. The shortest real DIDs we'd accept
// (e.g. `did:iden3:polygon:main:` + identifier) comfortably exceed 20 chars,
// and the local validator is only meant to catch obvious typos — final
// validity is decided by the backend.
const MIN_DID_LENGTH = 20;

interface OnboardByDIDFormProps {
  /** Target organization the user is being onboarded into. */
  orgId: string;
  /**
   * Optional pre-fetched groups for the org. If omitted the component
   * fetches them itself, matching the pattern in MembershipForm.
   */
  groups?: Group[];
  /**
   * DID to seed the input with. Read once, at mount: the field is editable
   * afterwards, so later changes to this prop are ignored. A caller that needs a
   * new value to take effect must remount the form (see UserList's `key`).
   */
  initialDid?: string;
  onClose: () => void;
  /** Called after a successful onboarding. */
  onSave: (result: { userId: string; membership: UserMembership }) => void;
}

export default function OnboardByDIDForm({
  orgId,
  groups,
  initialDid = '',
  onClose,
  onSave,
}: OnboardByDIDFormProps) {
  const [did, setDid] = useState(initialDid);
  const [selectedGroupId, setSelectedGroupId] = useState<string>('');
  const [fetchedGroups, setFetchedGroups] = useState<Group[]>([]);
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [groupsFailed, setGroupsFailed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Time-boxed access window (RD-1145) — onboard a regulator/auditor
  // DID with an auto-expiring profile. 'none' = permanent.
  const [expiryPreset, setExpiryPreset] = useState<string>('none');
  const [customExpiry, setCustomExpiry] = useState<string>('');

  // Use the prop if provided; otherwise fall back to what we fetched.
  // RD-1099: org-admin groups are excluded — only a super-admin (X-Admin-Token)
  // may assign org-admin membership, so the backend rejects this from the
  // dashboard's tier-2 (JWT) caller with a 403. Hiding them here keeps the UI
  // honest; the backend gate (denyJWTAdminTouchOrgAdminGroup) is the real
  // boundary. Read-only-admin groups stay assignable (delegation, not escalation).
  const allGroups = groups ?? fetchedGroups;
  const availableGroups = allGroups.filter(g => !g.is_org_admin);
  // RD-1239: distinguish "this org has nothing" from "everything it has is
  // filtered out above". Both render an empty dropdown, but only one of them is
  // fixed by creating a group — and claiming "no groups" when the org demonstrably
  // has one is what left admins stuck with a permanently disabled submit button.
  const onlyOrgAdminGroups = availableGroups.length === 0 && allGroups.length > 0;

  useEffect(() => {
    if (groups) return; // Parent supplied them, nothing to load.
    let cancelled = false;
    setLoadingGroups(true);
    rbacApi.groups
      .list(orgId, { limit: 250 })
      .then(res => {
        if (cancelled) return;
        setFetchedGroups((res.data?.data || []).map(gwa => gwa.group));
      })
      .catch(err => {
        if (cancelled) return;
        console.error('Failed to load groups:', err);
        setFetchedGroups([]);
        // A failed fetch is indistinguishable from an empty org by list length
        // alone, and "create a group" is the wrong advice for a network error.
        setGroupsFailed(true);
      })
      .finally(() => {
        if (!cancelled) setLoadingGroups(false);
      });
    return () => {
      cancelled = true;
    };
  }, [orgId, groups]);

  const trimmedDid = did.trim();
  const didLooksValid = trimmedDid.startsWith('did:') && trimmedDid.length >= MIN_DID_LENGTH;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!trimmedDid) {
      setError('DID is required');
      return;
    }
    if (!didLooksValid) {
      setError('Enter a valid DID (e.g. did:iden3:privado:main:...)');
      return;
    }
    if (!selectedGroupId) {
      setError('Please select a group');
      return;
    }

    const expires_at = resolveExpiry(expiryPreset, customExpiry);
    if (expiryPreset === 'custom' && !expires_at) {
      setError('Please pick a valid expiry date, or choose “No expiry”.');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      const res = await rbacApi.orgs.createMembershipByDid(orgId, {
        did: trimmedDid,
        group_id: selectedGroupId,
        ...(expires_at ? { expires_at } : {}),
      });
      const { membership, user_id: userId } = res.data;
      onSave({ userId, membership });
    } catch (err: unknown) {
      console.error('Failed to onboard user:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      const status = axiosError.response?.status;
      const rawError = axiosError.response?.data?.error;

      if (status === 409) {
        setError('User is already a member of this group');
      } else if (status === 403) {
        // Backend deliberately returns the same opaque "access denied"
        // string for two distinct deny paths (caller not full-admin of
        // :org_id vs target group belongs to a different org). Do not
        // attempt to distinguish them in the UI.
        setError('Access denied. You may not have permission to onboard users into this organization or group.');
      } else if (status === 400) {
        setError(rawError || 'Invalid request. Check the DID format and try again.');
      } else if (rawError) {
        setError(rawError);
      } else {
        setError('Failed to onboard user. Please try again.');
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
        <label htmlFor="onboard-did" className="block text-sm font-medium text-neutral-700">
          User DID
        </label>
        <Input
          id="onboard-did"
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder="did:iden3:privado:main:..."
          value={did}
          onChange={e => setDid(e.target.value)}
          disabled={saving}
          aria-invalid={did.length > 0 && !didLooksValid}
        />
        <p className="text-xs text-neutral-500">
          Paste the user's full DID. Accepted formats include
          <span className="font-mono"> did:iden3:...</span> and
          <span className="font-mono"> did:polygonid:...</span>.
        </p>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">Group</label>
        {loadingGroups ? (
          <div className="flex items-center gap-2 text-neutral-400 py-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-sm">Loading groups...</span>
          </div>
        ) : groupsFailed ? (
          <p className="text-neutral-500 text-sm py-2" data-testid="onboard-groups-error">
            Couldn't load this organization's groups. Close and reopen this dialog
            to retry.
          </p>
        ) : onlyOrgAdminGroups ? (
          <p
            className="text-neutral-500 text-sm py-2"
            data-testid="onboard-no-assignable-groups"
          >
            This organization's only groups are org-admin groups, which can't be
            assigned from here. Create a regular group in the Groups tab, then
            onboard the user into that.
          </p>
        ) : availableGroups.length === 0 ? (
          <p className="text-neutral-500 text-sm py-2" data-testid="onboard-no-groups">
            This organization has no groups yet. Create one in the Groups tab,
            then onboard the user into it.
          </p>
        ) : (
          <Select
            value={selectedGroupId}
            onValueChange={setSelectedGroupId}
            disabled={saving}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select group" />
            </SelectTrigger>
            <SelectContent>
              {availableGroups.map(group => (
                <SelectItem key={group.id} value={group.id}>
                  <div className="flex items-center gap-2">
                    <FolderTree className="w-4 h-4 text-neutral-400" />
                    <span>{group.name}</span>
                    <span className="text-neutral-400 text-xs font-mono">({group.path})</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      {/* Time-boxed access window (RD-1145) — auto-expiring regulator
          profile. */}
      {selectedGroupId && (
        <AccessWindowField
          preset={expiryPreset}
          onPresetChange={setExpiryPreset}
          custom={customExpiry}
          onCustomChange={setCustomExpiry}
          disabled={saving}
        />
      )}

      {selectedGroupId && (
        <div className="p-3 rounded-lg bg-primary-50 border border-primary-200">
          <p className="text-sm text-primary-600">
            If the DID hasn't authenticated before, an account is created and added to this group.
            Existing users are added without disturbing memberships in other organizations.
          </p>
        </div>
      )}

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
        <Button
          type="submit"
          disabled={saving || !didLooksValid || !selectedGroupId}
          className="gap-2"
        >
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Onboarding...
            </>
          ) : (
            <>
              <UserPlus className="w-4 h-4" />
              Onboard user
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
