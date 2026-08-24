import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { rbacApi } from '@/api/rbac';
import type { User, GroupWithAccess, UserRoleFilter } from '@/types/rbac';
import UserDetail from './UserDetail';
import OnboardByDIDForm from './OnboardByDIDForm';
import { ViewAsInExplorerButton } from './ViewAsInExplorerButton';
import { useOrgContext } from './RBACManager';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
import { AlertDialog } from '@/components/ui/ConfirmDialog';
import Pagination from '@/components/ui/Pagination';
import {
  Users,
  User as UserIcon,
  Shield,
  ShieldOff,
  Check,
  X,
  Loader2,
  Eye,
  Search,
  UserPlus,
} from 'lucide-react';

const ROLE_OPTIONS: { value: UserRoleFilter | 'any'; label: string }[] = [
  { value: 'any', label: 'Any role' },
  { value: 'org_admin', label: 'Org admin' },
  { value: 'admin', label: 'Contract admin' },
  { value: 'member', label: 'Member' },
];

const PAGE_SIZE = 25;

export default function UserList() {
  const { userId } = useParams();
  const navigate = useNavigate();
  const { selectedOrg } = useOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showUpdateError, setShowUpdateError] = useState(false);
  const [onboardOpen, setOnboardOpen] = useState(false);
  // DID to seed the onboard dialog with. Set when the dialog is opened from the
  // empty-search hint so the admin doesn't have to paste the DID a second time.
  const [onboardPrefillDid, setOnboardPrefillDid] = useState('');

  // Search state
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [debouncedSearch, setDebouncedSearch] = useState<string>('');

  // Filter state
  const [roleFilter, setRoleFilter] = useState<UserRoleFilter | 'any'>('any');
  const [selectedGroupIds, setSelectedGroupIds] = useState<string[]>([]);

  // Group filter options — populated when an org is selected.
  const [groupOptions, setGroupOptions] = useState<GroupWithAccess[]>([]);
  const [groupsLoadFailed, setGroupsLoadFailed] = useState(false);

  // Monotonic id of the newest users request. Searches are debounced but not
  // serialised, so two can be in flight at once and settle out of order. The
  // empty-result branch below is read together with the CURRENT query, so a
  // stale empty page would claim the currently-searched DID was never
  // onboarded and prefill the onboard dialog with it — inviting a duplicate
  // membership. Every state write in loadUsers is gated on still being newest.
  const usersRequestIdRef = useRef(0);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchQuery);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Reset group filter and reload group options when org changes — group IDs
  // are org-scoped, so a previous selection is meaningless under a new org.
  useEffect(() => {
    setSelectedGroupIds([]);
    setGroupsLoadFailed(false);
    if (!selectedOrg) {
      setGroupOptions([]);
      return;
    }
    let cancelled = false;
    rbacApi.groups
      .list(selectedOrg.id, { limit: 250 })
      .then(res => {
        if (!cancelled) setGroupOptions(res.data.data || []);
      })
      .catch(() => {
        if (cancelled) return;
        setGroupOptions([]);
        setGroupsLoadFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedOrg]);

  const loadUsers = useCallback(async (newOffset?: number) => {
    const currentOffset = newOffset ?? offset;
    const requestId = ++usersRequestIdRef.current;
    const isNewest = () => usersRequestIdRef.current === requestId;

    try {
      setLoading(true);
      const params: {
        limit: number;
        offset: number;
        org_id?: string;
        search?: string;
        group_id?: string[];
        role?: UserRoleFilter;
      } = {
        limit: PAGE_SIZE,
        offset: currentOffset,
      };
      if (selectedOrg) {
        params.org_id = selectedOrg.id;
      }
      if (debouncedSearch) {
        params.search = debouncedSearch;
      }
      if (selectedGroupIds.length > 0) {
        params.group_id = selectedGroupIds;
      }
      if (roleFilter !== 'any') {
        params.role = roleFilter;
      }
      const response = await rbacApi.users.list(params);
      // A superseded response must not touch state: it would overwrite the
      // newer query's rows and be re-interpreted against that newer query.
      if (!isNewest()) return;
      const page = response.data;
      setUsers(page.data || []);
      setTotal(page.total);
      setLoadFailed(false);
      if (newOffset !== undefined) {
        setOffset(newOffset);
      }
    } catch (error) {
      console.error('Failed to load users:', error);
      if (!isNewest()) return;
      setUsers([]);
      // A failed request must not render as "no such user" — that would invite
      // onboarding someone who may already exist.
      setLoadFailed(true);
    } finally {
      // Not just cosmetic: clearing this for a superseded request presents the
      // in-flight view as settled, flashing the stale page's empty state.
      if (isNewest()) setLoading(false);
    }
  }, [selectedOrg, debouncedSearch, selectedGroupIds, roleFilter, offset]);

  // Load users when org / search / filters change - reset to first page
  // reason: intentional reload when the listed filter keys change. loadUsers is
  // a non-memoised helper that reads current state via closure; adding it to
  // deps would require useCallback and risk a refetch loop.
  useEffect(() => {
    setOffset(0);
    loadUsers(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedOrg, debouncedSearch, selectedGroupIds, roleFilter]);

  // Open modal if userId is in URL
  useEffect(() => {
    if (userId && users.length > 0) {
      const user = users.find(u => u.id === userId);
      if (user) {
        setSelectedUser(user);
      }
    } else if (!userId) {
      setSelectedUser(null);
    }
  }, [userId, users]);

  const handleToggleBan = async (user: User) => {
    try {
      await rbacApi.users.update(user.id, { banned: !user.banned });
      await loadUsers();
    } catch (error) {
      console.error('Failed to update user:', error);
      setShowUpdateError(true);
    }
  };

  const handleUserUpdate = async () => {
    await loadUsers();
    // Update selected user with fresh data
    if (selectedUser) {
      const updated = users.find(u => u.id === selectedUser.id);
      if (updated) setSelectedUser(updated);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const truncateId = (id: string) => {
    if (id.length <= 20) return id;
    return `${id.slice(0, 10)}...${id.slice(-8)}`;
  };

  // Onboarding writes membership, so read-only admins (RD-866) don't get the
  // affordance, and the target org has to be known.
  const canOnboard = !!selectedOrg && !isReadonlyAdmin;

  const openOnboard = (prefillDid = '') => {
    setOnboardPrefillDid(prefillDid);
    setOnboardOpen(true);
  };

  // The search box also accepts wallet addresses, which don't belong in a DID
  // field — only carry the query over when it is plausibly a DID.
  const searchedDid = debouncedSearch.trim();
  const onboardPrefillFromSearch = searchedDid.startsWith('did:') ? searchedDid : '';

  // With a role/group filter also applied, "never onboarded" is not the only
  // explanation for an empty result — don't let the hint assert it is.
  const filtersNarrowing = roleFilter !== 'any' || selectedGroupIds.length > 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-medium text-neutral-700">Users</h3>
          <p className="text-xs text-neutral-500 mt-0.5">
            Manage user accounts, KYC status, and group memberships
          </p>
        </div>
        {canOnboard && (
          <Button
            size="sm"
            onClick={() => openOnboard()}
            className="gap-2"
            data-testid="onboard-by-did-button"
            title="Onboard a user by their DID into a group in this organization"
          >
            <UserPlus className="w-4 h-4" />
            Onboard by DID
          </Button>
        )}
      </div>

      {/* Search + filters */}
      <div className="flex flex-wrap items-start gap-3">
        <div className="relative flex-1 min-w-[220px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" />
          <Input
            type="text"
            placeholder="Search by DID or wallet address..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-neutral-500">Role</span>
          <Select
            value={roleFilter}
            onValueChange={v => setRoleFilter(v as UserRoleFilter | 'any')}
          >
            <SelectTrigger className="w-[160px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ROLE_OPTIONS.map(opt => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {(searchQuery || roleFilter !== 'any' || selectedGroupIds.length > 0) && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearchQuery('');
              setRoleFilter('any');
              setSelectedGroupIds([]);
            }}
            className="text-neutral-500"
          >
            Clear filters
          </Button>
        )}
      </div>

      {/* Group filter — multi-select chip toggles. Only shown when an org
          is selected, since group IDs are org-scoped. */}
      {selectedOrg && groupOptions.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-neutral-500 mr-1">Groups:</span>
          {groupOptions.map(g => {
            const id = g.group.id;
            const active = selectedGroupIds.includes(id);
            return (
              <Badge
                key={id}
                variant={active ? 'default' : 'outline'}
                className="cursor-pointer select-none"
                onClick={() =>
                  setSelectedGroupIds(prev =>
                    prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
                  )
                }
                title={active ? 'Click to remove from filter' : 'Click to add to filter'}
              >
                {g.group.name}
              </Badge>
            );
          })}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
        </div>
      ) : users.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <Users className="w-8 h-8 text-neutral-400" />
          </div>
          {loadFailed ? (
            <div data-testid="users-load-error">
              <p className="text-neutral-500 mb-2">Couldn't load users</p>
              <p className="text-neutral-400 text-sm max-w-md mx-auto">
                The request failed, so this list is incomplete. Retry before
                concluding that a user is missing.
              </p>
              <Button
                size="sm"
                variant="outline"
                onClick={() => loadUsers()}
                className="gap-2 mt-4"
                data-testid="users-retry-button"
              >
                Retry
              </Button>
            </div>
          ) : debouncedSearch ? (
            // RD-1239: this list only returns users who already belong to an org
            // the caller administers, so a not-yet-onboarded DID can never match.
            // Saying so turns a dead end ("is search broken?") into the next step.
            <div data-testid="users-empty-search">
              <p className="text-neutral-500 mb-2">No users match this search</p>
              <p className="text-neutral-400 text-sm max-w-md mx-auto">
                Search covers users who already belong to an organization you
                administer. Someone who has never been onboarded won't appear here.
              </p>
              {filtersNarrowing && (
                <p className="text-neutral-400 text-sm max-w-md mx-auto mt-1">
                  The active role or group filters may also be hiding matches.
                </p>
              )}
              {canOnboard && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => openOnboard(onboardPrefillFromSearch)}
                  className="gap-2 mt-4"
                  data-testid="onboard-by-did-hint-button"
                  title="Onboard a user by their DID into a group in this organization"
                >
                  <UserPlus className="w-4 h-4" />
                  Onboard by DID
                </Button>
              )}
            </div>
          ) : (
            <>
              <p className="text-neutral-500 mb-2">No users found</p>
              <p className="text-neutral-400 text-sm">
                Users are created automatically when they authenticate
              </p>
            </>
          )}
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>External ID</TableHead>
              <TableHead>Groups</TableHead>
              <TableHead>KYC</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Note</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.map((user, index) => (
              <TableRow
                key={user.id}
                className="animate-fade-in cursor-pointer"
                style={{ animationDelay: `${index * 30}ms` }}
                onClick={() => navigate(`/admin/rbac/users/${user.id}`)}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <UserIcon className="w-4 h-4 text-primary" />
                    <span
                      className="font-mono text-sm"
                      title={user.external_id}
                    >
                      {truncateId(user.external_id)}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  {user.groups && user.groups.length > 0 ? (
                    <div
                      className="flex flex-wrap gap-1 max-w-[260px]"
                      onClick={e => e.stopPropagation()}
                    >
                      {user.groups.map(g => (
                        <Badge
                          key={g.group_id}
                          variant={g.is_org_admin ? 'default' : 'secondary'}
                          className="cursor-pointer"
                          title={`${g.name}${g.is_org_admin ? ' (org admin)' : ''} — open Groups tab`}
                          onClick={() => navigate('/admin/rbac/groups')}
                        >
                          {g.name}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-neutral-400 text-sm">—</span>
                  )}
                </TableCell>
                <TableCell>
                  {user.kyc ? (
                    <div className="flex items-center gap-1.5 text-success-dark">
                      <Check className="w-4 h-4" />
                      <span className="text-sm">Verified</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5 text-neutral-400">
                      <X className="w-4 h-4" />
                      <span className="text-sm">No</span>
                    </div>
                  )}
                </TableCell>
                <TableCell>
                  {user.banned ? (
                    <Badge variant="destructive" className="gap-1">
                      <ShieldOff className="w-3 h-3" />
                      Banned
                    </Badge>
                  ) : (
                    <Badge variant="success" className="gap-1">
                      <Shield className="w-3 h-3" />
                      Active
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="text-neutral-500 text-sm">
                  {formatDate(user.created_at)}
                </TableCell>
                <TableCell className="text-neutral-500 text-sm max-w-[150px] truncate">
                  {user.note || '-'}
                </TableCell>
                <TableCell>
                  <div
                    className="flex items-center justify-end gap-2"
                    onClick={e => e.stopPropagation()}
                  >
                    {!isReadonlyAdmin && (
                      <Button
                        variant={user.banned ? 'success' : 'destructive'}
                        size="sm"
                        onClick={() => handleToggleBan(user)}
                        className="gap-1.5"
                        title={user.banned ? 'Unban this user' : 'Ban this user'}
                      >
                        {user.banned ? (
                          <>
                            <Shield className="w-3.5 h-3.5" />
                            Unban
                          </>
                        ) : (
                          <>
                            <ShieldOff className="w-3.5 h-3.5" />
                            Ban
                          </>
                        )}
                      </Button>
                    )}
                    {/* RD-928: tier-2-only "View as in Explorer" action.
                        Read-only admins (RD-866) don't get the affordance —
                        their whole role is read-only audit of admin actions,
                        not user-data browse. */}
                    {!isReadonlyAdmin && (
                      <ViewAsInExplorerButton targetDID={user.external_id} />
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => navigate(`/admin/rbac/users/${user.id}`)}
                      title="View user details"
                    >
                      <Eye className="w-4 h-4" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onPageChange={(newOffset) => loadUsers(newOffset)} />

      {/* User Detail Dialog */}
      <Dialog
        open={!!selectedUser}
        onOpenChange={open => !open && navigate('/admin/rbac/users')}
      >
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserIcon className="w-5 h-5 text-primary" />
              User Details
            </DialogTitle>
          </DialogHeader>
          {selectedUser && (
            <UserDetail
              user={selectedUser}
              onUpdate={handleUserUpdate}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Update Error Alert */}
      <AlertDialog
        open={showUpdateError}
        onOpenChange={setShowUpdateError}
        title="Update Failed"
        description="Failed to update user."
        buttonLabel="OK"
        variant="error"
      />

      {/* Onboard by DID Dialog */}
      <Dialog open={onboardOpen} onOpenChange={setOnboardOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserPlus className="w-5 h-5 text-primary" />
              Onboard user by DID
            </DialogTitle>
          </DialogHeader>
          {selectedOrg && (
            <OnboardByDIDForm
              // initialDid is read at mount. The host dialog normally unmounts on
              // close, but during its exit animation it briefly does not — keying
              // on the prefill makes a reopen remount deterministically, so a DID
              // carried over from the hint can never linger into the next open.
              key={onboardPrefillDid}
              orgId={selectedOrg.id}
              // On a failed group load, hand the form no list rather than an
              // empty one: an empty list reads as "this org has no groups", so
              // the form would advise creating one after a network error. Omitting
              // the prop makes it fetch and report the failure itself.
              groups={groupsLoadFailed ? undefined : groupOptions.map(g => g.group)}
              initialDid={onboardPrefillDid}
              onClose={() => setOnboardOpen(false)}
              onSave={() => {
                setOnboardOpen(false);
                // Refresh the user list so the freshly onboarded user
                // (or a new membership on an existing user) shows up.
                loadUsers();
              }}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
