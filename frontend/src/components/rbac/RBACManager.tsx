import { useState, useEffect, createContext, useContext } from 'react';
import { Outlet, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import {
  Building2,
  Users,
  Shield,
  ShieldCheck,
  FolderTree,
  FileCode2,
  Loader2,
  Globe,
  Info,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { rbacApi } from '@/api/rbac';
import type { Organization } from '@/types/rbac';
import { useAdmin } from '@/components/auth/RequireAdmin';

type RBACTab = 'organizations' | 'groups' | 'users' | 'contracts' | 'execution-policy' | 'configuration' | 'platform-configuration' | 'azure-tenants';

// Context for sharing organization selection across sub-tabs
interface OrgContextType {
  selectedOrg: Organization | null;
  setSelectedOrg: (org: Organization | null) => void;
  organizations: Organization[];
  refreshOrgs: () => Promise<void>;
}

// reason: OrgContext + useOrgContext are the org-selection context that
// RBACManager provides and its sub-tabs (OrganizationList, UserList, etc.)
// consume. They are intentionally co-located with the providing component, and
// the test suite mocks them via vi.mock('../RBACManager'). Splitting would
// touch every sub-tab and test mock; the only cost here is full reload (not
// HMR) when editing this manager file.
// eslint-disable-next-line react-refresh/only-export-components
export const OrgContext = createContext<OrgContextType | null>(null);

// reason: consumer hook for OrgContext above; same co-location rationale.
// eslint-disable-next-line react-refresh/only-export-components
export function useOrgContext() {
  const context = useContext(OrgContext);
  if (!context) {
    throw new Error('useOrgContext must be used within RBACManager');
  }
  return context;
}

/**
 * useOrgContextOptional returns the org context if the caller is rendered
 * within RBACManager's provider, or null otherwise. Used by components that
 * legitimately render both inside the RBAC tree (where the selected org is
 * meaningful) and in isolation in unit tests (where it isn't), without
 * forcing every such test to wrap in a provider.
 */
// reason: optional consumer hook for OrgContext above; same co-location
// rationale as useOrgContext. Added by RD-994; the matching eslint-disable was
// missed then and only surfaced once RD-959 made `eslint --max-warnings 0`
// CI-gating (the two landed on separate branches).
// eslint-disable-next-line react-refresh/only-export-components
export function useOrgContextOptional(): OrgContextType | null {
  return useContext(OrgContext);
}

export default function RBACManager() {
  const { isPlatformAdmin } = useAdmin();
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);
  const [showHowItWorks, setShowHowItWorks] = useState(false);

  // Derive active tab from URL
  const getActiveTab = (): RBACTab => {
    const path = location.pathname;
    if (path.includes('/platform-configuration')) return 'platform-configuration';
    if (path.includes('/azure-tenants')) return 'azure-tenants';
    if (path.includes('/execution-policy')) return 'execution-policy';
    if (path.includes('/configuration')) return 'configuration';
    if (path.includes('/groups')) return 'groups';
    if (path.includes('/users')) return 'users';
    if (path.includes('/contracts')) return 'contracts';
    return 'organizations';
  };

  const activeTab = getActiveTab();

  const loadOrganizations = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.orgs.list({ limit: 1000 });
      const orgs = response.data?.data || [];
      setOrganizations(orgs);

      // Check for org in URL params
      const orgIdFromUrl = searchParams.get('org');
      if (orgIdFromUrl) {
        const orgFromUrl = orgs.find(o => o.id === orgIdFromUrl);
        if (orgFromUrl) {
          setSelectedOrg(orgFromUrl);
          return;
        }
      }

      if (selectedOrg) {
        // Refresh the selected org data
        const updatedOrg = orgs.find(o => o.id === selectedOrg.id);
        if (updatedOrg) {
          setSelectedOrg(updatedOrg);
        } else if (orgs.length > 0) {
          setSelectedOrg(orgs[0]);
        } else {
          setSelectedOrg(null);
        }
      } else if (orgs.length === 1) {
        // Single-org admin: auto-select the only org so the user
        // doesn't have to interact with a one-option chooser. The
        // Select control below is disabled in this case (see
        // singleOrgLock derived flag); keeping selectedOrg in sync
        // with the URL so deep-links still work.
        setSelectedOrg(orgs[0]);
        setSearchParams({ org: orgs[0].id });
      }
    } catch (error) {
      console.error('Failed to load organizations:', error);
      setOrganizations([]);
    } finally {
      setLoading(false);
    }
  };

  // reason: mount-only load of organizations. loadOrganizations is a
  // non-memoised helper; this must run exactly once on mount, so the empty dep
  // array is intentional.
  useEffect(() => {
    loadOrganizations();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync org from URL when search params change
  // reason: re-derives the selected org from the URL when the org list or query
  // string changes. selectedOrg?.id is read only as a guard against a redundant
  // setState (avoiding a render loop); it is intentionally not a trigger, so it
  // is omitted from the deps.
  useEffect(() => {
    const orgIdFromUrl = searchParams.get('org');
    if (orgIdFromUrl && organizations.length > 0) {
      const org = organizations.find(o => o.id === orgIdFromUrl);
      if (org && org.id !== selectedOrg?.id) {
        setSelectedOrg(org);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, organizations]);

  const handleOrgChange = (orgId: string) => {
    if (orgId === '__all__') {
      setSelectedOrg(null);
      setSearchParams({});
      return;
    }
    const org = organizations.find(o => o.id === orgId);
    setSelectedOrg(org || null);
    // Update URL with new org
    if (org) {
      setSearchParams({ org: orgId });
    }
  };

  const handleTabChange = (value: string) => {
    const tab = value as RBACTab;
    const orgTabs: RBACTab[] = ['groups', 'users', 'contracts', 'execution-policy', 'configuration'];
    const needsOrg = orgTabs.includes(tab);

    const path = `/admin/rbac/${tab === 'organizations' ? 'organizations' : tab}`;
    if (needsOrg && selectedOrg) {
      navigate(`${path}?org=${selectedOrg.id}`);
    } else {
      navigate(path);
    }
  };

  // Tabs that show org selector (users shows it but doesn't block without one)
  const orgRequiredTabs: RBACTab[] = ['groups', 'users', 'contracts', 'execution-policy', 'configuration'];
  const requiresOrg = orgRequiredTabs.includes(activeTab);
  // Tabs that are completely blocked without org selection
  const orgBlockedTabs: RBACTab[] = ['groups', 'contracts', 'execution-policy', 'configuration'];
  const blockedWithoutOrg = orgBlockedTabs.includes(activeTab) && !selectedOrg;

  // Single-org admin: lock the dropdown. After RD-916/917 a tier-2 admin
  // sees only orgs they're a member of; with exactly one such org there's
  // nothing meaningful to choose, so we pre-selected it above and disable
  // the control to avoid presenting an interactive one-item chooser.
  const singleOrgLock = organizations.length === 1;

  return (
    <OrgContext.Provider
      value={{
        selectedOrg,
        setSelectedOrg,
        organizations,
        refreshOrgs: loadOrganizations,
      }}
    >
      <Card className="animate-fade-in" data-testid="rbac-manager">
        <CardHeader className="pb-4">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center">
                <Shield className="w-5 h-5 text-primary" />
              </div>
              <div>
                <CardTitle className="text-lg" data-testid="rbac-title">Access Control</CardTitle>
                <p className="text-sm text-neutral-500 mt-0.5">
                  Manage organizations, groups, roles, and permissions
                </p>
              </div>
            </div>

            {/* Organization Selector - always visible, disabled on global tabs */}
            <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center sm:gap-3 lg:w-auto">
              <span className="text-sm text-neutral-500 sm:whitespace-nowrap">Scope:</span>
              {loading ? (
                <div className="flex items-center gap-2 text-neutral-400">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Loading...</span>
                </div>
              ) : !requiresOrg ? (
                <div className="flex items-center gap-2 px-3 py-2 rounded-md bg-neutral-100 text-neutral-500">
                  <Globe className="w-4 h-4" />
                  <span className="text-sm">Global (all organizations)</span>
                </div>
              ) : organizations.length === 0 ? (
                <Badge variant="outline" className="text-neutral-500">
                  No organizations
                </Badge>
              ) : (
                <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
                  <Select
                    value={selectedOrg?.id || '__all__'}
                    onValueChange={handleOrgChange}
                    disabled={singleOrgLock}
                  >
                    <SelectTrigger
                      className={`w-full sm:w-[280px] ${blockedWithoutOrg ? 'border-error ring-1 ring-error/20' : ''} ${singleOrgLock ? 'opacity-100 cursor-default' : ''}`}
                      aria-label="Select organization scope"
                      data-testid="org-selector"
                      title={singleOrgLock ? 'You administer one organization — scope is locked to it.' : undefined}
                    >
                      {selectedOrg ? (
                        <SelectValue placeholder="Select organization" />
                      ) : (
                        <div className="flex items-center gap-2 whitespace-nowrap">
                          <Globe className="w-4 h-4 text-neutral-400 shrink-0" />
                          <span className="text-sm">All organizations</span>
                        </div>
                      )}
                    </SelectTrigger>
                    <SelectContent>
                      {!blockedWithoutOrg && !singleOrgLock && (
                        <SelectItem value="__all__">
                          <div className="flex items-center gap-2 whitespace-nowrap">
                            <Globe className="w-4 h-4 text-neutral-400 shrink-0" />
                            <span>All organizations</span>
                          </div>
                        </SelectItem>
                      )}
                      {organizations.map(org => (
                        <SelectItem key={org.id} value={org.id}>
                          <div className="flex items-center gap-2 whitespace-nowrap">
                            <Building2 className="w-4 h-4 text-neutral-400 shrink-0" />
                            <span className="truncate">{org.name}</span>
                            <span className="text-neutral-400 text-xs shrink-0">
                              ({org.slug})
                            </span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {blockedWithoutOrg && (
                    <span className="text-xs text-error whitespace-nowrap">
                      Select an org
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        </CardHeader>

        <CardContent className="pt-0">
          {/* How It Works - Collapsible */}
          <div className="mb-4">
            <button
              onClick={() => setShowHowItWorks(!showHowItWorks)}
              className="flex items-center gap-2 text-sm text-neutral-500 hover:text-neutral-700 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 rounded-md px-2 py-1 -ml-2"
              aria-expanded={showHowItWorks}
              aria-controls="how-permissions-work"
            >
              <Info className="w-4 h-4" aria-hidden="true" />
              <span>How permissions work</span>
              {showHowItWorks ? (
                <ChevronUp className="w-4 h-4" aria-hidden="true" />
              ) : (
                <ChevronDown className="w-4 h-4" aria-hidden="true" />
              )}
            </button>
            {showHowItWorks && (
              <div id="how-permissions-work" className="mt-3 p-4 rounded-lg bg-neutral-100 border border-neutral-200 text-sm animate-fade-in">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h4 className="font-medium text-neutral-700 mb-2">Permission Model</h4>
                    <ul className="space-y-1.5 text-neutral-500 text-xs">
                      <li className="flex items-start gap-2">
                        <Building2 className="w-3.5 h-3.5 mt-0.5 text-primary shrink-0" />
                        <span><strong className="text-neutral-700">Organizations</strong> are top-level tenants</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <FolderTree className="w-3.5 h-3.5 mt-0.5 text-primary shrink-0" />
                        <span><strong className="text-neutral-700">Groups</strong> define RPC methods, rate limits, and default claims</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <FileCode2 className="w-3.5 h-3.5 mt-0.5 text-primary shrink-0" />
                        <span><strong className="text-neutral-700">Contracts</strong> with grants define per-contract claims (admin, deploy, upgrade)</span>
                      </li>
                    </ul>
                  </div>
                  <div>
                    <h4 className="font-medium text-neutral-700 mb-2">How Users Get Permissions</h4>
                    <ul className="space-y-1.5 text-neutral-500 text-xs">
                      <li className="flex items-start gap-2">
                        <span className="text-primary font-mono shrink-0">1.</span>
                        <span>Add a <strong className="text-neutral-700">User</strong> to a <strong className="text-neutral-700">Group</strong></span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-primary font-mono shrink-0">2.</span>
                        <span>User inherits Group's allowed methods, rate limits, and default claims</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-primary font-mono shrink-0">3.</span>
                        <span>Contract grants give specific claims for registered contracts</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>

          <Tabs value={activeTab} onValueChange={handleTabChange} data-testid="rbac-tabs">
            <TabsList className="w-full justify-start mb-4">
              <TabsTrigger value="organizations" className="gap-2" data-testid="tab-organizations">
                <Building2 className="w-4 h-4" />
                <span>Organizations</span>
              </TabsTrigger>
              <TabsTrigger value="groups" className="gap-2" data-testid="tab-groups">
                <FolderTree className="w-4 h-4" />
                <span>Groups</span>
              </TabsTrigger>
              <TabsTrigger value="users" className="gap-2" data-testid="tab-users">
                <Users className="w-4 h-4" />
                <span>Users</span>
              </TabsTrigger>
              <TabsTrigger value="contracts" className="gap-2" data-testid="tab-contracts">
                <FileCode2 className="w-4 h-4" />
                <span>Contracts</span>
              </TabsTrigger>
              <TabsTrigger value="execution-policy" className="gap-2" data-testid="tab-execution-policy">
                <ShieldCheck className="w-4 h-4" />
                <span>Execution Policy</span>
              </TabsTrigger>
              <TabsTrigger value="configuration" className="gap-2" data-testid="tab-configuration">
                <FileCode2 className="w-4 h-4" />
                <span>Configuration</span>
              </TabsTrigger>
              {isPlatformAdmin && <TabsTrigger value="platform-configuration" className="gap-2" data-testid="tab-platform-configuration">
                <Globe className="h-4 w-4" />Platform configuration
              </TabsTrigger>}
              <TabsTrigger value="azure-tenants" className="gap-2" data-testid="tab-azure-tenants">
                <Shield className="w-4 h-4" />
                <span>Azure AD</span>
              </TabsTrigger>
            </TabsList>
          </Tabs>

          {/* Render nested route content */}
          {blockedWithoutOrg ? <NoOrgSelected /> : <Outlet />}
        </CardContent>
      </Card>
    </OrgContext.Provider>
  );
}

function NoOrgSelected() {
  return (
    <div className="text-center py-12">
      <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
        <Building2 className="w-8 h-8 text-neutral-400" />
      </div>
      <p className="text-neutral-500 mb-2">No organization selected</p>
      <p className="text-neutral-400 text-sm">
        Select an organization from the dropdown above to manage this resource
      </p>
    </div>
  );
}
