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
  Scale,
  Settings,
  Coins,
  FileText,
  ShieldBan,
  ScrollText,
  Building2,
  Loader2,
  AlertTriangle,
  MapPin,
} from 'lucide-react';
import { rbacApi } from '@/api/rbac';
import type { Organization } from '@/types/rbac';
import { CurrencyProvider } from './CurrencyContext';
import CurrencySelector from './CurrencySelector';

type ComplianceTab = 'config' | 'tokens' | 'travel-rules' | 'address-thresholds' | 'sanctions' | 'logs';

interface ComplianceOrgContextType {
  selectedOrg: Organization | null;
  setSelectedOrg: (org: Organization | null) => void;
  organizations: Organization[];
}

// reason: ComplianceOrgContext + useComplianceOrgContext are the org-selection
// context that ComplianceManager provides and its sub-tabs consume. They are
// intentionally co-located with the providing component and mocked in tests via
// vi.mock('../ComplianceManager'). Splitting would touch every sub-tab and test
// mock; the only cost here is full reload (not HMR) when editing this file.
// eslint-disable-next-line react-refresh/only-export-components
export const ComplianceOrgContext = createContext<ComplianceOrgContextType | null>(null);

// reason: consumer hook for ComplianceOrgContext above; same co-location rationale.
// eslint-disable-next-line react-refresh/only-export-components
export function useComplianceOrgContext() {
  const context = useContext(ComplianceOrgContext);
  if (!context) {
    throw new Error('useComplianceOrgContext must be used within ComplianceManager');
  }
  return context;
}

export default function ComplianceManager() {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);
  const [travelRuleEnabled, setTravelRuleEnabled] = useState<boolean | null>(null);

  const getActiveTab = (): ComplianceTab => {
    const path = location.pathname;
    if (path.includes('/tokens')) return 'tokens';
    if (path.includes('/travel-rules')) return 'travel-rules';
    if (path.includes('/address-thresholds')) return 'address-thresholds';
    if (path.includes('/sanctions')) return 'sanctions';
    if (path.includes('/logs')) return 'logs';
    return 'config';
  };

  const activeTab = getActiveTab();

  const loadOrganizations = async () => {
    try {
      setLoading(true);
      const response = await rbacApi.orgs.list({ limit: 1000 });
      const orgs = response.data?.data || [];
      setOrganizations(orgs);

      const orgIdFromUrl = searchParams.get('org');
      if (orgIdFromUrl) {
        const orgFromUrl = orgs.find((o: Organization) => o.id === orgIdFromUrl);
        if (orgFromUrl) {
          setSelectedOrg(orgFromUrl);
          return;
        }
      }

      if (selectedOrg) {
        const updatedOrg = orgs.find((o: Organization) => o.id === selectedOrg.id);
        if (updatedOrg) {
          setSelectedOrg(updatedOrg);
        } else if (orgs.length > 0) {
          setSelectedOrg(orgs[0]);
        } else {
          setSelectedOrg(null);
        }
      } else if (orgs.length === 1) {
        // Single-org admin: auto-select the only org so the user
        // doesn't have to interact with a one-option chooser. Mirrors
        // the RBACManager behaviour added in PR #210; the Select
        // control below is disabled via singleOrgLock when this fires.
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

  // reason: mount-only load of orgs + travel-rule status. loadOrganizations is a
  // non-memoised helper; this must run exactly once on mount, so the empty dep
  // array is intentional.
  useEffect(() => {
    loadOrganizations();
    rbacApi.status.get()
      .then(res => setTravelRuleEnabled(res.data?.security?.travel_rule_enabled ?? false))
      .catch(() => setTravelRuleEnabled(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // reason: re-derives the selected org from the URL when the org list or query
  // string changes. selectedOrg?.id is read only as a guard against a redundant
  // setState (avoiding a render loop); it is intentionally not a trigger, so it
  // is omitted from the deps.
  useEffect(() => {
    const orgIdFromUrl = searchParams.get('org');
    if (orgIdFromUrl && organizations.length > 0) {
      const org = organizations.find((o: Organization) => o.id === orgIdFromUrl);
      if (org && org.id !== selectedOrg?.id) {
        setSelectedOrg(org);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, organizations]);

  const handleOrgChange = (orgId: string) => {
    const org = organizations.find((o: Organization) => o.id === orgId);
    setSelectedOrg(org || null);
    if (org) {
      setSearchParams({ org: orgId });
    }
  };

  const handleTabChange = (value: string) => {
    const tab = value as ComplianceTab;
    const path = `/admin/compliance/${tab}`;
    if (selectedOrg) {
      navigate(`${path}?org=${selectedOrg.id}`);
    } else {
      navigate(path);
    }
  };

  // Token Prices shows system prices without org but still has a per-org section,
  // so it stays usable without a selected org. Every other tab — including
  // Sanctions — is org-scoped: the backend requires an explicit `org_id` for
  // listing org-scoped sanctions and rejects JWT-admin calls that omit it
  // (admin_compliance.go: "org_id query parameter is required"). Listing
  // global sanctions (org_id IS NULL) is super-admin only and not reachable
  // from the dashboard, so we never present "Global" as a scope option here.
  const blockedWithoutOrg = activeTab !== 'tokens' && !selectedOrg;

  // Single-org admin: lock the dropdown. After RD-916/917 a tier-2 admin
  // sees only orgs they're a member of; with exactly one such org there's
  // nothing meaningful to choose, so we pre-selected it above and disable
  // the control to avoid presenting an interactive one-item chooser.
  const singleOrgLock = organizations.length === 1;

  return (
    <CurrencyProvider orgId={selectedOrg?.id}>
    <ComplianceOrgContext.Provider
      value={{ selectedOrg, setSelectedOrg, organizations }}
    >
      <Card className="animate-fade-in">
        <CardHeader className="pb-4">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center">
                <Scale className="w-5 h-5 text-primary" />
              </div>
              <div>
                <CardTitle className="text-lg">Controls</CardTitle>
                <p className="text-sm text-neutral-500 mt-0.5">
                  Travel rule enforcement, token prices, and sanctions
                </p>
              </div>
            </div>

            <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center sm:gap-3 lg:w-auto">
              <CurrencySelector />
              <div className="w-px h-6 bg-neutral-200" />
              <span className="text-sm text-neutral-500 sm:whitespace-nowrap">Scope:</span>
              {loading ? (
                <div className="flex items-center gap-2 text-neutral-400">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Loading...</span>
                </div>
              ) : organizations.length === 0 ? (
                <Badge variant="outline" className="text-neutral-500">
                  No organizations
                </Badge>
              ) : (
                <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
                  <Select
                    value={selectedOrg?.id || ''}
                    onValueChange={handleOrgChange}
                    disabled={singleOrgLock}
                  >
                    <SelectTrigger
                      className={`w-full sm:w-[280px] ${!selectedOrg ? 'border-error ring-1 ring-error/20' : ''} ${singleOrgLock ? 'opacity-100 cursor-default' : ''}`}
                      title={singleOrgLock ? 'You administer one organization — scope is locked to it.' : undefined}
                    >
                      <SelectValue placeholder="Select organization" />
                    </SelectTrigger>
                    <SelectContent>
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
                  {!selectedOrg && !singleOrgLock && (
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
          {travelRuleEnabled === false && (
            <div className="flex items-center gap-2 p-3 mb-4 rounded-lg bg-red-50 border border-error/30 text-sm text-error-dark">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>
                Travel rule enforcement is <strong>disabled</strong> on the backend.
                Set <code className="px-1 py-0.5 rounded bg-error-light text-xs font-mono">ENABLE_TRAVEL_RULE=true</code> and restart to enforce thresholds and sanctions.
              </span>
            </div>
          )}
          <Tabs value={activeTab} onValueChange={handleTabChange}>
            <TabsList className="w-full justify-start mb-4">
              <TabsTrigger value="config" className="gap-2">
                <Settings className="w-4 h-4" />
                <span>Config</span>
              </TabsTrigger>
              <TabsTrigger value="travel-rules" className="gap-2">
                <FileText className="w-4 h-4" />
                <span>Travel Rules</span>
              </TabsTrigger>
              <TabsTrigger value="address-thresholds" className="gap-2">
                <MapPin className="w-4 h-4" />
                <span>Address Thresholds</span>
              </TabsTrigger>
              <TabsTrigger value="sanctions" className="gap-2">
                <ShieldBan className="w-4 h-4" />
                <span>Sanctions</span>
              </TabsTrigger>
              <TabsTrigger value="logs" className="gap-2">
                <ScrollText className="w-4 h-4" />
                <span>Logs</span>
              </TabsTrigger>
              <TabsTrigger value="tokens" className="gap-2">
                <Coins className="w-4 h-4" />
                <span>Token Prices</span>
              </TabsTrigger>
            </TabsList>
          </Tabs>

          {blockedWithoutOrg ? <NoOrgSelected /> : <Outlet />}
        </CardContent>
      </Card>
    </ComplianceOrgContext.Provider>
    </CurrencyProvider>
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
        Select an organization from the dropdown above to manage compliance settings
      </p>
    </div>
  );
}
