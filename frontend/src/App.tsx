import { ErrorInfo, Component, ReactNode } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Tabs, TabsList, TabsTrigger } from './components/ui/tabs';
import { Shield, Activity, ScrollText, Users, FileKey, Scale } from 'lucide-react';
import { AccountDropdown } from './components/auth/AccountDropdown';
import { TooltipProvider } from './components/ui/tooltip';

type Tab = 'rbac' | 'compliance' | 'disclosure' | 'logs' | 'diagnostics' | 'none';

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('React Error Boundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-neutral-100 flex items-center justify-center p-8">
          <div className="bg-white border border-neutral-200 rounded-xl shadow-card p-8 text-center max-w-md animate-fade-in">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-error-light flex items-center justify-center">
              <Shield className="w-8 h-8 text-error-dark" />
            </div>
            <h2 className="text-xl font-semibold text-neutral-900 mb-2">Something went wrong</h2>
            <p className="text-neutral-500 mb-6">
              {this.state.error?.message || 'An unexpected error occurred'}
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="rounded-full bg-primary px-6 py-2.5 text-white transition-colors hover:bg-primary-600 hover:shadow-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 focus-visible:ring-offset-2"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

function App() {
  const location = useLocation();
  const navigate = useNavigate();

  // Derive active tab from URL
  const getActiveTab = (): Tab => {
    if (location.pathname.includes('/account')) return 'none';
    if (location.pathname.includes('/rbac')) return 'rbac';
    if (location.pathname.includes('/compliance')) return 'compliance';
    if (location.pathname.includes('/disclosure')) return 'disclosure';
    if (location.pathname.includes('/logs')) return 'logs';
    if (location.pathname.includes('/diagnostics')) return 'diagnostics';
    // Default landing tab is RBAC (primary tier-2 admin work). The
    // diagnostics tab is intentionally last in the nav and not the
    // landing page — see findings doc #2.
    return 'rbac';
  };

  const activeTab = getActiveTab();

  const handleTabChange = (value: string) => {
    // Preserve org selection across tab switches
    const orgParam = new URLSearchParams(location.search).get('org');
    const suffix = orgParam ? `?org=${orgParam}` : '';

    switch (value) {
      case 'rbac':
        navigate('/admin/rbac' + suffix);
        break;
      case 'compliance':
        navigate('/admin/compliance' + suffix);
        break;
      case 'disclosure':
        navigate('/admin/disclosure' + suffix);
        break;
      case 'logs':
        navigate('/admin/logs');
        break;
      case 'diagnostics':
        navigate('/admin/diagnostics');
        break;
    }
  };

  return (
    <ErrorBoundary>
      <TooltipProvider delayDuration={500}>
        <div className="min-h-screen bg-neutral-100" data-testid="admin-app">
        {/* Navigation Header */}
        <header className="bg-white border-b border-neutral-200 shadow-sm sticky top-0 z-40" data-testid="admin-header">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              {/* Logo and Title */}
              <div className="flex items-center gap-3" data-testid="admin-logo">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-primary-300 flex items-center justify-center shadow-primary">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <div>
                  <h1 className="text-lg font-semibold text-neutral-900">Open Privacy Suite</h1>
                  <p className="text-xs text-neutral-500">Node Access Control</p>
                </div>
              </div>

              {/* Navigation Tabs — order: primary daily-driver tabs first
                  (RBAC → Controls → Disclosure), forensic / diagnostic
                  tabs last (Access Logs, Diagnostics). Diagnostics replaces
                  the prior "Dashboard" landing tab; its content (system
                  status + test request panel + demo deploy) is dev / ops
                  tooling, not where admins start their day. */}
              <Tabs value={activeTab} onValueChange={handleTabChange} data-testid="admin-nav">
                <TabsList>
                  <TabsTrigger value="rbac" className="gap-2" data-testid="nav-rbac">
                    <Users className="w-4 h-4" />
                    <span className="hidden sm:inline">RBAC</span>
                  </TabsTrigger>
                  <TabsTrigger value="compliance" className="gap-2">
                    <Scale className="w-4 h-4" />
                    <span className="hidden sm:inline">Controls</span>
                  </TabsTrigger>
                  <TabsTrigger value="disclosure" className="gap-2">
                    <FileKey className="w-4 h-4" />
                    <span className="hidden sm:inline">Disclosure</span>
                  </TabsTrigger>
                  <TabsTrigger value="logs" className="gap-2" data-testid="nav-logs">
                    <ScrollText className="w-4 h-4" />
                    <span className="hidden sm:inline">Access Logs</span>
                  </TabsTrigger>
                  <TabsTrigger value="diagnostics" className="gap-2" data-testid="nav-diagnostics">
                    <Activity className="w-4 h-4" />
                    <span className="hidden sm:inline">Diagnostics</span>
                  </TabsTrigger>
                </TabsList>
              </Tabs>

              {/* Account Menu */}
              <AccountDropdown />
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-6 py-8">
          <div className="animate-fade-in">
            <Outlet />
          </div>
        </main>
      </div>
      </TooltipProvider>
    </ErrorBoundary>
  );
}

export default App;
