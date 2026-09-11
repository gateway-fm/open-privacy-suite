import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { WagmiProvider } from 'wagmi';
import { RainbowKitProvider, lightTheme } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';

import { wagmiConfig } from './config/wagmi';
import { AuthProvider } from './contexts/AuthContext';
import { LoginPage } from './pages/LoginPage';
import { AzureCallbackPage } from './pages/AzureCallbackPage';
import { LinkWalletPage } from './pages/LinkWalletPage';
import { SuccessPage } from './pages/SuccessPage';
import { DisclosurePage } from './pages/DisclosurePage';
import AdminApp from './App';
import { Dashboard } from './components/dashboard/Dashboard';
import AccessLogs from './components/AccessLogs';
import RBACManager from './components/rbac/RBACManager';
import OrganizationList from './components/rbac/OrganizationList';
import GroupList from './components/rbac/GroupList';
import UserList from './components/rbac/UserList';
import ContractList from './components/rbac/ContractList';
import AzureTenantList from './components/rbac/AzureTenantList';
import ExecutionPolicy from './components/rbac/ExecutionPolicy';
import { AdminDisclosureDashboard } from './pages/admin/AdminDisclosureDashboard';
import { AccountPage } from './pages/AccountPage';
import ComplianceManager from './components/compliance/ComplianceManager';
import ComplianceConfig from './components/compliance/ComplianceConfig';
import TokenPriceList from './components/compliance/TokenPriceList';
import TravelRuleRecordList from './components/compliance/TravelRuleRecordList';
import SanctionsList from './components/compliance/SanctionsList';
import ComplianceLogList from './components/compliance/ComplianceLogList';
import AddressThresholdList from './components/compliance/AddressThresholdList';
import { RequireAuth } from './components/auth/RequireAuth';
import { RequireAdmin } from './components/auth/RequireAdmin';
import './index.css';

const queryClient = new QueryClient();

// Align wallet modal styling to Gateway light theme tokens.
const customTheme = lightTheme({
  accentColor: '#8950FA',
  accentColorForeground: 'white',
  borderRadius: 'large',
  fontStack: 'system',
  overlayBlur: 'small'
});

// reason: main.tsx is the Vite entry module — it is never imported, it only
// calls ReactDOM.createRoot().render() below. Fast Refresh cannot apply to the
// root render, so the "move component to a separate file" hint does not apply.
// eslint-disable-next-line react-refresh/only-export-components
function Root() {
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider theme={customTheme} modalSize="compact">
          <AuthProvider>
            <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
              <Routes>
                {/* Auth flow routes */}
                <Route path="/login" element={<LoginPage />} />
                <Route path="/auth/azure/callback" element={<AzureCallbackPage />} />
                <Route path="/link-wallet" element={<LinkWalletPage />} />
                <Route path="/success" element={<SuccessPage />} />
                <Route path="/disclosure" element={<DisclosurePage />} />

                {/* Admin dashboard with nested routes */}
                <Route
                  path="/admin"
                  element={(
                    <RequireAuth>
                      <RequireAdmin>
                        <AdminApp />
                      </RequireAdmin>
                    </RequireAuth>
                  )}
                >
                  <Route index element={<Navigate to="rbac" replace />} />
                  <Route path="diagnostics" element={<Dashboard />} />
                  {/* Back-compat: any old bookmark to /admin/dashboard
                      lands on the renamed Diagnostics tab. */}
                  <Route path="dashboard" element={<Navigate to="/admin/diagnostics" replace />} />
                  <Route path="logs" element={<AccessLogs />} />
                  <Route path="rbac" element={<RBACManager />}>
                    <Route index element={<Navigate to="organizations" replace />} />
                    <Route path="organizations" element={<OrganizationList />} />
                    <Route path="groups" element={<GroupList />} />
                    <Route path="users" element={<UserList />} />
                    <Route path="users/:userId" element={<UserList />} />
                    <Route path="contracts" element={<ContractList />} />
                    <Route path="execution-policy" element={<ExecutionPolicy />} />
                    <Route path="azure-tenants" element={<AzureTenantList />} />
                  </Route>
                  <Route path="compliance" element={<ComplianceManager />}>
                    <Route index element={<Navigate to="config" replace />} />
                    <Route path="config" element={<ComplianceConfig />} />
                    <Route path="tokens" element={<TokenPriceList />} />
                    <Route path="travel-rules" element={<TravelRuleRecordList />} />
                    <Route path="address-thresholds" element={<AddressThresholdList />} />
                    <Route path="sanctions" element={<SanctionsList />} />
                    <Route path="logs" element={<ComplianceLogList />} />
                  </Route>
                  <Route path="disclosure" element={<AdminDisclosureDashboard />} />
                  <Route path="account" element={<AccountPage />} />
                </Route>

                {/* Default redirect to login */}
                <Route path="/" element={<Navigate to="/login" replace />} />

                {/* Catch all - redirect to login */}
                <Route path="*" element={<Navigate to="/login" replace />} />
              </Routes>
            </BrowserRouter>
          </AuthProvider>
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
