import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Copy, Check, Wallet, Key, RefreshCw, FileKey, Building2, LayoutDashboard } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { AlertDialog } from '@/components/ui/ConfirmDialog';
import { useAuth } from '@/contexts/AuthContext';
import { useAdminStatus } from '@/hooks/useAdminStatus';
import { ethLinkApiMethods, EthAddressResponse, userApiMethods, UserOrg } from '@/api/auth';
import { getRpcEndpoint, getAddNetworkParams } from '@/config/rpc';

export function SuccessPage() {
  const navigate = useNavigate();
  const { isAuthenticated, accessToken, userDID, logout, isLoading } = useAuth();
  const [copied, setCopied] = useState<string | null>(null);
  const [linkedAddresses, setLinkedAddresses] = useState<EthAddressResponse[]>([]);
  const [userOrgs, setUserOrgs] = useState<UserOrg[]>([]);
  const [isAddingNetwork, setIsAddingNetwork] = useState(false);
  const [showMetaMaskError, setShowMetaMaskError] = useState(false);
  const { isAdmin, loading: adminStatusLoading } = useAdminStatus();

  const rpcEndpoint = getRpcEndpoint();

  // Redirect if not authenticated (wait for auth to load first)
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, isLoading, navigate]);

  // Load linked addresses
  useEffect(() => {
    if (!accessToken) return;

    const loadAddresses = async () => {
      try {
        const response = await ethLinkApiMethods.getAddresses(accessToken);
        setLinkedAddresses(response.addresses);
      } catch {
        // No addresses
      }
    };

    loadAddresses();
  }, [accessToken]);

  // Load user organizations
  useEffect(() => {
    if (!accessToken) return;

    const loadOrgs = async () => {
      try {
        const response = await userApiMethods.getMyOrganizations(accessToken);
        setUserOrgs(response.organizations);
      } catch {
        // No orgs or error
      }
    };

    loadOrgs();
  }, [accessToken]);

  // Copy to clipboard with fallback for mobile
  const copyToClipboard = async (text: string, type: string) => {
    try {
      // Try modern clipboard API first
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for older browsers/mobile
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }
      setCopied(type);
      setTimeout(() => setCopied(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
      // Show the text in a prompt as last resort
      window.prompt('Copy this text:', text);
    }
  };

  // Add network to MetaMask
  const handleAddToMetaMask = async () => {
    if (!window.ethereum) {
      setShowMetaMaskError(true);
      return;
    }

    setIsAddingNetwork(true);
    try {
      const params = getAddNetworkParams();
      await window.ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [params],
      });
    } catch (err) {
      console.error('Failed to add network:', err);
    } finally {
      setIsAddingNetwork(false);
    }
  };

  // Show nothing while auth state is being restored (prevents stale-state flash)
  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-neutral-100">
        <div className="flex items-center gap-2 text-neutral-500">
          <Shield className="h-5 w-5 animate-pulse text-primary" />
          <span className="text-sm">Loading…</span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-100 p-4" data-testid="success-page">
      <div className="w-full max-w-lg animate-fade-in-up">
        {/* Success Header */}
        <div className="text-center mb-8" data-testid="success-header">
          <div className="mx-auto mb-4 flex h-20 w-20 items-center justify-center rounded-2xl bg-gradient-to-br from-primary to-primary-300 shadow-lg shadow-primary animate-scale-in">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-neutral-900" data-testid="success-title">You're All Set!</h1>
          <p className="mt-2 text-neutral-500">
            Your authenticated RPC endpoint is ready to use
          </p>

          {/* Org admins land here like everyone else; without this the admin
              dashboard is only reachable by typing /admin into the address
              bar. Rendered only when the admin-status probe says yes — the
              route itself is still gated by RequireAdmin. */}
          {/* Fixed-height slot: the admin probe resolves a round trip after
              first paint, so rendering the button straight into the flow
              would shove the whole page down once it lands. Reserving the
              space costs regular users some whitespace and nobody a jump. */}
          <div className="mt-4 flex h-10 items-center justify-center">
            {!adminStatusLoading && isAdmin && (
              <Button
                onClick={() => navigate('/admin')}
                variant="outline"
                data-testid="go-to-admin-btn"
              >
                <LayoutDashboard className="mr-2 h-4 w-4" />
                Admin dashboard
              </Button>
            )}
          </div>
        </div>

        {/* RPC Endpoint Card */}
        <Card variant="default" className="mb-4" data-testid="rpc-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="w-5 h-5 text-primary" />
              Your RPC Endpoint
            </CardTitle>
            <CardDescription>
              Use this endpoint in your dApps and wallets
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* RPC URL */}
            <div className="space-y-2">
              <label className="text-xs text-neutral-400 uppercase tracking-wide">
                RPC URL
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 p-3 bg-neutral-100 rounded-lg font-mono text-sm text-neutral-900 overflow-x-auto" data-testid="rpc-endpoint">
                  {rpcEndpoint}
                </code>
                <Button
                  onClick={() => copyToClipboard(rpcEndpoint, 'rpc')}
                  variant="outline"
                  size="icon"
                  className="flex-shrink-0"
                  data-testid="copy-rpc-btn"
                >
                  {copied === 'rpc' ? (
                    <Check className="w-4 h-4 text-success-dark" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </div>

            {/* Access Token */}
            {accessToken && (
              <div className="space-y-2">
              <label className="text-xs text-neutral-400 uppercase tracking-wide">
                Access Token (for Authorization header)
              </label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 p-3 bg-neutral-100 rounded-lg font-mono text-xs text-neutral-700 overflow-hidden text-ellipsis">
                    Bearer {accessToken.slice(0, 20)}...{accessToken.slice(-10)}
                  </code>
                  <Button
                    onClick={() => copyToClipboard(accessToken, 'token')}
                    variant="outline"
                    size="icon"
                    className="flex-shrink-0"
                    title="Copy token"
                    data-testid="copy-token-btn"
                  >
                    {copied === 'token' ? (
                      <Check className="w-4 h-4 text-success-dark" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </Button>
                </div>
                {/* Foundry/Hardhat export command */}
                <div className="flex items-center gap-2 mt-2">
                  <Button
                    onClick={() => copyToClipboard(`export ETH_RPC_HEADERS="Authorization: Bearer ${accessToken}"`, 'foundry')}
                    variant="outline"
                    size="sm"
                    className="flex-1 text-xs"
                    data-testid="copy-foundry-btn"
                  >
                    {copied === 'foundry' ? (
                      <Check className="w-3 h-3 mr-2 text-success-dark" />
                    ) : (
                      <Copy className="w-3 h-3 mr-2" />
                    )}
                    Copy for Foundry/Hardhat
                  </Button>
                </div>
                <p className="text-xs text-neutral-400">
                  Token expires in 30 minutes. Use with <code className="bg-neutral-100 px-1 rounded">forge script --rpc-url {rpcEndpoint}</code>
                </p>
              </div>
            )}

            {/* Add to MetaMask */}
            <Button
              onClick={handleAddToMetaMask}
              variant="default"
              className="w-full"
              disabled={isAddingNetwork}
              data-testid="add-metamask-btn"
            >
              {isAddingNetwork ? (
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <svg className="w-5 h-5 mr-2" viewBox="0 0 35 33" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M32.9582 1L19.8241 10.7183L22.2665 4.99099L32.9582 1Z" fill="#E17726" stroke="#E17726" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M2.04858 1L15.0707 10.809L12.7396 4.99098L2.04858 1Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M28.2292 23.5334L24.7346 28.872L32.2175 30.9323L34.3611 23.6501L28.2292 23.5334Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M0.658203 23.6501L2.79013 30.9323L10.2614 28.872L6.77844 23.5334L0.658203 23.6501Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M9.87524 14.5149L7.79297 17.6507L15.1838 17.9891L14.9369 9.97729L9.87524 14.5149Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M25.1313 14.5149L19.9929 9.88647L19.824 17.9891L27.2149 17.6507L25.1313 14.5149Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.2614 28.872L14.7347 26.7067L10.8714 23.7034L10.2614 28.872Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.2715 26.7067L24.7346 28.872L24.1363 23.7034L20.2715 26.7067Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M24.7346 28.8721L20.2715 26.7068L20.6352 29.6168L20.5986 30.8407L24.7346 28.8721Z" fill="#D5BFB2" stroke="#D5BFB2" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.2614 28.8721L14.4091 30.8407L14.3842 29.6168L14.7347 26.7068L10.2614 28.8721Z" fill="#D5BFB2" stroke="#D5BFB2" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M14.4854 21.7842L10.7642 20.6903L13.3685 19.4897L14.4854 21.7842Z" fill="#233447" stroke="#233447" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.5208 21.7842L21.6377 19.4897L24.2536 20.6903L20.5208 21.7842Z" fill="#233447" stroke="#233447" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.2614 28.872L10.8948 23.5334L6.77844 23.6501L10.2614 28.872Z" fill="#CC6228" stroke="#CC6228" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M24.1113 23.5334L24.7347 28.872L28.2293 23.6501L24.1113 23.5334Z" fill="#CC6228" stroke="#CC6228" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M27.2149 17.6507L19.824 17.9891L20.5208 21.7842L21.6377 19.4897L24.2536 20.6903L27.2149 17.6507Z" fill="#CC6228" stroke="#CC6228" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.7643 20.6903L13.3685 19.4897L14.4854 21.7842L15.1839 17.9891L7.79297 17.6507L10.7643 20.6903Z" fill="#CC6228" stroke="#CC6228" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M7.79297 17.6507L10.8714 23.7034L10.7643 20.6903L7.79297 17.6507Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M24.2536 20.6903L24.1364 23.7034L27.2149 17.6507L24.2536 20.6903Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M15.1839 17.9891L14.4854 21.7842L15.3573 26.2285L15.5546 20.3519L15.1839 17.9891Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M19.824 17.9891L19.4649 20.3402L19.6489 26.2285L20.5208 21.7842L19.824 17.9891Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.5207 21.7842L19.6489 26.2285L20.2714 26.7068L24.1363 23.7034L24.2535 20.6903L20.5207 21.7842Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.7642 20.6903L10.8714 23.7034L14.7346 26.7068L15.3572 26.2285L14.4853 21.7842L10.7642 20.6903Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.5986 30.8407L20.6352 29.6168L20.2964 29.3251H14.7098L14.3842 29.6168L14.4091 30.8407L10.2614 28.8721L11.6684 30.0261L14.6566 32.1097H20.3447L23.3446 30.0261L24.7346 28.8721L20.5986 30.8407Z" fill="#C0AC9D" stroke="#C0AC9D" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.2715 26.7068L19.649 26.2285H15.3573L14.7348 26.7068L14.3843 29.6168L14.7099 29.3251H20.2965L20.6353 29.6168L20.2715 26.7068Z" fill="#161616" stroke="#161616" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M33.5167 11.3532L34.6585 5.98873L32.9582 1L20.2715 10.3799L25.1312 14.5149L32.0442 16.5286L33.5765 14.7384L32.9116 14.2601L33.9801 13.2845L33.1663 12.4922L34.2349 11.6649L33.5167 11.3532Z" fill="#763E1A" stroke="#763E1A" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M0.347656 5.98873L1.48956 11.3532L0.759557 11.6649L1.83988 12.4922L1.02615 13.2845L2.09481 14.2601L1.42989 14.7384L2.9622 16.5286L9.87528 14.5149L14.735 10.3799L2.04838 1L0.347656 5.98873Z" fill="#763E1A" stroke="#763E1A" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M32.0442 16.5285L25.1312 14.5149L27.2148 17.6507L24.1364 23.7034L28.2293 23.6501H34.361L32.0442 16.5285Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M9.87534 14.5149L2.96226 16.5285L0.658203 23.6501H6.77844L10.8714 23.7034L7.79299 17.6507L9.87534 14.5149Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M19.8241 17.989L20.2713 10.3799L22.2666 4.99097H12.7395L14.7348 10.3799L15.1837 17.989L15.3443 20.3635L15.3576 26.2285H19.6493L19.6626 20.3635L19.8241 17.989Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              )}
              Add Network to MetaMask
            </Button>
          </CardContent>
        </Card>

        {/* Identity Info */}
        <Card variant="default" className="mb-4">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-primary-50">
                  <Shield className="h-5 w-5 text-primary" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-neutral-900">
                    {userDID?.startsWith('azuread:') ? 'Microsoft Entra ID' : 'Privado ID'}
                  </p>
                  <p className="truncate font-mono text-xs text-neutral-400" title={userDID || 'Connected'}>
                    {userDID || 'Connected'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {userDID && (
                  <Button
                    onClick={() => copyToClipboard(userDID, 'did')}
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    title="Copy DID"
                  >
                    {copied === 'did' ? (
                      <Check className="w-4 h-4 text-success-dark" />
                    ) : (
                      <Copy className="w-4 h-4 text-neutral-400" />
                    )}
                  </Button>
                )}
                <div className="flex items-center gap-2 text-xs text-success-dark">
                  <div className="h-2 w-2 rounded-full bg-success animate-pulse" />
                  Verified
                </div>
              </div>
            </div>

            {/* Linked wallets */}
            {linkedAddresses.length > 0 && (
              <div className="mt-4 pt-4 border-t border-neutral-200">
                <p className="text-xs text-neutral-400 mb-2">Linked Wallets</p>
                <div className="space-y-2">
                  {linkedAddresses.map((addr) => (
                    <div
                      key={addr.address}
                      className="flex items-center gap-2 rounded-lg bg-neutral-100 p-2"
                    >
                      <Wallet className="h-3 w-3 flex-shrink-0 text-primary" />
                      <span className="flex-1 break-all font-mono text-xs text-neutral-700">
                        {addr.address}
                      </span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(addr.address, addr.address)}
                        className="flex-shrink-0 rounded p-1 text-neutral-400 transition-colors hover:text-neutral-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                        title="Copy address"
                        aria-label={`Copy wallet address ${addr.address}`}
                      >
                        {copied === addr.address ? (
                          <Check className="h-3 w-3 text-success-dark" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Organizations */}
            {userOrgs.length > 0 && (
              <div className="mt-4 pt-4 border-t border-neutral-200">
                <p className="text-xs text-neutral-400 mb-2">
                  Organizations {userOrgs.length > 1 && <span className="text-warning-dark">(multi-org: use org ID in RPC URL)</span>}
                </p>
                <div className="space-y-2">
                  {userOrgs.map((org) => (
                    <div
                      key={org.id}
                      className="flex items-center gap-2 rounded-lg bg-neutral-100 p-2"
                    >
                      <Building2 className="h-3 w-3 flex-shrink-0 text-primary" />
                      <div className="flex-1 min-w-0">
                        <span className="block text-xs font-medium text-neutral-700">{org.name}</span>
                        <span className="block truncate font-mono text-xs text-neutral-400" title={org.id}>
                          {org.id}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(org.id, `org-${org.id}`)}
                        className="flex-shrink-0 rounded p-1 text-neutral-400 transition-colors hover:text-neutral-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                        title="Copy org ID for RPC URL"
                        data-testid={`copy-org-${org.slug}`}
                        aria-label={`Copy organization ID for ${org.name}`}
                      >
                        {copied === `org-${org.id}` ? (
                          <Check className="h-3 w-3 text-success-dark" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
                {userOrgs.length > 1 && (
                  <p className="text-xs text-neutral-400 mt-2">
                    Use <code className="bg-neutral-100 px-1 rounded">{rpcEndpoint}/{'<org-id>'}</code> to deploy to a specific org
                  </p>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Usage Examples */}
        <Card variant="default">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Quick Start</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="text-xs text-neutral-400 mb-1">Foundry (cast)</p>
              <pre className="p-2 bg-neutral-100 rounded text-xs font-mono text-neutral-700 overflow-x-auto">
{`# Set auth header (use "Copy for Foundry" button above)
export ETH_RPC_HEADERS="Authorization: Bearer <token>"

# Query the chain
cast block-number --rpc-url ${rpcEndpoint}
cast balance <address> --rpc-url ${rpcEndpoint}`}
              </pre>
            </div>

            <div>
              <p className="text-xs text-neutral-400 mb-1">cURL</p>
              <pre className="p-2 bg-neutral-100 rounded text-xs font-mono text-neutral-700 overflow-x-auto">
{`curl ${rpcEndpoint} \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}'`}
              </pre>
            </div>

            <div>
              <p className="text-xs text-neutral-400 mb-1">ethers.js</p>
              <pre className="p-2 bg-neutral-100 rounded text-xs font-mono text-neutral-700 overflow-x-auto">
{`const provider = new ethers.JsonRpcProvider(
  "${rpcEndpoint}",
  undefined,
  { headers: { "Authorization": "Bearer <token>" } }
);`}
              </pre>
            </div>
          </CardContent>
        </Card>

        {/* Actions */}
        <div className="mt-6 flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <Button
              onClick={() => navigate('/link-wallet')}
              variant="outline"
              size="sm"
              className="flex-1"
            >
              <Wallet className="w-4 h-4 mr-2" />
              Manage Wallets
            </Button>
            <Button
              onClick={() => navigate('/disclosure')}
              variant="outline"
              size="sm"
              className="flex-1"
            >
              <FileKey className="w-4 h-4 mr-2" />
              Data Disclosure
            </Button>
          </div>
          <div className="text-center">
            <button
              type="button"
              onClick={logout}
              className="rounded px-1 text-sm text-neutral-400 transition-colors hover:text-neutral-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
            >
              Sign out
            </button>
          </div>
        </div>

        {/* MetaMask Not Installed Alert */}
        <AlertDialog
          open={showMetaMaskError}
          onOpenChange={setShowMetaMaskError}
          title="MetaMask Not Found"
          description="MetaMask is not installed. Please install MetaMask to add this network."
          buttonLabel="OK"
          variant="warning"
        />
      </div>
    </div>
  );
}
