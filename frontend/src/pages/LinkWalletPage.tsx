import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAccount, useSignMessage, useDisconnect } from 'wagmi';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { Wallet, Link2, Loader2, CheckCircle2, AlertCircle, ArrowRight, X, Copy, Check, LayoutDashboard } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { useAdminStatus } from '@/hooks/useAdminStatus';
import { ethLinkApiMethods, EthAddressResponse } from '@/api/auth';

type LinkStep = 'connect' | 'signing' | 'verifying' | 'success' | 'error';

interface LinkState {
  step: LinkStep;
  nonce: string | null;
  message: string | null;
  error: string | null;
  linkedAddresses: EthAddressResponse[];
}

export function LinkWalletPage() {
  const navigate = useNavigate();
  const { isAuthenticated, accessToken, logout, isLoading } = useAuth();
  const { isAdmin } = useAdminStatus();
  const { address, isConnected } = useAccount();
  const { disconnect } = useDisconnect();
  const { signMessageAsync } = useSignMessage();

  const [state, setState] = useState<LinkState>({
    step: 'connect',
    nonce: null,
    message: null,
    error: null,
    linkedAddresses: [],
  });
  const [isLinking, setIsLinking] = useState(false);
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);
  const [unlinkError, setUnlinkError] = useState<string | null>(null);

  // Copy address to clipboard
  const copyToClipboard = async (address: string) => {
    await navigator.clipboard.writeText(address);
    setCopiedAddress(address);
    setTimeout(() => setCopiedAddress(null), 2000);
  };

  // Redirect if not authenticated (wait for auth to load first)
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, isLoading, navigate]);

  // Load existing linked addresses
  useEffect(() => {
    if (!accessToken) return;

    const loadAddresses = async () => {
      try {
        const response = await ethLinkApiMethods.getAddresses(accessToken);
        setState(prev => ({ ...prev, linkedAddresses: response.addresses }));
      } catch {
        // No linked addresses yet
      }
    };

    loadAddresses();
  }, [accessToken]);

  // Check if current address is already linked
  const isCurrentAddressLinked = address
    ? state.linkedAddresses.some(
        a => a.address.toLowerCase() === address.toLowerCase()
      )
    : false;

  // Handle wallet link
  const handleLinkWallet = async () => {
    if (!accessToken || !address || !isConnected) return;

    setIsLinking(true);
    setState(prev => ({ ...prev, step: 'signing', error: null }));

    try {
      // Step 1: Get challenge
      const challenge = await ethLinkApiMethods.getChallenge(accessToken);
      setState(prev => ({
        ...prev,
        nonce: challenge.nonce,
        message: challenge.message,
      }));

      // Step 2: Sign message
      const signature = await signMessageAsync({ message: challenge.message });

      setState(prev => ({ ...prev, step: 'verifying' }));

      // Step 3: Verify signature and link
      await ethLinkApiMethods.verifyLink(
        accessToken,
        challenge.nonce,
        address,
        signature
      );

      // Refresh linked addresses
      const response = await ethLinkApiMethods.getAddresses(accessToken);
      setState(prev => ({
        ...prev,
        step: 'success',
        linkedAddresses: response.addresses,
      }));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to link wallet';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    } finally {
      setIsLinking(false);
    }
  };

  // Handle unlink
  const handleUnlink = async (addressToUnlink: string) => {
    if (!accessToken) return;
    setUnlinkError(null);

    try {
      await ethLinkApiMethods.unlinkAddress(accessToken, addressToUnlink);
      setState(prev => ({
        ...prev,
        linkedAddresses: prev.linkedAddresses.filter(
          a => a.address.toLowerCase() !== addressToUnlink.toLowerCase()
        ),
      }));
    } catch {
      setUnlinkError('Failed to unlink address. Please try again.');
    }
  };

  // Continue to success page
  const handleContinue = () => {
    navigate('/success');
  };

  // Skip wallet linking
  const handleSkip = () => {
    navigate('/success');
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-100 p-4" data-testid="link-wallet-page">
      <div className="w-full max-w-md animate-fade-in-up">
        {/* Header */}
        <div className="text-center mb-8" data-testid="link-wallet-header">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-primary to-primary-300 shadow-lg shadow-primary">
            <Wallet className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-neutral-900">Link Your Wallet</h1>
          <p className="mt-1 text-neutral-500">Connect an Ethereum address</p>
        </div>

        {/* Main Card */}
        <Card variant="default" data-testid="link-wallet-card">
          <CardHeader className="text-center">
            <CardTitle data-testid="link-wallet-title">Connect & Sign</CardTitle>
            <CardDescription>
              Link your Ethereum wallet to your identity for seamless RPC access
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Wallet Connection */}
            <div className="flex flex-col items-center gap-4">
              <ConnectButton.Custom>
                {({
                  account,
                  chain,
                  openConnectModal,
                  openChainModal,
                  mounted,
                }) => {
                  const connected = mounted && account && chain;

                  return (
                    <div className="w-full">
                      {!connected ? (
                        <Button
                          onClick={openConnectModal}
                          variant="default"
                          size="lg"
                          className="w-full"
                          data-testid="connect-wallet-btn"
                        >
                          <Wallet className="w-5 h-5 mr-2" />
                          Connect Wallet
                        </Button>
                      ) : (
                        <div className="space-y-3 rounded-xl border border-neutral-200 bg-white p-4 shadow-card" data-testid="wallet-connected">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary-50">
                                <Wallet className="h-5 w-5 text-primary" />
                              </div>
                              <div>
                                <p className="text-sm font-medium text-neutral-900" data-testid="wallet-address">
                                  {account.displayName}
                                </p>
                                <button
                                  type="button"
                                  onClick={openChainModal}
                                  className="flex items-center gap-1 rounded px-1 text-xs text-neutral-400 transition-colors hover:text-neutral-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                                >
                                  {chain.name}
                                </button>
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={() => disconnect()}
                              className="rounded p-1 text-neutral-400 transition-colors hover:text-neutral-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                              aria-label="Disconnect wallet"
                            >
                              <X className="w-4 h-4" />
                            </button>
                          </div>

                          {/* Link button */}
                          {!isCurrentAddressLinked ? (
                            <Button
                              onClick={handleLinkWallet}
                              disabled={isLinking}
                              variant="default"
                              className="w-full"
                              data-testid="sign-link-btn"
                            >
                              {isLinking ? (
                                <>
                                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                  {state.step === 'signing' && 'Sign in wallet...'}
                                  {state.step === 'verifying' && 'Verifying...'}
                                </>
                              ) : (
                                <>
                                  <Link2 className="w-4 h-4 mr-2" />
                                  Sign & Link Address
                                </>
                              )}
                            </Button>
                          ) : (
                            <div className="flex items-center justify-center gap-2 text-sm text-success-dark" data-testid="address-linked">
                              <CheckCircle2 className="w-4 h-4" />
                              Address linked
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                }}
              </ConnectButton.Custom>
            </div>

            {/* Error display */}
            {state.step === 'error' && state.error && (
              <div className="flex items-start gap-3 rounded-lg border border-error/30 bg-error-light p-3">
                <AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-error-dark" />
                <div>
                  <p className="text-sm font-medium text-error-dark">Error</p>
                  <p className="text-xs text-error-dark">{state.error}</p>
                </div>
              </div>
            )}

            {unlinkError && (
              <div className="flex items-start gap-3 rounded-lg border border-error/30 bg-error-light p-3">
                <AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-error-dark" />
                <p className="text-sm text-error-dark">{unlinkError}</p>
              </div>
            )}

            {/* Linked Addresses List */}
            {state.linkedAddresses.length > 0 && (
              <div className="space-y-3" data-testid="linked-addresses">
                <h3 className="text-sm font-medium text-neutral-700">Linked Addresses</h3>
                <div className="space-y-2">
                  {state.linkedAddresses.map((linked) => (
                    <div
                      key={linked.address}
                      className="flex items-center justify-between gap-2 rounded-lg bg-neutral-100 p-3"
                    >
                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        <CheckCircle2 className="h-4 w-4 flex-shrink-0 text-success-dark" />
                        <span className="font-mono text-xs text-neutral-700 break-all">
                          {linked.address}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <button
                          type="button"
                          onClick={() => copyToClipboard(linked.address)}
                          className="rounded p-1 text-neutral-400 transition-colors hover:text-neutral-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                          title="Copy address"
                          aria-label={`Copy address ${linked.address}`}
                        >
                          {copiedAddress === linked.address ? (
                            <Check className="h-4 w-4 text-success-dark" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleUnlink(linked.address)}
                          className="rounded px-1 py-0.5 text-xs text-neutral-400 transition-colors hover:text-error-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                        >
                          Unlink
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Action buttons */}
            <div className="flex flex-col gap-3 border-t border-neutral-200 pt-4">
              <Button
                onClick={handleContinue}
                variant="success"
                size="lg"
                className="w-full"
                disabled={state.linkedAddresses.length === 0}
                data-testid="continue-btn"
              >
                Continue
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>

              {state.linkedAddresses.length === 0 && (
                <Button
                  onClick={handleSkip}
                  variant="ghost"
                  size="sm"
                  className="w-full text-neutral-400"
                  data-testid="skip-btn"
                >
                  Skip for now
                </Button>
              )}

              {/* Login lands here by default, not on the user page, so without
                  this an admin has to clear the wallet step before the way
                  into the dashboard is even visible. */}
              {isAdmin && (
                <Button
                  onClick={() => navigate('/admin')}
                  variant="ghost"
                  size="sm"
                  className="w-full"
                  data-testid="link-wallet-admin-btn"
                >
                  <LayoutDashboard className="mr-2 h-4 w-4" />
                  Go to admin dashboard
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Logout option */}
        <div className="mt-6 text-center">
          <button
            type="button"
            onClick={logout}
            className="rounded px-1 text-sm text-neutral-400 underline underline-offset-2 transition-colors hover:text-neutral-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  );
}
