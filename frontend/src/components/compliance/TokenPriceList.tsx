import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog';
import {
  Select as UISelect,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Loader2, Plus, AlertCircle, Pencil, Trash2, Coins, AlertTriangle, RefreshCw } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import { useCurrency } from './CurrencyContext';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { useManagedStream } from '@/hooks/useManagedStream';
import ManagedStreamNotice from '@/components/rbac/ManagedStreamNotice';
import type { TokenPrice, UpsertTokenPriceInput, SystemTokenPrice } from '@/types/compliance';

// CoinGecko source options
const COINGECKO_OPTIONS = [
  { id: 'ethereum', label: 'CoinGecko: ETH', symbol: 'ETH', decimals: 18 },
  { id: 'tether', label: 'CoinGecko: USDT', symbol: 'USDT', decimals: 6 },
  { id: 'usd-coin', label: 'CoinGecko: USDC', symbol: 'USDC', decimals: 6 },
];

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function TokenPriceList() {
  const { selectedOrg } = useComplianceOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const { formatAmount, currencyLabel, coingeckoEnabled, currency } = useCurrency();
  const orgId = selectedOrg?.id;
  // Token entries belong to the compliance document once one is active.
  const { managed, checked } = useManagedStream('compliance', orgId);
  const canEdit = !isReadonlyAdmin && checked && !managed;

  const [tokens, setTokens] = useState<TokenPrice[]>([]);
  const [systemPrices, setSystemPrices] = useState<SystemTokenPrice[]>([]);
  const [loading, setLoading] = useState(!!orgId);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<TokenPrice | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<TokenPrice | null>(null);

  // Form state
  const [formAddress, setFormAddress] = useState('');
  const [formSymbol, setFormSymbol] = useState('');
  const [formDecimals, setFormDecimals] = useState('18');
  const [formPrice, setFormPrice] = useState('');
  const [formSource, setFormSource] = useState<string>('manual');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);

  const loadSystemPrices = async () => {
    try {
      const response = await complianceApi.systemPrices.list();
      setSystemPrices(response.data.data || []);
    } catch {
      // Not critical — system prices may not be available yet
      setSystemPrices([]);
    }
  };

  const loadTokens = async () => {
    if (!orgId) {
      setTokens([]);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.tokens.list(orgId);
      setTokens(response.data.data || []);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setTokens([]);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load token prices');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSystemPrices();
  }, [currency]);

  // reason: intentional reload when orgId/currency change. loadTokens is a
  // non-memoised helper that reads current state via closure; adding it to deps
  // would require useCallback and risk a refetch loop.
  useEffect(() => {
    loadTokens();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, currency]);

  const openCreateForm = () => {
    setEditing(null);
    setFormAddress('native');
    setFormSymbol('ETH');
    setFormDecimals('18');
    setFormPrice('');
    setFormSource('manual');
    setFormError(null);
    setShowForm(true);
  };

  const openEditForm = (token: TokenPrice) => {
    setEditing(token);
    setFormAddress(token.token_address);
    setFormSymbol(token.symbol);
    setFormDecimals(String(token.decimals));
    setFormPrice(String(token.price_fiat));
    setFormSource(token.coingecko_id || 'manual');
    setFormError(null);
    setShowForm(true);
  };

  const handleSourceChange = (source: string) => {
    setFormSource(source);
    if (source !== 'manual') {
      const opt = COINGECKO_OPTIONS.find(o => o.id === source);
      if (opt) {
        setFormSymbol(opt.symbol);
        setFormDecimals(String(opt.decimals));
        setFormPrice('0');
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;

    const address = editing ? editing.token_address : formAddress.trim().toLowerCase();
    if (!address) {
      setFormError('Token address is required');
      return;
    }
    if (address !== 'native' && !/^0x[0-9a-f]{40}$/.test(address)) {
      setFormError('Token address must be "native" or a valid 0x-prefixed Ethereum address (42 characters)');
      return;
    }

    const isCoingecko = formSource !== 'manual';
    const priceVal = parseFloat(formPrice) || 0;

    if (!formSymbol.trim()) {
      setFormError('Symbol is required');
      return;
    }
    if (!isCoingecko && priceVal <= 0) {
      setFormError('Price must be greater than 0 for manual pricing');
      return;
    }

    const input: UpsertTokenPriceInput = {
      symbol: formSymbol.trim(),
      decimals: parseInt(formDecimals) || 18,
      coingecko_id: isCoingecko ? formSource : null,
      prices: isCoingecko ? undefined : { [currency]: priceVal },
    };

    try {
      setFormSaving(true);
      setFormError(null);
      await complianceApi.tokens.upsert(orgId, address, input);
      setShowForm(false);
      loadTokens();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to save token price');
    } finally {
      setFormSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!orgId || !deleteTarget) return;
    try {
      await complianceApi.tokens.delete(orgId, deleteTarget.token_address);
      setDeleteTarget(null);
      loadTokens();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to delete token price');
    }
  };

  // Resolve displayed price for CoinGecko-mapped tokens
  const getResolvedPrice = (token: TokenPrice): { price: number; stale: boolean; updatedAt: string | null } => {
    if (token.coingecko_id) {
      const sys = systemPrices.find(s => s.coingecko_id === token.coingecko_id);
      if (sys && sys.price_fiat > 0) {
        return { price: sys.price_fiat, stale: sys.is_stale, updatedAt: sys.updated_at };
      }
      return { price: 0, stale: false, updatedAt: null };
    }
    return { price: token.price_fiat, stale: false, updatedAt: token.updated_at };
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
      </div>
    );
  }

  const coingeckoPrices = systemPrices.filter(sp => sp.source === 'coingecko');

  const renderPriceCard = (sp: SystemTokenPrice) => (
    <div
      key={sp.id}
      className={`p-4 rounded-lg border ${
        sp.price_fiat === 0
          ? 'bg-[#FEF2F2] border-[#FECACA]'
          : sp.is_stale
          ? 'bg-[#FFFBEB] border-[#FDE68A]'
          : 'bg-[#F0FDF4] border-[#BBF7D0]'
      }`}
    >
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5">
          <span className="font-medium text-[#374151]">{sp.symbol}</span>
          {sp.source && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0">
              {sp.source}
            </Badge>
          )}
        </div>
        <Badge
          variant={sp.price_fiat === 0 ? 'destructive' : sp.is_stale ? 'warning' : 'success'}
          className="text-xs"
        >
          {sp.price_fiat === 0 ? 'Unavailable' : sp.is_stale ? 'Stale' : 'Live'}
        </Badge>
      </div>
      <div className="text-xl font-semibold text-[#111827]">
        {sp.price_fiat === 0 ? '—' : formatAmount(sp.price_fiat)}
      </div>
      <div className="text-xs text-[#94A3B8] mt-1">
        {sp.price_fiat === 0 ? (
          <span className="text-[#991B1B] flex items-center gap-1">
            <AlertCircle className="w-3 h-3" />
            Price unavailable — add manual override
          </span>
        ) : sp.is_stale ? (
          <span className="text-[#92400E] flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" />
            Last updated {timeAgo(sp.updated_at)}
          </span>
        ) : (
          `Updated ${timeAgo(sp.updated_at)}`
        )}
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* CoinGecko Prices Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-neutral-500 uppercase tracking-wide">
            Auto-Fetched Prices (CoinGecko)
            {!coingeckoEnabled && (
              <Badge variant="outline" className="ml-2 text-[10px] px-1.5 py-0">Disabled</Badge>
            )}
          </h3>
          <Button variant="ghost" size="sm" onClick={loadSystemPrices}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" />
            Refresh
          </Button>
        </div>

        {!coingeckoEnabled ? (
          <div className="p-4 rounded-lg bg-neutral-100 border border-neutral-200 text-sm text-neutral-500">
            CoinGecko price fetching is disabled. Set <code className="text-xs bg-neutral-100 px-1 py-0.5 rounded">DISABLE_COINGECKO=false</code> to enable automatic price fetching.
          </div>
        ) : coingeckoPrices.length === 0 ? (
          <div className="p-4 rounded-lg bg-neutral-100 border border-neutral-200 text-sm text-neutral-500">
            No CoinGecko prices available. Prices will appear after the first CoinGecko fetch.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {coingeckoPrices.map(renderPriceCard)}
          </div>
        )}
      </div>

      {/* Per-Org Token Prices */}
      <div className="space-y-4">
        {/* Warning banner for tokens blocking transactions */}
        {(() => {
          const blockedTokens = tokens.filter(t => {
            if (t.coingecko_id) return false; // CoinGecko tokens resolve from system prices
            return t.price_fiat === 0;
          });
          if (blockedTokens.length === 0) return null;
          return (
            <div className="flex items-start gap-3 p-4 rounded-lg bg-red-50 border border-red-200 text-red-800">
              <AlertTriangle className="w-5 h-5 mt-0.5 shrink-0 text-red-600" />
              <div>
                <p className="font-semibold text-sm">
                  {blockedTokens.length} token{blockedTokens.length > 1 ? 's' : ''} blocking transactions
                </p>
                <p className="text-sm mt-1">
                  The following manual token{blockedTokens.length > 1 ? 's have' : ' has'} no price set for {currencyLabel} and will <strong>block all transactions</strong> until configured:{' '}
                  {blockedTokens.map(t => t.symbol).join(', ')}
                </p>
              </div>
            </div>
          );
        })()}

        <div className="flex items-center justify-between">
          <h3 className="text-base font-medium text-neutral-700">Per-Organization Token Prices</h3>
          {canEdit && orgId && (
            <Button size="sm" onClick={openCreateForm}>
              <Plus className="w-4 h-4 mr-1" />
              Add Token
            </Button>
          )}
        </div>

        {managed && <ManagedStreamNotice subject="Token prices" />}

        {!orgId ? (
          <div className="text-center py-8 text-neutral-500 text-sm">
            Select an organization above to manage per-org token prices.
          </div>
        ) : (
        <>

        {error && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-error-light border border-error/30 text-error-dark text-sm">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        {tokens.length === 0 ? (
          <div className="text-center py-12">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
              <Coins className="w-8 h-8 text-neutral-400" />
            </div>
            <p className="text-neutral-500 mb-2">No per-org token prices configured</p>
            <p className="text-neutral-400 text-sm">
              Native ETH will auto-resolve from CoinGecko if a system price is available.
              Add token prices for ERC-20 tokens or manual overrides.
            </p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Token Address</TableHead>
                <TableHead>Symbol</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Price ({currencyLabel})</TableHead>
                <TableHead>Updated</TableHead>
                {canEdit && <TableHead className="w-[80px]"></TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map(token => {
                const resolved = getResolvedPrice(token);
                return (
                  <TableRow key={token.id}>
                    <TableCell className="font-mono text-xs">
                      {token.token_address === 'native' ? (
                        <Badge variant="info">native (ETH)</Badge>
                      ) : (
                        <span className="text-neutral-500">{token.token_address}</span>
                      )}
                    </TableCell>
                    <TableCell className="font-medium">{token.symbol}</TableCell>
                    <TableCell>
                      {token.coingecko_id ? (
                        <Badge variant="outline" className="text-xs bg-blue-50 text-blue-700 border-blue-200">
                          {COINGECKO_OPTIONS.find(o => o.id === token.coingecko_id)?.label || `CoinGecko: ${token.coingecko_id}`}
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-xs">Manual</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {resolved.price === 0 ? (
                        <span className="text-error-dark flex items-center gap-1">
                          <AlertCircle className="w-3.5 h-3.5" />
                          Unavailable
                        </span>
                      ) : (
                        <span className="flex items-center gap-1">
                          {formatAmount(resolved.price)}
                          {resolved.stale && (
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                          )}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-neutral-500 text-sm">
                      {resolved.updatedAt ? (
                        <span className={resolved.stale ? 'text-amber-600' : ''}>
                          {timeAgo(resolved.updatedAt)}
                        </span>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                    {canEdit && (
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button variant="ghost" size="icon" onClick={() => openEditForm(token)}>
                            <Pencil className="w-4 h-4" />
                          </Button>
                          <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(token)}>
                            <Trash2 className="w-4 h-4 text-error-dark" />
                          </Button>
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
        </>)}
      </div>

      {/* Create/Edit Dialog */}
      <Dialog open={showForm} onOpenChange={open => { if (!open) setShowForm(false); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit Token Price' : 'Add Token Price'}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            {formError && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-error-light border border-error/30 text-error-dark text-sm">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {formError}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                Token Address
              </label>
              <Input
                value={formAddress}
                onChange={e => setFormAddress(e.target.value)}
                placeholder='native or 0x...'
                disabled={!!editing}
              />
              <p className="text-xs text-neutral-400 mt-1">
                Use "native" for the chain's native currency (ETH)
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">Price Source</label>
              <UISelect value={formSource} onValueChange={handleSourceChange}>
                <SelectTrigger>
                  <SelectValue placeholder="Select price source" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="manual">Manual</SelectItem>
                  {COINGECKO_OPTIONS.map(opt => (
                    <SelectItem key={opt.id} value={opt.id}>{opt.label}</SelectItem>
                  ))}
                </SelectContent>
              </UISelect>
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">Symbol</label>
              <Input
                value={formSymbol}
                onChange={e => setFormSymbol(e.target.value)}
                placeholder="ETH"
                disabled={formSource !== 'manual'}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">Decimals</label>
              <Input
                type="number"
                value={formDecimals}
                onChange={e => setFormDecimals(e.target.value)}
                placeholder="18"
                min="0"
                max="77"
                disabled={formSource !== 'manual'}
              />
            </div>

            {formSource === 'manual' && (
              <div>
                <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                  Price ({currencyLabel})
                </label>
                <Input
                  type="number"
                  value={formPrice}
                  onChange={e => setFormPrice(e.target.value)}
                  placeholder="2500.00"
                  min="0"
                  step="0.01"
                />
              </div>
            )}

            {formSource !== 'manual' && (
              <div className="p-3 rounded-lg bg-blue-50 border border-blue-200 text-sm text-blue-800">
                Price will be automatically fetched from CoinGecko. You can still set a manual fallback price above.
              </div>
            )}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                {editing ? 'Update' : 'Add'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => { if (!open) setDeleteTarget(null); }}
        title="Delete Token Price"
        description={`Are you sure you want to delete the price for ${deleteTarget?.symbol || 'this token'}? Compliance checks will no longer be able to calculate USD values for transfers involving this token.`}
        confirmLabel="Delete"
        onConfirm={handleDelete}
        variant="destructive"
      />
    </div>
  );
}
