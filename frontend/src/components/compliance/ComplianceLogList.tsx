import { useState, useEffect } from 'react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import Pagination from '@/components/ui/Pagination';
import { Loader2, AlertCircle, ScrollText, Copy, Check } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import { useCurrency } from './CurrencyContext';
import type { ComplianceLog, Decision, TransferType } from '@/types/compliance';

const PAGE_SIZE = 25;

export default function ComplianceLogList() {
  const { selectedOrg } = useComplianceOrgContext();
  const { formatAmount, currencyLabel } = useCurrency();
  const orgId = selectedOrg?.id;

  const [logs, setLogs] = useState<ComplianceLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [selectedLog, setSelectedLog] = useState<ComplianceLog | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Filters
  const [filterDecision, setFilterDecision] = useState<string>('');
  const [filterTransferType, setFilterTransferType] = useState<string>('');
  const [filterUserSearch, setFilterUserSearch] = useState('');
  const [debouncedUserSearch, setDebouncedUserSearch] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedUserSearch(filterUserSearch), 300);
    return () => clearTimeout(timer);
  }, [filterUserSearch]);

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const loadLogs = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.logs.list(orgId, {
        limit: PAGE_SIZE,
        offset: newOffset,
        decision: (filterDecision && filterDecision !== 'all' ? filterDecision as Decision : undefined),
        transfer_type: (filterTransferType && filterTransferType !== 'all' ? filterTransferType as TransferType : undefined),
        user_search: debouncedUserSearch || undefined,
      });
      const page = response.data;
      setLogs(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setLogs([]);
        setTotal(0);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load compliance logs');
      }
    } finally {
      setLoading(false);
    }
  };

  // reason: intentional reload when the filter keys change. loadLogs is a
  // non-memoised helper that reads current state via closure; re-running only on
  // the listed filter keys is the desired behaviour. Adding it to deps would
  // require useCallback and risk a refetch loop.
  useEffect(() => {
    setOffset(0);
    loadLogs(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, filterDecision, filterTransferType, debouncedUserSearch]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-medium text-neutral-700">Controls Logs</h3>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={filterDecision || 'all'} onValueChange={v => setFilterDecision(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="All decisions" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All decisions</SelectItem>
            <SelectItem value="allowed">Allowed</SelectItem>
            <SelectItem value="denied">Denied</SelectItem>
          </SelectContent>
        </Select>

        <Select value={filterTransferType || 'all'} onValueChange={v => setFilterTransferType(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="eth">ETH</SelectItem>
            <SelectItem value="erc20">ERC-20</SelectItem>
          </SelectContent>
        </Select>

        <Input
          value={filterUserSearch}
          onChange={e => setFilterUserSearch(e.target.value)}
          placeholder="Search by user DID..."
          className="max-w-[250px]"
        />
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-error-light border border-error/30 text-error-dark text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {logs.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <ScrollText className="w-8 h-8 text-neutral-400" />
          </div>
          <p className="text-neutral-500 mb-2">No compliance logs</p>
          <p className="text-neutral-400 text-sm">
            Compliance decisions will appear here when transfers are evaluated
          </p>
        </div>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>From</TableHead>
                <TableHead>To</TableHead>
                <TableHead>Amount ({currencyLabel})</TableHead>
                <TableHead>Decision</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.map(log => (
                <TableRow
                  key={log.id}
                  className="cursor-pointer hover:bg-neutral-100"
                  onClick={() => setSelectedLog(log)}
                >
                  <TableCell className="text-neutral-500 text-xs whitespace-nowrap">
                    {new Date(log.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-neutral-500">
                    {log.user_external_id
                      ? (log.user_external_id.length > 20 ? log.user_external_id.slice(0, 15) + '...' : log.user_external_id)
                      : log.user_id.slice(0, 8) + '...'}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{log.transfer_type.toUpperCase()}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <span className="font-mono text-xs text-neutral-500">
                        {log.from_address.slice(0, 6)}...{log.from_address.slice(-4)}
                      </span>
                      <button
                        onClick={(e) => { e.stopPropagation(); copyToClipboard(log.from_address, `${log.id}-from`); }}
                        className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors"
                        title="Copy address"
                      >
                        {copiedKey === `${log.id}-from` ? (
                          <Check className="w-3.5 h-3.5 text-success" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <span className="font-mono text-xs text-neutral-500">
                        {log.to_address.slice(0, 6)}...{log.to_address.slice(-4)}
                      </span>
                      <button
                        onClick={(e) => { e.stopPropagation(); copyToClipboard(log.to_address, `${log.id}-to`); }}
                        className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors"
                        title="Copy address"
                      >
                        {copiedKey === `${log.id}-to` ? (
                          <Check className="w-3.5 h-3.5 text-success" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </TableCell>
                  <TableCell>
                    {log.amount_fiat != null ? formatAmount(log.amount_fiat) : '—'}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5">
                      <Badge variant={log.decision === 'allowed' ? 'success' : 'destructive'}>
                        {log.decision}
                      </Badge>
                      {log.would_block && log.decision === 'allowed' && (
                        <Badge variant="warning" title="Allowed in monitor mode — would have been blocked under enforce">
                          Would block
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pagination
            total={total}
            limit={PAGE_SIZE}
            offset={offset}
            onPageChange={newOffset => loadLogs(newOffset)}
          />
        </>
      )}

      {/* Detail Dialog */}
      <Dialog open={!!selectedLog} onOpenChange={open => { if (!open) setSelectedLog(null); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Controls Log Detail</DialogTitle>
          </DialogHeader>
          {selectedLog && (
            <div className="space-y-4">
              <div className="grid grid-cols-[120px_1fr] gap-y-3 gap-x-4 text-sm">
                <span className="text-neutral-500 font-medium">Time</span>
                <span>{new Date(selectedLog.created_at).toLocaleString()}</span>

                {selectedLog.user_external_id && (
                  <>
                    <span className="text-neutral-500 font-medium">User (DID)</span>
                    <span className="font-mono text-xs break-all">{selectedLog.user_external_id}</span>
                  </>
                )}

                <span className="text-neutral-500 font-medium">User ID</span>
                <span className="font-mono text-xs break-all">{selectedLog.user_id}</span>

                <span className="text-neutral-500 font-medium">Transfer Type</span>
                <div>
                  <Badge variant="outline">{selectedLog.transfer_type.toUpperCase()}</Badge>
                </div>

                {selectedLog.token_address && (
                  <>
                    <span className="text-neutral-500 font-medium">Token Address</span>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm break-all">{selectedLog.token_address}</span>
                      <button
                        onClick={() => copyToClipboard(selectedLog.token_address!, 'detail-token')}
                        className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors shrink-0"
                        title="Copy address"
                      >
                        {copiedKey === 'detail-token' ? (
                          <Check className="w-3.5 h-3.5 text-success" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </>
                )}

                <span className="text-neutral-500 font-medium">From Address</span>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm break-all">{selectedLog.from_address}</span>
                  <button
                    onClick={() => copyToClipboard(selectedLog.from_address, 'detail-from')}
                    className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors shrink-0"
                    title="Copy address"
                  >
                    {copiedKey === 'detail-from' ? (
                      <Check className="w-3.5 h-3.5 text-success" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>

                <span className="text-neutral-500 font-medium">To Address</span>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm break-all">{selectedLog.to_address}</span>
                  <button
                    onClick={() => copyToClipboard(selectedLog.to_address, 'detail-to')}
                    className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors shrink-0"
                    title="Copy address"
                  >
                    {copiedKey === 'detail-to' ? (
                      <Check className="w-3.5 h-3.5 text-success" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>

                <span className="text-neutral-500 font-medium">Amount (wei)</span>
                <span className="font-mono text-sm break-all">{selectedLog.amount_wei}</span>

                <span className="text-neutral-500 font-medium">Amount ({currencyLabel})</span>
                <span>{selectedLog.amount_fiat != null ? formatAmount(selectedLog.amount_fiat) : '—'}</span>

                {selectedLog.threshold_fiat != null && (
                  <>
                    <span className="text-neutral-500 font-medium">Threshold ({currencyLabel})</span>
                    <span>{formatAmount(selectedLog.threshold_fiat)}</span>
                  </>
                )}

                <span className="text-neutral-500 font-medium">Decision</span>
                <div>
                  <Badge variant={selectedLog.decision === 'allowed' ? 'success' : 'destructive'}>
                    {selectedLog.decision}
                  </Badge>
                </div>

                {selectedLog.would_block && selectedLog.decision === 'allowed' && (
                  <>
                    <span className="text-neutral-500 font-medium">Monitor mode</span>
                    <div>
                      <Badge variant="warning">Would have blocked</Badge>
                    </div>
                  </>
                )}

                {selectedLog.denial_reason && (
                  <>
                    <span className="text-neutral-500 font-medium">Denial Reason</span>
                    <span className="text-error-dark">{selectedLog.denial_reason}</span>
                  </>
                )}

                {selectedLog.travel_rule_record_id && (
                  <>
                    <span className="text-neutral-500 font-medium">Travel Rule ID</span>
                    <span className="font-mono text-xs break-all">{selectedLog.travel_rule_record_id}</span>
                  </>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
