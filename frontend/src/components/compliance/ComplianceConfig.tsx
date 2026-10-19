import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Loader2, AlertCircle, CheckCircle2, Settings } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import { useCurrency } from './CurrencyContext';
import { useAdmin } from '@/components/auth/RequireAdmin';
import type { ComplianceConfig as ComplianceConfigType } from '@/types/compliance';

export default function ComplianceConfig() {
  const { selectedOrg } = useComplianceOrgContext();
  const { currencyLabel } = useCurrency();
  const { isReadonlyAdmin } = useAdmin();
  const orgId = selectedOrg?.id;

  const [config, setConfig] = useState<ComplianceConfigType | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const [enabled, setEnabled] = useState(false);
  const [thresholdFiat, setThresholdFiat] = useState('1000');
  const [unknownPricePolicy, setUnknownPricePolicy] = useState<'allowed' | 'forbidden'>('forbidden');
  const [enforcementMode, setEnforcementMode] = useState<'enforce' | 'monitor'>('enforce');

  const loadConfig = async () => {
    if (!orgId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.config.get(orgId);
      const cfg = response.data;
      setConfig(cfg);
      setEnabled(cfg.enabled);
      setThresholdFiat(String(cfg.threshold_fiat));
      setUnknownPricePolicy(cfg.unknown_price_policy || 'forbidden');
      setEnforcementMode(cfg.enforcement_mode || 'enforce');
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        // No config yet — show defaults
        setConfig(null);
        setEnabled(false);
        setThresholdFiat('1000');
        setUnknownPricePolicy('forbidden');
        setEnforcementMode('enforce');
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load compliance config');
      }
    } finally {
      setLoading(false);
    }
  };

  // reason: intentional reload-on-orgId. loadConfig is a non-memoised helper
  // that reads current state via closure; re-running only when orgId changes is
  // the desired behaviour. Adding it to deps would require useCallback and risk
  // a refetch loop.
  useEffect(() => {
    loadConfig();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  const handleSave = async () => {
    if (!orgId) return;
    try {
      setSaving(true);
      setError(null);
      setSuccess(false);
      const response = await complianceApi.config.update(orgId, {
        enabled,
        threshold_fiat: parseFloat(thresholdFiat) || 0,
        unknown_price_policy: unknownPricePolicy,
        enforcement_mode: enforcementMode,
      });
      setConfig(response.data);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to save config');
    } finally {
      setSaving(false);
    }
  };

  // Dirty-state tracking: the form only persists on Save, so surface when the
  // current selections differ from what's stored. When no config exists yet,
  // treat the form as dirty so the initial config can be created.
  const isDirty =
    !config ||
    enabled !== config.enabled ||
    thresholdFiat !== String(config.threshold_fiat) ||
    unknownPricePolicy !== (config.unknown_price_policy || 'forbidden') ||
    enforcementMode !== (config.enforcement_mode || 'enforce');

  // Warn before a full reload / tab close while there are unsaved changes —
  // compliance enablement is security-relevant and silently losing a toggle
  // gives a false sense of enforcement.
  useEffect(() => {
    if (!isDirty || isReadonlyAdmin) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [isDirty, isReadonlyAdmin]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-medium text-neutral-700">Controls Configuration</h3>
        <div className="flex items-center gap-2">
          {isDirty && !isReadonlyAdmin && (
            <Badge variant="warning">Unsaved changes</Badge>
          )}
          <Badge variant={enabled ? 'success' : 'secondary'}>
            {enabled ? 'Enabled' : 'Disabled'}
          </Badge>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-error-light border border-error/30 text-error-dark text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {success && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-success-light border border-success/30 text-success-dark text-sm">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          Configuration saved successfully
        </div>
      )}

      <div className="max-w-md space-y-4">
        <div>
          <label className="block text-sm font-medium text-neutral-700 mb-1.5">
            Enforcement
          </label>
          <Button
            variant={enabled ? 'default' : 'outline'}
            size="sm"
            disabled={isReadonlyAdmin}
            onClick={() => setEnabled(!enabled)}
          >
            {enabled ? 'Enabled' : 'Disabled'} {isReadonlyAdmin ? '' : `— Click to ${enabled ? 'disable' : 'enable'}`}
          </Button>
          <p className="text-xs text-neutral-400 mt-1">
            When enabled, transfers above the threshold require a travel rule record
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-neutral-700 mb-1.5">
            Threshold ({currencyLabel})
          </label>
          <Input
            type="number"
            value={thresholdFiat}
            onChange={e => setThresholdFiat(e.target.value)}
            disabled={isReadonlyAdmin}
            placeholder="1000"
            min="0"
            step="0.01"
          />
          <p className="text-xs text-neutral-400 mt-1">
            Transfers above this value will require travel rule compliance
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-neutral-700 mb-1.5">
            Transfers with unknown price
          </label>
          <Select
            value={unknownPricePolicy}
            onValueChange={(val: 'allowed' | 'forbidden') => setUnknownPricePolicy(val)}
            disabled={isReadonlyAdmin}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select policy" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="allowed">Allowed</SelectItem>
              <SelectItem value="forbidden">Forbidden</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-neutral-400 mt-1">
            When token price is missing, Allowed bypasses the threshold; Forbidden fails closed
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-neutral-700 mb-1.5">
            Enforcement mode
          </label>
          <Select
            value={enforcementMode}
            onValueChange={(val: 'enforce' | 'monitor') => setEnforcementMode(val)}
            disabled={isReadonlyAdmin}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select mode" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="enforce">Enforce — block violations</SelectItem>
              <SelectItem value="monitor">Monitor — allow &amp; record</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-neutral-400 mt-1">
            Enforce blocks non-compliant transfers (default). Monitor lets them proceed but records each as a “would-have-blocked” entry in the compliance log. Sanctioned addresses stay blocked in either mode.
          </p>
          {enforcementMode === 'monitor' && (
            <div className="flex items-center gap-2 mt-2 p-2 rounded-lg bg-amber-50 border border-amber-300 text-amber-800 text-xs">
              <AlertCircle className="w-3.5 h-3.5 shrink-0" />
              Monitor mode: threshold &amp; travel-rule violations are recorded but NOT blocked. Sanctions still block.
            </div>
          )}
        </div>

        {!isReadonlyAdmin && (
          <div className="flex items-center gap-3">
            <Button onClick={handleSave} disabled={saving || !isDirty}>
              {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Save Configuration
            </Button>
            {isDirty && (
              <span className="text-xs text-warning-dark">
                You have unsaved changes
              </span>
            )}
          </div>
        )}
      </div>

      {config && (
        <div className="pt-4 border-t border-neutral-200">
          <p className="text-xs text-neutral-400">
            Last updated: {new Date(config.updated_at).toLocaleString()}
          </p>
        </div>
      )}

      {!config && (
        <div className="pt-4 border-t border-neutral-200">
          <div className="flex items-center gap-2 text-sm text-neutral-500">
            <Settings className="w-4 h-4" />
            No configuration saved yet. Save to create the initial config.
          </div>
        </div>
      )}
    </div>
  );
}
