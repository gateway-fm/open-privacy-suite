import { useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Loader2,
  Play,
  Plus,
  Trash2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { executionPolicyApi } from '@/api/executionPolicy';
import { extractApiError, splitAddressList } from '@/lib/executionPolicy';
import type {
  ExecutionPolicyCallType,
  ExecutionPolicyRevision,
  ExecutionPolicySimulateFrame,
  ExecutionPolicySimulateInput,
  ExecutionPolicySimulateResult,
} from '@/types/executionPolicy';

const CALL_TYPES: ExecutionPolicyCallType[] = [
  'call',
  'staticcall',
  'delegatecall',
  'callcode',
];

interface FrameDraft {
  key: number;
  call_type: ExecutionPolicyCallType;
  storage_address: string;
  code_address: string;
  calldata: string;
}

let nextFrameKey = 1;

function emptyFrame(): FrameDraft {
  return {
    key: nextFrameKey++,
    call_type: 'call',
    storage_address: '',
    code_address: '',
    calldata: '',
  };
}

interface ExecutionPolicySimulatorProps {
  orgId: string;
  /** The revision the hypothetical execution is evaluated against. */
  revision: ExecutionPolicyRevision;
  /** Groups the hypothetical principal may be placed in. */
  groups: string[];
}

/**
 * ExecutionPolicySimulator asks one stored revision what it would decide about
 * a described execution.
 *
 * Simulation mutates nothing and runs against a draft as readily as against the
 * active policy, which is the point: it is how a reviewer checks what a policy
 * would do before putting it in force. The response carries two decisions — the
 * reference evaluator's and the compiled artifact's — and whether they agreed.
 */
export default function ExecutionPolicySimulator({
  orgId,
  revision,
  groups,
}: ExecutionPolicySimulatorProps) {
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [signer, setSigner] = useState('');
  const [linkedAddresses, setLinkedAddresses] = useState('');
  const [frames, setFrames] = useState<FrameDraft[]>([emptyFrame()]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ExecutionPolicySimulateResult | null>(null);

  const toggleGroup = (group: string) => {
    setSelectedGroups(current =>
      current.includes(group)
        ? current.filter(entry => entry !== group)
        : [...current, group]
    );
  };

  const updateFrame = (key: number, patch: Partial<FrameDraft>) => {
    setFrames(current =>
      current.map(frame => (frame.key === key ? { ...frame, ...patch } : frame))
    );
  };

  const removeFrame = (key: number) => {
    setFrames(current => (current.length === 1 ? current : current.filter(f => f.key !== key)));
  };

  const handleRun = async () => {
    setError(null);
    setResult(null);

    const wireFrames: ExecutionPolicySimulateFrame[] = frames.map(frame => {
      const wire: ExecutionPolicySimulateFrame = {
        call_type: frame.call_type,
        storage_address: frame.storage_address.trim(),
        calldata: frame.calldata.trim(),
      };
      const codeAddress = frame.code_address.trim();
      if (codeAddress) {
        wire.code_address = codeAddress;
      }
      return wire;
    });

    const payload: ExecutionPolicySimulateInput = {
      groups: selectedGroups,
      frames: wireFrames,
    };
    if (signer.trim()) {
      payload.signer = signer.trim();
    }
    const linked = splitAddressList(linkedAddresses);
    if (linked.length > 0) {
      payload.linked_addresses = linked;
    }

    try {
      setRunning(true);
      const response = await executionPolicyApi.simulate(orgId, revision.id, payload);
      setResult(response.data);
    } catch (err) {
      setError(extractApiError(err, 'The simulation could not be run.').message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-4" data-testid="execution-policy-simulator">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="flex items-center gap-2 text-sm font-medium text-neutral-700">
          <Play className="w-4 h-4 text-primary" />
          Simulate an execution against revision {revision.revision}
        </h4>
        <Badge variant="secondary">Nothing is changed by a simulation</Badge>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div>
          <span className="block text-sm font-medium text-neutral-700 mb-1.5">
            Groups of the hypothetical principal
          </span>
          {groups.length === 0 ? (
            <p className="text-xs text-neutral-500">
              This organization has no bindable groups.
            </p>
          ) : (
            <div className="space-y-1.5" data-testid="simulator-groups">
              {/* A div rather than a <label>: the checkbox is a Radix button,
                  and a wrapping label re-dispatches the click to it, toggling
                  the group twice. The accessible name comes from aria-label. */}
              {groups.map(group => (
                <div key={group} className="flex items-center gap-2 text-xs text-neutral-700">
                  <Checkbox
                    checked={selectedGroups.includes(group)}
                    onCheckedChange={() => toggleGroup(group)}
                    aria-label={`Group ${group}`}
                  />
                  <code className="font-mono truncate" title={group}>
                    {group}
                  </code>
                </div>
              ))}
            </div>
          )}
          <p className="mt-1 text-xs text-neutral-400">
            A principal in none of the bound groups is denied.
          </p>
        </div>

        <div className="space-y-3">
          <div>
            <label
              className="block text-sm font-medium text-neutral-700 mb-1.5"
              htmlFor="simulate-signer"
            >
              Signer (optional)
            </label>
            <Input
              id="simulate-signer"
              className="font-mono text-xs"
              placeholder="0x…"
              value={signer}
              onChange={event => setSigner(event.target.value)}
            />
            <p className="mt-1 text-xs text-neutral-400">
              Left empty, the execution has no recovered signer and no rule requiring one can be
              satisfied.
            </p>
          </div>

          <div>
            <label
              className="block text-sm font-medium text-neutral-700 mb-1.5"
              htmlFor="simulate-linked"
            >
              Linked addresses (optional)
            </label>
            <Input
              id="simulate-linked"
              className="font-mono text-xs"
              placeholder="0x… , 0x…"
              value={linkedAddresses}
              onChange={event => setLinkedAddresses(event.target.value)}
            />
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-neutral-700">
            Call frames, outermost first
          </span>
          <Button variant="outline" size="sm" onClick={() => setFrames(c => [...c, emptyFrame()])}>
            <Plus className="w-3.5 h-3.5 mr-1.5" />
            Add frame
          </Button>
        </div>

        {frames.map((frame, index) => (
          <div
            key={frame.key}
            className="rounded-lg border border-neutral-200 bg-neutral-100 p-3 space-y-2"
            data-testid="simulator-frame"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-neutral-500">Frame {index + 1}</span>
              {frames.length > 1 && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0 text-neutral-400"
                  aria-label={`Remove frame ${index + 1}`}
                  onClick={() => removeFrame(frame.key)}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              )}
            </div>

            <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
              <div>
                <span className="block text-xs text-neutral-500 mb-1">Call type</span>
                <Select
                  value={frame.call_type}
                  onValueChange={(value: ExecutionPolicyCallType) =>
                    updateFrame(frame.key, { call_type: value })
                  }
                >
                  <SelectTrigger aria-label={`Call type for frame ${index + 1}`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CALL_TYPES.map(callType => (
                      <SelectItem key={callType} value={callType}>
                        {callType}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div>
                <label
                  className="block text-xs text-neutral-500 mb-1"
                  htmlFor={`frame-${frame.key}-storage`}
                >
                  Storage address
                </label>
                <Input
                  id={`frame-${frame.key}-storage`}
                  className="font-mono text-xs"
                  placeholder="0x…"
                  value={frame.storage_address}
                  onChange={event =>
                    updateFrame(frame.key, { storage_address: event.target.value })
                  }
                />
              </div>

              <div>
                <label
                  className="block text-xs text-neutral-500 mb-1"
                  htmlFor={`frame-${frame.key}-code`}
                >
                  Code address (optional)
                </label>
                <Input
                  id={`frame-${frame.key}-code`}
                  className="font-mono text-xs"
                  placeholder="defaults to the storage address"
                  value={frame.code_address}
                  onChange={event => updateFrame(frame.key, { code_address: event.target.value })}
                />
              </div>
            </div>

            <div>
              <label
                className="block text-xs text-neutral-500 mb-1"
                htmlFor={`frame-${frame.key}-calldata`}
              >
                Calldata (0x-prefixed hex, selector included)
              </label>
              <Input
                id={`frame-${frame.key}-calldata`}
                className="font-mono text-xs"
                placeholder="0xa9059cbb…"
                value={frame.calldata}
                onChange={event => updateFrame(frame.key, { calldata: event.target.value })}
              />
            </div>
          </div>
        ))}
      </div>

      <Button onClick={handleRun} disabled={running}>
        {running ? (
          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
        ) : (
          <Play className="w-4 h-4 mr-2" />
        )}
        Run simulation
      </Button>

      {error && (
        <div
          role="alert"
          data-testid="simulate-error"
          className="rounded-lg bg-error-light border border-error/30 p-3 text-sm text-error-dark"
        >
          <div className="flex items-center gap-2 font-medium">
            <AlertCircle className="w-4 h-4 shrink-0" />
            The simulation failed
          </div>
          <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs">{error}</pre>
        </div>
      )}

      {result && (
        <div className="space-y-3" data-testid="simulate-result">
          <div
            className={`rounded-lg border p-3 ${
              result.allowed
                ? 'bg-success-light border-success/30'
                : 'bg-neutral-100 border-neutral-200'
            }`}
          >
            <div className="flex items-center gap-2">
              {result.allowed ? (
                <CheckCircle2 className="w-5 h-5 text-success-dark" />
              ) : (
                <Ban className="w-5 h-5 text-neutral-500" />
              )}
              <span className="text-sm font-medium text-neutral-900">
                {result.allowed ? 'Allowed' : 'Denied'}
              </span>
              {!result.allowed && result.code && (
                <Badge variant="destructive" data-testid="simulate-code">
                  {result.code}
                </Badge>
              )}
            </div>
            {result.reason && (
              <pre
                data-testid="simulate-reason"
                className="mt-2 whitespace-pre-wrap break-words font-mono text-xs text-neutral-700"
              >
                {result.reason}
              </pre>
            )}
            <dl className="mt-3 grid grid-cols-1 gap-1 text-xs text-neutral-500 sm:grid-cols-2">
              <div>
                <dt className="inline font-medium text-neutral-700">Compiled artifact: </dt>
                <dd className="inline" data-testid="simulate-compiled">
                  {result.compiled_allowed ? 'allowed' : 'denied'}
                  {result.compiled_code ? ` (${result.compiled_code})` : ''}
                </dd>
              </div>
              <div className="truncate">
                <dt className="inline font-medium text-neutral-700">Runtime digest: </dt>
                <dd className="inline font-mono" title={result.runtime_digest}>
                  {result.runtime_digest}
                </dd>
              </div>
            </dl>
          </div>

          {result.agreed ? (
            <div className="flex items-center gap-2 rounded-lg bg-neutral-100 border border-neutral-200 p-2.5 text-xs text-neutral-500">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-success-dark" />
              The reference evaluator and the compiled artifact reached the same decision.
            </div>
          ) : (
            <div
              role="alert"
              data-testid="simulate-disagreement"
              className="rounded-lg bg-error-light border-2 border-error p-3 text-sm text-error-dark"
            >
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle className="w-5 h-5 shrink-0" />
                The reviewed policy and the enforced policy disagree
              </div>
              <p className="mt-1.5">
                The document evaluated to <strong>{result.allowed ? 'allowed' : 'denied'}</strong>{' '}
                but the compiled artifact that actually enforces it evaluated to{' '}
                <strong>{result.compiled_allowed ? 'allowed' : 'denied'}</strong>. What a reviewer
                reads is therefore not what would be enforced. Do not activate this revision;
                report the artifact and its runtime digest.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
