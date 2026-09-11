import { useState } from 'react';
import {
  AlertCircle,
  Check,
  CheckCircle2,
  Copy,
  FileJson,
  Loader2,
  RotateCcw,
  Users,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { executionPolicyApi } from '@/api/executionPolicy';
import {
  buildPolicySkeleton,
  extractApiError,
  type ApiErrorShape,
} from '@/lib/executionPolicy';
import type {
  ExecutionPolicyContext,
  ExecutionPolicyRevisionDetail,
  PolicyDocument,
} from '@/types/executionPolicy';

interface ExecutionPolicyEditorProps {
  orgId: string;
  context: ExecutionPolicyContext;
  /** Read-only admins may read a policy but not submit one. */
  disabled?: boolean;
  /** Called with the stored draft once a candidate is accepted. */
  onSubmitted: (detail: ExecutionPolicyRevisionDetail) => void;
  /** Re-reads the editing context, which is how a stale base is resolved. */
  onReloadContext: () => void;
}

type EditorError = ApiErrorShape & { title: string; staleBase?: boolean };

/**
 * ExecutionPolicyEditor authors one candidate document and submits it against
 * the base revision the context reported.
 *
 * The document is written as JSON rather than assembled from form controls:
 * the backend owns the schema and is the only thing that may call a document
 * valid, so the editor's job is to hand the author the facts a rule needs
 * (group ids, contract addresses, ABI digests) and to show the server's
 * refusal verbatim when it comes back.
 */
export default function ExecutionPolicyEditor({
  orgId,
  context,
  disabled = false,
  onSubmitted,
  onReloadContext,
}: ExecutionPolicyEditorProps) {
  const [text, setText] = useState(() => buildPolicySkeleton(context));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<EditorError | null>(null);
  const [created, setCreated] = useState<number | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const abiContracts = context.contracts.filter(contract => contract.has_abi);
  const contractsWithoutAbi = context.contracts.filter(contract => !contract.has_abi);

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(value);
      setTimeout(() => setCopied(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const handleSubmit = async () => {
    setError(null);
    setCreated(null);

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      setError({
        title: 'The document is not valid JSON',
        message: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      setError({
        title: 'The document is not valid JSON',
        message: 'A policy document must be a JSON object.',
      });
      return;
    }

    try {
      setSubmitting(true);
      const response = await executionPolicyApi.submit(orgId, {
        policy: parsed as PolicyDocument,
        base_revision: context.base_revision,
      });
      setCreated(response.data.revision);
      onSubmitted(response.data);
    } catch (err) {
      const apiError = extractApiError(err, 'The candidate could not be submitted.');
      if (apiError.status === 409) {
        setError({
          ...apiError,
          staleBase: true,
          title: "This organization's policy changed while you were editing",
        });
      } else if (apiError.status === 400) {
        setError({ ...apiError, title: 'The policy was rejected' });
      } else {
        setError({ ...apiError, title: 'Submission failed' });
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-4" data-testid="execution-policy-editor">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 text-base font-medium text-neutral-700">
          <FileJson className="w-4 h-4 text-primary" />
          New candidate
        </h3>
        <div className="flex items-center gap-2">
          <Badge variant="outline" data-testid="editor-base-revision">
            Base revision {context.base_revision}
          </Badge>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setText(buildPolicySkeleton(context));
              setError(null);
              setCreated(null);
            }}
            disabled={disabled || submitting}
          >
            <RotateCcw className="w-3.5 h-3.5 mr-1.5" />
            Reset to skeleton
          </Button>
        </div>
      </div>

      <p className="text-sm text-neutral-500">
        A submitted candidate is stored as a <strong>draft</strong> and enforces nothing. It has
        to be activated before it decides anything. Every rule must pin the ABI digest of the
        contract it names, so that a later ABI change is detected instead of silently
        reinterpreting argument positions.
      </p>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-2">
          <label
            className="block text-sm font-medium text-neutral-700"
            htmlFor="execution-policy-document"
          >
            Policy document (JSON)
          </label>
          <Textarea
            id="execution-policy-document"
            variant="code"
            className="min-h-[320px] resize-y"
            spellCheck={false}
            value={text}
            disabled={disabled || submitting}
            onChange={event => setText(event.target.value)}
          />
        </div>

        <div className="space-y-4">
          <div>
            <h4 className="flex items-center gap-2 text-sm font-medium text-neutral-700 mb-2">
              <Users className="w-4 h-4 text-neutral-400" />
              Groups a binding may name
            </h4>
            {context.groups.length === 0 ? (
              <p className="text-xs text-neutral-500">
                This organization has no regular groups. Administrator groups are never
                bindable — they are a trust root, not ordinary policy.
              </p>
            ) : (
              <ul className="space-y-1" data-testid="editor-groups">
                {context.groups.map(group => (
                  <li key={group} className="flex items-center justify-between gap-2">
                    <code className="font-mono text-xs text-neutral-700 truncate" title={group}>
                      {group}
                    </code>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0 shrink-0 text-neutral-400"
                      title="Copy group id"
                      aria-label={`Copy group id ${group}`}
                      onClick={() => copy(group)}
                    >
                      {copied === group ? (
                        <Check className="w-3 h-3 text-success" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div>
            <h4 className="text-sm font-medium text-neutral-700 mb-2">
              Contracts a rule may name
            </h4>
            {abiContracts.length === 0 ? (
              <p className="text-xs text-neutral-500">
                No contract in this organization has a registered ABI, so no rule can be written
                yet.
              </p>
            ) : (
              <ul className="space-y-2" data-testid="editor-contracts">
                {abiContracts.map(contract => (
                  <li
                    key={contract.address}
                    className="rounded-lg border border-neutral-200 bg-white p-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-medium text-neutral-700 truncate">
                        {contract.name || 'Unnamed contract'}
                      </span>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 shrink-0 text-neutral-400"
                        title="Copy address"
                        aria-label={`Copy address of ${contract.name || contract.address}`}
                        onClick={() => copy(contract.address)}
                      >
                        {copied === contract.address ? (
                          <Check className="w-3 h-3 text-success" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </Button>
                    </div>
                    <code className="block font-mono text-[11px] text-neutral-500 break-all">
                      {contract.address}
                    </code>
                    <div className="mt-1 flex items-center justify-between gap-2">
                      <code
                        className="font-mono text-[11px] text-neutral-500 truncate"
                        title={contract.abi_digest}
                      >
                        abiDigest: {contract.abi_digest}
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 shrink-0 text-neutral-400"
                        title="Copy ABI digest"
                        aria-label={`Copy ABI digest of ${contract.name || contract.address}`}
                        onClick={() => copy(contract.abi_digest || '')}
                      >
                        {copied === contract.abi_digest ? (
                          <Check className="w-3 h-3 text-success" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {contractsWithoutAbi.length > 0 && (
              <p className="mt-2 text-xs text-neutral-400">
                {contractsWithoutAbi.length} contract
                {contractsWithoutAbi.length === 1 ? '' : 's'} without a registered ABI cannot
                carry a rule.
              </p>
            )}
          </div>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          data-testid="policy-submit-error"
          className="rounded-lg bg-error-light border border-error/30 p-3 text-sm text-error-dark"
        >
          <div className="flex items-center gap-2 font-medium">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error.title}
          </div>
          {error.staleBase && (
            <p className="mt-1.5">
              Another administrator stored a revision after this page loaded, so the base
              revision this candidate declares ({context.base_revision}) is no longer the latest.
              Nothing was saved. Reload the editing context, re-apply your changes on top of the
              new base, and submit again.
            </p>
          )}
          <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs">
            {error.message}
          </pre>
          {error.staleBase && (
            <Button
              variant="outline"
              size="sm"
              className="mt-2"
              onClick={() => {
                setError(null);
                onReloadContext();
              }}
            >
              <RotateCcw className="w-3.5 h-3.5 mr-1.5" />
              Reload context
            </Button>
          )}
        </div>
      )}

      {created !== null && (
        <div className="flex items-center gap-2 rounded-lg bg-success-light border border-success/30 p-3 text-sm text-success-dark">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          Draft revision {created} stored. It enforces nothing until it is activated.
        </div>
      )}

      {!disabled && (
        <div className="flex items-center gap-3">
          <Button onClick={handleSubmit} disabled={submitting}>
            {submitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Submit candidate
          </Button>
          <span className="text-xs text-neutral-400">
            Stored as a draft against base revision {context.base_revision}.
          </span>
        </div>
      )}
    </div>
  );
}
