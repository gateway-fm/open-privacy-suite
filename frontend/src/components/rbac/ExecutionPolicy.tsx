import { useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  FileCheck2,
  Loader2,
  RotateCcw,
  ScrollText,
  ShieldCheck,
  X,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { useManagedStream } from '@/hooks/useManagedStream';
import ManagedStreamNotice from './ManagedStreamNotice';
import { executionPolicyApi } from '@/api/executionPolicy';
import {
  extractApiError,
  formatPolicyTimestamp,
  shortDigest,
} from '@/lib/executionPolicy';
import type {
  ExecutionPolicyContext,
  ExecutionPolicyRevision,
  ExecutionPolicyRevisionDetail,
  ExecutionPolicyStatus,
} from '@/types/executionPolicy';
import { useOrgContext } from './RBACManager';
import ExecutionPolicyEditor from './ExecutionPolicyEditor';
import ExecutionPolicySimulator from './ExecutionPolicySimulator';

// RD-1287: versioned contract execution policies.

const STATUS_VARIANT: Record<
  ExecutionPolicyStatus,
  'success' | 'warning' | 'secondary' | 'outline'
> = {
  active: 'success',
  draft: 'warning',
  superseded: 'secondary',
  withdrawn: 'outline',
};

const STATUS_MEANING: Record<ExecutionPolicyStatus, string> = {
  active: 'In force — every execution in this organization is checked against it',
  draft: 'Enforces nothing — it has never been in force',
  superseded: 'Was in force until a later revision replaced it',
  withdrawn: 'Abandoned as a draft — it was never in force',
};

type PendingAction = { kind: 'activate' | 'withdraw'; revision: ExecutionPolicyRevision };

/**
 * ExecutionPolicy is the per-organization policy screen: the revision history,
 * the editor for a new candidate, and the review surface (document, generated
 * Solidity, digests, simulation) that a revision is approved from.
 */
export default function ExecutionPolicy() {
  const { selectedOrg } = useOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const orgId = selectedOrg?.id || '';
  // Once a reviewed execution-rules document owns this organisation, the
  // legacy draft/activate/withdraw calls answer 409: the screen keeps showing
  // the revisions but stops offering those controls.
  const { managed, checked } = useManagedStream('execution-rules', orgId);
  const canEdit = !isReadonlyAdmin && checked && !managed;

  const [context, setContext] = useState<ExecutionPolicyContext | null>(null);
  const [revisions, setRevisions] = useState<ExecutionPolicyRevision[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [selected, setSelected] = useState<ExecutionPolicyRevisionDetail | null>(null);
  const [selectedLoading, setSelectedLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [pending, setPending] = useState<PendingAction | null>(null);
  const [acting, setActing] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const load = async () => {
    if (!orgId) return;
    try {
      setLoading(true);
      setLoadError(null);
      const [contextResponse, revisionsResponse] = await Promise.all([
        executionPolicyApi.getContext(orgId),
        executionPolicyApi.listRevisions(orgId),
      ]);
      setContext(contextResponse.data);
      setRevisions(revisionsResponse.data || []);
    } catch (err) {
      setLoadError(extractApiError(err, 'Failed to load the execution policy.').message);
      setContext(null);
      setRevisions([]);
    } finally {
      setLoading(false);
    }
  };

  // reason: intentional reload-on-orgId. load() is a non-memoised helper that
  // reads current state via closure; re-running only when the organization
  // changes is the desired behaviour. Adding it to deps would require
  // useCallback and risk a refetch loop.
  useEffect(() => {
    setSelected(null);
    setActionNotice(null);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  const openRevision = async (revisionId: string) => {
    if (!orgId) return;
    try {
      setSelectedLoading(true);
      setDetailError(null);
      const response = await executionPolicyApi.getRevision(orgId, revisionId);
      setSelected(response.data);
    } catch (err) {
      setSelected(null);
      setDetailError(extractApiError(err, 'Failed to load the revision.').message);
    } finally {
      setSelectedLoading(false);
    }
  };

  const handleSubmitted = async (detail: ExecutionPolicyRevisionDetail) => {
    setSelected(detail);
    setActionNotice(null);
    await load();
  };

  const runPendingAction = async () => {
    if (!pending || !orgId) return;
    const { kind, revision } = pending;
    try {
      setActing(true);
      setDetailError(null);
      if (kind === 'activate') {
        await executionPolicyApi.activate(orgId, revision.id);
        setActionNotice(
          `Revision ${revision.revision} is now in force. Every execution in this organization is checked against it.`
        );
      } else {
        await executionPolicyApi.withdraw(orgId, revision.id);
        setActionNotice(`Draft revision ${revision.revision} was withdrawn. It never enforced anything.`);
      }
      await load();
      await openRevision(revision.id);
    } catch (err) {
      setActionNotice(null);
      setDetailError(
        extractApiError(
          err,
          kind === 'activate'
            ? 'Failed to activate the revision.'
            : 'Failed to withdraw the draft.'
        ).message
      );
    } finally {
      setActing(false);
      setPending(null);
    }
  };

  if (!orgId) {
    return null;
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="execution-policy">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-base font-medium text-neutral-700">
            <ShieldCheck className="w-4 h-4 text-primary" />
            Execution Policy
          </h3>
          <p className="mt-1 max-w-3xl text-sm text-neutral-500">
            A policy restricts what the members of a group may execute. It never grants anything:
            a caller still needs the access they already had. Revisions are versioned, and
            exactly one of them is in force at a time.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load}>
          <RotateCcw className="w-3.5 h-3.5 mr-1.5" />
          Reload
        </Button>
      </div>

      {managed && <ManagedStreamNotice subject="Execution rules" />}

      {loadError && (
        <div
          role="alert"
          data-testid="execution-policy-load-error"
          className="flex items-center gap-2 rounded-lg bg-error-light border border-error/30 p-3 text-sm text-error-dark"
        >
          <AlertCircle className="w-4 h-4 shrink-0" />
          {loadError}
        </div>
      )}

      {context && (
        <div
          className={`rounded-lg border p-3 text-sm ${
            context.active
              ? 'bg-success-light border-success/30 text-success-dark'
              : 'bg-neutral-100 border-neutral-200 text-neutral-500'
          }`}
          data-testid="active-policy-banner"
        >
          {context.active ? (
            <div className="flex flex-wrap items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>
                <strong>Revision {context.active.revision} is in force</strong> since{' '}
                {formatPolicyTimestamp(context.active.activated_at)} — runtime digest{' '}
                <code className="font-mono text-xs" title={context.active.runtime_digest}>
                  {shortDigest(context.active.runtime_digest)}
                </code>
                . No other revision decides anything.
              </span>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>
                <strong>No execution policy is in force.</strong> Nothing is restricted by this
                layer until a draft is activated; the organization&apos;s other access controls
                still apply.
              </span>
            </div>
          )}
        </div>
      )}

      {actionNotice && (
        <div className="flex items-center gap-2 rounded-lg bg-success-light border border-success/30 p-3 text-sm text-success-dark">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          {actionNotice}
        </div>
      )}

      <div className="space-y-2">
        <h4 className="flex items-center gap-2 text-sm font-medium text-neutral-700">
          <ScrollText className="w-4 h-4 text-neutral-400" />
          Revisions
        </h4>
        {revisions.length === 0 ? (
          <div className="rounded-lg border border-neutral-200 bg-neutral-100 p-6 text-center text-sm text-neutral-500">
            No policy revision has been submitted for this organization yet.
          </div>
        ) : (
          <Table data-testid="execution-policy-revisions">
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead>
                <TableHead>Revision</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Activated</TableHead>
                <TableHead>Runtime digest</TableHead>
                <TableHead className="text-right">Review</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {revisions.map(revision => (
                <TableRow
                  key={revision.id}
                  data-testid={`revision-row-${revision.revision}`}
                  className={revision.status === 'active' ? 'bg-success-light/40' : undefined}
                >
                  <TableCell>
                    <Badge
                      variant={STATUS_VARIANT[revision.status]}
                      title={STATUS_MEANING[revision.status]}
                    >
                      {revision.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-medium">{revision.revision}</TableCell>
                  <TableCell className="text-xs text-neutral-500">
                    {formatPolicyTimestamp(revision.created_at)}
                  </TableCell>
                  <TableCell className="text-xs text-neutral-500">
                    {formatPolicyTimestamp(revision.activated_at)}
                  </TableCell>
                  <TableCell>
                    <code
                      className="font-mono text-xs text-neutral-500"
                      title={revision.runtime_digest}
                    >
                      {shortDigest(revision.runtime_digest)}
                    </code>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => openRevision(revision.id)}
                      aria-label={`Review revision ${revision.revision}`}
                    >
                      <FileCheck2 className="w-3.5 h-3.5 mr-1.5" />
                      Review
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <p className="text-xs text-neutral-400">
          Exactly one revision is active; activating a draft retires the one before it in the same
          step. A draft — like a superseded or withdrawn revision — enforces nothing.
        </p>
      </div>

      {detailError && (
        <div
          role="alert"
          data-testid="execution-policy-action-error"
          className="rounded-lg bg-error-light border border-error/30 p-3 text-sm text-error-dark"
        >
          <div className="flex items-center gap-2 font-medium">
            <AlertCircle className="w-4 h-4 shrink-0" />
            The action was refused
          </div>
          <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-xs">
            {detailError}
          </pre>
        </div>
      )}

      {selectedLoading && (
        <div className="flex items-center gap-2 text-sm text-neutral-400">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading revision…
        </div>
      )}

      {selected && context && (
        <div
          className="rounded-xl border border-neutral-200 bg-white p-4 space-y-4"
          data-testid="revision-detail"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-medium text-neutral-700">
                Revision {selected.revision}
              </h4>
              <Badge
                variant={STATUS_VARIANT[selected.status]}
                title={STATUS_MEANING[selected.status]}
              >
                {selected.status}
              </Badge>
              <span className="text-xs text-neutral-400">
                {STATUS_MEANING[selected.status]}
              </span>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 text-neutral-400"
              aria-label="Close revision"
              onClick={() => setSelected(null)}
            >
              <X className="w-4 h-4" />
            </Button>
          </div>

          <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-3">
            <div>
              <dt className="font-medium text-neutral-700">Policy digest</dt>
              <dd className="font-mono text-neutral-500 break-all">{selected.policy_digest}</dd>
            </div>
            <div>
              <dt className="font-medium text-neutral-700">Solidity digest</dt>
              <dd className="font-mono text-neutral-500 break-all">{selected.solidity_digest}</dd>
            </div>
            <div>
              <dt className="font-medium text-neutral-700">Runtime digest</dt>
              <dd className="font-mono text-neutral-500 break-all">{selected.runtime_digest}</dd>
            </div>
          </dl>

          <p className="text-xs text-neutral-400">
            Built with solc {selected.compiler.version}, optimizer runs{' '}
            {selected.compiler.optimizer_runs}, EVM target {selected.compiler.evm_version}.
          </p>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div>
              <h5 className="text-xs font-medium uppercase tracking-wider text-neutral-500 mb-1.5">
                Submitted document
              </h5>
              <pre
                data-testid="revision-source"
                className="max-h-80 overflow-auto rounded-lg border border-neutral-200 bg-neutral-100 p-3 font-mono text-xs text-neutral-700 whitespace-pre-wrap break-words"
              >
                {selected.source}
              </pre>
            </div>
            <div>
              <h5 className="text-xs font-medium uppercase tracking-wider text-neutral-500 mb-1.5">
                Generated Solidity (read-only)
              </h5>
              <pre
                data-testid="revision-solidity"
                className="max-h-80 overflow-auto rounded-lg border border-neutral-200 bg-neutral-100 p-3 font-mono text-xs text-neutral-700 whitespace-pre-wrap break-words"
              >
                {selected.solidity_source}
              </pre>
            </div>
          </div>

          <details className="rounded-lg border border-neutral-200 bg-neutral-100 p-3">
            <summary className="cursor-pointer text-xs font-medium text-neutral-500">
              Compiled runtime bytecode
            </summary>
            <pre className="mt-2 max-h-48 overflow-auto font-mono text-[11px] text-neutral-500 whitespace-pre-wrap break-all">
              {selected.runtime_bytecode}
            </pre>
          </details>

          {canEdit && selected.status === 'draft' && (
            <div className="flex flex-wrap items-center gap-3 rounded-lg border border-warning/30 bg-warning-light p-3">
              <div className="flex-1 min-w-[240px] text-xs text-warning-dark">
                This draft enforces nothing. <strong>Activating it puts it in force</strong> for
                every execution in this organization and retires the revision that is active now.
              </div>
              <Button onClick={() => setPending({ kind: 'activate', revision: selected })}>
                <ShieldCheck className="w-4 h-4 mr-2" />
                Activate…
              </Button>
              <Button
                variant="destructive"
                onClick={() => setPending({ kind: 'withdraw', revision: selected })}
              >
                Withdraw draft…
              </Button>
            </div>
          )}

          <div className="border-t border-neutral-200 pt-4">
            <ExecutionPolicySimulator
              key={selected.id}
              orgId={orgId}
              revision={selected}
              groups={context.groups}
            />
          </div>
        </div>
      )}

      {context && (
        <div className="border-t border-neutral-200 pt-6">
          <ExecutionPolicyEditor
            key={orgId}
            orgId={orgId}
            context={context}
            disabled={!canEdit}
            onSubmitted={handleSubmitted}
            onReloadContext={load}
          />
        </div>
      )}

      <ConfirmDialog
        open={pending?.kind === 'activate'}
        onOpenChange={open => {
          if (!open) setPending(null);
        }}
        title={`Activate revision ${pending?.revision.revision ?? ''}?`}
        description={
          context?.active
            ? `Activating puts this revision in force immediately: from that moment every execution in this organization is checked against it, and revision ${context.active.revision} — active now — is retired. This is the step that makes a policy enforce.`
            : 'Activating puts this revision in force immediately: from that moment every execution in this organization is checked against it. This is the step that makes a policy enforce.'
        }
        confirmLabel="Activate and enforce"
        variant="warning"
        isLoading={acting}
        onConfirm={runPendingAction}
      />

      <ConfirmDialog
        open={pending?.kind === 'withdraw'}
        onOpenChange={open => {
          if (!open) setPending(null);
        }}
        title={`Withdraw draft revision ${pending?.revision.revision ?? ''}?`}
        description="The draft is abandoned and can never be activated. It has never been in force, so nothing that is enforced today changes."
        confirmLabel="Withdraw draft"
        variant="destructive"
        isLoading={acting}
        onConfirm={runPendingAction}
      />
    </div>
  );
}
