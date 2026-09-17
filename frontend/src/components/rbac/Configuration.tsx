import { useEffect, useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { configurationApi } from '@/api/configuration';
import { extractApiError } from '@/lib/executionPolicy';
import type { ConfigurationContext, ConfigurationKind, ConfigurationReview, ConfigurationRevision, ExecutionReadiness } from '@/types/configuration';
import { useOrgContext } from './RBACManager';
import { useAdmin } from '@/components/auth/RequireAdmin';

const streams: { kind: ConfigurationKind; label: string }[] = [
  { kind: 'groups', label: 'Groups and method permissions' },
  { kind: 'contract-registry', label: 'Contracts, read grants and events' },
  { kind: 'execution-rules', label: 'Execution rules' },
  { kind: 'compliance', label: 'Compliance settings' },
  { kind: 'approvers', label: 'Approvers and trusted CI' },
];

export default function Configuration({ initialKind = 'groups' }: { initialKind?: ConfigurationKind }) {
  const { selectedOrg } = useOrgContext();
  const { accessToken } = useAuth();
  const [kind, setKind] = useState<ConfigurationKind>(initialKind);
  if (!selectedOrg) return <p>Select an organization to manage its configuration.</p>;
  if (!accessToken) return <p>Sign in with a named account to draft or approve configuration.</p>;
  return <section className="space-y-5">
    <div><h3 className="text-lg font-medium">Configuration revisions</h3>
      <p className="text-sm text-neutral-600">Draft a complete document, review its changes, then ask a different human administrator to activate it. Memberships, user onboarding and sanctions remain operational actions.</p></div>
    <label className="block text-sm">Configuration stream
      <select aria-label="Configuration stream" className="block mt-1 border rounded p-2" value={kind} onChange={e => setKind(e.target.value as ConfigurationKind)}>
        {streams.map(stream => <option key={stream.kind} value={stream.kind}>{stream.label}</option>)}
      </select>
    </label>
    <ConfigurationPanel key={`${selectedOrg.id}:${kind}:${accessToken}`} token={accessToken} org={selectedOrg.id} kind={kind} />
  </section>;
}

export function PlatformConfiguration() {
  const { accessToken } = useAuth();
  const { isPlatformAdmin } = useAdmin();
  if (!accessToken || !isPlatformAdmin) return <p>A named platform administrator must sign in to manage platform configuration.</p>;
  return <section className="space-y-5">
    <div><h3 className="text-lg font-medium">Platform configuration</h3>
      <p className="text-sm text-neutral-600">Review shared infrastructure and tenant defaults. A different named platform administrator must activate the revision.</p></div>
    <ConfigurationPanel key={accessToken} token={accessToken} org="" kind="platform" />
  </section>;
}

function ConfigurationPanel({ token, org, kind }: { token: string; org: string; kind: ConfigurationKind }) {
  const api = useMemo(() => configurationApi(token, org, kind), [token, org, kind]);
  const [context, setContext] = useState<ConfigurationContext | null>(null);
  const [revisions, setRevisions] = useState<ConfigurationRevision[]>([]);
  const [source, setSource] = useState('');
  const [siblings, setSiblings] = useState('');
  const [review, setReview] = useState<ConfigurationReview | null>(null);
  const [reviewedBundle, setReviewedBundle] = useState<{ id: string; coactivate: string[] } | null>(null);
  const [selected, setSelected] = useState<ConfigurationRevision | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [execution, setExecution] = useState<ExecutionReadiness | null>(null);
  const [previewParams, setPreviewParams] = useState('[{ "from": "", "to": "", "data": "0x" }, "latest"]');
  const [previewMethod, setPreviewMethod] = useState('eth_call');
  const [diagnostic, setDiagnostic] = useState(false);
  const [preview, setPreview] = useState<unknown>(null);
  const coactivate = siblings.split(/[\s,]+/).filter(Boolean);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.context(), api.list()]).then(([ctx, list]) => {
      if (cancelled) return;
      setContext(ctx.data); setSource(JSON.stringify(ctx.data.source, null, 2)); setRevisions(list.data.revisions);
    }).catch(err => { if (!cancelled) setError(extractApiError(err, 'Could not load configuration.').message); });
    return () => { cancelled = true; };
  }, [api]);

  useEffect(() => {
    let cancelled = false;
    const poll = () => api.status().then(res => { if (!cancelled) setExecution(res.data.execution ?? null); }).catch(() => { if (!cancelled) setExecution(null); });
    void poll();
    const timer = window.setInterval(poll, 5000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [api]);

  const act = async (operation: () => Promise<void>) => {
    setBusy(true); setError(''); setNotice('');
    try { await operation(); } catch (err) { setReview(null); setError(extractApiError(err, 'Configuration operation failed.').message); }
    finally { setBusy(false); }
  };
  const reload = async () => {
    const [ctx, list] = await Promise.all([api.context(), api.list()]);
    setContext(ctx.data); setRevisions(list.data.revisions);
  };
  const save = () => act(async () => {
    JSON.parse(source); // Syntax feedback only; send the original text.
    const response = await api.submit(source);
    setSelected(response.data); setReview(null); setNotice(`Draft ${response.data.revision} saved. It is not active.`);
    await reload();
  });
  const inspect = (revision: ConfigurationRevision) => act(async () => {
    setPreview(null);
    setReview(null); setReviewedBundle(null); setSelected(revision);
    const bundle = { id: revision.id, coactivate: [...coactivate] };
    const response = await api.review(bundle.id, bundle.coactivate);
    setReviewedBundle(bundle);
    setReview(response.data);
  });
  const eligible = context?.viewer?.canActivate === true && review?.revisions.every(r => r.createdBy !== context.viewer.principalId) === true;
  const activate = () => act(async () => {
    if (!selected || !review || !reviewedBundle || !eligible) return;
    await api.activate(reviewedBundle.id, reviewedBundle.coactivate);
    setReview(null); setNotice('Revision activated in OPS. Node publication is tracked separately below.');
    await reload();
    setExecution((await api.status()).data.execution ?? null);
  });

  return <div className="space-y-5">
    {error && <div role="alert" className="border border-red-300 rounded p-3 text-red-800">{error}</div>}
    {notice && <p role="status">{notice}</p>}
    {context && <>
      <p className="text-sm">{context.active ? `Active revision ${context.active.revision}.` : 'No revision is active for this stream.'} Base revision is checked again on activation.</p>
      <label className="block text-sm">Configuration source
        <textarea aria-label="Configuration source" rows={16} spellCheck={false} className="block w-full mt-1 rounded border p-3 font-mono text-xs" value={source} onChange={e => setSource(e.target.value)} />
      </label>
      <div className="flex gap-2"><Button disabled={busy} onClick={save}>Save draft</Button>
        <Button variant="outline" disabled={busy} onClick={() => act(async () => { await reload(); setSource(JSON.stringify((await api.context()).data.source, null, 2)); setReview(null); })}>Reload current source</Button></div>
      <p className="text-sm text-neutral-600">List each managed resource to keep, or name it in explicit deletions. Omitting a managed resource is an error. Review shows unmanaged resources retained as drift.</p>
      {kind !== 'platform' && <label className="block text-sm">Coactivate revision IDs
        <input aria-label="Coactivate revision IDs" disabled={busy} className="block w-full mt-1 rounded border p-2" value={siblings} onChange={e => { setSiblings(e.target.value); setReview(null); setReviewedBundle(null); }} placeholder="Optional sibling revision IDs, separated by commas" />
      </label>}
      <ul className="divide-y rounded border">{revisions.map(r => <li className="flex items-center justify-between p-3 gap-3" key={r.id}>
        <span>Revision {r.revision} · {r.status} <code className="text-xs">{r.digest.slice(0, 12)}</code></span>
        <Button variant="outline" disabled={busy} onClick={() => inspect(r)}>Review revision {r.revision}</Button>
      </li>)}</ul>
      {selected && <section className="space-y-3 rounded border p-4">
        <h4 className="font-medium">Revision {selected.revision}</h4>
        <p className="break-all text-sm">Document digest: <code>{selected.digest}</code></p>
        <details><summary>Submitted source</summary><pre className="overflow-auto text-xs p-3">{selected.source}</pre></details>
        {selected.artifact != null && <details><summary>Compiled policy and reproducibility evidence</summary><pre className="overflow-auto text-xs p-3">{JSON.stringify(selected.artifact, null, 2)}</pre></details>}
        {kind === 'execution-rules' && <section className="space-y-3 rounded border p-3">
          <h4 className="font-medium">Preview candidate execution</h4>
          <p className="text-sm">Uses your linked sender, current facts and current chain state. The active policy must permit execution. A preview does not activate this revision or guarantee later inclusion.</p>
          {context.viewer?.principalKind === 'human' && context.viewer.canActivate && <label className="block text-sm">
            <input type="checkbox" checked={diagnostic} disabled={busy} onChange={e => { setDiagnostic(e.target.checked); setPreview(null); }} /> Human administrator diagnostic
            <span className="block text-neutral-600">Allows candidate record getters and bypasses execution rules inside this organization. Requires current full organization authority and is audited.</span>
          </label>}
          <label className="block text-sm">Simulation method
            <select aria-label="Simulation method" value={previewMethod} onChange={e => { setPreviewMethod(e.target.value); setPreview(null); }} disabled={busy} className="block rounded border p-2">
              {['eth_call', 'eth_estimateGas', 'debug_traceCall'].map(method => <option key={method}>{method}</option>)}
            </select>
          </label>
          <label className="block text-sm">Simulation parameters
            <textarea aria-label="Simulation parameters" value={previewParams} disabled={busy} onChange={e => { setPreviewParams(e.target.value); setPreview(null); }} rows={5} className="block w-full rounded border p-2 font-mono text-xs" />
          </label>
          <Button variant="outline" disabled={busy || !['draft', 'active'].includes(selected.status)} onClick={() => act(async () => {
            setPreview(null);
            const params: unknown = JSON.parse(previewParams);
            if (!Array.isArray(params)) throw new Error('Simulation parameters must be a JSON array.');
            setPreview((await api.preview(selected.id, previewMethod, params, diagnostic)).data);
          })}>Preview candidate in node</Button>
          {preview !== null && <pre aria-label="Node preview result" className="max-h-96 overflow-auto text-xs">{JSON.stringify(preview, null, 2)}</pre>}
        </section>}
        {review && <>
          <h4 className="font-medium">Reviewed changes and preserved resources</h4>
          <pre aria-label="Configuration review" className="max-h-96 overflow-auto rounded bg-neutral-50 p-3 text-xs">{JSON.stringify(review, null, 2)}</pre>
          {selected.status === 'draft' && (eligible ? <Button disabled={busy} onClick={activate}>Activate reviewed revision</Button> : <p>A different human administrator with current approval authority must activate this revision.</p>)}
        </>}
        {selected.status === 'draft' && context.viewer?.canActivate && <Button variant="outline" disabled={busy} onClick={() => act(async () => { await api.withdraw(selected.id); setSelected(null); setReview(null); await reload(); setNotice('Draft withdrawn.'); })}>Withdraw draft</Button>}
      </section>}
    </>}
    <section aria-label="Execution publication" className="rounded border p-3 text-sm">
      {!execution ? <p>Node publication status unavailable. Reload status before testing execution.</p> : execution.mode === 'legacy' ? <p>Legacy execution mode. Enable Reth policy mode to enforce execution revisions in the node.</p> : <>
        <p>{execution.ready ? 'Node ready with current policy facts.' : 'Publication pending or node unavailable; execution remains closed.'}</p>
        <p>Desired facts {execution.desired_version ?? 0}; node has applied {execution.applied_version ?? 0}.</p>
        {execution.reason && <p>{execution.reason}</p>}
      </>}
    </section>
  </div>;
}
