import { useMemo, useState } from "react";
import { rbacApi } from "@/api/rbac";
import type { MethodPolicyDocument } from "@/types/rbac";
import {
  parseAbiFunctions,
  parseAbiEvents,
  functionsWithKeyableParam,
  eventsWithKeyableParam,
  isCanonicalizableKeyType,
  isDynamicType,
  compileWizard,
  decompileWizard,
  validateWizard,
  renderPolicy,
  emptyRecord,
  emptyEvent,
  emptyTransaction,
  emptyAudienceRule,
  WHERE_OPS,
  type AbiFnInfo,
  type AbiEventInfo,
  type WizardState,
  type WizardRecord,
  type WizardCapture,
  type WizardReader,
  type WizardAllowRule,
  type WizardEvent,
  type WizardTransaction,
  type WizardAudienceRule,
} from "@/lib/methodPolicy";
import { Button } from "@/components/ui/button";
import { ShieldAlert, ShieldCheck, Check, Loader2, Plus, X, Info, FlaskConical } from "lucide-react";

interface Props {
  orgId: string;
  contractAddress: string;
  contractAbi?: string;
  initialPolicy?: MethodPolicyDocument | null;
  isReadonlyAdmin?: boolean;
}

type Mode = "none" | "structured" | "json" | "simulate";

export function MethodPolicyManager({ orgId, contractAddress, contractAbi, initialPolicy, isReadonlyAdmin }: Props) {
  const [policy, setPolicy] = useState<MethodPolicyDocument | null>(initialPolicy ?? null);
  const [mode, setMode] = useState<Mode>("none");
  const [w, setW] = useState<WizardState>({ records: [] });
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const fns = useMemo(() => parseAbiFunctions(contractAbi), [contractAbi]);
  const keyableFns = useMemo(() => functionsWithKeyableParam(fns), [fns]);
  const abiEvents = useMemo(() => parseAbiEvents(contractAbi), [contractAbi]);
  const keyableEvents = useMemo(() => eventsWithKeyableParam(abiEvents), [abiEvents]);
  const rendered = policy ? renderPolicy(policy) : [];
  const noAbi = !contractAbi;
  // Tier-2 org-admin control (RD-1206): editable by any non-read-only admin,
  // matching the contract's grants / ABI / visibleto-unlock managers. The admin
  // client authenticates with the org-admin JWT or the admin token.
  const canEdit = !isReadonlyAdmin;

  const compiled = useMemo(() => {
    try {
      return compileWizard(w);
    } catch {
      return null;
    }
  }, [w]);
  const clientError = mode === "structured" ? validateWizard(w, fns, abiEvents) : null;

  function resetBanners() {
    setError(null);
    setSuccess(null);
  }

  async function save(doc: MethodPolicyDocument | null): Promise<boolean> {
    setSaving(true);
    resetBanners();
    try {
      await rbacApi.contracts.updateMethodPolicies(orgId, contractAddress, doc);
      setPolicy(doc);
      setMode("none");
      setSuccess(doc ? "Method policy saved." : "Method policy cleared.");
      return true;
    } catch (e: unknown) {
      const err = e as { response?: { status?: number; data?: { error?: string } } };
      const status = err?.response?.status;
      const backendMsg = err?.response?.data?.error;
      if (status === 400 && backendMsg) setError(backendMsg);
      else if (status === 401 || status === 403) setError("Saving a method policy requires org-admin access for this organization.");
      else setError("Failed to save method policy.");
      return false;
    } finally {
      setSaving(false);
    }
  }

  function openStructured() {
    setW(policy ? decompileWizard(policy) : { records: [emptyRecord()] });
    resetBanners();
    setMode("structured");
  }
  function openJson() {
    setJsonText(JSON.stringify(policy ?? { records: {} }, null, 2));
    setJsonError(null);
    resetBanners();
    setMode("json");
  }
  function saveJson() {
    let parsed: MethodPolicyDocument;
    try {
      parsed = JSON.parse(jsonText) as MethodPolicyDocument;
    } catch (e) {
      setJsonError("Invalid JSON: " + (e as Error).message);
      return;
    }
    setJsonError(null);
    const isEmpty = !parsed.records || Object.keys(parsed.records).length === 0;
    void save(isEmpty ? null : parsed);
  }
  function clearPolicy() {
    if (typeof window !== "undefined" && !window.confirm(
      "Clear the method policy? Record-reader getters on this contract will revert to being readable by any member of a granted group."
    )) return;
    void save(null);
  }

  // ---- structured editor mutation helpers (immutable updates) ----
  const updateRecord = (ri: number, fn: (r: WizardRecord) => WizardRecord) =>
    setW({ records: w.records.map((r, i) => (i === ri ? fn(r) : r)) });

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-neutral-500" />
        <span className="text-sm font-medium text-neutral-700">Method access policies</span>
        {policy && <span className="text-xs px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">configured</span>}
      </div>
      <p className="text-xs text-neutral-500">
        Gate record-reader methods (e.g. <code>getPaymentInfo</code>) to a record&apos;s stakeholders, so only that
        payment&apos;s parties — and any designated settlement party or compliance principal — can read it.
      </p>

      {error && (
        <div className="p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-2">
          <ShieldAlert className="w-4 h-4 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}
      {success && <p className="text-xs text-success-dark flex items-center gap-1"><Check className="w-3 h-3" /> {success}</p>}

      {/* Current policy */}
      {rendered.length === 0 ? (
        <div className="p-3 rounded-lg border border-neutral-200 bg-neutral-50 text-xs text-neutral-600">
          No method policies configured — record-reader getters are gated by the contract grant only (any member of a
          granted group may read any record).
        </div>
      ) : (
        <div className="space-y-2">
          {rendered.map((r) => (
            <div key={r.recordType} className="p-3 rounded-lg border border-neutral-200 text-xs space-y-1">
              <div className="font-medium text-neutral-700">record: {r.recordType}</div>
              {r.readers.map((rd, i) => (
                <div key={i} className="text-neutral-600"><span className="font-mono">{rd.method}</span> readable by: {rd.allows.join("; ") || "(no one)"}</div>
              ))}
              {r.events.map((ev, i) => (
                <div key={`e${i}`} className="text-neutral-600">event <span className="font-mono">{ev.event}</span> admits: {ev.allows.join("; ") || "(no one)"}</div>
              ))}
              {r.transactions.map((t, i) => (
                <div key={`t${i}`} className="text-neutral-600">tx <span className="font-mono">{t.method}</span> admits: {t.allows.join("; ") || "(no one)"}</div>
              ))}
              {r.captures.map((c, i) => (
                <div key={`c${i}`} className="text-neutral-500">captured on <span className="font-mono">{c.method}</span>: {c.fields.join(", ")}</div>
              ))}
            </div>
          ))}
        </div>
      )}

      <div className="p-2 rounded bg-amber-50 border border-amber-200 flex items-start gap-2">
        <Info className="w-3.5 h-3.5 text-amber-600 mt-0.5 flex-shrink-0" />
        <p className="text-xs text-amber-700">
          The <strong>access</strong> section gates record-reader getters. The <strong>events</strong> and{" "}
          <strong>transactions</strong> sections additively admit the record&apos;s captured audience to matching
          logs / transactions (they widen, never narrow, the deny-by-default baseline). Use high-entropy, opaque
          record identifiers.
        </p>
      </div>

      {canEdit && mode === "none" && (
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={openStructured} disabled={noAbi}>{policy ? "Edit policy" : "Configure a policy"}</Button>
          <Button variant="ghost" size="sm" onClick={openJson} disabled={noAbi}>Edit JSON (advanced)</Button>
          {policy && <Button variant="ghost" size="sm" onClick={() => { resetBanners(); setMode("simulate"); }}><FlaskConical className="w-3 h-3" /> Simulate</Button>}
          {policy && <Button variant="ghost" size="sm" onClick={clearPolicy} disabled={saving}>Clear policy</Button>}
        </div>
      )}
      {isReadonlyAdmin && (
        <p className="text-xs text-neutral-500">Editing method policies requires org-admin (non-read-only) access; this view is read-only.</p>
      )}
      {canEdit && noAbi && <p className="text-xs text-neutral-500">Register the contract ABI first to configure method policies.</p>}

      {/* Structured editor */}
      {mode === "structured" && (
        <div className="p-3 rounded-lg border border-neutral-300 bg-white space-y-3" data-testid="method-policy-structured">
          {w.records.map((rec, ri) => (
            <RecordEditor
              key={ri}
              rec={rec}
              fns={fns}
              keyableFns={keyableFns}
              abiEvents={abiEvents}
              keyableEvents={keyableEvents}
              onChange={(fn) => updateRecord(ri, fn)}
              onRemove={() => setW({ records: w.records.filter((_, i) => i !== ri) })}
            />
          ))}
          <Button variant="ghost" size="sm" onClick={() => setW({ records: [...w.records, emptyRecord()] })}>
            <Plus className="w-3 h-3" /> add record type
          </Button>

          <div>
            <div className="text-xs font-medium text-neutral-600 mb-1">Policy preview</div>
            <pre className="text-[10px] bg-neutral-900 text-neutral-100 rounded p-2 overflow-auto max-h-48" data-testid="policy-preview">
              {compiled ? JSON.stringify(compiled, null, 2) : "…"}
            </pre>
          </div>
          {clientError && <p className="text-xs text-amber-700">{clientError}</p>}
          <div className="flex gap-2">
            <Button size="sm" disabled={saving || !!clientError || !compiled} onClick={() => compiled && void save(compiled)}>
              {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />} Save policy
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setMode("none")} disabled={saving}>Cancel</Button>
          </div>
        </div>
      )}

      {/* Advanced JSON */}
      {mode === "json" && (
        <div className="p-3 rounded-lg border border-neutral-300 bg-white space-y-2" data-testid="method-policy-json">
          <div className="text-xs text-neutral-600">Full policy document. Empty <code>{'{"records":{}}'}</code> clears it. Validated against the ABI on save; Simulate after saving to verify who can read.</div>
          <textarea className="w-full border rounded p-2 font-mono text-xs h-64" aria-label="Method policy JSON" value={jsonText} onChange={(e) => setJsonText(e.target.value)} spellCheck={false} />
          {jsonError && <p className="text-xs text-amber-700">{jsonError}</p>}
          <div className="flex gap-2">
            <Button size="sm" disabled={saving} onClick={saveJson}>{saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />} Save JSON</Button>
            <Button variant="ghost" size="sm" onClick={() => setMode("none")} disabled={saving}>Cancel</Button>
          </div>
        </div>
      )}

      {/* Simulator */}
      {mode === "simulate" && (
        <SimulatorPanel orgId={orgId} contractAddress={contractAddress} fns={fns} onClose={() => setMode("none")} />
      )}
    </div>
  );
}

// ---- Record editor ----
function RecordEditor({ rec, fns, keyableFns, abiEvents, keyableEvents, onChange, onRemove }: {
  rec: WizardRecord; fns: AbiFnInfo[]; keyableFns: AbiFnInfo[];
  abiEvents: AbiEventInfo[]; keyableEvents: AbiEventInfo[];
  onChange: (fn: (r: WizardRecord) => WizardRecord) => void; onRemove: () => void;
}) {
  const events = rec.events ?? [];
  const transactions = rec.transactions ?? [];
  return (
    <div className="border border-neutral-200 rounded p-2 space-y-2">
      <div className="flex items-center gap-2">
        <input className="border rounded px-2 py-1 text-sm w-48" placeholder="record type (payment)" aria-label="record type name"
          value={rec.recordType} onChange={(e) => onChange((r) => ({ ...r, recordType: e.target.value }))} />
        <button type="button" aria-label="remove record" className="ml-auto" onClick={onRemove}><X className="w-4 h-4 text-neutral-400" /></button>
      </div>

      {/* Captures */}
      <div className="text-xs font-medium text-neutral-600">Captures (who are the record&apos;s parties)</div>
      {rec.captures.map((cap, ci) => (
        <CaptureEditor key={ci} cap={cap} keyableFns={keyableFns} fns={fns}
          onChange={(fn) => onChange((r) => ({ ...r, captures: r.captures.map((c, i) => (i === ci ? fn(c) : c)) }))}
          onRemove={() => onChange((r) => ({ ...r, captures: r.captures.filter((_, i) => i !== ci) }))} />
      ))}
      <Button variant="ghost" size="sm" onClick={() => onChange((r) => ({ ...r, captures: [...r.captures, { writerSig: "", keyIndex: 0, remember: [{ field: "", source: "sender", merge: "set_once" }] }] }))}>
        <Plus className="w-3 h-3" /> add capture
      </Button>

      {/* Readers */}
      <div className="text-xs font-medium text-neutral-600">Readers to gate</div>
      {rec.readers.map((rd, di) => (
        <ReaderEditor key={di} rd={rd} keyableFns={keyableFns} fns={fns} rec={rec}
          onChange={(fn) => onChange((r) => ({ ...r, readers: r.readers.map((x, i) => (i === di ? fn(x) : x)) }))}
          onRemove={() => onChange((r) => ({ ...r, readers: r.readers.filter((_, i) => i !== di) }))} />
      ))}
      <Button variant="ghost" size="sm" onClick={() => onChange((r) => ({ ...r, readers: [...r.readers, { readerSig: "", keyIndex: 0, rules: [{ kind: "callerIn", fields: [], principals: [], returnPaths: [], where: null }] }] }))}>
        <Plus className="w-3 h-3" /> add reader
      </Button>

      {/* Events (additive) */}
      <div className="text-xs font-medium text-neutral-600">Event logs to gate (additive — admits the record audience)</div>
      {events.map((ev, ei) => (
        <EventEditor key={ei} ev={ev} keyableEvents={keyableEvents} abiEvents={abiEvents} rec={rec}
          onChange={(fn) => onChange((r) => ({ ...r, events: (r.events ?? []).map((x, i) => (i === ei ? fn(x) : x)) }))}
          onRemove={() => onChange((r) => ({ ...r, events: (r.events ?? []).filter((_, i) => i !== ei) }))} />
      ))}
      <Button variant="ghost" size="sm" onClick={() => onChange((r) => ({ ...r, events: [...(r.events ?? []), emptyEvent()] }))}>
        <Plus className="w-3 h-3" /> add event
      </Button>

      {/* Transactions (additive) */}
      <div className="text-xs font-medium text-neutral-600">Transactions to gate (additive — admits the record audience)</div>
      {transactions.map((tx, ti) => (
        <TransactionEditor key={ti} tx={tx} keyableFns={keyableFns} fns={fns} rec={rec}
          onChange={(fn) => onChange((r) => ({ ...r, transactions: (r.transactions ?? []).map((x, i) => (i === ti ? fn(x) : x)) }))}
          onRemove={() => onChange((r) => ({ ...r, transactions: (r.transactions ?? []).filter((_, i) => i !== ti) }))} />
      ))}
      <Button variant="ghost" size="sm" onClick={() => onChange((r) => ({ ...r, transactions: [...(r.transactions ?? []), emptyTransaction()] }))}>
        <Plus className="w-3 h-3" /> add transaction
      </Button>
    </div>
  );
}

function methodBySig(fns: AbiFnInfo[], sig: string) { return fns.find((f) => f.signature === sig); }

function KeyParamSelect({ fn, value, onChange, label }: { fn?: AbiFnInfo; value: number; onChange: (i: number) => void; label: string }) {
  return (
    <select className="border rounded px-2 py-1 text-sm" aria-label={label} value={value} onChange={(e) => onChange(Number(e.target.value))}>
      {(fn?.inputs ?? []).map((p, i) => (
        <option key={i} value={i} disabled={!isCanonicalizableKeyType(p.type)}>{i}: {p.name} ({p.type})</option>
      ))}
    </select>
  );
}

// Event key select. An indexed dynamic param (indexed string/bytes) is not
// recoverable from a log topic, so it is disabled with a hint.
function EventKeyParamSelect({ ev, value, onChange, label }: { ev?: AbiEventInfo; value: number; onChange: (i: number) => void; label: string }) {
  return (
    <select className="border rounded px-2 py-1 text-sm" aria-label={label} value={value} onChange={(e) => onChange(Number(e.target.value))}>
      {(ev?.inputs ?? []).map((p, i) => {
        const indexedDynamic = p.indexed && isDynamicType(p.type);
        const bad = !isCanonicalizableKeyType(p.type) || indexedDynamic;
        return (
          <option key={i} value={i} disabled={bad}>
            {i}: {p.name} ({p.type}{p.indexed ? " indexed" : ""}){indexedDynamic ? " — not recoverable" : ""}
          </option>
        );
      })}
    </select>
  );
}

// ---- Capture editor ----
function CaptureEditor({ cap, keyableFns, fns, onChange, onRemove }: {
  cap: WizardCapture; keyableFns: AbiFnInfo[]; fns: AbiFnInfo[];
  onChange: (fn: (c: WizardCapture) => WizardCapture) => void; onRemove: () => void;
}) {
  const writer = methodBySig(fns, cap.writerSig);
  return (
    <div className="border border-neutral-100 rounded p-2 space-y-1 bg-neutral-50">
      <div className="flex flex-wrap items-center gap-1">
        <select className="border rounded px-2 py-1 text-sm" aria-label="writer method" value={cap.writerSig}
          onChange={(e) => onChange((c) => ({ ...c, writerSig: e.target.value, keyIndex: 0 }))}>
          <option value="">writer method…</option>
          {keyableFns.map((f) => <option key={f.signature} value={f.signature}>{f.signature}</option>)}
        </select>
        <span className="text-xs text-neutral-500">key</span>
        <KeyParamSelect fn={writer} value={cap.keyIndex} onChange={(i) => onChange((c) => ({ ...c, keyIndex: i }))} label="writer key parameter" />
        <button type="button" aria-label="remove capture" className="ml-auto" onClick={onRemove}><X className="w-3.5 h-3.5 text-neutral-400" /></button>
      </div>
      {cap.remember.map((r, ri) => (
        <div key={ri} className="flex flex-wrap items-center gap-1">
          <input className="border rounded px-2 py-1 text-sm w-40 shrink-0" placeholder="field (payer)" aria-label={`capture field ${ri} name`}
            value={r.field} onChange={(e) => onChange((c) => ({ ...c, remember: c.remember.map((x, i) => (i === ri ? { ...x, field: e.target.value } : x)) }))} />
          <select className="border rounded px-2 py-1 text-sm shrink-0" aria-label={`capture field ${ri} source`} value={r.source}
            onChange={(e) => {
              const src = e.target.value as WizardCapture["remember"][number]["source"];
              onChange((c) => ({ ...c, remember: c.remember.map((x, i) => (i === ri ? { ...x, source: src, merge: src === "visibleTo" ? "union" : "set_once" } : x)) }));
            }}>
            <option value="sender">sender</option>
            <option value="param">param</option>
            <option value="visibleTo">visibleTo</option>
          </select>
          {r.source === "param" && (
            <select className="border rounded px-2 py-1 text-sm shrink-0" aria-label={`capture field ${ri} param index`} value={r.paramIndex ?? ""}
              onChange={(e) => onChange((c) => ({ ...c, remember: c.remember.map((x, i) => (i === ri ? { ...x, paramIndex: Number(e.target.value) } : x)) }))}>
              <option value="">param…</option>
              {(writer?.inputs ?? []).map((p, pi) => <option key={pi} value={pi}>{pi}: {p.name} ({p.type})</option>)}
            </select>
          )}
          {r.source === "visibleTo" ? (
            <span className="text-xs text-neutral-500 px-1" aria-label={`capture field ${ri} merge`}>union</span>
          ) : (
            <select className="border rounded px-2 py-1 text-sm shrink-0" aria-label={`capture field ${ri} merge`} value={r.merge}
              onChange={(e) => onChange((c) => ({ ...c, remember: c.remember.map((x, i) => (i === ri ? { ...x, merge: e.target.value as "set_once" | "union" } : x)) }))}>
              <option value="set_once">set_once</option>
              <option value="union">union</option>
            </select>
          )}
          <button type="button" aria-label={`remove capture field ${ri}`} onClick={() => onChange((c) => ({ ...c, remember: c.remember.filter((_, i) => i !== ri) }))}><X className="w-3.5 h-3.5 text-neutral-400" /></button>
        </div>
      ))}
      <Button variant="ghost" size="sm" onClick={() => onChange((c) => ({ ...c, remember: [...c.remember, { field: "", source: "sender", merge: "set_once" }] }))}>
        <Plus className="w-3 h-3" /> capture field
      </Button>
    </div>
  );
}

// captured field names available for a record (across all its captures).
function recordFieldNames(rec: WizardRecord): string[] {
  const s = new Set<string>();
  for (const c of rec.captures) for (const r of c.remember) if (r.field.trim()) s.add(r.field.trim());
  return [...s];
}

// ---- Reader editor ----
function ReaderEditor({ rd, keyableFns, fns, rec, onChange, onRemove }: {
  rd: WizardReader; keyableFns: AbiFnInfo[]; fns: AbiFnInfo[]; rec: WizardRecord;
  onChange: (fn: (r: WizardReader) => WizardReader) => void; onRemove: () => void;
}) {
  const reader = methodBySig(fns, rd.readerSig);
  const fieldNames = recordFieldNames(rec);
  return (
    <div className="border border-neutral-100 rounded p-2 space-y-1 bg-neutral-50">
      <div className="flex flex-wrap items-center gap-1">
        <select className="border rounded px-2 py-1 text-sm" aria-label="reader method" value={rd.readerSig}
          onChange={(e) => onChange((r) => ({ ...r, readerSig: e.target.value, keyIndex: 0 }))}>
          <option value="">reader method…</option>
          {keyableFns.map((f) => <option key={f.signature} value={f.signature}>{f.signature}</option>)}
        </select>
        <span className="text-xs text-neutral-500">key</span>
        <KeyParamSelect fn={reader} value={rd.keyIndex} onChange={(i) => onChange((r) => ({ ...r, keyIndex: i }))} label="reader key parameter" />
        <button type="button" aria-label="remove reader" className="ml-auto" onClick={onRemove}><X className="w-3.5 h-3.5 text-neutral-400" /></button>
      </div>
      {rd.rules.map((rule, ui) => (
        <RuleEditor key={ui} rule={rule} reader={reader} fieldNames={fieldNames}
          onChange={(fn) => onChange((r) => ({ ...r, rules: r.rules.map((x, i) => (i === ui ? fn(x) : x)) }))}
          onRemove={() => onChange((r) => ({ ...r, rules: r.rules.filter((_, i) => i !== ui) }))} />
      ))}
      <Button variant="ghost" size="sm" onClick={() => onChange((r) => ({ ...r, rules: [...r.rules, { kind: "callerIn", fields: [], principals: [], returnPaths: [], where: null }] }))}>
        <Plus className="w-3 h-3" /> allow rule
      </Button>
    </div>
  );
}

// ---- Rule editor ----
function RuleEditor({ rule, reader, fieldNames, onChange, onRemove }: {
  rule: WizardAllowRule; reader?: AbiFnInfo; fieldNames: string[];
  onChange: (fn: (r: WizardAllowRule) => WizardAllowRule) => void; onRemove: () => void;
}) {
  return (
    <div className="border-l-2 border-neutral-200 pl-2 ml-1 space-y-1">
      <div className="flex items-center gap-2">
        <span className="text-xs text-neutral-500">allow when caller</span>
        <select className="border rounded px-1 py-0.5 text-xs" aria-label="rule kind" value={rule.kind}
          onChange={(e) => onChange((r) => ({ ...r, kind: e.target.value as "callerIn" | "return" }))}>
          <option value="callerIn">is a captured party / principal</option>
          <option value="return">matches a returned address</option>
        </select>
        <button type="button" aria-label="remove rule" className="ml-auto" onClick={onRemove}><X className="w-3 h-3 text-neutral-400" /></button>
      </div>

      {rule.kind === "callerIn" ? (
        <>
          <div className="flex flex-wrap gap-2">
            {fieldNames.map((f) => (
              <label key={f} className="text-xs flex items-center gap-1">
                <input type="checkbox" aria-label={`allow field ${f}`} checked={rule.fields.includes(f)}
                  onChange={(e) => onChange((r) => ({ ...r, fields: e.target.checked ? [...r.fields, f] : r.fields.filter((x) => x !== f) }))} />
                {f}
              </label>
            ))}
          </div>
          <input className="border rounded px-2 py-1 text-xs w-full" aria-label="literal principals"
            placeholder="literal principals (comma-separated did:… or 0x…)" value={rule.principals.join(", ")}
            onChange={(e) => onChange((r) => ({ ...r, principals: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) }))} />
          {/* optional where */}
          {rule.where ? (
            <div className="flex flex-wrap items-center gap-1">
              <span className="text-xs text-neutral-500">and</span>
              <select className="border rounded px-1 py-0.5 text-xs" aria-label="where field" value={rule.where.field}
                onChange={(e) => onChange((r) => ({ ...r, where: { ...r.where!, field: e.target.value } }))}>
                <option value="">field…</option>
                {fieldNames.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
              <select className="border rounded px-1 py-0.5 text-xs" aria-label="where op" value={rule.where.op}
                onChange={(e) => onChange((r) => ({ ...r, where: { ...r.where!, op: e.target.value } }))}>
                {WHERE_OPS.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
              <input className="border rounded px-2 py-0.5 text-xs w-32" aria-label="where value" placeholder="value" value={rule.where.value}
                onChange={(e) => onChange((r) => ({ ...r, where: { ...r.where!, value: e.target.value } }))} />
              <button type="button" aria-label="remove where" onClick={() => onChange((r) => ({ ...r, where: null }))}><X className="w-3 h-3 text-neutral-400" /></button>
            </div>
          ) : (
            <Button variant="ghost" size="sm" onClick={() => onChange((r) => ({ ...r, where: { field: fieldNames[0] ?? "", op: "gte", value: "" } }))}>
              <Plus className="w-3 h-3" /> add condition (where)
            </Button>
          )}
        </>
      ) : (
        <div className="flex flex-wrap gap-2">
          {(reader?.addressOutputs ?? []).length === 0 && <span className="text-xs text-neutral-400">reader has no address outputs</span>}
          {(reader?.addressOutputs ?? []).map((o) => (
            <label key={o.name} className="text-xs flex items-center gap-1">
              <input type="checkbox" aria-label={`allow return ${o.name}`} checked={rule.returnPaths.includes(o.name)}
                onChange={(e) => onChange((r) => ({ ...r, returnPaths: e.target.checked ? [...r.returnPaths, o.name] : r.returnPaths.filter((x) => x !== o.name) }))} />
              {o.name}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

// ---- Event editor ----
function EventEditor({ ev, keyableEvents, abiEvents, rec, onChange, onRemove }: {
  ev: WizardEvent; keyableEvents: AbiEventInfo[]; abiEvents: AbiEventInfo[]; rec: WizardRecord;
  onChange: (fn: (e: WizardEvent) => WizardEvent) => void; onRemove: () => void;
}) {
  const info = abiEvents.find((e) => e.signature === ev.eventSig);
  const fieldNames = recordFieldNames(rec);
  return (
    <div className="border border-neutral-100 rounded p-2 space-y-1 bg-neutral-50">
      <div className="flex flex-wrap items-center gap-1">
        <select className="border rounded px-2 py-1 text-sm" aria-label="event" value={ev.eventSig}
          onChange={(e) => onChange((x) => ({ ...x, eventSig: e.target.value, keyIndex: 0 }))}>
          <option value="">event…</option>
          {keyableEvents.map((e) => <option key={e.signature} value={e.signature}>{e.signature}</option>)}
        </select>
        <span className="text-xs text-neutral-500">key</span>
        <EventKeyParamSelect ev={info} value={ev.keyIndex} onChange={(i) => onChange((x) => ({ ...x, keyIndex: i }))} label="event key parameter" />
        <button type="button" aria-label="remove event" className="ml-auto" onClick={onRemove}><X className="w-3.5 h-3.5 text-neutral-400" /></button>
      </div>
      {ev.rules.map((rule, ui) => (
        <AudienceRuleEditor key={ui} rule={rule} fieldNames={fieldNames} labelPrefix="event"
          onChange={(fn) => onChange((x) => ({ ...x, rules: x.rules.map((r, i) => (i === ui ? fn(r) : r)) }))}
          onRemove={() => onChange((x) => ({ ...x, rules: x.rules.filter((_, i) => i !== ui) }))} />
      ))}
      <Button variant="ghost" size="sm" onClick={() => onChange((x) => ({ ...x, rules: [...x.rules, emptyAudienceRule()] }))}>
        <Plus className="w-3 h-3" /> allow rule
      </Button>
    </div>
  );
}

// ---- Transaction editor ----
function TransactionEditor({ tx, keyableFns, fns, rec, onChange, onRemove }: {
  tx: WizardTransaction; keyableFns: AbiFnInfo[]; fns: AbiFnInfo[]; rec: WizardRecord;
  onChange: (fn: (t: WizardTransaction) => WizardTransaction) => void; onRemove: () => void;
}) {
  const writer = methodBySig(fns, tx.methodSig);
  const fieldNames = recordFieldNames(rec);
  return (
    <div className="border border-neutral-100 rounded p-2 space-y-1 bg-neutral-50">
      <div className="flex flex-wrap items-center gap-1">
        <select className="border rounded px-2 py-1 text-sm" aria-label="transaction method" value={tx.methodSig}
          onChange={(e) => onChange((x) => ({ ...x, methodSig: e.target.value, keyIndex: 0 }))}>
          <option value="">transaction method…</option>
          {keyableFns.map((f) => <option key={f.signature} value={f.signature}>{f.signature}</option>)}
        </select>
        <span className="text-xs text-neutral-500">key</span>
        <KeyParamSelect fn={writer} value={tx.keyIndex} onChange={(i) => onChange((x) => ({ ...x, keyIndex: i }))} label="transaction key parameter" />
        <button type="button" aria-label="remove transaction" className="ml-auto" onClick={onRemove}><X className="w-3.5 h-3.5 text-neutral-400" /></button>
      </div>
      {tx.rules.map((rule, ui) => (
        <AudienceRuleEditor key={ui} rule={rule} fieldNames={fieldNames} labelPrefix="transaction"
          onChange={(fn) => onChange((x) => ({ ...x, rules: x.rules.map((r, i) => (i === ui ? fn(r) : r)) }))}
          onRemove={() => onChange((x) => ({ ...x, rules: x.rules.filter((_, i) => i !== ui) }))} />
      ))}
      <Button variant="ghost" size="sm" onClick={() => onChange((x) => ({ ...x, rules: [...x.rules, emptyAudienceRule()] }))}>
        <Plus className="w-3 h-3" /> allow rule
      </Button>
    </div>
  );
}

// ---- Audience rule editor (callerIn-only; events/transactions) ----
function AudienceRuleEditor({ rule, fieldNames, labelPrefix, onChange, onRemove }: {
  rule: WizardAudienceRule; fieldNames: string[]; labelPrefix: string;
  onChange: (fn: (r: WizardAudienceRule) => WizardAudienceRule) => void; onRemove: () => void;
}) {
  return (
    <div className="border-l-2 border-neutral-200 pl-2 ml-1 space-y-1">
      <div className="flex items-center gap-2">
        <span className="text-xs text-neutral-500">admit when caller is a captured party / principal</span>
        <button type="button" aria-label={`remove ${labelPrefix} rule`} className="ml-auto" onClick={onRemove}><X className="w-3 h-3 text-neutral-400" /></button>
      </div>
      <div className="flex flex-wrap gap-2">
        {fieldNames.map((f) => (
          <label key={f} className="text-xs flex items-center gap-1">
            <input type="checkbox" aria-label={`${labelPrefix} allow field ${f}`} checked={rule.fields.includes(f)}
              onChange={(e) => onChange((r) => ({ ...r, fields: e.target.checked ? [...r.fields, f] : r.fields.filter((x) => x !== f) }))} />
            {f}
          </label>
        ))}
      </div>
      <input className="border rounded px-2 py-1 text-xs w-full" aria-label={`${labelPrefix} literal principals`}
        placeholder="literal principals (comma-separated did:… or 0x…)" value={rule.principals.join(", ")}
        onChange={(e) => onChange((r) => ({ ...r, principals: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) }))} />
      {rule.where ? (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-xs text-neutral-500">and</span>
          <select className="border rounded px-1 py-0.5 text-xs" aria-label={`${labelPrefix} where field`} value={rule.where.field}
            onChange={(e) => onChange((r) => ({ ...r, where: { ...r.where!, field: e.target.value } }))}>
            <option value="">field…</option>
            {fieldNames.map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          <select className="border rounded px-1 py-0.5 text-xs" aria-label={`${labelPrefix} where op`} value={rule.where.op}
            onChange={(e) => onChange((r) => ({ ...r, where: { ...r.where!, op: e.target.value } }))}>
            {WHERE_OPS.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input className="border rounded px-2 py-0.5 text-xs w-32" aria-label={`${labelPrefix} where value`} placeholder="value" value={rule.where.value}
            onChange={(e) => onChange((r) => ({ ...r, where: { ...r.where!, value: e.target.value } }))} />
          <button type="button" aria-label={`remove ${labelPrefix} where`} onClick={() => onChange((r) => ({ ...r, where: null }))}><X className="w-3 h-3 text-neutral-400" /></button>
        </div>
      ) : (
        <Button variant="ghost" size="sm" onClick={() => onChange((r) => ({ ...r, where: { field: fieldNames[0] ?? "", op: "gte", value: "" } }))}>
          <Plus className="w-3 h-3" /> add condition (where)
        </Button>
      )}
    </div>
  );
}

// ---- Simulator panel ----
function SimulatorPanel({ orgId, contractAddress, fns, onClose }: { orgId: string; contractAddress: string; fns: AbiFnInfo[]; onClose: () => void }) {
  const [method, setMethod] = useState("");
  const [recordKey, setRecordKey] = useState("");
  const [callerDID, setCallerDID] = useState("");
  const [callerETH, setCallerETH] = useState("");
  const [running, setRunning] = useState(false);
  type SimResult = { result: string; matched_rule?: string; note?: string; captured: Record<string, string[]> };
  const [result, setResult] = useState<SimResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    setRunning(true);
    setErr(null);
    setResult(null);
    try {
      const res = await rbacApi.contracts.simulateMethodPolicy(orgId, contractAddress, {
        method,
        record_key: recordKey,
        caller_did: callerDID,
        caller_eth_addresses: callerETH.split(",").map((s) => s.trim()).filter(Boolean),
      });
      setResult(res.data as SimResult);
    } catch (e: unknown) {
      const ee = e as { response?: { data?: { error?: string } } };
      setErr(ee?.response?.data?.error ?? "Simulation failed.");
    } finally {
      setRunning(false);
    }
  }

  const badge = result?.result === "allow" ? "bg-emerald-100 text-emerald-800"
    : result?.result === "deny" ? "bg-error-light text-error-dark" : "bg-amber-100 text-amber-800";

  return (
    <div className="p-3 rounded-lg border border-neutral-300 bg-white space-y-2" data-testid="method-policy-simulate">
      <div className="text-xs text-neutral-600 flex items-center gap-1"><FlaskConical className="w-3.5 h-3.5" /> Simulate: would a caller be allowed to read a record? (no on-chain call; the live return-address rule is not simulated)</div>
      <div className="grid grid-cols-2 gap-2">
        <select className="border rounded px-2 py-1 text-sm" aria-label="simulate method" value={method} onChange={(e) => setMethod(e.target.value)}>
          <option value="">reader method…</option>
          {fns.map((f) => <option key={f.signature} value={f.signature}>{f.signature}</option>)}
        </select>
        <input className="border rounded px-2 py-1 text-sm" aria-label="simulate record key" placeholder="record key (PAY-123)" value={recordKey} onChange={(e) => setRecordKey(e.target.value)} />
        <input className="border rounded px-2 py-1 text-sm" aria-label="simulate caller did" placeholder="caller DID (did:…)" value={callerDID} onChange={(e) => setCallerDID(e.target.value)} />
        <input className="border rounded px-2 py-1 text-sm" aria-label="simulate caller eth" placeholder="caller ETH addresses (0x…, comma-sep)" value={callerETH} onChange={(e) => setCallerETH(e.target.value)} />
      </div>
      {err && <p className="text-xs text-amber-700">{err}</p>}
      {result && (
        <div className="text-xs space-y-1">
          <div><span className={`px-2 py-0.5 rounded font-medium ${badge}`}>{result.result}</span>{result.matched_rule ? <span className="ml-2 text-neutral-500">via {result.matched_rule}</span> : null}</div>
          {result.note && <p className="text-amber-700">{result.note}</p>}
          <div className="text-neutral-500">record admit-set: {Object.entries(result.captured || {}).map(([k, v]) => `${k}=[${v.join(", ")}]`).join("; ") || "(none captured)"}</div>
        </div>
      )}
      <div className="flex gap-2">
        <Button size="sm" disabled={running || !method || !recordKey} onClick={() => void run()}>{running ? <Loader2 className="w-3 h-3 animate-spin" /> : <FlaskConical className="w-3 h-3" />} Simulate</Button>
        <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
      </div>
    </div>
  );
}
