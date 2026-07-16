// RD-1206 guided policy wizard. A step-by-step front end over the SAME tested
// model as the flat form (compileWizard/validateWizard in lib/methodPolicy): it
// walks an admin through one record's lifecycle — identify it, name its parties,
// gate its readers, then (optionally) admit those parties to its events and
// transactions — in plain language, with smart defaults, and a plain-English
// review before saving. Power-user dimensions (where-conditions, multiple allow
// rules) are preserved on edit but authored in the "Form editor (advanced)".
import { useMemo, useState } from "react";
import type { MethodPolicyDocument } from "@/types/rbac";
import {
  compileWizard,
  validateWizard,
  isCanonicalizableKeyType,
  isDynamicType,
  type AbiFnInfo,
  type AbiEventInfo,
  type WizardRecord,
  type WizardCapture,
  type WizardRememberField,
} from "@/lib/methodPolicy";
import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight, Plus, X, Check, Loader2, Info } from "lucide-react";

const STEPS = [
  { title: "Record", hint: "What this contract keeps private" },
  { title: "Parties", hint: "Who is on a record" },
  { title: "Readers", hint: "Who can read it" },
  { title: "Events", hint: "Logs parties may see", optional: true },
  { title: "Transactions", hint: "Txs parties may see", optional: true },
  { title: "Review", hint: "Confirm and save" },
];

// Pick the parameter that carries the record key on another method/event: prefer
// the same name as the identity chosen in step 1, then the same type, then the
// first usable one. Events must avoid an indexed dynamic (unrecoverable) key.
function autoKeyIndex(
  params: { name: string; type: string; indexed?: boolean }[],
  keyName: string,
  keyType: string,
  avoidIndexedDynamic = false,
): number {
  const ok = (p: { type: string; indexed?: boolean }) =>
    isCanonicalizableKeyType(p.type) && !(avoidIndexedDynamic && p.indexed && isDynamicType(p.type));
  let i = params.findIndex((p) => p.name === keyName && ok(p));
  if (i >= 0) return i;
  i = params.findIndex((p) => p.type === keyType && ok(p));
  if (i >= 0) return i;
  i = params.findIndex(ok);
  return i >= 0 ? i : 0;
}

function partyNamesOf(rec: WizardRecord): string[] {
  const s = new Set<string>();
  for (const c of rec.captures) for (const r of c.remember) if (r.field.trim()) s.add(r.field.trim());
  return [...s];
}

function sourceLabel(r: WizardRememberField, writer?: AbiFnInfo): string {
  if (r.source === "sender") return "the caller (sender)";
  if (r.source === "visibleTo") return "the visibleTo list";
  const p = r.paramIndex != null ? writer?.inputs[r.paramIndex] : undefined;
  return p ? `the “${p.name}” parameter` : "a parameter";
}

export function MethodPolicyWizard({
  fns,
  keyableFns,
  abiEvents,
  keyableEvents,
  initialRecord,
  otherRecords,
  saving,
  onSave,
  onCancel,
}: {
  fns: AbiFnInfo[];
  keyableFns: AbiFnInfo[];
  abiEvents: AbiEventInfo[];
  keyableEvents: AbiEventInfo[];
  initialRecord: WizardRecord;
  otherRecords: WizardRecord[];
  saving: boolean;
  onSave: (doc: MethodPolicyDocument) => void;
  onCancel: () => void;
}) {
  const [step, setStep] = useState(0);
  const [rec, setRec] = useState<WizardRecord>(initialRecord);

  const cap = rec.captures[0] ?? { writerSig: "", keyIndex: 0, remember: [] };
  const writer = fns.find((f) => f.signature === cap.writerSig);
  const keyParam = writer ? writer.inputs[cap.keyIndex] : undefined;
  const keyName = keyParam?.name ?? "";
  const keyType = keyParam?.type ?? "";
  const parties = partyNamesOf(rec);
  const rememberRows = cap.remember;

  const state = useMemo(() => ({ records: [rec, ...otherRecords] }), [rec, otherRecords]);
  const compiled = useMemo(() => {
    try {
      return compileWizard(state);
    } catch {
      return null;
    }
  }, [state]);
  const fullError = useMemo(() => validateWizard(state, fns, abiEvents), [state, fns, abiEvents]);

  // ---- mutation helpers (all immutable) ----
  const setCap = (fn: (c: WizardCapture) => WizardCapture) =>
    setRec((r) => {
      const c0 = r.captures[0] ?? { writerSig: "", keyIndex: 0, remember: [] };
      return { ...r, captures: [fn(c0), ...r.captures.slice(1)] };
    });
  const setRemember = (fn: (rows: WizardRememberField[]) => WizardRememberField[]) =>
    setCap((c) => ({ ...c, remember: fn(c.remember) }));

  const isReader = (sig: string) => rec.readers.some((r) => r.readerSig === sig);
  const readerFields = (sig: string) =>
    rec.readers.find((r) => r.readerSig === sig)?.rules.find((x) => x.kind === "callerIn")?.fields ?? [];
  const readerPrincipals = (sig: string) =>
    rec.readers.find((r) => r.readerSig === sig)?.rules.find((x) => x.kind === "callerIn")?.principals ?? [];
  const readerHasReturn = (sig: string) =>
    rec.readers.find((r) => r.readerSig === sig)?.rules.some((x) => x.kind === "return") ?? false;

  const toggleReader = (sig: string) =>
    setRec((r) => {
      if (r.readers.some((x) => x.readerSig === sig)) return { ...r, readers: r.readers.filter((x) => x.readerSig !== sig) };
      const fn = fns.find((f) => f.signature === sig);
      const ki = fn ? autoKeyIndex(fn.inputs, keyName, keyType) : 0;
      return {
        ...r,
        readers: [...r.readers, { readerSig: sig, keyIndex: ki, rules: [{ kind: "callerIn", fields: partyNamesOf(r), principals: [], returnPaths: [], where: null }] }],
      };
    });
  // Update the first callerIn rule of a reader (create one if absent); leaves any
  // other rules (where-conditions, return rules) authored in the form untouched.
  const editReaderCaller = (
    sig: string,
    fn: (rule: { fields: string[]; principals: string[] }) => { fields: string[]; principals: string[] },
  ) =>
    setRec((r) => ({
      ...r,
      readers: r.readers.map((rd) => {
        if (rd.readerSig !== sig) return rd;
        let idx = rd.rules.findIndex((x) => x.kind === "callerIn");
        const rules = rd.rules.slice();
        if (idx < 0) {
          rules.push({ kind: "callerIn", fields: [], principals: [], returnPaths: [], where: null });
          idx = rules.length - 1;
        }
        const upd = fn({ fields: rules[idx].fields, principals: rules[idx].principals });
        rules[idx] = { ...rules[idx], fields: upd.fields, principals: upd.principals };
        return { ...rd, rules };
      }),
    }));
  const toggleReaderField = (sig: string, field: string) =>
    editReaderCaller(sig, (r) => ({ ...r, fields: r.fields.includes(field) ? r.fields.filter((f) => f !== field) : [...r.fields, field] }));
  const setReaderPrincipals = (sig: string, principals: string[]) => editReaderCaller(sig, (r) => ({ ...r, principals }));
  const toggleReaderReturn = (sig: string) =>
    setRec((r) => ({
      ...r,
      readers: r.readers.map((rd) => {
        if (rd.readerSig !== sig) return rd;
        if (rd.rules.some((x) => x.kind === "return")) return { ...rd, rules: rd.rules.filter((x) => x.kind !== "return") };
        const fn = fns.find((f) => f.signature === sig);
        const paths = (fn?.addressOutputs ?? []).map((o) => o.name);
        return { ...rd, rules: [...rd.rules, { kind: "return", fields: [], principals: [], returnPaths: paths, where: null }] };
      }),
    }));

  // Events / transactions share the callerIn-only audience-rule shape.
  const isEvent = (sig: string) => (rec.events ?? []).some((e) => e.eventSig === sig);
  const eventFields = (sig: string) => (rec.events ?? []).find((e) => e.eventSig === sig)?.rules[0]?.fields ?? [];
  const toggleEvent = (sig: string) =>
    setRec((r) => {
      const evs = r.events ?? [];
      if (evs.some((e) => e.eventSig === sig)) return { ...r, events: evs.filter((e) => e.eventSig !== sig) };
      const info = abiEvents.find((e) => e.signature === sig);
      const ki = info ? autoKeyIndex(info.inputs, keyName, keyType, true) : 0;
      return { ...r, events: [...evs, { eventSig: sig, keyIndex: ki, rules: [{ fields: partyNamesOf(r), principals: [], where: null }] }] };
    });
  const toggleEventField = (sig: string, field: string) =>
    setRec((r) => ({
      ...r,
      events: (r.events ?? []).map((e) => {
        if (e.eventSig !== sig) return e;
        const rules = e.rules.length ? e.rules : [{ fields: [], principals: [], where: null }];
        const r0 = rules[0];
        return { ...e, rules: [{ ...r0, fields: r0.fields.includes(field) ? r0.fields.filter((f) => f !== field) : [...r0.fields, field] }, ...rules.slice(1)] };
      }),
    }));

  const isTx = (sig: string) => (rec.transactions ?? []).some((t) => t.methodSig === sig);
  const txFields = (sig: string) => (rec.transactions ?? []).find((t) => t.methodSig === sig)?.rules[0]?.fields ?? [];
  const toggleTx = (sig: string) =>
    setRec((r) => {
      const txs = r.transactions ?? [];
      if (txs.some((t) => t.methodSig === sig)) return { ...r, transactions: txs.filter((t) => t.methodSig !== sig) };
      const fn = fns.find((f) => f.signature === sig);
      const ki = fn ? autoKeyIndex(fn.inputs, keyName, keyType) : 0;
      return { ...r, transactions: [...txs, { methodSig: sig, keyIndex: ki, rules: [{ fields: partyNamesOf(r), principals: [], where: null }] }] };
    });
  const toggleTxField = (sig: string, field: string) =>
    setRec((r) => ({
      ...r,
      transactions: (r.transactions ?? []).map((t) => {
        if (t.methodSig !== sig) return t;
        const rules = t.rules.length ? t.rules : [{ fields: [], principals: [], where: null }];
        const r0 = rules[0];
        return { ...t, rules: [{ ...r0, fields: r0.fields.includes(field) ? r0.fields.filter((f) => f !== field) : [...r0.fields, field] }, ...rules.slice(1)] };
      }),
    }));

  // ---- per-step gate (why "Next" is disabled) ----
  const namedParties = rememberRows.filter((x) => x.field.trim());
  const stepErr = ((): string | null => {
    switch (step) {
      case 0:
        if (!rec.recordType.trim()) return "Name the record (e.g. “payment”).";
        if (!writer) return "Choose the function that creates a record.";
        if (!(keyParam && isCanonicalizableKeyType(keyParam.type))) return "Choose the parameter that identifies each record.";
        return null;
      case 1:
        if (namedParties.length === 0) return "Add at least one party (e.g. payer).";
        if (rememberRows.some((x) => x.field.trim() && x.source === "param" && (x.paramIndex == null || !writer?.inputs[x.paramIndex])))
          return "For a parameter-sourced party, pick which parameter holds it.";
        return null;
      case 2:
        if (rec.readers.length === 0) return "Pick at least one function that reads a record.";
        if (rec.readers.some((rd) => !rd.rules.some((x) => x.kind === "return") && readerFields(rd.readerSig).length === 0 && readerPrincipals(rd.readerSig).length === 0))
          return "Each reader needs at least one allowed party (or the returned address).";
        return null;
      case 5:
        return fullError;
      default:
        return null; // 3, 4 optional
    }
  })();

  const canSave = step === 5 && !saving && !fullError && !!compiled;

  return (
    <div className="p-3 rounded-lg border border-neutral-300 bg-white space-y-3" data-testid="method-policy-wizard">
      {/* progress */}
      <ol className="flex flex-wrap gap-1.5 text-xs">
        {STEPS.map((s, i) => (
          <li key={s.title}>
            <button
              type="button"
              onClick={() => i < step && setStep(i)}
              disabled={i > step}
              className={`px-2 py-0.5 rounded-full border ${
                i === step ? "bg-primary text-white border-primary" : i < step ? "bg-primary/10 text-primary border-primary/30" : "bg-neutral-50 text-neutral-400 border-neutral-200"
              }`}
            >
              {i + 1}. {s.title}
              {s.optional ? " ·opt" : ""}
            </button>
          </li>
        ))}
      </ol>
      <div>
        <div className="text-sm font-medium text-neutral-800">
          Step {step + 1} — {STEPS[step].title}
        </div>
        <div className="text-xs text-neutral-500">{STEPS[step].hint}</div>
      </div>

      {/* STEP 0 — record identity */}
      {step === 0 && (
        <div className="space-y-3">
          <div className="space-y-1">
            <label className="text-xs font-medium text-neutral-600">What does this contract keep private? Give it a name.</label>
            <input
              className="border rounded px-2 py-1 text-sm w-56 block"
              placeholder="payment"
              aria-label="record type name"
              value={rec.recordType}
              onChange={(e) => setRec((r) => ({ ...r, recordType: e.target.value }))}
            />
            <p className="text-xs text-neutral-400">A “record” is one private item — one payment, one invoice, one loan.</p>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-neutral-600">Which function creates one?</label>
            <select
              className="border rounded px-2 py-1 text-sm block w-full max-w-md"
              aria-label="creating method"
              value={cap.writerSig}
              onChange={(e) => setCap((c) => ({ ...c, writerSig: e.target.value, keyIndex: 0 }))}
            >
              <option value="">choose a function…</option>
              {keyableFns.map((f) => (
                <option key={f.signature} value={f.signature}>
                  {f.signature}
                </option>
              ))}
            </select>
          </div>
          {writer && (
            <div className="space-y-1">
              <label className="text-xs font-medium text-neutral-600">Which parameter identifies each record? (its ID)</label>
              <select
                className="border rounded px-2 py-1 text-sm block w-full max-w-md"
                aria-label="record key parameter"
                value={cap.keyIndex}
                onChange={(e) => setCap((c) => ({ ...c, keyIndex: Number(e.target.value) }))}
              >
                {writer.inputs.map((p, i) => (
                  <option key={i} value={i} disabled={!isCanonicalizableKeyType(p.type)}>
                    {i}: {p.name} ({p.type})
                  </option>
                ))}
              </select>
              <p className="text-xs text-neutral-400">The same ID is matched automatically on the readers, events and transactions below.</p>
            </div>
          )}
        </div>
      )}

      {/* STEP 1 — parties */}
      {step === 1 && (
        <div className="space-y-2">
          <p className="text-xs text-neutral-500">
            When <code className="font-mono">{writer?.name ?? "the creating function"}</code> runs, record who is involved. Only these parties (plus anyone you add
            later) will be able to see the record.
          </p>
          {rememberRows.map((r, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2 border border-neutral-100 rounded p-2 bg-neutral-50">
              <input
                className="border rounded px-2 py-1 text-sm w-36"
                placeholder="payer"
                aria-label={`party ${i} name`}
                value={r.field}
                onChange={(e) => setRemember((rows) => rows.map((x, j) => (j === i ? { ...x, field: e.target.value } : x)))}
              />
              <span className="text-xs text-neutral-500">is</span>
              <select
                className="border rounded px-2 py-1 text-sm"
                aria-label={`party ${i} source`}
                value={r.source}
                onChange={(e) => {
                  const src = e.target.value as WizardRememberField["source"];
                  setRemember((rows) => rows.map((x, j) => (j === i ? { ...x, source: src, merge: src === "visibleTo" ? "union" : "set_once" } : x)));
                }}
              >
                <option value="sender">the caller (sender)</option>
                <option value="param">a parameter…</option>
                <option value="visibleTo">everyone in the visibleTo list</option>
              </select>
              {r.source === "param" && (
                <select
                  className="border rounded px-2 py-1 text-sm"
                  aria-label={`party ${i} parameter`}
                  value={r.paramIndex ?? ""}
                  onChange={(e) => setRemember((rows) => rows.map((x, j) => (j === i ? { ...x, paramIndex: Number(e.target.value) } : x)))}
                >
                  <option value="">parameter…</option>
                  {(writer?.inputs ?? []).map((p, pi) => (
                    <option key={pi} value={pi}>
                      {pi}: {p.name} ({p.type})
                    </option>
                  ))}
                </select>
              )}
              {r.source === "visibleTo" ? (
                <span className="text-xs text-neutral-400">collects everyone listed</span>
              ) : (
                <label className="text-xs flex items-center gap-1 text-neutral-500">
                  <input
                    type="checkbox"
                    aria-label={`party ${i} multiple`}
                    checked={r.merge === "union"}
                    onChange={(e) => setRemember((rows) => rows.map((x, j) => (j === i ? { ...x, merge: e.target.checked ? "union" : "set_once" } : x)))}
                  />
                  can have several
                </label>
              )}
              <button type="button" aria-label={`remove party ${i}`} className="ml-auto" onClick={() => setRemember((rows) => rows.filter((_, j) => j !== i))}>
                <X className="w-3.5 h-3.5 text-neutral-400" />
              </button>
            </div>
          ))}
          <Button variant="ghost" size="sm" onClick={() => setRemember((rows) => [...rows, { field: "", source: "sender", merge: "set_once" }])}>
            <Plus className="w-3 h-3" /> add party
          </Button>
        </div>
      )}

      {/* STEP 2 — readers */}
      {step === 2 && (
        <div className="space-y-2">
          <p className="text-xs text-neutral-500">Pick the view functions that return a record's private data. Only the parties you tick can call them; everyone else is denied.</p>
          {keyableFns.map((f) => (
            <div key={f.signature} className="border border-neutral-100 rounded p-2 bg-neutral-50">
              <label className="text-sm flex items-center gap-2">
                <input type="checkbox" aria-label={`gate reader ${f.signature}`} checked={isReader(f.signature)} onChange={() => toggleReader(f.signature)} />
                <code className="font-mono text-xs">{f.signature}</code>
              </label>
              {isReader(f.signature) && (
                <div className="ml-6 mt-1 space-y-1">
                  <div className="text-xs text-neutral-500">allowed to read:</div>
                  <div className="flex flex-wrap gap-3">
                    {parties.map((p) => (
                      <label key={p} className="text-xs flex items-center gap-1">
                        <input type="checkbox" aria-label={`reader ${f.signature} allow ${p}`} checked={readerFields(f.signature).includes(p)} onChange={() => toggleReaderField(f.signature, p)} />
                        {p}
                      </label>
                    ))}
                  </div>
                  <details className="text-xs">
                    <summary className="cursor-pointer text-neutral-500">Advanced</summary>
                    <div className="mt-1 space-y-1">
                      <input
                        className="border rounded px-2 py-1 text-xs w-full"
                        aria-label={`reader ${f.signature} principals`}
                        placeholder="always-allow principals (comma-separated did:… or 0x…)"
                        value={readerPrincipals(f.signature).join(", ")}
                        onChange={(e) => setReaderPrincipals(f.signature, e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
                      />
                      {(f.addressOutputs?.length ?? 0) > 0 && (
                        <label className="flex items-center gap-1 text-neutral-600">
                          <input type="checkbox" aria-label={`reader ${f.signature} return`} checked={readerHasReturn(f.signature)} onChange={() => toggleReaderReturn(f.signature)} />
                          also allow the address this getter returns ({f.addressOutputs.map((o) => o.name).join(", ")})
                        </label>
                      )}
                      <p className="text-neutral-400">Need a condition (e.g. amount ≥ X)? Use “Form editor (advanced)”.</p>
                    </div>
                  </details>
                </div>
              )}
            </div>
          ))}
          {keyableFns.length === 0 && <p className="text-xs text-neutral-400">This ABI has no view function with a usable key parameter.</p>}
        </div>
      )}

      {/* STEP 3 — events (optional, additive) */}
      {step === 3 && (
        <div className="space-y-2">
          <div className="p-2 rounded bg-amber-50 border border-amber-200 flex items-start gap-2">
            <Info className="w-3.5 h-3.5 text-amber-600 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-amber-700">Optional. This <strong>adds</strong> the ticked parties to a record's matching logs — it never hides logs anyone can already see.</p>
          </div>
          {keyableEvents.map((e) => (
            <div key={e.signature} className="border border-neutral-100 rounded p-2 bg-neutral-50">
              <label className="text-sm flex items-center gap-2">
                <input type="checkbox" aria-label={`gate event ${e.signature}`} checked={isEvent(e.signature)} onChange={() => toggleEvent(e.signature)} />
                <code className="font-mono text-xs">{e.signature}</code>
              </label>
              {isEvent(e.signature) && (
                <div className="ml-6 mt-1">
                  <div className="text-xs text-neutral-500 mb-1">additionally visible to:</div>
                  <div className="flex flex-wrap gap-3">
                    {parties.map((p) => (
                      <label key={p} className="text-xs flex items-center gap-1">
                        <input type="checkbox" aria-label={`event ${e.signature} allow ${p}`} checked={eventFields(e.signature).includes(p)} onChange={() => toggleEventField(e.signature, p)} />
                        {p}
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
          {keyableEvents.length === 0 && <p className="text-xs text-neutral-400">This ABI has no event with a recoverable key parameter — skip this step.</p>}
        </div>
      )}

      {/* STEP 4 — transactions (optional, additive) */}
      {step === 4 && (
        <div className="space-y-2">
          <div className="p-2 rounded bg-amber-50 border border-amber-200 flex items-start gap-2">
            <Info className="w-3.5 h-3.5 text-amber-600 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-amber-700">Optional. Lets a record's parties see the matching transaction (by hash) — additive, never hides.</p>
          </div>
          {keyableFns.map((f) => (
            <div key={f.signature} className="border border-neutral-100 rounded p-2 bg-neutral-50">
              <label className="text-sm flex items-center gap-2">
                <input type="checkbox" aria-label={`gate tx ${f.signature}`} checked={isTx(f.signature)} onChange={() => toggleTx(f.signature)} />
                <code className="font-mono text-xs">{f.signature}</code>
              </label>
              {isTx(f.signature) && (
                <div className="ml-6 mt-1">
                  <div className="text-xs text-neutral-500 mb-1">additionally visible to:</div>
                  <div className="flex flex-wrap gap-3">
                    {parties.map((p) => (
                      <label key={p} className="text-xs flex items-center gap-1">
                        <input type="checkbox" aria-label={`tx ${f.signature} allow ${p}`} checked={txFields(f.signature).includes(p)} onChange={() => toggleTxField(f.signature, p)} />
                        {p}
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* STEP 5 — review */}
      {step === 5 && (
        <div className="space-y-2" data-testid="method-policy-wizard-review">
          <div className="text-xs font-medium text-neutral-600">In plain words</div>
          <ul className="text-xs text-neutral-700 list-disc pl-4 space-y-0.5">
            {writer && keyParam && (
              <li>
                A “{rec.recordType || "record"}” is identified by <span className="font-mono">{keyParam.name}</span> ({keyParam.type}), captured when{" "}
                <span className="font-mono">{writer.name}</span> runs.
              </li>
            )}
            {namedParties.length > 0 && <li>Parties: {namedParties.map((r) => `${r.field} = ${sourceLabel(r, writer)}`).join("; ")}.</li>}
            {rec.readers.map((rd) => {
              const who = [...readerFields(rd.readerSig), ...readerPrincipals(rd.readerSig)];
              return (
                <li key={rd.readerSig}>
                  <span className="font-mono">{rd.readerSig}</span> readable by: {who.join(", ") || "(no one)"}
                  {readerHasReturn(rd.readerSig) ? " + the address it returns" : ""}.
                </li>
              );
            })}
            {(rec.events ?? []).map((e) => (
              <li key={e.eventSig}>
                event <span className="font-mono">{e.eventSig}</span> additionally visible to: {eventFields(e.eventSig).join(", ") || "(no one)"}.
              </li>
            ))}
            {(rec.transactions ?? []).map((t) => (
              <li key={t.methodSig}>
                tx <span className="font-mono">{t.methodSig}</span> additionally visible to: {txFields(t.methodSig).join(", ") || "(no one)"}.
              </li>
            ))}
          </ul>
          <details className="text-xs">
            <summary className="cursor-pointer text-neutral-500">Show policy JSON</summary>
            <pre className="text-[10px] bg-neutral-900 text-neutral-100 rounded p-2 overflow-auto max-h-48 mt-1" data-testid="wizard-policy-preview">
              {compiled ? JSON.stringify(compiled, null, 2) : "…"}
            </pre>
          </details>
          {otherRecords.length > 0 && (
            <p className="text-xs text-neutral-500">
              This contract has {otherRecords.length} other record type(s); they are preserved. Edit them in “Form editor (advanced)”.
            </p>
          )}
          {fullError && <p className="text-xs text-amber-700">{fullError}</p>}
        </div>
      )}

      {stepErr && step !== 5 && <p className="text-xs text-amber-700">{stepErr}</p>}

      {/* nav */}
      <div className="flex items-center gap-2 pt-1 border-t border-neutral-100">
        <Button variant="ghost" size="sm" onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0}>
          <ChevronLeft className="w-3 h-3" /> Back
        </Button>
        {STEPS[step].optional && (
          <Button variant="ghost" size="sm" onClick={() => setStep((s) => s + 1)}>
            Skip
          </Button>
        )}
        <div className="ml-auto flex gap-2">
          <Button variant="ghost" size="sm" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
          {step < 5 ? (
            <Button size="sm" onClick={() => setStep((s) => s + 1)} disabled={!!stepErr}>
              Next <ChevronRight className="w-3 h-3" />
            </Button>
          ) : (
            <Button size="sm" onClick={() => compiled && onSave(compiled)} disabled={!canSave}>
              {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />} Save policy
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
