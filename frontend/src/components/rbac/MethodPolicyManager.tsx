import { useMemo, useState } from "react";
import { rbacApi } from "@/api/rbac";
import { getAdminToken } from "@/api/adminClient";
import type { MethodPolicyDocument } from "@/types/rbac";
import {
  parseAbiFunctions,
  functionsWithKeyableParam,
  isCanonicalizableKeyType,
  compileMethodPolicy,
  validateWizard,
  renderPolicy,
  type WizardState,
} from "@/lib/methodPolicy";
import { Button } from "@/components/ui/button";
import { ShieldAlert, ShieldCheck, Check, Loader2, Plus, X, Info } from "lucide-react";

interface Props {
  orgId: string;
  contractAddress: string;
  contractAbi?: string;
  initialPolicy?: MethodPolicyDocument | null;
  isReadonlyAdmin?: boolean;
}

const emptyWizard: WizardState = {
  recordType: "",
  writerSig: "",
  writerKeyIndex: 0,
  readerSig: "",
  readerKeyIndex: 0,
  remember: [{ field: "", source: "sender", merge: "set_once" }],
  allowFields: [],
  returnPaths: [],
};

export function MethodPolicyManager({ orgId, contractAddress, contractAbi, initialPolicy, isReadonlyAdmin }: Props) {
  const [policy, setPolicy] = useState<MethodPolicyDocument | null>(initialPolicy ?? null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [w, setW] = useState<WizardState>(emptyWizard);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const fns = useMemo(() => parseAbiFunctions(contractAbi), [contractAbi]);
  const keyableFns = useMemo(() => functionsWithKeyableParam(fns), [fns]);
  const writer = fns.find((f) => f.signature === w.writerSig);
  const reader = fns.find((f) => f.signature === w.readerSig);
  const rendered = policy ? renderPolicy(policy) : [];

  const compiled = useMemo(() => {
    try {
      return compileMethodPolicy(w, policy);
    } catch {
      return null;
    }
  }, [w, policy]);
  const clientError = wizardOpen ? validateWizard(w, fns) : null;

  const noAbi = !contractAbi;
  // C1: the PUT is super-admin only (X-Admin-Token). The dashboard falls back to
  // the user's JWT for tier-2 admins, which the backend rejects. There is no
  // JWT super-admin, so the only session that can save is one holding the admin
  // token — gate the edit affordance on that, and render read-only otherwise so
  // a tier-2 admin sees the policy (GET works for them) without a dead 403.
  const canEdit = !isReadonlyAdmin && getAdminToken() !== "";

  async function save(doc: MethodPolicyDocument | null) {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      await rbacApi.contracts.updateMethodPolicies(orgId, contractAddress, doc);
      setPolicy(doc);
      setWizardOpen(false);
      setSuccess(doc ? "Method policy saved." : "Method policy cleared.");
    } catch (e: unknown) {
      // L2: surface the backend's 400 validation message verbatim; for any
      // other status show a generic message (500 bodies are opaque by design).
      const err = e as { response?: { status?: number; data?: { error?: string } } };
      const status = err?.response?.status;
      const backendMsg = err?.response?.data?.error;
      if (status === 400 && backendMsg) {
        setError(backendMsg);
      } else if (status === 401 || status === 403) {
        setError("Saving a method policy requires the super-admin token.");
      } else {
        setError("Failed to save method policy.");
      }
    } finally {
      setSaving(false);
    }
  }

  // clearPolicy loosens privacy (records become readable by any group member) —
  // confirm first (M2).
  function clearPolicy() {
    if (typeof window !== "undefined" && !window.confirm(
      "Clear the method policy? Record-reader getters on this contract will revert to being readable by any member of a granted group."
    )) {
      return;
    }
    void save(null);
  }

  // mergeDefaultForSource keeps identity fields safe: sender/param default to
  // set_once (poison-protected), visibleTo audience to union (M3).
  function mergeDefaultForSource(source: "sender" | "param" | "visibleTo"): "set_once" | "union" {
    return source === "visibleTo" ? "union" : "set_once";
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-neutral-500" />
        <span className="text-sm font-medium text-neutral-700">Method access policies</span>
        {policy && (
          <span className="text-xs px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">configured</span>
        )}
      </div>

      <p className="text-xs text-neutral-500">
        Gate a record-reader method (e.g. <code>getPaymentInfo</code>) to a record&apos;s stakeholders,
        so only that payment&apos;s parties — and any designated settlement party — can read it, instead
        of every group member reading any record.
      </p>

      {error && (
        <div className="p-3 rounded-lg bg-error-light border border-error/30 flex items-start gap-2">
          <ShieldAlert className="w-4 h-4 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}
      {success && (
        <p className="text-xs text-success-dark flex items-center gap-1">
          <Check className="w-3 h-3" /> {success}
        </p>
      )}

      {/* Current policy display */}
      {rendered.length === 0 ? (
        <div className="p-3 rounded-lg border border-neutral-200 bg-neutral-50 text-xs text-neutral-600">
          No method policies configured — record-reader getters are gated by the contract grant only
          (any member of a granted group may read any record).
        </div>
      ) : (
        <div className="space-y-2">
          {rendered.map((r) => (
            <div key={r.recordType} className="p-3 rounded-lg border border-neutral-200 text-xs space-y-1">
              <div className="font-medium text-neutral-700">record: {r.recordType}</div>
              {r.readers.map((rd, i) => (
                <div key={i} className="text-neutral-600">
                  <span className="font-mono">{rd.method}</span> readable by:{" "}
                  {rd.allows.join("; ") || "(no one)"}
                </div>
              ))}
              {r.captures.map((c, i) => (
                <div key={`c${i}`} className="text-neutral-500">
                  captured on <span className="font-mono">{c.method}</span>: {c.fields.join(", ")}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* Surface asymmetry warning */}
      <div className="p-2 rounded bg-amber-50 border border-amber-200 flex items-start gap-2">
        <Info className="w-3.5 h-3.5 text-amber-600 mt-0.5 flex-shrink-0" />
        <p className="text-xs text-amber-700">
          A method policy gates the <strong>getter</strong> only — not the record&apos;s event logs. Gate
          those with event rules too. Use high-entropy, opaque record identifiers. Saving a policy
          requires the super-admin token.
        </p>
      </div>

      {canEdit && (
        <div className="flex gap-2">
          {!wizardOpen && (
            <Button variant="outline" size="sm" onClick={() => { setW(emptyWizard); setWizardOpen(true); setError(null); setSuccess(null); }} disabled={noAbi}>
              {policy ? "Add / edit a record policy" : "Configure a policy"}
            </Button>
          )}
          {policy && !wizardOpen && (
            <Button variant="ghost" size="sm" onClick={clearPolicy} disabled={saving}>
              Clear policy
            </Button>
          )}
        </div>
      )}
      {!canEdit && !isReadonlyAdmin && (
        <p className="text-xs text-neutral-500">
          Editing method policies requires the super-admin API token; this view is read-only.
        </p>
      )}
      {canEdit && noAbi && (
        <p className="text-xs text-neutral-500">Register the contract ABI first to configure method policies.</p>
      )}

      {wizardOpen && (
        <div className="p-3 rounded-lg border border-neutral-300 bg-white space-y-3" data-testid="method-policy-wizard">
          <div className="grid grid-cols-2 gap-2">
            <label className="text-xs text-neutral-600">
              Record type name
              <input
                className="mt-1 w-full border rounded px-2 py-1 text-sm"
                value={w.recordType}
                onChange={(e) => setW({ ...w, recordType: e.target.value })}
                placeholder="payment"
                aria-label="Record type name"
              />
            </label>
          </div>

          {/* Writer + key */}
          <div className="grid grid-cols-2 gap-2">
            <label className="text-xs text-neutral-600">
              Writer method (creates the record)
              <select
                className="mt-1 w-full border rounded px-2 py-1 text-sm"
                value={w.writerSig}
                aria-label="Writer method"
                onChange={(e) => setW({ ...w, writerSig: e.target.value, writerKeyIndex: 0 })}
              >
                <option value="">select…</option>
                {keyableFns.map((f) => (
                  <option key={f.signature} value={f.signature}>{f.signature}</option>
                ))}
              </select>
            </label>
            <label className="text-xs text-neutral-600">
              Record-key parameter (writer)
              <select
                className="mt-1 w-full border rounded px-2 py-1 text-sm"
                value={w.writerKeyIndex}
                aria-label="Writer key parameter"
                onChange={(e) => setW({ ...w, writerKeyIndex: Number(e.target.value) })}
              >
                {(writer?.inputs ?? []).map((p, i) => (
                  <option key={i} value={i} disabled={!isCanonicalizableKeyType(p.type)}>
                    {i}: {p.name} ({p.type})
                  </option>
                ))}
              </select>
            </label>
          </div>

          {/* Reader + key */}
          <div className="grid grid-cols-2 gap-2">
            <label className="text-xs text-neutral-600">
              Reader method (to gate)
              <select
                className="mt-1 w-full border rounded px-2 py-1 text-sm"
                value={w.readerSig}
                aria-label="Reader method"
                onChange={(e) => setW({ ...w, readerSig: e.target.value, readerKeyIndex: 0, returnPaths: [] })}
              >
                <option value="">select…</option>
                {keyableFns.map((f) => (
                  <option key={f.signature} value={f.signature}>{f.signature}</option>
                ))}
              </select>
            </label>
            <label className="text-xs text-neutral-600">
              Record-key parameter (reader)
              <select
                className="mt-1 w-full border rounded px-2 py-1 text-sm"
                value={w.readerKeyIndex}
                aria-label="Reader key parameter"
                onChange={(e) => setW({ ...w, readerKeyIndex: Number(e.target.value) })}
              >
                {(reader?.inputs ?? []).map((p, i) => (
                  <option key={i} value={i} disabled={!isCanonicalizableKeyType(p.type)}>
                    {i}: {p.name} ({p.type})
                  </option>
                ))}
              </select>
            </label>
          </div>

          {/* Remember fields */}
          <div className="space-y-1">
            <div className="text-xs font-medium text-neutral-600">Capture (who are the record&apos;s parties)</div>
            {w.remember.map((r, i) => (
              <div key={i} className="flex items-center gap-1">
                <input
                  className="border rounded px-2 py-1 text-sm w-28"
                  placeholder="field (payer)"
                  aria-label={`capture field ${i} name`}
                  value={r.field}
                  onChange={(e) => {
                    const rem = [...w.remember];
                    rem[i] = { ...rem[i], field: e.target.value };
                    setW({ ...w, remember: rem });
                  }}
                />
                <select
                  className="border rounded px-2 py-1 text-sm"
                  aria-label={`capture field ${i} source`}
                  value={r.source}
                  onChange={(e) => {
                    const src = e.target.value as WizardState["remember"][number]["source"];
                    const rem = [...w.remember];
                    // M3: reset merge to the safe default for the new source
                    // (identity → set_once, audience → union).
                    rem[i] = { ...rem[i], source: src, merge: mergeDefaultForSource(src) };
                    setW({ ...w, remember: rem });
                  }}
                >
                  <option value="sender">sender</option>
                  <option value="param">param</option>
                  <option value="visibleTo">visibleTo</option>
                </select>
                {r.source === "param" && (
                  <select
                    className="border rounded px-2 py-1 text-sm"
                    aria-label={`capture field ${i} param index`}
                    value={r.paramIndex ?? ""}
                    onChange={(e) => {
                      const rem = [...w.remember];
                      rem[i] = { ...rem[i], paramIndex: Number(e.target.value) };
                      setW({ ...w, remember: rem });
                    }}
                  >
                    <option value="">param…</option>
                    {(writer?.inputs ?? []).map((p, pi) => (
                      <option key={pi} value={pi}>{pi}: {p.name} ({p.type})</option>
                    ))}
                  </select>
                )}
                <select
                  className="border rounded px-2 py-1 text-sm"
                  aria-label={`capture field ${i} merge`}
                  value={r.merge}
                  onChange={(e) => {
                    const rem = [...w.remember];
                    rem[i] = { ...rem[i], merge: e.target.value as "set_once" | "union" };
                    setW({ ...w, remember: rem });
                  }}
                >
                  <option value="set_once">set_once</option>
                  <option value="union">union</option>
                </select>
                <button aria-label={`remove capture field ${i}`} onClick={() => setW({ ...w, remember: w.remember.filter((_, j) => j !== i) })}>
                  <X className="w-3.5 h-3.5 text-neutral-400" />
                </button>
              </div>
            ))}
            <Button variant="ghost" size="sm" onClick={() => setW({ ...w, remember: [...w.remember, { field: "", source: "sender", merge: "set_once" }] })}>
              <Plus className="w-3 h-3" /> capture field
            </Button>
            {w.remember.some((r) => r.source !== "visibleTo" && r.merge === "union") && (
              <p className="text-xs text-amber-700 flex items-center gap-1">
                <ShieldAlert className="w-3 h-3" />
                An identity field (from sender/param) set to <code>union</code> disables set-once poison
                protection for it. Use <code>set_once</code> for identity fields; <code>union</code> is for
                a shared audience.
              </p>
            )}
          </div>

          {/* Allow rules */}
          <div className="space-y-1">
            <div className="text-xs font-medium text-neutral-600">Allow the reader when the caller is…</div>
            <div className="flex flex-wrap gap-2">
              {w.remember.filter((r) => r.field).map((r) => (
                <label key={r.field} className="text-xs flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`allow field ${r.field}`}
                    checked={w.allowFields.includes(r.field)}
                    onChange={(e) =>
                      setW({ ...w, allowFields: e.target.checked ? [...w.allowFields, r.field] : w.allowFields.filter((f) => f !== r.field) })
                    }
                  />
                  {r.field}
                </label>
              ))}
            </div>
            {(reader?.addressOutputs.length ?? 0) > 0 && (
              <div className="flex flex-wrap gap-2">
                <span className="text-xs text-neutral-500">or a returned address:</span>
                {reader!.addressOutputs.map((o) => (
                  <label key={o.name} className="text-xs flex items-center gap-1">
                    <input
                      type="checkbox"
                      aria-label={`allow return ${o.name}`}
                      checked={w.returnPaths.includes(o.name)}
                      onChange={(e) =>
                        setW({ ...w, returnPaths: e.target.checked ? [...w.returnPaths, o.name] : w.returnPaths.filter((p) => p !== o.name) })
                      }
                    />
                    {o.name}
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Live JSON preview */}
          <div>
            <div className="text-xs font-medium text-neutral-600 mb-1">Policy preview</div>
            <pre className="text-[10px] bg-neutral-900 text-neutral-100 rounded p-2 overflow-auto max-h-40" data-testid="policy-preview">
              {compiled ? JSON.stringify(compiled, null, 2) : "…"}
            </pre>
          </div>

          {clientError && <p className="text-xs text-amber-700">{clientError}</p>}

          <div className="flex gap-2">
            <Button
              size="sm"
              disabled={saving || !!clientError || !compiled}
              onClick={() => compiled && void save(compiled)}
            >
              {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />} Save policy
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setWizardOpen(false)} disabled={saving}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
