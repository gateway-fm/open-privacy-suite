// RD-1206 method-policy helpers: parse a contract ABI into the pieces the
// wizard/display need, and render a policy document in plain language.
//
// Canonical function signatures come from viem's toFunctionSignature, which
// produces the exact Solidity canonical form the Go backend uses
// (abi.Method.Sig) — including nested tuples — so a UI-built policy validates
// server-side on the first save.
import { toFunctionSignature, type Abi, type AbiFunction } from "viem";
import type {
  MethodPolicyDocument,
  MethodPolicyAllowRule,
} from "@/types/rbac";

export interface AbiParam {
  name: string; // ABI name, or the positional index as a string when unnamed
  type: string;
}

export interface AbiFnInfo {
  name: string;
  signature: string; // canonical, matches the backend
  inputs: AbiParam[];
  outputs: AbiParam[];
  addressOutputs: AbiParam[]; // subset of outputs whose type is "address"
}

// Types the backend can canonicalize as a record key (must match
// rbac.canonicalizableType): scalar value types only.
const CANONICALIZABLE_KEY = /^(string|address|bool|bytes\d*|bytes|u?int\d*)$/;

export function isCanonicalizableKeyType(t: string): boolean {
  return CANONICALIZABLE_KEY.test(t);
}

export function parseAbiFunctions(abiJSON?: string): AbiFnInfo[] {
  if (!abiJSON) return [];
  let abi: Abi;
  try {
    abi = JSON.parse(abiJSON) as Abi;
  } catch {
    return [];
  }
  const out: AbiFnInfo[] = [];
  for (const item of abi) {
    if (item.type !== "function") continue;
    const fn = item as AbiFunction;
    let signature: string;
    try {
      signature = toFunctionSignature(fn);
    } catch {
      continue;
    }
    const inputs = (fn.inputs ?? []).map((i, idx) => ({ name: i.name || String(idx), type: i.type }));
    const outputs = (fn.outputs ?? []).map((o, idx) => ({ name: o.name || String(idx), type: o.type }));
    out.push({
      name: fn.name,
      signature,
      inputs,
      outputs,
      addressOutputs: outputs.filter((o) => o.type === "address"),
    });
  }
  return out;
}

// Functions with at least one canonicalizable parameter can serve as writers
// or readers (they need a key parameter).
export function functionsWithKeyableParam(fns: AbiFnInfo[]): AbiFnInfo[] {
  return fns.filter((f) => f.inputs.some((p) => isCanonicalizableKeyType(p.type)));
}

// describeAllowRule renders one allow rule for the display.
export function describeAllowRule(rule: MethodPolicyAllowRule): string {
  if (Array.isArray(rule.callerIn)) {
    return `caller is one of: ${rule.callerIn.join(", ")}`;
  }
  return `caller matches a returned address (${rule.callerIn.paths.join(", ")})`;
}

export interface RenderedRecord {
  recordType: string;
  readers: { method: string; keyParam: string; allows: string[] }[];
  captures: { method: string; keyParam: string; fields: string[] }[];
}

// WizardRememberField is one capture field being configured.
export interface WizardRememberField {
  field: string;
  source: "sender" | "param" | "visibleTo";
  paramIndex?: number;
  merge: "set_once" | "union";
}

// WizardState is the wizard's working model for ONE record type.
export interface WizardState {
  recordType: string;
  writerSig: string;
  writerKeyIndex: number;
  readerSig: string;
  readerKeyIndex: number;
  remember: WizardRememberField[];
  allowFields: string[]; // captured field names admitted
  returnPaths: string[]; // reader address-output names admitted
}

// validateWizard returns a human-readable error, or null when the state is
// coherent. This is a UX pre-check only — the backend re-validates against the
// ABI and is the source of truth.
export function validateWizard(s: WizardState, fns: AbiFnInfo[]): string | null {
  if (!s.recordType.trim()) return "Record type name is required.";
  const writer = fns.find((f) => f.signature === s.writerSig);
  const reader = fns.find((f) => f.signature === s.readerSig);
  if (!writer) return "Choose the writer method that creates the record.";
  if (!reader) return "Choose the reader method to gate.";
  const wKey = writer.inputs[s.writerKeyIndex];
  const rKey = reader.inputs[s.readerKeyIndex];
  if (!wKey || !isCanonicalizableKeyType(wKey.type)) return "Choose a valid record-key parameter on the writer.";
  if (!rKey || !isCanonicalizableKeyType(rKey.type)) return "Choose a valid record-key parameter on the reader.";
  if (wKey.type !== rKey.type) return `Writer and reader key types must match (writer ${wKey.type} vs reader ${rKey.type}).`;
  if (s.remember.length === 0) return "Capture at least one field (e.g. payer, payee).";
  const fieldNames = new Set<string>();
  for (const r of s.remember) {
    const name = r.field.trim();
    if (!name) return "Every captured field needs a name.";
    if (fieldNames.has(name)) return `Duplicate captured field name "${name}" — each must be unique.`;
    fieldNames.add(name);
    if (r.source === "param" && (r.paramIndex == null || !writer.inputs[r.paramIndex])) {
      return `Field "${name}" is sourced from a parameter — pick which one.`;
    }
    // An accumulating audience (visibleTo) must use union; set_once would only
    // ever keep the first tx's list and defeats the audience. Identity fields
    // (sender/param) should stay set_once (poison protection).
    if (r.source === "visibleTo" && r.merge === "set_once") {
      return `Field "${name}" (visibleTo audience) must use "union", not "set_once".`;
    }
  }
  if (s.allowFields.length === 0 && s.returnPaths.length === 0) {
    return "Add at least one allow rule (captured fields and/or returned addresses).";
  }
  for (const f of s.allowFields) {
    if (!fieldNames.has(f)) return `Allow rule references "${f}", which isn't a captured field.`;
  }
  const readerAddrOutputs = new Set(reader.addressOutputs.map((o) => o.name));
  for (const p of s.returnPaths) {
    if (!readerAddrOutputs.has(p)) {
      return `Return-address rule references "${p}", which is not an address output of the reader.`;
    }
  }
  return null;
}

// compileMethodPolicy builds the policy document for one record type from the
// wizard state, merging into an existing document (other record types kept).
export function compileMethodPolicy(
  s: WizardState,
  existing?: MethodPolicyDocument | null
): MethodPolicyDocument {
  const allow: MethodPolicyAllowRule[] = [];
  if (s.allowFields.length > 0) allow.push({ callerIn: [...s.allowFields] });
  if (s.returnPaths.length > 0) {
    allow.push({ callerIn: { source: "return", paths: [...s.returnPaths], kind: "address" } });
  }

  const remember: Record<string, { source: "sender" | "param" | "visibleTo"; index?: number; merge: "set_once" | "union" }> = {};
  for (const r of s.remember) {
    remember[r.field] =
      r.source === "param"
        ? { source: "param", index: r.paramIndex, merge: r.merge }
        : { source: r.source, merge: r.merge };
  }

  const records = { ...(existing?.records ?? {}) };
  records[s.recordType] = {
    capture: [{ method: s.writerSig, key: { source: "param", index: s.writerKeyIndex }, remember }],
    access: [
      {
        method: s.readerSig,
        key: { source: "param", index: s.readerKeyIndex },
        allow,
        onNoRecord: "deny",
        else: "deny",
      },
    ],
  };
  return { records };
}

// renderPolicy flattens a document into a display-friendly structure.
export function renderPolicy(doc: MethodPolicyDocument): RenderedRecord[] {
  const out: RenderedRecord[] = [];
  for (const [recordType, rec] of Object.entries(doc.records ?? {})) {
    out.push({
      recordType,
      readers: (rec.access ?? []).map((a) => ({
        method: a.method,
        keyParam: `param ${a.key.index}`,
        allows: (a.allow ?? []).map(describeAllowRule),
      })),
      captures: (rec.capture ?? []).map((c) => ({
        method: c.method,
        keyParam: `param ${c.key.index}`,
        fields: Object.entries(c.remember ?? {}).map(([name, f]) => {
          const src =
            f.source === "param" ? `param ${f.index}` : f.source;
          return `${name} = ${src} (${f.merge})`;
        }),
      })),
    });
  }
  return out;
}
