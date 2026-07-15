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
  MethodPolicyWhere,
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
  let base: string;
  if (Array.isArray(rule.callerIn)) {
    base = `caller is one of: ${rule.callerIn.join(", ")}`;
  } else {
    base = `caller matches a returned address (${rule.callerIn.paths.join(", ")})`;
  }
  if (rule.where) {
    base += ` — and ${rule.where.field} ${rule.where.op} ${rule.where.value}`;
  }
  return base;
}

export interface RenderedRecord {
  recordType: string;
  readers: { method: string; keyParam: string; allows: string[] }[];
  captures: { method: string; keyParam: string; fields: string[] }[];
}

// ---- Structured wizard model (array-based; full schema) ----
//
// The wizard edits the WHOLE document: N record types, each with N capture specs
// and N reader specs, each reader with N allow rules. compileWizard() emits the
// exact backend schema; validateWizard() mirrors every backend invariant for
// instant feedback (the backend remains the source of truth).

export interface WizardRememberField {
  field: string;
  source: "sender" | "param" | "visibleTo";
  paramIndex?: number;
  merge: "set_once" | "union";
}

export interface WizardCapture {
  writerSig: string;
  keyIndex: number;
  remember: WizardRememberField[];
}

// An allow rule is EITHER a callerIn list (captured field names and/or literal
// DID/address principals) with an optional where, OR a return-address rule.
export interface WizardAllowRule {
  kind: "callerIn" | "return";
  fields: string[]; // captured field names (callerIn kind)
  principals: string[]; // literal did:/0x principals (callerIn kind)
  returnPaths: string[]; // reader address-output names (return kind)
  where?: { field: string; op: string; value: string } | null;
}

export interface WizardReader {
  readerSig: string;
  keyIndex: number;
  rules: WizardAllowRule[];
}

export interface WizardRecord {
  recordType: string;
  captures: WizardCapture[];
  readers: WizardReader[];
}

export interface WizardState {
  records: WizardRecord[];
}

export const WHERE_OPS = ["eq", "neq", "lt", "lte", "gt", "gte"] as const;
const NUMERIC_WHERE_OPS = new Set(["lt", "lte", "gt", "gte"]);

function isLiteralPrincipal(s: string): boolean {
  return (s.startsWith("did:") && s.length > 4) || /^0x[0-9a-fA-F]{40}$/.test(s);
}

function isNumericKind(kind: string): boolean {
  return kind.startsWith("uint") || kind.startsWith("int");
}

// declaredKinds computes, for one record, field name → kind ("did" or ABI type),
// or an error string if a name is re-declared with a conflicting kind/merge.
function declaredKinds(
  rec: WizardRecord,
  fns: AbiFnInfo[]
): { kinds: Map<string, string>; merges: Map<string, string>; err: string | null } {
  const kinds = new Map<string, string>();
  const merges = new Map<string, string>();
  for (const cap of rec.captures) {
    const writer = fns.find((f) => f.signature === cap.writerSig);
    if (!writer) continue;
    const seen = new Set<string>();
    for (const r of cap.remember) {
      const name = r.field.trim();
      if (!name) return { kinds, merges, err: "Every captured field needs a name." };
      if (seen.has(name)) return { kinds, merges, err: `Duplicate field "${name}" within one capture.` };
      seen.add(name);
      let kind = "did";
      if (r.source === "param") {
        if (r.paramIndex == null || !writer.inputs[r.paramIndex]) {
          return { kinds, merges, err: `Field "${name}" is param-sourced — pick which parameter.` };
        }
        kind = writer.inputs[r.paramIndex].type;
      }
      const prevK = kinds.get(name);
      if (prevK && prevK !== kind) return { kinds, merges, err: `Field "${name}" has conflicting kinds across captures.` };
      const prevM = merges.get(name);
      if (prevM && prevM !== r.merge) return { kinds, merges, err: `Field "${name}" has conflicting merge modes across captures.` };
      kinds.set(name, kind);
      merges.set(name, r.merge);
    }
  }
  return { kinds, merges, err: null };
}

// validateWizard mirrors every backend invariant so the UI cannot Save a policy
// the backend would reject. Returns null when valid.
export function validateWizard(s: WizardState, fns: AbiFnInfo[]): string | null {
  if (s.records.length === 0) return "Add at least one record type.";
  const recordNames = new Set<string>();
  for (const rec of s.records) {
    const rt = rec.recordType.trim();
    if (!rt) return "Every record needs a name.";
    if (recordNames.has(rt)) return `Duplicate record type "${rt}".`;
    recordNames.add(rt);
    if (rec.captures.length === 0) return `Record "${rt}": add at least one capture.`;
    if (rec.readers.length === 0) return `Record "${rt}": add at least one reader method to gate.`;

    // key type must agree across every capture + reader of the record.
    let keyType = "";
    const checkKey = (sig: string, idx: number, what: string): string | null => {
      const fn = fns.find((f) => f.signature === sig);
      if (!fn) return `Record "${rt}": choose a ${what} method.`;
      const p = fn.inputs[idx];
      if (!p || !isCanonicalizableKeyType(p.type)) return `Record "${rt}": choose a valid record-key parameter on ${what} ${sig}.`;
      if (keyType === "") keyType = p.type;
      else if (keyType !== p.type) return `Record "${rt}": key types must match across methods (${p.type} vs ${keyType}).`;
      return null;
    };
    for (const cap of rec.captures) {
      const e = checkKey(cap.writerSig, cap.keyIndex, "writer");
      if (e) return e;
    }
    for (const rd of rec.readers) {
      const e = checkKey(rd.readerSig, rd.keyIndex, "reader");
      if (e) return e;
    }

    const { kinds, err } = declaredKinds(rec, fns);
    if (err) return `Record "${rt}": ${err}`;
    // visibleTo ⇒ union
    for (const cap of rec.captures) {
      for (const r of cap.remember) {
        if (r.source === "visibleTo" && r.merge === "set_once") {
          return `Record "${rt}": visibleTo field "${r.field}" must use union, not set_once.`;
        }
      }
    }

    for (const rd of rec.readers) {
      const reader = fns.find((f) => f.signature === rd.readerSig);
      if (!reader) return `Record "${rt}": choose a reader method.`;
      if (rd.rules.length === 0) return `Record "${rt}" reader ${rd.readerSig}: add at least one allow rule.`;
      const addrOuts = new Set(reader.addressOutputs.map((o) => o.name));
      for (const rule of rd.rules) {
        if (rule.kind === "return") {
          if (rule.returnPaths.length === 0) return `Record "${rt}": a return rule needs at least one address output.`;
          for (const p of rule.returnPaths) {
            if (!addrOuts.has(p)) return `Record "${rt}": return path "${p}" is not an address output of ${rd.readerSig}.`;
          }
          if (rule.where) return `Record "${rt}": where is not allowed on a return rule.`;
          continue;
        }
        // callerIn rule
        if (rule.fields.length === 0 && rule.principals.length === 0) {
          return `Record "${rt}": an allow rule needs at least one captured field or literal principal.`;
        }
        for (const f of rule.fields) {
          if (!kinds.has(f)) return `Record "${rt}": allow field "${f}" is not a captured field.`;
        }
        for (const p of rule.principals) {
          if (!isLiteralPrincipal(p)) return `Record "${rt}": principal "${p}" must be a did:… or 0x… address.`;
        }
        if (rule.where) {
          const w = rule.where;
          if (!w.field) return `Record "${rt}": where.field is required.`;
          const k = kinds.get(w.field);
          if (!k) return `Record "${rt}": where.field "${w.field}" is not a captured field.`;
          if (!WHERE_OPS.includes(w.op as (typeof WHERE_OPS)[number])) return `Record "${rt}": where.op "${w.op}" is invalid.`;
          if (NUMERIC_WHERE_OPS.has(w.op)) {
            if (!isNumericKind(k)) return `Record "${rt}": where op ${w.op} needs a numeric field, but "${w.field}" is ${k}.`;
            if (!/^-?\d+$/.test(w.value.trim())) return `Record "${rt}": where.value "${w.value}" must be an integer for op ${w.op}.`;
          }
          if (!w.value && w.op !== "eq" && w.op !== "neq") return `Record "${rt}": where.value is required.`;
        }
      }
    }
  }
  return null;
}

// compileWizard emits the exact backend policy document from the wizard state.
export function compileWizard(s: WizardState): MethodPolicyDocument {
  const records: MethodPolicyDocument["records"] = {};
  for (const rec of s.records) {
    const capture = rec.captures.map((cap) => {
      const remember: Record<string, { source: "sender" | "param" | "visibleTo"; index?: number; merge: "set_once" | "union" }> = {};
      for (const r of cap.remember) {
        remember[r.field.trim()] =
          r.source === "param"
            ? { source: "param", index: r.paramIndex, merge: r.merge }
            : { source: r.source, merge: r.merge };
      }
      return { method: cap.writerSig, key: { source: "param" as const, index: cap.keyIndex }, remember };
    });
    const access = rec.readers.map((rd) => {
      const allow: MethodPolicyAllowRule[] = [];
      for (const rule of rd.rules) {
        if (rule.kind === "return") {
          allow.push({ callerIn: { source: "return", paths: [...rule.returnPaths], kind: "address" } });
        } else {
          const entry: MethodPolicyAllowRule = { callerIn: [...rule.fields, ...rule.principals] };
          if (rule.where && rule.where.field) {
            entry.where = { field: rule.where.field, op: rule.where.op as MethodPolicyWhere["op"], value: rule.where.value };
          }
          allow.push(entry);
        }
      }
      return { method: rd.readerSig, key: { source: "param" as const, index: rd.keyIndex }, allow, onNoRecord: "deny" as const, else: "deny" as const };
    });
    records[rec.recordType.trim()] = { capture, access };
  }
  return { records };
}

// decompileWizard seeds the wizard from an existing policy document (for editing
// in place). Best-effort: returns a wizard state; anything the structured form
// can't represent 1:1 still round-trips through compile because the shapes match.
export function decompileWizard(doc: MethodPolicyDocument | null | undefined): WizardState {
  if (!doc || !doc.records) return { records: [] };
  const records: WizardRecord[] = [];
  for (const [recordType, rec] of Object.entries(doc.records)) {
    const captures: WizardCapture[] = (rec.capture ?? []).map((c) => ({
      writerSig: c.method,
      keyIndex: c.key.index,
      remember: Object.entries(c.remember ?? {}).map(([field, f]) => ({
        field,
        source: f.source,
        paramIndex: f.index,
        merge: f.merge,
      })),
    }));
    const readers: WizardReader[] = (rec.access ?? []).map((a) => ({
      readerSig: a.method,
      keyIndex: a.key.index,
      rules: (a.allow ?? []).map((r): WizardAllowRule => {
        if (Array.isArray(r.callerIn)) {
          const fields: string[] = [];
          const principals: string[] = [];
          for (const c of r.callerIn) {
            if (isLiteralPrincipal(c)) principals.push(c);
            else fields.push(c);
          }
          return { kind: "callerIn", fields, principals, returnPaths: [], where: r.where ?? null };
        }
        return { kind: "return", fields: [], principals: [], returnPaths: [...r.callerIn.paths] };
      }),
    }));
    records.push({ recordType, captures, readers });
  }
  return { records };
}

// Factory helpers for the UI.
export function emptyRecord(): WizardRecord {
  return {
    recordType: "",
    captures: [{ writerSig: "", keyIndex: 0, remember: [{ field: "", source: "sender", merge: "set_once" }] }],
    readers: [{ readerSig: "", keyIndex: 0, rules: [{ kind: "callerIn", fields: [], principals: [], returnPaths: [], where: null }] }],
  };
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
